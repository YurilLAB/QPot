// Command qpot-release builds QPot's release files and serves fake releases
// for the installer tests. It is a maintainer tool; it is not shipped.
//
//	qpot-release pack -version 0.1.0 -out dist
//	    builds qpot for every release platform and writes the archives the
//	    installers download plus SHA256SUMS. The archives are reproducible:
//	    the same commit gives byte-identical files, on any host and whatever
//	    the output folder (see doc/release.md). It builds the checked-out
//	    tree, so it refuses one that is not exactly the commit it names.
//	qpot-release check-version -tag v0.1.0
//	    checks that the installers and the Makefile name the tag's version.
//	qpot-release verify -sums dist/SHA256SUMS dist/qpot_*
//	    checks files against a SHA256SUMS file, as the installers do.
//	qpot-release test-server -version 0.1.0 -unix-qpot FILE -ready FILE
//	    serves fake releases (good and tampered) on two loopback addresses
//	    for scripts/test-install.sh and scripts/test-install.ps1.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/release"
)

// Platforms a release ships, as the installers name them (the Makefile's
// PLATFORMS must list the same; a test checks).
var defaultPlatforms = "linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "pack":
		err = runPack(os.Args[2:])
	case "check-version":
		err = runCheckVersion(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "test-server":
		err = runTestServer(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "qpot-release:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: qpot-release pack|check-version|verify|test-server [flags] (see the package comment)")
	os.Exit(2)
}

func runCheckVersion(args []string) error {
	fs := flag.NewFlagSet("check-version", flag.ExitOnError)
	tag := fs.String("tag", "", "the release tag, e.g. v0.1.0")
	root := fs.String("root", ".", "the repository root")
	_ = fs.Parse(args)
	v, err := release.ParseTag(*tag)
	if err != nil {
		return err
	}
	if err := release.CheckVersions(v, func(p string) ([]byte, error) {
		return os.ReadFile(filepath.Join(*root, filepath.FromSlash(p))) // #nosec G304 -- fixed repository files
	}); err != nil {
		return err
	}
	fmt.Printf("%s matches %s\n", *tag, strings.Join(release.VersionFiles(), ", "))
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	sumsPath := fs.String("sums", "SHA256SUMS", "the checksum list")
	_ = fs.Parse(args)
	data, err := os.ReadFile(*sumsPath)
	if err != nil {
		return err
	}
	sums, err := release.ParseSums(data)
	if err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("no files to verify")
	}
	for _, p := range fs.Args() {
		f, err := os.Open(p) // #nosec G304 -- files named on the command line
		if err != nil {
			return err
		}
		verr := sums.Verify(filepath.Base(p), f)
		_ = f.Close()
		if verr != nil {
			return verr
		}
		fmt.Printf("%s: OK\n", filepath.Base(p))
	}
	return nil
}

func runPack(args []string) error {
	fs := flag.NewFlagSet("pack", flag.ExitOnError)
	ver := fs.String("version", "", "the release version, e.g. 0.1.0")
	out := fs.String("out", "dist", "output folder")
	platforms := fs.String("platforms", defaultPlatforms, "space-separated GOOS/GOARCH list")
	commit := fs.String("commit", "", "the commit being released (default: git rev-parse HEAD)")
	_ = fs.Parse(args)
	v, err := release.ParseVersion(*ver)
	if err != nil {
		return err
	}
	ctx := context.Background()
	if *commit == "" {
		c, err := gitOut(ctx, "rev-parse", "HEAD")
		if err != nil {
			return err
		}
		*commit = c
	}
	// Resolve abbreviated refs before embedding image references. The CLI's
	// display commit may be shortened, but registry tags must name the complete
	// revision whose images passed the publication gates.
	resolved, err := gitOut(ctx, "rev-parse", "--verify", "--end-of-options", *commit+"^{commit}")
	if err != nil {
		return err
	}
	*commit = resolved
	// The build compiles the files on disk, not the commit: they must be
	// the same thing, or the archives would name a commit they were not
	// built from. Untracked files (the output folder, a build cache) do not
	// enter a Go build and are not looked at.
	head, err := gitOut(ctx, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return err
	}
	if head != *commit {
		return fmt.Errorf("the checked-out commit is %s, not the release commit %s", head, *commit)
	}
	changed, err := gitOut(ctx, "status", "--porcelain", "--untracked-files=no")
	if err != nil {
		return err
	}
	if changed != "" {
		return fmt.Errorf("the working tree differs from commit %s:\n%s", *commit, changed)
	}
	// The commit's time stamps everything, so a rebuild of the same commit
	// gives the same bytes.
	epoch, err := gitOut(ctx, "log", "-1", "--format=%ct", *commit)
	if err != nil {
		return err
	}
	secs, err := strconv.ParseInt(epoch, 10, 64)
	if err != nil {
		return fmt.Errorf("commit time %q: %w", epoch, err)
	}
	mtime := time.Unix(secs, 0).UTC()
	extra, err := readExtras()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o750); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "qpot-release-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	sums := release.Sums{}
	for _, plat := range strings.Fields(*platforms) {
		goos, goarch, ok := strings.Cut(plat, "/")
		if !ok {
			return fmt.Errorf("bad platform %q", plat)
		}
		exe := "qpot"
		if goos == "windows" {
			exe = "qpot.exe"
		}
		bin := filepath.Join(tmp, goos+"_"+goarch, exe)
		short := *commit
		if len(short) > 12 {
			short = short[:12]
		}
		ldflags := fmt.Sprintf("-s -w -X main.version=%s -X main.commit=%s -X main.buildDate=%s -X github.com/qpot/qpot/internal/instance.HiFiImageRevision=%s",
			v, short, mtime.Format(time.RFC3339), *commit)
		// -buildvcs=false: Go would otherwise record whether the tree has
		// uncommitted or untracked files, and this very run creates some
		// (the output folder, when it is inside the repository). Releases
		// 1.0.0 and 1.0.1 were packed into ./dist, so every platform after
		// the first carries vcs.modified=true and only a rebuild into that
		// same folder reproduces them. The commit is embedded above.
		cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-buildvcs=false", "-ldflags", ldflags, "-o", bin, "./cmd/qpot")
		cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		fmt.Fprintf(os.Stderr, "building %s/%s\n", goos, goarch)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("go build for %s: %w", plat, err)
		}
		data, err := os.ReadFile(bin) // #nosec G304 -- the binary just built
		if err != nil {
			return err
		}
		files := append([]release.File{{Name: exe, Mode: 0o755, Data: data}}, extra...)
		var buf bytes.Buffer
		if goos == "windows" {
			err = release.Zip(&buf, files, mtime)
		} else {
			err = release.TarGz(&buf, files, mtime)
		}
		if err != nil {
			return err
		}
		name := release.ArchiveName(v, goos, goarch)
		if err := os.WriteFile(filepath.Join(*out, name), buf.Bytes(), 0o644); err != nil { // #nosec G306 -- release archives are public
			return err
		}
		d, _ := release.Digest(bytes.NewReader(buf.Bytes()))
		sums[name] = d
	}
	if len(sums) == 0 {
		return errors.New("no platforms")
	}
	if err := os.WriteFile(filepath.Join(*out, release.SumsName), sums.Format(), 0o644); err != nil { // #nosec G306 -- the public checksum list
		return err
	}
	fmt.Print(string(sums.Format()))
	return nil
}

// readExtras returns the files every archive carries besides the program.
func readExtras() ([]release.File, error) {
	var files []release.File
	for _, n := range []string{"LICENSE", "README.md"} {
		data, err := os.ReadFile(n) // #nosec G304 -- fixed repository files
		if err != nil {
			return nil, err
		}
		files = append(files, release.File{Name: n, Mode: 0o644, Data: data})
	}
	return files, nil
}

func gitOut(ctx context.Context, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(cctx, "git", args...)
	cmd.Stdout, cmd.Stderr = &out, io.Discard
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(out.String()), nil
}
