package cicheck

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"errors"
	"flag"
	"fmt"
	"io"
	iofs "io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// ReviewedScanBaseline is the reviewed source revision before the stateful
// deception update. Never infer it from origin/main or HEAD^: fresh checkouts
// and release tags can otherwise silently omit the changes being released.
const ReviewedScanBaseline = "85791219d54574fca5d68c60dbbd474f5dfc195a"

const secretMemberLimit int64 = 256 << 20
const secretArchiveLimit int64 = 1 << 30

// RunSecretGateCommand runs the unsuppressed source or standalone release gate.
// The explicit config is the pinned Gitleaks upstream default configuration,
// never the repository's decoy allowlist. A scanner error or finding fails.
func RunSecretGateCommand(ctx context.Context, root, command string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(out)
	tool := fs.String("gitleaks", "", "absolute path to the pinned Gitleaks binary")
	config := fs.String("config", "", "pinned upstream default Gitleaks configuration")
	base := fs.String("base", ReviewedScanBaseline, "explicit reviewed source baseline")
	dir := fs.String("dir", "", "directory containing standalone release archives")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("secret gate does not accept positional arguments")
	}
	if out == nil {
		out = io.Discard
	}
	for label, path := range map[string]string{"scanner": *tool, "configuration": *config} {
		if !filepath.IsAbs(path) {
			return fmt.Errorf("secret gate requires an absolute %s path", label)
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("secret gate %s is missing or not a regular file", label)
		}
		if label == "scanner" && runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
			return errors.New("secret gate scanner is not executable")
		}
	}
	toolsData, err := os.ReadFile(filepath.Join(root, ".github", "ci-tools.env"))
	if err != nil {
		return errors.New("secret gate is missing its pinned tool manifest")
	}
	tools, err := ParseToolsEnv(toolsData)
	if err != nil || tools["GITLEAKS_VERSION"] == "" || tools["GITLEAKS_CONFIG_SHA256"] == "" {
		return errors.New("secret gate tool or default configuration pin is missing")
	}
	build, err := buildinfo.ReadFile(*tool)
	if err != nil || build.Main.Path != "github.com/zricethezav/gitleaks/v8" || build.Main.Version != "v"+strings.TrimPrefix(tools["GITLEAKS_VERSION"], "v") || build.Main.Replace != nil {
		return errors.New("secret gate scanner does not match the pinned Go module version")
	}
	configData, err := os.ReadFile(*config)
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(configData)) != tools["GITLEAKS_CONFIG_SHA256"] {
		return errors.New("secret gate configuration is not the pinned upstream default")
	}
	work, err := os.MkdirTemp("", "qpot-secret-gate-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	scanner := secretScanner{tool: *tool, config: *config, work: work, out: out}
	switch command {
	case "secrets-source":
		if *dir != "" {
			return errors.New("secrets-source does not accept -dir")
		}
		return scanner.source(ctx, root, *base)
	case "secrets-artifacts":
		if *dir == "" || *base != ReviewedScanBaseline {
			return errors.New("secrets-artifacts requires -dir and does not accept -base")
		}
		// Without go.sum nothing is proven and every checksum is scanned.
		if data, err := os.ReadFile(filepath.Join(root, "go.sum")); err == nil {
			scanner.moduleSums = goModuleSums(data)
		}
		return scanner.artifacts(ctx, *dir)
	default:
		return errors.New("unknown secret gate command")
	}
}

type secretScanner struct {
	tool, config, work string
	out                io.Writer
	// moduleSums is go.sum's module checksums, "path version" -> "h1:...".
	moduleSums map[string]string
}

// goModuleSums reads the module checksums in go.sum (not the go.mod ones).
func goModuleSums(data []byte) map[string]string {
	sums := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || strings.HasSuffix(f[1], "/go.mod") || !strings.HasPrefix(f[2], "h1:") {
			continue
		}
		sums[f[0]+" "+f[1]] = f[2]
	}
	return sums
}

// provenModuleSums lists the module checksums in a Go binary's embedded build
// info that equal go.sum's entry for that module and version. They are public
// hashes (sum.golang.org), yet Gitleaks' generic-api-key rule reads a line
// such as "aws-sdk-go-v2/credentials v1.20.13 h1:..." as a key. A file that is
// not a Go binary, or a checksum go.sum does not prove, gives nothing.
func provenModuleSums(binary string, sums map[string]string) []string {
	info, err := buildinfo.ReadFile(binary)
	if err != nil || len(sums) == 0 {
		return nil
	}
	var proven []string
	for _, dep := range info.Deps {
		for m := dep; m != nil; m = m.Replace {
			if m.Sum != "" && sums[m.Path+" "+m.Version] == m.Sum {
				proven = append(proven, m.Sum)
			}
		}
	}
	return proven
}

// maskProjection blanks each value in a text projection, keeping its length,
// and reports how many it blanked. Only exact strings are touched.
func maskProjection(path string, values []string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	masked := 0
	for _, v := range values {
		if v == "" {
			continue
		}
		masked += bytes.Count(data, []byte(v))
		data = bytes.ReplaceAll(data, []byte(v), bytes.Repeat([]byte(" "), len(v)))
	}
	if masked == 0 {
		return 0, nil
	}
	return masked, os.WriteFile(path, data, 0o600)
}

func (s secretScanner) scan(ctx context.Context, cwd, kind string, extra ...string) error {
	return s.scanInput(ctx, cwd, kind, nil, extra...)
}

func (s secretScanner) scanInput(ctx context.Context, cwd, kind string, input io.Reader, extra ...string) error {
	args := []string{kind, "--config", s.config, "--gitleaks-ignore-path", filepath.Join(s.work, "no-ignore-file"),
		"--ignore-gitleaks-allow", "--redact=100", "--no-banner", "--no-color", "--verbose", "--exit-code", "1"}
	args = append(args, extra...)
	if kind != "stdin" {
		args = append(args, ".")
	}
	cmd := exec.CommandContext(ctx, s.tool, args...) // #nosec G204 -- explicit pinned scanner, no shell
	cmd.Dir, cmd.Stdout, cmd.Stderr = cwd, s.out, s.out
	cmd.Stdin = input
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "GITLEAKS_") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	killGroup(cmd)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("unsuppressed %s secret scan failed: %w", kind, err)
	}
	return nil
}

func secretGit(ctx context.Context, root string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", root, "--literal-pathspecs"}, args...)...) // #nosec G204 -- fixed git subcommands, no shell
	killGroup(cmd)
	data, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("secret gate Git prerequisite failed: %w", err)
	}
	return data, nil
}

func (s secretScanner) source(ctx context.Context, root, base string) error {
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return err
	}
	top, err := secretGit(ctx, root, "rev-parse", "--show-toplevel")
	if err != nil {
		return err
	}
	topInfo, topErr := os.Stat(filepath.FromSlash(strings.TrimSpace(string(top))))
	rootInfo, rootErr := os.Stat(root)
	if topErr != nil || rootErr != nil || !os.SameFile(topInfo, rootInfo) {
		return errors.New("secret source root must be the repository top level")
	}
	resolved, err := secretGit(ctx, root, "rev-parse", "--verify", "--end-of-options", base+"^{commit}")
	if err != nil {
		return errors.New("reviewed secret baseline is missing; fetch full history")
	}
	base = strings.TrimSpace(string(resolved))
	if _, err := secretGit(ctx, root, "merge-base", "--is-ancestor", base, "HEAD"); err != nil {
		return errors.New("reviewed secret baseline is not an ancestor of HEAD")
	}
	head, err := secretGit(ctx, root, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(head)) != base {
		if err := s.scan(ctx, root, "git", "--log-opts="+base+"..HEAD"); err != nil {
			return err
		}
		if err := s.revisionBlobs(ctx, root, base); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(s.out, "reviewed baseline equals HEAD; checking working changes and untracked source")
	}
	diff, err := secretGit(ctx, root, "diff", "--no-ext-diff", "--no-renames", "--name-only", "-z", "--diff-filter=ACMT", base, "--")
	if err != nil {
		return err
	}
	untracked, err := secretGit(ctx, root, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return err
	}
	paths := make(map[string]bool)
	for _, p := range strings.Split(string(diff)+string(untracked), "\x00") {
		if p != "" {
			paths[p] = true
		}
	}
	stage := filepath.Join(s.work, "source")
	if err := os.Mkdir(stage, 0o700); err != nil {
		return err
	}
	// os.Root prevents a path race from redirecting a read outside the checkout.
	checkout, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer checkout.Close()
	names := make([]string, 0, len(paths))
	for name := range paths {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := secretCopySource(checkout, stage, name); err != nil {
			return err
		}
	}
	fmt.Fprintf(s.out, "unsuppressed working-source scan: %d changed/new files\n", len(names))
	if err := s.scan(ctx, stage, "dir"); err != nil {
		return err
	}
	return s.scanStagedInput(ctx, stage)
}

func (s secretScanner) scanStagedInput(ctx context.Context, stage string) error {
	// stdin scanning does not invoke Gitleaks' magic-byte binary detector.
	// A text projection can still contain TAR/PE signatures at fixed offsets,
	// so relying on its .txt name alone would silently skip some artifacts.
	return filepath.WalkDir(stage, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		scanErr := s.scanInput(ctx, stage, "stdin", f)
		closeErr := f.Close()
		if scanErr != nil {
			relative, relErr := filepath.Rel(stage, path)
			if relErr != nil {
				return scanErr
			}
			return fmt.Errorf("secret input %q: %w", relative, scanErr)
		}
		return closeErr
	})
}

// Git's textual diff scanner omits binary diffs, and path allowlists can omit
// otherwise textual files. Inspect the new blob versions too, including files
// removed by a later commit, rather than relying only on the final checkout.
func (s secretScanner) revisionBlobs(ctx context.Context, root, base string) error {
	baselineTree, err := secretGit(ctx, root, "ls-tree", "-r", "-z", base)
	if err != nil {
		return err
	}
	baseline := make(map[string]string)
	for _, record := range strings.Split(string(baselineTree), "\x00") {
		if record == "" {
			continue
		}
		header, path, found := strings.Cut(record, "\t")
		fields := strings.Fields(header)
		if !found || len(fields) != 3 {
			return errors.New("reviewed baseline tree could not be parsed")
		}
		if fields[1] == "blob" {
			baseline[path] = fields[2]
		}
	}
	commits, err := secretGit(ctx, root, "log", "--no-color", "--no-decorate", "--format=%H", base+"..HEAD", "--")
	if err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, commit := range strings.Fields(string(commits)) {
		paths, err := secretGit(ctx, root, "diff-tree", "--root", "--no-commit-id", "-r", "-m", "--name-only", "-z", "--diff-filter=ACMT", commit, "--")
		if err != nil {
			return err
		}
		for _, path := range strings.Split(string(paths), "\x00") {
			if path == "" {
				continue
			}
			entry, err := secretGit(ctx, root, "ls-tree", "-z", commit, "--", path)
			if err != nil {
				return err
			}
			header, _, found := strings.Cut(string(entry), "\t")
			fields := strings.Fields(header)
			if !found || len(fields) != 3 || fields[1] != "blob" {
				return errors.New("new revision contains an unsupported nonregular source object")
			}
			object := fields[2]
			// A merge can list unchanged baseline bytes against another parent.
			// The path is part of this decision: copying an old blob to a new
			// location must still be scanned as new source.
			if baseline[path] == object {
				continue
			}
			if fields[0] != "100644" && fields[0] != "100755" {
				return errors.New("new revision contains an unsupported nonregular source object")
			}
			if seen[object] {
				continue
			}
			seen[object] = true
			sizeBytes, err := secretGit(ctx, root, "cat-file", "-s", object)
			if err != nil {
				return err
			}
			size, err := strconv.ParseInt(strings.TrimSpace(string(sizeBytes)), 10, 64)
			if err != nil || size < 0 || size > secretMemberLimit {
				return errors.New("new revision contains an oversized source blob")
			}
			data, err := secretGit(ctx, root, "cat-file", "blob", object)
			if err != nil || int64(len(data)) != size {
				return errors.New("new revision blob could not be read completely")
			}
			fmt.Fprintf(s.out, "unsuppressed revision blob: %s\n", object)
			if err := s.scanInput(ctx, s.work, "stdin", bytes.NewReader(data)); err != nil {
				return err
			}
		}
	}
	return nil
}

func secretCopySource(root *os.Root, stage, name string) error {
	if !filepath.IsLocal(name) || strings.ContainsRune(name, '\x00') {
		return fmt.Errorf("unsafe source path %q", name)
	}
	var info os.FileInfo
	for i := range strings.Split(filepath.Clean(name), string(filepath.Separator)) {
		parts := strings.Split(filepath.Clean(name), string(filepath.Separator))[:i+1]
		var err error
		info, err = root.Lstat(filepath.Join(parts...))
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("source path %q is missing or traverses a symlink", name)
		}
	}
	if !info.Mode().IsRegular() || info.Size() > secretMemberLimit {
		return fmt.Errorf("source path %q is not a bounded regular file", name)
	}
	in, err := root.Open(name)
	if err != nil {
		return err
	}
	defer in.Close()
	opened, err := in.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return fmt.Errorf("source path %q changed while opening", name)
	}
	dst := filepath.Join(stage, name)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(out, io.LimitReader(in, secretMemberLimit+1))
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil || n != info.Size() || n > secretMemberLimit {
		return fmt.Errorf("source path %q changed or could not be copied completely", name)
	}
	return nil
}

func (s secretScanner) artifacts(ctx context.Context, dir string) error {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	archiveRoot, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer archiveRoot.Close()
	entries, err := iofs.ReadDir(archiveRoot.FS(), ".")
	if err != nil {
		return err
	}
	stage := filepath.Join(s.work, "artifacts")
	if err := os.Mkdir(stage, 0o700); err != nil {
		return err
	}
	count, masked := 0, 0
	var total int64
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".tar.gz") && !strings.HasSuffix(name, ".zip") {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("release archive is a symlink")
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > secretArchiveLimit {
			return errors.New("release archive is not a bounded regular file")
		}
		// Do not retain a .zip/.exe suffix on staging directories: Gitleaks'
		// default path allowlist applies to directories and would skip children.
		project := filepath.Join(stage, fmt.Sprintf("archive-%d", count))
		if err := os.Mkdir(project, 0o700); err != nil {
			return err
		}
		// Scan printable container bytes too, including ZIP comments and a
		// self-extracting prefix that is outside the decoded member streams.
		container, err := archiveRoot.Open(name)
		if err != nil {
			return err
		}
		projection, err := os.OpenFile(filepath.Join(project, "container.txt"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			_ = container.Close()
			return err
		}
		n, projectErr := secretProjectText(projection, io.LimitReader(container, secretArchiveLimit+1))
		inClose, outClose := container.Close(), projection.Close()
		if projectErr != nil || inClose != nil || outClose != nil || n != info.Size() || total+n > secretArchiveLimit {
			return errors.New("release archive changed or exceeds the complete scan budget")
		}
		total += n
		if strings.HasSuffix(name, ".tar.gz") {
			// PAX records and TAR metadata are compressed in the container and
			// are not part of a decoded member's body. Inspect that stream too.
			compressed, err := archiveRoot.Open(name)
			if err != nil {
				return err
			}
			gz, err := gzip.NewReader(compressed)
			if err != nil {
				_ = compressed.Close()
				return err
			}
			text, err := os.OpenFile(filepath.Join(project, "tar-container.txt"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				_ = gz.Close()
				_ = compressed.Close()
				return err
			}
			n, projectErr := secretProjectText(text, io.LimitReader(gz, secretArchiveLimit-total+1))
			gzClose, inClose, outClose := gz.Close(), compressed.Close(), text.Close()
			if projectErr != nil || gzClose != nil || inClose != nil || outClose != nil || total+n > secretArchiveLimit {
				return errors.New("TAR stream is corrupt or exceeds the complete scan budget")
			}
			total += n
		}
		members := 0
		seen := make(map[string]bool)
		var proven []string
		emit := func(name string, size int64, input io.Reader) error {
			if !filepath.IsLocal(name) || name == "." || filepath.Base(name) != name || strings.ContainsAny(name, "/\\") || size < 0 || size > secretMemberLimit || total+size > secretArchiveLimit {
				return errors.New("invalid, nested, or oversized standalone release member")
			}
			if seen[name] {
				return errors.New("duplicate standalone release member")
			}
			seen[name] = true
			total += size
			// Upstream path filters must not skip names such as gitleaks.toml.
			f, err := os.OpenFile(filepath.Join(project, fmt.Sprintf("member-%d.txt", members)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return errors.New("duplicate or unwritable standalone release member")
			}
			// The raw bytes, outside the scanned stage, only to read Go build
			// info from; the scan itself reads the projection.
			rawPath := filepath.Join(s.work, fmt.Sprintf("raw-%d-%d", count, members))
			raw, err := os.OpenFile(rawPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				_ = f.Close()
				return errors.New("unwritable standalone release member copy")
			}
			n, projectErr := secretProjectText(f, io.TeeReader(io.LimitReader(input, size+1), raw))
			closeErr, rawErr := f.Close(), raw.Close()
			if projectErr != nil || closeErr != nil || rawErr != nil || n != size {
				_ = os.Remove(rawPath)
				return errors.New("release member is corrupt or could not be read completely")
			}
			proven = append(proven, provenModuleSums(rawPath, s.moduleSums)...)
			if err := os.Remove(rawPath); err != nil {
				return err
			}
			members++
			return nil
		}
		archive, err := archiveRoot.Open(name)
		if err != nil {
			return err
		}
		readErr := secretReadArchiveFile(archive, strings.HasSuffix(name, ".zip"), emit)
		closeErr := archive.Close()
		if readErr != nil {
			return fmt.Errorf("secret scan archive %q: %w", name, readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("secret scan archive %q: %w", name, closeErr)
		}
		if members == 0 {
			return errors.New("standalone release archive has no regular members")
		}
		// A member's bytes are also in the archive's own projections (the
		// decoded TAR stream, a stored ZIP entry): blank the same proven
		// checksums in every projection of this archive.
		if len(proven) > 0 {
			projections, err := os.ReadDir(project)
			if err != nil {
				return err
			}
			for _, p := range projections {
				n, err := maskProjection(filepath.Join(project, p.Name()), proven)
				if err != nil {
					return err
				}
				masked += n
			}
		}
		count++
	}
	if count == 0 {
		return errors.New("secret artifact gate found no standalone release archives")
	}
	fmt.Fprintf(s.out, "unsuppressed standalone artifact scan: %d archives, %d container/member bytes\n", count, total)
	if masked > 0 {
		fmt.Fprintf(s.out, "left out %d Go module checksums from embedded build info, each equal to go.sum's for its module and version\n", masked)
	}
	return s.scanStagedInput(ctx, stage)
}

// Project bytes into a text file so Gitleaks' binary/.exe exclusions cannot
// silently skip a shipped executable. Compression/encryption is not decoded
// recursively; this gate inspects the release's actual top-level members.
func secretProjectText(out io.Writer, input io.Reader) (int64, error) {
	buf := make([]byte, 32<<10)
	var total int64
	for {
		n, err := input.Read(buf)
		for i, b := range buf[:n] {
			if (b < 32 || b > 126) && b != '\n' && b != '\r' && b != '\t' {
				buf[i] = ' '
			}
		}
		if n > 0 {
			written, writeErr := out.Write(buf[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

func secretReadArchive(path string, emit func(string, int64, io.Reader) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return secretReadArchiveFile(f, strings.HasSuffix(path, ".zip"), emit)
}

func secretReadArchiveFile(f *os.File, isZIP bool, emit func(string, int64, io.Reader) error) error {
	if isZIP {
		info, err := f.Stat()
		if err != nil {
			return err
		}
		z, err := zip.NewReader(f, info.Size())
		if err != nil {
			return err
		}
		for _, f := range z.File {
			if !f.Mode().IsRegular() || f.UncompressedSize64 > uint64(secretMemberLimit) {
				return errors.New("unsupported standalone ZIP member")
			}
			r, err := f.Open()
			if err != nil {
				return err
			}
			err = emit(f.Name, int64(f.UncompressedSize64), r)
			closeErr := r.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
		}
		return nil
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			// Verify the gzip trailer and refuse uninspected appended members.
			var tail [1]byte
			n, tailErr := io.ReadFull(gz, tail[:])
			if n != 0 {
				return errors.New("standalone TAR has trailing uninspected data")
			}
			if tailErr == io.EOF {
				return nil
			}
			return tailErr
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg {
			return errors.New("unsupported standalone TAR member")
		}
		if err := emit(h.Name, h.Size, tr); err != nil {
			return err
		}
	}
}
