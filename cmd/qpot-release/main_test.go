package main

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestPackEmbedsResolvedImageRevision(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Linux release builder uses these subprocess controls")
	}
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	revision := strings.Repeat("1234567890", 4)
	// status prints what the file "dirty" holds: nothing, for a clean tree.
	git := "#!/bin/sh\ncase \"$1\" in\nrev-parse) if [ \"$3\" = 'HEAD^{commit}' ] && [ -f other-head ]; then cat other-head; else printf '%s\\n' '" + revision + "'; fi;;\n" +
		"log) printf '%s\\n' 1761955200;;\nstatus) [ ! -f dirty ] || cat dirty;;\n*) exit 9;;\nesac\n"
	goTool := `#!/bin/sh
target=''
previous=''
for arg in "$@"; do
  if [ "$previous" = '-o' ]; then target=$arg; fi
  previous=$arg
done
[ -n "$target" ] || exit 8
mkdir -p "$(dirname "$target")" || exit 7
printf '%s\n' "$@" > "$target"
`
	for name, data := range map[string]string{"git": git, "go": goTool} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(data), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"LICENSE", "README.md"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("release fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Chdir(root)
	if err := runPack([]string{"-version", "0.1.0", "-commit", revision[:8], "-platforms", "linux/amd64", "-out", "dist"}); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(root, "dist", "qpot_0.1.0_linux_amd64.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	h, err := tr.Next()
	if err != nil || h.Name != "qpot" {
		t.Fatalf("release program: %v %v", h, err)
	}
	data, err := io.ReadAll(tr)
	if err != nil {
		t.Fatal(err)
	}
	flags := string(data)
	// Without it Go records the state of the working tree in the program,
	// and the output folder of this very run changes that state.
	if !strings.Contains(flags, "-buildvcs=false\n") || !strings.Contains(flags, "-trimpath\n") {
		t.Errorf("release build does not pass -trimpath and -buildvcs=false: %q", flags)
	}
	if !strings.Contains(flags, "-X main.commit="+revision[:12]+" ") || !strings.Contains(flags, "-X github.com/qpot/qpot/internal/instance.HiFiImageRevision="+revision+"\n") {
		t.Fatalf("release did not embed the resolved full image revision separately from display metadata: %q", flags)
	}
}

// TestPackRefusesATreeThatIsNotTheCommit: pack compiles the files on disk, so
// it must not label them with a commit they differ from.
func TestPackRefusesATreeThatIsNotTheCommit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Linux release builder uses these subprocess controls")
	}
	revision := strings.Repeat("1234567890", 4)
	for name, plant := range map[string]func(root string) error{
		"tracked file changed": func(root string) error {
			return os.WriteFile(filepath.Join(root, "dirty"), []byte(" M cmd/qpot/main.go\n"), 0o600)
		},
		"another commit checked out": func(root string) error {
			return os.WriteFile(filepath.Join(root, "other-head"), []byte(strings.Repeat("a", 40)+"\n"), 0o600)
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			if err := os.Mkdir(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			git := "#!/bin/sh\ncase \"$1\" in\nrev-parse) if [ \"$3\" = 'HEAD^{commit}' ] && [ -f other-head ]; then cat other-head; else printf '%s\\n' '" + revision + "'; fi;;\n" +
				"log) printf '%s\\n' 1761955200;;\nstatus) [ ! -f dirty ] || cat dirty;;\n*) exit 9;;\nesac\n"
			built := filepath.Join(root, "go-was-run")
			for tool, data := range map[string]string{"git": git, "go": "#!/bin/sh\n: > '" + built + "'\nexit 1\n"} {
				if err := os.WriteFile(filepath.Join(bin, tool), []byte(data), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for _, extra := range []string{"LICENSE", "README.md"} {
				if err := os.WriteFile(filepath.Join(root, extra), []byte("release fixture\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := plant(root); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Chdir(root)
			err := runPack([]string{"-version", "0.1.0", "-commit", revision, "-platforms", "linux/amd64", "-out", "dist"})
			if err == nil {
				t.Fatal("pack built a tree that is not the commit it names")
			}
			if _, statErr := os.Stat(built); statErr == nil {
				t.Errorf("pack started a build before refusing: %v", err)
			}
		})
	}
}

// TestPlatformsMatchMakefile: `make build-all` and the release build the
// same platforms, so the installers find an archive for each one the
// Makefile builds.
func TestPlatformsMatchMakefile(t *testing.T) {
	data, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^PLATFORMS = (.+)$`).FindSubmatch(data)
	if m == nil {
		t.Fatal("no PLATFORMS line in the Makefile")
	}
	if got := strings.Join(strings.Fields(string(m[1])), " "); got != defaultPlatforms {
		t.Fatalf("Makefile PLATFORMS %q, qpot-release builds %q", got, defaultPlatforms)
	}
}
