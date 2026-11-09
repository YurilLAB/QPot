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
	git := "#!/bin/sh\ncase \"$1\" in\nrev-parse) printf '%s\\n' '" + revision + "';;\nlog) printf '%s\\n' 1761955200;;\n*) exit 9;;\nesac\n"
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
	if !strings.Contains(flags, "-X main.commit="+revision[:12]+" ") || !strings.Contains(flags, "-X github.com/qpot/qpot/internal/instance.HiFiImageRevision="+revision+"\n") {
		t.Fatalf("release did not embed the resolved full image revision separately from display metadata: %q", flags)
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
