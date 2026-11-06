package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

// canaryCLIInstance saves an instance whose web UI is the given test server
// and returns its name.
func canaryCLIInstance(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	const name = "cnry-cli"
	cfg := config.Default(name)
	cfg.WebUI.BindAddr = "127.0.0.1"
	cfg.WebUI.Port = ts.Listener.Addr().(*net.TCPAddr).Port
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.DataPath, "qpot.id"), []byte("qp_abcdefghijklmnopqrstuvwx\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

// FuzzArtifactFileName: whatever header the answering server sends, the CLI
// writes a single file name in the working directory.
func FuzzArtifactFileName(f *testing.F) {
	for _, s := range []string{
		`attachment; filename="q4-salaries.html"`,
		`attachment; filename="../../.bashrc"`,
		`attachment; filename*=UTF-8''..%2F..%2Fx`,
		`attachment; filename="C:\\Windows\\x"`,
		`attachment; filename="a:b"`,
		`inline`, ``, `;;;`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, cd string) {
		const fallback = "cnry_x.html"
		got := artifactFileName(cd, fallback)
		if got == fallback {
			return
		}
		if got == "" || got == "." || got == ".." || strings.ContainsAny(got, "/\\:\x00") {
			t.Fatalf("artifactFileName(%q) = %q", cd, got)
		}
		if filepath.Base(got) != got || filepath.IsAbs(got) {
			t.Fatalf("artifactFileName(%q) = %q is not a plain name", cd, got)
		}
	})
}

// TestCanaryArtifactStaysInWorkingDir: `qpot canary artifact` named the output
// file after the server's Content-Disposition. Whatever answers on the web UI
// port (QPot is not running, another program holds it) could make it write
// anywhere the user can, e.g. ../.bashrc.
func TestCanaryArtifactStaysInWorkingDir(t *testing.T) {
	for _, cd := range []string{
		`attachment; filename="../escaped.html"`,
		`attachment; filename="sub/../../escaped.html"`,
		`attachment; filename="..\escaped.html"`,
		`attachment; filename=".."`,
	} {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Disposition", cd)
			_, _ = w.Write([]byte("<html>bait</html>"))
		}))
		name := canaryCLIInstance(t, ts)
		root := t.TempDir()
		work := filepath.Join(root, "work")
		if err := os.MkdirAll(filepath.Join(work, "sub"), 0o750); err != nil {
			t.Fatal(err)
		}
		t.Chdir(work)

		cmd := newCanaryArtifactCommand()
		cmd.SetArgs([]string{"cnry_0123456789abcdef01234567", "-i", name})
		err := cmd.Execute()
		ts.Close()

		if _, statErr := os.Stat(filepath.Join(root, "escaped.html")); statErr == nil {
			t.Fatalf("Content-Disposition %s wrote outside the working directory", cd)
		}
		if err != nil {
			continue // refusing is fine too
		}
		entries, _ := os.ReadDir(work)
		found := false
		for _, e := range entries {
			if !e.IsDir() {
				found = true
			}
		}
		if !found {
			t.Errorf("Content-Disposition %s: command succeeded but wrote no file in the working directory", cd)
		}
	}
}
