package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

// Operator-facing descriptions must retain the detection boundary rather than
// presenting a canary match as proof of compromise or an empirically low FP rate.
func TestCanaryDescriptionsStateDetectionLimits(t *testing.T) {
	cmd := newCanaryCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	descriptions := map[string]string{"CLI help": out.String()}
	for _, path := range []string{"README.md", "docs/canary.md", "doc/cli-reference.md"} {
		body, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		descriptions[path] = string(body)
	}
	for name, description := range descriptions {
		t.Run(name, func(t *testing.T) {
			text := strings.Join(strings.Fields(description), " ")
			for _, required := range []string{
				"has not been measured", "false-positive", "captured", "GET", "HEAD",
				"Reading a credential or file alone need not alert",
				"real AWS is not monitored",
				"No recorded trips does not prove no access occurred",
			} {
				if !strings.Contains(text, required) {
					t.Errorf("missing canary detection limitation %q", required)
				}
			}
			for _, claim := range []string{
				"near-zero-false-positive", "moment anyone touches",
				"alert on any interaction", "nobody has touched a canary",
			} {
				if strings.Contains(text, claim) {
					t.Errorf("unsupported canary claim %q", claim)
				}
			}
		})
	}
}

func TestCanaryEmptyTripsDoesNotRuleOutUnobservedAccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/canaries/trips" {
			t.Errorf("unexpected request path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"trips":[]}`))
	}))
	defer ts.Close()
	name := canaryCLIInstance(t, ts)
	cmd := newCanaryTripsCommand()
	cmd.SetArgs([]string{"-i", name})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "No trips recorded.") || !strings.Contains(out, "does not rule out access outside monitored events") {
		t.Fatalf("empty history must acknowledge the observation limit: %q", out)
	}
	if strings.Contains(out, "nobody has touched") {
		t.Fatalf("empty history incorrectly rules out unobserved access: %q", out)
	}
}

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
		if got == "" || got == "." || got == ".." || strings.ContainsAny(got, "/\\:\x00") ||
			!artifactNamePattern.MatchString(got) || strings.HasPrefix(got, ".") {
			t.Fatalf("artifactFileName(%q) = %q", cd, got)
		}
		if filepath.Base(got) != got || filepath.IsAbs(got) {
			t.Fatalf("artifactFileName(%q) = %q is not a plain name", cd, got)
		}
	})
}

// TestArtifactFileNameShape: the server's name is taken only in the shape QPot
// gives it; a hidden file, a device name Windows would open instead of a file,
// or anything else falls back to the canary's own name.
func TestArtifactFileNameShape(t *testing.T) {
	const fallback = "cnry_x.html"
	for cd, want := range map[string]string{
		`attachment; filename="Q4-salaries.html"`:  "Q4-salaries.html",
		`attachment; filename="document.html"`:     "document.html",
		`attachment; filename=".bashrc"`:           fallback,
		`attachment; filename="../.profile"`:       fallback,
		`attachment; filename="CON.html"`:          fallback,
		`attachment; filename="nul"`:               fallback,
		`attachment; filename="com1.txt"`:          fallback,
		`attachment; filename="report.html."`:      fallback,
		`attachment; filename="report .html"`:      fallback,
		`attachment; filename="a\x1b]52;c;x.html"`: fallback,
		`attachment; filename="CONSOLE.html"`:      "CONSOLE.html",
	} {
		if got := artifactFileName(cd, fallback); got != want {
			t.Errorf("artifactFileName(%s) = %q, want %q", cd, got, want)
		}
	}
}

// TestCanaryArtifactKeepsExistingFile: a name the server suggests never
// replaces a file already in the working directory; -o still may.
func TestCanaryArtifactKeepsExistingFile(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="notes.html"`)
		_, _ = w.Write([]byte("<html>bait</html>"))
	}))
	defer ts.Close()
	name := canaryCLIInstance(t, ts)
	work := t.TempDir()
	t.Chdir(work)
	if err := os.WriteFile("notes.html", []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := newCanaryArtifactCommand()
	cmd.SetArgs([]string{"cnry_0123456789abcdef01234567", "-i", name})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "-o") {
		t.Fatalf("overwriting an existing file: err = %v", err)
	}
	if got, _ := os.ReadFile("notes.html"); string(got) != "mine" {
		t.Fatalf("existing file now holds %q", got)
	}

	cmd = newCanaryArtifactCommand()
	cmd.SetArgs([]string{"cnry_0123456789abcdef01234567", "-i", name, "-o", "notes.html"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile("notes.html"); string(got) != "<html>bait</html>" {
		t.Fatalf("-o did not replace the file: %q", got)
	}
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
