package instance

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// stubCase is one command run by testdata/cowrie_stub.py (its docstring
// lists the keys).
type stubCase map[string]any

// stubResult is what the stub reports for one case.
type stubResult struct {
	Stdout  string           `json:"stdout"`
	Stderr  string           `json:"stderr"`
	Code    *int             `json:"code"`
	Seconds float64          `json:"seconds"`
	Events  []map[string]any `json:"events"`
	Lookups []string         `json:"lookups"`
	Fetches []struct {
		URL          string              `json:"url"`
		Method       string              `json:"method"`
		Headers      map[string][]string `json:"headers"`
		Timeout      float64             `json:"timeout"`
		MaxRedirects int                 `json:"max_redirects"`
		Address      string              `json:"address"`
	} `json:"fetches"`
	Connects []struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	} `json:"connects"`
	Files map[string]struct {
		Size  int64   `json:"size"`
		Mode  int     `json:"mode"`
		Mtime float64 `json:"mtime"`
		UID   int     `json:"uid"`
		B64   string  `json:"b64"`
	} `json:"files"`
	CPU           float64    `json:"cpu"`
	Peak          int64      `json:"peak"`
	Typeahead     []string   `json:"typeahead"`
	Exec          [][]string `json:"exec"`
	Exited        bool       `json:"exited"`
	PasswordInput bool       `json:"password_input"`
	Error         string     `json:"error"`
	Trace         string     `json:"trace"`
}

// code is the exit status, -1 when the command never exited.
func (r stubResult) code() int {
	if r.Code == nil {
		return -1
	}
	return *r.Code
}

// stubPatchFiles are the patch layer's modules the stub loads.
func stubPatchFiles() map[string][]byte {
	return map[string][]byte{"qpot_bait.py": cowrieQPotBaitPy, "coreutils.py": cowrieCoreutilsPy,
		"curl.py": cowrieCurlPy, "wget.py": cowrieWgetPy, "ssh.py": cowrieSSHPy, "ls.py": cowrieLsPy}
}

// runCowrieStub runs the cases through the patch layer's commands with the
// stubbed Cowrie (the files are written out, so the harness also runs with
// the image's own Python in a chroot that sees only the temp dir).
func runCowrieStub(t *testing.T, cases []stubCase) []stubResult {
	t.Helper()
	return runCowrieStubWith(t, stubPatchFiles(), cases)
}

func runCowrieStubWith(t *testing.T, files map[string][]byte, cases []stubCase) []stubResult {
	t.Helper()
	py := python(t)
	dir := t.TempDir()
	patch := filepath.Join(dir, "patch")
	if err := os.Mkdir(patch, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(patch, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stub, err := os.ReadFile(filepath.Join("testdata", "cowrie_stub.py"))
	if err != nil {
		t.Fatal(err)
	}
	specJSON, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{"cowrie_stub.py": stub, "cases.json": specJSON} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(py, "-I", filepath.Join(dir, "cowrie_stub.py"), patch, filepath.Join(dir, "cases.json"))
	// UTC (a POSIX TZ string, which Windows' C runtime reads too), so dates are the same everywhere
	cmd.Env = append(os.Environ(), "TZ=UTC0")
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if exit, ok := err.(*exec.ExitError); ok {
			stderr = string(exit.Stderr)
		}
		t.Fatalf("stub: %v\n%s\n%s", err, out, stderr)
	}
	var results []stubResult
	if err := json.Unmarshal(out, &results); err != nil || len(results) != len(cases) {
		t.Fatalf("stub output (%v, %d of %d results): %.2000s", err, len(results), len(cases), out)
	}
	for i, r := range results {
		if r.Error != "" {
			t.Fatalf("case %d %v: %s\n%s", i, cases[i]["argv"], r.Error, r.Trace)
		}
	}
	return results
}

// stubMillis is the elapsed time in curl's and ssh's messages, which varies
// as the real tools' does; the tests compare the rest of the text.
var stubMillis = regexp.MustCompile(`after [0-9]+ (ms|milliseconds)`)

func stubNormal(s string) string {
	return stubMillis.ReplaceAllString(s, "after N $1")
}

// stubWant is the real tool's output for a case, recorded where its notes say.
type stubWant struct {
	stdout, stderr string
	code           int
	seconds        float64 // the virtual time the command took; -1: not checked
}

// checkStub compares a result with the real tool's output.
func checkStub(t *testing.T, label string, got stubResult, want stubWant) {
	t.Helper()
	if stubNormal(got.Stdout) != stubNormal(want.stdout) || stubNormal(got.Stderr) != stubNormal(want.stderr) ||
		got.code() != want.code {
		t.Errorf("%s:\n got  code %d out %q err %q\n want code %d out %q err %q", label, got.code(), got.Stdout,
			got.Stderr, want.code, want.stdout, want.stderr)
	}
	if want.seconds >= 0 && (got.Seconds < want.seconds-0.05 || got.Seconds > want.seconds+0.05) {
		t.Errorf("%s: took %.2f s, want %.2f s", label, got.Seconds, want.seconds)
	}
}

// argvLabel is a case's command line for messages.
func argvLabel(c stubCase) string {
	if argv, ok := c["argv"].([]string); ok {
		return strings.Join(argv, " ")
	}
	return "?"
}
