package cicheck

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func readRepo(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The tools file must set these; ci.yml's jobs and ci-local use them.
var requiredTools = []string{
	"GOVULNCHECK_VERSION", "GOSEC_VERSION", "STATICCHECK_VERSION", "ACTIONLINT_VERSION",
	"GITLEAKS_VERSION", "SHELLCHECK_VERSION", "SHELLCHECK_SHA256", "GOSEC_EXCLUDES",
}

var ruleListRe = regexp.MustCompile(`G[0-9]{3}\s*,\s*G[0-9]{3}`)

// toolsDrift lists where ci.yml or ci-local.sh stops sharing the tools file:
// a copy of a value, a gosec rule list, a workflow-level version, a key CI
// never uses, or a job that uses a key before loading the file.
func toolsDrift(tools map[string]string, ciYML, ciLocal []byte) []string {
	var bad []string
	for _, k := range requiredTools {
		if tools[k] == "" {
			bad = append(bad, "ci-tools.env does not set "+k)
		}
	}
	for name, text := range map[string]string{"ci.yml": string(ciYML), "ci-local.sh": string(ciLocal)} {
		for k, v := range tools {
			if strings.Contains(text, v) {
				bad = append(bad, name+" keeps its own copy of "+k+" ("+v+")")
			}
		}
		if ruleListRe.MatchString(text) {
			bad = append(bad, name+" lists gosec rules itself: "+ruleListRe.FindString(text))
		}
	}
	w, err := ParseWorkflow(ciYML)
	if err != nil {
		return append(bad, "ci.yml: "+err.Error())
	}
	for k := range w.Env {
		if _, ok := tools[k]; ok || strings.HasSuffix(k, "_VERSION") {
			bad = append(bad, "ci.yml sets "+k+" at workflow level")
		}
	}
	used := map[string]bool{}
	for _, j := range w.Jobs {
		for k := range j.Env {
			if _, ok := tools[k]; ok {
				bad = append(bad, "job "+j.ID+" sets "+k+" itself")
			}
		}
		loaded := false
		for _, s := range j.Steps {
			text := s.Run
			for _, v := range s.Env {
				text += "\n" + v
			}
			for k := range tools {
				if !strings.Contains(text, "$"+k) && !strings.Contains(text, "${"+k) && !strings.Contains(text, "env."+k) {
					continue
				}
				used[k] = true
				if !loaded {
					bad = append(bad, "job "+j.ID+" step "+s.Label()+" uses "+k+" before loading ci-tools.env")
				}
			}
			if strings.Contains(s.Run, ".github/ci-tools.env") && strings.Contains(s.Run, "GITHUB_ENV") {
				loaded = true
			}
		}
	}
	for k := range tools {
		if !used[k] {
			bad = append(bad, "ci.yml never uses "+k)
		}
	}
	if !strings.Contains(string(ciLocal), "cicheck/cirun") {
		bad = append(bad, "ci-local.sh does not run the workflow through internal/cicheck/cirun")
	}
	return bad
}

// TestCIAndCILocalShareTheToolsFile: the tool versions and gosec's exclude
// list are set in .github/ci-tools.env only, every ci.yml job loads it
// before using them, and ci-local runs the jobs themselves.
func TestCIAndCILocalShareTheToolsFile(t *testing.T) {
	tools, err := ParseToolsEnv(readRepo(t, ".github/ci-tools.env"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range toolsDrift(tools, readRepo(t, ".github/workflows/ci.yml"), readRepo(t, "scripts/ci-local.sh")) {
		t.Error(p)
	}
}

// TestToolsDriftCatchesCopies is the negative control for the test above:
// each way of keeping a second copy is reported.
func TestToolsDriftCatchesCopies(t *testing.T) {
	tools, err := ParseToolsEnv(readRepo(t, ".github/ci-tools.env"))
	if err != nil {
		t.Fatal(err)
	}
	ci := string(readRepo(t, ".github/workflows/ci.yml"))
	local := readRepo(t, "scripts/ci-local.sh")
	load := "grep -E '^[A-Z][A-Z0-9_]*=' .github/ci-tools.env >> \"$GITHUB_ENV\""
	mutants := map[string]string{
		"workflow env":         strings.Replace(ci, "\njobs:\n", "\nenv:\n  GOSEC_VERSION: "+tools["GOSEC_VERSION"]+"\n\njobs:\n", 1),
		"literal exclude list": strings.Replace(ci, `-exclude="$GOSEC_EXCLUDES"`, `-exclude="`+tools["GOSEC_EXCLUDES"]+`"`, 1),
		"other rule list":      strings.Replace(ci, `-exclude="$GOSEC_EXCLUDES"`, `-exclude="G104,G204"`, 1),
		"literal version":      strings.Replace(ci, "@${STATICCHECK_VERSION}", "@"+tools["STATICCHECK_VERSION"], 1),
		"no loader":            strings.Replace(ci, load, "true", 1),
	}
	for name, m := range mutants {
		if m == ci {
			t.Fatalf("%s: the mutation did not apply", name)
		}
		if len(toolsDrift(tools, []byte(m), local)) == 0 {
			t.Errorf("%s: not reported", name)
		}
	}
	if len(toolsDrift(tools, []byte(ci), []byte(string(local)+"\nGOSEC_EXCLUDES="+tools["GOSEC_EXCLUDES"]+"\n"))) == 0 {
		t.Error("a copy in ci-local.sh is not reported")
	}
	extra := map[string]string{"UNUSED_VERSION": "v9.9.9"}
	for k, v := range tools {
		extra[k] = v
	}
	if len(toolsDrift(extra, []byte(ci), local)) == 0 {
		t.Error("a key CI never uses is not reported")
	}
}

// TestRunnerHandlesEveryJob: ci-local can run every Linux job of ci.yml as
// written (every action it uses has a local equivalent, every expression a
// local value), and the others are the Windows jobs it reports as not run.
func TestRunnerHandlesEveryJob(t *testing.T) {
	w, err := ParseWorkflow(readRepo(t, ".github/workflows/ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	r := &Runner{Root: ".", Out: os.Stderr}
	local := 0
	for _, j := range w.Jobs {
		if err := r.Check(w, j); err != nil {
			t.Error(err)
		}
		if j.Local() {
			local++
		} else if !strings.HasPrefix(j.RunsOn, "windows-") {
			t.Errorf("job %s runs on %s, which ci-local neither runs nor reports", j.ID, j.RunsOn)
		}
	}
	if local < 10 {
		t.Errorf("only %d Linux jobs", local)
	}
}

func TestCheckRefusesWhatItCannotRun(t *testing.T) {
	w := &Workflow{}
	r := &Runner{}
	for name, s := range map[string]Step{
		"unknown action": {Uses: "someone/deploy@v1"},
		"other shell":    {Run: "Get-Date", Shell: "pwsh"},
		"conditional":    {Run: "true", If: "github.event_name == 'push'"},
		"secret":         {Run: "echo ${{ secrets.TOKEN }}"},
		"unknown matrix": {Run: "echo ${{ matrix.nope }}"},
	} {
		j := Job{ID: "j", RunsOn: "ubuntu-latest", Steps: []Step{s}}
		if err := r.Check(w, j); err == nil {
			t.Errorf("%s: accepted", name)
		}
		j.RunsOn = "windows-latest"
		if err := r.Check(w, j); err != nil {
			t.Errorf("%s on Windows (not run locally): %v", name, err)
		}
		if err := r.RunJob(context.Background(), w, j); err == nil {
			t.Errorf("%s: RunJob ran a Windows job", name)
		}
	}
}

func TestParseToolsEnv(t *testing.T) {
	got, err := ParseToolsEnv([]byte("# c\n\nA_VERSION=v1.2.3\r\nB=G1,G2\n"))
	if err != nil || got["A_VERSION"] != "v1.2.3" || got["B"] != "G1,G2" || len(got) != 2 {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"a=1\n", "A\n", "A=\n", "A=1 2\n", "A=$(x)\n", "A=\"1\"\n", "A=1\nA=2\n", " A=1\n", "A=1;b\n"} {
		if _, err := ParseToolsEnv([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func FuzzParseToolsEnv(f *testing.F) {
	f.Add("A=1\n# x\nB_C=v1.2-3+4,5\n")
	f.Add("A=1\nA=2\n")
	f.Fuzz(func(t *testing.T, in string) {
		m, err := ParseToolsEnv([]byte(in))
		if err != nil {
			return
		}
		// What it accepts means the same as a $GITHUB_ENV file and to a shell.
		var b strings.Builder
		for k, v := range m {
			if strings.ContainsAny(v, " \t\n\"'$`\\;&|<>()") || v == "" || strings.ContainsAny(k, "=\n") {
				t.Fatalf("accepted %s=%q", k, v)
			}
			b.WriteString(k + "=" + v + "\n")
		}
		back, err := parseEnvFile(b.String())
		if err != nil || len(back) != len(m) {
			t.Fatalf("$GITHUB_ENV reading of %v: %v, %v", m, back, err)
		}
	})
}

func TestParseEnvFile(t *testing.T) {
	got, err := parseEnvFile("A=1\nB<<EOF\nx\ny=z\nEOF\n\nC=a=b\n")
	if err != nil || got["A"] != "1" || got["B"] != "x\ny=z" || got["C"] != "a=b" {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"B<<EOF\nx\n", "novalue\n", "=1\n"} {
		if _, err := parseEnvFile(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestExpand(t *testing.T) {
	got, err := Expand("go ${{ matrix.go }} ${{env.X}}", map[string]string{"go": "1.26"}, map[string]string{"X": "y"})
	if err != nil || got != "go 1.26 y" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := Expand("${{ secrets.T }}", nil, nil); err == nil {
		t.Error("a secret expanded")
	}
}

// TestRunJobLikeActions runs a small workflow through bash: $GITHUB_ENV and
// $GITHUB_PATH reach later steps, a failure skips the rest except
// if: always(), and the job fails.
func TestRunJobLikeActions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ci-local runs on Linux, as CI does")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	w := &Workflow{Env: map[string]string{"TOP": "top"}}
	j := Job{ID: "j", RunsOn: "ubuntu-latest", Matrix: []map[string]string{{"n": "1"}, {"n": "2"}}, Steps: []Step{
		{Run: "echo FROM_STEP=hello >> \"$GITHUB_ENV\"\necho " + bin + " >> \"$GITHUB_PATH\"\nprintf '#!/bin/sh\\necho tool-ran\\n' > " + bin + "/qpot-ci-tool\nchmod +x " + bin + "/qpot-ci-tool"},
		{Run: "test \"$FROM_STEP\" = hello\ntest \"$TOP\" = top\ntest \"$CI\" = true\nqpot-ci-tool\ntest ${{ matrix.n }} = 1"},
		{Run: "echo should-not-run > " + dir + "/skipped-${{ matrix.n }}"},
		{Run: "echo ran > " + dir + "/always-${{ matrix.n }}", If: "always()"},
	}}
	var out strings.Builder
	r := &Runner{Root: dir, Out: &out, Env: os.Environ()}
	err := r.RunJob(context.Background(), w, j)
	if err == nil || !strings.Contains(err.Error(), "n=2") || strings.Contains(err.Error(), "n=1") {
		t.Fatalf("RunJob = %v (want only the n=2 entry to fail)\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "tool-ran") {
		t.Errorf("$GITHUB_PATH did not reach the next step\n%s", out.String())
	}
	for _, f := range []string{"always-1", "always-2", "skipped-1"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s missing", f)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "skipped-2")); err == nil {
		t.Error("a step after a failure ran")
	}
}
