package release

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	shPinRe  = regexp.MustCompile(`(?m)^QPOT_SOURCE_COMMIT_PINNED="([^"\n]*)"`)
	ps1PinRe = regexp.MustCompile(`(?m)^\$QPOT_SOURCE_COMMIT_PINNED = "([^"\n]*)"`)
	commitRe = regexp.MustCompile(`^[0-9a-f]{40}$`)
	usesRe   = regexp.MustCompile(`(?m)^\s*(?:-\s+)?uses:\s*(\S+)`)
	pinnedRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$`)
)

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(repoFile(t, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// pinDrift lists what is wrong with the installers' source pins: each must
// pin exactly one full commit hash, and both the same one.
func pinDrift(sh, ps1 string) []string {
	var bad []string
	ms, mp := shPinRe.FindAllStringSubmatch(sh, -1), ps1PinRe.FindAllStringSubmatch(ps1, -1)
	if len(ms) != 1 || len(mp) != 1 {
		return append(bad, "each installer must set its source pin exactly once")
	}
	for who, v := range map[string]string{"install.sh": ms[0][1], "install.ps1": mp[0][1]} {
		if !commitRe.MatchString(v) {
			bad = append(bad, who+" pins "+strconvQuote(v)+", not a full commit hash")
		}
	}
	if ms[0][1] != mp[0][1] {
		bad = append(bad, "install.sh pins "+ms[0][1]+" but install.ps1 pins "+mp[0][1])
	}
	return bad
}

func strconvQuote(s string) string { return `"` + s + `"` }

// TestInstallersPinOneSourceCommit: without a release both installers build
// the same commit, named by its full hash, and it is a commit of this
// repository's history (so it was reviewed here, not typed in).
func TestInstallersPinOneSourceCommit(t *testing.T) {
	sh, ps1 := readRepoFile(t, "scripts/install.sh"), readRepoFile(t, "scripts/install.ps1")
	for _, p := range pinDrift(sh, ps1) {
		t.Error(p)
	}
	if t.Failed() {
		return
	}
	pin := shPinRe.FindStringSubmatch(sh)[1]
	root := repoFile(t, ".")
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		t.Skip("not a git checkout (an exported tree): the pin's ancestry cannot be checked")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	// CI checks out one commit only: there the history is not present.
	shallow, err := exec.Command("git", "-C", root, "rev-parse", "--is-shallow-repository").Output()
	if err != nil {
		t.Skipf("git rev-parse: %v", err)
	}
	if strings.TrimSpace(string(shallow)) == "true" {
		t.Skip("a shallow clone: the pin's ancestry cannot be checked")
	}
	out, err := exec.Command("git", "-C", root, "merge-base", "--is-ancestor", pin, "HEAD").CombinedOutput()
	if err != nil {
		t.Errorf("the pinned commit %s is not in HEAD's history: %v %s", pin, err, out)
	}
}

func TestPinDriftCatchesBadPins(t *testing.T) {
	good := strings.Repeat("ab", 20)
	sh := func(v string) string { return "#!/bin/bash\nQPOT_SOURCE_COMMIT_PINNED=\"" + v + "\"\n" }
	ps1 := func(v string) string { return "$QPOT_SOURCE_COMMIT_PINNED = \"" + v + "\"\r\n" }
	if bad := pinDrift(sh(good), ps1(good)); len(bad) != 0 {
		t.Fatalf("good pins reported: %v", bad)
	}
	for name, c := range map[string][2]string{
		"empty":       {sh(""), ps1("")},
		"short":       {sh(good[:12]), ps1(good[:12])},
		"upper case":  {sh(strings.ToUpper(good)), ps1(strings.ToUpper(good))},
		"a branch":    {sh("main"), ps1("main")},
		"different":   {sh(good), ps1(strings.Repeat("cd", 20))},
		"set twice":   {sh(good) + sh(good), ps1(good)},
		"not set":     {"#!/bin/bash\n", ps1(good)},
		"ps1 not set": {sh(good), "# none\r\n"},
	} {
		if len(pinDrift(c[0], c[1])) == 0 {
			t.Errorf("%s: not reported", name)
		}
	}
}

// TestReleaseWorkflowPinsActions: the release job can write releases and
// sign provenance, so remote actions are pinned to a commit (a tag can be
// moved). Explicit local validation workflows use the caller's exact commit.
func TestReleaseWorkflowPinsActions(t *testing.T) {
	wf := readRepoFile(t, ".github/workflows/release.yml")
	uses := usesRe.FindAllStringSubmatch(wf, -1)
	if len(uses) == 0 {
		t.Fatal("release.yml uses no actions")
	}
	for _, m := range uses {
		sameCommit := m[1] == "./.github/workflows/ci.yml" || m[1] == "./.github/workflows/codeql.yml"
		if !sameCommit && !pinnedRe.MatchString(m[1]) {
			t.Errorf("release.yml: %s is not a same-commit validation workflow or full commit-pinned action", m[1])
		}
	}
	for _, mutant := range []string{"actions/checkout@v4", "actions/checkout@" + strings.Repeat("a", 39), "actions/checkout@main"} {
		if pinnedRe.MatchString(mutant) {
			t.Errorf("%s counts as pinned", mutant)
		}
	}
}

// TestInstallersVerifyTheReleaseWorkflow: the workflow the installers make
// gh check (--signer-workflow) is the one that signs the provenance.
func TestInstallersVerifyTheReleaseWorkflow(t *testing.T) {
	const wf = ".github/workflows/release.yml"
	if _, err := os.Stat(repoFile(t, wf)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readRepoFile(t, wf), "actions/attest-build-provenance@") {
		t.Fatal("release.yml does not attest build provenance")
	}
	for _, f := range []string{"scripts/install.sh", "scripts/install.ps1"} {
		text := readRepoFile(t, f)
		for _, want := range []string{"/" + wf, "--source-ref", "--deny-self-hosted-runners", "--bundle"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s does not pass gh %s", f, want)
			}
		}
	}
}
