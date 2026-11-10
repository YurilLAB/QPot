package cicheck

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func readRepo(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The tools file must set these; CI, CodeQL and the local runner share them.
var requiredTools = []string{
	"GOVULNCHECK_VERSION", "GOSEC_VERSION", "STATICCHECK_VERSION", "ACTIONLINT_VERSION",
	"GITLEAKS_VERSION", "GITLEAKS_CONFIG_SHA256", "SHELLCHECK_VERSION", "SHELLCHECK_SHA256", "GOSEC_EXCLUDES",
	"CODEQL_VERSION", "CODEQL_GO_QUERIES_VERSION", "CODEQL_GO_BUNDLE_SHA256",
}

var ruleListRe = regexp.MustCompile(`G[0-9]{3}\s*,\s*G[0-9]{3}`)

// toolsDrift lists where CI, CodeQL or the local runner stop sharing the
// canonical manifest: copied values, workflow/job overrides, unused settings,
// and each job's use of a setting before loading the manifest.
func toolsDrift(tools map[string]string, ciYML, ciLocal, codeqlYML []byte) []string {
	var bad []string
	for _, k := range requiredTools {
		if tools[k] == "" {
			bad = append(bad, "ci-tools.env does not set "+k)
		}
	}
	for name, text := range map[string]string{"ci.yml": string(ciYML), "codeql.yml": string(codeqlYML), "ci-local.sh": string(ciLocal)} {
		for k, v := range tools {
			if strings.Contains(text, v) {
				bad = append(bad, name+" keeps its own copy of "+k+" ("+v+")")
			}
		}
		if ruleListRe.MatchString(text) {
			bad = append(bad, name+" lists gosec rules itself: "+ruleListRe.FindString(text))
		}
	}
	used := map[string]bool{}
	for name, data := range map[string][]byte{"ci.yml": ciYML, "codeql.yml": codeqlYML} {
		w, err := ParseWorkflow(data)
		if err != nil {
			bad = append(bad, name+": "+err.Error())
			continue
		}
		for k := range w.Env {
			if _, ok := tools[k]; ok || strings.HasSuffix(k, "_VERSION") {
				bad = append(bad, name+" sets "+k+" at workflow level")
			}
		}
		for _, j := range w.Jobs {
			for k := range j.Env {
				if _, ok := tools[k]; ok {
					bad = append(bad, name+" job "+j.ID+" sets "+k+" itself")
				}
			}
			loaded := false
			for _, step := range j.Steps {
				text := step.Run
				for _, values := range []map[string]string{step.Env, step.With} {
					for _, v := range values {
						text += "\n" + v
					}
				}
				for k := range tools {
					if !strings.Contains(text, "$"+k) && !strings.Contains(text, "${"+k) && !strings.Contains(text, "env."+k) {
						continue
					}
					used[k] = true
					if !loaded {
						bad = append(bad, name+" job "+j.ID+" step "+step.Label()+" uses "+k+" before loading ci-tools.env")
					}
				}
				if strings.Contains(step.Run, ".github/ci-tools.env") && strings.Contains(step.Run, "GITHUB_ENV") {
					loaded = true
				}
			}
		}
	}
	for k := range tools {
		if !used[k] {
			bad = append(bad, "validation workflows never use "+k)
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
	for _, p := range toolsDrift(tools, readRepo(t, ".github/workflows/ci.yml"), readRepo(t, "scripts/ci-local.sh"), readRepo(t, ".github/workflows/codeql.yml")) {
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
	codeql := readRepo(t, ".github/workflows/codeql.yml")
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
		if len(toolsDrift(tools, []byte(m), local, codeql)) == 0 {
			t.Errorf("%s: not reported", name)
		}
	}
	if len(toolsDrift(tools, []byte(ci), []byte(string(local)+"\nGOSEC_EXCLUDES="+tools["GOSEC_EXCLUDES"]+"\n"), codeql)) == 0 {
		t.Error("a copy in ci-local.sh is not reported")
	}
	for name, pair := range map[string][2]string{
		"CodeQL literal version":    {"codeql-bundle-v${CODEQL_VERSION}", "codeql-bundle-v" + tools["CODEQL_VERSION"]},
		"CodeQL literal query pack": {"${{ env.CODEQL_GO_QUERIES_VERSION }}", tools["CODEQL_GO_QUERIES_VERSION"]},
		"CodeQL literal checksum":   {"$CODEQL_GO_BUNDLE_SHA256", tools["CODEQL_GO_BUNDLE_SHA256"]},
		"CodeQL missing loader":     {load, "true"},
	} {
		mutant := []byte(strings.Replace(string(codeql), pair[0], pair[1], 1))
		if string(mutant) == string(codeql) {
			t.Fatalf("%s mutation did not apply", name)
		}
		if len(toolsDrift(tools, []byte(ci), local, mutant)) == 0 {
			t.Errorf("%s was not reported", name)
		}
	}
	extra := map[string]string{"UNUSED_VERSION": "v9.9.9"}
	for k, v := range tools {
		extra[k] = v
	}
	if len(toolsDrift(extra, []byte(ci), local, codeql)) == 0 {
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

// Publication requires complete source/security gates and actual native image
// acceptance on both shipped architectures. Registry writes consume the saved
// tested images; no write-capable job can rebuild a different artifact.
func TestHiFiPublicationRequiresLiveGate(t *testing.T) {
	type step struct {
		Uses            string         `yaml:"uses"`
		Run             string         `yaml:"run"`
		If              string         `yaml:"if"`
		With            map[string]any `yaml:"with"`
		ContinueOnError bool           `yaml:"continue-on-error"`
	}
	type job struct {
		Needs           yaml.Node         `yaml:"needs"`
		Uses            string            `yaml:"uses"`
		If              string            `yaml:"if"`
		Steps           []step            `yaml:"steps"`
		Permissions     map[string]string `yaml:"permissions"`
		ContinueOnError bool              `yaml:"continue-on-error"`
		Strategy        struct {
			Matrix struct {
				Include []map[string]string `yaml:"include"`
			} `yaml:"matrix"`
		} `yaml:"strategy"`
	}
	type workflow struct {
		Jobs map[string]job `yaml:"jobs"`
		On   map[string]struct {
			Branches    []string `yaml:"branches"`
			Paths       []string `yaml:"paths"`
			PathsIgnore []string `yaml:"paths-ignore"`
		} `yaml:"on"`
	}
	images := readRepo(t, ".github/workflows/images.yml")
	check := func(data []byte) bool {
		var w workflow
		if yaml.Unmarshal(data, &w) != nil {
			return false
		}
		// Any main commit may become a release tag, including documentation-
		// only changes. Every such commit needs its matching image references.
		push := w.On["push"]
		if len(push.Branches) != 1 || push.Branches[0] != "main" || len(push.Paths) != 0 || len(push.PathsIgnore) != 0 {
			return false
		}
		publish := w.Jobs["publish"]
		var needs []string
		if publish.Needs.Decode(&needs) != nil {
			return false
		}
		required := map[string]bool{"build": false, "hifi-validation": false, "source-validation": false, "semantic-validation": false}
		for _, need := range needs {
			if _, ok := required[need]; ok {
				required[need] = true
			}
		}
		for _, present := range required {
			if !present {
				return false
			}
		}
		if publish.ContinueOnError || strings.TrimSpace(publish.If) != "github.event_name == 'push' && github.ref == 'refs/heads/main'" {
			return false
		}
		for id, path := range map[string]string{"source-validation": "./.github/workflows/ci.yml", "semantic-validation": "./.github/workflows/codeql.yml"} {
			j := w.Jobs[id]
			if j.Uses != path || j.ContinueOnError || j.If != "" {
				return false
			}
		}
		validation := w.Jobs["hifi-validation"]
		var dependency string
		if validation.Needs.Decode(&dependency) != nil || dependency != "build" || validation.ContinueOnError || validation.If != "" {
			return false
		}
		wantRunners := map[string]string{"amd64": "ubuntu-latest", "arm64": "ubuntu-24.04-arm"}
		seenValidation := map[string]bool{}
		for _, m := range validation.Strategy.Matrix.Include {
			if wantRunners[m["arch"]] != m["runner"] || seenValidation[m["arch"]] {
				return false
			}
			seenValidation[m["arch"]] = true
		}
		if len(seenValidation) != 2 {
			return false
		}
		seenBuild := map[string]bool{}
		for _, m := range w.Jobs["build"].Strategy.Matrix.Include {
			key := m["image"] + "/" + m["arch"]
			if (m["image"] != "ssh-proxy" && m["image"] != "ssh-backend") || wantRunners[m["arch"]] != m["runner"] || seenBuild[key] {
				return false
			}
			seenBuild[key] = true
		}
		if len(seenBuild) != 4 {
			return false
		}
		foundGate, foundPublish, foundArtifacts := false, false, false
		for _, st := range validation.Steps {
			if strings.TrimSpace(st.Run) == "bash scripts/test-hifi.sh --use-built-images" && !st.ContinueOnError && st.If == "" {
				foundGate = true
			}
		}
		for id, j := range w.Jobs {
			if id != "publish" && (j.Permissions["packages"] == "write" || j.Permissions["contents"] == "write") {
				return false
			}
			for _, st := range j.Steps {
				if id == "build" && strings.Contains(st.Run, "${IMAGE}:ci") {
					return false // All smoke controls must use the matrix's loaded image.
				}
				if id == "build" && strings.Contains(st.Run, "--name be2") &&
					(!strings.Contains(st.Run, `-e "BACKEND_HOST_KEYS=$pool"`) ||
						strings.Contains(st.Run, " -v ") || strings.Contains(st.Run, "--mount") ||
						!strings.Contains(st.Run, `test "$(docker inspect --format '{{len .Mounts}}' be2)" = 0`) ||
						!strings.Contains(st.Run, "docker exec --user 65534:65534 be2 sh -c 'test ! -r /etc/ssh/ssh_host_ed25519_key'")) {
					return false // The pool's keys arrive without a mount, readable by root alone.
				}
				if st.Uses != "" && !regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$`).MatchString(st.Uses) {
					return false
				}
				if strings.HasPrefix(st.Uses, "docker/build-push-action@") && st.With["push"] != nil && st.With["push"] != false {
					return false
				}
				if strings.Contains(st.Run, "docker push ") && (id != "publish" || st.ContinueOnError || st.If != "") {
					return false
				}
				if id != "publish" {
					continue
				}
				if strings.Contains(st.Run, ":latest") {
					return false
				}
				if strings.HasPrefix(st.Uses, "actions/checkout@") || strings.HasPrefix(st.Uses, "docker/build-push-action@") {
					return false
				}
				if strings.HasPrefix(st.Uses, "actions/download-artifact@") && st.With["pattern"] == "hifi-${{ matrix.image }}-*-${{ github.run_id }}" {
					foundArtifacts = true
				}
				if strings.Contains(st.Run, "docker push ") && strings.Contains(st.Run, "docker load") && strings.Contains(st.Run, "{{index .RepoDigests 0}}") && strings.Contains(st.Run, "imagetools create") && !st.ContinueOnError {
					foundPublish = true
				}
			}
		}
		return foundGate && foundPublish && foundArtifacts
	}
	if !check(images) {
		t.Fatal("image publication is not protected by source/security/native live gates and tested-artifact identity")
	}
	for name, pair := range map[string][2]string{
		"main path filter":         {"push:\n    branches: [main]", "push:\n    branches: [main]\n    paths: ['docker/**']"},
		"main ignored paths":       {"push:\n    branches: [main]", "push:\n    branches: [main]\n    paths-ignore: ['README.md']"},
		"unbuilt smoke image":      {"\"${TEST_IMAGE}\"", "\"${IMAGE}:ci\""},
		"mounted host keys":        {`-e "BACKEND_HOST_KEYS=$pool"`, `-v "$keys:/etc/ssh/keys:ro"`},
		"mount check omitted":      {`test "$(docker inspect --format '{{len .Mounts}}' be2)" = 0`, "true"},
		"host-key denial omitted":  {"docker exec --user 65534:65534 be2 sh -c 'test ! -r /etc/ssh/ssh_host_ed25519_key'", "true"},
		"no validation dependency": {"needs: [build, hifi-validation, source-validation, semantic-validation]", "needs: [build]"},
		"publish on failure":       {"if: github.event_name == 'push' && github.ref == 'refs/heads/main'", "if: always()"},
		"skipped live gate":        {"run: bash scripts/test-hifi.sh --use-built-images", "run: true"},
		"ignored live failure":     {"run: bash scripts/test-hifi.sh --use-built-images", "continue-on-error: true\n        run: bash scripts/test-hifi.sh --use-built-images"},
		"replaced source workflow": {"uses: ./.github/workflows/ci.yml", "uses: someone/other/.github/workflows/ci.yml@main"},
		"source gate skipped":      {"name: Complete source and platform validation", "if: false\n    name: Complete source and platform validation"},
		"missing arm build":        {"image: ssh-backend, arch: arm64", "image: ssh-backend, arch: amd64"},
		"missing arm live":         {"- { arch: arm64, runner: ubuntu-24.04-arm }", "- { arch: amd64, runner: ubuntu-latest }"},
		"wrong artifact run":       {"pattern: hifi-${{ matrix.image }}-*-${{ github.run_id }}", "pattern: hifi-*"},
		"rebuild with write token": {"- name: Publish the tested images and their immutable manifest", "- uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n      - name: Publish the tested images and their immutable manifest"},
		"legacy tag overwritten":   {`--tag "${IMAGE}:${GITHUB_SHA}" "${digests[@]}"`, `--tag "${IMAGE}:${GITHUB_SHA}" --tag "${IMAGE}:latest" "${digests[@]}"`},
	} {
		mutant := []byte(strings.Replace(string(images), pair[0], pair[1], 1))
		if string(mutant) == string(images) {
			t.Fatalf("%s mutation did not apply", name)
		}
		var valid workflow
		if err := yaml.Unmarshal(mutant, &valid); err != nil {
			t.Fatalf("%s control is not valid workflow YAML: %v", name, err)
		}
		if check(mutant) {
			t.Errorf("%s could bypass publication validation", name)
		}
	}
	ci, err := ParseWorkflow(readRepo(t, ".github/workflows/ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	shared := false
	for _, j := range ci.Jobs {
		if j.ID == "hifi-organization-integration" {
			for _, st := range j.Steps {
				shared = shared || strings.TrimSpace(st.Run) == "bash scripts/test-hifi.sh"
			}
		}
	}
	if !shared {
		t.Fatal("ordinary CI no longer uses the publication gate's shared integration script")
	}
}

// A tag is not sufficient evidence that the source passed validation. The
// release's write/signing job depends on the same complete same-commit CI and
// semantic gates; manual or branch events cannot enter publication.
func TestReleasePublicationRequiresValidation(t *testing.T) {
	check := func(data []byte) bool {
		var w struct {
			Jobs map[string]struct {
				Uses            string   `yaml:"uses"`
				If              string   `yaml:"if"`
				Needs           []string `yaml:"needs"`
				ContinueOnError bool     `yaml:"continue-on-error"`
			} `yaml:"jobs"`
		}
		if yaml.Unmarshal(data, &w) != nil {
			return false
		}
		j := w.Jobs["release"]
		if j.ContinueOnError || j.If != "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')" {
			return false
		}
		needs := map[string]bool{}
		for _, n := range j.Needs {
			needs[n] = true
		}
		if !needs["source-validation"] || !needs["semantic-validation"] {
			return false
		}
		for id, path := range map[string]string{"source-validation": "./.github/workflows/ci.yml", "semantic-validation": "./.github/workflows/codeql.yml"} {
			v := w.Jobs[id]
			if v.Uses != path || v.If != "" || v.ContinueOnError {
				return false
			}
		}
		return true
	}
	data := readRepo(t, ".github/workflows/release.yml")
	if !check(data) {
		t.Fatal("release publication can bypass validation")
	}
	for name, pair := range map[string][2]string{
		"missing security":       {"needs: [source-validation, semantic-validation]", "needs: [source-validation]"},
		"always publish":         {"if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')", "if: always()"},
		"ignored source failure": {"name: Complete source and platform validation", "continue-on-error: true\n    name: Complete source and platform validation"},
		"skipped semantic":       {"name: Complete semantic security analysis", "if: false\n    name: Complete semantic security analysis"},
	} {
		mutant := []byte(strings.Replace(string(data), pair[0], pair[1], 1))
		if string(mutant) == string(data) {
			t.Fatalf("%s control did not apply", name)
		}
		if check(mutant) {
			t.Errorf("%s bypasses the release gate", name)
		}
	}
	for _, file := range []string{".github/workflows/ci.yml", ".github/workflows/codeql.yml"} {
		var w map[string]yaml.Node
		if err := yaml.Unmarshal(readRepo(t, file), &w); err != nil {
			t.Fatal(err)
		}
		var on map[string]yaml.Node
		trigger := w["on"]
		if err := trigger.Decode(&on); err != nil {
			t.Fatal(err)
		}
		if _, ok := on["workflow_call"]; !ok {
			t.Errorf("%s cannot be reused as the release gate", file)
		}
		if !strings.Contains(string(readRepo(t, file)), "${{ github.workflow }}-${{ github.ref }}") {
			t.Errorf("%s can cancel a different caller's validation", file)
		}
	}
}

// Inject actual subprocess failures into the shared bootstrap script. These
// controls exercise exit propagation and missing-test detection without running
// a Docker daemon or accepting a skipped live gate as a successful test.
func TestHiFiBootstrapPropagatesFailures(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Bash integration bootstrap runs on Linux CI")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	for _, scenario := range []struct {
		name string
		args []string
		want int
	}{
		{"build failure", nil, 17}, {"kernel failure", nil, 29}, {"missing gate", nil, 1}, {"missing metadata gate", nil, 1}, {"missing sticky gate", nil, 1}, {"missing cost gate", nil, 1}, {"live failure", nil, 23},
		{"accepted", nil, 0}, {"bad arguments", []string{"--use-built-images", "extra"}, 2},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			scripts := filepath.Join(root, "scripts")
			if err := os.Mkdir(bin, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(scripts, 0700); err != nil {
				t.Fatal(err)
			}
			script := filepath.Join(scripts, "test-hifi.sh")
			if err := os.WriteFile(script, readRepo(t, "scripts/test-hifi.sh"), 0700); err != nil {
				t.Fatal(err)
			}
			docker := `#!/bin/sh
printf 'docker %s\n' "$*" >> "$QPOT_FAKE_TRACE"
if [ "$QPOT_FAKE_SCENARIO" = 'build failure' ]; then exit 17; fi
`
			goTool := `#!/bin/sh
case " $* " in
 *' run netguard-integration '*)
  printf 'kernel %s\n' "$*" >> "$QPOT_FAKE_TRACE"
  if [ "$QPOT_FAKE_SCENARIO" = 'kernel failure' ]; then exit 29; fi
  exit 0;;
 *' -list '*)
  printf '%s\n' TestSSHOrganizationLive TestSSHOrganizationDatabaseLive TestSSHOrganizationServicesLive TestSSHCollectorPrivateLogsLive
  if [ "$QPOT_FAKE_SCENARIO" != 'missing gate' ]; then printf '%s\n' TestSSHBackendLive; fi
  if [ "$QPOT_FAKE_SCENARIO" != 'missing metadata gate' ]; then printf '%s\n' TestSSHStoreNativeMountMetadataLive; fi
  if [ "$QPOT_FAKE_SCENARIO" != 'missing sticky gate' ]; then printf '%s\n' TestSSHStickyCellLive; fi
  if [ "$QPOT_FAKE_SCENARIO" != 'missing cost gate' ]; then printf '%s\n' TestSSHBackendCaptureCostLive; fi
  exit 0;;
esac
printf 'live %s:%s:%s:%s:%s:%s:%s\n' "$QPOT_TEST_HIFI_LIVE" "$QPOT_TEST_HIFI_DATABASE" "$QPOT_TEST_SSH_COLLECTOR" "$QPOT_TEST_SSH_BACKEND" "$QPOT_TEST_HIFI_SERVICES" "$QPOT_TEST_DOCKER" "$QPOT_SSH_BACKEND_IMAGE" >> "$QPOT_FAKE_TRACE"
if [ "$QPOT_FAKE_SCENARIO" = 'live failure' ]; then exit 23; fi
`
			for name, body := range map[string]string{"docker": docker, "go": goTool} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			trace := filepath.Join(root, "trace")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bash, append([]string{script}, scenario.args...)...)
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "QPOT_FAKE_TRACE="+trace, "QPOT_FAKE_SCENARIO="+scenario.name,
				"QPOT_TEST_HIFI_SERVICES=0", "QPOT_TEST_HIFI_LIVE=0", "QPOT_TEST_HIFI_DATABASE=0", "QPOT_TEST_SSH_COLLECTOR=0", "QPOT_TEST_SSH_BACKEND=0", "QPOT_TEST_DOCKER=0", "QPOT_SSH_BACKEND_IMAGE=untrusted:old")
			output, runErr := cmd.CombinedOutput()
			code := 0
			if runErr != nil {
				if exit, ok := runErr.(*exec.ExitError); ok {
					code = exit.ExitCode()
				} else {
					t.Fatalf("bootstrap did not execute: %v", runErr)
				}
			}
			if code != scenario.want {
				t.Fatalf("exit%d want%d: %s", code, scenario.want, output)
			}
			logged, _ := os.ReadFile(trace)
			reached := strings.Contains(string(logged), "live 1:1:1:1:1:1:qpot-local/ssh-backend:development")
			if reached != (scenario.name == "accepted" || scenario.name == "live failure") {
				t.Fatalf("live gate execution/flags invalid: %s", logged)
			}
			kernelReached := strings.Contains(string(logged), "kernel run ./internal/cicheck/cirun -root "+root+" run netguard-integration")
			if kernelReached != (scenario.name != "build failure" && scenario.name != "bad arguments") {
				t.Fatalf("kernel gate execution invalid: %s", logged)
			}
			if scenario.name == "bad arguments" && len(logged) != 0 {
				t.Fatalf("invalid arguments changed Docker state: %s", logged)
			}
		})
	}
}

// Execute the actual publication command against failing Docker subprocesses.
// The fixture archives never reach a daemon or registry. Successful controls
// require two tested architecture images and immutable digests before the index.
func TestImagePublicationUsesOnlyTestedArtifacts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("image publication runs on Linux CI")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	var w struct {
		Jobs map[string]struct {
			Steps []struct{ Name, Run string } `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(readRepo(t, ".github/workflows/images.yml"), &w); err != nil {
		t.Fatal(err)
	}
	body := ""
	for _, st := range w.Jobs["publish"].Steps {
		if st.Name == "Publish the tested images and their immutable manifest" {
			body = st.Run
		}
	}
	if body == "" {
		t.Fatal("actual tested-artifact publication command missing")
	}
	for _, scenario := range []struct {
		name string
		want int
	}{
		{"accepted", 0}, {"load failure", 17}, {"corrupt archive", 1}, {"wrong architecture", 1}, {"wrong operating system", 1},
		{"push failure", 23}, {"missing digest", 1}, {"foreign repository", 1}, {"manifest failure", 31}, {"legacy tag regression", 49},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			artifacts := filepath.Join(dir, "hifi-images")
			for _, p := range []string{bin, artifacts} {
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatal(err)
				}
			}
			var archive bytes.Buffer
			zw := gzip.NewWriter(&archive)
			if _, err := zw.Write([]byte("owned synthetic saved-image fixture")); err != nil {
				t.Fatal(err)
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			for _, arch := range []string{"amd64", "arm64"} {
				data := archive.Bytes()
				if scenario.name == "corrupt archive" {
					data = []byte("not a gzip archive")
				}
				if err := os.WriteFile(filepath.Join(artifacts, "ssh-backend-"+arch+".tar.gz"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			fake := `#!/bin/sh
printf '%s\n' "$*" >> "$QPOT_FAKE_TRACE"
for arg in "$@"; do
 case "$arg" in *:latest) exit 49;; esac
done
case "$1" in
load)
 cat >/dev/null
 if [ "$QPOT_FAKE_SCENARIO" = 'load failure' ]; then exit 17; fi;;
image)
 case "$4" in
  '{{.Os}}/{{.Architecture}}')
   case "$QPOT_FAKE_SCENARIO" in
    'wrong architecture') printf '%s\n' linux/other;;
    'wrong operating system') printf 'windows/%s\n' "${5##*-}";;
    *) printf 'linux/%s\n' "${5##*-}";;
   esac;;
  '{{index .RepoDigests 0}}')
   case "$QPOT_FAKE_SCENARIO" in
    'missing digest') printf '%s\n' ghcr.io/yurillab/qpot-ssh-backend@sha256:bad;;
    'foreign repository') printf '%s\n' other.example/foreign@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;;
    *)
     case "$5" in
      *-amd64) printf '%s\n' ghcr.io/yurillab/qpot-ssh-backend@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;;
      *-arm64) printf '%s\n' ghcr.io/yurillab/qpot-ssh-backend@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;;
      *) exit 47;;
     esac;;
   esac;;
  *) exit 41;;
 esac;;
tag) :;;
push) if [ "$QPOT_FAKE_SCENARIO" = 'push failure' ]; then exit 23; fi;;
buildx)
 if [ "$2 $3" != 'imagetools create' ]; then exit 43; fi
 if [ "$QPOT_FAKE_SCENARIO" = 'manifest failure' ]; then exit 31; fi;;
*) exit 45;;
esac
`
			if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(fake), 0700); err != nil {
				t.Fatal(err)
			}
			trace := filepath.Join(dir, "trace")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := body
			if scenario.name == "legacy tag regression" {
				command = strings.Replace(body, `--tag "${IMAGE}:${GITHUB_SHA}" "${digests[@]}"`, `--tag "${IMAGE}:${GITHUB_SHA}" --tag "${IMAGE}:latest" "${digests[@]}"`, 1)
				if command == body {
					t.Fatal("legacy-tag mutation did not apply")
				}
			}
			cmd := exec.CommandContext(ctx, bash, "-c", command)
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "RUNNER_TEMP="+dir, "IMAGE=ghcr.io/yurillab/qpot-ssh-backend", "IMAGE_NAME=ssh-backend", "GITHUB_SHA="+strings.Repeat("c", 40), "GITHUB_RUN_ID=12345", "GITHUB_RUN_ATTEMPT=2", "QPOT_FAKE_TRACE="+trace, "QPOT_FAKE_SCENARIO="+scenario.name)
			output, runErr := cmd.CombinedOutput()
			code := 0
			if runErr != nil {
				if e, ok := runErr.(*exec.ExitError); ok {
					code = e.ExitCode()
				} else {
					t.Fatalf("execute publication control: %v", runErr)
				}
			}
			if code != scenario.want {
				t.Fatalf("exit%d want%d: %s", code, scenario.want, output)
			}
			logged, _ := os.ReadFile(trace)
			text := string(logged)
			indexed := strings.Contains(text, "buildx imagetools create ")
			if indexed != (scenario.name == "accepted" || scenario.name == "manifest failure" || scenario.name == "legacy tag regression") {
				t.Fatalf("invalid manifest execution: %s", logged)
			}
			if indexed {
				if strings.Count(text, "push ") != 2 || !strings.Contains(text, "@sha256:"+strings.Repeat("a", 64)) || !strings.Contains(text, "@sha256:"+strings.Repeat("b", 64)) {
					t.Fatalf("manifest did not consume both immutable tested references: %s", logged)
				}
				if strings.Contains(text, "build ") {
					t.Fatalf("publication rebuilt an image: %s", logged)
				}
			}
			if strings.Contains(text, ":latest") != (scenario.name == "legacy tag regression") {
				t.Fatalf("publication attempted to move the legacy image reference: %s", logged)
			}
		})
	}
}

// Uploaded SARIF and compressed archives can otherwise evade publication gates:
// the checked reports must be the analyzer's actual outputs, and the archives
// must be scanned before provenance is signed or release files are published.
func TestPublicationSecurityReportsAreRequired(t *testing.T) {
	type step struct {
		Uses, Run, If   string
		With            map[string]string `yaml:"with"`
		ContinueOnError bool              `yaml:"continue-on-error"`
	}
	type document struct {
		Jobs map[string]struct {
			Steps []step `yaml:"steps"`
		} `yaml:"jobs"`
	}
	checkRelease := func(data []byte) bool {
		var w document
		if yaml.Unmarshal(data, &w) != nil {
			return false
		}
		pack, scan, attest, publish := -1, -1, -1, -1
		for i, st := range w.Jobs["release"].Steps {
			if strings.Contains(st.Run, "./cmd/qpot-release pack ") {
				pack = i
			}
			if strings.Contains(st.Run, "secrets-artifacts") {
				if st.If != "" || st.ContinueOnError || !strings.Contains(st.Run, "-dir dist") || !strings.Contains(st.Run, "/config/gitleaks.toml") || strings.Contains(st.Run, ".gitleaks.toml") {
					return false
				}
				scan = i
			}
			if strings.HasPrefix(st.Uses, "actions/attest-build-provenance@") {
				attest = i
			}
			if strings.Contains(st.Run, "gh release create ") {
				assets := `dist/qpot_*.tar.gz dist/qpot_*.zip "dist/qpot_${TAG#v}_provenance.sigstore.json" dist/SHA256SUMS`
				if st.If != "" || st.ContinueOnError || !strings.HasSuffix(strings.TrimSpace(st.Run), assets) {
					return false
				}
				publish = i
			}
		}
		return pack >= 0 && scan > pack && attest > scan && publish > attest
	}
	checkCodeQL := func(data []byte) bool {
		var w document
		if yaml.Unmarshal(data, &w) != nil {
			return false
		}
		analysis, gate := -1, -1
		for i, st := range w.Jobs["analyze"].Steps {
			if strings.HasPrefix(st.Uses, "github/codeql-action/analyze@") {
				if st.If != "" || st.ContinueOnError || st.With["output"] != "${{ runner.temp }}/qpot-codeql" {
					return false
				}
				analysis = i
			}
			if strings.Contains(st.Run, "check-codeql") {
				command := strings.TrimSpace(st.Run)
				strict := `go run ./internal/cicheck/cirun check-codeql "$RUNNER_TEMP/qpot-codeql"`
				if st.If != "" || st.ContinueOnError || (command != strict && command != strict+" .github/codeql-reviews.json") {
					return false
				}
				gate = i
			}
		}
		return analysis >= 0 && gate > analysis
	}
	release := readRepo(t, ".github/workflows/release.yml")
	codeql := readRepo(t, ".github/workflows/codeql.yml")
	if !checkRelease(release) {
		t.Fatal("release does not scan unpacked artifacts before signing/publication")
	}
	if !checkCodeQL(codeql) {
		t.Fatal("CodeQL analysis can succeed without its fail-closed finding gate")
	}
	for name, c := range map[string]struct {
		data     []byte
		from, to string
		check    func([]byte) bool
	}{
		"archive scan missing":      {release, "secrets-artifacts", "list", checkRelease},
		"archive scan skipped":      {release, "- name: Scan unpacked release artifacts without source allowlists", "- if: false\n        name: Scan unpacked release artifacts without source allowlists", checkRelease},
		"archive scan ignored":      {release, "- name: Scan unpacked release artifacts without source allowlists", "- continue-on-error: true\n        name: Scan unpacked release artifacts without source allowlists", checkRelease},
		"unscanned upload glob":     {release, `dist/qpot_*.tar.gz dist/qpot_*.zip "dist/qpot_${TAG#v}_provenance.sigstore.json" dist/SHA256SUMS`, `dist/qpot_* dist/SHA256SUMS`, checkRelease},
		"missing upload checksum":   {release, `"dist/qpot_${TAG#v}_provenance.sigstore.json" dist/SHA256SUMS`, `"dist/qpot_${TAG#v}_provenance.sigstore.json"`, checkRelease},
		"missing upload provenance": {release, `"dist/qpot_${TAG#v}_provenance.sigstore.json" dist/SHA256SUMS`, `dist/SHA256SUMS`, checkRelease},
		"CodeQL missing check":      {codeql, "check-codeql", "list", checkCodeQL},
		"CodeQL wrong report path":  {codeql, "output: ${{ runner.temp }}/qpot-codeql", "output: ${{ runner.temp }}/unchecked-codeql", checkCodeQL},
		"CodeQL ignored check":      {codeql, "run: go run ./internal/cicheck/cirun check-codeql", "continue-on-error: true\n        run: go run ./internal/cicheck/cirun check-codeql", checkCodeQL},
	} {
		mutant := []byte(strings.Replace(string(c.data), c.from, c.to, 1))
		if string(mutant) == string(c.data) {
			t.Fatalf("%s mutation did not apply", name)
		}
		var valid document
		if err := yaml.Unmarshal(mutant, &valid); err != nil {
			t.Fatalf("%s control invalid YAML: %v", name, err)
		}
		if c.check(mutant) {
			t.Errorf("%s bypasses publication security checks", name)
		}
	}
}

func TestReleaseImagePreflightFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release preflight executes on Linux")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	var w struct {
		Jobs map[string]struct {
			Steps []struct{ Name, Run string } `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(readRepo(t, ".github/workflows/release.yml"), &w); err != nil {
		t.Fatal(err)
	}
	body := ""
	for _, st := range w.Jobs["release"].Steps {
		if st.Name == "Require matching published HiFi images for both architectures" {
			body = st.Run
		}
	}
	if body == "" {
		t.Fatal("release does not verify commit-specific published image availability")
	}
	for _, scenario := range []struct {
		name, sha string
		want      int
	}{
		{"accepted", strings.Repeat("a", 40), 0}, {"missing image", strings.Repeat("a", 40), 17}, {"checker failure", strings.Repeat("a", 40), 23},
		{"short revision", "abc", 1}, {"nonhex revision", strings.Repeat("z", 40), 1}, {"empty revision", "", 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0700); err != nil {
				t.Fatal(err)
			}
			docker := `#!/bin/sh
printf 'docker %s\n' "$*" >> "$QPOT_FAKE_TRACE"
if [ "$QPOT_FAKE_SCENARIO" = 'missing image' ]; then exit 17; fi
printf '{}\n'
`
			goTool := `#!/bin/sh
printf 'checker %s\n' "$*" >> "$QPOT_FAKE_TRACE"
if [ "$1 $2 $3" != 'run ./internal/cicheck/cirun check-image-index' ]; then exit 29; fi
if [ "$QPOT_FAKE_SCENARIO" = 'checker failure' ]; then exit 23; fi
`
			for name, text := range map[string]string{"docker": docker, "go": goTool} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(text), 0700); err != nil {
					t.Fatal(err)
				}
			}
			trace := filepath.Join(dir, "trace")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bash, "-c", body)
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "RUNNER_TEMP="+dir, "GITHUB_SHA="+scenario.sha, "QPOT_FAKE_TRACE="+trace, "QPOT_FAKE_SCENARIO="+scenario.name)
			output, runErr := cmd.CombinedOutput()
			code := 0
			if runErr != nil {
				if e, ok := runErr.(*exec.ExitError); ok {
					code = e.ExitCode()
				} else {
					t.Fatal(runErr)
				}
			}
			if code != scenario.want {
				t.Fatalf("exit%d want%d: %s", code, scenario.want, output)
			}
			logged, _ := os.ReadFile(trace)
			text := string(logged)
			if scenario.name == "accepted" {
				if strings.Count(text, "docker ") != 2 || strings.Count(text, "checker ") != 2 {
					t.Fatalf("both published images were not checked: %s", logged)
				}
				for _, image := range []string{"ssh-proxy", "ssh-backend"} {
					if !strings.Contains(text, "imagetools inspect --raw ghcr.io/yurillab/qpot-"+image+":"+scenario.sha) {
						t.Fatalf("commit-specific image was not inspected: %s", logged)
					}
				}
			} else if scenario.name == "missing image" {
				if strings.Contains(text, "checker ") {
					t.Fatal("missing image accepted by a checker")
				}
			} else if scenario.name == "checker failure" {
				if strings.Count(text, "docker ") != 1 || strings.Count(text, "checker ") != 1 {
					t.Fatalf("failed metadata gate did not stop preflight: %s", logged)
				}
			} else if len(logged) != 0 {
				t.Fatalf("invalid source revision reached registry: %s", logged)
			}
		})
	}
}

// The real publication command expands only archives covered by the artifact
// scanner, the exact trusted provenance output and the checksum manifest.
// Unexpected qpot_* files in dist must never become release attachments.
func TestReleaseUploadExcludesUnscannedExtraFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release publication runs on Linux")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct{ Name, Run string } `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(readRepo(t, ".github/workflows/release.yml"), &workflow); err != nil {
		t.Fatal(err)
	}
	body := ""
	for _, step := range workflow.Jobs["release"].Steps {
		if step.Name == "Publish the release" {
			body = step.Run
		}
	}
	if body == "" {
		t.Fatal("actual release upload command is missing")
	}
	for _, scenario := range []struct {
		name, status string
		want         int
	}{{"accepted", "0", 0}, {"upload failure", "17", 17}} {
		t.Run(scenario.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			dist := filepath.Join(dir, "dist")
			for _, path := range []string{bin, dist} {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			expected := map[string]bool{
				"dist/qpot_1.0.0_linux_amd64.tar.gz":       false,
				"dist/qpot_1.0.0_windows_amd64.zip":        false,
				"dist/qpot_1.0.0_provenance.sigstore.json": false,
				"dist/SHA256SUMS":                          false,
			}
			for _, file := range []string{
				"qpot_1.0.0_linux_amd64.tar.gz", "qpot_1.0.0_windows_amd64.zip",
				"qpot_1.0.0_provenance.sigstore.json", "SHA256SUMS",
				"qpot_unscanned-extra.txt", "qpot_debug-symbols",
				"qpot_unscanned.tar.gz.notes", "qpot_0.9.0_provenance.sigstore.json",
			} {
				if err := os.WriteFile(filepath.Join(dist, file), []byte("owned uploader argv scope fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			fake := "#!/bin/sh\nprintf '%s\\0' \"$@\" > \"$QPOT_UPLOAD_TRACE\"\nexit \"$QPOT_FAKE_GH_STATUS\"\n"
			if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(fake), 0o700); err != nil {
				t.Fatal(err)
			}
			trace := filepath.Join(dir, "upload-argv")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bash, "-c", body)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "TAG=v1.0.0", "QPOT_UPLOAD_TRACE="+trace, "QPOT_FAKE_GH_STATUS="+scenario.status)
			output, runErr := cmd.CombinedOutput()
			code := 0
			if runErr != nil {
				if exit, ok := runErr.(*exec.ExitError); ok {
					code = exit.ExitCode()
				} else {
					t.Fatal(runErr)
				}
			}
			if code != scenario.want {
				t.Fatalf("exit%d want%d: %s", code, scenario.want, output)
			}
			data, err := os.ReadFile(trace)
			if err != nil {
				t.Fatal(err)
			}
			args := strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00")
			if len(args) != 7+len(expected) || strings.Join(args[:7], "\x00") != "release\x00create\x00v1.0.0\x00--verify-tag\x00--title\x00QPot v1.0.0\x00--generate-notes" {
				t.Fatalf("unexpected release invocation: %q", args)
			}
			for _, arg := range args[7:] {
				if present, ok := expected[arg]; !ok || present {
					t.Fatalf("unscanned or duplicate release asset selected: %q", arg)
				}
				expected[arg] = true
			}
			for arg, present := range expected {
				if !present {
					t.Errorf("required scanned/trusted release asset omitted: %s", arg)
				}
			}
		})
	}
}

// Execute the actual Docker job's test step with a list-aware Go fixture. A
// renamed or unselected mandatory test must not turn an empty selection green.
func TestDockerIntegrationRequiresPrivateEvidenceAndLiveNames(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Docker integration workflow runs on Linux")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	workflow, err := ParseWorkflow(readRepo(t, ".github/workflows/ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	job, ok := workflow.Job("docker-integration")
	if !ok || job.Env["QPOT_TEST_DOCKER"] != "1" {
		t.Fatal("real Docker integration is absent or not enabled")
	}
	body := ""
	for _, step := range job.Steps {
		if step.Name == "Deliver, restart and clean up with the real collector and helper" {
			body = step.Run
		}
	}
	if body == "" || strings.Contains(body, "sudo") {
		t.Fatal("ordinary-user Docker helper gate is missing or elevated")
	}
	required := []string{
		"TestCollectorAndCleanupWithRealDocker", "TestDockerHelperForReal", "TestDockerSSHInventoryPrivateEvidenceAndUnsupportedObjects",
		"TestVectorRemapLive", "TestVectorConfigValidatesLive", "TestVectorEdgeConfigsValidateLive",
	}
	scenarios := []struct {
		name, omit string
		want       int
	}{{"accepted", "", 0}, {"selector omits private inventory", "", 1}, {"test command failure", "", 23}, {"list command failure", "", 19}}
	for _, test := range required {
		scenarios = append(scenarios, struct {
			name, omit string
			want       int
		}{"missing " + test, test, 1})
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			fakeGo := `#!/bin/sh
case " $* " in
 *' -list '*)
  if [ "$QPOT_FAKE_SCENARIO" = 'list command failure' ]; then exit 19; fi
  pattern=''
  while [ "$#" -gt 0 ]; do
   if [ "$1" = '-list' ]; then shift; pattern="$1"; break; fi
   shift
  done
  for name in TestCollectorAndCleanupWithRealDocker TestDockerHelperForReal TestDockerSSHInventoryPrivateEvidenceAndUnsupportedObjects TestVectorRemapLive TestVectorConfigValidatesLive TestVectorEdgeConfigsValidateLive; do
   if [ "$name" != "$QPOT_FAKE_OMIT" ] && printf '%s\n' "$name" | grep -Eq "$pattern"; then printf '%s\n' "$name"; fi
  done
  exit 0;;
esac
printf 'live %s %s\n' "$QPOT_TEST_DOCKER" "$*" >> "$QPOT_FAKE_TRACE"
if [ "$QPOT_FAKE_SCENARIO" = 'test command failure' ]; then exit 23; fi
`
			if err := os.WriteFile(filepath.Join(bin, "go"), []byte(fakeGo), 0o700); err != nil {
				t.Fatal(err)
			}
			command := body
			if scenario.name == "selector omits private inventory" {
				command = strings.Replace(body, "|TestDockerSSHInventoryPrivateEvidenceAndUnsupportedObjects", "", 1)
				if command == body {
					t.Fatal("private-inventory selector mutation did not apply")
				}
			}
			trace := filepath.Join(dir, "trace")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bash, "-c", command)
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "QPOT_TEST_DOCKER=0", "QPOT_FAKE_TRACE="+trace, "QPOT_FAKE_OMIT="+scenario.omit, "QPOT_FAKE_SCENARIO="+scenario.name)
			for key, value := range job.Env {
				cmd.Env = append(cmd.Env, key+"="+value)
			}
			output, runErr := cmd.CombinedOutput()
			code := 0
			if runErr != nil {
				if exit, ok := runErr.(*exec.ExitError); ok {
					code = exit.ExitCode()
				} else {
					t.Fatal(runErr)
				}
			}
			if code != scenario.want {
				t.Fatalf("exit%d want%d: %s", code, scenario.want, output)
			}
			logged, _ := os.ReadFile(trace)
			reached := strings.HasPrefix(string(logged), "live 1 test -race ")
			if reached != (scenario.name == "accepted" || scenario.name == "test command failure") {
				t.Fatalf("missing/failed mandatory test did not stop the live gate: %s", logged)
			}
		})
	}
}

func TestDeclaredServiceIDExpressionsRemainNarrow(t *testing.T) {
	id := strings.Repeat("a", 64)
	services := map[string]string{"clickhouse": id}
	got, err := expandWithServices("${{ job.services.clickhouse.id }}", nil, nil, services)
	if err != nil || got != id {
		t.Fatalf("actual service ID was not expanded: %q %v", got, err)
	}
	for _, expression := range []string{
		"job.services.missing.id", "job.services.clickhouse.ports.9000", "job.services.clickhouse", "job.container.id", "job.services.clickhouse.id.extra", "secrets.TOKEN", "job.services.clickhouse.id || secrets.TOKEN",
	} {
		if _, err := expandWithServices("${{ "+expression+" }}", nil, nil, services); err == nil {
			t.Fatalf("unsupported context expanded: %s", expression)
		}
	}
	for _, bad := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("a", 64) + "\n" + strings.Repeat("b", 64)} {
		if _, err := expandWithServices("${{ job.services.clickhouse.id }}", nil, nil, map[string]string{"clickhouse": bad}); err == nil {
			t.Fatal("unissued or malformed service ID expanded")
		}
	}
	if _, err := Expand("${{ job.services.clickhouse.id }}", nil, map[string]string{"job.services.clickhouse.id": id}); err == nil {
		t.Fatal("environment forged a service-container context")
	}
	r := &Runner{}
	good := Job{ID: "owned-service", RunsOn: "ubuntu-latest", Services: []Service{{Name: "clickhouse", Image: "test-only:local"}}, Steps: []Step{{Env: map[string]string{"CONTAINER": "${{ job.services.clickhouse.id }}"}, Run: `test -n "$CONTAINER"`}}}
	if err := r.Check(&Workflow{}, good); err != nil {
		t.Fatalf("declared service rejected: %v", err)
	}
	good.Services = nil
	if err := r.Check(&Workflow{}, good); err == nil {
		t.Fatal("unknown service context accepted before startup")
	}
}

func TestServiceIDIsCapturedFromOwnedStartup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ci-local service bootstrap runs on Linux")
	}
	for _, valid := range []bool{true, false} {
		t.Run(map[bool]string{true: "issued ID", false: "invalid output"}[valid], func(t *testing.T) {
			root := t.TempDir()
			id := strings.Repeat("a", 64)
			output := id
			if !valid {
				output = "not-a-container-id"
			}
			t.Setenv("QPOT_CI_CONTAINER_ID", output)
			t.Setenv("QPOT_CI_OWNED_ID", id)
			calls := filepath.Join(root, "docker-calls")
			t.Setenv("QPOT_CI_SERVICE_CALLS", calls)
			script := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$QPOT_CI_SERVICE_CALLS"
case "$1" in
 run) printf '%s\n' "$QPOT_CI_CONTAINER_ID"; printf 'startup diagnostic\n' >&2 ;;
 inspect) printf 'healthy\n' ;;
 ps) printf '%s\n' "$QPOT_CI_OWNED_ID" ;;
 rm) exit 0 ;;
 *) exit 1 ;;
esac
`
			if err := os.WriteFile(filepath.Join(root, "docker"), []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
			job := Job{ID: "service-identity", RunsOn: "ubuntu-latest", Services: []Service{{Name: "clickhouse", Image: "owned-test-only:local", Ports: []string{"127.0.0.1:19000:9000"}}}, Steps: []Step{{Env: map[string]string{"OWNED_CONTAINER": "${{ job.services.clickhouse.id }}"}, Run: `test "$OWNED_CONTAINER" = "` + id + `"
printf '%s' "$OWNED_CONTAINER" > "$GITHUB_WORKSPACE/observed-id"`}}}
			var logs bytes.Buffer
			r := &Runner{Root: root, Out: &logs, Env: os.Environ()}
			err := r.RunJob(t.Context(), &Workflow{}, job)
			if !valid {
				if err == nil {
					t.Fatal("startup without an actual container ID ran its steps")
				}
				if _, err := os.Stat(filepath.Join(root, "observed-id")); !os.IsNotExist(err) {
					t.Fatal("invalid service identity reached workflow step")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(filepath.Join(root, "observed-id"))
				if err != nil || string(got) != id {
					t.Fatalf("workflow did not receive owned ID: %q %v", got, err)
				}
			}
			data, readErr := os.ReadFile(calls)
			if readErr != nil || !strings.Contains(string(data), "rm -f "+id) || !strings.Contains(string(data), "label=qpot.ci-local.owner=qpot-ci-local-") || !strings.Contains(string(data), "--label qpot.ci-local.owner=qpot-ci-local-") {
				t.Fatalf("owned service cleanup did not run: %s %v", data, readErr)
			}
			if !strings.Contains(string(data), "-p 127.0.0.1:19000:9000") || strings.Contains(string(data), "127.0.0.1:127.0.0.1:") {
				t.Fatal("service startup changed the explicit loopback binding")
			}
			if !strings.Contains(logs.String(), "startup diagnostic") || !strings.Contains(logs.String(), output) {
				t.Fatal("service ID capture dropped startup output or diagnostics")
			}
		})
	}
}

func TestServicePortsStayOnLoopback(t *testing.T) {
	for _, mapping := range []string{"19000:9000", "127.0.0.1:19000:9000", "15432:5432/tcp", "127.0.0.1:15353:5353/udp"} {
		got, err := localServicePort(mapping)
		want := mapping
		if !strings.HasPrefix(want, "127.0.0.1:") {
			want = "127.0.0.1:" + want
		}
		if err != nil || got != want {
			t.Fatalf("loopback mapping changed: %q → %q: %v", mapping, got, err)
		}
	}
	for _, mapping := range []string{"0.0.0.0:19000:9000", "192.0.2.1:19000:9000", "[::]:19000:9000", "127.0.0.1:127.0.0.1:19000:9000", "9000", "0:9000", "19000:65536", "19000:9000/sctp", "-p 19000:9000", "19000:9000\n"} {
		if _, err := localServicePort(mapping); err == nil {
			t.Fatalf("unsupported service binding accepted: %q", mapping)
		}
		job := Job{ID: "bad-binding", RunsOn: "ubuntu-latest", Services: []Service{{Name: "database", Image: "test-only:local", Ports: []string{mapping}}}}
		if err := (&Runner{}).Check(&Workflow{}, job); err == nil {
			t.Fatalf("unsafe service binding was not rejected before startup: %q", mapping)
		}
	}
}

func TestServiceCleanupRejectsLeaksAndOwnsPartialStartup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ci-local service bootstrap runs on Linux")
	}
	for _, scenario := range []struct {
		name                string
		fails, removes, ran bool
	}{
		{"complete", false, true, true},
		{"created then start failed", true, true, false},
		{"failed before creation", true, false, false},
		{"remove failed", true, true, true},
		{"list failed", true, false, true},
		{"invalid cleanup ID", true, false, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			dir := t.TempDir()
			id := strings.Repeat("b", 64)
			calls := filepath.Join(dir, "docker-calls")
			t.Setenv("QPOT_CI_SERVICE_CALLS", calls)
			t.Setenv("QPOT_CI_SCENARIO", scenario.name)
			t.Setenv("QPOT_CI_OWNED_ID", id)
			fakeDocker := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$QPOT_CI_SERVICE_CALLS"
case "$1" in
 run)
  if [ "$QPOT_CI_SCENARIO" = 'failed before creation' ]; then exit 125; fi
  printf '%s\n' "$QPOT_CI_OWNED_ID"
  if [ "$QPOT_CI_SCENARIO" = 'created then start failed' ]; then exit 125; fi;;
 inspect) printf 'healthy\n';;
 ps)
  if [ "$QPOT_CI_SCENARIO" = 'list failed' ]; then exit 47; fi
  if [ "$QPOT_CI_SCENARIO" = 'failed before creation' ]; then exit 0; fi
  if [ "$QPOT_CI_SCENARIO" = 'invalid cleanup ID' ]; then printf 'untrusted-id\n'; else printf '%s\n' "$QPOT_CI_OWNED_ID"; fi;;
 rm) if [ "$QPOT_CI_SCENARIO" = 'remove failed' ]; then exit 48; fi;;
 *) exit 1;;
esac
`
			if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(fakeDocker), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			job := Job{ID: "cleanup", RunsOn: "ubuntu-latest", Services: []Service{{Name: "database", Image: "owned-test-only:local"}}, Steps: []Step{{Run: `printf ran > "$GITHUB_WORKSPACE/ran"`}}}
			var output bytes.Buffer
			runner := Runner{Root: dir, Out: &output, Env: os.Environ()}
			err := runner.RunJob(t.Context(), &Workflow{}, job)
			if (err != nil) != scenario.fails {
				t.Fatalf("job failure=%v, want %v: %s", err, scenario.fails, output.String())
			}
			data, err := os.ReadFile(calls)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "rm -f "+id) != scenario.removes {
				t.Fatalf("partial startup or ownership cleanup mismatch: %s", data)
			}
			label := regexp.MustCompile(`--label (qpot\.ci-local\.owner=\S+)`).FindStringSubmatch(string(data))
			if len(label) != 2 || !strings.Contains(string(data), "--filter label="+label[1]+" --format {{.ID}}") {
				t.Fatalf("cleanup did not select this job's generated ownership label: %s", data)
			}
			_, runErr := os.Stat(filepath.Join(dir, "ran"))
			if (runErr == nil) != scenario.ran {
				t.Fatal("workflow step ran after failed service startup")
			}
		})
	}
}

func TestServiceCleanupHonorsItsDeadline(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ci-local service bootstrap runs on Linux")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\nexec sleep 10\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := (&Runner{Out: &bytes.Buffer{}}).cleanupServiceContainers(ctx, "owned-test-only")
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("cleanup ignored its deadline: %v after %s", err, time.Since(start))
	}
}

func TestNativeLeaseGatesUseProductionCoordinationAndRequiredTests(t *testing.T) {
	w, err := ParseWorkflow(readRepo(t, ".github/workflows/ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	ch, ok := w.Job("clickhouse-integration")
	if !ok {
		t.Fatal("missing ClickHouse gate")
	}
	if len(ch.Services) != 1 || len(ch.Services[0].Ports) != 1 || ch.Services[0].Ports[0] != "127.0.0.1:19000:9000" {
		t.Fatal("ClickHouse CI must expose only the native port on loopback, never Keeper")
	}
	negative, bootstrap, positive := -1, -1, -1
	for index, step := range ch.Steps {
		if strings.Contains(step.Run, "required=TestCHIntelligenceLeaseMissingKeeperFailsClosed") {
			negative = index
			if step.Env["QPOT_TEST_CH_EXPECT_NO_KEEPER"] != "1" {
				t.Fatal("no-Keeper regression can silently skip")
			}
		}
		if strings.Contains(step.Run, "docker cp internal/instance/clickhouse_keeper.xml") {
			bootstrap = index
			if step.Env["CLICKHOUSE_CONTAINER"] != "${{ job.services.clickhouse.id }}" || !strings.Contains(step.Run, `docker restart "$CLICKHOUSE_CONTAINER"`) || !strings.Contains(step.Run, `docker exec --user 0 "$CLICKHOUSE_CONTAINER" chmod 0644 /etc/clickhouse-server/config.d/qpot-keeper.xml`) || !strings.Contains(step.Run, "system.zookeeper") {
				t.Fatal("Keeper bootstrap does not target the actual job service or verify its readiness")
			}
		}
		if strings.Contains(step.Run, "test_packages=(./internal/database ./internal/intelligence ./internal/server)") {
			positive = index
			for _, name := range []string{"TestCHIntelligenceLeaseNativeContentionAndFencing", "TestCHIntelligenceLeaseNativeExpiryAndLargeCheckpoint", "TestCHIntelligenceLeaseRejectsNonAtomicControlCatalog", "TestWorkerClassifiesAgainstClickHouse", "TestServerServesDataFromClickHouse"} {
				if !strings.Contains(step.Run, name) {
					t.Fatalf("native Keeper gate dropped mandatory test %s", name)
				}
			}
			if !strings.Contains(step.Run, `'"Action":"skip"'`) || !strings.Contains(step.Run, "grep -Fv TestCHIntelligenceLeaseMissingKeeperFailsClosed") {
				t.Fatal("positive Keeper gate can accept skipped or wrong-fixture tests")
			}
		}
	}
	if negative < 0 || bootstrap <= negative || positive <= bootstrap || ch.Env["QPOT_TEST_CLICKHOUSE"] != "1" {
		t.Fatal("Keeper bootstrap/fail-closed/storage gate ordering drifted")
	}
	pg, ok := w.Job("postgres-lease-integration")
	if !ok {
		t.Fatal("native PostgreSQL lease gate missing")
	}
	if len(pg.Services) != 1 || !bytes.Contains(readRepo(t, "internal/instance/ssh_organization.go"), []byte(`"`+pg.Services[0].Image+`"`)) {
		t.Fatal("PostgreSQL gate does not use the existing production PostgreSQL image")
	}
	if pg.Env["QPOT_TEST_POSTGRES"] != "1" {
		t.Fatal("PostgreSQL lease integration can silently skip")
	}
	if len(pg.Services[0].Ports) != 1 || pg.Services[0].Ports[0] != "127.0.0.1:15432:5432" {
		t.Fatal("PostgreSQL CI must expose its native port only on loopback")
	}
	var script strings.Builder
	for _, step := range pg.Steps {
		script.WriteString(step.Run)
	}
	for _, name := range []string{"TestPGIntelligenceLeaseIndependentOwnersAndAliases", "TestPGIntelligenceLeaseShadowCheckpointCannotSplitOwner", "TestPGIntelligenceLeaseRejectsDifferentProjectionScope", "TestPGIntelligenceLeaseCoordinatesDifferentDatabaseRoles", "TestPGIntelligenceLeaseExpiryRecoveryAndLargeCheckpoint", "TestPGIntelligenceLeaseClockCheckedAfterRowLock", "TestPGIntelligenceLeasePublicCheckpointProjectionAndTags"} {
		if !strings.Contains(script.String(), name) {
			t.Fatalf("native PostgreSQL gate dropped required test %s", name)
		}
	}
	if !strings.Contains(script.String(), `'"Action":"skip"'`) {
		t.Fatal("PostgreSQL lease gate does not reject skipped native tests")
	}
	es, ok := w.Job("elasticsearch-lease-integration")
	if !ok || len(es.Services) != 1 {
		t.Fatal("native Elasticsearch lease gate missing")
	}
	if es.Services[0].Image != "docker.elastic.co/elasticsearch/elasticsearch:8.17.0@sha256:2f602552550869fb29b6fd5848c5118d3ef3a2e1d5d45802e3ab9088cb2de8e2" || es.Env["QPOT_TEST_ELASTICSEARCH_LEASE"] != "1" || es.Env["QPOT_TEST_ELASTICSEARCH_LEASE_URL"] != "http://127.0.0.1:19200" {
		t.Fatal("Elasticsearch fixture version or explicit live-test opt-in drifted")
	}
	if es.Env["QPOT_TEST_ELASTIC"] != "" {
		t.Fatal("destructive legacy Elasticsearch fixtures must not share the native lease gate")
	}
	if len(es.Services[0].Ports) != 1 || es.Services[0].Ports[0] != "127.0.0.1:19200:9200" {
		t.Fatal("Elasticsearch CI must expose its native port only on loopback")
	}
	script.Reset()
	for _, step := range es.Steps {
		script.WriteString(step.Run)
	}
	if !strings.Contains(script.String(), "required=TestElasticsearchIntelligenceLeaseLive") || !strings.Contains(script.String(), `-run "^${required}$"`) || !strings.Contains(script.String(), `'"Action":"skip"'`) {
		t.Fatal("Elasticsearch lease gate can miss or skip its mandatory native test")
	}
	local := string(readRepo(t, "scripts/ci-local.sh"))
	for _, id := range []string{pg.ID, es.ID} {
		if !strings.Contains(local, ","+id+",") {
			t.Fatalf("ci-local --no-docker does not skip %s", id)
		}
	}
}

func TestNativeLeaseGatesRejectMissingSkippedAndFailedTests(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the local CI gate runs in Bash on Linux")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal("Bash is required for the native CI gate regression")
	}
	w, err := ParseWorkflow(readRepo(t, ".github/workflows/ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, gate := range []struct {
		job, marker string
		required    []string
	}{
		{"clickhouse-integration", "required=TestCHIntelligenceLeaseMissingKeeperFailsClosed", []string{"TestCHIntelligenceLeaseMissingKeeperFailsClosed"}},
		{"clickhouse-integration", "test_packages=(", []string{"TestCHIntelligenceLeaseNativeContentionAndFencing", "TestCHIntelligenceLeaseNativeExpiryAndLargeCheckpoint", "TestCHIntelligenceLeaseRejectsNonAtomicControlCatalog", "TestWorkerClassifiesAgainstClickHouse", "TestServerServesDataFromClickHouse"}},
		{"postgres-lease-integration", "pattern='^TestPGIntelligenceLease'", []string{"TestPGIntelligenceLeaseIndependentOwnersAndAliases", "TestPGIntelligenceLeaseShadowCheckpointCannotSplitOwner", "TestPGIntelligenceLeaseRejectsDifferentProjectionScope", "TestPGIntelligenceLeaseCoordinatesDifferentDatabaseRoles", "TestPGIntelligenceLeaseExpiryRecoveryAndLargeCheckpoint", "TestPGIntelligenceLeaseClockCheckedAfterRowLock", "TestPGIntelligenceLeasePublicCheckpointProjectionAndTags"}},
		{"elasticsearch-lease-integration", "required=TestElasticsearchIntelligenceLeaseLive", []string{"TestElasticsearchIntelligenceLeaseLive"}},
	} {
		t.Run(gate.marker, func(t *testing.T) {
			job, ok := w.Job(gate.job)
			if !ok {
				t.Fatal("native lease job missing")
			}
			body := ""
			for _, step := range job.Steps {
				if strings.Contains(step.Run, gate.marker) {
					body = step.Run
				}
			}
			if body == "" {
				t.Fatal("native lease gate script missing")
			}
			type scenario struct {
				name, omit string
				want       int
			}
			scenarios := []scenario{{"accepted", "", 0}, {"list command failure", "", 19}, {"test command failure", "", 23}, {"required test skipped", "", 1}}
			for _, required := range gate.required {
				scenarios = append(scenarios, scenario{"missing " + required, required, 1})
			}
			for _, scenario := range scenarios {
				t.Run(scenario.name, func(t *testing.T) {
					dir := t.TempDir()
					bin := filepath.Join(dir, "bin")
					if err := os.Mkdir(bin, 0o700); err != nil {
						t.Fatal(err)
					}
					fakeGo := `#!/bin/sh
set -eu
case " $* " in
 *' -list '*)
  if [ "$QPOT_FAKE_SCENARIO" = 'list command failure' ]; then exit 19; fi
  while IFS= read -r name; do
   if [ "$name" != "$QPOT_FAKE_OMIT" ]; then printf '%s\n' "$name"; fi
  done < "$QPOT_FAKE_INVENTORY"
  exit 0;;
esac
printf '%s\n' "$*" >> "$QPOT_FAKE_TRACE"
if [ "$QPOT_FAKE_SCENARIO" = 'test command failure' ]; then exit 23; fi
if [ "$QPOT_FAKE_SCENARIO" = 'required test skipped' ]; then
 printf '%s\n' '{"Action":"skip","Test":"required"}'
else
 printf '%s\n' '{"Action":"pass","Test":"required"}'
fi
`
					if err := os.WriteFile(filepath.Join(bin, "go"), []byte(fakeGo), 0o700); err != nil {
						t.Fatal(err)
					}
					inventory := filepath.Join(dir, "inventory")
					if err := os.WriteFile(inventory, []byte(strings.Join(gate.required, "\n")+"\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					trace := filepath.Join(dir, "trace")
					ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, bash, "-c", body)
					cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "RUNNER_TEMP="+dir, "QPOT_FAKE_SCENARIO="+scenario.name, "QPOT_FAKE_OMIT="+scenario.omit, "QPOT_FAKE_INVENTORY="+inventory, "QPOT_FAKE_TRACE="+trace)
					output, runErr := cmd.CombinedOutput()
					code := 0
					if runErr != nil {
						if exit, ok := runErr.(*exec.ExitError); ok {
							code = exit.ExitCode()
						} else {
							t.Fatal(runErr)
						}
					}
					if code != scenario.want {
						t.Fatalf("exit %d, want %d: %s", code, scenario.want, output)
					}
					_, traceErr := os.Stat(trace)
					shouldRun := scenario.omit == "" && scenario.name != "list command failure"
					if (traceErr == nil) != shouldRun {
						t.Fatal("required-test inventory did not control whether the native gate ran")
					}
				})
			}
		})
	}
}
