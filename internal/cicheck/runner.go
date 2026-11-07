package cicheck

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Runner runs workflow jobs on this machine: each run: step through
// `bash --noprofile --norc -eo pipefail`, as Actions does for a bash run:
// step on Linux, with $GITHUB_ENV, $GITHUB_PATH and $GITHUB_STEP_SUMMARY
// working the same way. The few actions the jobs use are replaced by
// their local equivalents (see uses); any other action is an error.
type Runner struct {
	Root  string            // the repository root ($GITHUB_WORKSPACE)
	Tools map[string]string // .github/ci-tools.env
	Out   io.Writer
	Env   []string // the starting environment, usually os.Environ()
	// GitleaksRange is the git log range the gitleaks step scans; empty
	// means the commits not yet on the upstream branch (what a push scans).
	GitleaksRange string
}

// usesHandler runs one action locally.
type usesHandler func(ctx context.Context, r *Runner, st *jobState, s Step) error

// uses maps an action (the part of uses: before @) to its local
// equivalent. Check refuses a workflow that uses anything else.
var uses = map[string]usesHandler{
	"actions/checkout": func(_ context.Context, r *Runner, _ *jobState, _ Step) error {
		fmt.Fprintf(r.Out, "(the working tree %s is the checkout)\n", r.Root)
		return nil
	},
	"actions/setup-go":                  setupGo,
	"actions/setup-python":              setupPython,
	"actions/upload-artifact":           uploadOnly,
	"github/codeql-action/upload-sarif": uploadOnly,
	"gitleaks/gitleaks-action":          runGitleaks,
}

func actionName(u string) string { n, _, _ := strings.Cut(u, "@"); return n }

// Local reports whether ci-local runs the job: CI runs it on Linux. Jobs on
// other runners (the Windows installer tests) are reported as not run.
func (j Job) Local() bool { return strings.HasPrefix(j.RunsOn, "ubuntu-") }

// Check reports why the runner cannot run a job faithfully, or nil. A job
// that is not Local is not run, so there is nothing to check.
func (r *Runner) Check(w *Workflow, j Job) error {
	if !j.Local() {
		return nil
	}
	var problems []string
	matrix := map[string]string{}
	if len(j.Matrix) > 0 {
		matrix = j.Matrix[0]
	}
	for _, s := range j.Steps {
		switch {
		case s.Uses != "" && s.Run != "":
			problems = append(problems, fmt.Sprintf("step %q has both uses and run", s.Label()))
		case s.Uses != "":
			if h, ok := uses[actionName(s.Uses)]; !ok || h == nil {
				problems = append(problems, fmt.Sprintf("step %q uses %s, which ci-local cannot run", s.Label(), s.Uses))
			}
		case s.Shell != "" && s.Shell != "bash":
			problems = append(problems, fmt.Sprintf("step %q uses shell %q", s.Label(), s.Shell))
		}
		if s.If != "" && s.If != "always()" {
			problems = append(problems, fmt.Sprintf("step %q has if: %s", s.Label(), s.If))
		}
		if s.Uses == "" {
			if err := checkExpr(s.Run, matrix); err != nil {
				problems = append(problems, fmt.Sprintf("step %q: %v", s.Label(), err))
			}
			for k, v := range s.Env {
				if err := checkExpr(v, matrix); err != nil {
					problems = append(problems, fmt.Sprintf("step %q env %s: %v", s.Label(), k, err))
				}
			}
		}
	}
	for _, sv := range j.Services {
		if sv.Image == "" {
			problems = append(problems, "service "+sv.Name+" has no image")
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("job %s: %s", j.ID, strings.Join(problems, "; "))
	}
	return nil
}

// checkExpr accepts expressions whose value the runner knows: matrix
// values and environment variables.
func checkExpr(s string, matrix map[string]string) error {
	for _, m := range exprRe.FindAllStringSubmatch(s, -1) {
		scope, key, _ := strings.Cut(strings.TrimSpace(m[1]), ".")
		switch scope {
		case "env":
		case "matrix":
			if _, ok := matrix[key]; !ok {
				return fmt.Errorf("unknown ${{ %s }}", m[1])
			}
		default:
			return fmt.Errorf("the expression ${{ %s }} has no local value", m[1])
		}
	}
	return nil
}

// jobState is one run of a job (one matrix entry).
type jobState struct {
	env    map[string]string
	matrix map[string]string
	tmp    string
}

func (st *jobState) environ(extra map[string]string) []string {
	all := map[string]string{}
	for k, v := range st.env {
		all[k] = v
	}
	for k, v := range extra {
		all[k] = v
	}
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+all[k])
	}
	return out
}

// RunJob runs every matrix entry of a job (once without a matrix).
func (r *Runner) RunJob(ctx context.Context, w *Workflow, j Job) error {
	if !j.Local() {
		return fmt.Errorf("job %s runs on %s in CI; ci-local runs only the Linux jobs", j.ID, j.RunsOn)
	}
	if err := r.Check(w, j); err != nil {
		return err
	}
	entries := j.Matrix
	if len(entries) == 0 {
		entries = []map[string]string{nil}
	}
	var failed []string
	for _, m := range entries {
		label := j.ID
		if m != nil {
			label += " " + formatMatrix(m)
		}
		fmt.Fprintf(r.Out, "\n=== job %s\n", label)
		if err := r.runOnce(ctx, w, j, m); err != nil {
			fmt.Fprintf(r.Out, "=== job %s FAILED: %v\n", label, err)
			failed = append(failed, label)
			continue
		}
		fmt.Fprintf(r.Out, "=== job %s passed\n", label)
	}
	if len(failed) > 0 {
		return fmt.Errorf("failed: %s", strings.Join(failed, ", "))
	}
	return nil
}

func formatMatrix(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

func (r *Runner) runOnce(ctx context.Context, w *Workflow, j Job, matrix map[string]string) (err error) {
	if j.TimeoutMinutes > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(j.TimeoutMinutes)*time.Minute)
		defer cancel()
	}
	tmp, err := os.MkdirTemp("", "qpot-ci-local-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	st := &jobState{env: map[string]string{}, matrix: matrix, tmp: tmp}
	for _, kv := range r.Env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			st.env[k] = v
		}
	}
	files := map[string]string{"GITHUB_ENV": "env", "GITHUB_PATH": "path", "GITHUB_STEP_SUMMARY": "summary.md", "GITHUB_OUTPUT": "output"}
	for k, name := range files {
		p := filepath.Join(tmp, name)
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			return err
		}
		st.env[k] = p
	}
	st.env["CI"] = "true"
	st.env["GITHUB_WORKSPACE"] = r.Root
	st.env["RUNNER_TEMP"] = tmp
	st.env["RUNNER_OS"] = "Linux"
	for _, scope := range []map[string]string{w.Env, j.Env} {
		for k, v := range scope {
			x, err := Expand(v, matrix, st.env)
			if err != nil {
				return err
			}
			st.env[k] = x
		}
	}
	stop, err := r.startServices(ctx, j, st)
	defer stop()
	if err != nil {
		return err
	}
	var firstErr error
	for i, s := range j.Steps {
		if firstErr != nil && s.If != "always()" {
			fmt.Fprintf(r.Out, "--- skipped: %s\n", s.Label())
			continue
		}
		fmt.Fprintf(r.Out, "--- step %d: %s\n", i+1, s.Label())
		var serr error
		if s.Uses != "" {
			serr = uses[actionName(s.Uses)](ctx, r, st, s)
		} else {
			serr = r.runStep(ctx, st, i, s)
		}
		if aerr := st.applyFiles(); aerr != nil && serr == nil {
			serr = aerr
		}
		if serr != nil {
			fmt.Fprintf(r.Out, "--- step %q failed: %v\n", s.Label(), serr)
			if firstErr == nil {
				firstErr = fmt.Errorf("step %q: %w", s.Label(), serr)
			}
		}
		if ctx.Err() != nil {
			return fmt.Errorf("the job's %d-minute limit passed", j.TimeoutMinutes)
		}
	}
	return firstErr
}

func (r *Runner) runStep(ctx context.Context, st *jobState, i int, s Step) error {
	script, err := Expand(s.Run, st.matrix, st.env)
	if err != nil {
		return err
	}
	stepEnv := map[string]string{}
	for k, v := range s.Env {
		x, err := Expand(v, st.matrix, st.env)
		if err != nil {
			return err
		}
		stepEnv[k] = x
	}
	f := filepath.Join(st.tmp, "step-"+strconv.Itoa(i+1)+".sh")
	if err := os.WriteFile(f, []byte(script), 0o600); err != nil {
		return err
	}
	dir := r.Root
	if s.WorkingDirectory != "" {
		dir = filepath.Join(r.Root, filepath.FromSlash(s.WorkingDirectory))
	}
	cmd := exec.CommandContext(ctx, "bash", "--noprofile", "--norc", "-eo", "pipefail", f) // #nosec G204 -- the workflow's own run: script
	cmd.Dir = dir
	cmd.Env = st.environ(stepEnv)
	cmd.Stdout, cmd.Stderr = r.Out, r.Out
	killGroup(cmd)
	return cmd.Run()
}

// applyFiles applies what a step wrote to $GITHUB_ENV and $GITHUB_PATH, as
// Actions does between steps, and empties the files.
func (st *jobState) applyFiles() error {
	envFile, pathFile := st.env["GITHUB_ENV"], st.env["GITHUB_PATH"]
	data, err := os.ReadFile(envFile) // #nosec G304 -- the job's own temp file
	if err != nil {
		return err
	}
	vars, err := parseEnvFile(string(data))
	if err != nil {
		return err
	}
	for k, v := range vars {
		st.env[k] = v
	}
	paths, err := os.ReadFile(pathFile) // #nosec G304 -- the job's own temp file
	if err != nil {
		return err
	}
	for _, p := range strings.Split(strings.TrimSpace(string(paths)), "\n") {
		if p = strings.TrimSpace(p); p != "" {
			st.env["PATH"] = p + string(os.PathListSeparator) + st.env["PATH"]
		}
	}
	if err := os.WriteFile(envFile, nil, 0o600); err != nil {
		return err
	}
	return os.WriteFile(pathFile, nil, 0o600)
}

// parseEnvFile reads the $GITHUB_ENV format: NAME=value lines, and
// NAME<<DELIMITER ... DELIMITER for values over several lines.
func parseEnvFile(s string) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(s))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSuffix(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if name, delim, ok := strings.Cut(line, "<<"); ok && !strings.Contains(name, "=") {
			var val []string
			closed := false
			for sc.Scan() {
				l := strings.TrimSuffix(sc.Text(), "\r")
				if l == delim {
					closed = true
					break
				}
				val = append(val, l)
			}
			if !closed {
				return nil, fmt.Errorf("$GITHUB_ENV: %s has no closing %s", name, delim)
			}
			out[name] = strings.Join(val, "\n")
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("$GITHUB_ENV: %q is not NAME=value", line)
		}
		out[k] = v
	}
	return out, sc.Err()
}

func setupGo(ctx context.Context, r *Runner, st *jobState, _ Step) error {
	cmd := exec.CommandContext(ctx, "go", "version")
	cmd.Env = st.environ(nil)
	cmd.Dir = r.Root
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go is not installed (CI sets it up from go.mod): %v", err)
	}
	fmt.Fprintf(r.Out, "%s", out)
	return nil
}

func setupPython(_ context.Context, r *Runner, st *jobState, s Step) error {
	v := s.With["python-version"]
	if v == "" {
		return errors.New("actions/setup-python without python-version")
	}
	want := "python" + v
	p, err := lookPathIn(want, st.env["PATH"])
	if err != nil {
		return fmt.Errorf("CI runs this job with Python %s (actions/setup-python); install %s, or skip the job", v, want)
	}
	bin := filepath.Join(st.tmp, "python-bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		return err
	}
	for _, n := range []string{"python", "python3"} {
		if err := os.Symlink(p, filepath.Join(bin, n)); err != nil {
			return err
		}
	}
	st.env["PATH"] = bin + string(os.PathListSeparator) + st.env["PATH"]
	fmt.Fprintf(r.Out, "python3 is %s\n", p)
	return nil
}

func lookPathIn(name, path string) (string, error) {
	for _, dir := range filepath.SplitList(path) {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", exec.ErrNotFound
}

func uploadOnly(_ context.Context, r *Runner, _ *jobState, s Step) error {
	fmt.Fprintf(r.Out, "(%s only uploads to GitHub; nothing to check locally)\n", actionName(s.Uses))
	return nil
}

// runGitleaks runs the gitleaks version CI pins on the commits a push of
// this branch would scan (gitleaks-action scans the pushed commits).
func runGitleaks(ctx context.Context, r *Runner, st *jobState, _ Step) error {
	v := st.env["GITLEAKS_VERSION"]
	if v == "" {
		v = r.Tools["GITLEAKS_VERSION"]
	}
	if v == "" {
		return errors.New("GITLEAKS_VERSION is not set in .github/ci-tools.env")
	}
	run := func(name string, args ...string) error {
		cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- fixed tools with the pinned version
		cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = r.Root, st.environ(nil), r.Out, r.Out
		killGroup(cmd)
		return cmd.Run()
	}
	if err := run("go", "install", "github.com/zricethezav/gitleaks/v8@v"+v); err != nil {
		return fmt.Errorf("installing gitleaks v%s: %w", v, err)
	}
	gopath, err := exec.CommandContext(ctx, "go", "env", "GOPATH").Output()
	if err != nil {
		return err
	}
	rng := r.GitleaksRange
	if rng == "" {
		if exec.CommandContext(ctx, "git", "-C", r.Root, "rev-parse", "--verify", "-q", "@{upstream}").Run() == nil {
			rng = "@{upstream}..HEAD"
		}
	}
	args := []string{"git", "--redact", "--no-banner", "-v", "--exit-code", "1"}
	if rng != "" {
		args = append(args, "--log-opts="+rng)
	}
	fmt.Fprintf(r.Out, "gitleaks v%s, commits: %s\n", v, firstNonEmpty(rng, "all history"))
	return run(filepath.Join(strings.TrimSpace(string(gopath)), "bin", "gitleaks"), append(args, r.Root)...)
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

// startServices starts the job's service containers with docker, published
// on 127.0.0.1 only, and waits until their health checks pass.
func (r *Runner) startServices(ctx context.Context, j Job, st *jobState) (func(), error) {
	var started []string
	stop := func() {
		for _, n := range started {
			_ = exec.Command("docker", "rm", "-f", n).Run() // #nosec G204 -- our own container names
		}
	}
	for _, sv := range j.Services {
		name := fmt.Sprintf("qpot-ci-local-%s-%s-%d", j.ID, sv.Name, os.Getpid())
		args := []string{"run", "-d", "--name", name}
		for _, p := range sv.Ports {
			args = append(args, "-p", "127.0.0.1:"+p)
		}
		keys := make([]string, 0, len(sv.Env))
		for k := range sv.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			args = append(args, "-e", k+"="+sv.Env[k])
		}
		opts, err := splitWords(sv.Options)
		if err != nil {
			return stop, fmt.Errorf("service %s options: %w", sv.Name, err)
		}
		args = append(append(args, opts...), sv.Image)
		cmd := exec.CommandContext(ctx, "docker", args...) // #nosec G204 -- the workflow's own service definition
		cmd.Stdout, cmd.Stderr = r.Out, r.Out
		if err := cmd.Run(); err != nil {
			return stop, fmt.Errorf("service %s needs Docker (docker run failed: %v)", sv.Name, err)
		}
		started = append(started, name)
		fmt.Fprintf(r.Out, "service %s: %s\n", sv.Name, name)
		deadline := time.Now().Add(3 * time.Minute)
		for {
			out, _ := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{if .State.Health}}{{.State.Health.Status}}{{else}}running{{end}}", name).Output() // #nosec G204 -- our own container name
			status := strings.TrimSpace(string(out))
			if status == "healthy" || status == "running" {
				break
			}
			if time.Now().After(deadline) || ctx.Err() != nil {
				return stop, fmt.Errorf("service %s did not become healthy (%s)", sv.Name, status)
			}
			time.Sleep(2 * time.Second)
		}
	}
	return stop, nil
}

// splitWords splits a docker options string into words, honouring double
// and single quotes (the workflow writes --health-cmd "..." this way).
func splitWords(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	in, quote := false, rune(0)
	for _, c := range s {
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteRune(c)
			}
		case c == '"' || c == '\'':
			quote, in = c, true
		case c == ' ' || c == '\t' || c == '\n':
			if in {
				out = append(out, cur.String())
				cur.Reset()
				in = false
			}
		default:
			cur.WriteRune(c)
			in = true
		}
	}
	if quote != 0 {
		return nil, errors.New("unclosed quote")
	}
	if in {
		out = append(out, cur.String())
	}
	return out, nil
}
