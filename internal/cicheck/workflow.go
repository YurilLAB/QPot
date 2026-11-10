// Package cicheck reads QPot's CI workflow and the tool versions it shares
// with scripts/ci-local.sh, and runs the workflow's jobs on a local machine
// the way GitHub Actions runs them: the same run: scripts, in the same
// order, with the same environment, so a local pass means what a CI pass
// means.
package cicheck

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Workflow is the part of a GitHub Actions workflow the local runner uses.
type Workflow struct {
	Env  map[string]string
	Jobs []Job // in file order
}

// Job is one job of a workflow.
type Job struct {
	ID             string
	Name           string
	RunsOn         string
	TimeoutMinutes int
	Env            map[string]string
	Services       []Service
	Matrix         []map[string]string // strategy.matrix.include; nil without a matrix
	Steps          []Step
}

// Service is a job's service container.
type Service struct {
	Name    string
	Image   string
	Env     map[string]string
	Ports   []string
	Options string
}

// Step is one step of a job.
type Step struct {
	Name, ID, Uses, Run, If, Shell, WorkingDirectory string
	With, Env                                        map[string]string
}

// Label names the step as the Actions log does.
func (s Step) Label() string {
	switch {
	case s.Name != "":
		return s.Name
	case s.Uses != "":
		return "Run " + s.Uses
	}
	return "Run " + firstLineOf(s.Run)
}

func firstLineOf(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return l
}

type rawStep struct {
	Name             string            `yaml:"name"`
	ID               string            `yaml:"id"`
	Uses             string            `yaml:"uses"`
	Run              string            `yaml:"run"`
	If               string            `yaml:"if"`
	Shell            string            `yaml:"shell"`
	WorkingDirectory string            `yaml:"working-directory"`
	With             map[string]string `yaml:"with"`
	Env              map[string]string `yaml:"env"`
	ContinueOnError  bool              `yaml:"continue-on-error"`
}

type rawService struct {
	Image   string            `yaml:"image"`
	Env     map[string]string `yaml:"env"`
	Ports   []string          `yaml:"ports"`
	Options string            `yaml:"options"`
}

type rawJob struct {
	Name           string                `yaml:"name"`
	RunsOn         string                `yaml:"runs-on"`
	TimeoutMinutes int                   `yaml:"timeout-minutes"`
	Env            map[string]string     `yaml:"env"`
	Services       map[string]rawService `yaml:"services"`
	Strategy       struct {
		FailFast *bool                `yaml:"fail-fast"`
		Matrix   map[string]yaml.Node `yaml:"matrix"`
	} `yaml:"strategy"`
	Steps []rawStep `yaml:"steps"`
}

// ParseWorkflow reads a workflow file. It refuses what the local runner
// cannot reproduce faithfully (a step that continues on error, a matrix
// other than include entries), so nothing is silently run differently.
func ParseWorkflow(data []byte) (*Workflow, error) {
	var raw struct {
		Env  map[string]string `yaml:"env"`
		Jobs yaml.Node         `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if raw.Jobs.Kind != yaml.MappingNode {
		return nil, errors.New("cicheck: the workflow has no jobs")
	}
	w := &Workflow{Env: raw.Env}
	for i := 0; i+1 < len(raw.Jobs.Content); i += 2 {
		id := raw.Jobs.Content[i].Value
		var rj rawJob
		if err := raw.Jobs.Content[i+1].Decode(&rj); err != nil {
			return nil, fmt.Errorf("cicheck: job %s: %w", id, err)
		}
		j := Job{ID: id, Name: rj.Name, RunsOn: rj.RunsOn, TimeoutMinutes: rj.TimeoutMinutes, Env: rj.Env}
		names := make([]string, 0, len(rj.Services))
		for n := range rj.Services {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			s := rj.Services[n]
			j.Services = append(j.Services, Service{Name: n, Image: s.Image, Env: s.Env, Ports: s.Ports, Options: s.Options})
		}
		for k, v := range rj.Strategy.Matrix {
			if k != "include" {
				return nil, fmt.Errorf("cicheck: job %s: matrix key %q is not supported (use include entries)", id, k)
			}
			if err := v.Decode(&j.Matrix); err != nil {
				return nil, fmt.Errorf("cicheck: job %s: matrix: %w", id, err)
			}
		}
		for _, rs := range rj.Steps {
			if rs.ContinueOnError {
				return nil, fmt.Errorf("cicheck: job %s step %q: continue-on-error is not supported", id, rs.Name)
			}
			j.Steps = append(j.Steps, Step{Name: rs.Name, ID: rs.ID, Uses: rs.Uses, Run: rs.Run, If: rs.If,
				Shell: rs.Shell, WorkingDirectory: rs.WorkingDirectory, With: rs.With, Env: rs.Env})
		}
		w.Jobs = append(w.Jobs, j)
	}
	return w, nil
}

// Job returns the job with that id.
func (w *Workflow) Job(id string) (Job, bool) {
	for _, j := range w.Jobs {
		if j.ID == id {
			return j, true
		}
	}
	return Job{}, false
}

var exprRe = regexp.MustCompile(`\$\{\{\s*([^}]*?)\s*\}\}`)

// Expand replaces ${{ matrix.X }} and ${{ env.X }} expressions. Any other
// expression is an error: the local runner cannot know its value.
func Expand(s string, matrix, env map[string]string) (string, error) {
	return expandWithServices(s, matrix, env, nil)
}

// serviceIDExpression deliberately accepts only the service-container ID
// context used by the workflow, not arbitrary job metadata or expressions.
func serviceIDExpression(expr string) (string, bool) {
	parts := strings.Split(expr, ".")
	if len(parts) != 4 || parts[0] != "job" || parts[1] != "services" || parts[2] == "" || parts[3] != "id" {
		return "", false
	}
	return parts[2], true
}

func validServiceID(id string) bool {
	return len(id) == 64 && strings.Trim(id, "0123456789abcdef") == ""
}

func expandWithServices(s string, matrix, env, services map[string]string) (string, error) {
	var bad error
	out := exprRe.ReplaceAllStringFunc(s, func(m string) string {
		expr := strings.TrimSpace(exprRe.FindStringSubmatch(m)[1])
		scope, key, ok := strings.Cut(expr, ".")
		var v string
		var have bool
		switch {
		case ok && scope == "matrix":
			v, have = matrix[key]
		case ok && scope == "env":
			v, have = env[key]
		case ok && scope == "job":
			if service, valid := serviceIDExpression(expr); valid {
				v, have = services[service]
				have = have && validServiceID(v)
			}
		}
		if !have {
			if bad == nil {
				bad = fmt.Errorf("cicheck: the expression ${{ %s }} has no local value", expr)
			}
			return m
		}
		return v
	})
	return out, bad
}

var (
	toolKeyRe   = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	toolValueRe = regexp.MustCompile(`^[A-Za-z0-9.,_+-]+$`)
)

// ParseToolsEnv reads .github/ci-tools.env: blank lines, # comments and
// KEY=value lines. Values are plain words (no quotes, spaces or $), so the
// file means the same to GitHub's $GITHUB_ENV and to a shell.
func ParseToolsEnv(data []byte) (map[string]string, error) {
	out := map[string]string{}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		switch {
		case !ok || !toolKeyRe.MatchString(k):
			return nil, fmt.Errorf("cicheck: ci-tools.env line %d: not KEY=value", i+1)
		case !toolValueRe.MatchString(v):
			return nil, fmt.Errorf("cicheck: ci-tools.env line %d: the value of %s must be letters, digits and . , _ + -", i+1, k)
		}
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("cicheck: ci-tools.env line %d: %s is set twice", i+1, k)
		}
		out[k] = v
	}
	return out, nil
}
