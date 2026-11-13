package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/qpot/qpot/internal/behaviour"
	"github.com/qpot/qpot/internal/config"
)

// alertsInstance makes instance "lab" exist and answers /api/alerts from
// memory, recording what was asked.
func alertsInstance(t *testing.T) (view *alertsView, calls *[]string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	path := config.Default("lab").ConfigPath
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("instance_name: lab\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	since := time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC)
	view = &alertsView{Enabled: true, Running: true, Webhook: true, Hooks: 2, Since: &since}
	for _, r := range behaviour.Rules {
		view.Rules = append(view.Rules, struct {
			behaviour.Rule
			Enabled bool `json:"enabled"`
		}{r, true})
	}
	view.Alerts = []behaviour.Alert{
		{ID: "a1", Rule: behaviour.RuleProgression, Severity: "high", Time: since.Add(time.Hour), Title: "A session went from discovery to persistence \x1b[2J",
			SessionID: "0123456789abcdef0123456789abcdef-1", Sources: []string{"198.51.100.2"}},
		{ID: "a2", Rule: behaviour.RuleSharedPlaybook, Severity: "medium", Time: since.Add(2 * time.Hour), Title: "2 sources share one playbook", Campaign: "c0ffee"},
	}
	calls = new([]string)
	real := alertsAPI
	t.Cleanup(func() { alertsAPI = real })
	alertsAPI = func(_ context.Context, name, method, path string, body any) (*alertsView, error) {
		if name != "lab" {
			return nil, errors.New("server not reachable (run 'qpot up' first)")
		}
		data, _ := json.Marshal(body)
		*calls = append(*calls, method+" "+path+" "+string(data))
		if method == http.MethodPut {
			req := body.(map[string]any)
			on := req["enabled"].(bool)
			rule, _ := req["rule"].(string)
			if rule == "" {
				view.Enabled, view.Running = on, on
			}
			for i := range view.Rules {
				if rule == "" || view.Rules[i].Name == rule {
					view.Rules[i].Enabled = on
				}
			}
		}
		return view, nil
	}
	return view, calls
}

func executeAlerts(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := &cobra.Command{Use: "qpot", SilenceUsage: true, SilenceErrors: true, PersistentPreRunE: checkInstanceFlag}
	root.AddCommand(newAlertsCommand())
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"alerts"}, args...))
	err := root.Execute()
	return out.String(), err
}

func TestAlertsCommand(t *testing.T) {
	view, calls := alertsInstance(t)

	out, err := executeAlerts(t, "-i", "lab")
	if err != nil {
		t.Fatalf("alerts: %v\n%s", err, out)
	}
	for _, want := range []string{"Behaviour alerts are on. An alert goes to this list, the control plane's log, the webhook, 2 response hooks.",
		"Watching since 2026-11-14 08:00 UTC", "yes  new-payload", "yes  returning-visitor",
		"2026-11-14 09:00:05"[:16], "progression", `discovery to persistence \x1b[2J`, "from 198.51.100.2",
		"qpot investigate session 0123456789abcdef0123456789abcdef-1", "qpot investigate campaign c0ffee"} {
		if !strings.Contains(out, want) {
			t.Errorf("alerts lacks %q:\n%s", want, out)
		}
	}
	if strings.ContainsRune(out, 0x1b) {
		t.Fatal("an escape sequence reached the terminal")
	}
	if (*calls)[0] != "GET /api/alerts?limit=30 null" {
		t.Fatalf("asked %q", (*calls)[0])
	}
	out, err = executeAlerts(t, "-i", "lab", "--json", "--limit", "5")
	var got alertsView
	if err != nil || json.Unmarshal([]byte(out), &got) != nil || len(got.Alerts) != 2 || len(got.Rules) != 5 {
		t.Fatalf("--json: %v\n%s", err, out)
	}

	out, err = executeAlerts(t, "disable", "returning-visitor", "-i", "lab")
	if err != nil || !strings.Contains(out, "no   returning-visitor") || !strings.Contains(out, "yes  progression") ||
		(*calls)[len(*calls)-1] != `PUT /api/alerts {"enabled":false,"rule":"returning-visitor"}` {
		t.Fatalf("disable: %v, asked %q\n%s", err, (*calls)[len(*calls)-1], out)
	}
	out, err = executeAlerts(t, "disable", "all", "-i", "lab")
	if err != nil || !strings.Contains(out, "Behaviour alerts are turned off") || (*calls)[len(*calls)-1] != `PUT /api/alerts {"enabled":false}` {
		t.Fatalf("disable all: %v\n%s", err, out)
	}
	if out, err = executeAlerts(t, "enable", "all", "-i", "lab"); err != nil || !strings.Contains(out, "yes  returning-visitor") {
		t.Fatalf("enable all: %v\n%s", err, out)
	}
	view.Running = false
	if out, _ = executeAlerts(t, "-i", "lab"); !strings.Contains(out, "the intelligence worker is off") {
		t.Fatalf("worker off:\n%s", out)
	}
	view.Problem = "The alert state file cannot be used."
	if out, _ = executeAlerts(t, "-i", "lab"); !strings.Contains(out, "cannot run: The alert state file") {
		t.Fatalf("problem:\n%s", out)
	}

	asked := len(*calls)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"enable", "volume", "-i", "lab"}, `there is no rule "volume"`},
		{[]string{"enable", "-i", "lab"}, "accepts 1 arg"},
		{[]string{"-i", "lab", "--limit", "0"}, "--limit must be"},
		{[]string{"-i", "missing"}, `instance "missing" does not exist`},
	} {
		if out, err := executeAlerts(t, tc.args...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v\n%s", tc.args, err, out)
		}
	}
	if len(*calls) != asked {
		t.Fatalf("a refused command reached the instance: %v", (*calls)[asked:])
	}
}
