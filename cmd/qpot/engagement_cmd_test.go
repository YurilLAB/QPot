package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// engagementLog is one Cowrie session that logs in, runs a probe and leaves,
// then a line that is not an event.
const engagementLog = `{"eventid":"cowrie.session.connect","src_ip":"203.0.113.5","session":"aa11","timestamp":"2026-03-01T10:00:00.000000Z"}
{"eventid":"cowrie.login.success","username":"root","password":"admin","src_ip":"203.0.113.5","session":"aa11","timestamp":"2026-03-01T10:00:01.000000Z"}
{"eventid":"cowrie.command.input","input":"uname -a","src_ip":"203.0.113.5","session":"aa11","timestamp":"2026-03-01T10:00:02.000000Z"}
{"eventid":"cowrie.session.closed","duration":4.5,"src_ip":"203.0.113.5","session":"aa11","timestamp":"2026-03-01T10:00:04.500000Z"}
not an event
`

// runEngagement runs `qpot engagement` under a root command that checks the
// instance flag the way the real one does.
func runEngagement(t *testing.T, args ...string) (string, error) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	root := &cobra.Command{Use: "qpot", SilenceUsage: true, SilenceErrors: true, PersistentPreRunE: checkInstanceFlag}
	root.AddCommand(newEngagementCommand())
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"engagement"}, args...))
	err := root.Execute()
	return out.String(), err
}

func TestEngagementCommandOnCowrieLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cowrie.json")
	if err := os.WriteFile(path, []byte(engagementLog), 0o600); err != nil {
		t.Fatal(err)
	}

	// No instance exists and none is named: the log alone is enough.
	text, err := runEngagement(t, "--cowrie-log", path)
	if err != nil {
		t.Fatalf("engagement on a log failed: %v\n%s", err, text)
	}
	for _, want := range []string{"METRIC", "COWRIE.JSON", "Logged in", "100.0%", "Left after a probe", "4.5s", "Log lines: 5 read, 1 malformed", "Top command stems: uname (1)"} {
		if !strings.Contains(text, want) {
			t.Errorf("%q is missing from:\n%s", want, text)
		}
	}
	if strings.Contains(text, "qp_") {
		t.Errorf("the output names a QPot ID:\n%s", text)
	}

	// Two logs, one labelled: JSON with both reports and their comparison.
	raw, err := runEngagement(t, "--cowrie-log", path, "--label", "stock", "--cowrie-log", path, "--json")
	if err != nil {
		t.Fatalf("engagement --json failed: %v\n%s", err, raw)
	}
	var got engagementOutput
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, raw)
	}
	if len(got.Reports) != 2 || len(got.Comparisons) != 1 {
		t.Fatalf("reports = %d, comparisons = %d, want 2 and 1", len(got.Reports), len(got.Comparisons))
	}
	first, second := got.Reports[0], got.Reports[1]
	if first.Label != "stock" || second.Label != "cowrie.json" || first.Source != "cowrie-log" {
		t.Errorf("labels = %q, %q, source = %q", first.Label, second.Label, first.Source)
	}
	m := first.Overall
	if m.Sessions != 1 || m.Funnel.LoggedIn.Count != 1 || m.Depth.Max != 1 || m.LeftAfterProbe.Count != 1 || m.Duration.All.MaxSeconds != 4.5 {
		t.Errorf("metrics = %+v", m)
	}
	if first.Input.Log == nil || first.Input.Log.Lines != 5 || first.Input.Log.Malformed != 1 || first.Input.Log.Events != 4 {
		t.Errorf("log stats = %+v", first.Input.Log)
	}
	if c := got.Comparisons[0]; c.A != "stock" || c.B != "cowrie.json" || len(c.Deltas) == 0 {
		t.Errorf("comparison = %+v", c)
	}

	// --since limits a log to the window; the fixture is older than a day.
	raw, err = runEngagement(t, "--cowrie-log", path, "--since", "1d", "--json")
	if err != nil {
		t.Fatal(err)
	}
	got = engagementOutput{}
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	if time.Since(time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC)) > 0 {
		if r := got.Reports[0]; r.Overall.Sessions != 0 || r.Input.Log.OutsideWindow != 4 {
			t.Errorf("with --since 1d: sessions = %d, outside the window = %d", r.Overall.Sessions, r.Input.Log.OutsideWindow)
		}
	}
}

func TestEngagementCommandErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cowrie.json")
	if err := os.WriteFile(path, []byte(engagementLog), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"nothing to measure", nil, "name an instance"},
		{"missing log", []string{"--cowrie-log", filepath.Join(t.TempDir(), "none.json")}, "cannot read the Cowrie log"},
		{"more labels than logs", []string{"--cowrie-log", path, "--label", "a", "--label", "b"}, "more labels than logs"},
		{"bad window", []string{"--cowrie-log", path, "--since", "soon"}, "invalid --since"},
		{"zero window", []string{"--cowrie-log", path, "--since", "0d"}, "invalid --since"},
		{"bad honeypot", []string{"--cowrie-log", path, "--honeypot", "a b"}, "invalid honeypot name"},
		{"instance that does not exist", []string{"-i", "nosuchinstance"}, "does not exist"},
		{"invalid instance name", []string{"-i", "../x"}, "invalid instance name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runEngagement(t, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want one containing %q\n%s", err, tc.want, out)
			}
		})
	}
}

func TestEngagementParseSince(t *testing.T) {
	good := map[string]time.Duration{"7d": 7 * 24 * time.Hour, "2w": 14 * 24 * time.Hour, "36h": 36 * time.Hour, " 1d ": 24 * time.Hour, "90m": 90 * time.Minute}
	for in, want := range good {
		if got, err := parseSince(in); err != nil || got != want {
			t.Errorf("parseSince(%q) = %v, %v, want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "d", "-1d", "0w", "1.5d", "99999d", "-3h", "0s", "week"} {
		if got, err := parseSince(in); err == nil {
			t.Errorf("parseSince(%q) = %v, want an error", in, got)
		}
	}
}
