package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/qpot/qpot/internal/cluster"
)

// fleetInstance answers /api/fleet for instance "lab" from memory.
func fleetInstance(t *testing.T) *fleetAnswer {
	t.Helper()
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	hash := strings.Repeat("ab", 32)
	members := []cluster.FleetMember{
		{Name: "syd", Address: "10.0.0.1:7946", Local: true, Status: cluster.NodeStatusHealthy, Intel: &cluster.ThreatIntel{Timestamp: now,
			TopSourceIPs: []cluster.IPCount{{IP: "203.0.113.9", Count: 40}},
			Sensor: &cluster.SensorReport{Version: "1.2.0", Honeypots: []string{"cowrie", "conpot"}, EventsHour: 50, EventsDay: 900, LastEvent: now.Add(-4 * time.Minute),
				Payloads: []string{hash}, Alerts: []cluster.SensorAlert{{Rule: "progression", Severity: "high", Title: "A session went on \x1b[2J", Time: now.Add(-time.Hour), Sources: []string{"203.0.113.9"}}}}}},
		{Name: "bne\x1b[31m", Address: "10.0.0.2:7946", Status: cluster.NodeStatusHealthy, Intel: &cluster.ThreatIntel{Timestamp: now,
			TopSourceIPs: []cluster.IPCount{{IP: "203.0.113.9", Count: 3}},
			Sensor:       &cluster.SensorReport{Version: "1.1.3", Honeypots: []string{"cowrie"}, EventsHour: 4, EventsDay: 30, Payloads: []string{hash}}}},
		{Name: "per", Address: "10.0.0.3:7946", Status: cluster.NodeStatusFailed},
	}
	view := &fleetAnswer{Clustered: true, Live: true, Cluster: "lab", FleetView: *cluster.BuildFleet(now, members)}
	// The server cleans what sensors say. The command does not rely on it:
	// an answer that carries escape sequences all the same prints as text.
	esc := func(s string) string { return strings.ReplaceAll(s, " [", "\x1b[") }
	view.Sensors[1].Name, view.Sensors[1].Version = esc(view.Sensors[1].Name), "1.1.3\x1b[0m"
	view.Sensors[1].Attention[0] += "\x1b[0m"
	view.Alerts[0].Title, view.Alerts[0].Sensor = esc(view.Alerts[0].Title), "syd\x1b[0m"
	for i := range view.Shared {
		view.Shared[i].Sensors[1] = esc(view.Shared[i].Sensors[1])
	}
	realAPI, realNow := fleetAPI, fleetNow
	t.Cleanup(func() { fleetAPI, fleetNow = realAPI, realNow })
	fleetNow = func() time.Time { return now }
	fleetAPI = func(_ context.Context, name string) (*fleetAnswer, error) {
		if name != "lab" {
			return nil, errors.New("server not reachable (run 'qpot up' first)")
		}
		return view, nil
	}
	return view
}

func executeFleet(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := &cobra.Command{Use: "qpot", SilenceUsage: true, SilenceErrors: true}
	root.AddCommand(newFleetCommand())
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"fleet"}, args...))
	err := root.Execute()
	return out.String(), err
}

func TestFleetCommand(t *testing.T) {
	view := fleetInstance(t)
	out, err := executeFleet(t, "-i", "lab")
	if err != nil {
		t.Fatalf("fleet: %v\n%s", err, out)
	}
	for _, want := range []string{
		"Cluster lab: 3 sensors, 2 online, 2 need a look.",
		"54 events in the last hour, 930 in the last day, 1 behaviour alert in the last day.",
		"* syd                  online    1.2.0      2                50        900      1  4m ago",
		`  bne\x1b[31m          online    1.1.3\x1b[0m 1                 4         30      0  -`,
		`    needs a look: runs 1.1.3, this sensor runs 1.2.0\x1b[0m`,
		"  per                  failed    -          0                 0          0      0  -",
		"    needs a look: offline",
		"payload  " + strings.Repeat("ab", 32) + ` syd, bne\x1b[31m`,
		"source   203.0.113.9", `syd, bne\x1b[31m (43 events in the last hour)`,
		"2026-11-14 11:00:05"[:16], `syd\x1b[0m`, "progression", `A session went on\x1b[2J`, "from 203.0.113.9",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("fleet lacks %q:\n%s", want, out)
		}
	}
	if strings.ContainsRune(out, 0x1b) {
		t.Fatal("an escape sequence reached the terminal")
	}

	out, err = executeFleet(t, "-i", "lab", "--json")
	var got fleetAnswer
	if err != nil || json.Unmarshal([]byte(out), &got) != nil || !got.Clustered || len(got.Sensors) != 3 || len(got.Shared) != 2 || got.Totals.NeedAttention != 2 {
		t.Fatalf("--json: %v\n%s", err, out)
	}

	// --check is for a scheduled job: the view, then a failing status.
	out, err = executeFleet(t, "-i", "lab", "--check")
	if err == nil || err.Error() != "2 of 3 sensors need a look" || !strings.Contains(out, "Cluster lab") {
		t.Fatalf("--check: %v\n%s", err, out)
	}
	for i := range view.Sensors {
		view.Sensors[i].Attention = nil
	}
	view.Totals.NeedAttention = 0
	if out, err = executeFleet(t, "-i", "lab", "--check"); err != nil || !strings.Contains(out, "none needs a look") {
		t.Fatalf("--check with nothing wrong: %v\n%s", err, out)
	}

	view.Clustered, view.Live, view.Shared, view.Sensors = false, false, nil, view.Sensors[:1]
	if out, err = executeFleet(t, "-i", "lab"); err != nil || !strings.Contains(out, "fleet of one") || strings.Contains(out, "Seen by more") {
		t.Fatalf("standalone: %v\n%s", err, out)
	}
	if _, err = executeFleet(t, "-i", "other"); err == nil || !strings.Contains(err.Error(), "qpot up") {
		t.Fatalf("an instance that is not running: %v", err)
	}
	if _, err = executeFleet(t, "extra"); err == nil {
		t.Fatal("an argument was accepted")
	}
}
