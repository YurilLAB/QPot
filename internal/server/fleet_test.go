package server

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/access"
	"github.com/qpot/qpot/internal/behaviour"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/intelligence"
)

// fleetDB is alertDB with event counts.
type fleetDB struct {
	alertDB
	hour, day int64
	fail      bool
}

func (d *fleetDB) GetStats(_ context.Context, since time.Time) (*database.Stats, error) {
	if d.fail {
		return nil, context.DeadlineExceeded
	}
	if time.Since(since) > 2*time.Hour {
		return &database.Stats{TotalEvents: d.day}, nil
	}
	return &database.Stats{TotalEvents: d.hour}, nil
}

func getFleet(t *testing.T, a *apiTestServer) fleetAnswer {
	t.Helper()
	rec := a.do(http.MethodGet, "/api/fleet", "")
	var v fleetAnswer
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != http.StatusOK || v.FleetView == nil {
		t.Fatalf("GET /api/fleet = %d %v: %s", rec.Code, err, rec.Body.String())
	}
	return v
}

// newFleetServer is a sensor with two honeypots on, events, a payload hash
// of this week and one of last month, and one behaviour alert of today.
func newFleetServer(t *testing.T, name string) (*apiTestServer, *fleetDB) {
	t.Helper()
	a := newAPITestServer(t, name, func(c *config.Config) {
		c.Intelligence.Enabled = true
		for hp, hc := range c.Honeypots {
			hc.Enabled = hp == "cowrie" || hp == "conpot"
			c.Honeypots[hp] = hc
		}
	})
	now := time.Now().UTC()
	db := &fleetDB{hour: 12, day: 340}
	db.stored = []*database.Event{{Timestamp: now.Add(-3 * time.Minute), Honeypot: "cowrie", SourceIP: "198.51.100.1", EventType: "cowrie.session.connect"}}
	db.iocs = []*database.IOC{
		{Type: intelligence.IOCTypeHash, Value: strings.Repeat("AB", 32), LastSeen: now.Add(-time.Hour)},
		{Type: intelligence.IOCTypeHash, Value: strings.Repeat("cd", 32), LastSeen: now.Add(-30 * 24 * time.Hour)},
		{Type: intelligence.IOCTypeHash, Value: strings.Repeat("ef", 16), LastSeen: now},
	}
	a.s.database = db
	st := &behaviour.State{Version: 1, Started: now.Add(-48 * time.Hour), Alerts: []behaviour.Alert{
		{ID: "old", Rule: behaviour.RuleNewPayload, Severity: "high", Title: "two days ago", Time: now.Add(-47 * time.Hour)},
		{ID: "new", Rule: behaviour.RuleProgression, Severity: "high", Title: "went from discovery to persistence", Time: now.Add(-time.Hour), Sources: []string{"198.51.100.1"}},
	}}
	if err := behaviour.Save(a.cfg.DataPath, st); err != nil {
		t.Fatal(err)
	}
	return a, db
}

// A sensor in no cluster is a fleet of one: the view is its own report.
func TestFleetOfOneSensor(t *testing.T) {
	a, db := newFleetServer(t, "fleet-one")
	assertAuthRequired(t, a.h, http.MethodGet, "/api/fleet", "")
	if rec := a.do(http.MethodPost, "/api/fleet", `{}`); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d", rec.Code)
	}
	v := getFleet(t, a)
	if v.Clustered || v.Live || len(v.Sensors) != 1 {
		t.Fatalf("view: %+v", v)
	}
	s := v.Sensors[0]
	if s.Name != "fleet-one" || !s.Local || !s.Online || s.Version != Version || !slices.Equal(s.Honeypots, []string{"conpot", "cowrie"}) ||
		s.EventsHour != 12 || s.EventsDay != 340 || s.Alerts != 1 || s.LastEvent == nil || s.Reported == nil || len(s.Attention) != 0 {
		t.Fatalf("this sensor: %+v", s)
	}
	if len(v.Alerts) != 1 || v.Alerts[0].Rule != behaviour.RuleProgression || v.Alerts[0].Sensor != "fleet-one" || !slices.Equal(v.Alerts[0].Sources, []string{"198.51.100.1"}) {
		t.Fatalf("alerts: %+v", v.Alerts)
	}
	// Only this week's SHA-256 hashes are in the report.
	if r := a.s.sensorReport(context.Background(), time.Now()); !slices.Equal(r.Payloads, []string{strings.Repeat("ab", 32)}) {
		t.Fatalf("payloads: %q", r.Payloads)
	}

	// A database that stops answering shows as that, once the report is
	// built again.
	db.fail = true
	if v := getFleet(t, a); len(v.Sensors[0].Attention) != 0 {
		t.Fatalf("the report was built again within %s: %+v", fleetReportAge, v.Sensors[0])
	}
	a.s.fleet.built = time.Time{}
	if v := getFleet(t, a); !slices.Equal(v.Sensors[0].Attention, []string{"database not reachable"}) {
		t.Fatalf("attention: %q", v.Sensors[0].Attention)
	}

	// A viewer may read the fleet.
	key, err := access.Add(a.cfg.DataPath, "vera", access.Viewer, validTestID)
	if err != nil {
		t.Fatal(err)
	}
	a.reload()
	if rec := a.as(key, http.MethodGet, "/api/fleet", ""); rec.Code != http.StatusOK {
		t.Fatalf("viewer GET = %d", rec.Code)
	}
}

// In a cluster the view has every member. What this control plane knows of
// the others depends on whether it runs the cluster: from a cluster.json
// read at the start it knows only that they exist.
func TestFleetOfACluster(t *testing.T) {
	a, _ := newFleetServer(t, "fleet-cluster")
	sec := withTestCluster(t, a.s)
	v := getFleet(t, a)
	if !v.Clustered || v.Live || v.Cluster != "lab" || len(v.Sensors) != 2 {
		t.Fatalf("view: %+v", v)
	}
	if s := v.Sensors[0]; s.Name != "sensor-1" || !s.Local || s.EventsDay != 340 || len(s.Attention) != 0 {
		t.Fatalf("this sensor: %+v", s)
	}
	if s := v.Sensors[1]; s.Name != "sensor-2" || s.Online || !slices.Equal(s.Attention, []string{"state not known"}) {
		t.Fatalf("the other sensor: %+v", s)
	}
	rec := a.do(http.MethodGet, "/api/fleet", "")
	for what, secret := range map[string]string{"password hash": sec.passwordHash, "member key": sec.memberKey, "CA key": sec.caKey, "QPot ID": validTestID} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Errorf("the answer carries the cluster's %s", what)
		}
	}

	// Running the cluster, the node hands it its report with its stats.
	cm, _, _ := startedTestCluster(t)
	a.s.SetCluster(cm)
	a.s.fleet.built = time.Time{}
	a.s.updateNodeStats(context.Background())
	intel := cm.GetThreatIntel()
	if len(intel) != 1 || intel[0].Sensor == nil || intel[0].Sensor.EventsDay != 340 || len(intel[0].Sensor.Alerts) != 1 || len(intel[0].Sensor.Honeypots) != 2 {
		t.Fatalf("the cluster was given %+v", intel)
	}
	if v := getFleet(t, a); !v.Live || len(v.Sensors) != 1 || !v.Sensors[0].Local || v.Sensors[0].EventsHour != 12 {
		t.Fatalf("live view: %+v", v)
	}
}
