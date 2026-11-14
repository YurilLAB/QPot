package cluster

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func sensorNamed(v *FleetView, name string) *FleetSensor {
	for i := range v.Sensors {
		if v.Sensors[i].Name == name {
			return &v.Sensors[i]
		}
	}
	return nil
}

// TestFleetViewShowsEverySensor: one view has each sensor's state, says what
// is wrong with the ones that need a look, names what more than one sensor
// saw, and puts their alerts in one list.
func TestFleetViewShowsEverySensor(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	alert := func(title string, ago time.Duration) SensorAlert {
		return SensorAlert{Rule: "new-payload", Severity: "high", Title: title, Time: now.Add(-ago), Sources: []string{"203.0.113.9"}}
	}
	members := []FleetMember{
		{Name: "syd", Address: "10.0.0.1:7946", Local: true, Status: NodeStatusHealthy, Stats: NodeStats{Uptime: time.Hour, ActiveAttacks: 3},
			Intel: &ThreatIntel{Timestamp: now.Add(-20 * time.Second),
				TopSourceIPs: []IPCount{{IP: "203.0.113.9", Count: 40}, {IP: "198.51.100.2", Count: 5}},
				Sensor: &SensorReport{Version: "1.2.0", Honeypots: []string{"cowrie", "conpot"}, EventsHour: 50, EventsDay: 900,
					LastEvent: now.Add(-time.Minute), Payloads: []string{hashA, hashB}, Alerts: []SensorAlert{alert("first", time.Hour)}, CanaryTrips: 1}}},
		{Name: "bne", Address: "10.0.0.2:7946", Status: NodeStatusHealthy,
			Intel: &ThreatIntel{Timestamp: now.Add(-40 * time.Second),
				TopSourceIPs: []IPCount{{IP: "203.0.113.9", Count: 2}, {IP: "::ffff:203.0.113.9", Count: 1}},
				Sensor: &SensorReport{Version: "1.1.3", Honeypots: []string{"cowrie"}, EventsHour: 4, EventsDay: 30,
					Payloads: []string{hashA}, Alerts: []SensorAlert{alert("second", time.Minute)}}}},
		// An older QPot: gossip gives its counts, it sends no report.
		{Name: "old", Address: "10.0.0.3:7946", Status: NodeStatusHealthy, Stats: NodeStats{TotalEvents: 77}, Intel: &ThreatIntel{Timestamp: now}},
		{Name: "down", Address: "10.0.0.4:7946", Status: NodeStatusFailed,
			Intel: &ThreatIntel{Timestamp: now.Add(-3 * time.Hour), Sensor: &SensorReport{Version: "1.2.0", EventsDay: 5, Payloads: []string{hashB}}}},
		{Name: "quiet", Address: "10.0.0.5:7946", Status: NodeStatusHealthy,
			Intel: &ThreatIntel{Timestamp: now.Add(-9 * time.Minute), Sensor: &SensorReport{Version: "1.2.0", Honeypots: []string{"dionaea"}}}},
		{Name: "nodb", Address: "10.0.0.6:7946", Status: NodeStatusHealthy,
			Intel: &ThreatIntel{Timestamp: now, Sensor: &SensorReport{Version: "1.2.0", Honeypots: []string{"cowrie"}, DatabaseDown: true}}},
	}
	v := BuildFleet(now, members)

	if v.Sensors[0].Name != "syd" || !v.Sensors[0].Local {
		t.Fatalf("this sensor is not first: %+v", v.Sensors[0])
	}
	want := map[string][]string{
		"syd":   {},
		"bne":   {"runs 1.1.3, this sensor runs 1.2.0"},
		"old":   {"sends no report (an older QPot, or its control plane is not running)"},
		"down":  {"offline"},
		"quiet": {"last report 9m ago", "no events in 24h"},
		"nodb":  {"database not reachable"},
	}
	for name, attention := range want {
		s := sensorNamed(v, name)
		if s == nil {
			t.Fatalf("sensor %s is not in the view", name)
		}
		if !slices.Equal(s.Attention, attention) {
			t.Errorf("%s needs %q, want %q", name, s.Attention, attention)
		}
	}
	if s := sensorNamed(v, "old"); s.EventsDay != 77 || s.Reported != nil {
		t.Errorf("a sensor with no report shows what gossip gave: %+v", s)
	}
	// The failed sensor's report is three hours old: what it held is not
	// counted as seen.
	if s := sensorNamed(v, "down"); s.Reported != nil || s.Version != "" {
		t.Errorf("an old report is shown as current: %+v", s)
	}
	if s := sensorNamed(v, "syd"); s.EventsHour != 50 || s.EventsDay != 900 || s.Alerts != 1 || s.CanaryTrips != 1 || s.LastEvent == nil || len(s.Honeypots) != 2 || s.Honeypots[0] != "conpot" {
		t.Errorf("this sensor's row: %+v", s)
	}
	wantShared := []FleetShared{
		{Kind: "payload", Value: hashA, Sensors: []string{"syd", "bne"}},
		// The two forms of one address are one source, counted once a sensor.
		{Kind: "source", Value: "203.0.113.9", Sensors: []string{"syd", "bne"}, Events: 43},
	}
	if len(v.Shared) != len(wantShared) {
		t.Fatalf("shared: %+v", v.Shared)
	}
	for i, w := range wantShared {
		g := v.Shared[i]
		if g.Kind != w.Kind || g.Value != w.Value || g.Events != w.Events || !slices.Equal(g.Sensors, w.Sensors) {
			t.Errorf("shared[%d] = %+v, want %+v", i, g, w)
		}
	}
	if len(v.Alerts) != 2 || v.Alerts[0].Title != "second" || v.Alerts[0].Sensor != "bne" || v.Alerts[1].Sensor != "syd" {
		t.Errorf("alerts are not together, newest first: %+v", v.Alerts)
	}
	if v.Totals != (FleetTotals{Sensors: 6, Online: 5, NeedAttention: 5, EventsHour: 54, EventsDay: 1007, Alerts: 2}) {
		t.Errorf("totals: %+v", v.Totals)
	}
}

// TestFleetKeepsSensorsOfOneNameApart: two members with one name are two
// sensors, and what only they saw is still seen by two.
func TestFleetKeepsSensorsOfOneNameApart(t *testing.T) {
	now := time.Now()
	rep := func() *ThreatIntel {
		return &ThreatIntel{Timestamp: now, Sensor: &SensorReport{Honeypots: []string{"cowrie"}, EventsDay: 1, Payloads: []string{hashA}}}
	}
	v := BuildFleet(now, []FleetMember{
		{Name: "pot", Address: "10.0.0.1:1", Status: NodeStatusHealthy, Intel: rep()},
		{Name: "pot", Address: "10.0.0.2:1", Status: NodeStatusHealthy, Intel: rep()},
	})
	if v.Sensors[0].Name == v.Sensors[1].Name {
		t.Fatalf("two sensors carry one name: %q", v.Sensors[0].Name)
	}
	if len(v.Shared) != 1 || len(v.Shared[0].Sensors) != 2 {
		t.Fatalf("shared: %+v", v.Shared)
	}
}

// hostileReport is a report with more of everything than a report may hold,
// and text that must not reach a terminal or a page.
func hostileReport(now time.Time) *SensorReport {
	r := &SensorReport{
		Version:    "1.2.0\x1b[2J",
		EventsHour: -5, EventsDay: -9,
		LastEvent:   now.Add(48 * time.Hour),
		CanaryTrips: -3,
	}
	for i := 0; i < 3*maxReportHoneypots; i++ {
		r.Honeypots = append(r.Honeypots, "hp"+strconv.Itoa(i), strings.Repeat("x", 33), "Bad Name", "cowrie")
	}
	for i := 0; i < 3*maxReportPayloads; i++ {
		h := []byte(hashA)
		h[i%64] = "0123456789abcdef"[i%16]
		h[(i/16)%64] = "0123456789abcdef"[(i/7)%16]
		r.Payloads = append(r.Payloads, string(h), strings.ToUpper(hashA), "not a hash")
	}
	for i := 0; i < 3*maxReportAlerts; i++ {
		r.Alerts = append(r.Alerts, SensorAlert{
			Rule: "new-payload", Severity: "loud",
			Title:   "a\x1b]0;owned\x07 title" + string(rune(0x202e)) + "\n second line " + strings.Repeat("long ", 200) + "\xff",
			Time:    now.Add(-time.Duration(i) * time.Minute),
			Sources: []string{"203.0.113.1", "not-an-ip", "fe80::1%eth0", "1.2.3.4", "1.2.3.5", "1.2.3.6", "1.2.3.7", "1.2.3.8"},
		}, SensorAlert{Rule: "Bad Rule", Severity: "high", Title: "x", Time: now}, SensorAlert{Rule: "progression", Title: "\x00\x01", Time: now})
	}
	return r
}

func checkReport(t *testing.T, r *SensorReport) {
	t.Helper()
	if r == nil {
		return
	}
	if r.Version != "" && !reReportVersion.MatchString(r.Version) {
		t.Errorf("version %q", r.Version)
	}
	if len(r.Honeypots) > maxReportHoneypots || len(r.Payloads) > maxReportPayloads || len(r.Alerts) > maxReportAlerts {
		t.Errorf("over the limits: %d honeypots, %d payloads, %d alerts", len(r.Honeypots), len(r.Payloads), len(r.Alerts))
	}
	for _, h := range r.Honeypots {
		if !reReportHoneypot.MatchString(h) {
			t.Errorf("honeypot %q", h)
		}
	}
	for _, p := range r.Payloads {
		if !reReportSHA256.MatchString(p) {
			t.Errorf("payload %q", p)
		}
	}
	if r.EventsHour < 0 || r.EventsDay < r.EventsHour || r.CanaryTrips < 0 {
		t.Errorf("counts: %d %d %d", r.EventsHour, r.EventsDay, r.CanaryTrips)
	}
	for _, a := range r.Alerts {
		if !reReportRule.MatchString(a.Rule) || a.Title == "" || utf8.RuneCountInString(a.Title) > maxReportText || len(a.Sources) > maxReportSources {
			t.Errorf("alert %+v", a)
		}
		checkLine(t, a.Title)
		if severityText(a.Severity) != a.Severity {
			t.Errorf("severity %q", a.Severity)
		}
		for _, s := range a.Sources {
			if sourceText(s) != s {
				t.Errorf("source %q", s)
			}
		}
	}
}

// checkLine fails when s could do more than print on one line.
func checkLine(t *testing.T, s string) {
	t.Helper()
	if !utf8.ValidString(s) {
		t.Errorf("not UTF-8: %q", s)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) || r == utf8.RuneError {
			t.Errorf("%q carries %U", s, r)
			return
		}
	}
}

// TestSensorReportIsHeldToItsLimits: a member's report is another machine's
// word. What is kept of it has no more than the limits, and no text that
// could do anything but print.
func TestSensorReportIsHeldToItsLimits(t *testing.T) {
	now := time.Now()
	got := hostileReport(now).clean(now)
	checkReport(t, got)
	if got.Version != "" || !got.LastEvent.IsZero() || got.EventsHour != 0 || got.CanaryTrips != 0 {
		t.Errorf("kept what is no version, time or count: %+v", got)
	}
	if len(got.Honeypots) != maxReportHoneypots || len(got.Payloads) != maxReportPayloads || len(got.Alerts) != maxReportAlerts {
		t.Errorf("kept %d honeypots, %d payloads, %d alerts: the limits are %d, %d, %d",
			len(got.Honeypots), len(got.Payloads), len(got.Alerts), maxReportHoneypots, maxReportPayloads, maxReportAlerts)
	}
	if a := got.Alerts[0]; a.Severity != "unknown" || !slices.Equal(a.Sources, []string{"203.0.113.1", "1.2.3.4", "1.2.3.5", "1.2.3.6", "1.2.3.7"}) || !strings.HasPrefix(a.Title, "a ]0;owned title second line long") {
		t.Errorf("alert kept as %+v", a)
	}

	// The same holds for a report that reaches a member, and for the view.
	m := plainCluster(t)
	peer := addMember(m, testNodeID(t), "10.0.0.5", 7946)
	body, err := json.Marshal(ThreatIntel{NodeID: peer.ID, Sensor: hostileReport(now),
		TopSourceIPs: []IPCount{{IP: "\x1b[31mred", Count: 9}, {IP: "198.51.100.7", Count: 2}}})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	m.handleIntelHTTP(rec, fromPeer(httptest.NewRequest(http.MethodPost, "/api/v1/cluster/intel", bytes.NewReader(body)), peer.ID))
	if rec.Code != http.StatusOK {
		t.Fatalf("intel answered %d", rec.Code)
	}
	m.mu.RLock()
	checkReport(t, m.peerIntel[peer.ID].Sensor)
	m.mu.RUnlock()
	// What is no address is no shared attacker either.
	if a := m.SharedAttackers(10); len(a) != 1 || a[0].IP != "198.51.100.7" {
		t.Errorf("shared attackers: %+v", a)
	}
	m.SetSensorReport(&SensorReport{Honeypots: []string{"cowrie"}, EventsDay: 1})
	m.UpdateThreatIntel([]IPCount{{IP: "198.51.100.7", Count: 1}})
	v := BuildFleet(time.Now(), m.FleetMembers())
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte(`\u001b`)) || bytes.Contains(out, []byte("owned\\u0007")) {
		t.Errorf("the view carries an escape sequence: %s", out)
	}
	if len(v.Shared) != 1 || v.Shared[0].Value != "198.51.100.7" {
		t.Errorf("shared sources: %+v", v.Shared)
	}
}

// TestSensorReportTravelsWithSync: a node sends its report with its intel
// and keeps the peer's from the answer, dated by its own clock; a peer that
// sends none (an older QPot) is shown as such.
func TestSensorReportTravelsWithSync(t *testing.T) {
	m := NewManager(t.TempDir())
	if _, err := m.InitCluster("prod", idPassword, DefaultClusterConfig()); err != nil {
		t.Fatal(err)
	}
	peerID, oldID := testNodeID(t), testNodeID(t)
	var sent ThreatIntel
	peer := servePeerAs(t, m, peerID, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &sent)
		// The peer's clock is three hours behind.
		_ = json.NewEncoder(w).Encode(ThreatIntel{NodeID: peerID, Timestamp: time.Now().Add(-3 * time.Hour),
			TopSourceIPs: []IPCount{{IP: "1.2.3.4", Count: 100}},
			Sensor:       &SensorReport{Version: "1.2.0", Honeypots: []string{"conpot"}, EventsHour: 3, EventsDay: 8, Payloads: []string{hashA}}})
	}))
	old := servePeerAs(t, m, oldID, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"node_id":"`+oldID+`","timestamp":"2026-11-14T00:00:00Z","top_source_ips":[{"ip":"1.2.3.4","count":1}]}`)
	}))
	h, p := urlHostPort(t, peer.URL)
	addMember(m, peerID, h, p).Name = "peer"
	h, p = urlHostPort(t, old.URL)
	addMember(m, oldID, h, p).Name = "old"

	m.SetSensorReport(&SensorReport{Version: "1.2.0", Honeypots: []string{"cowrie"}, EventsHour: 1, EventsDay: 2, Payloads: []string{hashA}})
	m.UpdateThreatIntel([]IPCount{{IP: "1.2.3.4", Count: 7}})
	m.sync()

	if sent.Sensor == nil || sent.Sensor.Version != "1.2.0" || len(sent.Sensor.Payloads) != 1 || len(sent.TopSourceIPs) != 1 {
		t.Fatalf("the peer was sent %+v", sent)
	}
	v := BuildFleet(time.Now(), m.FleetMembers())
	got := sensorNamed(v, "peer")
	if got == nil || got.Reported == nil || got.Version != "1.2.0" || got.EventsDay != 8 || len(got.Attention) != 0 {
		t.Fatalf("the peer's report was not kept as current: %+v", got)
	}
	if got := sensorNamed(v, "old"); got == nil || got.Reported != nil || len(got.Attention) != 1 || !strings.HasPrefix(got.Attention[0], "sends no report") {
		t.Fatalf("a peer with no report: %+v", got)
	}
	var payload, source bool
	for _, s := range v.Shared {
		payload = payload || s.Kind == "payload" && s.Value == hashA && len(s.Sensors) == 2
		source = source || s.Kind == "source" && s.Value == "1.2.3.4" && len(s.Sensors) == 3 && s.Events == 108
	}
	if !payload || !source {
		t.Fatalf("what the sensors share: %+v", v.Shared)
	}
	// Intel from a clock that runs behind counts like any other.
	if a := m.SharedAttackers(5); len(a) != 1 || a[0].Nodes != 3 {
		t.Fatalf("shared attackers: %+v", a)
	}

	// A member revoked from the cluster is still listed until it is gone,
	// with nothing of what it shared.
	m.mu.Lock()
	m.cluster.Revocations = append(m.cluster.Revocations, Revocation{NodeID: peerID, RevokedAt: time.Now()})
	m.mu.Unlock()
	v = BuildFleet(time.Now(), m.FleetMembers())
	if got := sensorNamed(v, "peer"); got == nil || got.Reported != nil || got.Version != "" {
		t.Fatalf("a revoked member's report is shown: %+v", got)
	}
	for _, s := range v.Shared {
		if slices.Contains(s.Sensors, "peer") {
			t.Fatalf("what a revoked member shared is counted: %+v", s)
		}
	}

	// A member that leaves takes its report with it.
	m.mu.Lock()
	m.cluster.Nodes[peerID].Status = NodeStatusLeft
	m.mu.Unlock()
	if v := BuildFleet(time.Now(), m.FleetMembers()); sensorNamed(v, "peer") != nil || len(v.Sensors) != 2 {
		t.Fatalf("a node that left is still a sensor: %+v", v.Sensors)
	}
}

// TestUpdatingIntelKeepsTheReport: the sources and the report are set apart
// and neither drops the other.
func TestUpdatingIntelKeepsTheReport(t *testing.T) {
	m := plainCluster(t)
	m.SetSensorReport(&SensorReport{Version: "1.2.0"})
	m.UpdateThreatIntel([]IPCount{{IP: "1.2.3.4", Count: 1}})
	m.SetSensorReport(&SensorReport{Version: "1.2.1"})
	in := m.GetThreatIntel()
	if len(in) != 1 || in[0].Sensor == nil || in[0].Sensor.Version != "1.2.1" || len(in[0].TopSourceIPs) != 1 || in[0].NodeID == "" {
		t.Fatalf("local intel: %+v", in[0])
	}
}

func FuzzSensorReport(f *testing.F) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	seed, _ := json.Marshal(ThreatIntel{NodeID: "n", Timestamp: now, TopSourceIPs: []IPCount{{IP: "1.2.3.4", Count: 2}}, Sensor: hostileReport(now)})
	f.Add(seed, "name\x1b[0m")
	f.Add([]byte(`{"sensor":{"version":"1","honeypots":["a","a"],"alerts":[{"rule":"x","title":"t","time":"2026-11-14T11:00:00Z"}]}}`), "pot")
	f.Add([]byte(`{"sensor":null,"top_source_ips":[{"ip":"::ffff:1.2.3.4","count":-1}]}`), "")
	f.Fuzz(func(t *testing.T, data []byte, name string) {
		var in ThreatIntel
		if json.Unmarshal(data, &in) != nil {
			return
		}
		checkReport(t, in.Sensor.clean(now))
		in.Timestamp = now
		twin := in
		v := BuildFleet(now, []FleetMember{
			{Name: name, Address: name, Local: true, Status: NodeStatusHealthy, Intel: &in},
			{Name: name, Address: "10.0.0.2:1", Status: NodeStatus(name), Intel: &twin},
		})
		if len(v.Sensors) != 2 || len(v.Alerts) > maxFleetAlerts || len(v.Shared) > 2*maxFleetShared {
			t.Fatalf("view: %d sensors, %d alerts, %d shared", len(v.Sensors), len(v.Alerts), len(v.Shared))
		}
		for _, s := range v.Sensors {
			checkLine(t, s.Name)
			checkLine(t, s.Address)
			for _, a := range s.Attention {
				checkLine(t, a)
			}
			if s.EventsDay < 0 || s.EventsHour < 0 || s.UptimeSecs < 0 {
				t.Fatalf("negative count: %+v", s)
			}
		}
		for _, s := range v.Shared {
			if len(s.Sensors) < 2 || (s.Kind == "source" && sourceText(s.Value) != s.Value) || (s.Kind == "payload" && !reReportSHA256.MatchString(s.Value)) {
				t.Fatalf("shared: %+v", s)
			}
		}
		for _, a := range v.Alerts {
			checkLine(t, a.Title)
			checkLine(t, a.Sensor)
		}
		if _, err := json.Marshal(v); err != nil {
			t.Fatal(err)
		}
	})
}
