package server

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/qpot/qpot/internal/cluster"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/intelligence"
)

const (
	// fleetReportAge is how long a sensor report is reused: the cluster
	// takes one every nodeStatsInterval, and the fleet page asks as often.
	fleetReportAge = 20 * time.Second
	// fleetPayloadAge is how far back the report's payload hashes go, and
	// fleetPayloads how many it reads.
	fleetPayloadAge = 7 * 24 * time.Hour
	fleetPayloads   = 200
	// fleetAlerts is how many of the last day's behaviour alerts it carries.
	fleetAlerts = 20
)

// fleetState caches this sensor's report.
type fleetState struct {
	mu     sync.Mutex
	built  time.Time
	report *cluster.SensorReport
}

// sensorReport is this sensor's report on itself, as its cluster shares it
// and the fleet view shows it: built from the settings, the database, the
// behaviour alerts and the canaries, at most every fleetReportAge.
func (s *Server) sensorReport(ctx context.Context, now time.Time) *cluster.SensorReport {
	f := &s.fleet
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.report != nil && now.Sub(f.built) < fleetReportAge && !now.Before(f.built) {
		return f.report
	}
	cfg, err := s.readConfig()
	if err != nil {
		cfg = s.config
	}
	r := &cluster.SensorReport{Version: Version}
	for name, hp := range cfg.SnapshotHoneypots() {
		if hp.Enabled {
			r.Honeypots = append(r.Honeypots, name)
		}
	}
	sort.Strings(r.Honeypots)
	s.reportEvents(ctx, now, r)
	s.reportAlerts(cfg, now, r)
	if s.canaries != nil {
		for _, trip := range s.canaries.Trips(0) {
			if trip != nil && now.Sub(trip.Time) <= 24*time.Hour {
				r.CanaryTrips++
			}
		}
	}
	f.report, f.built = r, now
	return r
}

// reportEvents fills what the database knows: the counts, the newest event
// and the payload hashes. A database that cannot be read is reported as
// down, with whatever was read before it failed.
func (s *Server) reportEvents(ctx context.Context, now time.Time, r *cluster.SensorReport) {
	db := s.db()
	if db == nil {
		r.DatabaseDown = true
		return
	}
	qctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	hour, err := db.GetStats(qctx, now.Add(-time.Hour))
	if err != nil || hour == nil {
		slog.Debug("Sensor report: events not counted", "error", err)
		r.DatabaseDown = true
		return
	}
	r.EventsHour = hour.TotalEvents
	day, err := db.GetStats(qctx, now.Add(-24*time.Hour))
	if err != nil || day == nil {
		r.DatabaseDown = true
		return
	}
	r.EventsDay = day.TotalEvents
	// Newest first: one event of the last month is the newest there is.
	if last, err := db.GetEvents(qctx, database.EventFilter{StartTime: now.Add(-30 * 24 * time.Hour), EndTime: now, Limit: 1}); err == nil && len(last) > 0 && last[0] != nil {
		r.LastEvent = last[0].Timestamp
	}
	// The most recently seen come first. No start time: that filters on
	// when a hash was first seen, and one seen again this week counts.
	iocs, err := db.GetIOCs(qctx, database.IOCFilter{Types: []string{intelligence.IOCTypeHash}, Limit: fleetPayloads})
	if err != nil {
		slog.Debug("Sensor report: payload hashes not read", "error", err)
		return
	}
	seen := func(ioc *database.IOC) time.Time {
		if ioc.FirstSeen.After(ioc.LastSeen) {
			return ioc.FirstSeen
		}
		return ioc.LastSeen
	}
	recent := make([]*database.IOC, 0, len(iocs))
	for _, ioc := range iocs {
		// Only SHA-256 names a file the same way on every sensor.
		if ioc != nil && len(ioc.Value) == 64 && !now.Add(-fleetPayloadAge).After(seen(ioc)) {
			recent = append(recent, ioc)
		}
	}
	sort.SliceStable(recent, func(i, j int) bool { return seen(recent[i]).After(seen(recent[j])) })
	for _, ioc := range recent {
		r.Payloads = append(r.Payloads, strings.ToLower(ioc.Value))
	}
}

// reportAlerts adds the behaviour alerts of the last day, the newest first.
func (s *Server) reportAlerts(cfg *config.Config, now time.Time, r *cluster.SensorReport) {
	if cfg.DataPath == "" {
		return
	}
	b := &s.behaviour
	b.mu.Lock()
	defer b.mu.Unlock()
	state, err := b.load(cfg.DataPath)
	if err != nil {
		return
	}
	for i := len(state.Alerts) - 1; i >= 0 && len(r.Alerts) < fleetAlerts; i-- {
		a := state.Alerts[i]
		if now.Sub(a.Time) > 24*time.Hour {
			continue
		}
		r.Alerts = append(r.Alerts, cluster.SensorAlert{Rule: a.Rule, Severity: a.Severity, Title: a.Title, Time: a.Time, Sources: a.Sources})
	}
}

// fleetAnswer is what GET /api/fleet gives.
type fleetAnswer struct {
	// Clustered is false for a sensor in no cluster: the view is then this
	// sensor alone. Live is true when this control plane runs the cluster,
	// so what the other sensors shared is current.
	Clustered bool   `json:"clustered"`
	Live      bool   `json:"live"`
	Cluster   string `json:"cluster,omitempty"`
	*cluster.FleetView
}

// fleetView builds the fleet view: this sensor's own report with what the
// cluster's members last shared.
func (s *Server) fleetView(ctx context.Context, now time.Time) fleetAnswer {
	report := s.sensorReport(ctx, now)
	own := &cluster.ThreatIntel{Timestamp: now, Sensor: report}
	cm, live := s.clusterView()
	var members []cluster.FleetMember
	out := fleetAnswer{Live: live}
	if cm != nil {
		members = cm.FleetMembers()
		if st := cm.GetStatus(); st != nil {
			out.Clustered, out.Cluster = true, st.Name
		}
	}
	local := false
	for i := range members {
		m := &members[i]
		switch {
		case m.Local:
			local = true
			// The report just built is the newest; the sources are the
			// cluster's to give.
			if m.Intel != nil {
				own.TopSourceIPs = m.Intel.TopSourceIPs
			}
			m.Intel = own
			m.Status = cluster.NodeStatusHealthy
		case !live:
			// Not this control plane's cluster to run: what cluster.json
			// held of the others when the server started says nothing now.
			m.Status, m.Intel = cluster.NodeStatusUnknown, nil
		}
	}
	if !local {
		stats := cluster.NodeStats{TotalEvents: report.EventsDay}
		if !s.startedAt.IsZero() {
			stats.Uptime = now.Sub(s.startedAt)
		}
		members = append(members, cluster.FleetMember{Name: s.config.InstanceName, Local: true, Status: cluster.NodeStatusHealthy, Stats: stats, Intel: own})
	}
	out.FleetView = cluster.BuildFleet(now, members)
	return out
}

// handleFleet answers GET /api/fleet: every sensor of this sensor's cluster
// in one view.
func (s *Server) handleFleet(w http.ResponseWriter, r *http.Request) {
	if !s.allowMethods(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, s.fleetView(r.Context(), time.Now()))
}
