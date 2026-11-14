package cluster

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// The limits of one sensor's report. A report comes from another machine:
// whatever it says is cut to these before it is kept.
const (
	maxReportHoneypots = 64
	maxReportPayloads  = 200
	maxReportAlerts    = 20
	maxReportSources   = 5
	maxReportText      = 200
	// reportStaleAfter is how old a report may be before the fleet view says
	// so: the control plane renews it every 30 s.
	reportStaleAfter = 5 * time.Minute
	// maxFleetShared and maxFleetAlerts bound the lists of the fleet view.
	maxFleetShared = 50
	maxFleetAlerts = 50
)

var (
	reReportVersion  = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}$`)
	reReportHoneypot = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	reReportRule     = regexp.MustCompile(`^[a-z][a-z-]{0,31}$`)
	reReportSHA256   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// SensorReport is what a sensor tells the other members about itself: enough
// for one of them to show every sensor's state and what several of them saw.
// It travels with the sensor's ThreatIntel. Events stay on the sensor that
// recorded them.
type SensorReport struct {
	// Version is the QPot version the sensor runs.
	Version string `json:"version,omitempty"`
	// Honeypots are the honeypots turned on, by name.
	Honeypots []string `json:"honeypots,omitempty"`
	// DatabaseDown is true when the sensor could not read its database.
	DatabaseDown bool `json:"database_down,omitempty"`
	// EventsHour and EventsDay count the events of the last hour and day.
	EventsHour int64 `json:"events_hour"`
	EventsDay  int64 `json:"events_day"`
	// LastEvent is the time of the newest event stored.
	LastEvent time.Time `json:"last_event,omitzero"`
	// Payloads are the SHA-256 hashes of the files captured in the last
	// week, the most recent first.
	Payloads []string `json:"payloads,omitempty"`
	// Alerts are the behaviour alerts of the last day, the newest first.
	Alerts []SensorAlert `json:"alerts,omitempty"`
	// CanaryTrips counts the canaries tripped in the last day.
	CanaryTrips int `json:"canary_trips,omitempty"`
}

// SensorAlert is one behaviour alert in a sensor's report.
type SensorAlert struct {
	Rule     string    `json:"rule"`
	Severity string    `json:"severity"`
	Title    string    `json:"title"`
	Time     time.Time `json:"time"`
	Sources  []string  `json:"source_ips,omitempty"`
}

// reportText makes text from another sensor safe to show on one line: no
// control or format characters, valid UTF-8, at most maxReportText runes.
func reportText(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == maxReportText {
			break
		}
		switch {
		case r == utf8.RuneError, unicode.IsControl(r), unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Co, unicode.Cs):
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// sourceText returns ip as an address in its usual form, "" when it is none.
func sourceText(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil || a.Zone() != "" {
		return ""
	}
	return a.Unmap().String()
}

func severityText(s string) string {
	switch s {
	case "critical", "high", "medium", "low", "info":
		return s
	}
	return "unknown"
}

// clean returns the report held to the limits above, with everything that
// is not what its field holds dropped. It never keeps a reference to r.
func (r *SensorReport) clean(now time.Time) *SensorReport {
	if r == nil {
		return nil
	}
	out := &SensorReport{DatabaseDown: r.DatabaseDown}
	if reReportVersion.MatchString(r.Version) {
		out.Version = r.Version
	}
	seen := map[string]bool{}
	for _, h := range r.Honeypots {
		if len(out.Honeypots) == maxReportHoneypots {
			break
		}
		if reReportHoneypot.MatchString(h) && !seen[h] {
			seen[h] = true
			out.Honeypots = append(out.Honeypots, h)
		}
	}
	sort.Strings(out.Honeypots)
	out.EventsHour, out.EventsDay = max(0, r.EventsHour), max(0, r.EventsDay)
	if out.EventsDay < out.EventsHour {
		out.EventsDay = out.EventsHour
	}
	// A clock a few minutes ahead is still a time; anything later is not.
	if !r.LastEvent.IsZero() && r.LastEvent.Year() >= 2000 && !r.LastEvent.After(now.Add(10*time.Minute)) {
		out.LastEvent = r.LastEvent.UTC()
	}
	seen = map[string]bool{}
	for _, p := range r.Payloads {
		if len(out.Payloads) == maxReportPayloads {
			break
		}
		if reReportSHA256.MatchString(p) && !seen[p] {
			seen[p] = true
			out.Payloads = append(out.Payloads, p)
		}
	}
	for _, a := range r.Alerts {
		if len(out.Alerts) == maxReportAlerts {
			break
		}
		title := reportText(a.Title)
		if !reReportRule.MatchString(a.Rule) || title == "" || a.Time.IsZero() || a.Time.After(now.Add(10*time.Minute)) {
			continue
		}
		c := SensorAlert{Rule: a.Rule, Severity: severityText(a.Severity), Title: title, Time: a.Time.UTC()}
		for _, ip := range a.Sources {
			if len(c.Sources) == maxReportSources {
				break
			}
			if s := sourceText(ip); s != "" {
				c.Sources = append(c.Sources, s)
			}
		}
		out.Alerts = append(out.Alerts, c)
	}
	sort.SliceStable(out.Alerts, func(i, j int) bool { return out.Alerts[i].Time.After(out.Alerts[j].Time) })
	out.CanaryTrips = min(max(0, r.CanaryTrips), 1_000_000)
	return out
}

// SetSensorReport sets the report this node shares with its cluster. The
// next sync sends it with the node's intel.
func (m *Manager) SetSensorReport(r *SensorReport) {
	now := time.Now()
	r = r.clean(now)
	m.mu.Lock()
	defer m.mu.Unlock()
	next := &ThreatIntel{Timestamp: now, Sensor: r}
	if m.cluster != nil && m.cluster.LocalNode != nil {
		next.NodeID = m.cluster.LocalNode.ID
	}
	// sync reads localIntel outside the lock: replace it, never change it.
	if m.localIntel != nil {
		next.TopSourceIPs = m.localIntel.TopSourceIPs
	}
	m.localIntel = next
}

// FleetMember is one sensor as the fleet view is built from it.
type FleetMember struct {
	Name    string
	Address string
	Local   bool
	Status  NodeStatus
	Stats   NodeStats
	// Intel is what the sensor last shared, nil when nothing was kept.
	Intel *ThreatIntel
}

// FleetSensor is one sensor's row of the fleet view.
type FleetSensor struct {
	Name          string   `json:"name"`
	Address       string   `json:"address,omitempty"`
	Local         bool     `json:"is_local"`
	Status        string   `json:"status"`
	Online        bool     `json:"online"`
	UptimeSecs    int64    `json:"uptime_seconds"`
	Version       string   `json:"version,omitempty"`
	Honeypots     []string `json:"honeypots"`
	EventsHour    int64    `json:"events_hour"`
	EventsDay     int64    `json:"events_day"`
	ActiveSources int64    `json:"active_sources"`
	Alerts        int      `json:"alerts"`
	CanaryTrips   int      `json:"canary_trips"`
	// Reported is when the sensor's report was made; absent when it sent
	// none. LastEvent is the time of its newest event.
	Reported  *time.Time `json:"reported,omitempty"`
	LastEvent *time.Time `json:"last_event,omitempty"`
	// Attention lists what is wrong with the sensor, in words; empty when
	// nothing is.
	Attention []string `json:"attention"`
}

// FleetShared is something more than one sensor saw.
type FleetShared struct {
	// Kind is "payload" (Value a SHA-256) or "source" (Value an address).
	Kind    string   `json:"kind"`
	Value   string   `json:"value"`
	Sensors []string `json:"sensors"`
	// Events counts a source's events of the last hour over those sensors.
	Events int64 `json:"events,omitempty"`
}

// FleetAlert is a behaviour alert and the sensor that raised it.
type FleetAlert struct {
	Sensor string `json:"sensor"`
	SensorAlert
}

// FleetTotals sums the fleet view.
type FleetTotals struct {
	Sensors       int   `json:"sensors"`
	Online        int   `json:"online"`
	NeedAttention int   `json:"need_attention"`
	EventsHour    int64 `json:"events_hour"`
	EventsDay     int64 `json:"events_day"`
	Alerts        int   `json:"alerts"`
}

// FleetView is every sensor of a cluster in one place: each one's state,
// what more than one of them saw, and their alerts together.
type FleetView struct {
	Sensors []FleetSensor `json:"sensors"`
	Shared  []FleetShared `json:"shared"`
	Alerts  []FleetAlert  `json:"alerts"`
	Totals  FleetTotals   `json:"totals"`
}

func ago(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// BuildFleet makes the fleet view of members at now. Reports are cleaned
// again here, so a view never shows more than the limits allow whatever the
// members hold.
func BuildFleet(now time.Time, members []FleetMember) *FleetView {
	v := &FleetView{Sensors: make([]FleetSensor, 0, len(members)), Shared: []FleetShared{}, Alerts: []FleetAlert{}}
	members = append([]FleetMember(nil), members...)
	sort.SliceStable(members, func(i, j int) bool {
		if members[i].Local != members[j].Local {
			return members[i].Local
		}
		return members[i].Name < members[j].Name
	})
	localVersion := ""
	for _, m := range members {
		if m.Local && m.Intel != nil && m.Intel.Sensor != nil && reReportVersion.MatchString(m.Intel.Sensor.Version) {
			localVersion = m.Intel.Sensor.Version
		}
	}
	type sighting struct {
		sensors []string
		events  int64
	}
	payloads, sources := map[string]*sighting{}, map[string]*sighting{}
	note := func(at map[string]*sighting, key, sensor string, events int64) {
		s := at[key]
		if s == nil {
			s = &sighting{}
			at[key] = s
		}
		if n := len(s.sensors); n == 0 || s.sensors[n-1] != sensor {
			s.sensors = append(s.sensors, sensor)
		}
		s.events += events
	}
	names := map[string]int{}
	for _, m := range members {
		name := reportText(m.Name)
		if name == "" {
			name = "(unnamed)"
		}
		// Two members may carry one name: what they saw must not be read as
		// one sensor's.
		names[name]++
		if n := names[name]; n > 1 {
			name = fmt.Sprintf("%s (%d)", name, n)
		}
		row := FleetSensor{
			Name: name, Address: reportText(m.Address), Local: m.Local, Status: string(m.Status),
			Online: m.Status == NodeStatusHealthy, UptimeSecs: max(0, int64(m.Stats.Uptime.Seconds())),
			EventsDay: max(0, m.Stats.TotalEvents), ActiveSources: max(0, m.Stats.ActiveAttacks),
			Honeypots: []string{}, Attention: []string{},
		}
		switch m.Status {
		case NodeStatusHealthy:
		case NodeStatusSuspect:
			row.Attention = append(row.Attention, "not answering")
		case NodeStatusMaintenance:
			row.Attention = append(row.Attention, "in maintenance")
		case NodeStatusUnknown:
			row.Attention = append(row.Attention, "state not known")
		default:
			row.Attention = append(row.Attention, "offline")
		}
		var rep *SensorReport
		fresh := m.Intel != nil && now.Sub(m.Intel.Timestamp) <= intelMaxAge
		if fresh {
			rep = m.Intel.Sensor.clean(now)
		}
		switch {
		case rep == nil && row.Online:
			row.Attention = append(row.Attention, "sends no report (an older QPot, or its control plane is not running)")
		case rep != nil:
			at := m.Intel.Timestamp.UTC()
			row.Reported = &at
			row.Version, row.Honeypots = rep.Version, append(row.Honeypots, rep.Honeypots...)
			row.EventsHour, row.EventsDay = rep.EventsHour, rep.EventsDay
			row.Alerts, row.CanaryTrips = len(rep.Alerts), rep.CanaryTrips
			if !rep.LastEvent.IsZero() {
				last := rep.LastEvent
				row.LastEvent = &last
			}
			if age := now.Sub(at); row.Online && age > reportStaleAfter {
				row.Attention = append(row.Attention, "last report "+ago(age)+" ago")
			}
			switch {
			case rep.DatabaseDown:
				row.Attention = append(row.Attention, "database not reachable")
			case len(rep.Honeypots) == 0:
				row.Attention = append(row.Attention, "no honeypots turned on")
			case rep.EventsDay == 0:
				row.Attention = append(row.Attention, "no events in 24h")
			}
			if localVersion != "" && rep.Version != "" && rep.Version != localVersion && !m.Local {
				row.Attention = append(row.Attention, "runs "+rep.Version+", this sensor runs "+localVersion)
			}
			for _, p := range rep.Payloads {
				note(payloads, p, name, 0)
			}
			for _, a := range rep.Alerts {
				v.Alerts = append(v.Alerts, FleetAlert{Sensor: name, SensorAlert: a})
			}
		}
		if fresh {
			counted := 0
			for _, ip := range m.Intel.TopSourceIPs {
				if counted == maxIntelSources {
					break
				}
				counted++
				if s := sourceText(ip.IP); s != "" && ip.Count > 0 {
					note(sources, s, name, ip.Count)
				}
			}
		}
		v.Totals.Sensors++
		if row.Online {
			v.Totals.Online++
		}
		if len(row.Attention) > 0 {
			v.Totals.NeedAttention++
		}
		v.Totals.EventsHour += row.EventsHour
		v.Totals.EventsDay += row.EventsDay
		v.Totals.Alerts += row.Alerts
		v.Sensors = append(v.Sensors, row)
	}
	shared := func(kind string, at map[string]*sighting) {
		var out []FleetShared
		for value, s := range at {
			if len(s.sensors) > 1 {
				out = append(out, FleetShared{Kind: kind, Value: value, Sensors: s.sensors, Events: s.events})
			}
		}
		sort.Slice(out, func(i, j int) bool {
			if len(out[i].Sensors) != len(out[j].Sensors) {
				return len(out[i].Sensors) > len(out[j].Sensors)
			}
			if out[i].Events != out[j].Events {
				return out[i].Events > out[j].Events
			}
			return out[i].Value < out[j].Value
		})
		if len(out) > maxFleetShared {
			out = out[:maxFleetShared]
		}
		v.Shared = append(v.Shared, out...)
	}
	shared("payload", payloads)
	shared("source", sources)
	sort.SliceStable(v.Alerts, func(i, j int) bool { return v.Alerts[i].Time.After(v.Alerts[j].Time) })
	if len(v.Alerts) > maxFleetAlerts {
		v.Alerts = v.Alerts[:maxFleetAlerts]
	}
	return v
}

// FleetMembers returns the cluster's sensors with what each last shared:
// this node first. Intel from a node that left, or was revoked, is not
// given.
func (m *Manager) FleetMembers() []FleetMember {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cluster == nil {
		return nil
	}
	localID := ""
	if m.cluster.LocalNode != nil {
		localID = m.cluster.LocalNode.ID
	}
	out := make([]FleetMember, 0, len(m.cluster.Nodes))
	for id, n := range m.cluster.Nodes {
		if n.Status == NodeStatusLeft {
			continue
		}
		fm := FleetMember{Name: n.Name, Address: fmt.Sprintf("%s:%d", n.Address, n.Port), Local: id == localID, Status: n.Status, Stats: n.Stats}
		switch {
		case fm.Local:
			fm.Intel = m.localIntel
		case !m.revokedLocked(id):
			fm.Intel = m.peerIntel[id]
		}
		out = append(out, fm)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Address < out[j].Address
	})
	return out
}
