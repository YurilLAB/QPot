// Package overview builds a local, at-a-glance picture of a QPot instance:
// host resources, per-honeypot activity over the last 24 hours and the latest
// events with a severity and a one-line summary.
//
// It replaces the former ypanel phone-home agent. Nothing leaves the host: the
// overview is served on the instance's own QPot-ID-authenticated API
// (GET /api/overview), shown on the dashboard's Overview tab, and printed by
// `qpot overview` (which can also summarise every instance on the host).
package overview

import (
	"context"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
)

const (
	maxRecentEvents = 25
	maxText         = 200
)

// Gauge is one resource meter: a 0-100 percentage plus a human caption such as
// "3.1 / 7.8 GB".
type Gauge struct {
	Pct     int    `json:"pct"`
	Caption string `json:"caption,omitempty"`
}

// Honeypot is one configured honeypot and its activity over the last 24 hours.
type Honeypot struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Port    int    `json:"port"`
	Hits24h int64  `json:"hits_24h"`
}

// Event is a recent event reduced to what an operator scans for.
type Event struct {
	Time      time.Time `json:"time"`
	Severity  string    `json:"severity"` // info | warn | critical
	Honeypot  string    `json:"honeypot"`
	SourceIP  string    `json:"source_ip"`
	Country   string    `json:"country,omitempty"`
	Port      int       `json:"port"`
	Summary   string    `json:"summary"`
	Technique string    `json:"technique,omitempty"`
	Tactic    string    `json:"tactic,omitempty"`
}

// Cluster identifies the group this node belongs to, when paired.
type Cluster struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Nodes   int    `json:"nodes"`
	Healthy int    `json:"healthy"`
}

// Overview is the whole picture for one instance.
type Overview struct {
	Instance     string     `json:"instance"`
	Hostname     string     `json:"hostname"`
	OS           string     `json:"os"`
	Arch         string     `json:"arch"`
	Version      string     `json:"version"`
	StartedAt    time.Time  `json:"started_at"`
	GeneratedAt  time.Time  `json:"generated_at"`
	CPU          Gauge      `json:"cpu"`
	Memory       Gauge      `json:"memory"`
	Disk         Gauge      `json:"disk"`
	Processes    Gauge      `json:"processes"`
	Database     string     `json:"database"`
	DatabaseOK   bool       `json:"database_ok"`
	Events24h    int64      `json:"events_24h"`
	UniqueIPs24h int64      `json:"unique_ips_24h"`
	EventsPerSec float64    `json:"events_per_sec"`
	Honeypots    []Honeypot `json:"honeypots"`
	RecentEvents []Event    `json:"recent_events"`
	Cluster      *Cluster   `json:"cluster,omitempty"`
}

// Build assembles the overview from the instance config, its database (may be
// nil) and the cluster summary (may be nil). Every source is best-effort: a
// degraded subsystem yields an honest partial overview rather than an error.
func Build(ctx context.Context, cfg *config.Config, db database.Database, cl *Cluster, version string) *Overview {
	h := collectHost()
	ov := &Overview{
		Instance:     cfg.InstanceName,
		Hostname:     h.Hostname,
		OS:           h.OSLabel,
		Arch:         h.Arch,
		Version:      firstNonEmpty(version, "dev"),
		StartedAt:    processStart.UTC(),
		GeneratedAt:  time.Now().UTC(),
		CPU:          Gauge{h.CPUPct, h.CPUCaption},
		Memory:       Gauge{h.MemPct, h.MemCaption},
		Disk:         Gauge{h.DiskPct, h.DiskCaption},
		Processes:    Gauge{h.ProcPct, h.ProcCaption},
		Database:     cfg.Database.Type,
		Honeypots:    []Honeypot{},
		RecentEvents: []Event{},
		Cluster:      cl,
	}

	hits := map[string]int64{}
	if db != nil {
		if st, err := db.GetStats(ctx, time.Now().Add(-24*time.Hour)); err == nil && st != nil {
			ov.DatabaseOK = true
			ov.Events24h = st.TotalEvents
			ov.UniqueIPs24h = st.UniqueIPs
			ov.EventsPerSec = float64(st.TotalEvents) / 86400
			for _, hc := range st.TopHoneypots {
				hits[strings.ToLower(strings.TrimSpace(hc.Honeypot))] = hc.Count
			}
		}
		if evs, err := db.GetEvents(ctx, database.EventFilter{Limit: maxRecentEvents}); err == nil {
			for _, e := range evs {
				ov.RecentEvents = append(ov.RecentEvents, toEvent(e))
			}
		}
	}

	for name, hp := range cfg.SnapshotHoneypots() {
		ov.Honeypots = append(ov.Honeypots, Honeypot{Name: name, Enabled: hp.Enabled, Port: hp.Port, Hits24h: hits[name]})
	}
	// Enabled first, then busiest, then by name.
	sort.Slice(ov.Honeypots, func(i, j int) bool {
		a, b := ov.Honeypots[i], ov.Honeypots[j]
		if a.Enabled != b.Enabled {
			return a.Enabled
		}
		if a.Hits24h != b.Hits24h {
			return a.Hits24h > b.Hits24h
		}
		return a.Name < b.Name
	})
	return ov
}

func toEvent(e *database.Event) Event {
	return Event{
		Time:      e.Timestamp.UTC(),
		Severity:  Severity(e),
		Honeypot:  clean(e.Honeypot, 64),
		SourceIP:  clean(e.SourceIP, 64),
		Country:   clean(e.Country, 64),
		Port:      e.DestPort,
		Summary:   clean(Summary(e), maxText),
		Technique: clean(strings.TrimSpace(e.TechniqueID+" "+e.TechniqueName), 128),
		Tactic:    clean(e.TacticName, 64),
	}
}

// Severity infers info / warn / critical for an event. Events carry no explicit
// severity: credential access, execution, lateral movement, impact and
// exfiltration techniques, and canary trips, are critical; any login, command
// or classified activity is a warning; everything else is informational.
func Severity(e *database.Event) string {
	switch e.TacticID {
	case "TA0006", "TA0008", "TA0002", "TA0040", "TA0010":
		return "critical"
	}
	if e.Honeypot == "canary" {
		return "critical"
	}
	if e.TechniqueID != "" || e.Username != "" || e.Password != "" || e.Command != "" {
		return "warn"
	}
	return "info"
}

// Summary is a one-line description of what the attacker did.
func Summary(e *database.Event) string {
	switch {
	case e.Command != "":
		return "ran: " + e.Command
	case e.Username != "":
		return "login " + e.Username + " / " + e.Password
	case len(e.Payload) > 0:
		return e.EventType + ": " + string(e.Payload)
	case e.EventType != "":
		return e.EventType
	case e.Protocol != "":
		return e.Protocol + " activity"
	}
	return "honeypot interaction"
}

// clean replaces control characters (attacker input can contain anything) and
// bounds the length to n runes without splitting a multi-byte character.
func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// host holds the system facts and resource gauges. The gauges are filled by
// collectResources: real /proc + statfs readings on Linux (metrics_linux.go),
// an honest "not measured" caption elsewhere (metrics_other.go).
type host struct {
	Hostname string
	OSLabel  string
	Arch     string

	CPUPct      int
	CPUCaption  string
	MemPct      int
	MemCaption  string
	DiskPct     int
	DiskCaption string
	ProcPct     int
	ProcCaption string
}

// processStart is when this control plane started.
var processStart = time.Now()

func collectHost() host {
	name, err := os.Hostname()
	if err != nil || name == "" {
		name = "unknown"
	}
	h := host{Hostname: name, OSLabel: runtime.GOOS, Arch: runtime.GOARCH}
	collectResources(&h)
	return h
}

// clampPct keeps a percentage inside [0,100].
func clampPct(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
