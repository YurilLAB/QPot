package ypanel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// knownHoneypotTypes is the worker's closed HoneypotType enum. The push endpoint
// VALIDATES honeypots[].type and recentEvents[].honeypot against this set and
// rejects the WHOLE snapshot on any unknown value — so we filter to it at the
// source. It is kept in lockstep with the worker's ypanel-types.ts enum and with
// QPot's own honeypot registry (the two already align, 26 types).
var knownHoneypotTypes = map[string]bool{
	"cowrie": true, "wordpot": true, "elasticpot": true, "conpot": true,
	"dionaea": true, "redishoneypot": true, "mailoney": true, "log4pot": true,
	"ciscoasa": true, "citrixhoneypot": true, "beelzebub": true, "ddospot": true,
	"dicompot": true, "endlessh": true, "galah": true, "h0neytr4p": true,
	"hellpot": true, "heralding": true, "honeyaml": true, "ipphoney": true,
	"medpot": true, "miniprint": true, "sentrypeer": true, "tanner": true,
	"adbhoney": true, "go-pot": true,
}

const (
	maxRecentEvents = 50  // worker caps at 100; we send the freshest 50
	maxHoneypots    = 32  // worker hard limit
	maxIntent       = 200 // worker field bound
	maxRawLine      = 512 // worker field bound
)

type gauge struct {
	Pct     int    `json:"pct"`
	Caption string `json:"caption,omitempty"`
}

type snapHoneypot struct {
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
	Port    int    `json:"port"`
	Hits24h int    `json:"hits24h"`
}

type snapEvent struct {
	ID       string `json:"id"`
	TS       string `json:"ts"`
	Severity string `json:"severity"`
	Honeypot string `json:"honeypot"`
	SrcIP    string `json:"srcIp"`
	Country  string `json:"country"`
	Port     int    `json:"port"`
	Intent   string `json:"intent"`
	Tactic   string `json:"tactic"`
	RawLine  string `json:"rawLine"`
}

// buildSnapshot assembles the exact push body the worker validates, in-process,
// from QPot's live manager + config + database. camelCase keys are load-bearing.
// It never returns an error: every data source is best-effort so a degraded
// subsystem (e.g. no DB) yields an honest partial snapshot rather than no push.
func (a *Agent) buildSnapshot(ctx context.Context) map[string]any {
	h := collectHost()

	// hits per honeypot over the last 24h, used to populate honeypots[].hits24h
	// and to derive eventsPerSec. Best-effort: empty when the DB is unavailable.
	hitsByType, totalEvents := a.hitCounts(ctx)

	honeypots := a.honeypots(hitsByType)
	events := a.recentEvents(ctx)

	var clusterID, clusterName any
	if id, name := a.clusterIdentity(); name != "" {
		clusterID, clusterName = id, name
	}

	region := strings.TrimSpace(a.cfg.Ypanel.Region)
	if region == "" {
		region = "self-reported"
	}

	return map[string]any{
		"v":            1,
		"instance_id":  a.cfg.Ypanel.InstanceID,
		"host":         clampStr(h.Hostname, 128),
		"status":       "online",
		"version":      clampStr(firstNonEmpty(a.version, "dev"), 32),
		"bootedAt":     h.BootedAt,
		"clusterId":    clusterID,
		"clusterName":  clusterName,
		"os":           clampStr(h.OSLabel, 32),
		"arch":         clampStr(h.Arch, 32),
		"region":       clampStr(region, 48),
		"cpu":          gauge{Pct: h.CPUPct, Caption: clampStr(h.CPUCaption, 48)},
		"mem":          gauge{Pct: h.MemPct, Caption: clampStr(h.MemCaption, 48)},
		"disk":         gauge{Pct: h.DiskPct, Caption: clampStr(h.DiskCaption, 48)},
		"procs":        gauge{Pct: h.ProcPct, Caption: clampStr(h.ProcCaption, 48)},
		"eventsPerSec": eventsPerSec(totalEvents),
		"honeypots":    honeypots,
		"recentEvents": events,
	}
}

// honeypots maps QPot's configured honeypots to the snapshot shape, filtered to
// the worker's known-type enum and to the worker's 32-entry ceiling. The
// snapshot's single per-honeypot "enabled" bool is the OPERATOR-controlled
// configured state — exactly what the panel's enable/disable toggle binds to and
// what the worker counts into honeypotsRunning — so it must mirror config, not a
// momentary container health read. (Gating on a live manager.Status would shell
// out to `docker ps` every push and make the toggle flap during a restart.)
func (a *Agent) honeypots(hits map[string]int) []snapHoneypot {
	out := make([]snapHoneypot, 0, len(a.cfg.Honeypots))
	for name, hp := range a.cfg.SnapshotHoneypots() {
		if !knownHoneypotTypes[name] {
			continue // unknown type would reject the whole snapshot
		}
		out = append(out, snapHoneypot{
			Type:    name,
			Enabled: hp.Enabled,
			Port:    clampPort(hp.Port),
			Hits24h: hits[name],
		})
	}
	// Stable ordering keeps the panel's honeypot list from reshuffling each push.
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	if len(out) > maxHoneypots {
		out = out[:maxHoneypots]
	}
	return out
}

// recentEvents pulls the freshest events from the DB and maps them to the
// worker schema, filtering to known honeypot types and synthesising a stable,
// unique id per event (the worker keys its live feed by id).
func (a *Agent) recentEvents(ctx context.Context) []snapEvent {
	if a.database == nil {
		return []snapEvent{}
	}
	evs, err := a.database.GetEvents(ctx, database.EventFilter{Limit: 200})
	if err != nil {
		a.log("recent events query failed: %v", err)
		return []snapEvent{}
	}

	out := make([]snapEvent, 0, maxRecentEvents)
	seen := map[string]bool{}
	for _, e := range evs {
		if len(out) >= maxRecentEvents {
			break
		}
		hp := strings.ToLower(strings.TrimSpace(e.Honeypot))
		if !knownHoneypotTypes[hp] {
			continue // recentEvents[].honeypot is the same closed enum
		}
		src := strings.TrimSpace(e.SourceIP)
		if src == "" {
			continue // worker requires a non-empty srcIp (minLen 1)
		}

		id := eventID(e)
		for seen[id] { // guarantee uniqueness within this snapshot
			id += "x"
		}
		seen[id] = true

		out = append(out, snapEvent{
			ID:       clampStr(id, 64),
			TS:       e.Timestamp.UTC().Format(time.RFC3339),
			Severity: severity(e),
			Honeypot: hp,
			SrcIP:    clampStr(sanitize(src), 45),
			Country:  country(e.Country),
			Port:     clampPort(e.DestPort),
			Intent:   clampStr(sanitize(intent(e)), maxIntent),
			Tactic:   clampStr(sanitize(tactic(e)), 64),
			RawLine:  clampStr(sanitize(rawLine(e)), maxRawLine),
		})
	}
	return out
}

// hitCounts returns per-honeypot 24h hit totals and the grand total, derived
// from the database stats. Best-effort: zeroes when the DB is unavailable.
func (a *Agent) hitCounts(ctx context.Context) (map[string]int, int64) {
	hits := map[string]int{}
	if a.database == nil {
		return hits, 0
	}
	stats, err := a.database.GetStats(ctx, time.Now().Add(-24*time.Hour))
	if err != nil || stats == nil {
		return hits, 0
	}
	for _, hc := range stats.TopHoneypots {
		hits[strings.ToLower(strings.TrimSpace(hc.Honeypot))] = int(hc.Count)
	}
	return hits, stats.TotalEvents
}

// clusterIdentity returns a (clusterId, clusterName) pair when this node is
// paired into a QPot cluster, else ("",""). The id is derived deterministically
// from the cluster name so the same group collapses to one cluster on the panel.
func (a *Agent) clusterIdentity() (string, string) {
	if a.cluster == nil {
		return "", ""
	}
	c, err := a.cluster.LoadCluster()
	if err != nil || c == nil || c.Name == "" {
		return "", ""
	}
	return "cl_" + shortHash(c.Name), c.Name
}

// ── derivations ──────────────────────────────────────────────────────────────

// severity maps a QPot event to the worker's {info, warn, critical} enum. QPot
// events carry no explicit severity, so we infer from the ATT&CK classification
// and the presence of credential/command activity.
func severity(e *database.Event) string {
	switch e.TacticID {
	// Credential Access, Lateral Movement, Execution, Impact, Exfiltration.
	case "TA0006", "TA0008", "TA0002", "TA0040", "TA0010":
		return "critical"
	}
	if e.Confidence >= 0.8 {
		return "critical"
	}
	if e.Classified || e.Username != "" || e.Password != "" || e.Command != "" {
		return "warn"
	}
	return "info"
}

// intent is a short human summary of what the attacker did. Prefer the event
// type, enrich with credential/command context when present.
func intent(e *database.Event) string {
	parts := make([]string, 0, 3)
	if e.EventType != "" {
		parts = append(parts, e.EventType)
	}
	if e.Username != "" {
		cred := e.Username
		if e.Password != "" {
			cred += "/" + e.Password
		}
		parts = append(parts, "login "+cred)
	} else if e.Command != "" {
		parts = append(parts, "cmd: "+e.Command)
	}
	if len(parts) == 0 {
		if e.Protocol != "" {
			return e.Protocol + " activity"
		}
		return "honeypot interaction"
	}
	return strings.Join(parts, " — ")
}

// tactic renders the MITRE tactic tag the panel can pivot on, e.g.
// "TA0006 Credential Access". Empty when the event is unclassified.
func tactic(e *database.Event) string {
	switch {
	case e.TacticID != "" && e.TacticName != "":
		return e.TacticID + " " + e.TacticName
	case e.TacticID != "":
		return e.TacticID
	case e.TacticName != "":
		return e.TacticName
	}
	return ""
}

// rawLine is the raw signal line shown in the event drawer. We synthesise one
// from the most descriptive field available.
func rawLine(e *database.Event) string {
	switch {
	case e.Command != "":
		return e.Command
	case e.Username != "":
		if e.Password != "" {
			return "login attempt " + e.Username + "/" + e.Password
		}
		return "login attempt " + e.Username
	case len(e.Payload) > 0:
		return string(e.Payload)
	default:
		return e.EventType
	}
}

// country normalises QPot's country field to the worker's 0–2 char ISO-3166
// alpha-2 expectation: a 2-letter code is upper-cased and passed through;
// anything else (full name, empty, code with extra text) becomes "" (allowed),
// which is honest rather than sending a value the worker rejects.
func country(c string) string {
	c = strings.TrimSpace(c)
	if len(c) == 2 {
		up := strings.ToUpper(c)
		if up[0] >= 'A' && up[0] <= 'Z' && up[1] >= 'A' && up[1] <= 'Z' {
			return up
		}
	}
	return ""
}

// eventID synthesises a stable, unique id for an event QPot's schema does not
// itself number. The same event always hashes to the same id (so re-pushes
// don't churn the panel's feed), and distinct events practically never collide.
func eventID(e *database.Event) string {
	key := fmt.Sprintf("%d|%s|%s|%d|%s|%s|%s",
		e.Timestamp.UnixNano(), e.Honeypot, e.SourceIP, e.DestPort,
		e.EventType, e.Username, e.Command)
	sum := sha256.Sum256([]byte(key))
	return "ev_" + hex.EncodeToString(sum[:])[:20]
}

// eventsPerSec converts a 24h event total into a rate, clamped to the worker's
// [0, 1_000_000] bound.
func eventsPerSec(total24h int64) float64 {
	if total24h <= 0 {
		return 0
	}
	rate := float64(total24h) / 86400.0
	if rate > 1_000_000 {
		return 1_000_000
	}
	return rate
}

// ── string hygiene ───────────────────────────────────────────────────────────

// sanitize strips the control characters (0x00–0x1F, 0x7F) the worker rejects,
// replacing them with spaces so the surrounding text stays readable.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// clampStr bounds a string to n runes, never splitting a multi-byte rune.
func clampStr(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

func clampPort(p int) int {
	if p < 0 {
		return 0
	}
	if p > 65535 {
		return 65535
	}
	return p
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
