// Package behaviour raises alerts on what a visitor does, where the volume
// alert (config.AlertConfig) only counts events:
//
//   - a payload the instance has not seen before;
//   - a session that goes from discovery to persistence;
//   - a planted credential used in a service other than the one it was
//     planted in;
//   - sources that share a campaign's payload, download host or command
//     sequence;
//   - a source that comes back and is hands-on again.
//
// It reads what the intelligence worker already stored (sessions, payload
// hashes) and the canary trips, and keeps a small state of what it has
// alerted on, so each thing alerts once. The first evaluation is a baseline:
// what is already there is remembered, not alerted, so turning the feature
// on never floods the operator with the past.
//
// Evaluate is pure: it takes the state and an input and returns the alerts
// to raise. Delivery (webhook, hooks, the stored list) is the server's.
package behaviour

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/intelligence"
)

// The rules.
const (
	RuleNewPayload       = "new-payload"
	RuleProgression      = "progression"
	RuleCredentialReuse  = "credential-reuse"
	RuleSharedPlaybook   = "shared-playbook"
	RuleReturningVisitor = "returning-visitor"
)

// Rule describes one rule to an operator.
type Rule struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// Rules lists every rule, in the order they are shown.
var Rules = []Rule{
	{RuleNewPayload, "New payload", "high", "A file was downloaded or uploaded whose SHA-256 this instance has not recorded before."},
	{RuleProgression, "Discovery to persistence", "high", "One session looked around the system and then tried to stay: a cron job, an SSH key, a new account or service."},
	{RuleCredentialReuse, "Planted credential used elsewhere", "critical", "A credential QPot planted in one honeypot was used against another: it was read there and carried over."},
	{RuleSharedPlaybook, "Sources sharing a playbook", "medium", "Different sources showed the same payload, download host or command sequence: one campaign. Raised when a campaign forms and as it grows."},
	{RuleReturningVisitor, "Returning visitor", "medium", "A source that ran commands in an earlier session came back, at least an hour later, and ran commands again."},
}

// IsRule reports whether name is a rule.
func IsRule(name string) bool {
	for _, r := range Rules {
		if r.Name == name {
			return true
		}
	}
	return false
}

func severityOf(rule string) string {
	for _, r := range Rules {
		if r.Name == rule {
			return r.Severity
		}
	}
	return "medium"
}

// Limits on what the state keeps. It is small and bounded whatever visitors
// do: at a limit the oldest entries go, and the worst that follows is one
// repeated alert for something not seen for a long time.
const (
	MaxAlerts    = 500
	maxPayloads  = 50000
	maxSessions  = 50000
	maxCampaigns = 20000
	maxTrips     = 20000
	// MaxPerRun bounds the alerts one evaluation raises, most severe first;
	// the rest are raised by later evaluations.
	MaxPerRun = 25
	// ReturnAfter is how long a source must have been away to count as
	// returning.
	ReturnAfter = time.Hour
	// maxSources is how many addresses an alert lists.
	maxSources = 10
)

// campaignSteps are the campaign sizes, in sessions of distinct sources, at
// which the shared-playbook rule alerts.
var campaignSteps = []int{2, 5, 10, 25, 50, 100, 250, 500, 1000}

// Alert is one raised alert.
type Alert struct {
	// ID names what the alert is about, so the same thing is one alert.
	ID       string    `json:"id"`
	Rule     string    `json:"rule"`
	Severity string    `json:"severity"`
	Time     time.Time `json:"time"`
	// Title is one line; Detail says what was observed.
	Title  string `json:"title"`
	Detail string `json:"detail"`
	// SessionID and Campaign name the case to open (qpot investigate).
	SessionID string   `json:"session_id,omitempty"`
	Campaign  string   `json:"campaign_fingerprint,omitempty"`
	Sources   []string `json:"source_ips,omitempty"`
	// Evidence lists the values the alert rests on: a hash, a canary, the
	// stages reached.
	Evidence []string `json:"evidence,omitempty"`
}

// State is what has been alerted on. The zero value is a state that has
// not run yet.
type State struct {
	Version int `json:"version"`
	// Started is the time of the baseline: nothing before it alerts.
	Started   time.Time            `json:"started"`
	Payloads  map[string]time.Time `json:"payloads,omitempty"`
	Sessions  map[string]time.Time `json:"sessions,omitempty"` // "<rule>/<session id>"
	Campaigns map[string]int       `json:"campaigns,omitempty"`
	Trips     map[string]time.Time `json:"trips,omitempty"`
	// Alerts are the most recent alerts, oldest first.
	Alerts []Alert `json:"alerts,omitempty"`
}

// Input is what one evaluation looks at.
type Input struct {
	Now time.Time
	// Sessions are the stored sessions, as many as the caller reads.
	Sessions []*database.TTPSession
	// Payloads are the stored file-hash indicators.
	Payloads []*database.IOC
	Trips    []*canary.Trip
	Canaries []*canary.Canary
	// Off names the rules that are turned off.
	Off []string
}

func (s *State) init() {
	if s.Payloads == nil {
		s.Payloads = map[string]time.Time{}
	}
	if s.Sessions == nil {
		s.Sessions = map[string]time.Time{}
	}
	if s.Campaigns == nil {
		s.Campaigns = map[string]int{}
	}
	if s.Trips == nil {
		s.Trips = map[string]time.Time{}
	}
}

func alertID(rule, subject string) string {
	sum := sha256.Sum256([]byte(rule + "\x00" + subject))
	return hex.EncodeToString(sum[:12])
}

// interactive reports whether a session ran something: it reached a stage
// past getting in.
func interactive(s *database.TTPSession) bool {
	for _, stage := range s.KillChainStages {
		switch stage {
		case "", "reconnaissance", "resource-development", "initial-access", "credential-access":
		default:
			return true
		}
	}
	return false
}

// progressed reports whether a session shows discovery and, after it,
// persistence. The stages are kept in the order the session first showed
// them.
func progressed(s *database.TTPSession) bool {
	seenDiscovery := false
	for _, stage := range s.KillChainStages {
		switch stage {
		case "discovery":
			seenDiscovery = true
		case "persistence":
			if seenDiscovery {
				return true
			}
		}
	}
	return false
}

func sources(list []string) []string {
	if len(list) > maxSources {
		list = list[:maxSources]
	}
	return append([]string{}, list...)
}

// plantedIn returns the honeypot a planted canary was planted in: its name
// starts with it ("cowrie bait: AWS access key").
func plantedIn(c *canary.Canary) string {
	hp, _, ok := strings.Cut(c.Name, " bait:")
	if !ok || hp == "" || strings.ContainsAny(hp, " \t") {
		return ""
	}
	return hp
}

// trippedIn returns the honeypot a trip's detail names ("matched in cowrie
// session").
func trippedIn(t *canary.Trip) string {
	rest, ok := strings.CutPrefix(t.Detail, "matched in ")
	if !ok {
		return ""
	}
	hp, ok := strings.CutSuffix(rest, " session")
	if !ok || hp == "" || strings.ContainsAny(hp, " \t") {
		return ""
	}
	return hp
}

// Evaluate returns the alerts to raise for in, and records them in state.
// The first call for a state raises none: it is the baseline.
func Evaluate(state *State, in Input) []Alert {
	state.init()
	state.Version = 1
	now := in.Now.UTC()
	baseline := state.Started.IsZero()
	if baseline {
		state.Started = now
	}
	off := map[string]bool{}
	for _, r := range in.Off {
		off[r] = true
	}
	var raised []Alert
	raise := func(a Alert) {
		a.ID = alertID(a.Rule, a.ID)
		a.Severity = severityOf(a.Rule)
		a.Time = now
		raised = append(raised, a)
	}

	// A payload this instance has not recorded before.
	for _, ioc := range in.Payloads {
		if ioc == nil || ioc.Type != intelligence.IOCTypeHash || len(ioc.Value) != 64 {
			continue
		}
		if _, seen := state.Payloads[ioc.Value]; seen {
			continue
		}
		state.Payloads[ioc.Value] = now
		if baseline || off[RuleNewPayload] || ioc.FirstSeen.Before(state.Started) {
			continue
		}
		a := Alert{ID: ioc.Value, Rule: RuleNewPayload, Title: "A payload not seen before: " + ioc.Value[:16] + "…",
			Detail:   fmt.Sprintf("A file with SHA-256 %s was transferred to %s. This instance had not recorded that hash before.", ioc.Value, orUnknown(ioc.Honeypot)),
			Evidence: []string{"sha256 " + ioc.Value}}
		if ioc.SourceIP != "" {
			a.Sources = []string{ioc.SourceIP}
		}
		raise(a)
	}

	// Sessions, oldest first, so an earlier visit is known before a later one.
	sessions := make([]*database.TTPSession, 0, len(in.Sessions))
	for _, s := range in.Sessions {
		if s != nil && s.SessionID != "" {
			sessions = append(sessions, s)
		}
	}
	sort.SliceStable(sessions, func(i, j int) bool {
		if !sessions[i].FirstSeen.Equal(sessions[j].FirstSeen) {
			return sessions[i].FirstSeen.Before(sessions[j].FirstSeen)
		}
		return sessions[i].SessionID < sessions[j].SessionID
	})
	once := func(rule, id string) bool {
		key := rule + "/" + id
		if _, done := state.Sessions[key]; done {
			return false
		}
		state.Sessions[key] = now
		return true
	}
	// The latest interactive session of each source seen so far.
	earlier := map[string]*database.TTPSession{}
	type campaign struct {
		sources map[string]bool
		last    *database.TTPSession
		all     []string
	}
	campaigns := map[string]*campaign{}
	for _, s := range sessions {
		recent := !s.LastSeen.Before(state.Started)

		if progressed(s) && once(RuleProgression, s.SessionID) && !baseline && !off[RuleProgression] && recent {
			raise(Alert{ID: s.SessionID, Rule: RuleProgression, SessionID: s.SessionID, Campaign: s.CampaignFingerprint, Sources: sources(s.SourceIPs),
				Title:    "A session went from discovery to persistence",
				Detail:   "The session looked around the system and then tried to stay. Stages, in the order it reached them: " + strings.Join(s.KillChainStages, ", ") + ".",
				Evidence: append([]string{"stages " + strings.Join(s.KillChainStages, " > ")}, techniques(s)...)})
		}

		source, _, ok := intelligence.SplitSessionID(s.SessionID)
		named := ok && len(s.SourceIPs) > 0 // a shared or unknown source is no one visitor
		if named && interactive(s) {
			if prev := earlier[source]; prev != nil && s.FirstSeen.Sub(prev.LastSeen) >= ReturnAfter &&
				once(RuleReturningVisitor, s.SessionID) && !baseline && !off[RuleReturningVisitor] && recent {
				raise(Alert{ID: s.SessionID, Rule: RuleReturningVisitor, SessionID: s.SessionID, Campaign: s.CampaignFingerprint, Sources: sources(s.SourceIPs),
					Title: "A visitor came back and ran commands again",
					Detail: fmt.Sprintf("This source ran commands in a session that ended %s, and is active again after %s away.",
						prev.LastSeen.UTC().Format("2006-01-02 15:04 UTC"), s.FirstSeen.Sub(prev.LastSeen).Round(time.Minute)),
					Evidence: []string{"earlier session " + prev.SessionID}})
			}
			earlier[source] = s
		}

		if named && s.CampaignFingerprint != "" {
			c := campaigns[s.CampaignFingerprint]
			if c == nil {
				c = &campaign{sources: map[string]bool{}}
				campaigns[s.CampaignFingerprint] = c
			}
			if !c.sources[source] {
				c.sources[source] = true
				for _, ip := range s.SourceIPs {
					if len(c.all) < maxSources {
						c.all = append(c.all, ip)
					}
				}
			}
			if c.last == nil || s.LastSeen.After(c.last.LastSeen) {
				c.last = s
			}
		}
	}
	// Campaigns: when one forms, and as it grows.
	fingerprints := make([]string, 0, len(campaigns))
	for fp := range campaigns {
		fingerprints = append(fingerprints, fp)
	}
	sort.Strings(fingerprints)
	for _, fp := range fingerprints {
		c := campaigns[fp]
		step := 0
		for _, n := range campaignSteps {
			if len(c.sources) >= n {
				step = n
			}
		}
		if step == 0 || state.Campaigns[fp] >= step {
			continue
		}
		state.Campaigns[fp] = step
		if baseline || off[RuleSharedPlaybook] || c.last.LastSeen.Before(state.Started) {
			continue
		}
		raise(Alert{ID: fmt.Sprintf("%s/%d", fp, step), Rule: RuleSharedPlaybook, Campaign: fp, Sources: c.all,
			Title:    fmt.Sprintf("%d sources share one playbook", len(c.sources)),
			Detail:   fmt.Sprintf("%d different sources showed the same payload, download host or command sequence. Open the campaign to see which, and the records that show it.", len(c.sources)),
			Evidence: []string{fmt.Sprintf("%d sources in campaign %s", len(c.sources), fp)}})
	}

	// A planted credential used in another service than it was planted in.
	planted := map[string]*canary.Canary{}
	for _, c := range in.Canaries {
		if c != nil && c.Planted {
			planted[c.ID] = c
		}
	}
	for _, t := range in.Trips {
		if t == nil || t.ID == "" {
			continue
		}
		if _, done := state.Trips[t.ID]; done {
			continue
		}
		state.Trips[t.ID] = now
		c := planted[t.CanaryID]
		if c == nil || baseline || off[RuleCredentialReuse] || t.Time.Before(state.Started) {
			continue
		}
		from, to := plantedIn(c), trippedIn(t)
		if from == "" || to == "" || from == to {
			continue
		}
		a := Alert{ID: t.ID, Rule: RuleCredentialReuse, Title: "A credential planted in " + from + " was used against " + to,
			Detail:   fmt.Sprintf("%q is planted in %s (%s). It was captured in a %s session: someone read it there and used it here.", c.Name, from, c.Memo, to),
			Evidence: []string{"canary " + c.ID, "trip " + t.ID}}
		if t.SourceIP != "" {
			a.Sources = []string{t.SourceIP}
		}
		raise(a)
	}

	// Most severe first, and no more than one run may raise.
	sort.SliceStable(raised, func(i, j int) bool { return rank(raised[i].Severity) < rank(raised[j].Severity) })
	if len(raised) > MaxPerRun {
		// What is left out alerts on a later run: forget that it was seen.
		for _, a := range raised[MaxPerRun:] {
			state.forget(a)
		}
		raised = raised[:MaxPerRun]
	}
	state.Alerts = append(state.Alerts, raised...)
	if len(state.Alerts) > MaxAlerts {
		state.Alerts = append([]Alert{}, state.Alerts[len(state.Alerts)-MaxAlerts:]...)
	}
	state.prune()
	return raised
}

// forget undoes the record that an alert's subject was seen.
func (s *State) forget(a Alert) {
	switch a.Rule {
	case RuleNewPayload:
		for _, e := range a.Evidence {
			delete(s.Payloads, strings.TrimPrefix(e, "sha256 "))
		}
	case RuleProgression, RuleReturningVisitor:
		delete(s.Sessions, a.Rule+"/"+a.SessionID)
	case RuleSharedPlaybook:
		delete(s.Campaigns, a.Campaign)
	case RuleCredentialReuse:
		for _, e := range a.Evidence {
			if id, ok := strings.CutPrefix(e, "trip "); ok {
				delete(s.Trips, id)
			}
		}
	}
}

func rank(severity string) int {
	switch severity {
	case "critical":
		return 0
	case "high":
		return 1
	}
	return 2
}

func orUnknown(s string) string {
	if s == "" {
		return "a honeypot"
	}
	return s
}

func techniques(s *database.TTPSession) []string {
	if len(s.Techniques) == 0 {
		return nil
	}
	list := s.Techniques
	if len(list) > 12 {
		list = list[:12]
	}
	return []string{"techniques " + strings.Join(list, ", ")}
}

// prune keeps the state within its limits, dropping what was recorded
// longest ago.
func (s *State) prune() {
	pruneTimes(s.Payloads, maxPayloads)
	pruneTimes(s.Sessions, maxSessions)
	pruneTimes(s.Trips, maxTrips)
	if over := len(s.Campaigns) - maxCampaigns; over > 0 {
		keys := make([]string, 0, len(s.Campaigns))
		for k := range s.Campaigns {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys[:over] {
			delete(s.Campaigns, k)
		}
	}
}

func pruneTimes(m map[string]time.Time, limit int) {
	over := len(m) - limit
	if over <= 0 {
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if !m[keys[i]].Equal(m[keys[j]]) {
			return m[keys[i]].Before(m[keys[j]])
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys[:over] {
		delete(m, k)
	}
}
