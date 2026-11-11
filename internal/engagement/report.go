package engagement

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// Report is the engagement of one deployment over the events it was given.
type Report struct {
	// Label names the deployment in tables.
	Label string `json:"label"`
	// Source says where the events came from: "qpot-instance" or
	// "cowrie-log". Set by the caller.
	Source string `json:"source,omitempty"`
	// HoneypotFilter lists the honeypots the events were limited to.
	HoneypotFilter []string `json:"honeypot_filter,omitempty"`
	Window         Window   `json:"window"`
	Input          Input    `json:"input"`
	Limits         Limits   `json:"limits"`
	// Sources describes the source addresses of the sessions.
	Sources SourceSummary `json:"source_addresses"`
	// Overall covers every honeypot together.
	Overall Metrics `json:"overall"`
	// Honeypots holds the same metrics per honeypot, by name.
	Honeypots []HoneypotMetrics `json:"honeypots"`
	// Notes says which limits were reached and what that does to the
	// numbers.
	Notes []string `json:"notes,omitempty"`

	// detail carries the per-session samples and the source table Compare
	// uses. It is not part of the JSON.
	detail *detail
}

// Window is the time of the first and of the last event used.
type Window struct {
	First time.Time `json:"first_event,omitzero"`
	Last  time.Time `json:"last_event,omitzero"`
}

// Input counts the events given and what happened to them.
type Input struct {
	Events int64 `json:"events"`
	Used   int64 `json:"events_used"`
	// WithoutTime had no timestamp.
	WithoutTime int64 `json:"events_without_time"`
	// WithoutSessionKey had neither a session id nor a source address.
	WithoutSessionKey int64 `json:"events_without_session_key"`
	// OutsideSessionSample belong to a session key dropped by the session
	// limit. They still count in the diversity and intelligence figures.
	OutsideSessionSample int64 `json:"events_outside_session_sample"`
	// Log is set by the caller when the events were read from a log file.
	Log *LogStats `json:"log,omitempty"`
}

// Limits are the limits the report was computed under.
type Limits struct {
	Distinct        int `json:"distinct_values"`
	Stems           int `json:"command_stems"`
	SessionCommands int `json:"commands_per_session"`
	Sessions        int `json:"session_keys"`
	// SessionsReached is true when the session limit dropped session keys:
	// the session figures then cover a sample.
	SessionsReached bool `json:"session_keys_reached"`
	// Sample is the number of sessions kept for each rank test of a
	// comparison. SampleReached is true when a report had more: its rank
	// tests then run on a fixed sample of that size.
	Sample        int  `json:"rank_test_sessions"`
	SampleReached bool `json:"rank_test_sessions_reached"`
	// PairedSources is the number of source addresses kept for the overlap
	// and shared-source analysis of a comparison. PairedSourcesReached is
	// true when a report had more.
	PairedSources        int  `json:"paired_sources"`
	PairedSourcesReached bool `json:"paired_sources_reached"`
}

// HoneypotMetrics are the metrics of one honeypot.
type HoneypotMetrics struct {
	Honeypot string `json:"honeypot"`
	Metrics
}

// Metrics are the engagement figures of one scope.
type Metrics struct {
	Sessions       int64        `json:"sessions"`
	Funnel         Funnel       `json:"funnel"`
	Duration       Durations    `json:"duration"`
	Depth          Depth        `json:"depth"`
	Diversity      Diversity    `json:"diversity"`
	LeftAfterProbe Stage        `json:"left_after_probe"`
	Returning      Returning    `json:"returning_sources"`
	Intelligence   Intelligence `json:"intelligence"`
	TopStems       []StemCount  `json:"top_command_stems"`
	// Intervals are the 95% intervals of the shares and medians above, in
	// table order. A figure whose base is too small has none.
	Intervals []Interval `json:"intervals_95,omitempty"`
}

// Interval is the 95% confidence interval of one metric, in the metric's
// unit.
type Interval struct {
	// Key is the key of the metric, as in Definitions.
	Key  string  `json:"key"`
	Low  float64 `json:"low"`
	High float64 `json:"high"`
	// N is the size of the base: sessions, or sources.
	N int64 `json:"n"`
	// Method is "wilson" for a share (the Wilson score interval) and
	// "order-statistics" for a median (two order statistics chosen by
	// binomial ranks, valid for any distribution).
	Method string `json:"method"`
}

// Interval methods.
const (
	MethodWilson          = "wilson"
	MethodOrderStatistics = "order-statistics"
)

// interval returns the interval of the metric with the given key.
func (m *Metrics) interval(key string) *Interval {
	for i := range m.Intervals {
		if m.Intervals[i].Key == key {
			return &m.Intervals[i]
		}
	}
	return nil
}

// Stage is a count of sessions and its share of a base.
type Stage struct {
	Count   int64   `json:"count"`
	Percent float64 `json:"percent"`
}

// Funnel counts the sessions that reached each step, as a share of all
// sessions. The steps are counted independently.
type Funnel struct {
	LoginAttempted Stage `json:"login_attempted"`
	LoggedIn       Stage `json:"logged_in"`
	Interactive    Stage `json:"interactive"`
	Payload        Stage `json:"payload"`
}

// Durations hold the session length over all sessions and over the sessions
// that logged in.
type Durations struct {
	All      DurationStats `json:"all_sessions"`
	LoggedIn DurationStats `json:"logged_in_sessions"`
	// Reported is how many sessions took the length the honeypot stated
	// instead of last event minus first event.
	Reported int64 `json:"honeypot_reported_sessions"`
}

// DurationStats summarise session lengths in seconds.
type DurationStats struct {
	Sessions      int64   `json:"sessions"`
	MedianSeconds float64 `json:"median_seconds"`
	P90Seconds    float64 `json:"p90_seconds"`
	MaxSeconds    float64 `json:"max_seconds"`
	TotalSeconds  float64 `json:"total_seconds"`
}

// Depth is the number of commands per interactive session.
type Depth struct {
	InteractiveSessions int64   `json:"interactive_sessions"`
	Median              float64 `json:"median_commands"`
	P90                 int64   `json:"p90_commands"`
	Max                 int64   `json:"max_commands"`
	Total               int64   `json:"total_commands"`
}

// Diversity describes how varied the commands are.
type Diversity struct {
	// DistinctCommands counts distinct normalized input lines.
	DistinctCommands        int64 `json:"distinct_commands"`
	DistinctCommandsReached bool  `json:"distinct_commands_limit_reached"`
	// PerSessionMedian is the median number of distinct input lines per
	// interactive session.
	PerSessionMedian float64 `json:"distinct_per_session_median"`
	// PerSessionReached counts the sessions with more distinct lines than
	// the per-session limit; they count as the limit.
	PerSessionReached int64 `json:"sessions_at_per_session_limit"`
	// StemEntropyBits is the Shannon entropy of the command stems.
	StemEntropyBits float64 `json:"stem_entropy_bits"`
	DistinctStems   int64   `json:"distinct_stems"`
	StemsReached    bool    `json:"stems_limit_reached"`
}

// StemCount is a command stem and how many input lines had it.
type StemCount struct {
	Stem  string `json:"stem"`
	Count int64  `json:"count"`
}

// Returning counts the sources that came back.
type Returning struct {
	// InteractiveSources had at least one interactive session.
	InteractiveSources int64 `json:"interactive_sources"`
	// Returned started another session at least ReturnAfter after one of
	// their interactive sessions ended.
	Returned int64   `json:"returned"`
	Percent  float64 `json:"percent"`
}

// Distinct is a count of distinct values and its rate per 1000 sessions.
type Distinct struct {
	Count        int64   `json:"count"`
	Per1000      float64 `json:"per_1000_sessions"`
	LimitReached bool    `json:"limit_reached"`
}

// Intelligence counts what the sessions left that can be acted on.
type Intelligence struct {
	PayloadHashes   Distinct `json:"payload_hashes"`
	DownloadURLs    Distinct `json:"download_urls"`
	DownloadHosts   Distinct `json:"download_hosts"`
	CredentialPairs Distinct `json:"credential_pairs"`
	Techniques      Distinct `json:"attack_techniques"`
}

// sourceSpan is what the returning-sources figure needs about one source.
type sourceSpan struct {
	interactive bool
	minEnd      int64 // earliest end of an interactive session
	maxStart    int64 // latest start of any session
}

// scopeAcc collects the sessions of one scope.
type scopeAcc struct {
	sessions                                   int64
	attempted, loggedIn, interactive, payload  int64
	left, reported, perSessionOver, totalCmds  int64
	durAll, durLoggedIn, depth, distinctPerSes []int64
	sources                                    map[uint32]*sourceSpan
}

func (c *scopeAcc) add(s *session) {
	c.sessions++
	dur := s.last - s.first
	if s.reported > 0 {
		dur = s.reported
		c.reported++
	}
	c.durAll = append(c.durAll, dur)
	if s.attempted {
		c.attempted++
	}
	if s.loggedIn {
		c.loggedIn++
		c.durLoggedIn = append(c.durLoggedIn, dur)
	}
	if s.payload {
		c.payload++
	}
	interactive := s.commands > 0
	if interactive {
		c.interactive++
		c.totalCmds += int64(s.commands)
		c.depth = append(c.depth, int64(s.commands))
		c.distinctPerSes = append(c.distinctPerSes, int64(len(s.cmds)))
		if s.cmdsOver {
			c.perSessionOver++
		}
		probe := s.lastProbe == probeYes || (s.lastProbe == probeIfNoPayload && !s.payload)
		if s.commands <= ShortSession && probe {
			c.left++
		}
	}
	if s.src == 0 {
		return
	}
	if c.sources == nil {
		c.sources = make(map[uint32]*sourceSpan)
	}
	sp := c.sources[s.src]
	if sp == nil {
		sp = &sourceSpan{maxStart: s.first}
		c.sources[s.src] = sp
	}
	sp.maxStart = max(sp.maxStart, s.first)
	if interactive {
		if !sp.interactive || s.last < sp.minEnd {
			sp.minEnd = s.last
		}
		sp.interactive = true
	}
}

// Report computes the report from the events added so far. The Aggregator
// must not be used afterwards.
func (a *Aggregator) Report(label string) *Report {
	a.groups.finish()
	overall := &scopeAcc{}
	perHP := make([]*scopeAcc, len(a.hpNames))
	for i := range perHP {
		perHP[i] = &scopeAcc{}
	}
	kept := int64(0)
	db := newDetailBuilder(a)
	for key, g := range a.groups.m {
		kept += g.events
		if !g.bySource {
			overall.add(&g.one)
			perHP[g.honeypot].add(&g.one)
			db.add(key, 0, &g.one)
			continue
		}
		for i := range g.segs {
			overall.add(&g.segs[i])
			perHP[g.honeypot].add(&g.segs[i])
			db.add(key, i, &g.segs[i])
		}
	}

	// Counted here, not as events arrive: which events a dropped key had
	// already received depends on their order, the kept ones do not.
	a.in.OutsideSessionSample = a.in.Used - kept
	r := &Report{
		Label: label,
		Input: a.in,
		Limits: Limits{
			Distinct:        a.opt.DistinctLimit,
			Stems:           a.opt.StemLimit,
			SessionCommands: a.opt.SessionCommandLimit,
			Sessions:        a.opt.SessionLimit,
			SessionsReached: a.groups.over,
			Sample:          a.opt.SampleLimit,
			SampleReached:   db.durAll.over(),
			PairedSources:   a.opt.SourceLimit,
		},
		Honeypots: make([]HoneypotMetrics, 0, len(a.hpNames)),
	}
	r.Sources, r.detail = db.finish()
	r.Limits.PairedSourcesReached = r.detail.sourcesOver
	if a.haveTime {
		r.Window = Window{First: time.UnixMicro(a.first).UTC(), Last: time.UnixMicro(a.last).UTC()}
	}
	r.Overall = metricsOf(overall, a.overall)
	for i, name := range a.hpNames {
		r.Honeypots = append(r.Honeypots, HoneypotMetrics{Honeypot: name, Metrics: metricsOf(perHP[i], a.hpSets[i])})
	}
	sort.Slice(r.Honeypots, func(i, j int) bool { return r.Honeypots[i].Honeypot < r.Honeypots[j].Honeypot })

	if a.groups.over {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"More than %d session keys: sessions, funnel, duration, depth, left after a probe and returning sources cover a fixed sample of %d keys. Diversity and intelligence counts cover every event.",
			a.opt.SessionLimit, a.opt.SessionLimit))
	}
	if r.Limits.SampleReached {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"More than %d sessions: the rank tests of a comparison (session length, commands per session) use a fixed sample of %d sessions per row. Medians and their intervals cover every session.",
			a.opt.SampleLimit, a.opt.SampleLimit))
	}
	if r.Limits.PairedSourcesReached {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"More than %d source addresses: the source overlap and the shared-source analysis of a comparison cover a fixed sample of %d of them. The source counts cover all.",
			a.opt.SourceLimit, a.opt.SourceLimit))
	}
	r.Notes = append(r.Notes, limitNotes("all honeypots", &r.Overall, a.opt)...)
	for i := range r.Honeypots {
		r.Notes = append(r.Notes, limitNotes(r.Honeypots[i].Honeypot, &r.Honeypots[i].Metrics, a.opt)...)
	}
	return r
}

// limitNotes lists the limits one scope reached.
func limitNotes(scope string, m *Metrics, o Options) []string {
	var notes []string
	add := func(reached bool, what string, limit int) {
		if reached {
			notes = append(notes, fmt.Sprintf("%s: %s reached the limit of %d; the count is a lower bound.", scope, what, limit))
		}
	}
	add(m.Diversity.DistinctCommandsReached, "distinct commands", o.DistinctLimit)
	add(m.Intelligence.PayloadHashes.LimitReached, "payload hashes", o.DistinctLimit)
	add(m.Intelligence.DownloadURLs.LimitReached, "download URLs", o.DistinctLimit)
	add(m.Intelligence.DownloadHosts.LimitReached, "download hosts", o.DistinctLimit)
	add(m.Intelligence.CredentialPairs.LimitReached, "credential pairs", o.DistinctLimit)
	add(m.Intelligence.Techniques.LimitReached, "ATT&CK techniques", o.DistinctLimit)
	if m.Diversity.StemsReached {
		notes = append(notes, fmt.Sprintf(
			"%s: more than %d distinct command stems; the entropy counts the others as one stem and is a lower bound, and the top stems come from the %d kept.",
			scope, o.StemLimit, o.StemLimit))
	}
	if m.Diversity.PerSessionReached > 0 {
		notes = append(notes, fmt.Sprintf(
			"%s: %d sessions had more than %d distinct commands and count as %d.",
			scope, m.Diversity.PerSessionReached, o.SessionCommandLimit, o.SessionCommandLimit))
	}
	return notes
}

// metricsOf turns the sessions and distinct values of a scope into metrics.
func metricsOf(c *scopeAcc, sets *scopeSets) Metrics {
	m := Metrics{Sessions: c.sessions}
	m.Funnel = Funnel{
		LoginAttempted: stageOf(c.attempted, c.sessions),
		LoggedIn:       stageOf(c.loggedIn, c.sessions),
		Interactive:    stageOf(c.interactive, c.sessions),
		Payload:        stageOf(c.payload, c.sessions),
	}
	m.Duration = Durations{All: durationStats(c.durAll), LoggedIn: durationStats(c.durLoggedIn), Reported: c.reported}

	sortInt64(c.depth)
	sortInt64(c.distinctPerSes)
	m.Depth = Depth{InteractiveSessions: c.interactive, Total: c.totalCmds}
	if n := len(c.depth); n > 0 {
		m.Depth.Median = round(median(c.depth), 2)
		m.Depth.P90 = p90(c.depth)
		m.Depth.Max = c.depth[n-1]
	}
	m.LeftAfterProbe = stageOf(c.left, c.interactive)

	sets.commands.finish()
	sets.stems.finish()
	m.Diversity = Diversity{
		DistinctCommands:        int64(len(sets.commands.m)),
		DistinctCommandsReached: sets.commands.over,
		PerSessionReached:       c.perSessionOver,
		DistinctStems:           int64(len(sets.stems.m)),
		StemsReached:            sets.stems.over,
	}
	if len(c.distinctPerSes) > 0 {
		m.Diversity.PerSessionMedian = round(median(c.distinctPerSes), 2)
	}
	m.Diversity.StemEntropyBits, m.TopStems = stemStats(sets)

	for _, sp := range c.sources {
		if !sp.interactive {
			continue
		}
		m.Returning.InteractiveSources++
		if sp.maxStart-sp.minEnd >= ReturnAfter.Microseconds() {
			m.Returning.Returned++
		}
	}
	m.Returning.Percent = percent(m.Returning.Returned, m.Returning.InteractiveSources)

	m.Intelligence = Intelligence{
		PayloadHashes:   distinctOf(sets.hashes, c.sessions),
		DownloadURLs:    distinctOf(sets.urls, c.sessions),
		DownloadHosts:   distinctOf(sets.hosts, c.sessions),
		CredentialPairs: distinctOf(sets.creds, c.sessions),
		Techniques:      distinctOf(sets.techniques, c.sessions),
	}

	// The 95% intervals, in table order. The slices are ascending by now.
	share := func(key string, count, base int64) {
		if lo, hi, ok := wilson(count, base); ok {
			m.Intervals = append(m.Intervals, Interval{Key: key, Low: round(lo*100, 2), High: round(hi*100, 2), N: base, Method: MethodWilson})
		}
	}
	middle := func(key string, v []int64, unit float64, digits int) {
		if lo, hi, ok := medianInterval(v); ok {
			m.Intervals = append(m.Intervals, Interval{
				Key: key, Low: round(float64(lo)/unit, digits), High: round(float64(hi)/unit, digits),
				N: int64(len(v)), Method: MethodOrderStatistics,
			})
		}
	}
	share("login_attempted_pct", c.attempted, c.sessions)
	share("logged_in_pct", c.loggedIn, c.sessions)
	share("interactive_pct", c.interactive, c.sessions)
	share("payload_pct", c.payload, c.sessions)
	middle("duration_logged_in_median_s", c.durLoggedIn, 1e6, 3)
	middle("duration_all_median_s", c.durAll, 1e6, 3)
	middle("depth_median", c.depth, 1, 0)
	middle("distinct_per_session_median", c.distinctPerSes, 1, 0)
	share("left_after_probe_pct", c.left, c.interactive)
	share("returning_sources_pct", m.Returning.Returned, m.Returning.InteractiveSources)
	return m
}

// stemStats returns the Shannon entropy of the stem counts, in bits, and the
// most used stems. Stems dropped by the limit count as one stem.
func stemStats(sets *scopeSets) (float64, []StemCount) {
	stems := sets.stems.keys()
	top := make([]StemCount, 0, len(stems))
	var kept int64
	for _, s := range stems {
		n := *sets.stems.m[s]
		kept += n
		top = append(top, StemCount{Stem: s, Count: n})
	}
	entropy := 0.0
	if sets.stemTotal > 0 {
		total := float64(sets.stemTotal)
		for _, sc := range top {
			p := float64(sc.Count) / total
			entropy -= p * math.Log2(p)
		}
		if rest := sets.stemTotal - kept; rest > 0 {
			p := float64(rest) / total
			entropy -= p * math.Log2(p)
		}
	}
	sort.SliceStable(top, func(i, j int) bool { return top[i].Count > top[j].Count })
	if len(top) > TopStemCount {
		top = top[:TopStemCount]
	}
	return round(entropy, 4), top
}

func distinctOf(set *capped[uint64, struct{}], sessions int64) Distinct {
	set.finish()
	d := Distinct{Count: int64(len(set.m)), LimitReached: set.over}
	if sessions > 0 {
		d.Per1000 = round(float64(d.Count)*1000/float64(sessions), 2)
	}
	return d
}

func stageOf(count, base int64) Stage {
	return Stage{Count: count, Percent: percent(count, base)}
}

func percent(count, base int64) float64 {
	if base <= 0 {
		return 0
	}
	return round(float64(count)*100/float64(base), 2)
}

// durationStats summarises session lengths given in microseconds.
func durationStats(us []int64) DurationStats {
	sortInt64(us)
	d := DurationStats{Sessions: int64(len(us))}
	if len(us) == 0 {
		return d
	}
	var total int64
	for _, v := range us {
		total += v
	}
	d.MedianSeconds = round(median(us)/1e6, 3)
	d.P90Seconds = round(float64(p90(us))/1e6, 3)
	d.MaxSeconds = round(float64(us[len(us)-1])/1e6, 3)
	d.TotalSeconds = round(float64(total)/1e6, 3)
	return d
}

func sortInt64(v []int64) {
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
}

// median of an ascending, non-empty slice: the middle value, or the mean of
// the two middle values.
func median(v []int64) float64 {
	n := len(v)
	if n%2 == 1 {
		return float64(v[n/2])
	}
	return (float64(v[n/2-1]) + float64(v[n/2])) / 2
}

// p90 of an ascending, non-empty slice by the nearest-rank method: the value
// at rank ceil(0.9 n), counting from 1.
func p90(v []int64) int64 {
	rank := (9*len(v) + 9) / 10
	return v[rank-1]
}

func round(x float64, digits int) float64 {
	p := math.Pow(10, float64(digits))
	return math.Round(x*p) / p
}
