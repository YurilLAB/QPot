package engagement

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// MaxSessionRatio is the largest ratio between the session counts of two
// reports at which Compare still calls their exposure comparable.
const MaxSessionRatio = 3.0

// MinPeriodOverlap is the smallest share of the combined observation period
// that two reports must have in common, in percent, for Compare to call their
// exposure comparable.
const MinPeriodOverlap = 80.0

// CollapsedShare is the share of a report's sessions, in percent, that one
// source address (or all private and reserved addresses together) may carry.
// Above it the sources count as collapsed, the way they do behind NAT or
// Docker's port proxy, and the shared-source analysis is skipped.
const CollapsedShare = 50.0

// reservedPrefixes are the address ranges that never name a visitor on the
// internet, beyond the ones net/netip classifies itself (private, loopback,
// link-local, multicast, unspecified). The list matches the one
// internal/intelligence uses for indicators. Like there, the documentation
// ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) are
// not on it: tests use them as stand-ins for public addresses, and a real
// capture cannot contain them.
var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),     // "this network"
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),   // reserved, and broadcast
}

// sourceKeyOf turns a logged source address into the key sources are counted
// and paired by. An IPv4 address is its own key; an IPv6 address counts as
// its /64, the smallest prefix one host is routinely given, as in
// internal/intelligence; an IPv4-mapped IPv6 address is the IPv4 address.
// public is false for an address that cannot name a visitor on the internet:
// private, loopback, link-local, multicast, unspecified or otherwise
// reserved, or text that is not an address at all.
func sourceKeyOf(raw string) (key string, public bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "text:" + raw, false
	}
	addr = addr.Unmap().WithZone("")
	public = !(addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsMulticast())
	if public {
		for _, p := range reservedPrefixes {
			if p.Contains(addr) {
				public = false
				break
			}
		}
	}
	if addr.Is4() {
		return addr.String(), public
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return addr.String(), public
	}
	return prefix.String(), public
}

// sourceStat is what one report knows about one source: how far it went over
// all of its sessions.
type sourceStat struct {
	sessions    int64
	loggedIn    bool
	command     bool
	payload     bool
	maxCommands uint32
	longest     int64 // microseconds
	public      bool
}

func (st *sourceStat) add(s *session) {
	st.sessions++
	st.loggedIn = st.loggedIn || s.loggedIn
	st.command = st.command || s.commands > 0
	st.payload = st.payload || s.payload
	st.maxCommands = max(st.maxCommands, s.commands)
	st.longest = max(st.longest, sessionLength(s))
}

// sessionLength is the length of a session in microseconds: what the honeypot
// stated, else last event minus first event.
func sessionLength(s *session) int64 {
	if s.reported > 0 {
		return s.reported
	}
	return s.last - s.first
}

// sourceEntry is one source of a report, under the hash of its key.
type sourceEntry struct {
	key groupKey
	sourceStat
}

// sampleKey orders the sessions of a report for the rank-test sample. It is a
// hash of the session's key, so which sessions are kept has nothing to do
// with what they did.
type sampleKey struct {
	h, b uint64
	seg  uint64
}

func lessSampleKey(x, y sampleKey) bool {
	if x.h != y.h {
		return x.h < y.h
	}
	if x.b != y.b {
		return x.b < y.b
	}
	return x.seg < y.seg
}

// sampleKeyOf is the sample key of run seg of the group under key. The run
// number goes through a bijective mix (the splitmix64 finalizer), so the runs
// of one source spread over the whole order instead of standing together.
func sampleKeyOf(key groupKey, seg int) sampleKey {
	x := key.a + uint64(seg)*0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	x ^= x >> 31
	return sampleKey{h: x, b: key.b, seg: uint64(seg)}
}

// sampler keeps the values of the limit sessions with the smallest sample
// keys, whatever order they are added in. It never holds more than limit
// values: a heap with the largest kept key on top.
type sampler struct {
	limit int
	total int64
	keys  []sampleKey
	vals  []int64
}

func newSampler(limit int) *sampler {
	return &sampler{limit: max(1, limit)}
}

func (s *sampler) add(k sampleKey, v int64) {
	s.total++
	if len(s.keys) < s.limit {
		s.keys = append(s.keys, k)
		s.vals = append(s.vals, v)
		for i := len(s.keys) - 1; i > 0; {
			parent := (i - 1) / 2
			if !lessSampleKey(s.keys[parent], s.keys[i]) {
				break
			}
			s.swap(i, parent)
			i = parent
		}
		return
	}
	if !lessSampleKey(k, s.keys[0]) {
		return
	}
	s.keys[0], s.vals[0] = k, v
	for i := 0; ; {
		largest := i
		for _, child := range [2]int{2*i + 1, 2*i + 2} {
			if child < len(s.keys) && lessSampleKey(s.keys[largest], s.keys[child]) {
				largest = child
			}
		}
		if largest == i {
			return
		}
		s.swap(i, largest)
		i = largest
	}
}

func (s *sampler) swap(i, j int) {
	s.keys[i], s.keys[j] = s.keys[j], s.keys[i]
	s.vals[i], s.vals[j] = s.vals[j], s.vals[i]
}

// values returns the kept values in ascending order, or nil when there are
// none.
func (s *sampler) values() []int64 {
	if len(s.vals) == 0 {
		return nil
	}
	out := append([]int64(nil), s.vals...)
	sortInt64(out)
	return out
}

func (s *sampler) over() bool { return s.total > int64(len(s.vals)) }

// detail is what Compare needs from a report beyond its published figures:
// per-session samples for the rank tests and the per-source table for the
// shared-source analysis. It is not part of the JSON; a report read back from
// JSON compares without them.
type detail struct {
	// Ascending values of the sampled sessions. Lengths are in microseconds.
	durAll, durLoggedIn, depth, distinct []int64
	// sources is ascending by key and holds at most Options.SourceLimit
	// entries: the ones with the smallest keys.
	sources     []sourceEntry
	sourcesOver bool
}

// detailBuilder collects the detail of a report while its sessions are
// walked.
type detailBuilder struct {
	a                                     *Aggregator
	durAll, durLoggedIn, depth, distinct  *sampler
	keys                                  []groupKey // by source index; zero until asked for
	public                                []bool
	known                                 []bool
	bySource                              map[groupKey]*sourceStat
	sessions, withoutSource, fromReserved int64
}

func newDetailBuilder(a *Aggregator) *detailBuilder {
	n := len(a.srcNames) + 1
	return &detailBuilder{
		a:      a,
		durAll: newSampler(a.opt.SampleLimit), durLoggedIn: newSampler(a.opt.SampleLimit),
		depth: newSampler(a.opt.SampleLimit), distinct: newSampler(a.opt.SampleLimit),
		keys: make([]groupKey, n), public: make([]bool, n), known: make([]bool, n),
		bySource: make(map[groupKey]*sourceStat),
	}
}

// add counts one session: run seg of the group under key.
func (b *detailBuilder) add(key groupKey, seg int, s *session) {
	sk := sampleKeyOf(key, seg)
	length := sessionLength(s)
	b.durAll.add(sk, length)
	if s.loggedIn {
		b.durLoggedIn.add(sk, length)
	}
	if s.commands > 0 {
		b.depth.add(sk, int64(s.commands))
		b.distinct.add(sk, int64(len(s.cmds)))
	}

	b.sessions++
	if s.src == 0 {
		b.withoutSource++
		return
	}
	if !b.known[s.src] {
		text, public := sourceKeyOf(b.a.srcNames[s.src-1])
		b.keys[s.src], b.public[s.src], b.known[s.src] = b.a.digest("source-key", text), public, true
	}
	if !b.public[s.src] {
		b.fromReserved++
	}
	st := b.bySource[b.keys[s.src]]
	if st == nil {
		st = &sourceStat{public: b.public[s.src]}
		b.bySource[b.keys[s.src]] = st
	}
	st.add(s)
}

// SourceSummary describes the source addresses of a report. A source is an
// IPv4 address or an IPv6 /64.
type SourceSummary struct {
	// Sources is the number of distinct sources.
	Sources int64 `json:"sources"`
	// Public of them could name a visitor on the internet; Reserved are
	// private, loopback, link-local or otherwise reserved addresses, or text
	// that is not an address.
	Public   int64 `json:"public_sources"`
	Reserved int64 `json:"reserved_sources"`
	// SessionsWithoutSource had no source address at all.
	SessionsWithoutSource int64 `json:"sessions_without_source"`
	// SessionsFromReserved came from a reserved source.
	SessionsFromReserved int64 `json:"sessions_from_reserved_sources"`
	// BusiestSessions is the number of sessions of the source with the most,
	// and BusiestPercent its share of all sessions.
	BusiestSessions int64   `json:"busiest_source_sessions"`
	BusiestPercent  float64 `json:"busiest_source_percent"`
	// Collapsed is true when one source, or the reserved sources together,
	// carry more than CollapsedShare percent of the sessions: the logged
	// source is then probably a gateway or proxy, not the visitor.
	Collapsed bool `json:"collapsed"`
	// CollapsedReason says which of the two it was.
	CollapsedReason string `json:"collapsed_reason,omitempty"`
}

// finish returns the summary of the sources and the detail kept for Compare.
func (b *detailBuilder) finish() (SourceSummary, *detail) {
	sum := SourceSummary{
		Sources:               int64(len(b.bySource)),
		SessionsWithoutSource: b.withoutSource,
		SessionsFromReserved:  b.fromReserved,
	}
	entries := make([]sourceEntry, 0, len(b.bySource))
	for key, st := range b.bySource {
		if st.public {
			sum.Public++
		} else {
			sum.Reserved++
		}
		sum.BusiestSessions = max(sum.BusiestSessions, st.sessions)
		entries = append(entries, sourceEntry{key: key, sourceStat: *st})
	}
	sum.BusiestPercent = percent(sum.BusiestSessions, b.sessions)
	switch {
	case float64(sum.BusiestSessions)*100 > CollapsedShare*float64(b.sessions):
		sum.Collapsed = true
		sum.CollapsedReason = fmt.Sprintf("one source address carries %d of %d sessions (%.1f%%, limit %.0f%%)",
			sum.BusiestSessions, b.sessions, float64(sum.BusiestSessions)*100/float64(b.sessions), CollapsedShare)
	case float64(b.fromReserved)*100 > CollapsedShare*float64(b.sessions):
		sum.Collapsed = true
		sum.CollapsedReason = fmt.Sprintf("private and reserved addresses carry %d of %d sessions (%.1f%%, limit %.0f%%)",
			b.fromReserved, b.sessions, float64(b.fromReserved)*100/float64(b.sessions), CollapsedShare)
	}

	sort.Slice(entries, func(i, j int) bool { return lessGroupKey(entries[i].key, entries[j].key) })
	d := &detail{
		durAll: b.durAll.values(), durLoggedIn: b.durLoggedIn.values(),
		depth: b.depth.values(), distinct: b.distinct.values(),
	}
	if limit := b.a.opt.SourceLimit; len(entries) > limit {
		entries = append([]sourceEntry(nil), entries[:limit]...)
		d.sourcesOver = true
	}
	if len(entries) > 0 {
		d.sources = entries
	}
	return sum, d
}

// ArmExposure is the exposure one report had.
type ArmExposure struct {
	Label    string `json:"label"`
	Sessions int64  `json:"sessions"`
	// Sources and PublicSources count distinct source addresses, an IPv6
	// address by its /64.
	Sources       int64 `json:"sources"`
	PublicSources int64 `json:"public_sources"`
	// First and Last are the first and the last event used.
	First time.Time `json:"first_event,omitzero"`
	Last  time.Time `json:"last_event,omitzero"`
	// PeriodSeconds is Last minus First.
	PeriodSeconds float64 `json:"period_seconds"`
}

// Exposure says whether two reports saw comparable traffic. Compare fills it
// in before anything else; a difference between two reports means little when
// Comparable is false.
type Exposure struct {
	A ArmExposure `json:"a"`
	B ArmExposure `json:"b"`
	// SessionRatio and SourceRatio are the larger count divided by the
	// smaller. Zero when one side has none.
	SessionRatio float64 `json:"session_ratio"`
	SourceRatio  float64 `json:"source_ratio"`
	// OverlapSeconds is the time both reports cover. OverlapPercent is its
	// share of the combined period, from the earlier first event to the
	// later last event.
	OverlapSeconds float64 `json:"period_overlap_seconds"`
	OverlapPercent float64 `json:"period_overlap_percent"`
	// SourcesKnown is false when a report carries no source table (it was
	// read back from JSON). The four fields after it are then empty.
	SourcesKnown bool `json:"sources_known"`
	// SharedSources is the number of public sources both reports saw, and
	// Jaccard that number divided by the number either saw.
	SharedSources int64   `json:"shared_sources"`
	Jaccard       float64 `json:"source_jaccard"`
	// SourcesSampled is true when a report had more sources than its limit.
	// SharedSources and Jaccard then cover the same fixed part of the
	// address space on both sides, with ComparedA and ComparedB public
	// sources in it.
	SourcesSampled bool  `json:"sources_sampled"`
	ComparedA      int64 `json:"compared_public_sources_a"`
	ComparedB      int64 `json:"compared_public_sources_b"`
	// Comparable is false when a threshold was missed; Problems says which.
	Comparable bool     `json:"comparable"`
	Problems   []string `json:"problems,omitempty"`
}

// PairedMeasure is one way of asking, for every shared source, on which side
// it went further.
type PairedMeasure struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	// AFurther, BFurther and Tied count the shared sources.
	AFurther int64 `json:"a_further"`
	BFurther int64 `json:"b_further"`
	Tied     int64 `json:"tied"`
	// PValue is the exact two-sided sign test on AFurther against BFurther
	// (for a yes/no measure, the exact McNemar test). PAdjusted is the value
	// after Holm's correction over the measures.
	PValue    float64 `json:"p_value"`
	PAdjusted float64 `json:"p_adjusted"`
	// Verdict is VerdictClear or VerdictNone.
	Verdict string `json:"verdict"`
}

// Paired is the analysis of the sources both reports saw. Each such source
// met both deployments, so it is its own control.
type Paired struct {
	// Shared is the number of public sources seen by both reports.
	Shared int64 `json:"shared_sources"`
	// Skipped is true when the measures were not computed; Reason says why.
	Skipped bool   `json:"skipped"`
	Reason  string `json:"reason,omitempty"`
	// Sampled is true when a report had more sources than its limit: the
	// shared sources are then the ones in a fixed part of the address space.
	Sampled  bool            `json:"sampled"`
	Measures []PairedMeasure `json:"measures,omitempty"`
}

// pairedDefs are the measures of the shared-source analysis: the key, the
// name, and how far one source went by that measure.
var pairedDefs = []struct {
	key, name string
	reach     func(st *sourceStat) int64
}{
	{"logged_in", "Logged in", func(st *sourceStat) int64 { return boolReach(st.loggedIn) }},
	{"ran_command", "Ran a command", func(st *sourceStat) int64 { return boolReach(st.command) }},
	{"payload", "Fetched or uploaded a payload", func(st *sourceStat) int64 { return boolReach(st.payload) }},
	{"max_commands", "Most commands in one session", func(st *sourceStat) int64 { return int64(st.maxCommands) }},
	{"longest_session", "Longest session", func(st *sourceStat) int64 { return st.longest }},
}

func boolReach(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// periodSeconds is the length of a window in seconds.
func periodSeconds(w Window) float64 {
	if w.First.IsZero() || w.Last.Before(w.First) {
		return 0
	}
	return round(w.Last.Sub(w.First).Seconds(), 3)
}

// ratio is the larger of two counts divided by the smaller; zero when either
// is zero.
func ratio(x, y int64) float64 {
	if x <= 0 || y <= 0 {
		return 0
	}
	return round(float64(max(x, y))/float64(min(x, y)), 2)
}

// exposureOf compares the exposure of two reports and analyses the sources
// they share.
func exposureOf(a, b *Report) (Exposure, Paired) {
	arm := func(r *Report) ArmExposure {
		return ArmExposure{
			Label: r.Label, Sessions: r.Overall.Sessions,
			Sources: r.Sources.Sources, PublicSources: r.Sources.Public,
			First: r.Window.First, Last: r.Window.Last, PeriodSeconds: periodSeconds(r.Window),
		}
	}
	e := Exposure{A: arm(a), B: arm(b), Comparable: true}
	problem := func(format string, args ...any) {
		e.Comparable = false
		e.Problems = append(e.Problems, fmt.Sprintf(format, args...))
	}

	e.SessionRatio = ratio(e.A.Sessions, e.B.Sessions)
	e.SourceRatio = ratio(e.A.Sources, e.B.Sources)
	more, fewer := a, b
	if b.Overall.Sessions > a.Overall.Sessions {
		more, fewer = b, a
	}
	switch {
	case fewer.Overall.Sessions == 0:
		problem("%s has no sessions.", fewer.Label)
	case e.SessionRatio > MaxSessionRatio:
		problem("%s has %.1f times the sessions of %s (limit %.0f).",
			more.Label, e.SessionRatio, fewer.Label, MaxSessionRatio)
	}

	if !a.Window.First.IsZero() && !b.Window.First.IsZero() {
		start, end := a.Window.First, a.Window.Last
		if b.Window.First.After(start) {
			start = b.Window.First
		}
		if b.Window.Last.Before(end) {
			end = b.Window.Last
		}
		from, to := a.Window.First, a.Window.Last
		if b.Window.First.Before(from) {
			from = b.Window.First
		}
		if b.Window.Last.After(to) {
			to = b.Window.Last
		}
		if both := end.Sub(start); both >= 0 {
			e.OverlapSeconds = round(both.Seconds(), 3)
			if combined := to.Sub(from); combined > 0 {
				e.OverlapPercent = round(float64(both)*100/float64(combined), 2)
			} else {
				e.OverlapPercent = 100 // both cover the same single instant
			}
		}
	}
	if e.A.Sessions > 0 && e.B.Sessions > 0 && e.OverlapPercent < MinPeriodOverlap {
		problem("The two periods share %.1f%% of the combined period (at least %.0f%% is needed).",
			e.OverlapPercent, MinPeriodOverlap)
	}

	var p Paired
	if a.detail == nil || b.detail == nil {
		p.Skipped = true
		p.Reason = "A report carries no source table: it was not computed in this run."
		return e, p
	}
	e.SourcesKnown = true
	pairs := sharedSources(a.detail, b.detail, &e)
	p.Shared, p.Sampled = e.SharedSources, e.SourcesSampled
	switch {
	case a.Sources.Collapsed:
		p.Skipped = true
		p.Reason = fmt.Sprintf("In %s %s. Its source addresses may be a gateway or proxy, not the visitors.", a.Label, a.Sources.CollapsedReason)
	case b.Sources.Collapsed:
		p.Skipped = true
		p.Reason = fmt.Sprintf("In %s %s. Its source addresses may be a gateway or proxy, not the visitors.", b.Label, b.Sources.CollapsedReason)
	case len(pairs) == 0:
		p.Skipped = true
		p.Reason = "No public source address was seen by both."
	}
	if p.Skipped {
		return e, p
	}

	raw := make([]float64, len(pairedDefs))
	p.Measures = make([]PairedMeasure, len(pairedDefs))
	for i, def := range pairedDefs {
		m := PairedMeasure{Key: def.key, Name: def.name}
		for _, pair := range pairs {
			x, y := def.reach(pair[0]), def.reach(pair[1])
			switch {
			case x > y:
				m.AFurther++
			case y > x:
				m.BFurther++
			default:
				m.Tied++
			}
		}
		m.PValue = signTest(m.AFurther, m.BFurther)
		raw[i] = m.PValue
		p.Measures[i] = m
	}
	for i, adj := range holm(raw) {
		p.Measures[i].PAdjusted = adj
		p.Measures[i].Verdict = verdictOf(adj)
	}
	return e, p
}

// sharedSources returns, for every public source in both tables, its entry in
// each, and writes the overlap figures into e. When a table was cut at its
// limit it holds the sources with the smallest keys, so both tables are
// compared up to the smaller of the cut-off keys: below it each is complete.
func sharedSources(a, b *detail, e *Exposure) [][2]*sourceStat {
	e.SourcesSampled = a.sourcesOver || b.sourcesOver
	bounded := false
	var bound groupKey
	for _, d := range []*detail{a, b} {
		if !d.sourcesOver || len(d.sources) == 0 {
			continue
		}
		last := d.sources[len(d.sources)-1].key
		if !bounded || lessGroupKey(last, bound) {
			bound, bounded = last, true
		}
	}
	inside := func(k groupKey) bool { return !bounded || !lessGroupKey(bound, k) }

	var pairs [][2]*sourceStat
	i, j := 0, 0
	for i < len(a.sources) || j < len(b.sources) {
		var x, y *sourceEntry
		switch {
		case j >= len(b.sources):
			x = &a.sources[i]
		case i >= len(a.sources):
			y = &b.sources[j]
		case lessGroupKey(a.sources[i].key, b.sources[j].key):
			x = &a.sources[i]
		case lessGroupKey(b.sources[j].key, a.sources[i].key):
			y = &b.sources[j]
		default:
			x, y = &a.sources[i], &b.sources[j]
		}
		if x != nil {
			i++
			if x.public && inside(x.key) {
				e.ComparedA++
			} else {
				x = nil
			}
		}
		if y != nil {
			j++
			if y.public && inside(y.key) {
				e.ComparedB++
			} else {
				y = nil
			}
		}
		if x != nil && y != nil {
			pairs = append(pairs, [2]*sourceStat{&x.sourceStat, &y.sourceStat})
		}
	}
	e.SharedSources = int64(len(pairs))
	if either := e.ComparedA + e.ComparedB - e.SharedSources; either > 0 {
		e.Jaccard = round(float64(e.SharedSources)/float64(either), 4)
	}
	return pairs
}
