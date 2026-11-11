package engagement

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// Direction says which way a metric is better for a deception honeypot.
type Direction string

const (
	// HigherIsBetter: more engagement or more intelligence.
	HigherIsBetter Direction = "higher"
	// LowerIsBetter: fewer visitors lost.
	LowerIsBetter Direction = "lower"
	// NoDirection: the value depends on exposure or volume, or on a single
	// session, and says nothing by itself.
	NoDirection Direction = "none"
)

// Definition names one metric of a report and its direction.
type Definition struct {
	Key    string    `json:"key"`
	Name   string    `json:"name"`
	Unit   string    `json:"unit"`
	Better Direction `json:"better"`
	// value returns the metric and whether it is defined (its base is not
	// empty).
	value func(m *Metrics) (float64, bool)
}

func count(get func(m *Metrics) int64) func(m *Metrics) (float64, bool) {
	return func(m *Metrics) (float64, bool) { return float64(get(m)), true }
}

func ofSessions(get func(m *Metrics) float64) func(m *Metrics) (float64, bool) {
	return func(m *Metrics) (float64, bool) { return get(m), m.Sessions > 0 }
}

func ofLoggedIn(get func(d *DurationStats) float64) func(m *Metrics) (float64, bool) {
	return func(m *Metrics) (float64, bool) {
		return get(&m.Duration.LoggedIn), m.Duration.LoggedIn.Sessions > 0
	}
}

func ofInteractive(get func(m *Metrics) float64) func(m *Metrics) (float64, bool) {
	return func(m *Metrics) (float64, bool) { return get(m), m.Depth.InteractiveSessions > 0 }
}

var definitions = []Definition{
	{"sessions", "Sessions", "count", NoDirection, count(func(m *Metrics) int64 { return m.Sessions })},
	{"login_attempted_pct", "Attempted a login", "%", NoDirection, ofSessions(func(m *Metrics) float64 { return m.Funnel.LoginAttempted.Percent })},
	{"logged_in_pct", "Logged in", "%", HigherIsBetter, ofSessions(func(m *Metrics) float64 { return m.Funnel.LoggedIn.Percent })},
	{"interactive_pct", "Ran a command", "%", HigherIsBetter, ofSessions(func(m *Metrics) float64 { return m.Funnel.Interactive.Percent })},
	{"payload_pct", "Fetched or uploaded a payload", "%", HigherIsBetter, ofSessions(func(m *Metrics) float64 { return m.Funnel.Payload.Percent })},
	{"duration_logged_in_median_s", "Duration, logged in: median", "s", HigherIsBetter, ofLoggedIn(func(d *DurationStats) float64 { return d.MedianSeconds })},
	{"duration_logged_in_p90_s", "Duration, logged in: p90", "s", HigherIsBetter, ofLoggedIn(func(d *DurationStats) float64 { return d.P90Seconds })},
	{"duration_logged_in_max_s", "Duration, logged in: max", "s", NoDirection, ofLoggedIn(func(d *DurationStats) float64 { return d.MaxSeconds })},
	{"duration_logged_in_total_s", "Duration, logged in: total", "s", NoDirection, ofLoggedIn(func(d *DurationStats) float64 { return d.TotalSeconds })},
	{"duration_all_median_s", "Duration, all sessions: median", "s", HigherIsBetter, ofSessions(func(m *Metrics) float64 { return m.Duration.All.MedianSeconds })},
	{"duration_all_p90_s", "Duration, all sessions: p90", "s", HigherIsBetter, ofSessions(func(m *Metrics) float64 { return m.Duration.All.P90Seconds })},
	{"duration_all_max_s", "Duration, all sessions: max", "s", NoDirection, ofSessions(func(m *Metrics) float64 { return m.Duration.All.MaxSeconds })},
	{"duration_all_total_s", "Duration, all sessions: total", "s", NoDirection, ofSessions(func(m *Metrics) float64 { return m.Duration.All.TotalSeconds })},
	{"depth_median", "Commands per interactive session: median", "count", HigherIsBetter, ofInteractive(func(m *Metrics) float64 { return m.Depth.Median })},
	{"depth_p90", "Commands per interactive session: p90", "count", HigherIsBetter, ofInteractive(func(m *Metrics) float64 { return float64(m.Depth.P90) })},
	{"depth_max", "Commands per interactive session: max", "count", NoDirection, ofInteractive(func(m *Metrics) float64 { return float64(m.Depth.Max) })},
	{"distinct_commands", "Distinct commands", "count", NoDirection, count(func(m *Metrics) int64 { return m.Diversity.DistinctCommands })},
	{"distinct_per_session_median", "Distinct commands per interactive session: median", "count", HigherIsBetter, ofInteractive(func(m *Metrics) float64 { return m.Diversity.PerSessionMedian })},
	{"stem_entropy_bits", "Command stem entropy", "bits", HigherIsBetter, ofInteractive(func(m *Metrics) float64 { return m.Diversity.StemEntropyBits })},
	{"left_after_probe_pct", "Left after a probe", "%", LowerIsBetter, ofInteractive(func(m *Metrics) float64 { return m.LeftAfterProbe.Percent })},
	{"returning_sources_pct", "Returning sources", "%", HigherIsBetter, func(m *Metrics) (float64, bool) {
		return m.Returning.Percent, m.Returning.InteractiveSources > 0
	}},
	{"payload_hashes", "Payload hashes", "count", NoDirection, count(func(m *Metrics) int64 { return m.Intelligence.PayloadHashes.Count })},
	{"payload_hashes_per_1000", "Payload hashes per 1000 sessions", "per 1000", HigherIsBetter, ofSessions(func(m *Metrics) float64 { return m.Intelligence.PayloadHashes.Per1000 })},
	{"download_urls", "Download URLs", "count", NoDirection, count(func(m *Metrics) int64 { return m.Intelligence.DownloadURLs.Count })},
	{"download_urls_per_1000", "Download URLs per 1000 sessions", "per 1000", HigherIsBetter, ofSessions(func(m *Metrics) float64 { return m.Intelligence.DownloadURLs.Per1000 })},
	{"download_hosts", "Download hosts", "count", NoDirection, count(func(m *Metrics) int64 { return m.Intelligence.DownloadHosts.Count })},
	{"download_hosts_per_1000", "Download hosts per 1000 sessions", "per 1000", HigherIsBetter, ofSessions(func(m *Metrics) float64 { return m.Intelligence.DownloadHosts.Per1000 })},
	{"credential_pairs", "Credential pairs that logged in", "count", NoDirection, count(func(m *Metrics) int64 { return m.Intelligence.CredentialPairs.Count })},
	{"credential_pairs_per_1000", "Credential pairs per 1000 sessions", "per 1000", HigherIsBetter, ofSessions(func(m *Metrics) float64 { return m.Intelligence.CredentialPairs.Per1000 })},
	{"attack_techniques", "ATT&CK techniques", "count", NoDirection, count(func(m *Metrics) int64 { return m.Intelligence.Techniques.Count })},
	{"attack_techniques_per_1000", "ATT&CK techniques per 1000 sessions", "per 1000", HigherIsBetter, ofSessions(func(m *Metrics) float64 { return m.Intelligence.Techniques.Per1000 })},
}

// Definitions lists the metrics a comparison covers, in table order.
func Definitions() []Definition {
	return append([]Definition(nil), definitions...)
}

// Verdicts of a tested row.
const (
	// VerdictClear: the difference is larger than chance explains at the
	// 5% level, after Holm's correction over the tested rows.
	VerdictClear = "clear difference"
	// VerdictNone: chance alone could have produced a difference this large.
	// It does not mean the two sides are the same.
	VerdictNone = "no clear difference"
	// VerdictTooFew: a report has fewer than MinCompare sessions (or
	// sources) in the base of the row.
	VerdictTooFew = "too few to compare"
)

// Tests of a row.
const (
	// TestFisher is Fisher's exact test of two shares.
	TestFisher = "fisher-exact"
	// TestMannWhitney is the Mann-Whitney U test of two samples.
	TestMannWhitney = "mann-whitney"
)

func verdictOf(adjusted float64) string {
	if adjusted <= Alpha {
		return VerdictClear
	}
	return VerdictNone
}

// rowTest says how the uncertainty of one table row is worked out. A row
// without one (counts, totals, maxima, p90, entropy, rates per 1000 sessions)
// gets neither an interval nor a verdict.
type rowTest struct {
	// share returns the count and the base of a share row.
	share func(m *Metrics) (count, base int64)
	// sample returns the sampled values of a median row, and base its number
	// of sessions.
	sample func(d *detail) []int64
	base   func(m *Metrics) int64
	// verdict is false for a row without a direction: it gets intervals and
	// no test.
	verdict bool
}

var rowTests = map[string]rowTest{
	"login_attempted_pct": {share: func(m *Metrics) (int64, int64) { return m.Funnel.LoginAttempted.Count, m.Sessions }},
	"logged_in_pct":       {verdict: true, share: func(m *Metrics) (int64, int64) { return m.Funnel.LoggedIn.Count, m.Sessions }},
	"interactive_pct":     {verdict: true, share: func(m *Metrics) (int64, int64) { return m.Funnel.Interactive.Count, m.Sessions }},
	"payload_pct":         {verdict: true, share: func(m *Metrics) (int64, int64) { return m.Funnel.Payload.Count, m.Sessions }},
	"duration_logged_in_median_s": {
		verdict: true, sample: func(d *detail) []int64 { return d.durLoggedIn },
		base: func(m *Metrics) int64 { return m.Duration.LoggedIn.Sessions },
	},
	"duration_all_median_s": {
		verdict: true, sample: func(d *detail) []int64 { return d.durAll },
		base: func(m *Metrics) int64 { return m.Duration.All.Sessions },
	},
	"depth_median": {
		verdict: true, sample: func(d *detail) []int64 { return d.depth },
		base: func(m *Metrics) int64 { return m.Depth.InteractiveSessions },
	},
	"distinct_per_session_median": {
		verdict: true, sample: func(d *detail) []int64 { return d.distinct },
		base: func(m *Metrics) int64 { return m.Depth.InteractiveSessions },
	},
	"left_after_probe_pct": {verdict: true, share: func(m *Metrics) (int64, int64) {
		return m.LeftAfterProbe.Count, m.Depth.InteractiveSessions
	}},
	"returning_sources_pct": {verdict: true, share: func(m *Metrics) (int64, int64) {
		return m.Returning.Returned, m.Returning.InteractiveSources
	}},
}

// Range is a 95% interval of a difference.
type Range struct {
	Low  float64 `json:"low"`
	High float64 `json:"high"`
}

// Delta is one metric of two reports side by side.
type Delta struct {
	Key    string    `json:"key"`
	Name   string    `json:"name"`
	Unit   string    `json:"unit"`
	Better Direction `json:"better"`
	A      float64   `json:"a"`
	B      float64   `json:"b"`
	// Defined is false when the metric has no base in one of the reports
	// (no sessions, no interactive sessions, ...). Difference and Favours
	// are then empty.
	Defined bool `json:"defined"`
	// Difference is B minus A.
	Difference float64 `json:"difference"`
	// Favours is "a", "b" or "equal" by the metric's direction, and empty
	// for a metric without one. It compares the two figures as measured and
	// says nothing about chance; Verdict does.
	Favours string `json:"favours,omitempty"`

	// AInterval and BInterval are the 95% intervals of A and B, for a share
	// or a median with a large enough base.
	AInterval *Interval `json:"a_interval,omitempty"`
	BInterval *Interval `json:"b_interval,omitempty"`
	// DifferenceInterval is the 95% interval of B minus A in percentage
	// points, for a share: Newcombe's hybrid score interval.
	DifferenceInterval *Range `json:"difference_interval,omitempty"`
	// AN and BN are the sizes of the base of the row in A and B, for a row
	// with a test or an interval.
	AN int64 `json:"a_n,omitempty"`
	BN int64 `json:"b_n,omitempty"`
	// Test is TestFisher or TestMannWhitney when the row was tested.
	Test string `json:"test,omitempty"`
	// ASample and BSample are the sessions the rank test used. They are
	// smaller than AN and BN when a report reached its sample limit.
	ASample int64 `json:"a_sample,omitempty"`
	BSample int64 `json:"b_sample,omitempty"`
	// BLarger is, for a rank test, the chance that a session drawn from B
	// has a larger value than one drawn from A, a tie counting as half.
	// 0.5 means neither side tends to be larger.
	BLarger *float64 `json:"b_larger_probability,omitempty"`
	// PValue is the two-sided p-value of the test, and PAdjusted the value
	// after Holm's correction over the tested rows of the comparison.
	PValue    *float64 `json:"p_value,omitempty"`
	PAdjusted *float64 `json:"p_adjusted,omitempty"`
	// Verdict is VerdictClear, VerdictNone or VerdictTooFew, and empty for
	// a row that is not tested.
	Verdict string `json:"verdict,omitempty"`
}

// Comparison holds every metric of two reports side by side, with what is
// needed to judge the differences.
type Comparison struct {
	A string `json:"a"`
	B string `json:"b"`
	// Exposure says whether the two reports saw comparable traffic.
	Exposure Exposure `json:"exposure"`
	Deltas   []Delta  `json:"deltas"`
	// TestedRows is the number of rows Holm's correction was applied over.
	TestedRows int `json:"tested_rows"`
	// Paired analyses the sources both reports saw.
	Paired Paired `json:"paired"`
	// Notes say what limits the reading of this comparison.
	Notes []string `json:"notes,omitempty"`
}

// Compare sets the overall metrics of two reports side by side: A is the
// first, B the second, and every difference is B minus A.
//
// It checks first whether the two had comparable exposure. Shares get a 95%
// interval for the difference and Fisher's exact test; medians get the
// Mann-Whitney U test on the per-session samples the reports carry. The
// p-values of all tested rows are corrected together by Holm's method, and
// each row is marked VerdictClear or VerdictNone at Alpha. A row with fewer
// than MinCompare sessions in either report is marked VerdictTooFew. The
// sources both reports saw are analysed as pairs.
//
// A verdict says whether chance explains a difference. Whether the
// difference is caused by the deployments depends on how the two were
// exposed (see doc/effectiveness.md).
func Compare(a, b Report) Comparison {
	c := Comparison{A: a.Label, B: b.Label, Deltas: make([]Delta, 0, len(definitions))}
	c.Exposure, c.Paired = exposureOf(&a, &b)

	var tested []int
	var raw []float64
	noSamples := false
	for _, def := range definitions {
		av, aok := def.value(&a.Overall)
		bv, bok := def.value(&b.Overall)
		d := Delta{Key: def.Key, Name: def.Name, Unit: def.Unit, Better: def.Better, A: av, B: bv, Defined: aok && bok}
		if d.Defined {
			d.Difference = round(bv-av, 4)
			switch {
			case def.Better == NoDirection:
			case d.Difference == 0:
				d.Favours = "equal"
			case (d.Difference > 0) == (def.Better == HigherIsBetter):
				d.Favours = "b"
			default:
				d.Favours = "a"
			}
		}
		if iv := a.Overall.interval(def.Key); iv != nil {
			copied := *iv
			d.AInterval = &copied
		}
		if iv := b.Overall.interval(def.Key); iv != nil {
			copied := *iv
			d.BInterval = &copied
		}

		rt, ok := rowTests[def.Key]
		switch {
		case !ok:
		case rt.share != nil:
			ka, na := rt.share(&a.Overall)
			kb, nb := rt.share(&b.Overall)
			d.AN, d.BN = na, nb
			if lo, hi, ok := newcombe(ka, na, kb, nb); ok {
				d.DifferenceInterval = &Range{Low: round(lo*100, 2), High: round(hi*100, 2)}
			}
			switch {
			case !rt.verdict:
			case na < MinCompare || nb < MinCompare:
				d.Verdict = VerdictTooFew
			default:
				d.Test = TestFisher
				p := fisherExact(ka, na, kb, nb)
				d.PValue = &p
				tested, raw = append(tested, len(c.Deltas)), append(raw, p)
			}
		default:
			d.AN, d.BN = rt.base(&a.Overall), rt.base(&b.Overall)
			switch {
			case d.AN < MinCompare || d.BN < MinCompare:
				d.Verdict = VerdictTooFew
			case a.detail == nil || b.detail == nil:
				noSamples = true
			default:
				sa, sb := rt.sample(a.detail), rt.sample(b.detail)
				if len(sa) == 0 || len(sb) == 0 {
					noSamples = true
					break
				}
				d.Test = TestMannWhitney
				d.ASample, d.BSample = int64(len(sa)), int64(len(sb))
				p, larger := mannWhitney(sa, sb)
				larger = round(larger, 4)
				d.PValue, d.BLarger = &p, &larger
				tested, raw = append(tested, len(c.Deltas)), append(raw, p)
			}
		}
		c.Deltas = append(c.Deltas, d)
	}
	c.TestedRows = len(tested)
	for i, adj := range holm(raw) {
		d := &c.Deltas[tested[i]]
		d.PAdjusted = &adj
		d.Verdict = verdictOf(adj)
	}

	if !c.Exposure.Comparable {
		c.Notes = append(c.Notes, "The exposure check failed. The differences describe two deployments that did not see comparable traffic; they do not measure the deployments.")
	}
	if noSamples {
		c.Notes = append(c.Notes, "A report carries no per-session samples (it was not computed in this run): the median rows were not tested.")
	}
	for _, r := range []*Report{&a, &b} {
		if r.Limits.SampleReached {
			c.Notes = append(c.Notes, fmt.Sprintf("%s has more than %d sessions: its rank tests use a fixed sample of at most that many sessions per row.", r.Label, r.Limits.Sample))
		}
		if r.Limits.PairedSourcesReached {
			c.Notes = append(c.Notes, fmt.Sprintf("%s has more than %d source addresses: the source overlap and the shared-source analysis cover the same fixed part of the address space on both sides.", r.Label, r.Limits.PairedSources))
		}
		if r.Sources.Collapsed {
			c.Notes = append(c.Notes, fmt.Sprintf("In %s %s: its returning sources row says nothing about visitors.", r.Label, r.Sources.CollapsedReason))
		}
	}
	return c
}

// formatValue prints a metric value in its unit.
func formatValue(v float64, unit string) string {
	switch unit {
	case "count":
		return strconv.FormatFloat(v, 'f', -1, 64)
	case "%":
		return strconv.FormatFloat(v, 'f', 1, 64) + "%"
	case "s":
		return strconv.FormatFloat(v, 'f', 1, 64) + "s"
	}
	return strconv.FormatFloat(v, 'f', 2, 64)
}

// formatInterval prints a 95% interval in the unit of its metric.
func formatInterval(iv *Interval, unit string) string {
	if iv == nil {
		return "-"
	}
	digits, suffix := 1, unit
	if unit == "count" {
		digits, suffix = -1, ""
	}
	return strconv.FormatFloat(iv.Low, 'f', digits, 64) + " to " + strconv.FormatFloat(iv.High, 'f', digits, 64) + suffix
}

// formatP prints a p-value.
func formatP(p float64) string {
	if p < 0.001 {
		return "<0.001"
	}
	return strconv.FormatFloat(p, 'f', 3, 64)
}

const timeLayout = "2006-01-02 15:04:05Z"

// textWidth is the width the sentences under the tables are wrapped to.
const textWidth = 96

// writeWrapped prints text as lines of at most textWidth columns, each after
// indent. A word longer than a line gets a line of its own.
func writeWrapped(w io.Writer, indent, text string) {
	line := indent
	for _, word := range strings.Fields(text) {
		switch {
		case line == indent:
			line += word
		case len(line)+1+len(word) > textWidth:
			fmt.Fprintln(w, line)
			line = indent + word
		default:
			line += " " + word
		}
	}
	if line != indent {
		fmt.Fprintln(w, line)
	}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format(timeLayout)
}

// WriteText prints the reports as a plain table, one column per report. With
// exactly two reports the table has the difference (second minus first).
//
// With more than one report it compares the first with each of the others:
// an exposure check before the table, and after it the 95% intervals, the
// tested differences with their verdicts, and the analysis of the sources
// both saw.
func WriteText(w io.Writer, reports []*Report) error {
	if len(reports) == 0 {
		return nil
	}
	var comparisons []Comparison
	for _, other := range reports[1:] {
		comparisons = append(comparisons, Compare(*reports[0], *other))
	}
	for i := range comparisons {
		if err := writeExposure(w, &comparisons[i]); err != nil {
			return err
		}
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	header := []string{"METRIC"}
	for _, r := range reports {
		header = append(header, strings.ToUpper(r.Label))
	}
	if len(reports) == 2 {
		header = append(header, "DIFFERENCE")
	}
	header = append(header, "BETTER")
	fmt.Fprintln(tw, strings.Join(header, "\t"))
	for _, def := range definitions {
		row := []string{def.Name}
		values := make([]float64, len(reports))
		defined := true
		for i, r := range reports {
			v, ok := def.value(&r.Overall)
			values[i] = v
			defined = defined && ok
			if ok {
				row = append(row, formatValue(v, def.Unit))
			} else {
				row = append(row, "-")
			}
		}
		if len(reports) == 2 {
			diff := "-"
			if defined {
				diff = formatValue(values[1]-values[0], def.Unit)
				if values[1] > values[0] {
					diff = "+" + diff
				}
			}
			row = append(row, diff)
		}
		better := "-"
		if def.Better != NoDirection {
			better = string(def.Better)
		}
		row = append(row, better)
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if err := writeIntervals(w, reports); err != nil {
		return err
	}
	for i := range comparisons {
		if err := writeDifferences(w, &comparisons[i]); err != nil {
			return err
		}
		if err := writePaired(w, &comparisons[i]); err != nil {
			return err
		}
	}

	for _, r := range reports {
		fmt.Fprintf(w, "\n%s\n", r.Label)
		fmt.Fprintf(w, "  Events: %d read, %d used", r.Input.Events, r.Input.Used)
		if !r.Window.First.IsZero() {
			fmt.Fprintf(w, ", from %s to %s", r.Window.First.Format(timeLayout), r.Window.Last.Format(timeLayout))
		}
		fmt.Fprintln(w)
		if l := r.Input.Log; l != nil {
			fmt.Fprintf(w, "  Log lines: %d read, %d malformed, %d too long, %d outside the time window\n", l.Lines, l.Malformed, l.Oversized, l.OutsideWindow)
		}
		if dropped := r.Input.WithoutTime + r.Input.WithoutSessionKey; dropped > 0 {
			fmt.Fprintf(w, "  Events not used: %d without a time, %d without a session id or source address\n", r.Input.WithoutTime, r.Input.WithoutSessionKey)
		}
		if n := r.Overall.Duration.Reported; n > 0 {
			fmt.Fprintf(w, "  Duration stated by the honeypot for %d of %d sessions\n", n, r.Overall.Sessions)
		}
		if s := r.Sources; s.Sources > 0 {
			fmt.Fprintf(w, "  Source addresses: %d, of them %d public; the busiest has %.1f%% of the sessions\n", s.Sources, s.Public, s.BusiestPercent)
			if s.Collapsed {
				fmt.Fprintf(w, "  Sources may have collapsed: %s\n", s.CollapsedReason)
			}
		}
		if len(r.Overall.TopStems) > 0 {
			parts := make([]string, 0, len(r.Overall.TopStems))
			for _, s := range r.Overall.TopStems {
				parts = append(parts, fmt.Sprintf("%s (%d)", s.Stem, s.Count))
			}
			fmt.Fprintf(w, "  Top command stems: %s\n", strings.Join(parts, ", "))
		}
		if len(r.Honeypots) > 1 {
			fmt.Fprintln(w, "  Per honeypot:")
			hw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
			fmt.Fprintln(hw, "    HONEYPOT\tSESSIONS\tLOGGED IN\tRAN A COMMAND\tPAYLOAD\tMEDIAN DURATION\tMEDIAN COMMANDS\tLEFT AFTER A PROBE")
			for i := range r.Honeypots {
				h := &r.Honeypots[i]
				depth, left := "-", "-"
				if h.Depth.InteractiveSessions > 0 {
					depth = formatValue(h.Depth.Median, "count")
					left = formatValue(h.LeftAfterProbe.Percent, "%")
				}
				fmt.Fprintf(hw, "    %s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n", h.Honeypot, h.Sessions,
					formatValue(h.Funnel.LoggedIn.Percent, "%"), formatValue(h.Funnel.Interactive.Percent, "%"),
					formatValue(h.Funnel.Payload.Percent, "%"), formatValue(h.Duration.All.MedianSeconds, "s"), depth, left)
			}
			if err := hw.Flush(); err != nil {
				return err
			}
		}
		for _, n := range r.Notes {
			fmt.Fprintf(w, "  Note: %s\n", n)
		}
	}
	return nil
}

// writeExposure prints the exposure check of one comparison.
func writeExposure(w io.Writer, c *Comparison) error {
	e := &c.Exposure
	fmt.Fprintf(w, "Exposure check: A = %s, B = %s\n", c.A, c.B)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  \tA\tB")
	rate := func(r float64) string {
		if r == 0 {
			return ""
		}
		return "ratio " + strconv.FormatFloat(r, 'f', -1, 64)
	}
	period := func(sec float64) string {
		return time.Duration(sec * float64(time.Second)).Round(time.Second).String()
	}
	fmt.Fprintf(tw, "  Sessions\t%d\t%d\t%s\n", e.A.Sessions, e.B.Sessions, rate(e.SessionRatio))
	fmt.Fprintf(tw, "  Source addresses\t%d\t%d\t%s\n", e.A.Sources, e.B.Sources, rate(e.SourceRatio))
	fmt.Fprintf(tw, "  Public source addresses\t%d\t%d\n", e.A.PublicSources, e.B.PublicSources)
	fmt.Fprintf(tw, "  First event\t%s\t%s\n", formatTime(e.A.First), formatTime(e.B.First))
	fmt.Fprintf(tw, "  Last event\t%s\t%s\n", formatTime(e.A.Last), formatTime(e.B.Last))
	fmt.Fprintf(tw, "  Period\t%s\t%s\n", period(e.A.PeriodSeconds), period(e.B.PeriodSeconds))
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "  Both periods cover %s: %.1f%% of the combined period.\n", period(e.OverlapSeconds), e.OverlapPercent)
	if e.SourcesKnown {
		sampled := ""
		if e.SourcesSampled {
			sampled = ", in the sampled part of the address space"
		}
		writeWrapped(w, "  ", fmt.Sprintf("Public source addresses seen by both%s: %d of the %d seen by either (Jaccard index %.4f).",
			sampled, e.SharedSources, e.ComparedA+e.ComparedB-e.SharedSources, e.Jaccard))
	}
	if e.Comparable {
		writeWrapped(w, "  ", fmt.Sprintf("Passed: session ratio at most %.0f, period overlap at least %.0f%%. This does not show that the two had the same visitors.", MaxSessionRatio, MinPeriodOverlap))
	}
	for _, p := range e.Problems {
		writeWrapped(w, "  ", "NOT COMPARABLE: "+p)
	}
	if !e.Comparable {
		writeWrapped(w, "  ", "The numbers below are still printed. Read them as a description of each side, not as the effect of the deployment.")
	}
	fmt.Fprintln(w)
	return nil
}

// writeIntervals prints the 95% intervals of the shares and medians, one
// column per report.
func writeIntervals(w io.Writer, reports []*Report) error {
	var rows []string
	found := false
	for _, def := range definitions {
		if _, ok := rowTests[def.Key]; !ok {
			continue
		}
		row := []string{def.Name}
		for _, r := range reports {
			iv := r.Overall.interval(def.Key)
			found = found || iv != nil
			row = append(row, formatInterval(iv, def.Unit))
		}
		rows = append(rows, strings.Join(row, "\t"))
	}
	if !found {
		return nil
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	header := []string{"95% INTERVAL"}
	for _, r := range reports {
		header = append(header, strings.ToUpper(r.Label))
	}
	fmt.Fprintln(tw, strings.Join(header, "\t"))
	for _, row := range rows {
		fmt.Fprintln(tw, row)
	}
	return tw.Flush()
}

// writeDifferences prints the tested rows of one comparison.
func writeDifferences(w io.Writer, c *Comparison) error {
	fmt.Fprintf(w, "\nDifferences, B minus A: A = %s, B = %s\n", c.A, c.B)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "METRIC\tB MINUS A\tADJ. P\tVERDICT")
	for i := range c.Deltas {
		d := &c.Deltas[i]
		if _, ok := rowTests[d.Key]; !ok {
			continue
		}
		diff, p, verdict := "-", "-", "-"
		switch {
		case d.DifferenceInterval != nil:
			diff = fmt.Sprintf("%+.1f to %+.1f", d.DifferenceInterval.Low, d.DifferenceInterval.High)
		case d.BLarger != nil:
			diff = fmt.Sprintf("B>A %.1f%% of pairs", *d.BLarger*100)
		}
		if d.PAdjusted != nil {
			p = formatP(*d.PAdjusted)
		}
		if d.Verdict != "" {
			verdict = d.Verdict
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", d.Name, diff, p, verdict)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	writeWrapped(w, "  ", fmt.Sprintf("Verdicts are at the %.0f%% level after Holm's correction over the %d tested rows. A row needs %d sessions on each side.", Alpha*100, c.TestedRows, MinCompare))
	writeWrapped(w, "  ", "Shares: the 95% interval of B minus A, in percentage points.")
	writeWrapped(w, "  ", "Medians: of all pairs of one session from each side, the share where B has the larger value (a tie counts as half; 50% means neither side tends to be larger).")
	for _, n := range c.Notes {
		writeWrapped(w, "  ", "Note: "+n)
	}
	return nil
}

// writePaired prints the shared-source analysis of one comparison.
func writePaired(w io.Writer, c *Comparison) error {
	p := &c.Paired
	fmt.Fprintf(w, "\nShared sources: A = %s, B = %s\n", c.A, c.B)
	if c.Exposure.SourcesKnown {
		sampled := ""
		if p.Sampled {
			sampled = ", in the sampled part of the address space"
		}
		fmt.Fprintf(w, "  %d public source addresses were seen by both%s.\n", p.Shared, sampled)
	}
	if p.Skipped {
		writeWrapped(w, "  ", "Not analysed. "+p.Reason)
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "MEASURE\tA FURTHER\tB FURTHER\tTIED\tP\tADJ. P\tVERDICT")
	for _, m := range p.Measures {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%s\t%s\t%s\n", m.Name, m.AFurther, m.BFurther, m.Tied, formatP(m.PValue), formatP(m.PAdjusted), m.Verdict)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	writeWrapped(w, "  ", fmt.Sprintf("For each shared source: the side on which it went further. P is the exact two-sided sign test; verdicts are at the %.0f%% level after Holm's correction over the %d rows.", Alpha*100, len(p.Measures)))
	return nil
}
