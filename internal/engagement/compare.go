package engagement

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
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
	// for a metric without one.
	Favours string `json:"favours,omitempty"`
}

// Comparison holds every metric of two reports side by side.
type Comparison struct {
	A      string  `json:"a"`
	B      string  `json:"b"`
	Deltas []Delta `json:"deltas"`
}

// Compare sets the overall metrics of two reports side by side. It compares
// what was measured; whether the difference means anything depends on the
// two deployments having had the same exposure (see doc/effectiveness.md).
func Compare(a, b Report) Comparison {
	c := Comparison{A: a.Label, B: b.Label, Deltas: make([]Delta, 0, len(definitions))}
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
		c.Deltas = append(c.Deltas, d)
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

// WriteText prints the reports as a plain table, one column per report. With
// exactly two reports it adds the difference (second minus first).
func WriteText(w io.Writer, reports []*Report) error {
	if len(reports) == 0 {
		return nil
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

	for _, r := range reports {
		fmt.Fprintf(w, "\n%s\n", r.Label)
		fmt.Fprintf(w, "  Events: %d read, %d used", r.Input.Events, r.Input.Used)
		if !r.Window.First.IsZero() {
			fmt.Fprintf(w, ", from %s to %s", r.Window.First.Format("2006-01-02 15:04:05Z"), r.Window.Last.Format("2006-01-02 15:04:05Z"))
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
