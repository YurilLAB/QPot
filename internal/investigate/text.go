package investigate

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Clean returns s safe to print on a terminal or keep in a text file:
// everything a visitor could use to move the cursor, recolour the screen or
// reorder what is read comes out as a visible escape. A case is made of
// attacker input, and it is read in a terminal.
func Clean(s string) string {
	clean := true
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && n == 1) || unsafeRune(r) {
			clean = false
			break
		}
		i += n
	}
	if clean {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case unsafeRune(r):
			if r < 0x100 {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				fmt.Fprintf(&b, `\u{%x}`, r)
			}
		default:
			b.WriteRune(r)
		}
		i += n
	}
	return b.String()
}

// unsafeRune reports whether a rune may not reach a terminal as it is:
// control characters, and the format characters that hide or reorder text.
func unsafeRune(r rune) bool {
	return r < 0x20 || (r >= 0x7f && r < 0xa0) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04:05.000")
}

func refsText(refs []string, more int) string {
	if len(refs) == 0 {
		return ""
	}
	s := "[" + Clean(refs[0])
	if n := len(refs) - 1 + more; n > 0 {
		s += " +" + strconv.Itoa(n)
	}
	return s + "]"
}

// WriteListing prints a listing as text.
func WriteListing(w io.Writer, l *Listing) error {
	out := bufio.NewWriter(w)
	fmt.Fprintf(out, "Campaigns with more than one session: %d\n", len(l.Campaigns))
	for _, c := range l.Campaigns {
		fmt.Fprintf(out, "  %s  %d sessions  %d events  %s  last %s\n", Clean(c.Fingerprint), c.Sessions, c.Events,
			Clean(sourcesText(c.Sources, c.MoreSources)), stamp(c.LastSeen))
	}
	fmt.Fprintf(out, "\nSessions, most recent first: %d\n", len(l.Sessions))
	for _, s := range l.Sessions {
		campaign := ""
		if s.CampaignSessions > 1 {
			campaign = fmt.Sprintf("  campaign of %d", s.CampaignSessions)
		}
		fmt.Fprintf(out, "  %s  %s  %d events  %s → %s%s\n", Clean(s.SessionID), Clean(sourcesText(s.Sources, s.MoreSources)),
			s.Events, stamp(s.FirstSeen), stamp(s.LastSeen), campaign)
	}
	if l.More {
		fmt.Fprintf(out, "\nOnly the %d most recent sessions were looked through.\n", l.Scanned)
	}
	fmt.Fprintln(out, "\nOpen one with: qpot investigate session <session-id>   or   qpot investigate campaign <fingerprint>")
	return out.Flush()
}

func sourcesText(sources []string, more int) string {
	if len(sources) == 0 {
		return "(no source address)"
	}
	s := strings.Join(sources, ", ")
	if more > 0 {
		s += fmt.Sprintf(" and %d more", more)
	}
	return s
}

// WriteText prints a case as text: the summary, each session's timeline with
// captured output, the files, the links, the related sessions and the gaps.
// Every line that states something ends with the record it rests on.
func WriteText(w io.Writer, c *Case) error {
	out := bufio.NewWriter(w)
	s := c.Summary
	fmt.Fprintf(out, "%s %s\n", strings.ToUpper(c.Kind[:1])+c.Kind[1:], Clean(c.ID))
	if c.Instance != "" {
		fmt.Fprintf(out, "  Instance    %s\n", Clean(c.Instance))
	}
	fmt.Fprintf(out, "  Generated   %s UTC\n", stamp(c.Generated))
	if c.Kind == "session" {
		fmt.Fprintf(out, "  Campaign    %s\n", Clean(s.Campaign))
	} else {
		fmt.Fprintf(out, "  Sessions    %d\n", s.Sessions)
	}
	fmt.Fprintf(out, "  Sources     %s\n", Clean(sourcesText(s.Sources, s.MoreSources)))
	fmt.Fprintf(out, "  Seen        %s → %s UTC (%s)\n", stamp(s.FirstSeen), stamp(s.LastSeen), s.LastSeen.Sub(s.FirstSeen).Round(time.Second))
	fmt.Fprintf(out, "  Events      %d counted, %d read\n", s.Events, s.EventsRead)
	fmt.Fprintf(out, "  Honeypots   %s\n", Clean(strings.Join(s.Honeypots, ", ")))
	fmt.Fprintf(out, "  Reached     %s\n", orDash(strings.Join(s.Reached, " → ")))
	fmt.Fprintf(out, "  Techniques  %s\n", orDash(Clean(strings.Join(s.Techniques, ", "))))
	fmt.Fprintf(out, "  Confidence  %.0f %%\n", s.Confidence*100)

	for _, sc := range c.Sessions {
		fmt.Fprintf(out, "\nTimeline of session %s (%d events read)\n", Clean(sc.Session.SessionID), sc.EventsRead)
		if len(sc.Timeline) == 0 {
			fmt.Fprintln(out, "  (nothing to show)")
		}
		for _, st := range sc.Timeline {
			count := ""
			// A folded run of logins says how many in its summary.
			if st.Count > 1 && st.Phase != PhaseCredentials {
				count = fmt.Sprintf(" ×%d", st.Count)
			}
			fmt.Fprintf(out, "  %s  %-11s %-14s %s%s  %s\n", stamp(st.At), st.Phase, Clean(cut(st.Honeypot, 14)), Clean(st.Summary), count, refsText(st.Refs, st.MoreRefs))
			if st.Phase == PhaseCommand && st.Outcome != "" {
				fmt.Fprintf(out, "      %s\n", Clean(st.Outcome))
			}
			if st.ExitCode != nil {
				fmt.Fprintf(out, "      exit code %d\n", *st.ExitCode)
			}
			if st.CausedBy != "" {
				fmt.Fprintf(out, "      follows the command in [%s]: %s\n", Clean(st.CausedBy), Clean(st.Because))
			}
			if o := st.Output; o != nil {
				writeStream(out, "output", o.Stdout)
				writeStream(out, "errors", o.Stderr)
				if o.Cut {
					fmt.Fprintln(out, "      (the output is cut)")
				}
			}
		}
		if len(sc.Files) > 0 {
			fmt.Fprintln(out, "\n  Files")
			for _, f := range sc.Files {
				name := f.SHA256
				switch {
				case f.Empty:
					name = "(empty file)"
				case name == "":
					name = "(no hash recorded)"
				}
				fmt.Fprintf(out, "    %s  %d transfers  %s\n", Clean(name), f.Transfers, refsText(f.Refs, 0))
				for _, u := range f.URLs {
					fmt.Fprintf(out, "      from %s\n", Clean(u))
				}
				for _, n := range f.Names {
					fmt.Fprintf(out, "      as %s\n", Clean(n))
				}
				for _, cmd := range f.Commands {
					fmt.Fprintf(out, "      by the command in [%s]\n", Clean(cmd))
				}
			}
		}
		if len(sc.Evidence) > 0 {
			fmt.Fprintln(out, "\n  Campaign evidence in this session")
			for _, ev := range sc.Evidence {
				shared := ""
				if ev.Shared {
					shared = "  (shared)"
				}
				fmt.Fprintf(out, "    %-16s %s%s  %s\n", ev.Kind, Clean(cut(oneLineSep(ev.Value), maxSummary)), shared, refsText(ev.Refs, 0))
			}
		}
	}

	if len(c.Links) > 0 {
		fmt.Fprintln(out, "\nWhy these sessions are one campaign")
		for _, l := range c.Links {
			fmt.Fprintf(out, "  %s: %s\n", l.Kind, Clean(cut(oneLineSep(l.Value), maxSummary)))
			for _, side := range l.Sessions {
				fmt.Fprintf(out, "    session %s at %s  %s\n", Clean(side.SessionID), stamp(side.At), refsText(side.Refs, 0))
			}
		}
	}
	if len(c.Trips) > 0 {
		fmt.Fprintln(out, "\nCanary trips by this source")
		for _, t := range c.Trips {
			where := "at another time"
			if t.SessionID != "" {
				where = "in session " + Clean(t.SessionID)
			}
			fmt.Fprintf(out, "  %s  %s (%s) over %s, %s  [trip:%s]\n", stamp(t.Time), Clean(t.Name), Clean(t.Kind), Clean(t.Channel), where, Clean(t.ID))
		}
	}
	if len(c.Related) > 0 {
		fmt.Fprintln(out, "\nRelated sessions")
		for _, r := range c.Related {
			fmt.Fprintf(out, "  %-22s %s  %s  %d events  %s\n", r.Relation, Clean(r.SessionID), Clean(sourcesText(r.Sources, 0)), r.EventCount, stamp(r.FirstSeen))
		}
	}
	fmt.Fprintln(out, "\nGaps")
	if len(c.Gaps) == 0 {
		fmt.Fprintln(out, "  None found: nothing read for this case was cut, discarded or left out.")
	}
	for _, g := range c.Gaps {
		where := ""
		if g.SessionID != "" && len(c.Sessions) > 1 {
			where = " (session " + Clean(g.SessionID) + ")"
		}
		fmt.Fprintf(out, "  %s%s: %s  %s\n", g.Kind, where, Clean(g.Detail), refsText(g.Refs, max(0, g.Count-len(g.Refs))))
	}
	fmt.Fprintf(out, "\n%d records support this case. A name in [brackets] is a record's reference.\n", len(c.Records))
	return out.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// oneLineSep shows a value of several lines (a command sequence) on one.
func oneLineSep(s string) string { return strings.ReplaceAll(s, "\n", " ; ") }

// writeStream prints captured output, each line cleaned and indented.
func writeStream(out *bufio.Writer, label, text string) {
	if text == "" {
		return
	}
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	const most = 40
	fmt.Fprintf(out, "      %s:\n", label)
	for i, line := range lines {
		if i == most {
			fmt.Fprintf(out, "        … %d more lines\n", len(lines)-most)
			break
		}
		fmt.Fprintf(out, "        %s\n", Clean(cut(strings.TrimRight(line, "\r"), 2000)))
	}
}
