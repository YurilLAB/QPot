package investigate

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/intelligence"
)

// emptySHA256 is the SHA-256 of no bytes: what a download that fetched
// nothing is stored as.
const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// readBatch is how many events one read asks for.
const readBatch = 1000

// Reading steps: a session is read forwards in windows of time that narrow
// where the events are dense and widen where they are sparse.
const (
	firstWindow = time.Minute
	maxWindow   = 6 * time.Hour
	// tripSlack is how far outside a session's time a canary trip of its
	// source still counts as part of it: a beacon follows the theft.
	tripSlack = 5 * time.Minute
)

// readSession returns the session's stored events, earliest first, at most
// max of them. more is true when the session has events after those.
//
// The database returns a window newest first, so the session is read in
// consecutive windows from its start: the timeline then begins at the
// initial connection whatever the limit is. An event belongs to the session
// when its source hashes to the session ID's source part, which is how the
// campaign builder assigned it; the source addresses only narrow the read.
func readSession(ctx context.Context, db Reader, s *database.TTPSession, want string, max int) (events []*database.Event, more bool, err error) {
	if s.FirstSeen.IsZero() || s.LastSeen.Before(s.FirstSeen) {
		return nil, false, nil
	}
	filter := database.EventFilter{Limit: readBatch}
	if n := len(s.SourceIPs); n > 0 && n <= maxSourceFilter {
		filter.SourceIPs = s.SourceIPs
	}
	// Stored session times may be whole seconds: a second either side takes
	// in every event, and no other session of the source is that close.
	start := s.FirstSeen.Add(-time.Second).Truncate(time.Millisecond)
	last := s.LastSeen.Add(time.Second).Truncate(time.Millisecond)
	window := firstWindow
	queries := 0
	take := func(page []*database.Event) bool {
		sort.SliceStable(page, func(i, j int) bool { return page[i].Timestamp.Before(page[j].Timestamp) })
		for _, e := range page {
			if e == nil {
				continue
			}
			if hash, _ := intelligence.SessionSourceHash(e); hash != want {
				continue
			}
			if len(events) >= max {
				more = true
				return false
			}
			events = append(events, e)
		}
		return true
	}
	for !start.After(last) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		if queries++; queries > maxQueries {
			return events, true, nil
		}
		next := start.Add(window)
		if next.After(last) {
			next = last.Add(time.Millisecond)
		}
		// The bounds are inclusive and the backends keep milliseconds or
		// microseconds, so a window ends one microsecond before the next.
		filter.StartTime, filter.EndTime, filter.Offset = start, next.Add(-time.Microsecond), 0
		page, err := db.GetEvents(ctx, filter)
		if err != nil {
			return nil, false, fmt.Errorf("investigate: read events: %w", err)
		}
		if len(page) >= readBatch {
			if window > time.Millisecond {
				// Too dense to be sure the window is whole: narrow it.
				if window /= 8; window < time.Millisecond {
					window = time.Millisecond
				}
				window = window.Truncate(time.Millisecond)
				continue
			}
			// One millisecond holds a batch or more: read it by offset.
			for {
				if !take(page) {
					return events, true, nil
				}
				if len(page) < readBatch {
					break
				}
				if queries++; queries > maxQueries {
					return events, true, nil
				}
				filter.Offset += readBatch
				if page, err = db.GetEvents(ctx, filter); err != nil {
					return nil, false, fmt.Errorf("investigate: read events: %w", err)
				}
			}
		} else {
			if !take(page) {
				return events, true, nil
			}
			if len(page) < readBatch/8 && window < maxWindow {
				if window *= 2; window > maxWindow {
					window = maxWindow
				}
			}
		}
		start = next
	}
	return events, false, nil
}

// phaseOf places an event type in the course of an intrusion.
func phaseOf(e *database.Event) string {
	t := strings.ToLower(e.EventType)
	switch {
	case strings.Contains(t, "file_download") || strings.Contains(t, "file_upload"):
		return PhaseTransfer
	case intelligence.IsCommandEvent(t):
		return PhaseCommand
	case strings.Contains(t, "login") || strings.Contains(t, ".auth") || (e.Username != "" && e.Password != ""):
		return PhaseCredentials
	case strings.Contains(t, "session.closed") || strings.Contains(t, "disconnect") || strings.Contains(t, "connection.close"):
		return PhaseClose
	case strings.Contains(t, "connect"):
		return PhaseConnection
	}
	return PhaseOther
}

// outcomeOf reads what a login event says of its result.
func outcomeOf(eventType string) string {
	t := strings.ToLower(eventType)
	switch {
	case strings.Contains(t, "success") || strings.Contains(t, "succeeded") || strings.Contains(t, "accepted"):
		return "accepted"
	case strings.Contains(t, "fail") || strings.Contains(t, "denied") || strings.Contains(t, "refused"):
		return "refused"
	}
	return ""
}

// oneLine is s with every run of white space as one space.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// printable returns the payload as text when it is text, else "".
func printable(p []byte) string {
	if len(p) == 0 || !utf8.Valid(p) {
		return ""
	}
	for _, r := range string(p) {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return ""
		}
	}
	return oneLine(string(p))
}

// session builds one session's part of the case.
func (b *builder) session(ctx context.Context, db Reader, s *database.TTPSession, max int) (*SessionCase, error) {
	sc := &SessionCase{Session: s, Honeypots: []string{}, Reached: []string{}, Timeline: []Step{}, Files: []File{}, Evidence: []Evidence{}}
	id := s.SessionID
	want, _, ok := intelligence.SplitSessionID(id)
	if !ok {
		b.gap(Gap{Kind: GapOldSession, SessionID: id,
			Detail: "This session was stored by an earlier version of QPot, which did not group events by source. Its events cannot be picked out again, so it has no timeline."})
		return sc, nil
	}
	events, more, err := readSession(ctx, db, s, want, max)
	if err != nil {
		return nil, err
	}
	sc.EventsRead = len(events)
	switch {
	case more:
		b.gap(Gap{Kind: GapEventLimit, SessionID: id, Count: len(events),
			Detail: fmt.Sprintf("The session counted %d events. The timeline holds the first %d; what came after is not shown.", s.EventCount, len(events))})
	case int64(len(events)) < s.EventCount:
		b.gap(Gap{Kind: GapEventsMissing, SessionID: id, Count: int(s.EventCount) - len(events),
			Detail: fmt.Sprintf("The session counted %d events, and %d are stored now. The others were removed by retention or disk cleanup, or were stored more than once and merged.", s.EventCount, len(events))})
	}
	unknown := false
	if len(events) > 0 {
		_, unknown = intelligence.SessionSourceHash(events[0])
	}
	shared := s.SharedInfrastructure && len(s.SourceIPs) == 0
	switch {
	case unknown:
		b.gap(Gap{Kind: GapUnknownSource, SessionID: id,
			Detail: "These are a honeypot's events without a usable source address. They may come from any number of visitors: this is not one actor's activity."})
	case shared:
		b.gap(Gap{Kind: GapSharedSource, SessionID: id,
			Detail: "The source address of these events is Docker's own, not the visitor's. They are grouped by the honeypot's connection ID, so the visitor's address is not known and other connections of the same visitor are not linked."})
	}

	refs := make([]string, len(events))
	honeypots := newSet()
	reached := map[string]bool{}
	type agg struct {
		count int
		refs  []string
	}
	gaps := map[string]*agg{}
	note := func(kind, ref string) {
		g := gaps[kind]
		if g == nil {
			g = &agg{}
			gaps[kind] = g
		}
		g.count++
		if len(g.refs) < MaxRefs {
			g.refs = append(g.refs, ref)
		}
	}
	var cutDetail string
	uncaptured := map[string]int{}
	starts := map[string]int{} // capture ID of a started command: its step
	dropped := map[int]bool{}  // steps merged into a later one
	unclassified := 0
	var steps []Step

	for i, e := range events {
		ref := b.record(id, e)
		refs[i] = ref
		honeypots.add(e.Honeypot)
		if !e.Classified {
			unclassified++
		}
		md := e.Metadata
		typ := strings.ToLower(e.EventType)
		hifi := md["capture_id"] != "" || md["state_scope"] == "private_cell"

		// What was cut or lost on the way into the record.
		switch {
		case strings.HasSuffix(typ, ".log.line_discarded"):
			note(GapLineDiscarded, ref)
		case hifi && md["truncated"] == "true":
			note(GapCaptureCut, ref)
		case !hifi && md["truncated"] != "":
			note(GapValueCut, ref)
			if cutDetail == "" && md["input_chars"] != "" {
				cutDetail = fmt.Sprintf(" The first cut command was %s characters long (SHA-256 %s).", md["input_chars"], md["input_sha256"])
			}
		}
		if md["command_truncated"] == "true" {
			note(GapValueCut, ref)
		}
		if md["capture_error"] != "" || md["attribution_error"] != "" {
			note(GapCaptureError, ref)
		}

		phase := phaseOf(e)
		reached[phase] = true
		st := Step{At: e.Timestamp, Phase: phase, Honeypot: e.Honeypot, EventType: e.EventType, Count: 1,
			Technique: e.TechniqueID, Refs: []string{ref}, connection: md["session"]}
		switch phase {
		case PhaseConnection:
			st.Summary = "Connected to " + e.Honeypot
			if e.DestPort > 0 {
				st.Summary += " on port " + strconv.Itoa(e.DestPort)
			}
			if e.SourceIP != "" && !shared && !unknown {
				st.Summary += " from " + e.SourceIP
			}
		case PhaseCredentials:
			st.Username, st.Password, st.Outcome = e.Username, e.Password, outcomeOf(e.EventType)
			st.Summary = credentialSummary(st)
		case PhaseCommand:
			st.Command = e.Command
			st.Summary = oneLine(e.Command)
			captureID := md["capture_id"]
			st.single = hifi
			switch {
			case strings.HasSuffix(typ, ".command.start") && captureID != "":
				starts[captureID] = len(steps)
			case strings.HasSuffix(typ, ".command.finish"):
				if at, ok := starts[captureID]; ok && captureID != "" {
					// The start and the finish are one command: one step,
					// dated by its start, resting on both records.
					st.At = steps[at].At
					st.Refs = append([]string{steps[at].Refs[0]}, st.Refs...)
					dropped[at] = true
					delete(starts, captureID)
				}
				if code, err := strconv.Atoi(md["exit_code"]); err == nil {
					st.ExitCode = &code
				}
				st.Output = b.outputOf(e, id, ref, note)
			case strings.HasSuffix(typ, ".command.failed") && len(steps) > 0:
				// Cowrie reports a command it does not know a second time.
				if prev := &steps[len(steps)-1]; prev.Phase == PhaseCommand && prev.Command == e.Command && prev.connection == st.connection && prev.Outcome == "" {
					prev.Outcome = "not known to the honeypot"
					prev.Refs = append(prev.Refs, ref)
					continue
				}
				st.Outcome = "not known to the honeypot"
			}
			if !hifi {
				uncaptured[e.Honeypot]++
			}
		case PhaseTransfer:
			// Only a whole SHA-256 is a hash; anything else in that field
			// stays in the record and is not shown as one.
			if sum := strings.ToLower(md["shasum"]); len(sum) == 64 && strings.Trim(sum, "0123456789abcdef") == "" {
				st.SHA256 = sum
			}
			st.File = md["outfile"]
			if st.File == "" {
				st.File = md["filename"]
			}
			if p := string(e.Payload); strings.Contains(p, "://") && utf8.ValidString(p) {
				st.URL = strings.TrimSpace(p)
			}
			if strings.Contains(typ, "fail") {
				st.Outcome = "failed"
			}
			st.CausedBy, st.Because = causeOf(steps, st)
			st.Summary = transferSummary(typ, st)
		case PhaseClose:
			st.Summary = "Connection to " + e.Honeypot + " closed"
			if d, err := strconv.ParseFloat(md["duration"], 64); err == nil && d >= 0 && d < 1e9 {
				st.Summary += fmt.Sprintf(" after %.1f s", d)
			}
		default:
			st.Summary = e.EventType
			if e.Command != "" {
				st.Command = e.Command
				st.Summary += ": " + oneLine(e.Command)
			} else if text := printable(e.Payload); text != "" {
				st.Summary += ": " + text
			}
		}
		st.Summary = cut(st.Summary, maxSummary)
		if n := len(steps); n > 0 && !dropped[n-1] && fold(&steps[n-1], st) {
			continue
		}
		steps = append(steps, st)
	}

	// Commands that started and have no finish among the events read.
	unfinished := 0
	var unfinishedRefs []string
	for _, at := range starts {
		unfinished++
		unfinishedRefs = append(unfinishedRefs, steps[at].Refs[0])
		steps[at].Outcome = "no finish recorded"
	}
	sort.Strings(unfinishedRefs)

	kept := steps[:0]
	for i, st := range steps {
		if !dropped[i] {
			kept = append(kept, st)
		}
	}
	steps = kept

	// Canary trips by this session's source.
	if !shared && !unknown {
		for _, t := range b.opts.Trips {
			if t == nil || t.SourceIP == "" {
				continue
			}
			if hash, none := intelligence.SessionSourceHash(&database.Event{SourceIP: t.SourceIP}); none || hash != want {
				continue
			}
			inside := !t.Time.Before(s.FirstSeen.Add(-tripSlack)) && !t.Time.After(s.LastSeen.Add(tripSlack))
			b.trip(t, id, inside)
			if !inside {
				continue
			}
			reached[PhaseCanary] = true
			summary := fmt.Sprintf("Canary %q (%s) tripped over %s", t.Name, t.Kind, t.Channel)
			if t.Detail != "" {
				summary += ": " + oneLine(t.Detail)
			}
			steps = append(steps, Step{At: t.Time, Phase: PhaseCanary, Summary: cut(summary, maxSummary), Count: 1 + t.Repeats, Refs: []string{"trip:" + t.ID}})
		}
	} else if n := tripsBetween(b.opts.Trips, s.FirstSeen, s.LastSeen); n > 0 {
		b.gap(Gap{Kind: GapCanaryUnmatched, SessionID: id, Count: n,
			Detail: fmt.Sprintf("%d canary trips happened during this session's time. Its source address is not the visitor's, so they cannot be matched to it.", n)})
	}
	sort.SliceStable(steps, func(i, j int) bool { return steps[i].At.Before(steps[j].At) })
	for i := range steps {
		if steps[i].Count > 1 && steps[i].Phase == PhaseCredentials {
			steps[i].Summary = cut(credentialSummary(steps[i]), maxSummary)
		}
	}
	sc.Timeline = append(sc.Timeline, steps...)
	sc.Files = files(steps)
	sc.Honeypots, _ = honeypots.first(maxListed)
	for _, p := range phaseOrder {
		if reached[p] {
			sc.Reached = append(sc.Reached, p)
		}
	}

	// The strong evidence, as the campaign builder read it from these events.
	if !unknown {
		for _, ev := range intelligence.CollectEvidence(events) {
			out := Evidence{Kind: ev.Kind, Value: ev.Value, At: ev.At, key: ev.Key, Refs: []string{}}
			seen := map[string]bool{}
			for _, i := range ev.Events {
				if r := refs[i]; !seen[r] && len(out.Refs) < MaxRefs {
					seen[r] = true
					out.Refs = append(out.Refs, r)
				}
			}
			sc.Evidence = append(sc.Evidence, out)
		}
	}

	// The gaps, one per kind.
	add := func(kind, detail string) {
		if g := gaps[kind]; g != nil {
			b.gap(Gap{Kind: kind, SessionID: id, Count: g.count, Refs: g.refs, Detail: detail})
		}
	}
	add(GapLineDiscarded, "The collector discarded log lines longer than it reads. Each record named here holds only the beginning of such a line.")
	add(GapValueCut, "Values too long to store whole were cut. The records named here hold their beginning."+cutDetail)
	add(GapCaptureCut, "The capture of these commands ran out of room: their recorded input or output is incomplete.")
	add(GapCaptureError, "The capture of these commands reported an error, or could not name the connection they came over.")
	add(GapOutputMissing, "These commands' output was captured to a file that is no longer there (removed by disk cleanup, or not readable by this user).")
	if unfinished > 0 {
		b.gap(Gap{Kind: GapUnfinished, SessionID: id, Count: unfinished, Refs: unfinishedRefs,
			Detail: "These commands have a start record and no finish among the events read: they were still running, or the finish was lost."})
	}
	names := make([]string, 0, len(uncaptured))
	for hp := range uncaptured {
		names = append(names, hp)
	}
	sort.Strings(names)
	for _, hp := range names {
		b.gap(Gap{Kind: GapOutputNotKept, SessionID: id, Count: uncaptured[hp],
			Detail: fmt.Sprintf("%s records what was typed, not what each command printed: its %d commands here have no output.", hp, uncaptured[hp])})
	}
	if unclassified > 0 {
		b.gap(Gap{Kind: GapUnclassified, SessionID: id, Count: unclassified,
			Detail: fmt.Sprintf("%d of these events are not classified yet: the session's techniques and evidence do not count them until the worker's next run.", unclassified)})
	}
	if len(s.SourceIPs) >= 10000 {
		b.gap(Gap{Kind: GapSourceList, SessionID: id, Count: len(s.SourceIPs),
			Detail: "The session lists the most addresses a session keeps. Its source used more than are listed."})
	}
	return sc, nil
}

// credentialSummary words a login step.
func credentialSummary(st Step) string {
	if st.Count > 1 {
		s := fmt.Sprintf("%d logins", st.Count)
		if st.Outcome != "" {
			s += " " + st.Outcome
		}
		if len(st.Tried) > 0 {
			s += ", starting with " + strings.Join(st.Tried, ", ")
		}
		return s
	}
	s := "Login as " + strconv.Quote(st.Username)
	if st.Password != "" {
		s += " with password " + strconv.Quote(st.Password)
	}
	if st.Outcome != "" {
		s += ": " + st.Outcome
	}
	return s
}

// transferSummary words a file transfer step.
func transferSummary(typ string, st Step) string {
	verb := "Downloaded"
	if strings.Contains(typ, "upload") {
		verb = "Uploaded"
	}
	if st.Outcome == "failed" {
		verb = strings.TrimSuffix(verb, "ed") + " failed:"
	}
	what := st.URL
	if what == "" {
		what = st.File
	}
	if what == "" {
		what = "a file"
	}
	s := verb + " " + oneLine(what)
	switch {
	case st.SHA256 == emptySHA256:
		s += " (empty)"
	case st.SHA256 != "":
		s += " (SHA-256 " + st.SHA256 + ")"
	}
	return s
}

// causeOf finds the command a transfer follows from: the latest earlier
// command of the same honeypot connection that names the transfer's URL, its
// host or its file. It claims nothing when no command does.
func causeOf(steps []Step, t Step) (ref, because string) {
	host := urlHost(t.URL)
	name := ""
	if t.File != "" {
		name = path.Base(strings.ReplaceAll(t.File, "\\", "/"))
	}
	for i, looked := len(steps)-1, 0; i >= 0 && looked < 500; i, looked = i-1, looked+1 {
		c := steps[i]
		if c.Phase != PhaseCommand || c.Honeypot != t.Honeypot || c.Command == "" {
			continue
		}
		if c.connection != "" && t.connection != "" && c.connection != t.connection {
			continue
		}
		switch {
		case t.URL != "" && strings.Contains(c.Command, t.URL):
			return c.Refs[len(c.Refs)-1], "the command names this URL"
		case host != "" && strings.Contains(strings.ToLower(c.Command), host):
			return c.Refs[len(c.Refs)-1], "the command names this host"
		case len(name) >= 3 && name != "." && strings.Contains(c.Command, name):
			return c.Refs[len(c.Refs)-1], "the command names this file"
		}
	}
	return "", ""
}

// fold merges next into last when both stand for the same thing happening
// again, and reports whether it did. A run of refused logins is one step,
// as is a repeated command or a burst of the same event.
func fold(last *Step, next Step) bool {
	if last.single || next.single || last.Phase != next.Phase || last.Honeypot != next.Honeypot || !strings.EqualFold(last.EventType, next.EventType) {
		return false
	}
	switch next.Phase {
	case PhaseCredentials:
		if next.Outcome == "accepted" || last.Outcome != next.Outcome {
			return false
		}
		if last.Count == 1 {
			last.Tried = []string{last.Username + " / " + last.Password}
			last.Username, last.Password = "", ""
		}
		if pair := next.Username + " / " + next.Password; len(last.Tried) < 10 && !contains(last.Tried, pair) {
			last.Tried = append(last.Tried, pair)
		}
	case PhaseCommand:
		if last.Command != next.Command || last.Output != nil || next.Output != nil || last.Outcome != next.Outcome || last.connection != next.connection {
			return false
		}
	case PhaseTransfer, PhaseCanary:
		return false
	default:
		if last.Summary != next.Summary {
			return false
		}
	}
	last.Count += next.Count
	until := next.At
	last.Until = &until
	for _, r := range next.Refs {
		if len(last.Refs) < MaxRefs {
			last.Refs = append(last.Refs, r)
		} else {
			last.MoreRefs++
		}
	}
	return true
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// files gathers a timeline's transfers by content: one entry per hash, or
// per URL or name when a transfer has no hash.
func files(steps []Step) []File {
	index := map[string]int{}
	var out []File
	for _, st := range steps {
		if st.Phase != PhaseTransfer {
			continue
		}
		key := "h:" + st.SHA256
		if st.SHA256 == "" {
			key = "u:" + st.URL + "\x00" + st.File
		}
		i, ok := index[key]
		if !ok {
			i = len(out)
			index[key] = i
			out = append(out, File{SHA256: st.SHA256, Empty: st.SHA256 == emptySHA256, FirstSeen: st.At, Refs: []string{}})
		}
		f := &out[i]
		f.Transfers++
		if st.URL != "" && !contains(f.URLs, st.URL) && len(f.URLs) < MaxRefs {
			f.URLs = append(f.URLs, st.URL)
		}
		if st.File != "" && !contains(f.Names, st.File) && len(f.Names) < MaxRefs {
			f.Names = append(f.Names, st.File)
		}
		for _, r := range st.Refs {
			if len(f.Refs) < MaxRefs && !contains(f.Refs, r) {
				f.Refs = append(f.Refs, r)
			}
		}
		if st.CausedBy != "" && !contains(f.Commands, st.CausedBy) && len(f.Commands) < MaxRefs {
			f.Commands = append(f.Commands, st.CausedBy)
		}
	}
	if out == nil {
		out = []File{}
	}
	return out
}

// outputOf reads what a finished command printed.
func (b *builder) outputOf(e *database.Event, sessionID, ref string, note func(kind, ref string)) *Output {
	if b.opts.Output == nil || e.Metadata["stdout_file"] == "" {
		return nil
	}
	if b.output >= maxOutputTotal {
		note(GapCaptureCut, ref)
		return &Output{Cut: true}
	}
	out := &Output{}
	found := false
	for _, stream := range []string{"stdout", "stderr"} {
		data, wasCut, ok, err := b.opts.Output.Output(e, stream)
		if err != nil || !ok {
			continue
		}
		found = true
		if len(data) > MaxOutput {
			data, wasCut = data[:MaxOutput], true
		}
		out.Cut = out.Cut || wasCut
		text := string(data)
		if !utf8.Valid(data) {
			text = strings.ToValidUTF8(text, "\uFFFD")
			out.Binary = true
		}
		if stream == "stdout" {
			out.Stdout, out.stdout = text, data
		} else {
			out.Stderr, out.stderr = text, data
		}
		out.Bytes += len(data)
		b.output += len(data)
	}
	if !found {
		note(GapOutputMissing, ref)
		return nil
	}
	return out
}

// trip puts a canary trip on the case once; a trip inside a session's time
// belongs to that session.
func (b *builder) trip(t *canary.Trip, sessionID string, inside bool) {
	owner := ""
	if inside {
		owner = sessionID
	}
	for i := range b.trips {
		if b.trips[i].ID == t.ID {
			if b.trips[i].SessionID == "" {
				b.trips[i].SessionID = owner
			}
			return
		}
	}
	b.trips = append(b.trips, Trip{ID: t.ID, CanaryID: t.CanaryID, Kind: string(t.Kind), Name: t.Name, Memo: t.Memo,
		Channel: t.Channel, Time: t.Time, SourceIP: t.SourceIP, Detail: t.Detail, Repeats: t.Repeats, SessionID: owner})
}

// tripsBetween counts the trips inside a time span.
func tripsBetween(trips []*canary.Trip, from, to time.Time) int {
	n := 0
	for _, t := range trips {
		if t != nil && !t.Time.Before(from) && !t.Time.After(to) {
			n++
		}
	}
	return n
}
