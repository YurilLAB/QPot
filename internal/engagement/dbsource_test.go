package engagement

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// stored builds events the way the collector's add_qpot_metadata transform
// stores them for Cowrie: event_type from eventid, command from input,
// payload from url, and session / shasum / duration as metadata strings. The
// timestamp is the collector's clock.
func stored() []*database.Event {
	base := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	md := func(kv ...string) map[string]string {
		m := map[string]string{"session": "a1b2c3d4e5f6", "sensor": "pot", "dst_ip": "192.0.2.1"}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	ev := func(sec int, typ string, m map[string]string) *database.Event {
		return &database.Event{
			Timestamp: base.Add(time.Duration(sec) * time.Second), Honeypot: "cowrie", SourceIP: "203.0.113.5",
			SourcePort: 50022, DestPort: 2222, Protocol: "ssh", EventType: typ, Metadata: m,
		}
	}
	connect := ev(0, "cowrie.session.connect", md())
	version := ev(0, "cowrie.client.version", md("version", "SSH-2.0-Go"))
	failed := ev(1, "cowrie.login.failed", md())
	failed.Username, failed.Password = "root", "123456"
	success := ev(2, "cowrie.login.success", md())
	success.Username, success.Password = "root", "admin"
	command := ev(3, "cowrie.command.input", md())
	command.Command, command.TechniqueID, command.Classified = "uname -a", "T1082", true
	download := ev(5, "cowrie.session.file_download", md("shasum", sha, "outfile", "var/lib/cowrie/downloads/abc"))
	download.Payload = []byte("http://198.51.100.9/bins/x86")
	closed := ev(12, "cowrie.session.closed", md("duration", "12.25"))
	return []*database.Event{connect, version, failed, success, command, download, closed}
}

func TestFromDatabaseEvent(t *testing.T) {
	in := stored()
	base := in[0].Timestamp
	want := []Event{
		{Time: base, Honeypot: "cowrie", SourceIP: "203.0.113.5", SessionID: "a1b2c3d4e5f6", Type: "cowrie.session.connect"},
		{Time: base, Honeypot: "cowrie", SourceIP: "203.0.113.5", SessionID: "a1b2c3d4e5f6", Type: "cowrie.client.version"},
		{Time: base.Add(time.Second), Honeypot: "cowrie", SourceIP: "203.0.113.5", SessionID: "a1b2c3d4e5f6", Type: "cowrie.login.failed", Username: "root", Password: "123456"},
		{Time: base.Add(2 * time.Second), Honeypot: "cowrie", SourceIP: "203.0.113.5", SessionID: "a1b2c3d4e5f6", Type: "cowrie.login.success", Username: "root", Password: "admin"},
		{Time: base.Add(3 * time.Second), Honeypot: "cowrie", SourceIP: "203.0.113.5", SessionID: "a1b2c3d4e5f6", Type: "cowrie.command.input", Command: "uname -a", TechniqueID: "T1082"},
		{Time: base.Add(5 * time.Second), Honeypot: "cowrie", SourceIP: "203.0.113.5", SessionID: "a1b2c3d4e5f6", Type: "cowrie.session.file_download", URL: "http://198.51.100.9/bins/x86", SHA256: sha},
		{Time: base.Add(12 * time.Second), Honeypot: "cowrie", SourceIP: "203.0.113.5", SessionID: "a1b2c3d4e5f6", Type: "cowrie.session.closed", ReportedDuration: 12250 * time.Millisecond},
	}
	for i, d := range in {
		if got := FromDatabaseEvent(d); !reflect.DeepEqual(got, want[i]) {
			t.Errorf("event %d:\n got %+v\nwant %+v", i, got, want[i])
		}
	}

	// Honeypots that write session_id; a raw request in the payload column
	// is not a URL; a shasum outside a payload event (Cowrie's TTY log) is
	// not a payload hash; a duration outside session.closed is not a length.
	other := FromDatabaseEvent(&database.Event{
		Timestamp: base, Honeypot: "heralding", EventType: "Heralding.Login.Failed", SourceIP: "203.0.113.7",
		Payload:  []byte("GET / HTTP/1.1"),
		Metadata: map[string]string{"session_id": "h-1", "shasum": sha, "duration": "9"},
	})
	if other.SessionID != "h-1" || other.Type != "heralding.login.failed" || other.URL != "" || other.SHA256 != "" || other.ReportedDuration != 0 {
		t.Errorf("other honeypot = %+v", other)
	}
	if e := FromDatabaseEvent(&database.Event{EventType: "x"}); e.SessionID != "" || e.Type != "x" {
		t.Errorf("event without metadata = %+v", e)
	}

	// The stored session gives the numbers the same session gives when read
	// from Cowrie's own log (cowrieFixture holds it).
	fromDB, err := Compute("x", func(emit func(Event) bool) error {
		for _, d := range in {
			emit(FromDatabaseEvent(d))
		}
		return nil
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	logEvents, _ := readAll(t, strings.NewReader(cowrieFixture))
	fromLog, err := Compute("x", sliceSource(logEvents[:7]), Options{})
	if err != nil {
		t.Fatal(err)
	}
	a, b := fromDB.Overall, fromLog.Overall
	// The log's command carries no technique: classification is QPot's.
	a.Intelligence.Techniques = b.Intelligence.Techniques
	if !reflect.DeepEqual(a, b) {
		t.Errorf("the same session differs between the database and the log:\n db  %+v\n log %+v", a, b)
	}
}

// TestMappingMatchesCollectorTransform fails when the collector's transform
// stops writing the fields FromDatabaseEvent reads.
func TestMappingMatchesCollectorTransform(t *testing.T) {
	src, err := os.ReadFile("../instance/compose.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	start := strings.Index(text, "  add_qpot_metadata:")
	if start < 0 {
		t.Fatal("the add_qpot_metadata transform is gone from internal/instance/compose.go")
	}
	transform := text[start:]
	for _, want := range []string{
		`et = string!(.eventid)`,               // event_type is the honeypot's event id
		`.event_type = downcase(et)`,           // in lower case
		`cmd = string!(.input)`,                // command is the input line
		`.command = cmd`,                       //
		`pl = string!(.url)`,                   // payload is the download URL
		`.payload = pl`,                        //
		`for_each(["session", "session_id"`,    // metadata keeps the session id,
		`"shasum"`,                             // the payload hash
		`"duration"`,                           // and the session length
		`.timestamp = format_timestamp!(now()`, // the time is the collector's
	} {
		if !strings.Contains(transform, want) {
			t.Errorf("the collector transform no longer contains %q: check FromDatabaseEvent", want)
		}
	}
}

// fakeStore answers GetEvents like the backends do: the events of the
// window, newest first, cut by limit and offset. Its clock is as coarse as
// precision, the way ClickHouse compares in milliseconds.
type fakeStore struct {
	events    []*database.Event
	precision time.Duration
	maxLimit  int
	calls     int
	fail      error
}

func (f *fakeStore) GetEvents(_ context.Context, q database.EventFilter) ([]*database.Event, error) {
	f.calls++
	if f.fail != nil {
		return nil, f.fail
	}
	if q.Limit <= 0 {
		return nil, errors.New("unbounded read")
	}
	f.maxLimit = max(f.maxLimit, q.Limit)
	cut := func(t time.Time) time.Time { return t.Truncate(f.precision) }
	var out []*database.Event
	for _, e := range f.events {
		ts := cut(e.Timestamp)
		if !q.StartTime.IsZero() && ts.Before(cut(q.StartTime)) {
			continue
		}
		if ts.After(cut(q.EndTime)) {
			continue
		}
		if len(q.Honeypots) > 0 && q.Honeypots[0] != e.Honeypot {
			continue
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Timestamp.After(out[j].Timestamp) })
	if q.Offset >= len(out) {
		return nil, nil
	}
	out = out[q.Offset:]
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

func TestReadDatabaseReadsEveryEventOnce(t *testing.T) {
	base := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	var events []*database.Event
	add := func(at time.Duration, n int, hp string) {
		for i := 0; i < n; i++ {
			events = append(events, &database.Event{
				Timestamp: base.Add(at), Honeypot: hp, EventType: "cowrie.command.input",
				Command: fmt.Sprint("c", len(events)), Metadata: map[string]string{"session": "s"},
			})
		}
	}
	add(0, 3, "cowrie")
	add(time.Millisecond, 1, "cowrie")
	add(5*time.Millisecond, 23, "cowrie") // one millisecond holding several batches
	add(5*time.Millisecond+300*time.Microsecond, 4, "cowrie")
	add(6*time.Millisecond, 2, "adbhoney")
	add(time.Second, 7, "cowrie")
	add(time.Second+999*time.Microsecond, 1, "cowrie")
	add(time.Hour, 1, "cowrie")
	before := &database.Event{Timestamp: base.Add(-time.Millisecond), Honeypot: "cowrie", Command: "before"}
	after := &database.Event{Timestamp: base.Add(2 * time.Hour), Honeypot: "cowrie", Command: "after"}
	all := append([]*database.Event{before, after}, events...)

	for _, precision := range []time.Duration{time.Millisecond, time.Microsecond, time.Nanosecond} {
		for _, batch := range []int{1, 2, 3, 5, 8, 23, 24, 41, 42, 43, 500} {
			for _, bounded := range []bool{true, false} {
				name := fmt.Sprintf("%v/batch %d/since %v", precision, batch, bounded)
				store := &fakeStore{events: all, precision: precision}
				q := DBQuery{Until: base.Add(time.Hour), Batch: batch}
				wantN := len(events) + 1 // with no start, "before" is in the window
				if bounded {
					q.Since = base
					wantN = len(events)
				}
				seen := map[string]int{}
				n, err := ReadDatabase(context.Background(), store, q, func(e Event) bool {
					seen[e.Command]++
					return true
				})
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if int(n) != wantN || len(seen) != wantN {
					t.Fatalf("%s: read %d events, %d distinct, want %d", name, n, len(seen), wantN)
				}
				for c, k := range seen {
					if k != 1 || c == "after" || (bounded && c == "before") {
						t.Fatalf("%s: event %q read %d times", name, c, k)
					}
				}
				if store.maxLimit != batch {
					t.Fatalf("%s: asked for %d events at once, want %d", name, store.maxLimit, batch)
				}
			}
		}
	}

	// The honeypot filter is passed on.
	store := &fakeStore{events: all, precision: time.Millisecond}
	n, err := ReadDatabase(context.Background(), store, DBQuery{Since: base, Until: base.Add(time.Hour), Honeypots: []string{"adbhoney"}}, func(Event) bool { return true })
	if err != nil || n != 2 || store.maxLimit != DefaultBatch {
		t.Errorf("filtered read: %d events, limit %d, %v", n, store.maxLimit, err)
	}
}

func TestReadDatabaseStopsAndFails(t *testing.T) {
	base := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	var events []*database.Event
	for i := 0; i < 50; i++ {
		events = append(events, &database.Event{Timestamp: base.Add(time.Duration(i) * time.Second), Honeypot: "cowrie"})
	}
	q := DBQuery{Since: base, Until: base.Add(time.Hour), Batch: 10}

	store := &fakeStore{events: events, precision: time.Millisecond}
	n, err := ReadDatabase(context.Background(), store, q, func(Event) bool { return false })
	if err != nil || n != 1 || store.calls != 1 {
		t.Errorf("emit said stop: %d events in %d calls, %v", n, store.calls, err)
	}

	if _, err := ReadDatabase(context.Background(), store, DBQuery{Since: base}, func(Event) bool { return true }); err == nil {
		t.Error("a window without an end must be refused")
	}

	boom := errors.New("database away")
	if _, err := ReadDatabase(context.Background(), &fakeStore{fail: boom}, q, func(Event) bool { return true }); !errors.Is(err, boom) {
		t.Errorf("error = %v, want %v", err, boom)
	}

	ctx, cancel := context.WithCancel(context.Background())
	store = &fakeStore{events: events, precision: time.Millisecond}
	n, err = ReadDatabase(ctx, store, q, func(Event) bool {
		cancel()
		return true
	})
	if !errors.Is(err, context.Canceled) || n >= 50 {
		t.Errorf("cancelled read: %d events, %v", n, err)
	}

	// An empty window is not read at all.
	store = &fakeStore{events: events, precision: time.Millisecond}
	if n, err := ReadDatabase(context.Background(), store, DBQuery{Since: base.Add(time.Hour), Until: base}, func(Event) bool { return true }); err != nil || n != 0 || store.calls != 0 {
		t.Errorf("empty window: %d events in %d calls, %v", n, store.calls, err)
	}
}
