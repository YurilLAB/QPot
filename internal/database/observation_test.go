package database

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

func obsID(seed string) string { return observationID(sha256.Sum256([]byte(seed))) }

func TestIsObservationID(t *testing.T) {
	good := obsID("x")
	cases := map[string]bool{
		good:                                   true,
		strings.ToUpper(good):                  false,
		good[:35]:                              false,
		good + "0":                             false,
		"f47ac10b-58cc-4372-a567-0e02b2c3d479": false, // version 4: a random ID from the database
		"f47ac10b-58cc-8372-a567-0e02b2c3d479": false, // version 8, another variant nibble
		"f47ac10b-58cc-8372-8567-0e02b2c3d479": true,
		"f47ac10b058cc-8372-8567-0e02b2c3d479": false,
		"g47ac10b-58cc-8372-8567-0e02b2c3d479": false,
		"":                                     false,
		"17":                                   false,
	}
	for id, want := range cases {
		if got := IsObservationID(id); got != want {
			t.Errorf("IsObservationID(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestPlanReplays(t *testing.T) {
	t0 := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	a, b, c := obsID("a"), obsID("b"), obsID("c")
	ev := func(id string, sec int) *Event {
		return &Event{ID: id, Timestamp: t0.Add(time.Duration(sec) * time.Second)}
	}
	events := []*Event{
		ev(a, 0),    // first reading of a: stays
		ev(b, 1),    // b is already classified: this is a second copy
		ev(a, 2),    // a read again later: second copy
		ev("42", 3), // no observation ID: nothing may be concluded
		ev("42", 4), // nor from two rows sharing such an ID
		ev(c, 5),    // c twice at the same time: cannot be told apart,
		ev(c, 5),    // so neither is deleted and it is counted once
		nil,         // tolerated
		ev(obsID("d"), 6),
	}
	p := planReplays(events, map[string]bool{b: true})
	var keep, remove []string
	for _, e := range p.keep {
		keep = append(keep, fmt.Sprintf("%s@%d", e.ID, e.Timestamp.Unix()-t0.Unix()))
	}
	for _, e := range p.remove {
		remove = append(remove, fmt.Sprintf("%s@%d", e.ID, e.Timestamp.Unix()-t0.Unix()))
	}
	wantKeep := []string{a + "@0", "42@3", "42@4", c + "@5", obsID("d") + "@6"}
	wantRemove := []string{b + "@1", a + "@2"}
	if strings.Join(keep, " ") != strings.Join(wantKeep, " ") {
		t.Errorf("keep = %v\nwant   %v", keep, wantKeep)
	}
	if strings.Join(remove, " ") != strings.Join(wantRemove, " ") {
		t.Errorf("remove = %v\nwant     %v", remove, wantRemove)
	}
}

// FuzzPlanReplays checks the rules that make deleting safe, on any batch:
// a row to delete always leaves a row of the same observation behind, and an
// observation is counted at most once.
func FuzzPlanReplays(f *testing.F) {
	f.Add([]byte{0, 0, 1, 0, 0, 1, 2, 3}, uint8(1))
	f.Add([]byte{5, 1, 5, 1, 5, 2, 9, 9}, uint8(0))
	f.Fuzz(func(t *testing.T, data []byte, classifiedMask uint8) {
		if len(data) > 400 {
			data = data[:400]
		}
		t0 := time.Unix(1700000000, 0).UTC()
		var events []*Event
		for i := 0; i+1 < len(data); i += 2 {
			id := obsID(fmt.Sprint(data[i] % 8))
			if data[i]%11 == 10 {
				id = fmt.Sprint(data[i]) // a row without an observation ID
			}
			events = append(events, &Event{ID: id, Timestamp: t0.Add(time.Duration(data[i+1]%4) * time.Second)})
		}
		classified := map[string]bool{}
		for i := 0; i < 8; i++ {
			if classifiedMask&(1<<i) != 0 {
				classified[obsID(fmt.Sprint(i))] = true
			}
		}
		p := planReplays(events, classified)
		if len(p.keep)+len(p.remove) > len(events) {
			t.Fatalf("%d kept + %d removed from %d events", len(p.keep), len(p.remove), len(events))
		}
		type key struct {
			id string
			at int64
		}
		kept := map[string]int{}
		keptAt := map[key]bool{}
		for _, e := range p.keep {
			if IsObservationID(e.ID) {
				kept[e.ID]++
				keptAt[key{e.ID, e.Timestamp.UnixMilli()}] = true
				if classified[e.ID] {
					t.Fatalf("an observation that is already classified is counted again: %s", e.ID)
				}
			}
		}
		for id, n := range kept {
			if n != 1 {
				t.Fatalf("observation %s is counted %d times", id, n)
			}
		}
		for _, e := range p.remove {
			if !IsObservationID(e.ID) {
				t.Fatalf("a row without an observation ID is deleted: %q", e.ID)
			}
			if !classified[e.ID] && kept[e.ID] != 1 {
				t.Fatalf("deleting %s would leave no copy of it", e.ID)
			}
			// The delete matches ID and time: it must not match the copy
			// that stays.
			if keptAt[key{e.ID, e.Timestamp.UnixMilli()}] {
				t.Fatalf("the row to delete has the ID and time of the row that stays: %s", e.ID)
			}
		}
		// Every observation that is not classified yet keeps a copy.
		for _, e := range events {
			if IsObservationID(e.ID) && !classified[e.ID] && kept[e.ID] != 1 {
				t.Fatalf("observation %s lost every copy", e.ID)
			}
		}
	})
}

// Two rows of one observation with the same time cannot be told apart by any
// column; the plan names every row but one classified row, by its place.
func TestPlanOneRowPerObservation(t *testing.T) {
	rows := []placedRow{
		// a: twins, both tagged. The first in (part, offset) order stays.
		{Key: "a", Classified: true, Part: "p2", Offset: 0},
		{Key: "a", Classified: true, Part: "p1", Offset: 7},
		// b: tagged, and an unclassified copy that came after.
		{Key: "b", Classified: false, Part: "p1", Offset: 1},
		{Key: "b", Classified: true, Part: "p3", Offset: 4},
		// c: no classified row (the tag never landed): nothing goes.
		{Key: "c", Classified: false, Part: "p1", Offset: 2},
		{Key: "c", Classified: false, Part: "p2", Offset: 2},
		// d: one row.
		{Key: "d", Classified: true, Part: "p1", Offset: 3},
		// e: three rows, the same place read twice is one row.
		{Key: "e", Classified: true, Part: "p4", Offset: 1},
		{Key: "e", Classified: true, Part: "p4", Offset: 1},
		{Key: "e", Classified: true, Part: "p4", Offset: 2},
	}
	got := strings.Join(planOneRowPerObservation(rows), " ")
	if want := "p2:0 p1:1 p4:2"; got != want {
		t.Errorf("rows to delete: %s\nwant:          %s", got, want)
	}
}

// FuzzPlanOneRowPerObservation: whatever the rows, a key with a classified
// row keeps exactly one (a classified one), a key without one keeps all its
// rows, and nothing is named that was not given.
func FuzzPlanOneRowPerObservation(f *testing.F) {
	f.Add([]byte{0, 1, 0, 1, 1, 0, 2, 2, 1})
	f.Add([]byte{3, 3, 3, 3, 3, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 600 {
			data = data[:600]
		}
		var rows []placedRow
		for i := 0; i+2 < len(data); i += 3 {
			// A real place holds one row, so places differ between keys.
			key := fmt.Sprint(data[i] % 5)
			rows = append(rows, placedRow{Key: key, Classified: data[i+1]%2 == 1,
				Part: fmt.Sprintf("k%s-p%d", key, data[i+2]%3), Offset: uint64(data[i+2] / 3 % 4)})
		}
		del := map[string]bool{}
		for _, p := range planOneRowPerObservation(rows) {
			del[p] = true
		}
		places := map[string]map[string]bool{} // key -> places
		classifiedLeft := map[string]map[string]bool{}
		hasClassified := map[string]bool{}
		given := map[string]bool{}
		for _, r := range rows {
			given[r.place()] = true
			if places[r.Key] == nil {
				places[r.Key], classifiedLeft[r.Key] = map[string]bool{}, map[string]bool{}
			}
			places[r.Key][r.place()] = true
			if r.Classified {
				hasClassified[r.Key] = true
			}
		}
		for p := range del {
			if !given[p] {
				t.Fatalf("a place that holds none of the rows is named: %s", p)
			}
		}
		for _, r := range rows {
			if !del[r.place()] && r.Classified {
				classifiedLeft[r.Key][r.place()] = true
			}
		}
		for k, ps := range places {
			left := 0
			for p := range ps {
				if !del[p] {
					left++
				}
			}
			switch {
			case !hasClassified[k] && left != len(ps):
				t.Fatalf("key %s has no classified row and lost %d of %d rows", k, len(ps)-left, len(ps))
			case hasClassified[k] && left != 1:
				t.Fatalf("key %s keeps %d rows, want 1", k, left)
			case hasClassified[k] && len(classifiedLeft[k]) == 0:
				t.Fatalf("key %s keeps no classified row", k)
			}
		}
	})
}

// The sweep deletes in time order, naming each ID once per statement, with
// bounds that hold every row named.
func TestPlanSweepDeletes(t *testing.T) {
	rows := []sweepRow{{"c", 30}, {"a", 10}, {"b", 20}, {"a", 40}, {"d", 20}, {"e", 50}}
	var got []string
	for _, d := range planSweepDeletes(rows, 2) {
		got = append(got, fmt.Sprintf("%v %d-%d", d.IDs, d.Lo, d.Hi))
	}
	if want := "[a b] 10-20; [d c] 20-30; [a e] 40-50"; strings.Join(got, "; ") != want {
		t.Errorf("deletes: %s\nwant:    %s", strings.Join(got, "; "), want)
	}
}

// FuzzPlanSweepDeletes: every row is covered by a statement that names its ID
// and whose bounds hold its time, no statement names more than size IDs
// (unless one ID has several rows in a row), and no ID is named that was not
// given.
func FuzzPlanSweepDeletes(f *testing.F) {
	f.Add([]byte{1, 2, 3, 1, 2, 3, 4, 4}, uint8(2))
	f.Add([]byte{9, 9, 9, 9}, uint8(0))
	f.Fuzz(func(t *testing.T, data []byte, size uint8) {
		if len(data) > 400 {
			data = data[:400]
		}
		var rows []sweepRow
		given := map[string]bool{}
		for i := 0; i+1 < len(data); i += 2 {
			r := sweepRow{ID: fmt.Sprint(data[i] % 16), Millis: int64(data[i+1])}
			rows = append(rows, r)
			given[r.ID] = true
		}
		plan := planSweepDeletes(rows, int(size))
		limit := max(int(size), 1)
		for _, r := range rows {
			covered := false
			for _, d := range plan {
				if d.Lo <= r.Millis && r.Millis <= d.Hi && slices.Contains(d.IDs, r.ID) {
					covered = true
				}
			}
			if !covered {
				t.Fatalf("row %v is in no statement", r)
			}
		}
		for _, d := range plan {
			if len(d.IDs) == 0 || d.Lo > d.Hi {
				t.Fatalf("empty or inverted statement %+v", d)
			}
			if len(d.IDs) > limit {
				t.Fatalf("statement names %d IDs, limit %d", len(d.IDs), limit)
			}
			for _, id := range d.IDs {
				if !given[id] {
					t.Fatalf("ID %s was not given", id)
				}
			}
		}
	})
}

func TestParseBackupEvent(t *testing.T) {
	id := obsID("line")
	line := `{"timestamp":"2026-11-11 16:29:17.737","honeypot":"cowrie","source_ip":"203.0.113.9","source_port":55632,"dest_port":"22","protocol":"ssh","event_type":"cowrie.command.input","username":"root","password":"hunter2","command":"uname -a","payload":"raw\\bytes","metadata":{"session":"s1","n":7,"nested":{"a":1}},"country":"AU","city":"Cairns","asn":"64500","event_id":"` + id + `","sensor_id":"qs_x","message":"..."}`
	e, err := ParseBackupEvent([]byte(line), "2026/11/11/cowrie.log", 120)
	if err != nil {
		t.Fatal(err)
	}
	if e.ID != id || e.Honeypot != "cowrie" || e.SourceIP != "203.0.113.9" || e.SourcePort != 55632 || e.DestPort != 22 ||
		e.Protocol != "ssh" || e.EventType != "cowrie.command.input" || e.Username != "root" || e.Password != "hunter2" ||
		e.Command != "uname -a" || string(e.Payload) != `raw\bytes` || e.Country != "AU" || e.City != "Cairns" || e.ASN != "64500" {
		t.Errorf("fields not restored: %+v", e)
	}
	if want := time.Date(2026, 11, 11, 16, 29, 17, 737e6, time.UTC); !e.Timestamp.Equal(want) {
		t.Errorf("time = %s, want %s", e.Timestamp, want)
	}
	if e.Metadata["session"] != "s1" || e.Metadata["n"] != "7" || e.Metadata["nested"] != `{"a":1}` {
		t.Errorf("metadata = %v", e.Metadata)
	}
	if e.Classified {
		t.Error("a restored event must be classified again")
	}

	// A line from before events carried an ID: its place in the backup
	// names it, so the same line restores to the same ID and an equal line
	// elsewhere to another.
	old := []byte(`{"timestamp":"2026-11-01 00:00:00.000","honeypot":"cowrie","source_ip":"203.0.113.9","event_id":"7c1f2a55-7d1e-4a9b-9a51-0d3c8a4f6b21"}`)
	first, err := ParseBackupEvent(old, "2026/11/01/cowrie.log", 0)
	if err != nil {
		t.Fatal(err)
	}
	same, _ := ParseBackupEvent(old, "2026/11/01/cowrie.log", 0)
	other, _ := ParseBackupEvent(old, "2026/11/01/cowrie.log", int64(len(old)+1))
	if !IsObservationID(first.ID) || first.ID != same.ID || first.ID == other.ID {
		t.Errorf("IDs for a line without one: %s, again %s, at another offset %s", first.ID, same.ID, other.ID)
	}

	for _, bad := range []string{``, `not json`, `[]`, `{"honeypot":"cowrie"}`, `{"timestamp":"2026-11-01 00:00:00.000"}`,
		`{"timestamp":"yesterday","honeypot":"cowrie"}`} {
		if _, err := ParseBackupEvent([]byte(bad), "f", 0); err == nil {
			t.Errorf("ParseBackupEvent(%q) accepted it", bad)
		}
	}
	// Ports out of range are dropped, not wrapped.
	e, err = ParseBackupEvent([]byte(`{"timestamp":"2026-11-01 00:00:00","honeypot":"x","source_port":70000,"dest_port":-1}`), "f", 0)
	if err != nil || e.SourcePort != 0 || e.DestPort != 0 {
		t.Errorf("out-of-range ports: %+v, %v", e, err)
	}
}

func FuzzParseBackupEvent(f *testing.F) {
	f.Add([]byte(`{"timestamp":"2026-11-11 16:29:17.737","honeypot":"cowrie","metadata":{"a":"b"}}`), "2026/11/11/cowrie.log", int64(0))
	f.Add([]byte(`{"timestamp":"2026-11-11T16:29:17Z","honeypot":"x","source_port":"99999","event_id":"zz"}`), "", int64(-1))
	f.Fuzz(func(t *testing.T, line []byte, file string, offset int64) {
		e, err := ParseBackupEvent(line, file, offset)
		if err != nil {
			return
		}
		if !IsObservationID(e.ID) {
			t.Fatalf("a restored event has no observation ID: %q", e.ID)
		}
		if e.Honeypot == "" || e.Timestamp.IsZero() && !strings.Contains(string(line), "0001") {
			t.Fatalf("a restored event lacks its honeypot or time: %+v", e)
		}
		if e.SourcePort < 0 || e.SourcePort > 65535 || e.DestPort < 0 || e.DestPort > 65535 {
			t.Fatalf("port out of range: %d %d", e.SourcePort, e.DestPort)
		}
	})
}

// memoryStore is an EventRestorer over a map.
type memoryStore struct {
	rows  map[string]*Event
	calls int
}

func (m *memoryStore) CountEvents(context.Context) (int64, error) { return int64(len(m.rows)), nil }
func (m *memoryStore) RestoreEvents(_ context.Context, events []*Event, dryRun bool) (int, error) {
	m.calls++
	n := 0
	seen := map[string]bool{}
	for _, e := range events {
		if _, ok := m.rows[e.ID]; ok || seen[e.ID] {
			continue
		}
		seen[e.ID] = true
		n++
		if !dryRun {
			m.rows[e.ID] = e
		}
	}
	return n, nil
}

func TestRestoreBackups(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	line := func(seed, hp string) string {
		return fmt.Sprintf(`{"timestamp":"2026-11-10 12:00:00.000","honeypot":%q,"source_ip":"203.0.113.9","event_id":%q}`, hp, obsID(seed))
	}
	// Day one: three events, one of them written twice (the collector read
	// its line twice), a damaged line, an empty line, and a last line
	// without a newline. Day two: one event and one from before IDs.
	write("2026/11/10/cowrie.log", line("1", "cowrie")+"\n"+line("2", "cowrie")+"\n{cut off\n\n"+line("1", "cowrie")+"\n"+line("3", "cowrie"))
	write("2026/11/11/conpot.log", line("4", "conpot")+"\n"+`{"timestamp":"2026-11-11 01:00:00.000","honeypot":"conpot"}`+"\n")
	write("2026/11/11/notes.txt", "not a backup\n")
	huge := `{"timestamp":"2026-11-11 02:00:00.000","honeypot":"conpot","command":"` + strings.Repeat("x", maxBackupLine) + `"}`
	write("2026/11/12/conpot.log", huge+"\n"+line("5", "conpot")+"\n")

	store := &memoryStore{rows: map[string]*Event{obsID("2"): {ID: obsID("2")}}}
	rep, err := RestoreBackups(context.Background(), store, dir, RestoreOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(store.rows) != 1 {
		t.Fatalf("a dry run stored %d rows", len(store.rows)-1)
	}
	want := RestoreReport{Files: 3, Lines: 9, Stored: 5, AlreadyStored: 2, Unreadable: 2, FirstDay: "2026/11/10", LastDay: "2026/11/12", DryRun: true}
	if rep != want {
		t.Errorf("dry run report\n got %+v\nwant %+v", rep, want)
	}

	var seen []string
	rep, err = RestoreBackups(context.Background(), store, dir, RestoreOptions{Progress: func(file string, _ RestoreReport) { seen = append(seen, file) }})
	if err != nil {
		t.Fatal(err)
	}
	want.DryRun = false
	if rep != want {
		t.Errorf("report\n got %+v\nwant %+v", rep, want)
	}
	if len(store.rows) != 6 {
		t.Errorf("the store holds %d events, want 6", len(store.rows))
	}
	if strings.Join(seen, " ") != "2026/11/10/cowrie.log 2026/11/11/conpot.log 2026/11/12/conpot.log" {
		t.Errorf("files read: %v", seen)
	}

	// Again: everything is there already.
	rep, err = RestoreBackups(context.Background(), store, dir, RestoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Stored != 0 || rep.AlreadyStored != 7 || len(store.rows) != 6 {
		t.Errorf("second restore stored %d, skipped %d, store holds %d; want 0, 7, 6", rep.Stored, rep.AlreadyStored, len(store.rows))
	}

	if _, err := RestoreBackups(context.Background(), store, filepath.Join(dir, "missing"), RestoreOptions{}); err == nil {
		t.Error("a missing backup folder is not an error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RestoreBackups(ctx, store, dir, RestoreOptions{}); err == nil {
		t.Error("a cancelled restore reports success")
	}
}

// A restore batch is tried again only when the server says it is out of
// memory; any other refusal is the caller's to see at once.
func TestMemoryRefusal(t *testing.T) {
	if !memoryRefusal(fmt.Errorf("look up stored observations: %w", &clickhouse.Exception{Code: 241, Message: "(total) memory limit exceeded"})) {
		t.Error("a wrapped memory-limit exception is not recognised")
	}
	for _, err := range []error{nil, fmt.Errorf("plain"), &clickhouse.Exception{Code: 60, Message: "unknown table"}, context.DeadlineExceeded} {
		if memoryRefusal(err) {
			t.Errorf("%v counts as a memory refusal", err)
		}
	}
}
