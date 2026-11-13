package database

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestClickHouseRemovesReplayedEvents stores, the way the collector does,
// every way one observation can end up as two rows, and checks which rows
// RemoveReplayedEvents deletes. Establishes for the real store what
// FuzzPlanReplays checks for the plan: the copy that stays is never touched.
func TestClickHouseRemovesReplayedEvents(t *testing.T) {
	db := connectCH(t)
	ch := db.(*ClickHouse)
	ctx := context.Background()
	marker := fmt.Sprintf("replay-%d", time.Now().UnixNano())
	id := func(name string) string { return obsID(marker + name) }
	send := func(values ...string) {
		t.Helper()
		if err := ch.conn.Exec(ctx, `INSERT INTO events (timestamp, honeypot, source_ip, event_type, command, event_id) VALUES `+strings.Join(values, ", ")); err != nil {
			t.Fatal(err)
		}
	}
	row := func(at, command, eventID string) string {
		return fmt.Sprintf("('2026-11-12 10:00:%s', 'cowrie', '198.51.100.91', '%s', '%s', '%s')", at, marker, command, eventID)
	}
	unclassified := func() []*Event {
		t.Helper()
		rows, err := ch.conn.Query(ctx, `SELECT timestamp, command, toString(event_id) FROM events WHERE event_type = ? AND classified = 0 ORDER BY timestamp ASC, command ASC`, marker)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []*Event
		for rows.Next() {
			e := &Event{Honeypot: "cowrie", EventType: marker}
			if err := rows.Scan(&e.Timestamp, &e.Command, &e.ID); err != nil {
				t.Fatal(err)
			}
			out = append(out, e)
		}
		return out
	}
	commands := func(where string) string {
		t.Helper()
		rows, err := ch.conn.Query(ctx, `SELECT command FROM events WHERE event_type = ? AND `+where+` ORDER BY timestamp ASC, command ASC`, marker)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatal(err)
			}
			out = append(out, c)
		}
		return strings.Join(out, " ")
	}

	var index uint64
	if err := ch.conn.QueryRow(ctx, `SELECT count() FROM system.data_skipping_indices WHERE database = currentDatabase() AND table = 'events' AND name = ?`, eventIDIndex).Scan(&index); err != nil || index != 1 {
		t.Fatalf("the events table has %d observation indexes (%v), want 1", index, err)
	}

	// a: counted earlier (classified), then read again.
	send(row("00.000", "a-first", id("a")))
	first := unclassified()
	if len(first) != 1 {
		t.Fatalf("setup: %d unclassified rows, want 1", len(first))
	}
	first[0].TechniqueID = "T1059"
	if err := db.(BatchTagger).TagEvents(ctx, first); err != nil {
		t.Fatal(err)
	}
	send(row("05.000", "a-again", id("a")))
	// b: read twice before it was ever counted.
	send(row("10.000", "b-first", id("b")))
	send(row("17.000", "b-again", id("b")))
	// c: once.
	send(row("20.000", "c-only", id("c")))
	// d: two rows that share a random ID from the database, not an
	// observation ID. Nothing may be concluded from that.
	send(row("30.000", "d-one", "0d0d0d0d-0000-4000-8000-00000000000d"))
	send(row("31.000", "d-two", "0d0d0d0d-0000-4000-8000-00000000000d"))
	// e: twice with the same ID and time, in different insert blocks (as if
	// insert deduplication had not caught a retry). The two rows cannot be
	// told apart, so neither may be deleted.
	send(row("40.000", "e-twin", id("e")), row("41.000", "filler-1", id("f1")))
	send(row("40.000", "e-twin", id("e")), row("42.000", "filler-2", id("f2")))

	events := unclassified()
	if len(events) != 10 {
		t.Fatalf("setup: %d unclassified rows, want 10", len(events))
	}
	kept, removed, err := db.(ReplayRemover).RemoveReplayedEvents(ctx, events)
	if err != nil {
		t.Fatal(err)
	}
	var keptCommands []string
	for _, e := range kept {
		keptCommands = append(keptCommands, e.Command)
	}
	if got, want := strings.Join(keptCommands, " "), "b-first c-only d-one d-two e-twin filler-1 filler-2"; got != want {
		t.Errorf("events to classify: %s\nwant:               %s", got, want)
	}
	if removed != 2 {
		t.Errorf("removed %d rows, want 2", removed)
	}
	if got, want := commands("1"), "a-first b-first c-only d-one d-two e-twin e-twin filler-1 filler-2"; got != want {
		t.Errorf("rows left:  %s\nwant:       %s", got, want)
	}
	if got := commands("classified = 1"); got != "a-first" {
		t.Errorf("classified rows: %q, want only a-first", got)
	}

	// Again, and from a stale list (a second worker with the old batch):
	// nothing more goes.
	if _, removed, err := db.(ReplayRemover).RemoveReplayedEvents(ctx, events); err != nil || removed != 2 {
		// The stale plan names the same two rows; they are gone already.
		t.Errorf("stale batch: removed %d, %v; want the same 2 named", removed, err)
	}
	if kept, removed, err := db.(ReplayRemover).RemoveReplayedEvents(ctx, unclassified()); err != nil || removed != 0 || len(kept) != 7 {
		t.Errorf("second pass: kept %d, removed %d, %v; want 7, 0", len(kept), removed, err)
	}
	if got, want := commands("1"), "a-first b-first c-only d-one d-two e-twin e-twin filler-1 filler-2"; got != want {
		t.Errorf("rows after a second pass: %s\nwant:                     %s", got, want)
	}
}

// chMarkerRows returns helpers for a test's own rows in the shared events
// table: send stores rows, row writes one, unclassified reads the test's
// unclassified rows oldest first, and commands lists the test's rows that
// match where.
func chMarkerRows(t *testing.T, ch *ClickHouse, marker string) (send func(values ...string), row func(at, command, eventID string) string,
	unclassified func() []*Event, commands func(where string) string) {
	ctx := context.Background()
	send = func(values ...string) {
		t.Helper()
		if err := ch.conn.Exec(ctx, `INSERT INTO events (timestamp, honeypot, source_ip, event_type, command, event_id) VALUES `+strings.Join(values, ", ")); err != nil {
			t.Fatal(err)
		}
	}
	row = func(at, command, eventID string) string {
		return fmt.Sprintf("('2026-11-12 10:00:%s', 'cowrie', '198.51.100.92', '%s', '%s', '%s')", at, marker, command, eventID)
	}
	unclassified = func() []*Event {
		t.Helper()
		rows, err := ch.conn.Query(ctx, `SELECT timestamp, command, toString(event_id) FROM events WHERE event_type = ? AND classified = 0 ORDER BY timestamp ASC, command ASC`, marker)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []*Event
		for rows.Next() {
			e := &Event{Honeypot: "cowrie", EventType: marker}
			if err := rows.Scan(&e.Timestamp, &e.Command, &e.ID); err != nil {
				t.Fatal(err)
			}
			out = append(out, e)
		}
		return out
	}
	commands = func(where string) string {
		t.Helper()
		rows, err := ch.conn.Query(ctx, `SELECT command FROM events WHERE event_type = ? AND `+where+` ORDER BY timestamp ASC, command ASC`, marker)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatal(err)
			}
			out = append(out, c)
		}
		return strings.Join(out, " ")
	}
	return send, row, unclassified, commands
}

// TestClickHouseTaggingLeavesOneRowPerObservation: a line the collector read
// twice before either copy was classified is two rows with the same ID and
// time, which no column tells apart. Tagging marks both; afterwards one row
// must be left, classified, with its tags. With lightweight updates and with
// the mutations a server without them gets.
func TestClickHouseTaggingLeavesOneRowPerObservation(t *testing.T) {
	for _, patch := range []bool{true, false} {
		t.Run(fmt.Sprintf("lightweight=%v", patch), func(t *testing.T) {
			db := connectCH(t)
			ch := db.(*ClickHouse)
			ctx := context.Background()
			if !ch.patchUpdates {
				t.Fatal("the events table of the pinned server takes no lightweight updates")
			}
			ch.patchUpdates = patch
			marker := fmt.Sprintf("twins-%v-%d", patch, time.Now().UnixNano())
			id := func(name string) string { return obsID(marker + name) }
			send, row, unclassified, commands := chMarkerRows(t, ch, marker)
			// Two insert blocks, as two collector batches: the twin in both.
			send(row("40.000", "e-twin", id("e")), row("41.000", "filler-1", id("f1")))
			send(row("40.000", "e-twin", id("e")), row("42.000", "filler-2", id("f2")))
			events := unclassified()
			kept, _, err := db.(ReplayRemover).RemoveReplayedEvents(ctx, events)
			if err != nil {
				t.Fatal(err)
			}
			if len(kept) != 3 {
				t.Fatalf("events to classify: %d, want 3 (the twin once)", len(kept))
			}
			for _, e := range kept {
				e.TechniqueID, e.Categories, e.Classified = "T1059", []string{"execution"}, true
			}
			for round := 1; round <= 2; round++ {
				// The second round is the worker replaying its checkpoint
				// after a crash: nothing more may go.
				if err := db.(BatchTagger).TagEvents(ctx, kept); err != nil {
					t.Fatal(err)
				}
				if got, want := commands("1"), "e-twin filler-1 filler-2"; got != want {
					t.Fatalf("round %d: rows left: %s\nwant:                %s", round, got, want)
				}
				if got := commands("classified = 1 AND technique_id = 'T1059' AND has(categories, 'execution')"); got != "e-twin filler-1 filler-2" {
					t.Fatalf("round %d: tagged rows: %q", round, got)
				}
			}
			// A copy that arrives after the tag is unclassified and removed
			// like any other second copy.
			send(row("40.000", "e-twin", id("e")))
			if _, removed, err := db.(ReplayRemover).RemoveReplayedEvents(ctx, unclassified()); err != nil || removed != 1 {
				t.Fatalf("a copy after tagging: removed %d, %v; want 1", removed, err)
			}
			if got := commands("1"); got != "e-twin filler-1 filler-2" {
				t.Errorf("rows left at the end: %s", got)
			}
		})
	}
}

// TestClickHouseSweepsReplayedEvents: the sweep removes every unclassified
// row whose observation is already classified, wherever it is, in windows
// smaller than the table, and nothing else.
func TestClickHouseSweepsReplayedEvents(t *testing.T) {
	db := connectCH(t)
	ch := db.(*ClickHouse)
	ctx := context.Background()
	savedWindow, savedProbe := sweepWindow, sweepProbe
	sweepWindow, sweepProbe = 3, 3
	t.Cleanup(func() { sweepWindow, sweepProbe = savedWindow, savedProbe })
	marker := fmt.Sprintf("sweep-%d", time.Now().UnixNano())
	id := func(name string) string { return obsID(marker + name) }
	random := "0e0e0e0e-0000-4000-8000-00000000000e"
	send, row, unclassified, commands := chMarkerRows(t, ch, marker)

	// Classified first: a, b and a row with a random ID from the database.
	send(row("00.000", "a-first", id("a")), row("01.000", "b-first", id("b")), row("02.000", "r-first", random))
	first := unclassified()
	for _, e := range first {
		e.TechniqueID, e.Classified = "T1110", true
	}
	if err := db.(BatchTagger).TagEvents(ctx, first); err != nil {
		t.Fatal(err)
	}
	// Then what the collector sends again, older than an unclassified
	// backlog (c, d) the worker has not reached: a with its own time, b with
	// another, and a row that only shares the random ID.
	send(row("00.000", "a-again", id("a")), row("09.000", "b-again", id("b")), row("02.000", "r-again", random))
	send(row("30.000", "c-only", id("c")), row("31.000", "d-one", id("d")), row("32.000", "d-two", id("d")))

	var unclassifiedRows uint64
	if err := ch.conn.QueryRow(ctx, `SELECT count() FROM events WHERE classified = 0`).Scan(&unclassifiedRows); err != nil {
		t.Fatal(err)
	}
	// Rounds over every unclassified row of the shared table (windows overlap
	// by the rows of their last time).
	removed := 0
	for i := uint64(0); i < 4*(unclassifiedRows/uint64(sweepWindow)+2); i++ {
		n, err := db.(ReplaySweeper).SweepReplayedEvents(ctx)
		if err != nil {
			t.Fatal(err)
		}
		removed += n
	}
	if removed < 2 {
		t.Errorf("the sweep removed %d rows, want at least the 2 copies", removed)
	}
	if got, want := commands("1"), "a-first b-first r-again r-first c-only d-one d-two"; got != want {
		t.Errorf("rows left: %s\nwant:       %s", got, want)
	}
	if got := commands("classified = 1"); got != "a-first b-first r-first" {
		t.Errorf("classified rows: %q", got)
	}
}

// TestClickHouseRestoreEvents: restoring stores what is missing, with the
// event's own time and ID, and nothing twice.
func TestClickHouseRestoreEvents(t *testing.T) {
	db := connectCH(t)
	ch := db.(*ClickHouse)
	ctx := context.Background()
	marker := fmt.Sprintf("restore-%d", time.Now().UnixNano())
	at := time.Date(2026, 11, 10, 8, 30, 15, 123e6, time.UTC)
	ev := func(n int) *Event {
		return &Event{ID: obsID(fmt.Sprint(marker, n)), Timestamp: at.Add(time.Duration(n) * time.Second), Honeypot: "cowrie",
			SourceIP: "198.51.100.92", SourcePort: 40000 + n, DestPort: 22, Protocol: "ssh", EventType: marker,
			Username: "root", Password: "pw", Command: fmt.Sprint("cmd-", n), Payload: []byte(`a\zb`), Metadata: map[string]string{"session": "s1"}, Country: "AU"}
	}
	count := func() uint64 {
		t.Helper()
		var n uint64
		if err := ch.conn.QueryRow(ctx, `SELECT count() FROM events WHERE event_type = ?`, marker).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	r := db.(EventRestorer)
	batch := []*Event{ev(1), ev(2), ev(2), ev(3)} // the backup holds one line twice
	if n, err := r.RestoreEvents(ctx, batch, true); err != nil || n != 3 || count() != 0 {
		t.Fatalf("dry run: would store %d (%v), stored %d; want 3, 0", n, err, count())
	}
	if n, err := r.RestoreEvents(ctx, batch, false); err != nil || n != 3 || count() != 3 {
		t.Fatalf("restore: stored %d (%v), table has %d; want 3, 3", n, err, count())
	}
	if n, err := r.RestoreEvents(ctx, append(batch, ev(4)), false); err != nil || n != 1 || count() != 4 {
		t.Fatalf("restore again: stored %d (%v), table has %d; want 1, 4", n, err, count())
	}
	var (
		ts         time.Time
		id, cmd    string
		port       uint16
		classified uint8
		meta       map[string]string
		payload    string
	)
	if err := ch.conn.QueryRow(ctx, `SELECT timestamp, toString(event_id), command, source_port, classified, metadata, payload FROM events WHERE event_type = ? AND command = 'cmd-2'`, marker).
		Scan(&ts, &id, &cmd, &port, &classified, &meta, &payload); err != nil {
		t.Fatal(err)
	}
	if !ts.Equal(at.Add(2*time.Second)) || id != ev(2).ID || port != 40002 || classified != 0 || meta["session"] != "s1" || payload != `a\zb` {
		t.Errorf("restored row: time %s id %s port %d classified %d metadata %v payload %q", ts, id, port, classified, meta, payload)
	}
	if n, err := r.CountEvents(ctx); err != nil || n < 4 {
		t.Errorf("CountEvents = %d, %v", n, err)
	}
}

// TestPGIngestStoresARetriedBatchOnce is the PostgreSQL side of the retried
// batch: the collector's insert statement, sent twice.
func TestPGIngestStoresARetriedBatchOnce(t *testing.T) {
	ts := connectPG(t)
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := ts.pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", strings.Fields(q)[0], err)
		}
	}
	count := func() int {
		t.Helper()
		var n int
		if err := ts.pool.QueryRow(ctx, `SELECT count(*) FROM events`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	a, b := obsID("pg-a"), obsID("pg-b")
	batch := func(at string) string {
		return `[{"timestamp":"2026-11-12 05:28:03.341+00","honeypot":"cowrie","source_ip":"203.0.113.9","command":"uname -a","payload":"\\x61","metadata":{"session":"s1"},"event_id":"` + a + `","message":"raw"},
			{"timestamp":"` + at + `","honeypot":"cowrie","source_ip":"203.0.113.9","command":"id","payload":"\\x61","event_id":"` + b + `"}]`
	}
	const sinkInsert = `INSERT INTO events_ingest SELECT * FROM jsonb_populate_recordset(NULL::events_ingest, $1)`

	// Control: the view alone, as it was. A repeated batch is stored twice.
	exec(eventsIngestViewSQL)
	exec(sinkInsert, batch("2026-11-12 05:28:04.000+00"))
	exec(sinkInsert, batch("2026-11-12 05:28:04.000+00"))
	if got := count(); got != 4 {
		t.Fatalf("without the index and trigger a repeated batch is stored as %d rows, expected 4: this test no longer shows the defect", got)
	}
	exec(`DELETE FROM events`)

	exec(eventsIngestTriggerSQL)
	exec(eventsObservationIndexSQL)
	exec(sinkInsert, batch("2026-11-12 05:28:04.000+00"))
	exec(sinkInsert, batch("2026-11-12 05:28:04.000+00"))
	exec(sinkInsert, batch("2026-11-12 05:28:04.000+00"))
	if got := count(); got != 2 {
		t.Fatalf("a batch sent three times is stored as %d rows, want 2", got)
	}
	// An event without an ID (an older collector) still goes in, each time.
	old := `[{"timestamp":"2026-11-12 05:30:00.000+00","honeypot":"cowrie","command":"old"}]`
	exec(sinkInsert, old)
	exec(sinkInsert, old)
	if got := count(); got != 4 {
		t.Fatalf("events without an ID: %d rows, want 4", got)
	}
	// The second observation read again later: a new time, so a new row,
	// which the worker's pass then removes.
	exec(sinkInsert, batch("2026-11-12 05:40:00.000+00"))
	if got := count(); got != 5 {
		t.Fatalf("a line read again is stored as %d rows in all, want 5", got)
	}
	events, err := ts.GetUnclassifiedEvents(ctx, 100)
	if err != nil || len(events) != 5 {
		t.Fatalf("GetUnclassifiedEvents = %d, %v", len(events), err)
	}
	kept, removed, err := ts.RemoveReplayedEvents(ctx, events)
	if err != nil || removed != 1 || len(kept) != 4 {
		t.Fatalf("RemoveReplayedEvents kept %d, removed %d, %v; want 4, 1", len(kept), removed, err)
	}
	var at time.Time
	if err := ts.pool.QueryRow(ctx, `SELECT timestamp FROM events WHERE event_id = $1`, b).Scan(&at); err != nil {
		t.Fatalf("the observation read twice has not exactly one row left: %v", err)
	}
	if want := time.Date(2026, 11, 12, 5, 28, 4, 0, time.UTC); !at.Equal(want) {
		t.Errorf("the copy that stayed is from %s, want the first one (%s)", at, want)
	}
	// A classified copy always stays, whatever its time.
	exec(`UPDATE events SET classified = TRUE WHERE event_id = $1`, b)
	exec(`INSERT INTO events (timestamp, honeypot, command, event_id) VALUES ('2026-11-12 05:00:00+00', 'cowrie', 'earlier copy', $1)`, b)
	events, err = ts.GetUnclassifiedEvents(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, removed, err := ts.RemoveReplayedEvents(ctx, events); err != nil || removed != 1 {
		t.Fatalf("copy of a classified observation: removed %d, %v; want 1", removed, err)
	}
	var classified bool
	if err := ts.pool.QueryRow(ctx, `SELECT classified FROM events WHERE event_id = $1`, b).Scan(&classified); err != nil || !classified {
		t.Errorf("the classified row did not stay alone: classified=%v, %v", classified, err)
	}
	if _, removed, err := ts.RemoveReplayedEvents(ctx, events); err != nil || removed != 0 {
		t.Errorf("stale batch: removed %d, %v; want 0", removed, err)
	}
}

func TestPGRestoreEvents(t *testing.T) {
	ts := connectPG(t)
	ctx := context.Background()
	if _, err := ts.pool.Exec(ctx, eventsObservationIndexSQL); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 10, 8, 30, 15, 123e6, time.UTC)
	ev := func(n int) *Event {
		return &Event{ID: obsID(fmt.Sprint("pg-restore", n)), Timestamp: at.Add(time.Duration(n) * time.Second), Honeypot: "cowrie",
			SourceIP: "198.51.100.92", SourcePort: 40000 + n, DestPort: 22, Protocol: "ssh", EventType: "cowrie.command.input",
			Command: fmt.Sprint("cmd-", n), Payload: []byte("a\\zb"), Metadata: map[string]string{"session": "s\x00 1"}}
	}
	batch := []*Event{ev(1), ev(2), ev(2), ev(3)}
	if n, err := ts.RestoreEvents(ctx, batch, true); err != nil || n != 3 {
		t.Fatalf("dry run: %d, %v", n, err)
	}
	if n, _ := ts.CountEvents(ctx); n != 0 {
		t.Fatalf("a dry run stored %d rows", n)
	}
	if n, err := ts.RestoreEvents(ctx, batch, false); err != nil || n != 3 {
		t.Fatalf("restore: %d, %v", n, err)
	}
	if n, err := ts.RestoreEvents(ctx, append(batch, ev(4)), false); err != nil || n != 1 {
		t.Fatalf("restore again: %d, %v", n, err)
	}
	if n, err := ts.CountEvents(ctx); err != nil || n != 4 {
		t.Fatalf("CountEvents = %d, %v; want 4", n, err)
	}
	got, err := ts.GetUnclassifiedEvents(ctx, 10)
	if err != nil || len(got) != 4 {
		t.Fatalf("restored events are not all unclassified: %d, %v", len(got), err)
	}
	if !got[1].Timestamp.Equal(at.Add(2*time.Second)) || got[1].Command != "cmd-2" || string(got[1].Payload) != "a\\zb" || got[1].SourcePort != 40002 {
		t.Errorf("restored row: %+v", got[1])
	}
}

// TestPGHypertableStoresARetriedBatchOnce runs the production schema setup on
// a server that has TimescaleDB, where events is a hypertable: its unique
// index must include the time, and the collector's insert goes through the
// view's trigger.
func TestPGHypertableStoresARetriedBatchOnce(t *testing.T) {
	ts := connectPG(t)
	ctx := context.Background()
	var available int
	if err := ts.pool.QueryRow(ctx, `SELECT count(*) FROM pg_available_extensions WHERE name = 'timescaledb'`).Scan(&available); err != nil || available == 0 {
		t.Skip("this server has no TimescaleDB extension")
	}
	if _, err := ts.pool.Exec(ctx, `DROP TABLE IF EXISTS events CASCADE`); err != nil {
		t.Fatal(err)
	}
	if err := ts.InitializeSchema(ctx); err != nil {
		t.Fatalf("InitializeSchema: %v", err)
	}
	var hypertables int
	if err := ts.pool.QueryRow(ctx, `SELECT count(*) FROM timescaledb_information.hypertables WHERE hypertable_name = 'events'`).Scan(&hypertables); err != nil || hypertables != 1 {
		t.Fatalf("events is not a hypertable (%d, %v): the test would prove nothing", hypertables, err)
	}
	a := obsID("hyper-a")
	batch := `[{"timestamp":"2026-11-12 05:28:03.341+00","honeypot":"cowrie","source_ip":"203.0.113.9","command":"uname -a","event_id":"` + a + `"}]`
	const sinkInsert = `INSERT INTO events_ingest SELECT * FROM jsonb_populate_recordset(NULL::events_ingest, $1)`
	for i := 0; i < 3; i++ {
		if _, err := ts.pool.Exec(ctx, sinkInsert, batch); err != nil {
			t.Fatalf("sink-style insert %d: %v", i+1, err)
		}
	}
	if n, err := ts.CountEvents(ctx); err != nil || n != 1 {
		t.Fatalf("a batch sent three times is stored as %d rows (%v), want 1", n, err)
	}
	// Read again later, then removed; then restored from a backup: still one.
	again := strings.Replace(batch, "05:28:03.341", "06:00:00.000", 1)
	if _, err := ts.pool.Exec(ctx, sinkInsert, again); err != nil {
		t.Fatal(err)
	}
	events, err := ts.GetUnclassifiedEvents(ctx, 10)
	if err != nil || len(events) != 2 {
		t.Fatalf("GetUnclassifiedEvents = %d, %v; want 2", len(events), err)
	}
	if kept, removed, err := ts.RemoveReplayedEvents(ctx, events); err != nil || removed != 1 || len(kept) != 1 {
		t.Fatalf("RemoveReplayedEvents kept %d, removed %d, %v", len(kept), removed, err)
	}
	if n, err := ts.RestoreEvents(ctx, []*Event{{ID: a, Timestamp: time.Date(2026, 11, 12, 5, 28, 3, 341e6, time.UTC), Honeypot: "cowrie"}}, false); err != nil || n != 0 {
		t.Fatalf("restoring a stored observation stored %d, %v", n, err)
	}
	if n, err := ts.RestoreEvents(ctx, []*Event{{ID: obsID("hyper-b"), Timestamp: time.Date(2026, 11, 12, 5, 28, 3, 341e6, time.UTC), Honeypot: "cowrie", SourceIP: "203.0.113.9"}}, false); err != nil || n != 1 {
		t.Fatalf("restoring a missing observation stored %d, %v", n, err)
	}
	if n, _ := ts.CountEvents(ctx); n != 2 {
		t.Fatalf("the hypertable holds %d rows, want 2", n)
	}
}

// TestClickHouseRestoredRowsAreNotSecondCopies: the events table lost rows
// the worker had classified (a part detached after a crash, a partition
// dropped), the set of classified IDs still knows them, and a restore brings
// the rows back. They are the only copies there are: neither the sweep nor
// the worker's own check may delete them, and the worker classifies them
// again.
func TestClickHouseRestoredRowsAreNotSecondCopies(t *testing.T) {
	db := connectCH(t)
	ch := db.(*ClickHouse)
	ctx := context.Background()
	savedWindow, savedProbe := sweepWindow, sweepProbe
	sweepWindow, sweepProbe = 3, 3
	t.Cleanup(func() { sweepWindow, sweepProbe = savedWindow, savedProbe })
	marker := fmt.Sprintf("lost-%d", time.Now().UnixNano())
	at := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	ev := func(n int) *Event {
		return &Event{ID: obsID(fmt.Sprint(marker, n)), Timestamp: at.Add(time.Duration(n) * time.Second), Honeypot: "cowrie",
			SourceIP: "198.51.100.93", DestPort: 22, Protocol: "ssh", EventType: marker, Command: fmt.Sprint("cmd-", n)}
	}
	count := func(where string) uint64 {
		t.Helper()
		var n uint64
		if err := ch.conn.QueryRow(ctx, `SELECT count() FROM events WHERE event_type = ? AND `+where, marker).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	known := func() int {
		t.Helper()
		got, err := ch.knownClassified(ctx, []string{ev(1).ID, ev(2).ID, ev(3).ID})
		if err != nil {
			t.Fatal(err)
		}
		return len(got)
	}
	tag := func(events ...*Event) {
		t.Helper()
		for _, e := range events {
			e.TechniqueID, e.Classified = "T1110", true
		}
		if err := db.(BatchTagger).TagEvents(ctx, events); err != nil {
			t.Fatal(err)
		}
	}
	r := db.(EventRestorer)
	if n, err := r.RestoreEvents(ctx, []*Event{ev(1), ev(2), ev(3)}, false); err != nil || n != 3 {
		t.Fatalf("first restore stored %d, %v; want 3", n, err)
	}
	// The worker classifies 1 and 2; the set knows them.
	tag(ev(1), ev(2))
	if count("classified = 1") != 2 || known() != 2 {
		t.Fatalf("after tagging: %d classified rows, %d IDs in the set; want 2 and 2", count("classified = 1"), known())
	}
	// The table loses both rows; the set does not.
	if err := ch.conn.Exec(ctx, `ALTER TABLE events DELETE WHERE event_type = ? AND classified = 1 SETTINGS mutations_sync = 2`, marker); err != nil {
		t.Fatal(err)
	}
	if count("1") != 1 || known() != 2 {
		t.Fatalf("after the loss: %d rows, %d IDs in the set; want 1 and 2", count("1"), known())
	}
	// A dry run changes nothing, the set included.
	if n, err := r.RestoreEvents(ctx, []*Event{ev(1), ev(2), ev(3)}, true); err != nil || n != 2 || known() != 2 {
		t.Fatalf("dry run: would store %d (%v), set knows %d; want 2, 2", n, err, known())
	}
	if n, err := r.RestoreEvents(ctx, []*Event{ev(1), ev(2), ev(3)}, false); err != nil || n != 2 {
		t.Fatalf("restore after the loss stored %d, %v; want 2", n, err)
	}
	if known() != 0 {
		t.Fatalf("the set still knows %d of the restored IDs: their rows would be deleted as second copies", known())
	}
	// Every round of the sweep over the shared table, then the worker's own
	// check of what it reads.
	var unclassifiedRows uint64
	if err := ch.conn.QueryRow(ctx, `SELECT count() FROM events WHERE classified = 0`).Scan(&unclassifiedRows); err != nil {
		t.Fatal(err)
	}
	for i := uint64(0); i < 4*(unclassifiedRows/uint64(sweepWindow)+2); i++ {
		if _, err := db.(ReplaySweeper).SweepReplayedEvents(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if kept, removed, err := db.(ReplayRemover).RemoveReplayedEvents(ctx, []*Event{ev(1), ev(2), ev(3)}); err != nil || removed != 0 || len(kept) != 3 {
		t.Fatalf("RemoveReplayedEvents kept %d, removed %d, %v; want 3, 0", len(kept), removed, err)
	}
	if count("1") != 3 || count("classified = 0") != 3 {
		t.Fatalf("restored rows left: %d (%d unclassified); want 3 and 3", count("1"), count("classified = 0"))
	}
	// Classified again, each is one row the set knows.
	tag(ev(1), ev(2), ev(3))
	if count("1") != 3 || count("classified = 1") != 3 || known() != 3 {
		t.Fatalf("after classifying the restored rows: %d rows, %d classified, %d in the set; want 3, 3, 3", count("1"), count("classified = 1"), known())
	}
}
