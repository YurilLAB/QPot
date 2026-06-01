package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
)

// TestServerServesDataFromClickHouse is a full-stack integration test: a real
// server (New) backed by a real ClickHouse serves inserted events/stats through
// the authenticated API. Gated on QPOT_TEST_CLICKHOUSE=1.
func TestServerServesDataFromClickHouse(t *testing.T) {
	if os.Getenv("QPOT_TEST_CLICKHOUSE") != "1" {
		t.Skip("set QPOT_TEST_CLICKHOUSE=1 to run the full-stack ClickHouse test")
	}
	port := 9000
	if p := os.Getenv("QPOT_TEST_CH_PORT"); p != "" {
		port, _ = strconv.Atoi(p)
	}
	host := os.Getenv("QPOT_TEST_CH_HOST")
	if host == "" {
		host = "127.0.0.1"
	}

	cfg := config.Default("srv-integration")
	cfg.QPotID = validTestID
	cfg.WebUI.QPotIDAuth = true
	cfg.Intelligence.Enabled = false // keep the test focused on the data API
	cfg.Database.Type = "clickhouse"
	cfg.Database.Host = host
	cfg.Database.Port = port
	cfg.Database.Username = envOrCH("QPOT_TEST_CH_USER", "qpot")
	cfg.Database.Password = envOrCH("QPOT_TEST_CH_PASS", "qpotpass")
	cfg.Database.Database = envOrCH("QPOT_TEST_CH_DB", "qpot")

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if s.database == nil {
		t.Fatal("server came up without a database connection (ClickHouse not reachable?)")
	}

	// Seed a couple of events directly through the DB layer.
	ctx := context.Background()
	if err := s.database.InsertEvents(ctx, []*database.Event{
		{Timestamp: time.Now().UTC(), Honeypot: "cowrie", SourceIP: "203.0.113.50", DestPort: 22, Protocol: "ssh", EventType: "login_failed", Username: "root"},
		{Timestamp: time.Now().UTC(), Honeypot: "cowrie", SourceIP: "2001:db8::1", DestPort: 23, Protocol: "telnet", EventType: "command", Command: "id"},
	}); err != nil {
		t.Fatalf("seed InsertEvents: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	ts := httptest.NewServer(s.authMiddleware(s.mux))
	defer ts.Close()
	client := ts.Client()

	do := func(path string) map[string]interface{} {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		req.Header.Set("X-QPot-ID", validTestID)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status %d, want 200", path, resp.StatusCode)
		}
		var m map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
			t.Fatalf("GET %s: decode: %v", path, err)
		}
		return m
	}

	// /api/events must return the seeded events.
	ev := do("/api/events?honeypot=cowrie&limit=50")
	events, _ := ev["events"].([]interface{})
	if len(events) == 0 {
		t.Error("/api/events returned no events after seeding")
	}

	// /api/stats must reflect a positive total.
	st := do("/api/stats")
	if tot, _ := st["total_events"].(float64); tot <= 0 {
		t.Errorf("/api/stats total_events=%v, want >0", st["total_events"])
	}
}

func envOrCH(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
