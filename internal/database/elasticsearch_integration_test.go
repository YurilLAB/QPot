package database

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
)

// connectES connects to Elasticsearch from QPOT_TEST_ES_* env vars, skipping
// unless QPOT_TEST_ELASTIC=1, and starts from empty qpot-* indices.
func connectES(t *testing.T) *Elasticsearch {
	t.Helper()
	if os.Getenv("QPOT_TEST_ELASTIC") != "1" {
		t.Skip("set QPOT_TEST_ELASTIC=1 to run Elasticsearch integration tests")
	}
	port := 9200
	if p := os.Getenv("QPOT_TEST_ES_PORT"); p != "" {
		port, _ = strconv.Atoi(p)
	}
	es, _ := NewElasticsearch(&config.DatabaseConfig{Type: "elasticsearch",
		Host: envOr("QPOT_TEST_ES_HOST", "127.0.0.1"), Port: port})
	ctx := context.Background()
	if err := es.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	// ES 8 rejects wildcard deletes by default, so delete each index by name.
	data, _, err := es.esRequest(ctx, http.MethodGet, "/_cat/indices/qpot-*?h=index", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, idx := range strings.Fields(string(data)) {
		if _, status, err := es.esRequest(ctx, http.MethodDelete, "/"+idx, nil); err != nil || status >= 300 {
			t.Fatalf("delete index %s: status %d, %v", idx, status, err)
		}
	}
	if err := es.InitializeSchema(ctx); err != nil {
		t.Fatalf("InitializeSchema: %v", err)
	}
	t.Cleanup(func() { es.Close() })
	return es
}

func esRefresh(t *testing.T, es *Elasticsearch) {
	t.Helper()
	if _, _, err := es.esRequest(context.Background(), http.MethodPost, "/qpot-*/_refresh", nil); err != nil {
		t.Fatal(err)
	}
}

// Honeypot stats must report top commands, and event totals must not be
// capped at Elasticsearch's default 10,000 hit-count limit.
func TestESStatsCommandsAndTotals(t *testing.T) {
	es := connectES(t)
	ctx := context.Background()
	const n = 10050
	now := time.Now().UTC()
	events := make([]*Event, 0, n)
	for i := 0; i < n; i++ {
		events = append(events, &Event{Timestamp: now.Add(-time.Duration(i) * time.Millisecond),
			Honeypot: "cowrie", SourceIP: fmt.Sprintf("203.0.113.%d", i%200+1),
			EventType: "command", Command: fmt.Sprintf("uname -%c", 'a'+i%3)})
	}
	for i := 0; i < n; i += 2000 {
		end := min(i+2000, n)
		if err := es.InsertEvents(ctx, events[i:end]); err != nil {
			t.Fatalf("InsertEvents: %v", err)
		}
	}
	esRefresh(t, es)

	since := now.Add(-time.Hour)
	hs, err := es.GetHoneypotStats(ctx, "cowrie", since)
	if err != nil {
		t.Fatal(err)
	}
	if len(hs.Commands) == 0 {
		t.Error("GetHoneypotStats returned no top commands")
	}
	if hs.TotalEvents != n {
		t.Errorf("GetHoneypotStats TotalEvents = %d, want %d", hs.TotalEvents, n)
	}
	st, err := es.GetStats(ctx, since)
	if err != nil {
		t.Fatal(err)
	}
	if st.TotalEvents != n {
		t.Errorf("GetStats TotalEvents = %d, want %d", st.TotalEvents, n)
	}
}

// Attacker-shaped events (raw binary payload, empty or bogus source IP) must
// still be stored.
func TestESInsertAttackerShapedEvents(t *testing.T) {
	es := connectES(t)
	ctx := context.Background()
	now := time.Now().UTC()
	events := []*Event{
		{Timestamp: now, Honeypot: "dionaea", SourceIP: "203.0.113.9", EventType: "connect",
			Payload: []byte("\x00\x01SMB\xff\xferaw bytes")},
		{Timestamp: now, Honeypot: "cowrie", SourceIP: "", EventType: "session"},
		{Timestamp: now, Honeypot: "cowrie", SourceIP: "not-an-ip", EventType: "session"},
	}
	if err := es.InsertEvents(ctx, events); err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}
	esRefresh(t, es)
	got, err := es.GetEvents(ctx, EventFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(events) {
		t.Fatalf("stored %d of %d events", len(got), len(events))
	}
}

// IOC values are attacker-controlled; IDs built from them (URLs with '/', '?',
// '#', long commands) must still round-trip.
func TestESInsertIOCAwkwardIDs(t *testing.T) {
	es := connectES(t)
	ctx := context.Background()
	now := time.Now().UTC()
	vals := []string{"http://198.51.100.5/a/b.sh?x=1#frag", strings.Repeat("A", 40000)}
	for _, v := range vals {
		ioc := &IOC{ID: "url:" + v + ":cowrie", Type: "url", Value: v, Honeypot: "cowrie",
			FirstSeen: now, LastSeen: now, Count: 1}
		if err := es.InsertIOC(ctx, ioc); err != nil {
			t.Errorf("InsertIOC(%.40q): %v", v, err)
		}
	}
	esRefresh(t, es)
	got, err := es.GetIOCs(ctx, IOCFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(vals) {
		t.Fatalf("stored %d of %d IOCs", len(got), len(vals))
	}
}

func TestESIOCFilters(t *testing.T) {
	es := connectES(t)
	checkIOCValueAndSourceFilters(t, es, func() { esRefresh(t, es) })
}

func TestESTagsSameTimestampEventsSeparately(t *testing.T) {
	es := connectES(t)
	ip := fmt.Sprintf("198.51.100.%d", 100+time.Now().UnixNano()%100)
	checkSameMillisecondTagging(t, es, ip, func() {
		_, _, _ = es.esRequest(context.Background(), http.MethodPost, "/qpot-events-*/_refresh", nil)
	})
}
