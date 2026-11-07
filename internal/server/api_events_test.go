package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
)

// filterDB records the filter GetEvents gets and returns n events.
type filterDB struct {
	fakeDB
	mu  sync.Mutex
	got []database.EventFilter
	n   int
}

func (f *filterDB) GetEvents(_ context.Context, fl database.EventFilter) ([]*database.Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, fl)
	n := f.n
	if fl.Limit > 0 && n > fl.Limit {
		n = fl.Limit
	}
	out := make([]*database.Event, n)
	for i := range out {
		out[i] = &database.Event{Honeypot: "cowrie", SourceIP: "203.0.113.5", Timestamp: time.Unix(int64(1000-i), 0).UTC()}
	}
	return out, nil
}

func (f *filterDB) last() database.EventFilter {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.got[len(f.got)-1]
}

func TestParseEventFilter(t *testing.T) {
	q := url.Values{
		"honeypot":   {"cowrie,dionaea", "canary"},
		"source_ip":  {"203.0.113.5", "2001:DB8:0::1"},
		"event_type": {"login.failed", "cowrie.command.input"},
		"country":    {"de,us"},
		"since":      {"2026-11-01T00:00:00Z"},
		"until":      {"1794096000"},
		"q":          {`wget 'http://x/%_\`},
		"limit":      {"50"},
		"offset":     {"100"},
	}
	f, err := parseEventFilter(q)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.Honeypots, ",") != "cowrie,dionaea,canary" || strings.Join(f.SourceIPs, ",") != "203.0.113.5,2001:db8::1" || len(f.EventTypes) != 2 ||
		strings.Join(f.Countries, ",") != "DE,US" || f.Text != `wget 'http://x/%_\` || f.Limit != 50 || f.Offset != 100 ||
		!f.StartTime.Equal(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) || f.EndTime.Unix() != 1794096000 {
		t.Fatalf("filter: %+v", f)
	}
	if f, err := parseEventFilter(url.Values{}); err != nil || f.Limit != defaultEventLimit || f.Offset != 0 {
		t.Fatalf("defaults: %+v %v", f, err)
	}

	many := make([]string, maxEventFilterValues+1)
	for i := range many {
		many[i] = fmt.Sprintf("hp%d", i)
	}
	for _, bad := range []url.Values{
		{"honeypot": {"<script>"}}, {"honeypot": {"Cowrie"}}, {"honeypot": {strings.Join(many, ",")}},
		{"source_ip": {"203.0.113.5' OR 1=1"}}, {"source_ip": {"example.com"}}, {"source_ip": {"fe80::1%eth0"}},
		{"event_type": {"a b"}}, {"event_type": {"x;DROP"}}, {"country": {"DEU"}}, {"country": {"1A"}},
		{"since": {"yesterday"}}, {"until": {"-5"}}, {"since": {"2026-11-02T00:00:00Z"}, "until": {"2026-11-01T00:00:00Z"}},
		{"q": {strings.Repeat("a", database.MaxEventText+1)}}, {"q": {"a\x00b"}}, {"q": {"a\nb"}}, {"q": {"\xff"}},
		{"limit": {"0"}}, {"limit": {"1001"}}, {"limit": {"ten"}}, {"offset": {"-1"}}, {"offset": {"100001"}},
	} {
		if _, err := parseEventFilter(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestEventsEndpoint(t *testing.T) {
	a := newAPITestServer(t, "api-events", nil)
	db := &filterDB{n: 3}
	a.s.database = db
	assertAuthRequired(t, a.h, http.MethodGet, "/api/events", "")
	if rec := a.do(http.MethodPost, "/api/events", `{}`); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rec.Code)
	}

	rec := a.do(http.MethodGet, "/api/events?honeypot=cowrie&q=root&limit=2&offset=4", "")
	var page eventsPage
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &page) != nil {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body.String())
	}
	if len(page.Events) != 2 || !page.HasMore || page.NextOffset != 6 || page.Limit != 2 || page.Offset != 4 {
		t.Fatalf("page: %+v", page)
	}
	if got := db.last(); got.Limit != 3 || got.Offset != 4 || got.Text != "root" || len(got.Honeypots) != 1 {
		t.Fatalf("filter sent: %+v", got)
	}
	if strings.Contains(rec.Body.String(), validTestID) || strings.Contains(rec.Body.String(), "qpot_id") {
		t.Fatal("events page carries the QPot ID")
	}

	rec = a.do(http.MethodGet, "/api/events?limit=5", "")
	page = eventsPage{}
	if json.Unmarshal(rec.Body.Bytes(), &page) != nil || len(page.Events) != 3 || page.HasMore || page.NextOffset != 0 {
		t.Fatalf("last page: %s", rec.Body.String())
	}

	rec = a.do(http.MethodGet, "/api/events?source_ip=1.2.3.4'--", "")
	if e := decodeAPIError(t, rec); rec.Code != http.StatusBadRequest || !strings.Contains(e.Error, "source_ip") || strings.Contains(e.Error, "--") {
		t.Fatalf("bad source_ip: %d %+v", rec.Code, e)
	}

	db.n = 0
	rec = a.do(http.MethodGet, "/api/events", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"events":[]`) {
		t.Fatalf("no events: %s", rec.Body.String())
	}

	a.s.database = nil
	rec = a.do(http.MethodGet, "/api/events", "")
	if e := decodeAPIError(t, rec); rec.Code != http.StatusServiceUnavailable || e.Code != "QP-INST-005" {
		t.Fatalf("no database: %d %+v", rec.Code, e)
	}
}

// FuzzEventsQuery: any query string gets an answer without a server error,
// and whatever reaches the database is within the documented bounds.
func FuzzEventsQuery(f *testing.F) {
	for _, s := range []string{"", "honeypot=cowrie&limit=10", "q=%27%22%5C%25_", "q=%00", "since=1&until=0",
		"source_ip=::1&source_ip=1.2.3.4", "limit=999999999999999999999", "honeypot=" + strings.Repeat("a,", 30), "country=de&event_type=x.y"} {
		f.Add(s)
	}
	a := newAPITestServer(f, "api-fuzz-events", func(*config.Config) {})
	db := &filterDB{n: 1}
	a.s.database = db
	f.Fuzz(func(t *testing.T, raw string) {
		before := len(db.got)
		req := httptest.NewRequest(http.MethodGet, "/api/events", nil)
		req.URL.RawQuery = raw
		req.Header.Set("X-QPot-ID", validTestID)
		rec := httptest.NewRecorder()
		a.h.ServeHTTP(rec, req)
		if rec.Code >= 500 {
			t.Fatalf("%q: %d %s", raw, rec.Code, rec.Body.String())
		}
		if rec.Code != http.StatusOK {
			if len(db.got) != before {
				t.Fatalf("%q refused (%d) but queried the database", raw, rec.Code)
			}
			return
		}
		got := db.last()
		if got.Limit < 2 || got.Limit > maxEventLimit+1 || got.Offset < 0 || got.Offset > maxEventOffset ||
			len(got.Text) > database.MaxEventText || len(got.Honeypots) > maxEventFilterValues ||
			len(got.SourceIPs) > maxEventFilterValues || strings.ContainsAny(got.Text, "\x00\n\r") {
			t.Fatalf("%q reached the database as %+v", raw, got)
		}
	})
}
