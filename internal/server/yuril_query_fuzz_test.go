package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
)

// queryFakeDB is a fakeDB that returns a fixed, non-empty IOC and attacker set
// so the /api/yuril/query matching/filtering code path is actually exercised
// under fuzzing (the bare fakeDB returns nil for both, short-circuiting the
// interesting logic).
type queryFakeDB struct {
	fakeDB
}

func (q *queryFakeDB) GetTopAttackers(ctx context.Context, limit int, since time.Time) ([]*database.AttackerStats, error) {
	return []*database.AttackerStats{
		{
			SourceIP:    "203.0.113.7",
			Country:     "AU",
			AttackCount: 42,
			Honeypots:   []string{"cowrie"},
			FirstSeen:   time.Now().Add(-48 * time.Hour),
			LastSeen:    time.Now(),
		},
	}, nil
}

func (q *queryFakeDB) GetIOCs(ctx context.Context, fl database.IOCFilter) ([]*database.IOC, error) {
	return []*database.IOC{
		{Type: "ip", Value: "203.0.113.7", SourceIP: "203.0.113.7", Honeypot: "cowrie"},
		{Type: "hash", Value: "d41d8cd98f00b204e9800998ecf8427e", Honeypot: "dionaea"},
		{Type: "domain", Value: "evil.example", Honeypot: "_yuril"},
	}, nil
}

// FuzzHandleYurilQuery throws arbitrary ip/hash/domain query values at the
// inbound Yuril/operator-plane lookup endpoint. These params are attacker- and
// peer-influenced (YurilAntivirus asks "have you seen this indicator?"), so the
// handler must never panic and must always return a valid HTTP status. When at
// least one selector is present and non-blank it must answer 200; when all are
// blank it must answer 400 — never anything in between, never a 500 from the
// stub DB.
func FuzzHandleYurilQuery(f *testing.F) {
	seeds := []string{
		"ip=203.0.113.7",
		"hash=D41D8CD98F00B204E9800998ECF8427E",
		"domain=evil.example",
		"ip=203.0.113.7&hash=x&domain=y",
		"ip=%00%01%02",
		"ip=' OR 1=1--",
		"domain=" + strings.Repeat("a.", 2000) + "com",
		"ip=   ",
		"",
		"unrelated=1",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	cfg := &config.Config{QPotID: validTestID, WebUI: config.WebUIConfig{QPotIDAuth: true}}
	s := &Server{config: cfg, database: &queryFakeDB{}, mux: http.NewServeMux()}

	f.Fuzz(func(t *testing.T, rawQuery string) {
		req := httptest.NewRequest(http.MethodGet, "/api/yuril/query", nil)
		req.URL.RawQuery = rawQuery
		rec := httptest.NewRecorder()
		s.handleYurilQuery(rec, req) // must not panic

		if rec.Code < 100 || rec.Code >= 600 {
			t.Fatalf("query %q: invalid status %d", rawQuery, rec.Code)
		}

		// Mirror the handler's own selector parsing: it trims whitespace and
		// requires at least one non-blank selector. The status must follow that
		// rule exactly so the contract stays predictable for the Yuril side.
		q := req.URL.Query()
		hasSelector := strings.TrimSpace(q.Get("ip")) != "" ||
			strings.TrimSpace(q.Get("hash")) != "" ||
			strings.TrimSpace(q.Get("domain")) != ""
		if hasSelector && rec.Code != http.StatusOK {
			t.Errorf("query %q has a selector but returned %d, want 200", rawQuery, rec.Code)
		}
		if !hasSelector && rec.Code != http.StatusBadRequest {
			t.Errorf("query %q has no selector but returned %d, want 400", rawQuery, rec.Code)
		}
	})
}
