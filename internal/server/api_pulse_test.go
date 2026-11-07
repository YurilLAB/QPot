package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// slotDB is a database that counts slots: it answers CountSlots with counts
// placed relative to the query, and records what it was asked.
type slotDB struct {
	fakeDB
	mu      sync.Mutex
	queries []database.SlotQuery
	// counts are the answer (Slot relative to the query's From).
	counts   []database.SlotCount
	slotErr  error
	unique   int64
	latest   time.Time
	top      []*database.AttackerStats
	topErr   error
	topLimit int
	statsErr error
}

func (d *slotDB) CountSlots(_ context.Context, q database.SlotQuery) ([]database.SlotCount, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.queries = append(d.queries, q)
	return d.counts, d.slotErr
}

func (d *slotDB) asked() []database.SlotQuery {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]database.SlotQuery(nil), d.queries...)
}

func (d *slotDB) GetStats(context.Context, time.Time) (*database.Stats, error) {
	if d.statsErr != nil {
		return nil, d.statsErr
	}
	return &database.Stats{UniqueIPs: d.unique}, nil
}

func (d *slotDB) GetEvents(_ context.Context, f database.EventFilter) ([]*database.Event, error) {
	if d.latest.IsZero() || f.Limit != 1 {
		return nil, nil
	}
	return []*database.Event{{Timestamp: d.latest}}, nil
}

func (d *slotDB) GetTopAttackers(_ context.Context, limit int, _ time.Time) ([]*database.AttackerStats, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.topLimit = limit
	return d.top, d.topErr
}

func getPulse(t *testing.T, a *apiTestServer, query string) (int, pulseAnswer) {
	t.Helper()
	rec := a.do(http.MethodGet, "/api/pulse"+query, "")
	var out pulseAnswer
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%v: %s", err, rec.Body.String())
		}
	}
	return rec.Code, out
}

func TestPulse(t *testing.T) {
	a := newAPITestServer(t, "api-pulse", nil)
	db := &slotDB{unique: 17, latest: time.UnixMilli(1_800_000_000_123),
		top: []*database.AttackerStats{
			{SourceIP: "198.51.100.7", AttackCount: 40, Country: "DE"},
			{SourceIP: "2001:db8::9", AttackCount: 9, Country: "ZZ"},
			{SourceIP: "203.0.113.5", AttackCount: 3, Country: ""},
		}}
	// 24h: 48 slots of the range before (0..47), 48 of the range (48..95).
	db.counts = []database.SlotCount{
		{Honeypot: "cowrie", Slot: 0, Count: 5},     // first slot before
		{Honeypot: "dionaea", Slot: 47, Count: 2},   // last slot before
		{Honeypot: "cowrie", Slot: 48, Count: 10},   // first slot of the range
		{Honeypot: "cowrie", Slot: 95, Count: 1},    // last slot of the range
		{Honeypot: "dionaea", Slot: 60, Count: 7},   // within
		{Honeypot: "heralding", Slot: 70, Count: 3}, // within
		{Honeypot: "conpot", Slot: 71, Count: 3},    // ties heralding: by name
		{Honeypot: "adbhoney", Slot: 72, Count: 1},  // smaller
		{Honeypot: "endlessh", Slot: 73, Count: 1},  // ...
		{Honeypot: "mailoney", Slot: 74, Count: 1},  // last of the 1s by name: cut from types, counted in honeypots
		{Honeypot: "honeytrap", Slot: 75, Count: 1}, // seventh type
		{Honeypot: "cowrie", Slot: 96, Count: 1000}, // after the range: ignored
		{Honeypot: "cowrie", Slot: -1, Count: 1000}, // before the before: ignored
		{Honeypot: "elasticpot", Slot: 5, Count: 4}, // only before: no type, not counted in honeypots
	}
	a.s.database = db
	assertAuthRequired(t, a.h, http.MethodGet, "/api/pulse", "")

	before := time.Now().UTC()
	code, p := getPulse(t, a, "")
	if code != http.StatusOK {
		t.Fatalf("GET: %d", code)
	}
	q := db.asked()
	if len(q) != 1 || q[0].Step != 30*time.Minute || q[0].Slots != 96 {
		t.Fatalf("asked %+v", q)
	}
	// The range ends at the end of the slot now is in, on a step boundary.
	end := q[0].End()
	if end.UnixMilli()%(30*60*1000) != 0 || end.Before(before) || end.Sub(before) > 30*time.Minute {
		t.Errorf("range ends %v (now %v)", end, before)
	}
	start := q[0].From.Add(48 * 30 * time.Minute)
	if p.Range != "24h" || len(p.Slots) != 48 || len(p.Before) != 48 {
		t.Fatalf("range %q, %d slots, %d before", p.Range, len(p.Slots), len(p.Before))
	}
	if p.Slots[0].Key != start.UnixMilli() || p.Slots[47].Key != start.Add(47*30*time.Minute).UnixMilli() ||
		p.Before[0].Key != q[0].From.UnixMilli() || p.Before[47].Key != start.Add(-30*time.Minute).UnixMilli() {
		t.Errorf("keys: slots %d..%d, before %d..%d (from %v)", p.Slots[0].Key, p.Slots[47].Key, p.Before[0].Key, p.Before[47].Key, q[0].From)
	}
	if p.Total != 28 || p.Previous != 11 {
		t.Errorf("total %d previous %d, want 28 and 11", p.Total, p.Previous)
	}
	if p.Slots[0].N != 10 || p.Slots[47].N != 1 || p.Slots[12].N != 7 || p.Before[0].N != 5 || p.Before[47].N != 2 || p.Before[5].N != 4 {
		t.Errorf("slot counts: %+v / %+v", p.Slots, p.Before)
	}
	var names []string
	for _, ty := range p.Types {
		names = append(names, ty.Type)
	}
	if strings.Join(names, ",") != "cowrie,dionaea,conpot,heralding,adbhoney,endlessh,honeytrap" {
		t.Errorf("types %v", names)
	}
	if c := p.Types[0]; c.N != 11 || len(c.Slots) != 48 || c.Slots[0].N != 10 || c.Slots[47].N != 1 || c.Slots[0].Key != p.Slots[0].Key {
		t.Errorf("cowrie: %+v", c)
	}
	if p.Honeypots != 8 || p.Sources != 17 || p.Latest != 1_800_000_000_123 || db.topLimit != pulseSources {
		t.Errorf("honeypots %d sources %d latest %d (top %d asked)", p.Honeypots, p.Sources, p.Latest, db.topLimit)
	}
	want := []pulseSource{{"198.51.100.7", 40, "Germany", ""}, {"2001:db8::9", 9, "ZZ", ""}, {"203.0.113.5", 3, "", ""}}
	if len(p.TopSources) != 3 || p.TopSources[0] != want[0] || p.TopSources[1] != want[1] || p.TopSources[2] != want[2] {
		t.Errorf("top sources %+v", p.TopSources)
	}
	if p.Sensors == nil || len(p.Sensors) != 0 {
		t.Errorf("sensors %+v", p.Sensors)
	}

	// The same range again within 2 s: the cached answer, no new query.
	if code, again := getPulse(t, a, "?range=24h"); code != http.StatusOK || again.Total != p.Total || len(db.asked()) != 1 {
		t.Errorf("second GET: %d, %d queries", code, len(db.asked()))
	}
	// The other ranges: their own steps.
	for _, c := range []struct {
		r     string
		step  time.Duration
		slots int
	}{{"1h", time.Minute, 120}, {"1m", 2 * time.Second, 60}} {
		n := len(db.asked())
		code, p := getPulse(t, a, "?range="+c.r)
		q := db.asked()
		if code != http.StatusOK || len(q) != n+1 || q[n].Step != c.step || q[n].Slots != c.slots || len(p.Slots) != c.slots/2 || p.Range != c.r {
			t.Errorf("%s: %d, asked %+v, %d slots", c.r, code, q[n:], len(p.Slots))
		}
	}
	// No latest event in the range: latest is left out.
	db.latest = time.Time{}
	a.s.api.pulse = pulseCache{}
	if rec := a.do(http.MethodGet, "/api/pulse?range=1m", ""); strings.Contains(rec.Body.String(), `"latest"`) {
		t.Errorf("latest without events: %s", rec.Body.String())
	}
}

func TestPulseRefuses(t *testing.T) {
	a := newAPITestServer(t, "api-pulse-no", nil)
	for _, r := range []string{"2h", "24H", "1d", "24h ", "%00", strings.Repeat("1", 300)} {
		rec := a.do(http.MethodGet, "/api/pulse?range="+url.QueryEscape(r), "")
		if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), r) && r != "" {
			t.Errorf("range %q: %d %s", r, rec.Code, rec.Body.String())
		}
	}
	if rec := a.do(http.MethodPost, "/api/pulse", `{}`); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", rec.Code)
	}
	// No database.
	if rec := a.do(http.MethodGet, "/api/pulse", ""); rec.Code != http.StatusServiceUnavailable || decodeAPIError(t, rec).Code != "QP-INST-005" {
		t.Errorf("no database: %d %s", rec.Code, rec.Body.String())
	}
	// A database that cannot count slots.
	a.s.database = &fakeDB{}
	if rec := a.do(http.MethodGet, "/api/pulse", ""); rec.Code != http.StatusNotImplemented {
		t.Errorf("no slot counter: %d %s", rec.Code, rec.Body.String())
	}
	// Failing queries: 500 without the driver's words, and nothing cached.
	secret := "pw-" + strings.Repeat("s", 12)
	fail := errors.New("auth failed for qpot:" + secret)
	for _, db := range []*slotDB{{slotErr: fail}, {statsErr: fail}, {topErr: fail}} {
		a.s.database = db
		a.s.api.pulse = pulseCache{}
		rec := a.do(http.MethodGet, "/api/pulse", "")
		if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), secret) {
			t.Errorf("failing database: %d %s", rec.Code, rec.Body.String())
		}
		if len(a.s.api.pulse.last) != 0 {
			t.Error("a failed answer was cached")
		}
	}
}

func TestPulseWindow(t *testing.T) {
	now := time.Date(2026, 11, 7, 10, 17, 5, 300_000_000, time.FixedZone("AEST", 10*3600))
	for _, c := range []struct {
		r    string
		want time.Time
	}{
		{"24h", time.Date(2026, 11, 6, 0, 30, 0, 0, time.UTC)}, // ends 00:30 UTC (10:17 AEST is 00:17 UTC)
		{"1h", time.Date(2026, 11, 6, 23, 18, 0, 0, time.UTC)},
		{"1m", time.Date(2026, 11, 7, 0, 16, 6, 0, time.UTC)},
	} {
		if got := pulseWindow(now, pulseRanges[c.r]); !got.Equal(c.want) {
			t.Errorf("%s: start %v, want %v", c.r, got, c.want)
		}
	}
	// On a boundary the range ends with the slot that starts there.
	b := time.Date(2026, 11, 7, 0, 30, 0, 0, time.UTC)
	if got := pulseWindow(b, pulseRanges["24h"]); !got.Equal(b.Add(30*time.Minute - 24*time.Hour)) {
		t.Errorf("boundary: %v", got)
	}
}

func FuzzPulseRange(f *testing.F) {
	for _, s := range []string{"24h", "1h", "1m", "", "2h", "%", "24h&range=1h", "\x00"} {
		f.Add(s)
	}
	a := newAPITestServer(f, "api-pulse-fuzz", nil)
	a.s.database = &slotDB{}
	f.Fuzz(func(t *testing.T, r string) {
		rec := a.do(http.MethodGet, "/api/pulse?range="+url.QueryEscape(r), "")
		_, known := pulseRanges[r]
		switch {
		case r == "" || known:
			if rec.Code != http.StatusOK {
				t.Fatalf("%q: %d", r, rec.Code)
			}
		case rec.Code != http.StatusBadRequest:
			t.Fatalf("%q: %d", r, rec.Code)
		}
	})
}
