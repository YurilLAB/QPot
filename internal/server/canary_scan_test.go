package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/geo/geotest"
)

// recentDB answers GetEvents with a fixed set of captured events and records
// what it was asked, as the database would for the quick canary scan.
type recentDB struct {
	*fakeDB
	mu      sync.Mutex
	recent  []*database.Event
	filters []database.EventFilter
}

func (d *recentDB) GetEvents(_ context.Context, f database.EventFilter) ([]*database.Event, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.filters = append(d.filters, f)
	return d.recent, nil
}

func (d *recentDB) asked() []database.EventFilter {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]database.EventFilter(nil), d.filters...)
}

// TestQuickScanTripsWithinSeconds: a canary used inside a honeypot trips on
// the quick scan, placed where the collector placed the event, and the same
// event does not trip it again on the next scan or when the intelligence
// worker reaches it minutes later.
func TestQuickScanTripsWithinSeconds(t *testing.T) {
	old := canary.TripDedupeWindow
	canary.TripDedupeWindow = 0 // the worker comes minutes later, past the window
	defer func() { canary.TripDedupeWindow = old }()

	db := &recentDB{fakeDB: &fakeDB{}}
	s := newCanaryTestServer(t, nil)
	s.database = db
	m := &canaryMatcher{s: s}

	// No canary yet: nothing to look for, so the database is not asked.
	s.scanRecentForCanaries(t.Context(), m)
	if n := len(db.asked()); n != 0 {
		t.Fatalf("scanned the database %d times with no canary to look for", n)
	}

	c, err := s.canaries.Create(canary.KindAWS, "ci", "jenkins")
	if err != nil {
		t.Fatal(err)
	}
	used := &database.Event{
		Timestamp: time.Now().Add(-20 * time.Second),
		Honeypot:  "cowrie", SourceIP: "81.2.69.160", SourcePort: 40112, DestPort: 22,
		EventType: "command", Command: "aws s3 ls --access-key " + c.AccessKeyID,
		Country: "SE", City: "Stockholm", ASN: "1257",
	}
	db.recent = []*database.Event{
		used,
		// A trip's own event names the canary too; it is not a new use.
		{Timestamp: time.Now(), Honeypot: "canary", Command: c.AccessKeyID},
	}

	s.scanRecentForCanaries(t.Context(), m)
	evs := db.insertedEvents()
	if len(evs) != 1 || evs[0].Honeypot != "canary" {
		t.Fatalf("quick scan inserted %+v, want one trip event", evs)
	}
	if evs[0].Country != "SE" || evs[0].City != "Stockholm" || evs[0].ASN != "1257" {
		t.Fatalf("trip event placed at %q/%q/%q, want SE/Stockholm/1257", evs[0].Country, evs[0].City, evs[0].ASN)
	}
	f := db.asked()[0]
	if f.Limit != canaryScanLimit || time.Since(f.StartTime) > canaryScanLookback+time.Minute ||
		time.Since(f.StartTime) < canaryScanLookback-time.Minute {
		t.Fatalf("quick scan asked for %+v, want the last %s, at most %d events", f, canaryScanLookback, canaryScanLimit)
	}

	// The next scan reads the same event again; the worker reads it through
	// its own query, with the row's ID set.
	s.scanRecentForCanaries(t.Context(), m)
	again := *used
	again.ID = "row-1"
	if m.MatchEvent(t.Context(), &again) {
		t.Fatal("the worker tripped the canary again for an event the quick scan had")
	}
	if n := len(db.insertedEvents()); n != 1 {
		t.Fatalf("%d trip events for one use, want 1", n)
	}
	if got, _ := s.canaries.Get(c.ID); got.Trips != 1 {
		t.Fatalf("canary counted %d hits for one use", got.Trips)
	}

	// A second use is a second trip; "unknown" is not a place.
	second := *used
	second.Timestamp = used.Timestamp.Add(time.Second)
	second.Country, second.City, second.ASN = "unknown", "unknown", "unknown"
	if !m.MatchEvent(t.Context(), &second) {
		t.Fatal("a second use of the canary did not trip it")
	}
	if last := db.insertedEvents()[1]; last.Country != "" || last.City != "" || last.ASN != "" {
		t.Fatalf("unplaced source stored as %q/%q/%q", last.Country, last.City, last.ASN)
	}
}

// TestBeaconTripIsPlaced: a beacon hit is placed with the instance's GeoIP
// database, which the settings name by the collector's path for it.
func TestBeaconTripIsPlaced(t *testing.T) {
	db := &fakeDB{}
	s := newCanaryTestServer(t, db)
	s.config.DataPath = t.TempDir()
	s.config.Collector.GeoIPDBPath = "/data/geoip/test.mmdb"
	mmdb, err := os.ReadFile(geotest.WriteMMDB(t))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(s.config.DataPath, "geoip")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "test.mmdb"), mmdb, 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := s.canaries.Create(canary.KindWeb, "bookmark", "")
	if err != nil {
		t.Fatal(err)
	}
	hit := func(ip string) {
		r := httptest.NewRequest(http.MethodGet, "/c/"+c.Token, nil)
		r.RemoteAddr = ip + ":51000"
		s.mux.ServeHTTP(httptest.NewRecorder(), r)
	}
	hit(geotest.KnownIP)
	evs := db.insertedEvents()
	if len(evs) != 1 || evs[0].Country != geotest.Country || evs[0].City != geotest.City || evs[0].ASN != geotest.ASN {
		t.Fatalf("beacon trip events %+v, want one placed in %s", evs, geotest.Country)
	}
	trips := s.canaries.Trips(10)
	if len(trips) != 1 || trips[0].Country != geotest.Country {
		t.Fatalf("stored trips %+v, want one placed in %s", trips, geotest.Country)
	}

	// An address the database does not know stays unplaced.
	hit("10.9.8.7")
	if evs := db.insertedEvents(); len(evs) != 2 || evs[1].Country != "" {
		t.Fatalf("unknown address placed: %+v", evs)
	}
	if !strings.HasPrefix(s.geoIPPath(), s.config.DataPath) {
		t.Fatalf("GeoIP path %q is not in the instance folder", s.geoIPPath())
	}
}
