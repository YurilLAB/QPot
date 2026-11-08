package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/database"
)

// A canary trip's event and IOCs were inserted once; when that failed (the
// database down or restarting) the failure was only logged, so the trip
// stayed in the canary history but never reached the activity feed or the
// IOC store.

var errFlakyDown = errors.New("database unavailable")

// flakyDB is a database that refuses writes and reads while down. With
// lostReply set, a write while down is stored and still reported as failed:
// the commit happened but the reply was lost.
type flakyDB struct {
	fakeDB
	state     sync.Mutex
	down      bool
	lostReply bool
}

func (f *flakyDB) setDown(down bool) { f.state.Lock(); f.down = down; f.state.Unlock() }
func (f *flakyDB) failing() (down, lost bool) {
	f.state.Lock()
	defer f.state.Unlock()
	return f.down, f.lostReply
}

func (f *flakyDB) InsertEvent(ctx context.Context, e *database.Event) error {
	return f.InsertEvents(ctx, []*database.Event{e})
}
func (f *flakyDB) InsertEvents(ctx context.Context, e []*database.Event) error {
	if down, lost := f.failing(); down {
		if lost {
			_ = f.fakeDB.InsertEvents(ctx, e)
		}
		return errFlakyDown
	}
	return f.fakeDB.InsertEvents(ctx, e)
}
func (f *flakyDB) InsertIOCs(ctx context.Context, iocs []*database.IOC) error {
	if down, lost := f.failing(); down {
		if lost {
			_ = f.fakeDB.InsertIOCs(ctx, iocs)
		}
		return errFlakyDown
	}
	return f.fakeDB.InsertIOCs(ctx, iocs)
}

// GetEvents answers like a database: the stored events the filter matches.
func (f *flakyDB) GetEvents(ctx context.Context, fl database.EventFilter) ([]*database.Event, error) {
	if down, _ := f.failing(); down {
		return nil, errFlakyDown
	}
	in := func(v string, set []string) bool {
		if len(set) == 0 {
			return true
		}
		for _, s := range set {
			if s == v {
				return true
			}
		}
		return false
	}
	var out []*database.Event
	for _, e := range f.insertedEvents() {
		if !in(e.Honeypot, fl.Honeypots) || !in(e.EventType, fl.EventTypes) ||
			(!fl.StartTime.IsZero() && e.Timestamp.Before(fl.StartTime)) ||
			(!fl.EndTime.IsZero() && e.Timestamp.After(fl.EndTime)) {
			continue
		}
		cp := *e
		out = append(out, &cp)
	}
	return out, nil
}

func (f *flakyDB) storedIOCs() []*database.IOC {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*database.IOC(nil), f.iocs...)
}

// tripEvents returns the stored canary trip events.
func tripEvents(db *flakyDB) []*database.Event {
	var out []*database.Event
	for _, e := range db.insertedEvents() {
		if e.Honeypot == "canary" && e.EventType == "canary_trip" {
			out = append(out, e)
		}
	}
	return out
}

// tripBeacon mints a web canary on s and fetches its beacon once.
func tripBeacon(t *testing.T, s *Server) {
	t.Helper()
	c, err := s.canaries.Create(canary.KindWeb, "bookmark", "fake link")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/c/"+c.Token, nil)
	req.RemoteAddr = "203.0.113.9:51000"
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("beacon: %d", rec.Code)
	}
	if n := len(s.canaries.Trips(0)); n != 1 {
		t.Fatalf("%d trips recorded, want 1", n)
	}
}

// wantOneTripEvent checks the database holds the trip's event exactly once,
// and its IOCs.
func wantOneTripEvent(t *testing.T, s *Server, db *flakyDB) {
	t.Helper()
	got := tripEvents(db)
	if len(got) != 1 {
		t.Fatalf("%d canary trip events in the database, want exactly 1", len(got))
	}
	if trips := s.canaries.Trips(0); len(trips) == 1 && got[0].Metadata["trip_id"] != trips[0].ID {
		t.Errorf("the event does not carry its trip's ID: %v", got[0].Metadata)
	}
	if want := len(s.classifier.ExtractIOCs(got[0])); want == 0 || len(db.storedIOCs()) != want {
		t.Errorf("%d IOCs stored, want %d", len(db.storedIOCs()), want)
	}
}

// TestCanaryTripReachesDatabaseAfterOutage: database down, trip, database
// up: the event arrives, exactly once however often the outbox is replayed.
func TestCanaryTripReachesDatabaseAfterOutage(t *testing.T) {
	db := &flakyDB{down: true}
	dir := t.TempDir()
	s := newOutboxTestServer(t, db, dir)
	tripBeacon(t, s)
	if n := len(tripEvents(db)); n != 0 {
		t.Fatalf("%d events stored while the database was down", n)
	}
	replayPending(t, s) // still down: nothing, and nothing lost
	db.setDown(false)
	replayPending(t, s)
	replayPending(t, s)
	wantOneTripEvent(t, s, db)
}

// TestCanaryTripSurvivesRestart: the same, with the process gone between the
// trip and the database's return.
func TestCanaryTripSurvivesRestart(t *testing.T) {
	db := &flakyDB{down: true}
	dir := t.TempDir()
	s := newOutboxTestServer(t, db, dir)
	tripBeacon(t, s)

	db.setDown(false)
	restarted := newOutboxTestServer(t, db, dir)
	replayPending(t, restarted)
	replayPending(t, restarted)
	if n := len(tripEvents(db)); n != 1 {
		t.Fatalf("%d canary trip events after a restart, want exactly 1", n)
	}
	wantOneTripEvent(t, restarted, db)
}

// TestCanaryReplayAfterLostReply: an insert that reached the database but
// reported failure is not written a second time by the replay.
func TestCanaryReplayAfterLostReply(t *testing.T) {
	db := &flakyDB{down: true, lostReply: true}
	s := newOutboxTestServer(t, db, t.TempDir())
	tripBeacon(t, s)
	db.setDown(false)
	replayPending(t, s)
	replayPending(t, s)
	if n := len(tripEvents(db)); n != 1 {
		t.Fatalf("%d canary trip events after a lost reply and a replay, want exactly 1", n)
	}
}

// TestCanaryTripWithoutDatabase: a server that never reached its database
// (s.database nil) dropped trips outright; the next start that reaches it
// writes them.
func TestCanaryTripWithoutDatabase(t *testing.T) {
	dir := t.TempDir()
	s := newOutboxTestServer(t, nil, dir)
	tripBeacon(t, s)
	db := &flakyDB{}
	restarted := newOutboxTestServer(t, db, dir)
	replayPending(t, restarted)
	if n := len(tripEvents(db)); n != 1 {
		t.Fatalf("%d canary trip events, want exactly 1", n)
	}
	if !strings.HasPrefix(tripEvents(db)[0].Metadata["trip_id"], "trip_") {
		t.Errorf("trip ID missing: %v", tripEvents(db)[0].Metadata)
	}
}

// TestCanaryOutboxConcurrentReplays: replays running at once (the loop and a
// new trip's own attempt) write each trip once, its IOCs included.
func TestCanaryOutboxConcurrentReplays(t *testing.T) {
	db := &flakyDB{down: true}
	s := newOutboxTestServer(t, db, t.TempDir())
	tripBeacon(t, s)
	db.setDown(false)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			replayPending(t, s)
		}()
	}
	wg.Wait()
	replayPending(t, s)
	wantOneTripEvent(t, s, db)
}

// TestCanaryOutboxFullKeepsTheQueuedTrips: with maxCanaryOutbox trips
// waiting, a new trip is tried once and not queued; the waiting ones stay.
func TestCanaryOutboxFullKeepsTheQueuedTrips(t *testing.T) {
	old := maxCanaryOutbox
	maxCanaryOutbox = 2
	t.Cleanup(func() { maxCanaryOutbox = old })
	db := &flakyDB{down: true}
	dir := t.TempDir()
	s := newOutboxTestServer(t, db, dir)
	for i := 0; i < 3; i++ {
		c, err := s.canaries.Create(canary.KindWeb, "c", "")
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/c/"+c.Token, nil)
		req.RemoteAddr = "203.0.113.9:51000"
		s.mux.ServeHTTP(httptest.NewRecorder(), req)
	}
	queued, err := s.canaryOutbox.pending()
	if err != nil || len(queued) != 2 {
		t.Fatalf("%d trips queued (%v), want the first 2", len(queued), err)
	}
	trips := s.canaries.Trips(0) // newest first
	if len(trips) != 3 {
		t.Fatalf("%d trips in the canary history, want 3", len(trips))
	}
	for _, q := range queued {
		if q.TripID == trips[0].ID {
			t.Error("the newest trip was queued over a full outbox")
		}
	}
	db.setDown(false)
	replayPending(t, s)
	if n := len(tripEvents(db)); n != 2 {
		t.Fatalf("%d trip events after the replay, want the 2 queued", n)
	}
}

// TestCanaryOutboxSetsAsideUnreadableEntries: a damaged entry is renamed
// aside, not deleted, and the others are still delivered.
func TestCanaryOutboxSetsAsideUnreadableEntries(t *testing.T) {
	db := &flakyDB{down: true}
	dir := t.TempDir()
	s := newOutboxTestServer(t, db, dir)
	tripBeacon(t, s)
	bad := filepath.Join(dir, canaryOutboxDir, "trip_00000000000000000000.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	db.setDown(false)
	replayPending(t, s)
	wantOneTripEvent(t, s, db)
	if _, err := os.Stat(bad + ".bad"); err != nil {
		t.Errorf("the damaged entry was not set aside: %v", err)
	}
}
