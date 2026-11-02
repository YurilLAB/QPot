package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/intelligence"
)

// A store save failure must not swallow the alert for an in-memory trip.
func TestCanaryBeaconAlertsDespiteSaveFailure(t *testing.T) {
	db := &fakeDB{}
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	cs, err := canary.NewStore(dataDir, 0)
	if err != nil {
		t.Fatal(err)
	}
	c, err := cs.Create(canary.KindWeb, "x", "y")
	if err != nil {
		t.Fatal(err)
	}
	// Make subsequent saves fail (MkdirAll fails because dataDir is now a file).
	os.RemoveAll(dataDir)
	os.WriteFile(dataDir, []byte("x"), 0o600)

	s := &Server{
		config:   &config.Config{QPotID: validTestID, Canary: config.CanaryConfig{Enabled: true}},
		mux:      http.NewServeMux(),
		canaries: cs,
		database: db,
	}
	s.setupRoutes()
	req := httptest.NewRequest(http.MethodGet, "/c/"+c.Token, nil)
	s.mux.ServeHTTP(httptest.NewRecorder(), req)

	trips := cs.Trips(0)
	t.Logf("trips recorded in store: %d, events emitted: %d", len(trips), len(db.insertedEvents()))
	if len(trips) == 1 && len(db.insertedEvents()) == 0 {
		t.Errorf("trip recorded in memory but alert event never emitted (persistence error swallowed the alert)")
	}
}

// A client that hangs up must not cancel the alert's DB insert.
type ctxDB struct{ fakeDB }

func (f *ctxDB) InsertEvent(ctx context.Context, e *database.Event) error {
	if err := ctx.Err(); err != nil {
		return err // like a real driver
	}
	return f.fakeDB.InsertEvent(ctx, e)
}

func TestCanaryBeaconAlertsAfterClientDisconnect(t *testing.T) {
	db := &ctxDB{}
	cs, _ := canary.NewStore(t.TempDir(), 0)
	c, _ := cs.Create(canary.KindWeb, "x", "y")
	s := &Server{
		config:   &config.Config{QPotID: validTestID, Canary: config.CanaryConfig{Enabled: true}},
		mux:      http.NewServeMux(),
		canaries: cs,
		database: db,
	}
	s.setupRoutes()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // client already gone
	req := httptest.NewRequest(http.MethodGet, "/c/"+c.Token, nil).WithContext(ctx)
	s.mux.ServeHTTP(httptest.NewRecorder(), req)
	t.Logf("trips=%d events=%d", len(cs.Trips(0)), len(db.insertedEvents()))
	if len(cs.Trips(0)) == 1 && len(db.insertedEvents()) == 0 {
		t.Errorf("trip recorded but alert event lost because request ctx was cancelled")
	}
}

// An event matching no rule must trip a canary once, not every worker cycle.
type unclassDB struct {
	fakeDB
	ev     *database.Event
	tagged bool
}

func (f *unclassDB) TagEvent(ctx context.Context, e *database.Event) error {
	f.tagged = true // row becomes classified=1 and is no longer returned
	return nil
}

func (f *unclassDB) GetUnclassifiedEvents(ctx context.Context, limit int) ([]*database.Event, error) {
	if f.tagged {
		return nil, nil
	}
	cp := *f.ev // DB returns a fresh row each time, classified=0
	return []*database.Event{&cp}, nil
}

func TestCanaryEventTripsOnlyOnce(t *testing.T) {
	cs, _ := canary.NewStore(t.TempDir(), 0)
	c, _ := cs.Create(canary.KindAWS, "ci key", "runner")
	db := &unclassDB{ev: &database.Event{
		Timestamp: time.Now(), Honeypot: "cowrie", SourceIP: "198.51.100.7",
		EventType: "zzz.unmatched", Command: "export AWS_ACCESS_KEY_ID=" + c.AccessKeyID,
	}}
	s := &Server{
		config:   &config.Config{QPotID: validTestID, Canary: config.CanaryConfig{Enabled: true}},
		canaries: cs,
		database: db,
	}
	loader := intelligence.NewATTCKLoader(t.TempDir())
	cl := intelligence.NewClassifier(loader, nil)
	w := intelligence.NewWorker(cl, db, 50*time.Millisecond, 10).WithCanaryMatcher(&canaryMatcher{s: s})
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Millisecond)
	defer cancel()
	w.Run(ctx)
	n := len(cs.Trips(0))
	t.Logf("one attacker event -> %d canary trips, %d critical events", n, len(db.insertedEvents()))
	if n > 1 {
		t.Errorf("single event re-tripped canary %d times", n)
	}
}
