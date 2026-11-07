package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	if len(trips) != 1 || len(db.insertedEvents()) != 1 {
		t.Errorf("save failure must still record and emit exactly one trip")
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
	if len(cs.Trips(0)) != 1 || len(db.insertedEvents()) != 1 {
		t.Errorf("disconnected request must still record and emit exactly one trip")
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
	if n != 1 || len(db.insertedEvents()) != 1 {
		t.Errorf("single event must record and emit exactly one canary trip: %d trips, %d events", n, len(db.insertedEvents()))
	}
}

// failingDB returns driver-style errors carrying internal details.
type failingDB struct{ fakeDB }

var errInternalDetail = errors.New(`dial tcp db-internal.corp:9000: password authentication failed for user "qpot"`)

func (f *failingDB) GetEvents(ctx context.Context, fl database.EventFilter) ([]*database.Event, error) {
	return nil, errInternalDetail
}
func (f *failingDB) GetTTPSessions(ctx context.Context, limit int) ([]*database.TTPSession, error) {
	return nil, errInternalDetail
}

// API errors must not echo database/driver error text (hosts, users, SQL).
func TestAPIDoesNotLeakDatabaseErrors(t *testing.T) {
	s := &Server{
		config:   &config.Config{QPotID: validTestID},
		mux:      http.NewServeMux(),
		database: &failingDB{},
	}
	s.setupRoutes()
	for _, path := range []string{"/api/events", "/api/ttps"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-QPot-ID", validTestID)
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("%s: status %d, want 500", path, rec.Code)
		}
		if body := rec.Body.String(); strings.Contains(body, "db-internal") || strings.Contains(body, "password") {
			t.Errorf("%s leaks the database error: %s", path, body)
		}
	}
}
