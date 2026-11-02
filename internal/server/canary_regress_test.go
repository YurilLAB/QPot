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

// countingDB counts IOC insert calls.
type countingDB struct {
	fakeDB
	single, batches int
}

func (c *countingDB) InsertIOC(ctx context.Context, ioc *database.IOC) error {
	c.single++
	return c.fakeDB.InsertIOC(ctx, ioc)
}
func (c *countingDB) InsertIOCs(ctx context.Context, iocs []*database.IOC) error {
	c.batches++
	return c.fakeDB.InsertIOCs(ctx, iocs)
}

// Inbound Yuril intel is stored in one batch, deduplicated, with IDs, and the
// provenance fields cannot be overwritten by the sender's context.
func TestYurilIntelBatchedAndProvenanceProtected(t *testing.T) {
	db := &countingDB{}
	s := &Server{config: &config.Config{QPotID: validTestID}, mux: http.NewServeMux(), database: db}
	s.setupRoutes()
	body := `{"source":"edr","items":[
		{"type":"ip","value":"198.51.100.4","severity":"high",
		 "context":{"origin":"forged","yuril_source":"forged","severity":"forged","host":"pc-7"}},
		{"type":"ip","value":"198.51.100.4"},
		{"type":"domain","value":"evil.example.org"},
		{"type":"bogus","value":"x"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/yuril/intel", strings.NewReader(body))
	req.Header.Set("X-QPot-ID", validTestID)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if db.single != 0 || db.batches != 1 {
		t.Fatalf("InsertIOC calls=%d InsertIOCs calls=%d, want 0 and 1", db.single, db.batches)
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	if len(db.iocs) != 2 {
		t.Fatalf("stored %d IOCs, want 2 (duplicate and unsupported type dropped)", len(db.iocs))
	}
	ip := db.iocs[0]
	if ip.ID != "ip:198.51.100.4:_yuril" {
		t.Errorf("IOC ID = %q", ip.ID)
	}
	m := ip.Metadata
	if m["origin"] != "yuril_inbound" || m["yuril_source"] != "edr" || m["severity"] != "high" || m["host"] != "pc-7" {
		t.Errorf("provenance not protected / context lost: %v", m)
	}
	if !strings.Contains(rec.Body.String(), `"accepted":2`) {
		t.Errorf("response: %s", rec.Body.String())
	}
}

// scopedDB only answers filtered queries, like a real database holding far
// more rows than any "top N then filter in memory" scan would see.
type scopedDB struct{ fakeDB }

func (d *scopedDB) GetTopAttackers(ctx context.Context, limit int, since time.Time) ([]*database.AttackerStats, error) {
	return nil, nil // the IP is not among the top attackers
}
func (d *scopedDB) GetEvents(ctx context.Context, fl database.EventFilter) ([]*database.Event, error) {
	if len(fl.SourceIPs) == 1 && fl.SourceIPs[0] == "192.0.2.77" {
		return []*database.Event{{Timestamp: time.Now().Add(-time.Hour), Honeypot: "cowrie", SourceIP: "192.0.2.77", Country: "NL"}}, nil
	}
	return nil, nil
}
func (d *scopedDB) GetIOCs(ctx context.Context, fl database.IOCFilter) ([]*database.IOC, error) {
	for _, v := range fl.Values {
		if v == "d41d8cd98f00b204e9800998ecf8427e" {
			return []*database.IOC{{ID: "hash:d41d8cd98f00b204e9800998ecf8427e:dionaea", Type: "hash", Value: v, Honeypot: "dionaea"}}, nil
		}
	}
	return nil, nil
}

// The Yuril lookup must find a quiet IP and an old IOC via database filters,
// not only what appears in the top-1000 / first-5000 rows.
func TestYurilQueryUsesDatabaseFilters(t *testing.T) {
	s := &Server{config: &config.Config{QPotID: validTestID}, mux: http.NewServeMux(), database: &scopedDB{}}
	s.setupRoutes()
	req := httptest.NewRequest(http.MethodGet, "/api/yuril/query?ip=192.0.2.77&hash=D41D8CD98F00B204E9800998ECF8427E", nil)
	req.Header.Set("X-QPot-ID", validTestID)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `"ip_activity"`) || !strings.Contains(body, `"matching_iocs_count":1`) {
		t.Fatalf("status %d body %s", rec.Code, body)
	}
}
