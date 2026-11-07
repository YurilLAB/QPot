package server

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/config"
)

// Unit tests point New at an unreachable database on purpose; they must not
// sit through the production startup wait.
func init() { dbStartupWait = 0 }

// New must keep retrying an unreachable database until dbStartupWait elapses
// (the database container is usually still starting), then come up DB-less.
func TestConnectDatabaseWaitsThenGivesUp(t *testing.T) {
	old := dbStartupWait
	dbStartupWait = 3 * time.Second
	defer func() { dbStartupWait = old }()
	cfg := config.Default("db-wait-test")
	cfg.Database.Host = "127.0.0.1"
	cfg.Database.Port = 1 // nothing listens here
	start := time.Now()
	if db := connectDatabase(cfg); db != nil {
		t.Fatal("connectDatabase returned a database for an unreachable server")
	}
	if waited := time.Since(start); waited < 3*time.Second {
		t.Fatalf("gave up after %v, want to keep retrying for the startup wait", waited)
	}
}

type offlineATTCKTransport struct{}

func (offlineATTCKTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network disabled for hermetic server test")
}

func TestServerDisablesDatabaseAfterSchemaFailure(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	oldClient := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: offlineATTCKTransport{}}
	t.Cleanup(func() { http.DefaultClient = oldClient })
	var failSchema atomic.Bool
	failSchema.Store(true)
	var dataRequests atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/_cluster/health":
			_, _ = w.Write([]byte(`{"status":"green"}`))
		case r.Method == http.MethodPut:
			if r.URL.Path == "/qpot-intelligence-checkpoint" && failSchema.Load() {
				http.Error(w, "schema rejected", http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`{"acknowledged":true}`))
		default:
			dataRequests.Add(1)
			http.Error(w, "unexpected data access", http.StatusInternalServerError)
		}
	}))
	defer backend.Close()
	host, port, err := net.SplitHostPort(strings.TrimPrefix(backend.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default("schema-readiness")
	cfg.QPotID = validTestID
	cfg.Security.SandboxMode = "none"
	cfg.Database.Type, cfg.Database.Host = "elasticsearch", host
	cfg.Database.Port, err = strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.database != nil || s.worker != nil {
		t.Fatal("failed schema must not expose a database or start an intelligence worker")
	}
	for _, path := range []string{"/api/events", "/api/iocs", "/api/ttps"} {
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, authReq(http.MethodGet, path, ""))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s must report unavailable: %d %s", path, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, authReq(http.MethodGet, "/api/intelligence", ""))
	var summary map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary["worker_enabled"] != false || summary["worker_healthy"] != false {
		t.Fatalf("summary concealed unavailable worker: %v", summary)
	}
	// Local canary persistence remains available independently of the DB.
	// It must not attempt an alert insert against the unready backend.
	c, err := s.canaries.Create(canary.KindWeb, "schema-failure", "synthetic test")
	if err != nil {
		t.Fatal(err)
	}
	s.mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/c/"+c.Token, nil))
	stored, err := canary.NewStore(cfg.DataPath, cfg.Canary.MaxTrips)
	if err != nil || len(stored.Trips(0)) != 1 {
		t.Fatalf("schema failure prevented local canary recording: %v", err)
	}
	if dataRequests.Load() != 0 {
		t.Fatal("failed schema was followed by a database read or event write")
	}
	// A repaired schema is accepted on a subsequent control-plane start.
	failSchema.Store(false)
	restarted, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.database == nil || restarted.worker == nil {
		t.Fatal("repaired schema did not restore the database and worker")
	}
	_ = restarted.database.Close()
}
