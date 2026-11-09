package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/qpot/qpot/internal/database"
)

// Unit tests point the server at an unreachable database on purpose; they
// must not sit through the production startup wait.
func init() { dbStartupWait = 0 }

// waitFor polls cond until it holds, failing the test after 10 seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// freePort is a TCP port on 127.0.0.1 that nothing listened on a moment ago.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// hangingTransport is a network whose requests answer only when cancelled:
// MITRE's ATT&CK download on a slow link.
type hangingTransport struct{}

func (hangingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	<-r.Context().Done()
	return nil, r.Context().Err()
}

// TestWebUIAnswersAtOnce: the web UI answers while the database is still
// starting and MITRE's ATT&CK download is still under way. Before, it waited
// for both: up to 90 seconds for the database, up to 30 for the download.
func TestWebUIAnswersAtOnce(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	oldClient := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: hangingTransport{}}
	t.Cleanup(func() { http.DefaultClient = oldClient })
	replaceOpenDatabase(t, func(ctx context.Context, _ *config.Config) (database.Database, error) {
		<-ctx.Done() // a database that does not answer yet
		return nil, ctx.Err()
	}, time.Minute, time.Minute)
	cfg := config.Default("ui-at-once")
	cfg.QPotID = validTestID
	cfg.Intelligence.Enabled = true
	cfg.Intelligence.ATTCKDataPath = t.TempDir()

	begin := time.Now()
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	startServerOn(t, s, port)
	client := &http.Client{Timeout: time.Second} // the real network, not the hanging one
	code := 0
	for code == 0 && time.Since(begin) < 3*time.Second {
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
		if err != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		code = resp.StatusCode
		resp.Body.Close()
	}
	if code != http.StatusOK {
		t.Fatalf("the web UI did not answer within 3 s of starting (status %d)", code)
	}
	if s.db() != nil || s.intelClassifier() != nil {
		t.Error("the database or the ATT&CK data was there: this did not test the UI answering before them")
	}
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, authReq(http.MethodGet, "/api/events", ""))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("/api/events before the database: %d, want 503", rec.Code)
	}
}

// TestServerTriesTheDatabaseOftenWhileItStarts: during dbStartupWait the
// server tries the database every startupRetry (a database container still
// starting answers within seconds, and the collector needs the schema it
// creates), then backs off.
func TestServerTriesTheDatabaseOftenWhileItStarts(t *testing.T) {
	s := newOutboxTestServer(t, nil, t.TempDir())
	var tries atomic.Int32
	replaceOpenDatabase(t, func(context.Context, *config.Config) (database.Database, error) {
		tries.Add(1)
		return nil, errFlakyDown
	}, time.Second, time.Second)
	oldWait, oldRetry := dbStartupWait, startupRetry
	dbStartupWait, startupRetry = 400*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { dbStartupWait, startupRetry = oldWait, oldRetry })
	stop := startServer(t, s)
	time.Sleep(450 * time.Millisecond)
	during := tries.Load()
	time.Sleep(900 * time.Millisecond)
	after := tries.Load() - during
	stop()
	if during < 10 {
		t.Errorf("%d tries during the start-up wait, want one every 10 ms", during)
	}
	if after > 2 {
		t.Errorf("%d tries in the 900 ms after it, want the 1 s backoff", after)
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
	var dataRequests, schemaTries atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/_cluster/health":
			_, _ = w.Write([]byte(`{"status":"green"}`))
		case r.Method == http.MethodPut:
			if r.URL.Path == "/qpot-intelligence-checkpoint" && failSchema.Load() {
				schemaTries.Add(1)
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
	old := reconnectBackoff
	reconnectBackoff = [2]time.Duration{10 * time.Millisecond, 40 * time.Millisecond}
	t.Cleanup(func() { reconnectBackoff = old })
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	stop := startServer(t, s)
	waitFor(t, "two refused schema attempts", func() bool { return schemaTries.Load() >= 2 })
	if s.db() != nil || s.intelWorker() != nil {
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
	// The schema repaired: the running server takes the database on its next
	// try, with no restart.
	failSchema.Store(false)
	waitFor(t, "the database and the worker", func() bool { return s.db() != nil && s.intelWorker() != nil })
	stop()
	_ = s.db().Close()
}
