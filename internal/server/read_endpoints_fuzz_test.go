package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/instance"
)

// Many individually bounded attacker log lines must not accumulate an
// unbounded dashboard response. Exercise the actual handler and process reader,
// using a finite synthetic producer in place of Docker; no daemon is involved.
func TestLogRepliesHaveByteAndLineBudgets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the finite subprocess fixture uses a Unix shell")
	}
	if _, err := exec.LookPath("awk"); err != nil {
		t.Skip("awk unavailable for the finite log fixture")
	}
	for _, tc := range []struct {
		name      string
		program   string
		wantLines int
		truncated bool
	}{
		{"ordinary", `printf 'first\nsecond\n'`, 2, false},
		{"many large lines", `exec awk 'BEGIN { row="x"; for(i=0;i<15;i++) row=row row; for(i=0;i<256;i++) print row }'`, 128, true},
		{"many empty lines", `exec awk 'BEGIN { for(i=0;i<20050;i++) print "" }'`, 10000, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin := t.TempDir()
			if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\n"+tc.program+"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			cfg := config.Default("logs-budget")
			cfg.DataPath = t.TempDir()
			cfg.Security.SandboxMode = "none"
			manager, err := instance.NewManager(cfg)
			if err != nil {
				t.Fatal(err)
			}
			s := &Server{config: cfg, manager: manager}
			request := httptest.NewRequest(http.MethodGet, "/api/logs?tail=5000", nil)
			response := httptest.NewRecorder()
			s.handleLogs(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status %d: %s", response.Code, response.Body)
			}
			var lines []string
			if err := json.Unmarshal(response.Body.Bytes(), &lines); err != nil {
				t.Fatal(err)
			}
			bytes := 0
			for _, line := range lines {
				bytes += len(line)
			}
			if bytes > 4<<20 || len(lines) > 10000 {
				t.Fatalf("unbounded log response: %d raw bytes in %d lines", bytes, len(lines))
			}
			if len(lines) != tc.wantLines {
				t.Fatalf("got %d lines, want %d", len(lines), tc.wantLines)
			}
			if got := response.Header().Get("X-QPot-Logs-Truncated") == "true"; got != tc.truncated {
				t.Fatalf("truncation notice %v, want %v", got, tc.truncated)
			}
			if !tc.truncated && strings.Join(lines, "\n") != "first\nsecond" {
				t.Fatalf("ordinary logs changed: %q", lines)
			}
		})
	}
}

// stubDB is a benign database.Database that returns empty results for every
// read, so the server's read handlers run their query-parameter parsing and
// response-building code under fuzzing without needing a real backend.
type stubDB struct{}

func (stubDB) Connect(context.Context) error                         { return nil }
func (stubDB) Close() error                                          { return nil }
func (stubDB) Ping(context.Context) error                            { return nil }
func (stubDB) InitializeSchema(context.Context) error                { return nil }
func (stubDB) GetSchemaVersion(context.Context) (int, error)         { return 1, nil }
func (stubDB) SetSchemaVersion(context.Context, int) error           { return nil }
func (stubDB) InsertEvent(context.Context, *database.Event) error    { return nil }
func (stubDB) InsertEvents(context.Context, []*database.Event) error { return nil }
func (stubDB) GetEvents(context.Context, database.EventFilter) ([]*database.Event, error) {
	return nil, nil
}
func (stubDB) GetEventByID(context.Context, string) (*database.Event, error) { return nil, nil }
func (stubDB) GetStats(context.Context, time.Time) (*database.Stats, error) {
	return &database.Stats{}, nil
}
func (stubDB) GetTopAttackers(context.Context, int, time.Time) ([]*database.AttackerStats, error) {
	return nil, nil
}
func (stubDB) GetHoneypotStats(context.Context, string, time.Time) (*database.HoneypotStats, error) {
	return &database.HoneypotStats{}, nil
}
func (stubDB) RetentionCleanup(context.Context, time.Time) error                 { return nil }
func (stubDB) Optimize(context.Context) error                                    { return nil }
func (stubDB) ExportData(context.Context, time.Time, time.Time, io.Writer) error { return nil }
func (stubDB) ImportData(context.Context, io.Reader) error                       { return nil }
func (stubDB) WithPool(*database.Pool) database.Database                         { return stubDB{} }
func (stubDB) GetPoolStats() database.PoolStats                                  { return database.PoolStats{} }
func (stubDB) TagEvent(context.Context, *database.Event) error                   { return nil }
func (stubDB) InsertIOC(context.Context, *database.IOC) error                    { return nil }
func (stubDB) InsertIOCs(context.Context, []*database.IOC) error                 { return nil }
func (stubDB) GetIOCs(context.Context, database.IOCFilter) ([]*database.IOC, error) {
	return nil, nil
}
func (stubDB) UpsertTTPSession(context.Context, *database.TTPSession) error { return nil }
func (stubDB) GetTTPSessions(context.Context, int) ([]*database.TTPSession, error) {
	return nil, nil
}
func (stubDB) GetUnclassifiedEvents(context.Context, int) ([]*database.Event, error) {
	return nil, nil
}

// FuzzReadEndpointQueries throws arbitrary query strings at every
// authenticated read endpoint. The filters (honeypot, type, limit, tail, since)
// are attacker-influenced via the URL, so the handlers must parse them without
// panicking and always return a valid HTTP status, never crash the process.
func FuzzReadEndpointQueries(f *testing.F) {
	seeds := []string{
		"limit=10&honeypot=cowrie",
		"limit=-1&honeypot=a&honeypot=b",
		"tail=999999999999999999999999",
		"type=../../etc&honeypot=%00",
		"limit=abc&since=not-a-time",
		"honeypot=' OR 1=1--",
		"limit=0&limit=5",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	cfg := config.Default("fuzz-read")
	cfg.QPotID = validTestID
	cfg.WebUI.QPotIDAuth = true
	s := &Server{config: cfg, database: stubDB{}, mux: http.NewServeMux()}
	s.setupRoutes()
	handler := s.authMiddleware(s.mux)

	// The endpoints whose query parameters (honeypot, type, limit, since) are
	// attacker-influenced and that build their result from s.database alone.
	// /api/status and /api/logs depend on s.manager (always set by New() in
	// production) and parse no interesting query params, so they are out of
	// scope for query-parsing fuzzing.
	paths := []string{"/api/events", "/api/stats", "/api/ioc"}

	f.Fuzz(func(t *testing.T, rawQuery string) {
		for _, p := range paths {
			// Build the request for the bare path, then attach the fuzzed query
			// via RawQuery so arbitrary bytes (spaces, control chars) exercise
			// the handler's parser rather than tripping NewRequest's own
			// request-line parsing.
			req := httptest.NewRequest(http.MethodGet, p, nil)
			req.URL.RawQuery = rawQuery
			req.Header.Set("X-QPot-ID", validTestID)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req) // must not panic
			if rec.Code < 100 || rec.Code >= 600 {
				t.Fatalf("path %s query %q: invalid status %d", p, rawQuery, rec.Code)
			}
		}
	})
}
