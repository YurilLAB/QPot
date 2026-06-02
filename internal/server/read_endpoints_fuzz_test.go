package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
)

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
