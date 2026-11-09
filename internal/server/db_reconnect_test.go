package server

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
)

// lateDatabase makes openDatabase fail until it has been tried `failures`
// times, then return db (never, when db is nil).
func lateDatabase(t *testing.T, failures int, db database.Database) func() int {
	t.Helper()
	var mu sync.Mutex
	tries := 0
	replaceOpenDatabase(t, func(context.Context, *config.Config) (database.Database, error) {
		mu.Lock()
		defer mu.Unlock()
		tries++
		if tries <= failures || db == nil {
			return nil, errFlakyDown
		}
		return db, nil
	}, 10*time.Millisecond, 40*time.Millisecond)
	return func() int { mu.Lock(); defer mu.Unlock(); return tries }
}

// replaceOpenDatabase swaps in open and a short backoff until the test ends.
// Tests that start a server call it before startServer, so the server has
// stopped when they are put back.
func replaceOpenDatabase(t *testing.T, open func(context.Context, *config.Config) (database.Database, error), first, most time.Duration) {
	t.Helper()
	old, oldBackoff := openDatabase, reconnectBackoff
	openDatabase, reconnectBackoff = open, [2]time.Duration{first, most}
	t.Cleanup(func() { openDatabase, reconnectBackoff = old, oldBackoff })
}

// startServer runs s.Start on a free port until stop is called or the test
// ends; stop returns once Start has.
func startServer(t *testing.T, s *Server) (stop func()) {
	t.Helper()
	return startServerOn(t, s, 0)
}

// startServerOn is startServer on 127.0.0.1:port (0: any free port).
func startServerOn(t *testing.T, s *Server, port int) (stop func()) {
	t.Helper()
	s.config.WebUI.BindAddr, s.config.WebUI.Port = "127.0.0.1", port
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(30 * time.Second):
				t.Error("the server did not stop")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

// TestServerReachesALateDatabase: a server that started while its database
// was away keeps trying to reach it. Once it is there, what needs it starts:
// the canary trip waiting in the outbox is written, once, and the
// intelligence worker runs. Before, all of that stayed off until QPot was
// restarted, whenever the database took longer to come back than the start
// waited for it.
func TestServerReachesALateDatabase(t *testing.T) {
	dir := t.TempDir()
	s := newOutboxTestServer(t, nil, dir)
	tripBeacon(t, s) // no database yet: the trip waits in the outbox
	db := &flakyDB{}
	tries := lateDatabase(t, 3, db)
	startServer(t, s)

	deadline := time.Now().Add(10 * time.Second)
	for len(tripEvents(db)) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the trip never reached the database (%d tries to reach it)", tries())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if tries() != 4 {
		t.Errorf("reached the database on try %d, want the 4th", tries())
	}
	if s.db() != db {
		t.Error("the server does not use the database it reached")
	}
	if s.intelWorker() == nil {
		t.Error("the intelligence worker did not start once the database was reached")
	}
	time.Sleep(100 * time.Millisecond) // the outbox loop's next pass changes nothing
	wantOneTripEvent(t, s, db)
}

// TestServerWithoutDatabaseStartsNothingThatNeedsIt: control. While the
// database stays away the server keeps trying, and nothing that needs it
// runs.
func TestServerWithoutDatabaseStartsNothingThatNeedsIt(t *testing.T) {
	s := newOutboxTestServer(t, nil, t.TempDir())
	tripBeacon(t, s)
	tries := lateDatabase(t, 0, nil)
	startServer(t, s)
	time.Sleep(300 * time.Millisecond)
	if tries() < 3 {
		t.Errorf("only %d tries to reach the database", tries())
	}
	if s.db() != nil || s.intelWorker() != nil {
		t.Error("something that needs the database started without one")
	}
	if waiting, err := s.canaryOutbox.pending(); err != nil || len(waiting) != 1 {
		t.Errorf("%d trips waiting (%v), want 1", len(waiting), err)
	}
}

// TestServerStopEndsTheAttemptToReachTheDatabase: stopping the server
// cancels an attempt to reach the database that is under way (one to an
// unanswering host waits up to 15 seconds) and returns only once it has
// ended, so no database is opened after Start returned.
func TestServerStopEndsTheAttemptToReachTheDatabase(t *testing.T) {
	s := newOutboxTestServer(t, nil, t.TempDir())
	var inFlight atomic.Int32
	trying := make(chan struct{}, 1)
	replaceOpenDatabase(t, func(ctx context.Context, _ *config.Config) (database.Database, error) {
		inFlight.Add(1)
		defer inFlight.Add(-1)
		select {
		case trying <- struct{}{}:
		default:
		}
		select { // an unanswering host: only the cancel ends the attempt
		case <-ctx.Done():
		case <-time.After(time.Minute):
		}
		time.Sleep(50 * time.Millisecond) // and giving up takes a moment
		return nil, errFlakyDown
	}, time.Millisecond, time.Millisecond)
	stop := startServer(t, s)
	select {
	case <-trying:
	case <-time.After(10 * time.Second):
		t.Fatal("the server never tried to reach the database")
	}
	begin := time.Now()
	stop()
	if n := inFlight.Load(); n != 0 {
		t.Errorf("Start returned with %d attempts to reach the database still running", n)
	}
	if d := time.Since(begin); d > 10*time.Second {
		t.Errorf("stopping took %v: the attempt was not cancelled", d)
	}
}

// TestServerStopsTryingWithoutADatabaseClient: a config naming no database
// QPot can open stays that way while QPot runs, so it tries once and stops.
func TestServerStopsTryingWithoutADatabaseClient(t *testing.T) {
	s := newOutboxTestServer(t, nil, t.TempDir())
	var tries atomic.Int32
	replaceOpenDatabase(t, func(context.Context, *config.Config) (database.Database, error) {
		tries.Add(1)
		return nil, errNoDatabaseClient
	}, time.Millisecond, time.Millisecond)
	startServer(t, s)
	time.Sleep(200 * time.Millisecond)
	if n := tries.Load(); n != 1 {
		t.Errorf("%d tries for a config without a database client, want 1", n)
	}
}
