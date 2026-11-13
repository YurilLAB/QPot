package intelligence

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// backlogDB serves unclassified events oldest-first and removes them once
// tagged, like a real store.
type backlogDB struct {
	fakeDB
	mu       sync.Mutex
	pending  []*database.Event
	fetches  int
	tagFails bool
}

func (b *backlogDB) GetUnclassifiedEvents(ctx context.Context, limit int) ([]*database.Event, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fetches++
	n := min(limit, len(b.pending))
	return append([]*database.Event(nil), b.pending[:n]...), nil
}

func (b *backlogDB) TagEvent(ctx context.Context, e *database.Event) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tagFails {
		return errors.New("tag failed")
	}
	for i, p := range b.pending {
		if p == e {
			b.pending = append(b.pending[:i], b.pending[i+1:]...)
			break
		}
	}
	return nil
}

func backlog(n int) []*database.Event {
	evs := make([]*database.Event, n)
	for i := range evs {
		evs[i] = &database.Event{Timestamp: time.Now(), Honeypot: "cowrie", SourceIP: "203.0.113.9", EventType: "cowrie.command.input", Command: "id"}
	}
	return evs
}

// One tick must work through the whole backlog, not one batch of it.
func TestWorkerDrainsBacklog(t *testing.T) {
	db := &backlogDB{pending: backlog(250)}
	w := newTestWorker(t, &db.fakeDB)
	w.db = db
	w.drain(context.Background())
	if len(db.pending) != 0 {
		t.Fatalf("%d events left unclassified after one drain (fetches %d)", len(db.pending), db.fetches)
	}
}

// When events cannot be marked classified they would come straight back;
// draining must stop instead of reprocessing (and re-counting) them.
func TestWorkerDrainStopsWhenTaggingFails(t *testing.T) {
	db := &backlogDB{pending: backlog(250), tagFails: true}
	w := newTestWorker(t, &db.fakeDB)
	w.db = db
	w.drain(context.Background())
	if db.fetches != 1 {
		t.Fatalf("fetched %d batches although tagging failed, want 1", db.fetches)
	}
}

// stopDB's read waits until the worker is stopped and then fails with the
// cancellation, as a query does when the control plane stops; with canceled
// set it fails that way at once, while the worker runs.
type stopDB struct {
	fakeDB
	reading  chan struct{}
	canceled bool
}

func (d *stopDB) GetUnclassifiedEvents(ctx context.Context, _ int) ([]*database.Event, error) {
	if d.canceled {
		return nil, context.Canceled
	}
	select {
	case d.reading <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestWorkerStoppedMidStepHasNoError: a step cut short because the worker is
// being stopped is no fault. It was recorded as one, so a worker stopped at
// the wrong moment was reported as stopped with an error it never had. The
// same failure while the worker runs is still reported.
func TestWorkerStoppedMidStepHasNoError(t *testing.T) {
	db := &stopDB{reading: make(chan struct{}, 1)}
	w := NewWorker(newTestClassifierT(t), db, time.Millisecond, 10)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); w.Run(ctx) }()
	select {
	case <-db.reading:
	case <-time.After(5 * time.Second):
		t.Fatal("the worker never read")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	if state, err := w.Status(); state != "stopped" || err != nil {
		t.Fatalf("a worker stopped in the middle of a read: state %q, error %v; want stopped and no error", state, err)
	}

	running := NewWorker(newTestClassifierT(t), &stopDB{canceled: true}, time.Millisecond, 10)
	running.runOnce(context.Background())
	if _, err := running.Status(); err == nil {
		t.Fatal("a read that failed while the worker runs was not reported")
	}
}
