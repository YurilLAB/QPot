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
