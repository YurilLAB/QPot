package server

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// fakeDB is a minimal database.Database for server handler tests. It records
// IOCs passed to InsertIOC and returns zero values everywhere else.
type fakeDB struct {
	mu             sync.Mutex
	iocs           []*database.IOC
	events         []*database.Event
	checkpointData []byte
}

func (f *fakeDB) LoadIntelligenceCheckpoint(context.Context) (*database.IntelligenceCheckpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.checkpointData) == 0 {
		return nil, nil
	}
	var cp database.IntelligenceCheckpoint
	err := json.Unmarshal(f.checkpointData, &cp)
	return &cp, err
}
func (f *fakeDB) SaveIntelligenceCheckpoint(_ context.Context, cp *database.IntelligenceCheckpoint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	f.checkpointData = data
	return nil
}
func (f *fakeDB) ReadIntelligenceIOCs(context.Context, []*database.IOC) ([]*database.IOC, error) {
	return nil, nil
}
func (f *fakeDB) ReplaceIntelligenceIOCs(ctx context.Context, _ uint64, rows []*database.IOC) error {
	return f.InsertIOCs(ctx, rows)
}
func (f *fakeDB) ReplaceIntelligenceSessions(context.Context, uint64, []*database.TTPSession) error {
	return nil
}

func (f *fakeDB) InsertIOC(ctx context.Context, ioc *database.IOC) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.iocs = append(f.iocs, ioc)
	return nil
}
func (f *fakeDB) InsertIOCs(ctx context.Context, iocs []*database.IOC) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.iocs = append(f.iocs, iocs...)
	return nil
}

func (f *fakeDB) Connect(ctx context.Context) error                 { return nil }
func (f *fakeDB) Close() error                                      { return nil }
func (f *fakeDB) Ping(ctx context.Context) error                    { return nil }
func (f *fakeDB) InitializeSchema(ctx context.Context) error        { return nil }
func (f *fakeDB) GetSchemaVersion(ctx context.Context) (int, error) { return 1, nil }
func (f *fakeDB) SetSchemaVersion(ctx context.Context, v int) error { return nil }
func (f *fakeDB) InsertEvent(ctx context.Context, e *database.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
	return nil
}
func (f *fakeDB) InsertEvents(ctx context.Context, e []*database.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e...)
	return nil
}
func (f *fakeDB) insertedEvents() []*database.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*database.Event, len(f.events))
	copy(out, f.events)
	return out
}
func (f *fakeDB) GetEvents(ctx context.Context, fl database.EventFilter) ([]*database.Event, error) {
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
func (f *fakeDB) RetentionCleanup(ctx context.Context, t time.Time) error           { return nil }
func (f *fakeDB) Optimize(ctx context.Context) error                                { return nil }
func (f *fakeDB) ExportData(ctx context.Context, s, e time.Time, w io.Writer) error { return nil }
func (f *fakeDB) ImportData(ctx context.Context, r io.Reader) error                 { return nil }
func (f *fakeDB) WithPool(p *database.Pool) database.Database                       { return f }
func (f *fakeDB) GetPoolStats() database.PoolStats                                  { return database.PoolStats{} }
func (f *fakeDB) TagEvent(ctx context.Context, e *database.Event) error             { return nil }
func (f *fakeDB) GetIOCs(ctx context.Context, fl database.IOCFilter) ([]*database.IOC, error) {
	return nil, nil
}
func (f *fakeDB) UpsertTTPSession(ctx context.Context, s *database.TTPSession) error { return nil }
func (f *fakeDB) GetTTPSessions(ctx context.Context, limit int) ([]*database.TTPSession, error) {
	return nil, nil
}
func (f *fakeDB) GetUnclassifiedEvents(ctx context.Context, limit int) ([]*database.Event, error) {
	return nil, nil
}
