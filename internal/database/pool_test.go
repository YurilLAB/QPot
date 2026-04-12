package database

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockDB is a minimal Database implementation for pool tests.
// It records how many times Ping was called and can be made to fail.
type mockDB struct {
	mu        sync.Mutex
	pingCalls atomic.Int64
	closed    atomic.Bool
	failPing  atomic.Bool
}

func (m *mockDB) Connect(ctx context.Context) error   { return nil }
func (m *mockDB) Close() error                        { m.closed.Store(true); return nil }
func (m *mockDB) Ping(ctx context.Context) error {
	m.pingCalls.Add(1)
	if m.failPing.Load() {
		return fmt.Errorf("ping failed")
	}
	return nil
}
func (m *mockDB) InitializeSchema(ctx context.Context) error                        { return nil }
func (m *mockDB) GetSchemaVersion(ctx context.Context) (int, error)                 { return 1, nil }
func (m *mockDB) SetSchemaVersion(ctx context.Context, v int) error                 { return nil }
func (m *mockDB) InsertEvent(ctx context.Context, e *Event) error                   { return nil }
func (m *mockDB) InsertEvents(ctx context.Context, evs []*Event) error              { return nil }
func (m *mockDB) GetEvents(ctx context.Context, f EventFilter) ([]*Event, error)    { return nil, nil }
func (m *mockDB) GetEventByID(ctx context.Context, id string) (*Event, error)       { return nil, nil }
func (m *mockDB) GetStats(ctx context.Context, since time.Time) (*Stats, error)     { return &Stats{}, nil }
func (m *mockDB) GetTopAttackers(ctx context.Context, limit int, since time.Time) ([]*AttackerStats, error) {
	return nil, nil
}
func (m *mockDB) GetHoneypotStats(ctx context.Context, hp string, since time.Time) (*HoneypotStats, error) {
	return &HoneypotStats{}, nil
}
func (m *mockDB) RetentionCleanup(ctx context.Context, olderThan time.Time) error { return nil }
func (m *mockDB) Optimize(ctx context.Context) error                              { return nil }
func (m *mockDB) ExportData(ctx context.Context, s, e time.Time, w io.Writer) error {
	return nil
}
func (m *mockDB) ImportData(ctx context.Context, r io.Reader) error { return nil }
func (m *mockDB) WithPool(pool *Pool) Database                      { return m }
func (m *mockDB) GetPoolStats() PoolStats                           { return PoolStats{} }
func (m *mockDB) TagEvent(ctx context.Context, e *Event) error      { return nil }
func (m *mockDB) InsertIOC(ctx context.Context, ioc *IOC) error     { return nil }
func (m *mockDB) GetIOCs(ctx context.Context, f IOCFilter) ([]*IOC, error) {
	return nil, nil
}
func (m *mockDB) UpsertTTPSession(ctx context.Context, s *TTPSession) error { return nil }
func (m *mockDB) GetTTPSessions(ctx context.Context, limit int) ([]*TTPSession, error) {
	return nil, nil
}
func (m *mockDB) GetUnclassifiedEvents(ctx context.Context, limit int) ([]*Event, error) {
	return nil, nil
}

// factory returns a new mockDB.
func mockFactory() (Database, error) { return &mockDB{}, nil }

func newTestPool(t *testing.T, maxOpen, maxIdle int) *Pool {
	t.Helper()
	cfg := &PoolConfig{
		MaxOpenConns:        maxOpen,
		MaxIdleConns:        maxIdle,
		ConnMaxLifetime:     time.Hour,
		ConnMaxIdleTime:     30 * time.Minute,
		HealthCheckInterval: time.Hour, // disable background cleanup during test
		AcquireTimeout:      2 * time.Second,
	}
	p, err := NewPool(cfg, mockFactory)
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

// ---- basic lifecycle ----

func TestPoolAcquireRelease(t *testing.T) {
	p := newTestPool(t, 5, 2)
	conn, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	if conn == nil {
		t.Fatal("Acquire returned nil connection")
	}
	conn.Release()

	stats := p.Stats()
	if stats.InUseConnections != 0 {
		t.Errorf("after Release, InUseConnections = %d, want 0", stats.InUseConnections)
	}
}

func TestPoolAcquireMultiple(t *testing.T) {
	p := newTestPool(t, 5, 2)
	conns := make([]*PooledConnection, 5)
	for i := range conns {
		c, err := p.Acquire(context.Background())
		if err != nil {
			t.Fatalf("Acquire [%d] failed: %v", i, err)
		}
		conns[i] = c
	}
	stats := p.Stats()
	if stats.InUseConnections != 5 {
		t.Errorf("InUseConnections = %d, want 5", stats.InUseConnections)
	}
	for _, c := range conns {
		c.Release()
	}
}

func TestPoolAcquireTimesOutWhenFull(t *testing.T) {
	p := newTestPool(t, 2, 2)
	// Drain all connections.
	c1, _ := p.Acquire(context.Background())
	c2, _ := p.Acquire(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := p.Acquire(ctx)
	if err == nil {
		t.Error("Acquire should fail when pool is full and context times out")
	}
	c1.Release()
	c2.Release()
}

func TestPoolReleaseAfterCloseDoesNotPanic(t *testing.T) {
	p := newTestPool(t, 3, 2)
	conn, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	p.Close()
	// Should not panic.
	conn.Release()
}

func TestPoolCloseIdempotent(t *testing.T) {
	p := newTestPool(t, 3, 2)
	if err := p.Close(); err != nil {
		t.Errorf("first Close failed: %v", err)
	}
	// Second close should not panic (Cleanup in newTestPool calls it again).
}

// ---- concurrent stress ----

func TestPoolConcurrentAcquireRelease(t *testing.T) {
	const maxOpen = 10
	const goroutines = 50
	const opsPerGoroutine = 100

	p := newTestPool(t, maxOpen, 5)

	var wg sync.WaitGroup
	var errCount atomic.Int64

	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < opsPerGoroutine; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				conn, err := p.Acquire(ctx)
				cancel()
				if err != nil {
					// Timeout under high contention is acceptable.
					continue
				}
				// Simulate brief work.
				time.Sleep(time.Microsecond)
				conn.Release()
			}
		}()
	}
	wg.Wait()

	stats := p.Stats()
	if stats.InUseConnections != 0 {
		t.Errorf("after concurrent test, InUseConnections = %d, want 0", stats.InUseConnections)
	}
	_ = errCount.Load()
}

func TestPoolConcurrentWithContextCancellation(t *testing.T) {
	p := newTestPool(t, 3, 3)

	var wg sync.WaitGroup
	const goroutines = 30
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			conn, err := p.Acquire(ctx)
			if err != nil {
				return // timeout/cancel is expected
			}
			time.Sleep(10 * time.Millisecond)
			conn.Release()
		}()
	}
	wg.Wait()

	stats := p.Stats()
	if stats.InUseConnections != 0 {
		t.Errorf("in-use connections should be 0 after test, got %d", stats.InUseConnections)
	}
}

// ---- round-robin ----

func TestReadReplicaPoolRoundRobin(t *testing.T) {
	// Create 3 replica configs.
	replicas := []*ReadReplicaConfig{
		{Name: "r1", Host: "host1", Port: 9001, Weight: 1},
		{Name: "r2", Host: "host2", Port: 9002, Weight: 1},
		{Name: "r3", Host: "host3", Port: 9003, Weight: 1},
	}

	pool, err := NewReadReplicaPool(replicas, func(cfg *ReadReplicaConfig) (Database, error) {
		return &mockDB{}, nil
	})
	if err != nil {
		t.Fatalf("NewReadReplicaPool failed: %v", err)
	}
	defer pool.Close()

	// selectRoundRobin should cycle through replicas.
	seen := make(map[string]int)
	for i := 0; i < 30; i++ {
		r := pool.selectRoundRobin()
		if r != nil {
			seen[r.Config.Name]++
		}
	}
	// Each replica should have been selected roughly equally.
	for _, name := range []string{"r1", "r2", "r3"} {
		if seen[name] == 0 {
			t.Errorf("round-robin never selected replica %q in 30 calls", name)
		}
	}
}

// ---- pool stats ----

func TestPoolStats(t *testing.T) {
	p := newTestPool(t, 5, 3)
	stats := p.Stats()
	if stats.TotalConnections == 0 {
		t.Error("pool should have at least the idle connections created")
	}
	if stats.TotalCreated == 0 {
		t.Error("TotalCreated should be > 0 after pool initialization")
	}
}

// ---- AcquireWithRetry ----

func TestAcquireWithRetrySucceeds(t *testing.T) {
	p := newTestPool(t, 3, 2)
	conn, err := p.AcquireWithRetry(context.Background(), 3)
	if err != nil {
		t.Fatalf("AcquireWithRetry failed: %v", err)
	}
	conn.Release()
}

func TestAcquireWithRetryFailsWhenFull(t *testing.T) {
	p := newTestPool(t, 1, 1)
	// Hold the only connection.
	held, _ := p.Acquire(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := p.AcquireWithRetry(ctx, 2)
	if err == nil {
		t.Error("AcquireWithRetry should fail when pool is exhausted")
	}
	held.Release()
}
