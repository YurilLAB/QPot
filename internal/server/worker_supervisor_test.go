package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/intelligence"
)

// leaseDB is a database whose worker lease the test can refuse and revoke.
type leaseDB struct {
	fakeDB
	mu       sync.Mutex
	refuse   int  // refuse this many acquisitions
	revoked  bool // the current lease is gone
	fence    uint64
	acquired int
}

func (d *leaseDB) IntelligenceLockIdentity() string { return "worker-supervisor-test" }

func (d *leaseDB) AcquireIntelligenceLease(_ context.Context, owner string, ttl time.Duration, _ uint64) (database.IntelligenceLease, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.refuse > 0 {
		d.refuse--
		return database.IntelligenceLease{}, database.ErrIntelligenceLeaseBusy
	}
	d.fence++
	d.acquired++
	d.revoked = false
	return database.IntelligenceLease{Owner: owner, Fence: d.fence, ExpiresAt: time.Now().Add(ttl), Namespace: "test"}, nil
}

func (d *leaseDB) held(lease database.IntelligenceLease) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.revoked || lease.Fence != d.fence {
		return database.ErrIntelligenceLeaseLost
	}
	return nil
}

func (d *leaseDB) RenewIntelligenceLease(_ context.Context, lease database.IntelligenceLease, ttl time.Duration) (database.IntelligenceLease, error) {
	if err := d.held(lease); err != nil {
		return database.IntelligenceLease{}, err
	}
	lease.ExpiresAt = time.Now().Add(ttl)
	return lease, nil
}

func (d *leaseDB) ReleaseIntelligenceLease(context.Context, database.IntelligenceLease) error {
	return nil
}

func (d *leaseDB) ReserveIntelligenceRevision(_ context.Context, lease database.IntelligenceLease, minimum uint64) (uint64, error) {
	if err := d.held(lease); err != nil {
		return 0, err
	}
	return minimum + 1, nil
}

func (d *leaseDB) ValidateIntelligenceLease(_ context.Context, lease database.IntelligenceLease) error {
	return d.held(lease)
}

func (d *leaseDB) revoke() {
	d.mu.Lock()
	d.revoked = true
	d.mu.Unlock()
}

func (d *leaseDB) acquisitions() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.acquired
}

// TestWorkerIsReplacedAfterLosingItsLease: a worker that cannot take the
// database lease, or loses the one it had, stops for good by design. The
// control plane must start a new one. Before, intelligence stayed off until
// the control plane was restarted by hand, and a database restart of 30
// seconds was enough to get there.
func TestWorkerIsReplacedAfterLosingItsLease(t *testing.T) {
	// The worker's local lock lives in the user's config folder.
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("AppData", dir)
	t.Setenv("HOME", dir)
	old := workerRestartDelay
	workerRestartDelay = [2]time.Duration{5 * time.Millisecond, 20 * time.Millisecond}
	t.Cleanup(func() { workerRestartDelay = old })

	db := &leaseDB{refuse: 2}
	loader := intelligence.NewATTCKLoader(t.TempDir())
	builder := intelligence.NewTTPBuilder(time.Minute)
	s := &Server{
		config: &config.Config{QPotID: validTestID, Intelligence: config.IntelligenceConfig{
			Enabled: true, WorkerInterval: 2 * time.Millisecond, WorkerBatchSize: 10}},
		database:   db,
		ttpBuilder: builder,
		classifier: intelligence.NewClassifier(loader, builder),
	}
	first := s.newWorker(db)
	if first == nil {
		t.Fatal("no worker")
	}
	s.worker = first

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); s.superviseWorker(ctx, first) }()

	await := func(what string, ok func() bool) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
			if ok() {
				return
			}
		}
		state, err := s.intelWorker().Status()
		t.Fatalf("%s: worker is %q (%v) after %d acquisitions", what, state, err, db.acquisitions())
	}
	running := func() bool {
		state, _ := s.intelWorker().Status()
		return state == "running"
	}

	// Refused twice (another owner's lease still alive), then admitted.
	await("a worker that was refused the lease is replaced until one gets it", running)
	if s.intelWorker() == first {
		t.Fatal("the worker that was refused the lease is still the one in use")
	}
	if got := db.acquisitions(); got != 1 {
		t.Fatalf("%d leases issued, want 1", got)
	}

	// The database goes away for longer than the lease lasts.
	owner := s.intelWorker()
	db.revoke()
	await("a worker that lost its lease is replaced", func() bool {
		return s.intelWorker() != owner && running() && db.acquisitions() == 2
	})
	if state, _ := owner.Status(); state != "stopped" {
		t.Errorf("the worker that lost its lease is %q, want stopped: it must never be resumed", state)
	}

	// And again: recovery is not a one-off.
	owner = s.intelWorker()
	db.revoke()
	await("a second lost lease is recovered from too", func() bool {
		return s.intelWorker() != owner && running() && db.acquisitions() == 3
	})

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the supervisor did not stop with its context")
	}
}
