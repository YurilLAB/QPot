package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/hostsetup"
)

// A runtime store must not silently keep the old account-local ownership
// contract when its database cannot provide distributed ownership.
type uncoordinatedWorkerDB struct {
	fakeDB
	loads atomic.Int64
}

// workerLeaseAuthority models one atomic database control record shared by
// independently routed clients. The backend adapters have separate real-DB
// tests; this model exercises Worker lifecycle and delayed transport replies.
type workerLeaseAuthority struct {
	mu              sync.Mutex
	raw             *recoveryDB
	owner           string
	fence, reserved uint64
	expires         time.Time
	clockOffset     time.Duration
	renewErr        error
	renewAmbiguous  bool
	iocRevision     map[string]uint64
	sessionRevision map[string]uint64
}

type leasedWorkerDB struct {
	*recoveryDB
	authority    *workerLeaseAuthority
	identity     string
	issued       database.IntelligenceLease // protected by authority.mu
	acquired     chan struct{}
	renewed      chan struct{}
	loads        atomic.Int64
	reads        atomic.Int64
	saves        atomic.Int64
	tags         atomic.Int64
	projects     atomic.Int64
	closed       atomic.Int64
	acquireErr   error
	holdIOCs     <-chan struct{}
	iocReady     chan struct{}
	iocOnce      sync.Once
	holdAcquire  <-chan struct{}
	acquireReady chan struct{}
}

func newWorkerLeaseAuthority(n int) *workerLeaseAuthority {
	return &workerLeaseAuthority{raw: recoveryStore(n), iocRevision: map[string]uint64{}, sessionRevision: map[string]uint64{}}
}

func (a *workerLeaseAuthority) client(identity string) *leasedWorkerDB {
	return &leasedWorkerDB{recoveryDB: a.raw, authority: a, identity: identity, acquired: make(chan struct{}, 1), renewed: make(chan struct{}, 16)}
}

func (d *leasedWorkerDB) IntelligenceLockIdentity() string { return d.identity }
func (a *workerLeaseAuthority) now() time.Time             { return time.Now().Add(a.clockOffset) }
func (a *workerLeaseAuthority) valid(lease database.IntelligenceLease) error {
	if lease.Owner == "" || lease.Owner != a.owner || lease.Fence != a.fence || lease.Namespace != "shared-database" || !a.expires.After(a.now()) {
		return database.ErrIntelligenceLeaseLost
	}
	return nil
}

func (d *leasedWorkerDB) AcquireIntelligenceLease(ctx context.Context, owner string, ttl time.Duration, minimum uint64) (database.IntelligenceLease, error) {
	if d.acquireErr != nil {
		return database.IntelligenceLease{}, d.acquireErr
	}
	if d.holdAcquire != nil {
		close(d.acquireReady)
		select {
		case <-d.holdAcquire:
		case <-ctx.Done():
			return database.IntelligenceLease{}, ctx.Err()
		}
	}
	a := d.authority
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return database.IntelligenceLease{}, err
	}
	if a.owner != "" && a.expires.After(a.now()) {
		return database.IntelligenceLease{}, database.ErrIntelligenceLeaseBusy
	}
	if a.fence >= math.MaxInt64-1 {
		return database.IntelligenceLease{}, fmt.Errorf("fence exhausted")
	}
	cp, err := a.raw.fakeDB.LoadIntelligenceCheckpoint(ctx)
	if err != nil {
		return database.IntelligenceLease{}, err
	}
	if cp != nil {
		minimum = max(minimum, cp.Revision)
	}
	a.owner, a.fence, a.expires, a.reserved = owner, a.fence+1, a.now().Add(ttl), max(a.reserved, minimum)
	d.issued = database.IntelligenceLease{Owner: owner, Fence: a.fence, ExpiresAt: a.expires, Namespace: "shared-database"}
	select {
	case d.acquired <- struct{}{}:
	default:
	}
	return d.issued, nil
}

func (d *leasedWorkerDB) Close() error { d.closed.Add(1); return nil }

func (d *leasedWorkerDB) RenewIntelligenceLease(ctx context.Context, lease database.IntelligenceLease, ttl time.Duration) (database.IntelligenceLease, error) {
	a := d.authority
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return database.IntelligenceLease{}, err
	}
	if err := a.valid(lease); err != nil {
		return database.IntelligenceLease{}, err
	}
	if a.renewErr == nil || a.renewAmbiguous {
		a.expires = a.now().Add(ttl)
		d.issued.ExpiresAt = a.expires
	}
	select {
	case d.renewed <- struct{}{}:
	default:
	}
	return d.issued, a.renewErr
}

func (d *leasedWorkerDB) ReleaseIntelligenceLease(ctx context.Context, lease database.IntelligenceLease) error {
	a := d.authority
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := a.valid(lease); err != nil {
		return err
	}
	a.owner, a.expires = "", time.Time{}
	return nil
}

func (d *leasedWorkerDB) ValidateIntelligenceLease(ctx context.Context, lease database.IntelligenceLease) error {
	a := d.authority
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return a.valid(lease)
}

func (d *leasedWorkerDB) ReserveIntelligenceRevision(ctx context.Context, lease database.IntelligenceLease, minimum uint64) (uint64, error) {
	a := d.authority
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := a.valid(lease); err != nil {
		return 0, err
	}
	if max(a.reserved, minimum) >= math.MaxInt64-2 {
		return 0, fmt.Errorf("revision exhausted")
	}
	a.reserved = max(a.reserved, minimum) + 1
	return a.reserved, nil
}

func (d *leasedWorkerDB) LoadIntelligenceCheckpoint(ctx context.Context) (*database.IntelligenceCheckpoint, error) {
	d.loads.Add(1)
	d.authority.mu.Lock()
	defer d.authority.mu.Unlock()
	return d.recoveryDB.LoadIntelligenceCheckpoint(ctx)
}

func (d *leasedWorkerDB) GetUnclassifiedEvents(ctx context.Context, limit int) ([]*database.Event, error) {
	d.reads.Add(1)
	d.authority.mu.Lock()
	defer d.authority.mu.Unlock()
	return d.recoveryDB.GetUnclassifiedEvents(ctx, limit)
}

func (d *leasedWorkerDB) SaveIntelligenceCheckpoint(ctx context.Context, cp *database.IntelligenceCheckpoint) error {
	a := d.authority
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.valid(d.issued); err != nil {
		return err
	}
	if cp.Revision > a.reserved {
		return fmt.Errorf("unreserved checkpoint")
	}
	d.saves.Add(1)
	return d.recoveryDB.SaveIntelligenceCheckpoint(ctx, cp)
}

func (d *leasedWorkerDB) ReadIntelligenceIOCs(ctx context.Context, keys []*database.IOC) ([]*database.IOC, error) {
	d.authority.mu.Lock()
	defer d.authority.mu.Unlock()
	return d.recoveryDB.ReadIntelligenceIOCs(ctx, keys)
}

func (d *leasedWorkerDB) ReplaceIntelligenceIOCs(ctx context.Context, revision uint64, rows []*database.IOC) error {
	a := d.authority
	a.mu.Lock()
	if err := a.valid(d.issued); err != nil {
		a.mu.Unlock()
		return err
	}
	data, err := json.Marshal(rows)
	a.mu.Unlock()
	if err != nil {
		return err
	}
	var copy []*database.IOC
	if err := json.Unmarshal(data, &copy); err != nil {
		return err
	}
	if d.holdIOCs != nil {
		d.iocOnce.Do(func() { close(d.iocReady) })
		<-d.holdIOCs // accepted server work may commit after its client loses ownership
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var accepted []*database.IOC
	for _, row := range copy {
		if a.iocRevision[row.ID] <= revision {
			accepted = append(accepted, row)
			a.iocRevision[row.ID] = revision
		}
	}
	d.projects.Add(1)
	return d.recoveryDB.ReplaceIntelligenceIOCs(ctx, revision, accepted)
}

func (d *leasedWorkerDB) ReplaceIntelligenceSessions(ctx context.Context, revision uint64, rows []*database.TTPSession) error {
	a := d.authority
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.valid(d.issued); err != nil {
		return err
	}
	var accepted []*database.TTPSession
	for _, row := range rows {
		if a.sessionRevision[row.SessionID] <= revision {
			accepted = append(accepted, row)
			a.sessionRevision[row.SessionID] = revision
		}
	}
	d.projects.Add(1)
	return d.recoveryDB.ReplaceIntelligenceSessions(ctx, revision, accepted)
}

func (d *leasedWorkerDB) TagEvent(ctx context.Context, event *database.Event) error {
	a := d.authority
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.valid(d.issued); err != nil {
		return err
	}
	d.tags.Add(1)
	return d.recoveryDB.TagEvent(ctx, event)
}

func leasedTestWorker(t *testing.T, db *leasedWorkerDB) *Worker {
	t.Helper()
	base := recoveryWorker(t, db.recoveryDB)
	return NewWorker(base.classifier, db, time.Hour, 100)
}

func ownTestWorker(t *testing.T, worker *Worker) func() {
	t.Helper()
	lock, err := acquireWorkerLock(worker.ownershipKey)
	if err != nil {
		t.Fatal(err)
	}
	worker.ownershipLock = lock
	if err := worker.acquireDatabaseOwnership(t.Context()); err != nil {
		_ = lock.Close()
		t.Fatal(err)
	}
	var closed sync.Once
	return func() {
		closed.Do(func() {
			if leaser, lease, _, err := worker.leaseSnapshot(); err == nil {
				_ = leaser.ReleaseIntelligenceLease(t.Context(), lease)
			}
			_ = lock.Close()
		})
	}
}

func waitWorkerSignal(t *testing.T, signal <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestWorkerDatabaseOwnershipExcludesRoutingAliasesAndRenewsBetweenTicks(t *testing.T) {
	lockTestConfig(t)
	authority := newWorkerLeaseAuthority(0)
	firstDB, secondDB := authority.client("database-hostname"), authority.client("database-address-alias")
	first := leasedTestWorker(t, firstDB)
	first.leaseInterval = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); first.Run(ctx) }()
	waitWorkerSignal(t, firstDB.acquired, "first database owner")
	second := leasedTestWorker(t, secondDB)
	second.Run(t.Context()) // its different local lock cannot provide DB ownership
	if secondDB.loads.Load() != 0 || secondDB.reads.Load() != 0 {
		t.Fatal("second routed client read shared intelligence without ownership")
	}
	var coded *hostsetup.Error
	if !errors.As(second.LastError(), &coded) || coded.Code != CodeOwnership {
		t.Fatalf("second owner error=%v", second.LastError())
	}
	waitWorkerSignal(t, firstDB.renewed, "renewal before the one-hour batch cadence")
	waitWorkerSignal(t, firstDB.renewed, "second independent renewal")
	if status, err := first.Status(); status != "running" || err != nil {
		t.Fatalf("renewing owner status=%s error=%v", status, err)
	}
	cancel()
	waitWorkerSignal(t, done, "owner shutdown")
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.owner != "" || authority.fence != 1 {
		t.Fatalf("release deleted history or retained ownership: owner=%q fence=%d", authority.owner, authority.fence)
	}
}

func TestWorkerAmbiguousRenewalStopsWithoutShutdownWrites(t *testing.T) {
	lockTestConfig(t)
	authority := newWorkerLeaseAuthority(0)
	db := authority.client("renewal-ambiguity")
	w := leasedTestWorker(t, db)
	w.leaseInterval = 10 * time.Millisecond
	done := make(chan struct{})
	go func() { defer close(done); w.Run(t.Context()) }()
	waitWorkerSignal(t, db.acquired, "database owner")
	authority.mu.Lock()
	authority.renewErr, authority.renewAmbiguous = errDBDown, true // server renewed, reply was lost
	authority.mu.Unlock()
	waitWorkerSignal(t, done, "failed-renewal shutdown")
	var coded *hostsetup.Error
	if state, err := w.Status(); state != "stopped" || !errors.As(err, &coded) || coded.Code != CodeLeaseLost {
		t.Fatalf("ambiguous renewal failed open: state=%s error=%v", state, err)
	}
	if db.saves.Load() != 0 || db.tags.Load() != 0 || db.projects.Load() != 0 {
		t.Fatal("empty worker wrote after its renewal became ambiguous")
	}
}

func TestWorkerLeaseLossFencesBackgroundShutdownAndRevisionReservation(t *testing.T) {
	lockTestConfig(t)
	authority := newWorkerLeaseAuthority(1)
	oldDB := authority.client("old-host-account")
	old := leasedTestWorker(t, oldDB)
	closeOld := ownTestWorker(t, old)
	defer closeOld()
	authority.raw.failStage = "iocs"
	old.runOnce(t.Context())
	if old.pending == nil || !old.pendingSaved {
		t.Fatal("fixture did not retain an acknowledged pending checkpoint")
	}
	staleCtx, closeContext, err := old.ownedContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer closeContext()
	authority.mu.Lock()
	authority.clockOffset += time.Minute
	authority.raw.failStage = ""
	authority.mu.Unlock()
	newDB := authority.client("new-host-account")
	next := leasedTestWorker(t, newDB)
	closeNext := ownTestWorker(t, next)
	defer closeNext()
	next.runOnce(t.Context())
	assertRecovery(t, authority.raw, 1)
	saves, tags, projects := oldDB.saves.Load(), oldDB.tags.Load(), oldDB.projects.Load()
	old.shutdown() // fresh background context must not revive the old owner
	if _, err := old.nextRevision(t.Context(), old.pending.Revision); err == nil {
		t.Fatal("fenced owner reserved a revision")
	}
	if oldDB.saves.Load() != saves || oldDB.tags.Load() != tags || oldDB.projects.Load() != projects {
		t.Fatal("fenced owner performed shutdown or reservation writes")
	}
	waitWorkerSignal(t, staleCtx.Done(), "cancellation of already-issued owned contexts")
	var coded *hostsetup.Error
	if !errors.As(old.LastError(), &coded) || coded.Code != CodeLeaseLost {
		t.Fatalf("lost lease error=%v", old.LastError())
	}
}

func TestWorkerValidLeaseAllowsBoundedGracefulRecovery(t *testing.T) {
	lockTestConfig(t)
	authority := newWorkerLeaseAuthority(1)
	db := authority.client("graceful-owner")
	w := leasedTestWorker(t, db)
	closeOwner := ownTestWorker(t, w)
	defer closeOwner()
	authority.raw.failStage = "iocs"
	w.runOnce(t.Context())
	authority.raw.failStage = ""
	w.shutdown()
	assertRecovery(t, authority.raw, 1)
	if w.LastError() != nil {
		t.Fatalf("legitimate graceful recovery retained error: %v", w.LastError())
	}
}

func TestWorkerDelayedOldProjectionCannotOverwriteRecoveredNewerTotals(t *testing.T) {
	lockTestConfig(t)
	authority := newWorkerLeaseAuthority(1)
	oldDB := authority.client("delayed-owner")
	gate := make(chan struct{})
	defer func() {
		select {
		case <-gate:
		default:
			close(gate)
		}
	}()
	oldDB.holdIOCs, oldDB.iocReady = gate, make(chan struct{})
	old := leasedTestWorker(t, oldDB)
	old.leaseInterval = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); old.Run(ctx) }()
	waitWorkerSignal(t, oldDB.iocReady, "accepted old projection")
	_, _, oldLifetime, err := old.leaseSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	authority.mu.Lock()
	authority.clockOffset += time.Minute
	authority.mu.Unlock()
	newDB := authority.client("successor-owner")
	next := leasedTestWorker(t, newDB)
	closeNext := ownTestWorker(t, next)
	defer closeNext()
	waitWorkerSignal(t, oldLifetime.Done(), "old owner renewal fencing")
	if state, err := old.Status(); state != "stopped" || err == nil {
		t.Fatalf("fenced worker advertised running while an old server request was pending: state=%s error=%v", state, err)
	}
	next.runOnce(t.Context()) // recover exact old acknowledged WAL
	authority.mu.Lock()
	extra := *authority.raw.raw[0]
	extra.ID = "second-event"
	extra.Timestamp = extra.Timestamp.Add(time.Second)
	authority.raw.raw = append(authority.raw.raw, &extra)
	authority.mu.Unlock()
	next.runOnce(t.Context()) // publish a genuinely newer count before the late old write
	assertRecovery(t, authority.raw, 2)
	close(gate)
	waitWorkerSignal(t, done, "stale worker termination")
	assertRecovery(t, authority.raw, 2)
	if oldDB.tags.Load() != 0 || oldDB.saves.Load() != 1 {
		t.Fatalf("old owner advanced after delayed projection: saves=%d tags=%d", oldDB.saves.Load(), oldDB.tags.Load())
	}
	var coded *hostsetup.Error
	if !errors.As(old.LastError(), &coded) || coded.Code != CodeLeaseLost {
		t.Fatalf("old worker did not report fencing: %v", old.LastError())
	}
}

func TestWorkerOwnedEventsRequireImmutableRowIdentity(t *testing.T) {
	lockTestConfig(t)
	authority := newWorkerLeaseAuthority(1)
	authority.raw.raw[0].ID = ""
	db := authority.client("missing-event-id")
	w := leasedTestWorker(t, db)
	closeOwner := ownTestWorker(t, w)
	defer closeOwner()
	w.runOnce(t.Context())
	if db.saves.Load() != 0 || db.tags.Load() != 0 || db.projects.Load() != 0 {
		t.Fatal("event without immutable row identity reached durable worker writes")
	}
	var coded *hostsetup.Error
	if !errors.As(w.LastError(), &coded) || coded.Code != CodePreparation {
		t.Fatalf("missing-row-identity error=%v", w.LastError())
	}
}

func TestWorkerCorruptLocalRevisionFloorStopsBeforeGlobalReservation(t *testing.T) {
	lockTestConfig(t)
	authority := newWorkerLeaseAuthority(0)
	w := leasedTestWorker(t, authority.client("corrupt-floor"))
	closeOwner := ownTestWorker(t, w)
	defer closeOwner()
	if _, err := w.ownershipLock.WriteAt([]byte{0xff}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := w.nextRevision(t.Context(), 0); err == nil {
		t.Fatal("corrupt local floor was ignored")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.reserved != 0 {
		t.Fatal("corrupt local floor consumed a database reservation")
	}
}

func TestWorkerIsNotHealthyWhileDatabaseOwnershipIsPending(t *testing.T) {
	lockTestConfig(t)
	authority := newWorkerLeaseAuthority(0)
	db := authority.client("pending-owner")
	gate := make(chan struct{})
	db.holdAcquire, db.acquireReady = gate, make(chan struct{})
	w := leasedTestWorker(t, db)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); w.Run(ctx) }()
	waitWorkerSignal(t, db.acquireReady, "pending ownership request")
	if status, err := w.Status(); status != "not_started" || err != nil {
		t.Fatalf("worker advertised work before acquiring DB ownership: status=%s error=%v", status, err)
	}
	if db.loads.Load() != 0 {
		t.Fatal("worker read a checkpoint before acquiring ownership")
	}
	cancel()
	waitWorkerSignal(t, done, "cancelled ownership request")
}

func TestWorkerUnavailableCoordinationIsNotReportedAsLostExistingLease(t *testing.T) {
	lockTestConfig(t)
	authority := newWorkerLeaseAuthority(1)
	db := authority.client("unavailable-keeper")
	db.acquireErr = database.ErrIntelligenceLeaseUnavailable
	w := leasedTestWorker(t, db)
	w.Run(t.Context())
	var coded *hostsetup.Error
	if state, err := w.Status(); state != "stopped" || !errors.As(err, &coded) || coded.Code != CodeLeaseStore {
		t.Fatalf("unavailable coordination must report its setup prerequisite: state=%s error=%v", state, err)
	}
	if db.loads.Load() != 0 || db.reads.Load() != 0 || db.saves.Load() != 0 || db.projects.Load() != 0 || db.tags.Load() != 0 || db.closed.Load() != 0 {
		t.Fatal("failed ownership acquisition accessed intelligence or closed the shared database")
	}
}

func TestWorkerDatabaseReservationSurvivesAnUnpublishedBatchAcrossAccounts(t *testing.T) {
	lockTestConfig(t)
	authority := newWorkerLeaseAuthority(0)
	first := leasedTestWorker(t, authority.client("first-account"))
	closeFirst := ownTestWorker(t, first)
	defer closeFirst()
	one, err := first.nextRevision(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	closeFirst() // no checkpoint was published; the DB must still retain the reservation
	second := leasedTestWorker(t, authority.client("another-account-and-alias"))
	closeSecond := ownTestWorker(t, second)
	defer closeSecond()
	floor, err := readWorkerRevision(second.ownershipLock)
	if err != nil || floor != 0 {
		t.Fatalf("second account did not start with its independent empty file: floor=%d error=%v", floor, err)
	}
	two, err := second.nextRevision(t.Context(), 0)
	if err != nil || two <= one {
		t.Fatalf("database reused an unpublished reservation: first=%d second=%d error=%v", one, two, err)
	}
	if cp, err := authority.raw.LoadIntelligenceCheckpoint(t.Context()); err != nil || cp != nil {
		t.Fatalf("fixture unexpectedly derived its floor from a checkpoint: checkpoint=%v error=%v", cp, err)
	}
}

func (d *uncoordinatedWorkerDB) IntelligenceLockIdentity() string { return "uncoordinated-runtime" }
func (d *uncoordinatedWorkerDB) LoadIntelligenceCheckpoint(ctx context.Context) (*database.IntelligenceCheckpoint, error) {
	d.loads.Add(1)
	return d.fakeDB.LoadIntelligenceCheckpoint(ctx)
}

func TestWorkerRuntimeWithoutDatabaseOwnershipStopsBeforeCheckpointRead(t *testing.T) {
	lockTestConfig(t)
	db := &uncoordinatedWorkerDB{}
	w := newTestWorker(t, &db.fakeDB)
	w.db = db
	w.ownershipKey = db.IntelligenceLockIdentity()
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
	defer cancel()
	w.Run(ctx)
	var coded *hostsetup.Error
	if !errors.As(w.LastError(), &coded) || coded.Code != "QP-INTEL-008" || db.loads.Load() != 0 {
		t.Fatalf("uncoordinated runtime accessed checkpoint: loads=%d error=%v", db.loads.Load(), w.LastError())
	}
	if status, _ := w.Status(); status != "stopped" {
		t.Fatalf("uncoordinated runtime status=%q", status)
	}
}
