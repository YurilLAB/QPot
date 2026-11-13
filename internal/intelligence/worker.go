package intelligence

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/hostsetup"
)

// CanaryMatcher inspects each processed event for planted canary values.
// Canary notifications are at-least-once across a process crash; they are not
// part of the IOC/TTP checkpoint transaction.
type CanaryMatcher interface {
	MatchEvent(ctx context.Context, event *database.Event) bool
}

// Worker periodically classifies unclassified events in the background. There
// must be one intelligence worker per database, as in the instance server.
// The durable checkpoint is its write-ahead record, not an in-memory retry queue.
type Worker struct {
	classifier *Classifier
	db         database.Database
	interval   time.Duration
	batchSize  int
	canary     CanaryMatcher

	initialized   bool
	revision      uint64
	pending       *database.IntelligenceCheckpoint
	pendingSaved  bool
	canaryScanned bool
	ownershipKey  string
	ownershipLock *os.File
	leaseMu       sync.RWMutex
	leaser        database.IntelligenceLeaser
	lease         database.IntelligenceLease
	leaseLost     error
	leaseContext  context.Context
	leaseCancel   context.CancelFunc
	leaseTTL      time.Duration
	leaseInterval time.Duration
	errorMu       sync.RWMutex
	lastError     error
	running       bool
	started       bool
	ready         bool
	replays       atomic.Uint64
	// sweeping is set while second copies are being found (by a sweep or
	// in a batch): the next sweep is due before the next batch. lastSweep
	// is when one ran; behind says the last batch was full.
	sweeping  bool
	lastSweep time.Time
	behind    bool
}

// ReplaysRemoved returns how many event rows this worker has deleted because
// they were a second copy of an observation already stored: a log line the
// collector read twice. Such a row is never counted.
func (w *Worker) ReplaysRemoved() uint64 { return w.replays.Load() }

// CarryReplaysRemoved starts this worker's count at n: a worker that replaces
// a stopped one goes on counting where that one was.
func (w *Worker) CarryReplaysRemoved(n uint64) { w.replays.Store(n) }

const (
	defaultWorkerInterval  = 5 * time.Minute // config.DefaultWorkerInterval
	defaultWorkerBatchSize = 500
	shutdownTimeout        = 10 * time.Second
	maxBatchesPerTick      = 200
	// sweepEvery is how often the worker looks for second copies of
	// classified events when it has found none lately and has more to
	// classify than one batch; sweepIdleEvery when it is keeping up (then
	// its own next batch reads every unclassified row anyway). A sweep
	// reads the unclassified rows of the events table, which at 25 million
	// rows costs about a second of the database's one CPU.
	sweepEvery     = 30 * time.Second
	sweepIdleEvery = 2 * time.Minute
	// canaryOwnershipEvery is how long the canary scan of a batch goes on
	// without confirming the lease again (the lease lasts 30 seconds).
	canaryOwnershipEvery = time.Second
)

// Stable runtime codes share the CLI's explainable error catalog.
const (
	CodeRecovery    = "QP-INTEL-001"
	CodeCheckpoint  = "QP-INTEL-002"
	CodeReplay      = "QP-INTEL-003"
	CodeOwnership   = "QP-INTEL-004"
	CodePreparation = "QP-INTEL-005"
	CodeEncoding    = "QP-INTEL-006"
	CodeLeaseLost   = "QP-INTEL-007"
	CodeLeaseStore  = "QP-INTEL-008"
)

// LastError returns the last operational error, or nil after successful work.
// Its wrapped cause is available without logging event payloads or credentials.
func (w *Worker) LastError() error {
	w.errorMu.RLock()
	defer w.errorMu.RUnlock()
	return w.lastError
}

// Status returns a consistent lifecycle/error snapshot for health reporting.
// A retrying worker is still running and will retry on its normal cadence;
// stopped means Run returned: this Worker is finished, and the control plane
// starts a new one (which takes a new lease and reloads the checkpoint).
func (w *Worker) Status() (state string, lastError error) {
	w.errorMu.RLock()
	defer w.errorMu.RUnlock()
	var coded *hostsetup.Error
	lost := errors.As(w.lastError, &coded) && coded != nil && coded.Code == CodeLeaseLost
	switch {
	case !w.started:
		state = "not_started"
	case !w.running || lost:
		state = "stopped"
	case !w.ready:
		state = "not_started"
	case w.lastError != nil:
		state = "retrying"
	default:
		state = "running"
	}
	return state, w.lastError
}

func (w *Worker) report(code, stage string, err error) {
	w.leaseMu.RLock()
	owned := w.leaser != nil && w.lease.Owner != ""
	w.leaseMu.RUnlock()
	if owned && !w.hasLostLease() && (errors.Is(err, database.ErrIntelligenceLeaseLost) || errors.Is(err, database.ErrIntelligenceLeaseUnavailable)) {
		w.loseLease(err)
		return
	}
	w.leaseMu.RLock()
	lost := w.leaseLost
	w.leaseMu.RUnlock()
	if lost != nil {
		code, err = CodeLeaseLost, hostsetup.E(CodeLeaseLost).Wrap(lost)
	}
	var coded *hostsetup.Error
	var encoding *database.IntelligenceEncodingError
	if errors.As(err, &encoding) {
		// This is a storage representation limit, not a transient write or
		// connectivity failure. Preserve its cause without logging raw data.
		coded = hostsetup.E(CodeEncoding).Wrap(err)
	} else if !errors.As(err, &coded) {
		coded = hostsetup.E(code).Wrap(err)
	}
	w.errorMu.Lock()
	w.lastError = coded
	w.errorMu.Unlock()
	slog.Warn("Intelligence worker paused", "code", coded.Code, "stage", stage, "remedy", coded.Remedy())
}

func (w *Worker) clearError() {
	w.leaseMu.RLock()
	defer w.leaseMu.RUnlock()
	if w.leaseLost == nil {
		w.errorMu.Lock()
		w.lastError = nil
		w.errorMu.Unlock()
	}
}

// NewWorker creates a worker. Non-positive settings use safe defaults.
func NewWorker(classifier *Classifier, db database.Database, interval time.Duration, batchSize int) *Worker {
	if interval <= 0 {
		interval = defaultWorkerInterval
	}
	if batchSize <= 0 {
		batchSize = defaultWorkerBatchSize
	}
	w := &Worker{classifier: classifier, db: db, interval: interval, batchSize: batchSize}
	if identity, ok := db.(interface{ IntelligenceLockIdentity() string }); ok {
		w.ownershipKey = identity.IntelligenceLockIdentity()
	}
	return w
}

// WithCanaryMatcher attaches the matcher used for captured event observations.
func (w *Worker) WithCanaryMatcher(m CanaryMatcher) *Worker { w.canary = m; return w }

// Run starts the worker loop once and blocks until cancellation. A stopped
// worker requires a new Worker so recovery cannot reuse stale in-memory state.
func (w *Worker) Run(ctx context.Context) {
	w.errorMu.Lock()
	if w.started {
		w.errorMu.Unlock()
		return
	}
	w.started, w.running = true, true
	w.errorMu.Unlock()
	defer func() {
		w.errorMu.Lock()
		w.running = false
		w.errorMu.Unlock()
	}()
	if ctx.Err() != nil {
		return
	}
	if w.ownershipKey != "" {
		lock, err := acquireWorkerLock(w.ownershipKey)
		if err != nil {
			w.report(CodeOwnership, "local ownership", err)
			return
		}
		w.ownershipLock = lock
		defer func() { _ = lock.Close(); w.ownershipLock = nil }()
	}
	if err := w.acquireDatabaseOwnership(ctx); err != nil {
		w.report(CodeOwnership, "database ownership", err)
		return
	}
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	stopRenewal := w.startLeaseRenewal(cancelRun)
	defer stopRenewal()
	w.errorMu.Lock()
	w.ready = true
	w.errorMu.Unlock()
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	// Only a store that can look for second copies ahead of the order gets
	// a sweep between passes.
	var sweepTick <-chan time.Time
	if _, ok := w.db.(database.ReplaySweeper); ok {
		sweepTicker := time.NewTicker(sweepEvery)
		defer sweepTicker.Stop()
		sweepTick = sweepTicker.C
	}
	w.drain(runCtx)
	for {
		select {
		case <-runCtx.Done():
			if ctx.Err() != nil && !w.hasLostLease() {
				w.shutdown()
			}
			return
		case <-ticker.C:
			w.drain(runCtx)
		case <-sweepTick:
			// Second copies found between two passes are removed now,
			// and the pass that removes the rest starts at once.
			if w.sweepDue() && w.sweep(runCtx) > 0 {
				w.drain(runCtx)
			}
		}
	}
}

// sweep removes a window's worth of rows that are second copies of
// classified events, wherever they are in time (database.ReplaySweeper),
// and returns how many. It runs only between batches, never while a batch
// is half recorded. A failure is logged and changes nothing else: the
// copies are still removed when the worker reads them in order.
func (w *Worker) sweep(ctx context.Context) int {
	sweeper, ok := w.db.(database.ReplaySweeper)
	if !ok || !w.initialized || w.pending != nil || ctx.Err() != nil {
		return 0
	}
	w.lastSweep = time.Now()
	w.sweeping = false
	owned, release, err := w.ownedContext(ctx)
	if err != nil {
		w.report(CodeOwnership, "replayed events ownership", err)
		return 0
	}
	defer release()
	if err := w.checkDatabaseOwnership(owned); err != nil {
		w.report(CodeOwnership, "replayed events ownership", err)
		return 0
	}
	removed, err := sweeper.SweepReplayedEvents(owned)
	if err != nil {
		slog.Warn("Looking for events the collector read a second time failed; they are removed when the worker reaches them", "error", err)
		return 0
	}
	if removed > 0 {
		w.sweeping = true
		w.replays.Add(uint64(removed))
		slog.Info("Removed events the collector read a second time", "rows", removed)
	}
	return removed
}

// sweepDue says whether a sweep should run before the next batch: while
// copies are being found, one runs before every batch, so removing them and
// classifying new events take turns; otherwise every sweepEvery while the
// worker is behind and every sweepIdleEvery while it keeps up.
func (w *Worker) sweepDue() bool {
	every := sweepIdleEvery
	if w.behind {
		every = sweepEvery
	}
	return w.sweeping || time.Since(w.lastSweep) >= every
}

// shutdown makes one bounded attempt to complete the durable pending record.
// Abrupt exit is safe too: recovery does not depend on this final attempt.
func (w *Worker) shutdown() {
	if w.hasLostLease() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if w.pending != nil {
		_, _ = w.replay(ctx)
	}
}

func (w *Worker) drain(ctx context.Context) {
	defer w.flush(ctx)
	for i := 0; i < maxBatchesPerTick && ctx.Err() == nil; i++ {
		if w.sweepDue() {
			w.sweep(ctx)
		}
		n, complete := w.runBatch(ctx)
		w.behind = complete && n >= w.batchSize
		if !complete || (n < w.batchSize && !w.sweeping) {
			return
		}
	}
}

func (w *Worker) runOnce(ctx context.Context) int {
	n, _ := w.runBatch(ctx)
	w.flush(ctx)
	return n
}

// Active sessions are persisted with every batch, before its events are tagged.
// Expiration now only releases memory; it cannot discard unwritten intelligence.
func (w *Worker) flush(context.Context) {
	if w.pending == nil && w.classifier.ttpBuilder != nil {
		w.classifier.ttpBuilder.FlushExpired()
	}
}

func (w *Worker) initialize(ctx context.Context) error {
	if w.initialized {
		return nil
	}
	store, ok := w.db.(database.IntelligenceStore)
	if !ok {
		return hostsetup.E(CodePreparation).Wrap(fmt.Errorf("database does not support durable intelligence checkpoints"))
	}
	cp, err := store.LoadIntelligenceCheckpoint(ctx)
	if err != nil {
		return err
	}
	if cp != nil {
		if cp.Revision == 0 || cp.Revision >= math.MaxInt64-1 {
			return fmt.Errorf("invalid intelligence checkpoint revision")
		}
		if w.classifier.ttpBuilder != nil {
			if err := w.classifier.ttpBuilder.restoreCheckpoint(cp.State); err != nil {
				return err
			}
		}
		w.revision = cp.Revision
		if !cp.Complete {
			w.pending, w.pendingSaved = cp, true
		} else {
			w.flush(ctx)
		}
	} else if w.classifier.ttpBuilder != nil {
		// Nothing durable yet: whatever a predecessor that lost its lease
		// left in the shared builder was never committed, and its events
		// will be read again. Counting on top of it would count them twice.
		if err := w.classifier.ttpBuilder.restoreCheckpoint(nil); err != nil {
			return err
		}
	}
	w.initialized = true
	return nil
}

// replay never recomputes counts or reclassifies events. In particular, a write
// error can mean the server committed before the connection failed: retrying the
// same revision and absolute rows is safe in that case too.
func (w *Worker) replay(ctx context.Context) (int, bool) {
	cp := w.pending
	if cp == nil {
		return 0, true
	}
	owned, release, err := w.ownedContext(ctx)
	if err != nil {
		w.report(CodeReplay, "replay ownership", err)
		return len(cp.Events), false
	}
	defer release()
	ctx = owned
	n := len(cp.Events)
	store := w.db.(database.IntelligenceStore)
	fail := func(stage string, err error) (int, bool) {
		code := CodeReplay
		if stage == "checkpoint" || stage == "completion" {
			code = CodeCheckpoint
		}
		w.report(code, stage, err)
		return n, false
	}
	if !w.pendingSaved {
		if err := store.SaveIntelligenceCheckpoint(ctx, cp); err != nil {
			return fail("checkpoint", err)
		}
		w.pendingSaved = true
	}
	if !cp.Complete {
		if err := w.validateOwnedEvents(cp.Events); err != nil {
			return fail("event identity", err)
		}
		if err := w.checkDatabaseOwnership(ctx); err != nil {
			return fail("IOCs ownership", err)
		}
		if err := store.ReplaceIntelligenceIOCs(ctx, cp.Revision, cp.IOCs); err != nil {
			return fail("IOCs", err)
		}
		if err := w.checkDatabaseOwnership(ctx); err != nil {
			return fail("sessions ownership", err)
		}
		if err := store.ReplaceIntelligenceSessions(ctx, cp.Revision, cp.Sessions); err != nil {
			return fail("sessions", err)
		}

		// Scan captured events for watched canary (honeytoken) values. A hit
		// confirms the value appeared in monitored event data, not who used it or
		// whether access was malicious. Canary trip events (honeypot="canary") are
		// skipped so a recorded trip can never re-trip.
		if !w.canaryScanned {
			if w.canary != nil {
				// Ownership is confirmed before the scan and again whenever
				// canaryOwnershipEvery has passed, not before every event: a
				// database round trip per event was a fifth of a batch's time.
				var checked time.Time
				for _, event := range cp.Events {
					if event.Honeypot != "canary" {
						if time.Since(checked) >= canaryOwnershipEvery {
							if err := w.checkDatabaseOwnership(ctx); err != nil {
								return fail("canary ownership", err)
							}
							checked = time.Now()
						}
						w.canary.MatchEvent(ctx, event)
					}
				}
			}
			w.canaryScanned = true
		}
		if err := w.checkDatabaseOwnership(ctx); err != nil {
			return fail("event tags ownership", err)
		}
		if bt, ok := w.db.(database.BatchTagger); ok {
			if err := bt.TagEvents(ctx, cp.Events); err != nil {
				return fail("event tags", err)
			}
		} else {
			for _, event := range cp.Events {
				if err := w.checkDatabaseOwnership(ctx); err != nil {
					return fail("event tag ownership", err)
				}
				if err := w.db.TagEvent(ctx, event); err != nil {
					return fail("event tag", err)
				}
			}
		}
		// Retain the active session state, but release the completed batch's raw
		// payloads. Completion is a new version, never a conflicting overwrite
		// of the prepared record under the same revision.
		revision, err := w.nextRevision(ctx, cp.Revision)
		if err != nil {
			return fail("completion", err)
		}
		cp = &database.IntelligenceCheckpoint{Revision: revision, State: cp.State, Complete: true}
		w.pending, w.pendingSaved = cp, false
		if err := store.SaveIntelligenceCheckpoint(ctx, cp); err != nil {
			return fail("completion", err)
		}
	}
	w.revision = cp.Revision
	w.pending, w.pendingSaved, w.canaryScanned = nil, false, false
	w.clearError()
	return n, true
}

func (w *Worker) runBatch(ctx context.Context) (int, bool) {
	owned, release, err := w.ownedContext(ctx)
	if err != nil {
		w.report(CodeOwnership, "batch ownership", err)
		return 0, false
	}
	defer release()
	ctx = owned
	if err := w.initialize(ctx); err != nil {
		w.report(CodeRecovery, "recover checkpoint", err)
		return 0, false
	}
	if w.pending != nil {
		return w.replay(ctx)
	}
	events, err := w.db.GetUnclassifiedEvents(ctx, w.batchSize)
	if err != nil {
		w.report(CodePreparation, "read source events", err)
		return 0, false
	}
	if len(events) == 0 {
		w.clearError()
		return 0, true
	}
	if err := w.validateOwnedEvents(events); err != nil {
		w.report(CodePreparation, "source event identity", err)
		return 0, false
	}
	// A collector that lost its place reads log lines again, and they arrive
	// as new rows with the observation ID of the rows already stored. Delete
	// those second copies before anything is counted. This needs no
	// write-ahead record: which copy goes is decided by the stored rows
	// alone, so doing it twice, or after a crash, removes nothing more.
	if remover, ok := w.db.(database.ReplayRemover); ok {
		if err := w.checkDatabaseOwnership(ctx); err != nil {
			w.report(CodeOwnership, "replayed events ownership", err)
			return 0, false
		}
		read := len(events)
		kept, removed, err := remover.RemoveReplayedEvents(ctx, events)
		if err != nil {
			w.report(CodePreparation, "remove replayed events", err)
			return 0, false
		}
		if removed > 0 {
			w.replays.Add(uint64(removed))
			// More copies may lie further on: look for them ahead of the
			// order from the next batch on.
			w.sweeping = true
			slog.Info("Removed events the collector read a second time", "rows", removed)
		}
		if events = kept; len(events) == 0 {
			w.clearError()
			return read, true
		}
	}

	// Before preparing anything, save the previous builder state so a baseline
	// read failure cannot count these events a second time on the next pass.
	var before []byte
	if w.classifier.ttpBuilder != nil {
		before, err = w.classifier.ttpBuilder.checkpoint()
		if err != nil {
			w.report(CodePreparation, "snapshot sessions", err)
			return 0, false
		}
	}
	// The direct canary-trip path owns its policy-assigned tags and additive
	// IOC keys. A legacy unclassified canary row needs acknowledgment, not a
	// second classification or worker projection that overwrites that path.
	var iocs []*database.IOC
	for _, event := range events {
		if event.Honeypot != "canary" {
			iocs = append(iocs, w.classifier.Classify(ctx, event)...)
		}
	}
	iocs, err = w.prepareIOCs(ctx, iocs)
	if err != nil {
		if w.classifier.ttpBuilder != nil {
			_ = w.classifier.ttpBuilder.restoreCheckpoint(before)
		}
		w.report(CodePreparation, "prepare IOC baseline", err)
		return len(events), false
	}
	revision, err := w.nextRevision(ctx, w.revision)
	if err != nil {
		if w.classifier.ttpBuilder != nil {
			_ = w.classifier.ttpBuilder.restoreCheckpoint(before)
		}
		w.report(CodeCheckpoint, "reserve checkpoint revision", err)
		return len(events), false
	}
	cp := &database.IntelligenceCheckpoint{Revision: revision, Events: events, IOCs: iocs}
	for _, event := range events {
		event.Classified = true
	}
	if w.classifier.ttpBuilder != nil {
		cp.Sessions = w.classifier.ttpBuilder.GetActiveSessions()
		cp.State, err = w.classifier.ttpBuilder.checkpoint()
		if err != nil {
			_ = w.classifier.ttpBuilder.restoreCheckpoint(before)
			w.report(CodePreparation, "encode session checkpoint", err)
			return len(events), false
		}
	}
	w.pending, w.pendingSaved, w.canaryScanned = cp, false, false
	return w.replay(ctx)
}

// prepareIOCs folds each stored baseline exactly once BEFORE checkpointing.
// Backends look up complete identities rather than paginating search results;
// long values omitted from search indexes still have retrievable stored rows.
func (w *Worker) prepareIOCs(ctx context.Context, sightings []*database.IOC) ([]*database.IOC, error) {
	type key struct{ typ, value, honeypot string }
	rows := make(map[key]*database.IOC)
	var result []*database.IOC
	merge := func(dst, src *database.IOC) {
		dst.Count += src.Count
		if !src.FirstSeen.IsZero() && (dst.FirstSeen.IsZero() || src.FirstSeen.Before(dst.FirstSeen)) {
			dst.FirstSeen = src.FirstSeen
		}
		if src.LastSeen.After(dst.LastSeen) {
			dst.LastSeen = src.LastSeen
		}
	}
	for _, ioc := range sightings {
		if ioc == nil {
			continue
		}
		k := key{ioc.Type, ioc.Value, ioc.Honeypot}
		if dst := rows[k]; dst != nil {
			merge(dst, ioc)
		} else {
			cp := *ioc
			rows[k] = &cp
			result = append(result, &cp)
		}
	}
	stored, err := w.db.(database.IntelligenceStore).ReadIntelligenceIOCs(ctx, result)
	if err != nil {
		return nil, err
	}
	for _, old := range stored {
		if dst := rows[key{old.Type, old.Value, old.Honeypot}]; dst != nil {
			merge(dst, old)
			if dst.TechniqueID == "" {
				dst.TechniqueID = old.TechniqueID
			}
		}
	}
	return result, nil
}
