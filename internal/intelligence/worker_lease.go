package intelligence

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/hostsetup"
)

const workerLeaseTTL = 30 * time.Second

// acquireDatabaseOwnership runs before checkpoint recovery. The local account
// lock is additional exclusion and a migration seed, never the DB authority.
func (w *Worker) acquireDatabaseOwnership(ctx context.Context) error {
	if w.ownershipKey == "" {
		return nil // hermetic, non-runtime stores used by classifier callers
	}
	leaser, ok := w.db.(database.IntelligenceLeaser)
	if !ok {
		return hostsetup.E(CodeLeaseStore).Wrap(fmt.Errorf("database cannot provide intelligence ownership"))
	}
	if w.ownershipLock == nil {
		return fmt.Errorf("local intelligence ownership is not held")
	}
	minimum, err := readWorkerRevision(w.ownershipLock)
	if err != nil {
		return err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	owner := hex.EncodeToString(nonce[:])
	ttl := w.leaseTTL
	if ttl == 0 {
		ttl = workerLeaseTTL
	}
	lease, err := leaser.AcquireIntelligenceLease(ctx, owner, ttl, minimum)
	if err != nil {
		if errors.Is(err, database.ErrIntelligenceLeaseUnavailable) {
			return hostsetup.E(CodeLeaseStore).Wrap(err)
		}
		return err
	}
	if lease.Owner != owner || lease.Fence == 0 || lease.ExpiresAt.IsZero() || lease.Namespace == "" {
		return fmt.Errorf("database returned incomplete intelligence ownership")
	}
	w.leaseMu.Lock()
	w.leaser, w.lease, w.leaseLost, w.leaseTTL = leaser, lease, nil, ttl
	w.leaseContext, w.leaseCancel = context.WithCancel(context.Background())
	w.leaseMu.Unlock()
	return nil
}

func (w *Worker) hasLostLease() bool {
	w.leaseMu.RLock()
	defer w.leaseMu.RUnlock()
	return w.leaseLost != nil
}

func (w *Worker) loseLease(err error) {
	w.leaseMu.Lock()
	first := w.leaseLost == nil
	if first {
		w.leaseLost = err
	}
	cancel := w.leaseCancel
	w.leaseMu.Unlock()
	if first {
		w.errorMu.Lock()
		w.lastError = hostsetup.E(CodeLeaseLost).Wrap(err)
		w.errorMu.Unlock()
	}
	if cancel != nil {
		cancel()
	}
	if first {
		w.report(CodeLeaseLost, "database lease lost", err)
	}
}

func (w *Worker) leaseSnapshot() (database.IntelligenceLeaser, database.IntelligenceLease, context.Context, error) {
	w.leaseMu.RLock()
	defer w.leaseMu.RUnlock()
	if w.leaseLost != nil {
		return nil, database.IntelligenceLease{}, nil, hostsetup.E(CodeLeaseLost).Wrap(w.leaseLost)
	}
	if w.leaser == nil || w.lease.Owner == "" || w.leaseContext == nil {
		return nil, database.IntelligenceLease{}, nil, hostsetup.E(CodeOwnership).Wrap(fmt.Errorf("database intelligence ownership is not held"))
	}
	return w.leaser, w.lease, w.leaseContext, nil
}

func (w *Worker) checkDatabaseOwnership(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.ownershipKey == "" {
		return nil
	}
	leaser, lease, _, err := w.leaseSnapshot()
	if err != nil {
		return err
	}
	if err := leaser.ValidateIntelligenceLease(ctx, lease); err != nil {
		// Ordinary cancellation must still permit a bounded graceful replay
		// under a valid lease. A transport failure or lost lease cannot.
		if ctx.Err() != nil && !w.hasLostLease() {
			return ctx.Err()
		}
		w.loseLease(err)
		return hostsetup.E(CodeLeaseLost).Wrap(err)
	}
	return nil
}

// ownedContext also ties graceful shutdown requests to ownership loss. Merely
// creating a fresh background context must never revive a fenced-out worker.
func (w *Worker) ownedContext(ctx context.Context) (context.Context, func(), error) {
	if err := w.checkDatabaseOwnership(ctx); err != nil {
		return nil, nil, err
	}
	if w.ownershipKey == "" {
		return ctx, func() {}, nil
	}
	_, lease, lifetime, err := w.leaseSnapshot()
	if err != nil {
		return nil, nil, err
	}
	owned, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(lifetime, cancel)
	owned = database.WithIntelligenceLease(owned, lease)
	return owned, func() { stop(); cancel() }, nil
}

// startLeaseRenewal keeps ownership alive independently of the batch cadence.
// It remains active during the bounded ordinary shutdown drain. Its cleanup
// waits for renewal to finish before releasing the exact owner/fence tuple.
func (w *Worker) startLeaseRenewal(cancelRun context.CancelFunc) func() {
	if w.ownershipKey == "" {
		return func() {}
	}
	_, _, lifetime, err := w.leaseSnapshot()
	if err != nil {
		w.loseLease(err)
		cancelRun()
		return func() {}
	}
	interval := w.leaseInterval
	if interval == 0 {
		interval = w.leaseTTL / 3
	}
	renewCtx, stopRenewal := context.WithCancel(context.Background())
	done := make(chan struct{})
	stopLoss := context.AfterFunc(lifetime, cancelRun)
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-renewCtx.Done():
				return
			case <-lifetime.Done():
				return
			case <-ticker.C:
				leaser, lease, _, err := w.leaseSnapshot()
				if err != nil {
					w.loseLease(err)
					return
				}
				callCtx, cancel := context.WithTimeout(renewCtx, min(5*time.Second, w.leaseTTL/3))
				next, err := leaser.RenewIntelligenceLease(callCtx, lease, w.leaseTTL)
				cancel()
				if renewCtx.Err() != nil {
					return
				}
				if err == nil && (next.Owner != lease.Owner || next.Fence != lease.Fence || next.Namespace != lease.Namespace || next.ExpiresAt.IsZero()) {
					err = fmt.Errorf("database returned inconsistent intelligence renewal")
				}
				if err != nil {
					w.loseLease(err)
					return
				}
				w.leaseMu.Lock()
				if w.leaseLost == nil {
					w.lease = next
				}
				w.leaseMu.Unlock()
			}
		}
	}()
	return func() {
		stopRenewal()
		<-done
		stopLoss()
		w.leaseMu.Lock()
		leaser, lease, cancel := w.leaser, w.lease, w.leaseCancel
		w.leaser, w.leaseContext, w.leaseCancel = nil, nil, nil
		w.leaseMu.Unlock()
		if cancel != nil {
			cancel()
		}
		ctx, cancelRelease := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancelRelease()
		if err := leaser.ReleaseIntelligenceLease(ctx, lease); err != nil && !errors.Is(err, database.ErrIntelligenceLeaseLost) {
			w.report(CodeOwnership, "release database ownership", err)
		}
	}
}

func (w *Worker) validateOwnedEvents(events []*database.Event) error {
	for _, event := range events {
		if event == nil || (w.ownershipKey != "" && strings.TrimSpace(event.ID) == "") {
			return fmt.Errorf("intelligence source event has no immutable row identity")
		}
	}
	return nil
}
