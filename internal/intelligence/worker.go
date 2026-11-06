package intelligence

import (
	"context"
	"log/slog"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// CanaryMatcher inspects each processed event for any planted canary
// (honeytoken) value and records a trip when one is found. It is defined here
// — rather than importing the canary package directly — to keep the
// intelligence package free of that dependency and avoid an import cycle. The
// server wires in a concrete implementation backed by the canary store.
type CanaryMatcher interface {
	// MatchEvent reports whether event tripped a canary (and records it). It
	// must be safe for concurrent use and must never block on slow I/O.
	MatchEvent(ctx context.Context, event *database.Event) bool
}

// Worker periodically classifies unclassified events in the background.
type Worker struct {
	classifier *Classifier
	db         database.Database
	interval   time.Duration
	batchSize  int
	canary     CanaryMatcher

	// Writes that failed, tried again on every pass: the events they came
	// from are already marked classified, so a database that was briefly
	// unavailable otherwise lost them for good. Only the Run goroutine (or a
	// test calling runOnce/drain) touches them.
	pendingIOCs     []*database.IOC
	pendingSessions map[string]*database.TTPSession // by SessionID, the latest version
}

// Bounds of the retry buffers: the newest are kept beyond them.
const (
	maxPendingIOCs     = 100_000
	maxPendingSessions = 10_000
)

// Sane fallbacks so a Worker built from a partially-specified config never
// runs with a zero interval (which would panic time.NewTicker) or a zero
// batch size (which would silently classify nothing).
const (
	defaultWorkerInterval  = 15 * time.Minute
	defaultWorkerBatchSize = 500
)

// NewWorker creates a Worker with the given settings. Non-positive interval
// or batch size are clamped to safe defaults: a zero interval would panic
// time.NewTicker in Run, and a zero batch size would make the worker a no-op.
func NewWorker(classifier *Classifier, db database.Database, interval time.Duration, batchSize int) *Worker {
	if interval <= 0 {
		interval = defaultWorkerInterval
	}
	if batchSize <= 0 {
		batchSize = defaultWorkerBatchSize
	}
	return &Worker{
		classifier: classifier,
		db:         db,
		interval:   interval,
		batchSize:  batchSize,
	}
}

// WithCanaryMatcher attaches a canary matcher so captured sessions are scanned
// for planted honeytoken values as they are classified. Returns the worker to
// allow fluent wiring. A nil matcher is ignored at match time.
func (w *Worker) WithCanaryMatcher(m CanaryMatcher) *Worker {
	w.canary = m
	return w
}

// Run starts the worker loop. Blocks until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// Run immediately on start.
	w.drain(ctx)

	for {
		select {
		case <-ctx.Done():
			w.shutdown()
			return
		case <-ticker.C:
			w.drain(ctx)
		}
	}
}

// shutdownTimeout bounds the final writes when the worker stops.
const shutdownTimeout = 10 * time.Second

// shutdown writes what is still pending and the sessions still in progress,
// which live only in memory and would be lost with the process.
func (w *Worker) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if w.classifier.ttpBuilder != nil {
		for _, session := range w.classifier.ttpBuilder.GetActiveSessions() {
			w.queueSession(session)
		}
	}
	w.flush(ctx)
}

// maxBatchesPerTick bounds one drain so a single tick cannot run forever.
const maxBatchesPerTick = 200

// drain classifies batches until the backlog is empty. One batch per tick
// (500 events every 15 minutes by default) capped classification at ~33
// events a minute, so under normal honeypot load the oldest-first backlog
// grew without bound: IOCs and canary trips lagged further and further, and
// TTP sessions were split once the lag passed their inactivity window.
// Draining stops early when a batch could not be marked classified, since the
// same events would otherwise come straight back and be counted again.
func (w *Worker) drain(ctx context.Context) {
	defer w.flush(ctx)
	for i := 0; i < maxBatchesPerTick && ctx.Err() == nil; i++ {
		n, tagged := w.runBatch(ctx)
		if n < w.batchSize || !tagged {
			return
		}
	}
}

// runOnce classifies one batch of unclassified events and flushes. Returns
// count classified.
func (w *Worker) runOnce(ctx context.Context) int {
	n, _ := w.runBatch(ctx)
	w.flush(ctx)
	return n
}

// flush runs on every pass, events or not: it persists the TTP sessions that
// have expired (with no new events they used to stay in memory, unwritten)
// and tries the writes that failed before again.
func (w *Worker) flush(ctx context.Context) {
	if w.classifier.ttpBuilder != nil {
		for _, session := range w.classifier.ttpBuilder.FlushExpired() {
			w.queueSession(session)
		}
	}
	for id, session := range w.pendingSessions {
		if err := w.db.UpsertTTPSession(ctx, session); err != nil {
			slog.Warn("Intelligence worker: failed to upsert TTP session; will retry", "error", err,
				"session_id", id, "pending", len(w.pendingSessions))
			break // the database is likely down: try the rest next pass
		}
		delete(w.pendingSessions, id)
	}
	if len(w.pendingIOCs) > 0 {
		w.writeIOCs(ctx, nil)
	}
}

// queueSession adds a session to write, replacing an older version of it.
func (w *Worker) queueSession(session *database.TTPSession) {
	if w.pendingSessions == nil {
		w.pendingSessions = make(map[string]*database.TTPSession)
	}
	if _, queued := w.pendingSessions[session.SessionID]; !queued && len(w.pendingSessions) >= maxPendingSessions {
		var oldest string
		for id, s := range w.pendingSessions {
			if oldest == "" || s.LastSeen.Before(w.pendingSessions[oldest].LastSeen) {
				oldest = id
			}
		}
		delete(w.pendingSessions, oldest)
		slog.Warn("Intelligence worker: TTP session retry buffer full; dropped the oldest", "session_id", oldest)
	}
	w.pendingSessions[session.SessionID] = session
}

// writeIOCs inserts the IOCs that failed before and iocs in one batch; on
// failure they are kept (the newest maxPendingIOCs) for the next pass.
func (w *Worker) writeIOCs(ctx context.Context, iocs []*database.IOC) {
	batch := append(w.pendingIOCs, iocs...)
	if len(batch) == 0 {
		return
	}
	if err := w.db.InsertIOCs(ctx, batch); err != nil {
		if drop := len(batch) - maxPendingIOCs; drop > 0 {
			slog.Warn("Intelligence worker: IOC retry buffer full; dropped the oldest", "dropped", drop)
			batch = batch[drop:]
		}
		w.pendingIOCs = batch
		slog.Warn("Intelligence worker: failed to insert IOC batch; will retry", "error", err,
			"count", len(batch))
		return
	}
	w.pendingIOCs = nil
}

// runBatch classifies one batch and reports how many events it processed and
// whether all of them were marked classified.
func (w *Worker) runBatch(ctx context.Context) (int, bool) {
	events, err := w.db.GetUnclassifiedEvents(ctx, w.batchSize)
	if err != nil {
		slog.Warn("Intelligence worker: failed to get unclassified events", "error", err)
		return 0, false
	}

	if len(events) == 0 {
		return 0, true
	}
	tagged := true

	iocs := w.classifier.ClassifyBatch(ctx, events)

	// Scan captured sessions for planted canary (honeytoken) values. A hit
	// means an attacker exfiltrated a token and replayed it against our own
	// deception estate — a high-fidelity signal. Canary trip events
	// (honeypot="canary") are skipped so a recorded trip can never re-trip.
	if w.canary != nil {
		for _, event := range events {
			if event.Honeypot == "canary" {
				continue
			}
			w.canary.MatchEvent(ctx, event)
		}
	}

	// Mark EVERY processed event, not just rule matches. An unmatched event
	// left at classified=0 would be re-fetched every cycle (re-extracting and
	// re-forwarding its IOCs, re-tripping canaries) and, because the fetch is
	// oldest-first with a LIMIT, a full batch of unmatched events would block
	// newer events from ever being classified.
	for _, event := range events {
		event.Classified = true
	}
	if bt, ok := w.db.(database.BatchTagger); ok {
		if err := bt.TagEvents(ctx, events); err != nil {
			tagged = false
			slog.Warn("Intelligence worker: failed to tag events", "error", err, "count", len(events))
		}
	} else {
		for _, event := range events {
			if err := w.db.TagEvent(ctx, event); err != nil {
				tagged = false
				slog.Warn("Intelligence worker: failed to tag event", "error", err)
			}
		}
	}

	// Persist all IOCs from this cycle in one batch. ClickHouse (the default
	// backend) creates a data part per INSERT, so a per-IOC loop here caused
	// avoidable merge pressure; InsertIOCs collapses it into a single batch.
	// Earlier failed IOCs go in the same batch.
	if len(iocs) > 0 || len(w.pendingIOCs) > 0 {
		w.writeIOCs(ctx, iocs)
	}

	n := len(events)

	slog.Info("Intelligence worker classified events", "count", n, "interval", w.interval.String())
	return n, tagged
}
