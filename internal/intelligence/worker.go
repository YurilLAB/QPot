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
}

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
			return
		case <-ticker.C:
			w.drain(ctx)
		}
	}
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
	for i := 0; i < maxBatchesPerTick && ctx.Err() == nil; i++ {
		n, tagged := w.runBatch(ctx)
		if n < w.batchSize || !tagged {
			return
		}
	}
}

// runOnce classifies one batch of unclassified events. Returns count classified.
func (w *Worker) runOnce(ctx context.Context) int {
	n, _ := w.runBatch(ctx)
	return n
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
	if len(iocs) > 0 {
		if err := w.db.InsertIOCs(ctx, iocs); err != nil {
			slog.Warn("Intelligence worker: failed to insert IOC batch", "error", err,
				"count", len(iocs))
		}
	}

	n := len(events)

	// Flush and persist expired TTP sessions.
	if w.classifier.ttpBuilder != nil {
		expired := w.classifier.ttpBuilder.FlushExpired()
		for _, session := range expired {
			if err := w.db.UpsertTTPSession(ctx, session); err != nil {
				slog.Warn("Intelligence worker: failed to upsert TTP session", "error", err,
					"session_id", session.SessionID)
			}
		}
	}

	slog.Info("Intelligence worker classified events", "count", n, "interval", w.interval.String())
	return n, tagged
}
