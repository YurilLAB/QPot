package intelligence

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// Forwarder is the subset of the Yuril forwarder the worker needs. Defining
// it here (rather than importing the yuril package directly) keeps the
// intelligence package free of an outbound dependency and avoids any import
// cycle, while *yuril.Forwarder satisfies it as-is.
type Forwarder interface {
	Forward(ctx context.Context, batchID string, iocs []*database.IOC) error
}

// Worker periodically classifies unclassified events in the background.
type Worker struct {
	classifier *Classifier
	db         database.Database
	interval   time.Duration
	batchSize  int
	forwarder  Forwarder
}

// NewWorker creates a Worker with the given settings.
func NewWorker(classifier *Classifier, db database.Database, interval time.Duration, batchSize int) *Worker {
	return &Worker{
		classifier: classifier,
		db:         db,
		interval:   interval,
		batchSize:  batchSize,
	}
}

// WithForwarder attaches a Yuril forwarder so newly classified IOCs are
// pushed downstream after they are persisted. Returns the worker to allow
// fluent wiring. A nil forwarder is ignored at forward time.
func (w *Worker) WithForwarder(f Forwarder) *Worker {
	w.forwarder = f
	return w
}

// Run starts the worker loop. Blocks until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// Run immediately on start.
	w.runOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.runOnce(ctx)
		}
	}
}

// runOnce classifies one batch of unclassified events. Returns count classified.
func (w *Worker) runOnce(ctx context.Context) int {
	events, err := w.db.GetUnclassifiedEvents(ctx, w.batchSize)
	if err != nil {
		slog.Warn("Intelligence worker: failed to get unclassified events", "error", err)
		return 0
	}

	if len(events) == 0 {
		return 0
	}

	iocs := w.classifier.ClassifyBatch(ctx, events)

	for _, event := range events {
		if !event.Classified {
			continue
		}
		if err := w.db.TagEvent(ctx, event); err != nil {
			slog.Warn("Intelligence worker: failed to tag event", "error", err)
		}
	}

	for _, ioc := range iocs {
		if err := w.db.InsertIOC(ctx, ioc); err != nil {
			slog.Warn("Intelligence worker: failed to insert IOC", "error", err,
				"type", ioc.Type, "value", ioc.Value)
		}
	}

	// Push the freshly classified IOCs downstream to Yuril when a forwarder
	// is attached. Forwarding failures are non-fatal: the IOCs are already
	// persisted locally, so QPot stays useful even if Yuril is unreachable.
	if w.forwarder != nil && len(iocs) > 0 {
		batchID := fmt.Sprintf("qpot-intel-%d", time.Now().UnixNano())
		if err := w.forwarder.Forward(ctx, batchID, iocs); err != nil {
			slog.Warn("Intelligence worker: failed to forward IOCs to Yuril",
				"error", err, "count", len(iocs))
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

	slog.Info("Intelligence worker classified events", "count", n, "next_run", w.interval)
	return n
}
