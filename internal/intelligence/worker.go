package intelligence

import (
	"context"
	"log/slog"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// Worker periodically classifies unclassified events in the background.
type Worker struct {
	classifier *Classifier
	db         database.Database
	interval   time.Duration
	batchSize  int
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

	// Flush and persist expired TTP sessions.
	expired := w.classifier.ttpBuilder.FlushExpired()
	for _, session := range expired {
		if err := w.db.UpsertTTPSession(ctx, session); err != nil {
			slog.Warn("Intelligence worker: failed to upsert TTP session", "error", err,
				"session_id", session.SessionID)
		}
	}

	n := len(events)
	slog.Info("Intelligence worker classified events", "count", n, "next_run", w.interval)
	return n
}
