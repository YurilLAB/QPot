package database

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

// eventIDIndex lets a lookup by observation ID skip the parts of the events
// table that cannot hold it. The table is ordered by time, and a second copy
// of an observation can arrive any time after the first.
const eventIDIndex = "idx_event_id"

// observationChunk is how many IDs one lookup names: about 40 KiB of query
// text, well inside ClickHouse's default query size limit.
const observationChunk = 1000

// ensureEventIDIndex adds the observation ID index to an events table that
// has none, and builds it for the rows already stored.
func (ch *ClickHouse) ensureEventIDIndex(ctx context.Context) error {
	var n uint64
	if err := ch.conn.QueryRow(ctx,
		"SELECT count() FROM system.data_skipping_indices WHERE database = currentDatabase() AND table = 'events' AND name = ?",
		eventIDIndex).Scan(&n); err != nil {
		return fmt.Errorf("check events observation index: %w", err)
	}
	if n > 0 {
		return nil
	}
	if err := ch.conn.Exec(ctx, "ALTER TABLE events ADD INDEX IF NOT EXISTS "+eventIDIndex+" event_id TYPE bloom_filter(0.01) GRANULARITY 4"); err != nil {
		return fmt.Errorf("add events observation index: %w", err)
	}
	// Building it for stored rows runs in the background; until it is done
	// a lookup reads those parts in full, which is slower and still right.
	if err := ch.conn.Exec(ctx, "ALTER TABLE events MATERIALIZE INDEX "+eventIDIndex); err != nil {
		return fmt.Errorf("build events observation index: %w", err)
	}
	return nil
}

// The set of classified observation IDs.
//
// The worker asks, for every batch of new events, which of their IDs already
// have a classified row: those events are second copies. Asked of the events
// table, that reads the whole table, because the table is ordered by time
// and its ID index cannot say no to a few hundred IDs at once (measured: 24
// of 25 million rows read, 2.3 s, for each batch of 500). The IDs the worker
// has classified are therefore kept a second time in a small table ordered
// by ID, where the same question reads a few hundred short ranges.
//
// The set says "classified" only after the events row does (tagging writes
// the row first), so a row can never be taken for a second copy of itself.
// An ID missing from the set costs one event counted twice if the collector
// replays it; an ID wrongly in the set would cost the event. A database
// filled by an earlier version has classified rows and no set: the worker's
// first lookup starts a copy of their IDs in the background and uses the
// events table until that is done.
const (
	classifiedIDsTable = "classified_event_ids"
	// classifiedIDsReady is the row whose presence says the IDs of every
	// row classified before the set existed are in it.
	classifiedIDsReady = "00000000-0000-0000-0000-000000000000"
	// classifiedIDsRetry is how long a failed copy waits before the next.
	classifiedIDsRetry = time.Minute
)

// classifiedIDs is what one connection knows about the set.
type classifiedIDs struct {
	mu      sync.Mutex
	ready   bool
	copying bool
	next    time.Time // no copy is started before this
}

// ensureClassifiedIDs creates the set. Its rows outlive the events they name
// by a few days (events are kept 90 days from their time, IDs 100 days from
// their classification), so a replay of an event that still exists is found.
func (ch *ClickHouse) ensureClassifiedIDs(ctx context.Context) error {
	if err := ch.conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS `+classifiedIDsTable+` (
			event_id UUID,
			seen DateTime DEFAULT now()
		) ENGINE = ReplacingMergeTree
		ORDER BY event_id
		TTL seen + INTERVAL 100 DAY
		SETTINGS index_granularity = 256
	`); err != nil {
		return fmt.Errorf("create the set of classified observation IDs: %w", err)
	}
	return nil
}

// recordClassifiedIDs adds the IDs of events that were just marked
// classified. Adding an ID twice changes nothing.
func (ch *ClickHouse) recordClassifiedIDs(ctx context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}
	batch, err := ch.conn.PrepareBatch(ctx, "INSERT INTO "+classifiedIDsTable+" (event_id)")
	if err != nil {
		return fmt.Errorf("record classified observation IDs: %w", err)
	}
	defer batch.Abort()
	for _, e := range events {
		if err := batch.Append(e.ID); err != nil {
			return fmt.Errorf("record classified observation IDs: %w", err)
		}
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("record classified observation IDs: %w", err)
	}
	return nil
}

// classifiedIDsUsable reports whether the set holds every classified ID. When
// it does not, a copy of the IDs of the rows classified so far is started in
// the background (one at a time, and not more often than classifiedIDsRetry).
func (ch *ClickHouse) classifiedIDsUsable(ctx context.Context) bool {
	ch.ids.mu.Lock()
	defer ch.ids.mu.Unlock()
	if ch.ids.ready {
		return true
	}
	var n uint64
	if err := ch.conn.QueryRow(ctx, "SELECT count() FROM "+classifiedIDsTable+" WHERE event_id = toUUID(?)", classifiedIDsReady).Scan(&n); err != nil {
		return false
	}
	if n > 0 {
		ch.ids.ready = true
		return true
	}
	if !ch.ids.copying && !time.Now().Before(ch.ids.next) {
		ch.ids.copying = true
		go ch.copyClassifiedIDs()
	}
	return false
}

// copyClassifiedIDs fills the set from the events table and then marks it
// complete. Rows the worker classifies meanwhile are added by the worker,
// so the copy only has to cover what was classified before it began.
func (ch *ClickHouse) copyClassifiedIDs() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	err := ch.fillClassifiedIDs(ctx)
	ch.ids.mu.Lock()
	ch.ids.copying = false
	if err != nil {
		ch.ids.next = time.Now().Add(classifiedIDsRetry)
	}
	ch.ids.mu.Unlock()
	if err != nil {
		slog.Warn("The IDs of classified events were not copied; lookups read the events table until they are", "error", err)
	}
}

func (ch *ClickHouse) fillClassifiedIDs(ctx context.Context) error {
	start := time.Now()
	// One thread: the copy shares the database's one CPU with the collector.
	sctx := clickhouse.Context(ctx, clickhouse.WithSettings(clickhouse.Settings{"max_threads": 1, "max_insert_threads": 1}))
	if err := ch.conn.Exec(sctx, "INSERT INTO "+classifiedIDsTable+" (event_id, seen) SELECT event_id, toDateTime(timestamp) FROM events WHERE classified = 1"); err != nil {
		return err
	}
	// The marker outlives every other row.
	if err := ch.conn.Exec(ctx, "INSERT INTO "+classifiedIDsTable+" (event_id, seen) VALUES (toUUID(?), toDateTime('2100-01-01 00:00:00'))", classifiedIDsReady); err != nil {
		return err
	}
	slog.Info("Copied the IDs of classified events", "seconds", int(time.Since(start).Seconds()))
	return nil
}

// storedObservations returns which of ids have a row in events; with
// classifiedOnly, a classified row.
func (ch *ClickHouse) storedObservations(ctx context.Context, ids []string, classifiedOnly bool) (map[string]bool, error) {
	found := make(map[string]bool)
	fromSet := classifiedOnly && ch.classifiedIDsUsable(ctx)
	for start := 0; start < len(ids); start += observationChunk {
		end := min(start+observationChunk, len(ids))
		query := "SELECT DISTINCT toString(event_id) FROM events WHERE event_id IN (SELECT toUUID(arrayJoin(?)))"
		if fromSet {
			query = "SELECT DISTINCT toString(event_id) FROM " + classifiedIDsTable + " WHERE event_id IN (SELECT toUUID(arrayJoin(?)))"
		} else if classifiedOnly {
			query += " AND classified = 1"
		}
		rows, err := ch.conn.Query(ctx, query, ids[start:end])
		if err != nil {
			return nil, fmt.Errorf("look up stored observations: %w", err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, fmt.Errorf("look up stored observations: %w", err)
			}
			found[id] = true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, fmt.Errorf("look up stored observations: %w", err)
		}
	}
	return found, nil
}

// RemoveReplayedEvents implements ReplayRemover. A row is deleted only when
// it is unclassified and matches a second copy's ID and time exactly, so the
// copy that stays is never touched. It is a lightweight delete: the rows are
// masked at once (the statement waits for that), so the next read of
// unclassified events no longer returns them, and no part is rewritten for a
// batch of a few hundred rows.
func (ch *ClickHouse) RemoveReplayedEvents(ctx context.Context, events []*Event) ([]*Event, int, error) {
	if ch.conn == nil {
		return nil, 0, fmt.Errorf("not connected")
	}
	ids := observationIDs(events)
	if len(ids) == 0 {
		return events, 0, nil
	}
	classified, err := ch.storedObservations(ctx, ids, true)
	if err != nil {
		return nil, 0, err
	}
	plan := planReplays(events, classified)
	if len(plan.remove) == 0 {
		return plan.keep, 0, nil
	}
	sctx := clickhouse.Context(ctx, clickhouse.WithSettings(clickhouse.Settings{"lightweight_deletes_sync": 2}))
	for start := 0; start < len(plan.remove); start += tagChunk {
		chunk := plan.remove[start:min(start+tagChunk, len(plan.remove))]
		rowIDs := make([]string, len(chunk))
		keys := make([]string, len(chunk))
		lo, hi := chunk[0].Timestamp, chunk[0].Timestamp
		for i, e := range chunk {
			rowIDs[i] = e.ID
			keys[i] = e.ID + "@" + strconv.FormatInt(e.Timestamp.UnixMilli(), 10)
			if e.Timestamp.Before(lo) {
				lo = e.Timestamp
			}
			if e.Timestamp.After(hi) {
				hi = e.Timestamp
			}
		}
		if err := ch.conn.Exec(sctx, `
			DELETE FROM events
			WHERE classified = 0
			  AND toString(event_id) IN ?
			  AND has(?, concat(toString(event_id), '@', toString(toUnixTimestamp64Milli(timestamp))))
			  AND timestamp >= fromUnixTimestamp64Milli(?) AND timestamp <= fromUnixTimestamp64Milli(?)
		`, rowIDs, keys, lo.UnixMilli(), hi.UnixMilli()); err != nil {
			return nil, 0, fmt.Errorf("remove replayed events: %w", err)
		}
	}
	return plan.keep, len(plan.remove), nil
}

// CountEvents implements EventRestorer.
func (ch *ClickHouse) CountEvents(ctx context.Context) (int64, error) {
	if ch.conn == nil {
		return 0, fmt.Errorf("not connected")
	}
	var n uint64
	if err := ch.conn.QueryRow(ctx, "SELECT count() FROM events").Scan(&n); err != nil {
		return 0, fmt.Errorf("count events: %w", err)
	}
	return int64(n), nil
}

// restoreAttempts and restoreBackoff bound how often and how long a restore
// batch waits for a server that is short of memory.
const restoreAttempts = 6

var restoreBackoff = time.Second

// memoryRefusal reports whether err is ClickHouse refusing a query because
// the server is at its memory limit (code 241). It passes: merges and other
// queries finish, and the same query then runs.
func memoryRefusal(err error) bool {
	var ex *clickhouse.Exception
	return errors.As(err, &ex) && ex.Code == 241
}

// RestoreEvents implements EventRestorer. A batch the server refuses for lack
// of memory is tried again a few times: looking up and then storing is safe
// to repeat, since what the first try stored is found by the second.
func (ch *ClickHouse) RestoreEvents(ctx context.Context, events []*Event, dryRun bool) (int, error) {
	if ch.conn == nil {
		return 0, fmt.Errorf("not connected")
	}
	stored := 0
	wait := restoreBackoff
	for attempt := 1; ; attempt++ {
		n, err := ch.restoreEvents(ctx, events, dryRun)
		stored += n
		if err == nil || !memoryRefusal(err) || attempt == restoreAttempts {
			return stored, err
		}
		select {
		case <-ctx.Done():
			return stored, ctx.Err()
		case <-time.After(wait):
		}
		wait *= 2
	}
}

func (ch *ClickHouse) restoreEvents(ctx context.Context, events []*Event, dryRun bool) (int, error) {
	stored, err := ch.storedObservations(ctx, observationIDs(events), false)
	if err != nil {
		return 0, err
	}
	var missing []*Event
	for _, e := range events {
		if e != nil && IsObservationID(e.ID) && !stored[e.ID] {
			stored[e.ID] = true // a backup that holds a line twice restores it once
			missing = append(missing, e)
		}
	}
	if dryRun || len(missing) == 0 {
		return len(missing), nil
	}
	batch, err := ch.conn.PrepareBatch(ctx, `INSERT INTO events (timestamp, honeypot, source_ip, source_port,
		dest_port, protocol, event_type, username, password, command, payload, metadata, country, city, asn, event_id)`)
	if err != nil {
		return 0, fmt.Errorf("prepare restore batch: %w", err)
	}
	for _, e := range missing {
		meta := e.Metadata
		if meta == nil {
			meta = map[string]string{}
		}
		if err := batch.Append(e.Timestamp, e.Honeypot, e.SourceIP, e.SourcePort, e.DestPort,
			e.Protocol, e.EventType, e.Username, e.Password, e.Command, string(e.Payload), meta,
			e.Country, e.City, e.ASN, e.ID); err != nil {
			_ = batch.Abort()
			return 0, fmt.Errorf("append restored event: %w", err)
		}
	}
	if err := batch.Send(); err != nil {
		return 0, fmt.Errorf("store restored events: %w", err)
	}
	return len(missing), nil
}

// CountSharedSources implements SharedSourceCounter.
func (ch *ClickHouse) CountSharedSources(ctx context.Context, since time.Time) (int64, int64, error) {
	if ch.conn == nil {
		return 0, 0, fmt.Errorf("not connected")
	}
	var shared, total uint64
	if err := ch.conn.QueryRow(ctx,
		"SELECT countIf(metadata[?] != ''), count() FROM events WHERE timestamp >= fromUnixTimestamp64Milli(?)",
		SharedSourceKey, since.UnixMilli()).Scan(&shared, &total); err != nil {
		return 0, 0, fmt.Errorf("count shared source addresses: %w", err)
	}
	return int64(shared), int64(total), nil // #nosec G115 -- row counts
}
