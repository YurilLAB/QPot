package database

import (
	"context"
	"errors"
	"fmt"
	"strconv"
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

// storedObservations returns which of ids have a row in events; with
// classifiedOnly, a classified row.
func (ch *ClickHouse) storedObservations(ctx context.Context, ids []string, classifiedOnly bool) (map[string]bool, error) {
	found := make(map[string]bool)
	for start := 0; start < len(ids); start += observationChunk {
		end := min(start+observationChunk, len(ids))
		query := "SELECT DISTINCT toString(event_id) FROM events WHERE event_id IN (SELECT toUUID(arrayJoin(?)))"
		if classifiedOnly {
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
