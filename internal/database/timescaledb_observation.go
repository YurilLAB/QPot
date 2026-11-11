package database

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// RemoveReplayedEvents implements ReplayRemover. Here Event.ID is the row's
// serial id and the observation ID is the event_id column, so the store
// compares the rows itself: an unclassified row goes when another row of the
// same observation is classified, or is older (by time, then id). The oldest
// row of an observation is therefore never deleted, and neither is a
// classified one.
func (ts *TimescaleDB) RemoveReplayedEvents(ctx context.Context, events []*Event) ([]*Event, int, error) {
	if ts.pool == nil {
		return nil, 0, fmt.Errorf("not connected")
	}
	ids := make([]int64, 0, len(events))
	for _, e := range events {
		if e == nil {
			continue
		}
		if id, err := strconv.ParseInt(e.ID, 10, 64); err == nil {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return events, 0, nil
	}
	rows, err := ts.pool.Query(ctx, `
		DELETE FROM events e USING events o
		WHERE e.id = ANY($1::bigint[]) AND e.classified = FALSE AND e.event_id IS NOT NULL
		  AND o.event_id = e.event_id AND o.id <> e.id
		  AND (o.classified = TRUE OR (o.timestamp, o.id) < (e.timestamp, e.id))
		RETURNING e.id::text
	`, ids)
	if err != nil {
		return nil, 0, fmt.Errorf("remove replayed events: %w", err)
	}
	gone := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, 0, fmt.Errorf("remove replayed events: %w", err)
		}
		gone[id] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("remove replayed events: %w", err)
	}
	if len(gone) == 0 {
		return events, 0, nil
	}
	kept := make([]*Event, 0, len(events))
	for _, e := range events {
		if e != nil && !gone[e.ID] {
			kept = append(kept, e)
		}
	}
	return kept, len(gone), nil
}

// CountEvents implements EventRestorer.
func (ts *TimescaleDB) CountEvents(ctx context.Context) (int64, error) {
	if ts.pool == nil {
		return 0, fmt.Errorf("not connected")
	}
	var n int64
	if err := ts.pool.QueryRow(ctx, "SELECT count(*) FROM events").Scan(&n); err != nil {
		return 0, fmt.Errorf("count events: %w", err)
	}
	return n, nil
}

// RestoreEvents implements EventRestorer.
func (ts *TimescaleDB) RestoreEvents(ctx context.Context, events []*Event, dryRun bool) (int, error) {
	if ts.pool == nil {
		return 0, fmt.Errorf("not connected")
	}
	ids := observationIDs(events)
	stored := make(map[string]bool, len(ids))
	if len(ids) > 0 {
		rows, err := ts.pool.Query(ctx, "SELECT DISTINCT event_id::text FROM events WHERE event_id = ANY($1::uuid[])", ids)
		if err != nil {
			return 0, fmt.Errorf("look up stored observations: %w", err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return 0, fmt.Errorf("look up stored observations: %w", err)
			}
			stored[id] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return 0, fmt.Errorf("look up stored observations: %w", err)
		}
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
	batch := &pgx.Batch{}
	for _, e := range missing {
		var meta map[string]string
		if e.Metadata != nil {
			meta = make(map[string]string, len(e.Metadata))
			for k, v := range e.Metadata {
				meta[pgText(k)] = pgText(v)
			}
		}
		batch.Queue(`
			INSERT INTO events (
				timestamp, honeypot, source_ip, source_port, dest_port,
				protocol, event_type, username, password, command,
				payload, metadata, country, city, asn, event_id
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
			ON CONFLICT DO NOTHING
		`,
			e.Timestamp, pgText(e.Honeypot), pgInet(e.SourceIP), e.SourcePort, e.DestPort,
			pgText(e.Protocol), pgText(e.EventType), pgText(e.Username), pgText(e.Password), pgText(e.Command),
			e.Payload, meta, pgText(e.Country), pgText(e.City), pgText(e.ASN), e.ID,
		)
	}
	br := ts.pool.SendBatch(ctx, batch)
	defer br.Close()
	for i := range missing {
		if _, err := br.Exec(); err != nil {
			return 0, fmt.Errorf("store restored event %d/%d: %w", i+1, len(missing), err)
		}
	}
	return len(missing), nil
}

// CountSharedSources implements SharedSourceCounter.
func (ts *TimescaleDB) CountSharedSources(ctx context.Context, since time.Time) (int64, int64, error) {
	if ts.pool == nil {
		return 0, 0, fmt.Errorf("not connected")
	}
	var shared, total int64
	if err := ts.pool.QueryRow(ctx,
		"SELECT count(*) FILTER (WHERE COALESCE(metadata->>$1, '') <> ''), count(*) FROM events WHERE timestamp >= $2",
		SharedSourceKey, since).Scan(&shared, &total); err != nil {
		return 0, 0, fmt.Errorf("count shared source addresses: %w", err)
	}
	return shared, total, nil
}
