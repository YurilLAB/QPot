package database

import (
	"context"
	"fmt"
)

// The dashboard asks for the newest few indicators and sessions every ten
// seconds, and for counts over the newest events. Answered naively, each of
// those reads every column of every row the worker ever stored and sorts
// them (measured with 625,000 indicators: 1.8 s and 136 MB per call, twice
// per open dashboard per poll). The reads here cost what they return:
//
//   - a page of indicators or sessions is found by its keys and time alone,
//     and only the rows of that page are read in full, by primary key;
//   - the legacy tables (iocs, ttp_sessions), which an instance created
//     since the worker has its own tables never fills, are left out of a
//     query when they are empty, and are otherwise matched by their own keys
//     instead of against every key the worker's table holds;
//   - counts over the newest events are made by the database from the
//     columns they need.

const (
	iocColumns = "id, type, value, honeypot, source_ip, technique_id, first_seen, last_seen, count, metadata"
	// iocPageColumns is what choosing a page of indicators needs: the key,
	// the order and what a filter can name.
	iocPageColumns     = "type, value, honeypot, source_ip, first_seen, last_seen"
	sessionColumns     = "session_id, campaign_fingerprint, source_ips, shared_infrastructure, kill_chain_stages, techniques, ioc_ids, event_count, first_seen, last_seen, confidence"
	sessionPageColumns = "session_id, last_seen"
)

// hasRows reports whether a table holds any row. The count comes from the
// parts' metadata; no row is read.
func (ch *ClickHouse) hasRows(ctx context.Context, table string) (bool, error) {
	var n uint64
	if err := ch.conn.QueryRow(ctx, "SELECT count() FROM "+table).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// iocSource is every indicator once, as a subquery: the worker's table, and
// with legacy what only the legacy table holds. With keys (a subquery of
// type, value, honeypot) it is those indicators only, read by primary key.
func iocSource(columns string, legacy bool, keys string) string {
	q := "(SELECT " + columns + " FROM intelligence_iocs FINAL"
	if keys != "" {
		q += " WHERE (type, value, honeypot) IN " + keys
	}
	if legacy {
		q += " UNION ALL SELECT " + columns + " FROM iocs FINAL WHERE (type, value, honeypot) NOT IN" +
			" (SELECT type, value, honeypot FROM intelligence_iocs FINAL WHERE (type, value, honeypot) IN (SELECT type, value, honeypot FROM iocs))"
		if keys != "" {
			q += " AND (type, value, honeypot) IN " + keys
		}
	}
	return q + ")"
}

// sessionSource is every session once, as iocSource is every indicator.
func sessionSource(columns string, legacy bool, keys string) string {
	q := "(SELECT " + columns + " FROM intelligence_sessions FINAL"
	if keys != "" {
		q += " WHERE session_id IN " + keys
	}
	if legacy {
		q += " UNION ALL SELECT " + columns + " FROM ttp_sessions FINAL WHERE session_id NOT IN" +
			" (SELECT session_id FROM intelligence_sessions FINAL WHERE session_id IN (SELECT session_id FROM ttp_sessions))"
		if keys != "" {
			q += " AND session_id IN " + keys
		}
	}
	return q + ")"
}

// TechniqueCount is one ATT&CK technique and how many of the sampled events
// carry it.
type TechniqueCount struct {
	TechniqueID   string
	TechniqueName string
	TacticName    string
	Count         int
}

// RecentSummarizer is implemented by the stores that count over the newest
// events themselves. A caller without it reads the events and counts.
type RecentSummarizer interface {
	// RecentTechniques counts the techniques of the newest sample events,
	// most frequent first; events without a technique are not counted.
	RecentTechniques(ctx context.Context, sample int) ([]TechniqueCount, error)
	// RecentCategories counts the categories of the newest sample events.
	RecentCategories(ctx context.Context, sample int) (map[string]int, error)
}

// IOCCounter is implemented by the stores that can say how many indicators
// they hold without returning them.
type IOCCounter interface {
	CountIOCs(ctx context.Context) (int64, error)
}

// RecentTechniques implements RecentSummarizer.
func (ch *ClickHouse) RecentTechniques(ctx context.Context, sample int) ([]TechniqueCount, error) {
	if ch.conn == nil {
		return nil, fmt.Errorf("not connected")
	}
	if sample <= 0 {
		return nil, nil
	}
	// The name is the newest event's, as a reader of the same events in
	// GetEvents' order (newest first) would take it.
	rows, err := ch.conn.Query(ctx, fmt.Sprintf(`
		SELECT technique_id, argMax(technique_name, timestamp), argMax(tactic_name, timestamp), count() AS c
		FROM (SELECT timestamp, technique_id, technique_name, tactic_name FROM events ORDER BY timestamp DESC LIMIT %d)
		WHERE technique_id != ''
		GROUP BY technique_id
		ORDER BY c DESC, technique_id`, sample))
	if err != nil {
		return nil, fmt.Errorf("count recent techniques: %w", err)
	}
	defer rows.Close()
	var out []TechniqueCount
	for rows.Next() {
		var t TechniqueCount
		var n uint64
		if err := rows.Scan(&t.TechniqueID, &t.TechniqueName, &t.TacticName, &n); err != nil {
			return nil, fmt.Errorf("count recent techniques: %w", err)
		}
		t.Count = int(n)
		out = append(out, t)
	}
	return out, rows.Err()
}

// RecentCategories implements RecentSummarizer.
func (ch *ClickHouse) RecentCategories(ctx context.Context, sample int) (map[string]int, error) {
	if ch.conn == nil {
		return nil, fmt.Errorf("not connected")
	}
	counts := map[string]int{}
	if sample <= 0 {
		return counts, nil
	}
	rows, err := ch.conn.Query(ctx, fmt.Sprintf(`
		SELECT category, count()
		FROM (SELECT categories FROM events ORDER BY timestamp DESC LIMIT %d)
		ARRAY JOIN categories AS category
		GROUP BY category`, sample))
	if err != nil {
		return nil, fmt.Errorf("count recent categories: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var c string
		var n uint64
		if err := rows.Scan(&c, &n); err != nil {
			return nil, fmt.Errorf("count recent categories: %w", err)
		}
		counts[c] = int(n)
	}
	return counts, rows.Err()
}

// CountIOCs implements IOCCounter: every indicator GetIOCs would return with
// no filter, counted from the keys alone.
func (ch *ClickHouse) CountIOCs(ctx context.Context) (int64, error) {
	if ch.conn == nil {
		return 0, fmt.Errorf("not connected")
	}
	legacy, err := ch.hasRows(ctx, "iocs")
	if err != nil {
		return 0, fmt.Errorf("count iocs: %w", err)
	}
	var n uint64
	if err := ch.conn.QueryRow(ctx, "SELECT count() FROM "+iocSource("type, value, honeypot", legacy, "")).Scan(&n); err != nil {
		return 0, fmt.Errorf("count iocs: %w", err)
	}
	return int64(n), nil
}
