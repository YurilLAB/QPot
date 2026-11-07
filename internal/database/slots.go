package database

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Event counts per honeypot in fixed time slots, for the web UI's pulse (a
// timeline of attacks). Database implementations that can count them
// server-side implement SlotCounter; the three QPot ships all do.

// MaxSlots bounds SlotQuery.Slots.
const MaxSlots = 240

// SlotQuery asks for event counts per honeypot in Slots slots of Step each,
// the first starting at From.
type SlotQuery struct {
	From  time.Time
	Step  time.Duration
	Slots int
}

// SlotCount is how many events one honeypot had in one slot (0 is the slot
// starting at From).
type SlotCount struct {
	Honeypot string
	Slot     int
	Count    int64
}

// SlotCounter counts events per honeypot and time slot.
type SlotCounter interface {
	CountSlots(ctx context.Context, q SlotQuery) ([]SlotCount, error)
}

// End is the end of the last slot.
func (q SlotQuery) End() time.Time { return q.From.Add(time.Duration(q.Slots) * q.Step) }

func (q SlotQuery) check() error {
	if q.From.IsZero() || q.Step < time.Second || q.Step > 24*time.Hour || q.Step%time.Millisecond != 0 ||
		q.Slots < 1 || q.Slots > MaxSlots {
		return fmt.Errorf("slot query out of range: step %s, %d slots", q.Step, q.Slots)
	}
	return nil
}

// keep drops counts outside the query's slots (a backend's rounding at the
// edges).
func (q SlotQuery) keep(c SlotCount) bool { return c.Slot >= 0 && c.Slot < q.Slots && c.Count > 0 }

// CountSlots counts events per honeypot and slot in ClickHouse.
func (ch *ClickHouse) CountSlots(ctx context.Context, q SlotQuery) ([]SlotCount, error) {
	if err := q.check(); err != nil {
		return nil, err
	}
	// The bounds go as milliseconds: the driver sends a time.Time parameter
	// in whole seconds.
	rows, err := ch.conn.Query(ctx, `SELECT honeypot, intDiv(toUnixTimestamp64Milli(timestamp) - ?, ?) AS slot, count() AS n
		FROM events WHERE timestamp >= fromUnixTimestamp64Milli(toInt64(?)) AND timestamp < fromUnixTimestamp64Milli(toInt64(?))
		GROUP BY honeypot, slot`,
		q.From.UnixMilli(), q.Step.Milliseconds(), q.From.UnixMilli(), q.End().UnixMilli())
	if err != nil {
		return nil, fmt.Errorf("count slots: %w", err)
	}
	defer rows.Close()
	var out []SlotCount
	for rows.Next() {
		var hp string
		var slot int64
		var n uint64
		if err := rows.Scan(&hp, &slot, &n); err != nil {
			return nil, fmt.Errorf("count slots: %w", err)
		}
		if c := (SlotCount{Honeypot: hp, Slot: int(slot), Count: int64(n)}); q.keep(c) { // #nosec G115 -- a count of events fits
			out = append(out, c)
		}
	}
	return out, rows.Err()
}

// pgSlotsQuery builds TimescaleDB's slot count; every value is a parameter.
func pgSlotsQuery(q SlotQuery) (string, []interface{}) {
	return `SELECT honeypot, floor((extract(epoch FROM timestamp) * 1000 - $1) / $2)::bigint AS slot, count(*)
		FROM events WHERE timestamp >= $3 AND timestamp < $4 GROUP BY honeypot, slot`,
		[]interface{}{q.From.UnixMilli(), q.Step.Milliseconds(), q.From, q.End()}
}

// CountSlots counts events per honeypot and slot in TimescaleDB.
func (ts *TimescaleDB) CountSlots(ctx context.Context, q SlotQuery) ([]SlotCount, error) {
	if err := q.check(); err != nil {
		return nil, err
	}
	if ts.pool == nil {
		return nil, fmt.Errorf("not connected")
	}
	query, args := pgSlotsQuery(q)
	rows, err := ts.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("count slots: %w", err)
	}
	defer rows.Close()
	var out []SlotCount
	for rows.Next() {
		var c SlotCount
		var slot int64
		if err := rows.Scan(&c.Honeypot, &slot, &c.Count); err != nil {
			return nil, fmt.Errorf("count slots: %w", err)
		}
		c.Slot = int(slot)
		if q.keep(c) {
			out = append(out, c)
		}
	}
	return out, rows.Err()
}

// esSlotsBody builds Elasticsearch's slot count: one date_range bucket per
// slot under a terms bucket per honeypot.
func esSlotsBody(q SlotQuery) map[string]interface{} {
	ranges := make([]interface{}, 0, q.Slots)
	for i := 0; i < q.Slots; i++ {
		from := q.From.Add(time.Duration(i) * q.Step).UnixMilli()
		ranges = append(ranges, map[string]interface{}{
			"key": strconv.Itoa(i), "from": strconv.FormatInt(from, 10), "to": strconv.FormatInt(from+q.Step.Milliseconds(), 10)})
	}
	return map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{"range": map[string]interface{}{"timestamp": map[string]interface{}{
			"gte": q.From.UTC().Format(time.RFC3339Nano), "lt": q.End().UTC().Format(time.RFC3339Nano)}}},
		"aggs": map[string]interface{}{"hp": map[string]interface{}{
			"terms": map[string]interface{}{"field": "honeypot", "size": 500},
			"aggs": map[string]interface{}{"slots": map[string]interface{}{
				"date_range": map[string]interface{}{"field": "timestamp", "format": "epoch_millis", "ranges": ranges}}},
		}},
	}
}

// esSlotsAnswer is the part of Elasticsearch's answer esSlotsBody asks for.
type esSlotsAnswer struct {
	Aggregations struct {
		HP struct {
			Buckets []struct {
				Key   string `json:"key"`
				Slots struct {
					Buckets []struct {
						Key      string `json:"key"`
						DocCount int64  `json:"doc_count"`
					} `json:"buckets"`
				} `json:"slots"`
			} `json:"buckets"`
		} `json:"hp"`
	} `json:"aggregations"`
}

func parseESSlots(q SlotQuery, data []byte) ([]SlotCount, error) {
	var a esSlotsAnswer
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("count slots: %w", err)
	}
	var out []SlotCount
	for _, hp := range a.Aggregations.HP.Buckets {
		for _, b := range hp.Slots.Buckets {
			slot, err := strconv.Atoi(b.Key)
			if err != nil {
				continue
			}
			if c := (SlotCount{Honeypot: hp.Key, Slot: slot, Count: b.DocCount}); q.keep(c) {
				out = append(out, c)
			}
		}
	}
	return out, nil
}

// CountSlots counts events per honeypot and slot in Elasticsearch.
func (es *Elasticsearch) CountSlots(ctx context.Context, q SlotQuery) ([]SlotCount, error) {
	if err := q.check(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(esSlotsBody(q))
	if err != nil {
		return nil, err
	}
	data, status, err := es.esRequest(ctx, http.MethodPost, "/qpot-events-*/_search", body)
	if err != nil {
		return nil, fmt.Errorf("count slots: %w", err)
	}
	if status >= 300 {
		return nil, fmt.Errorf("count slots: status %d", status)
	}
	return parseESSlots(q, data)
}
