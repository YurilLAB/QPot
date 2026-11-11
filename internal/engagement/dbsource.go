package engagement

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// DefaultBatch is how many stored events ReadDatabase asks for at a time.
const DefaultBatch = 5000

// EventReader is the part of database.Database that ReadDatabase uses.
type EventReader interface {
	GetEvents(ctx context.Context, filter database.EventFilter) ([]*database.Event, error)
}

// DBQuery selects the stored events to read.
type DBQuery struct {
	// Since and Until bound the window, both inclusive. Until must be set,
	// so the window does not move while it is read.
	Since time.Time
	Until time.Time
	// Honeypots limits the events to these honeypots; empty means all.
	Honeypots []string
	// Batch is the page size; DefaultBatch when zero.
	Batch int
}

// FromDatabaseEvent maps a stored QPot event onto an Event, following what
// the collector's add_qpot_metadata transform writes (internal/instance):
//
//   - event_type is the honeypot's own event id, in lower case;
//   - command is the honeypot's "input" (or "command") field;
//   - payload is the "url" of a download, else a raw request;
//   - metadata keeps "session" (Cowrie, ADBHoney) or "session_id", "shasum"
//     and "duration" as strings;
//   - timestamp is when the collector handled the line, not the time in the
//     honeypot's log.
func FromDatabaseEvent(d *database.Event) Event {
	typ := strings.ToLower(d.EventType)
	e := Event{
		Time:        d.Timestamp,
		Honeypot:    d.Honeypot,
		SourceIP:    d.SourceIP,
		Type:        typ,
		Username:    d.Username,
		Password:    d.Password,
		Command:     d.Command,
		TechniqueID: d.TechniqueID,
	}
	e.SessionID = d.Metadata["session"]
	if e.SessionID == "" {
		e.SessionID = d.Metadata["session_id"]
	}
	if isPayload(typ) || isPayloadFailed(typ) {
		e.SHA256 = d.Metadata["shasum"]
		// The payload column also holds raw requests; only a URL is one.
		if p := string(d.Payload); strings.Contains(p, "://") {
			e.URL = p
		}
	}
	if strings.HasSuffix(typ, ".session.closed") {
		if sec, err := strconv.ParseFloat(d.Metadata["duration"], 64); err == nil {
			e.ReportedDuration = secondsToDuration(sec)
		}
	}
	return e
}

// ReadDatabase passes every stored event of the window to emit, newest
// first, until there are no more or emit returns false. It returns how many
// events it passed on.
//
// It never asks for more than one batch at a time. The database interface
// pages by offset over events ordered by time only, which Elasticsearch
// refuses beyond 10000 and which is not stable across equal times. So each
// batch moves the end of the window instead: a full batch is used down to,
// but not including, its oldest millisecond, and the next batch ends at that
// millisecond. Only a single millisecond holding a whole batch or more is
// read by offset.
func ReadDatabase(ctx context.Context, db EventReader, q DBQuery, emit func(Event) bool) (int64, error) {
	if q.Until.IsZero() {
		return 0, fmt.Errorf("engagement: the end of the window is not set")
	}
	batch := q.Batch
	if batch <= 0 {
		batch = DefaultBatch
	}
	var n int64
	send := func(d *database.Event) bool {
		if d == nil {
			return true
		}
		n++
		return emit(FromDatabaseEvent(d))
	}
	// lastOf is the last instant of a millisecond, in every precision the
	// backends compare at.
	lastOf := func(ms time.Time) time.Time { return ms.Add(time.Millisecond - time.Nanosecond) }

	end := q.Until
	for q.Since.IsZero() || !end.Before(q.Since) {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		page, err := db.GetEvents(ctx, database.EventFilter{Honeypots: q.Honeypots, StartTime: q.Since, EndTime: end, Limit: batch})
		if err != nil {
			return n, fmt.Errorf("engagement: read events: %w", err)
		}
		if len(page) < batch {
			for _, d := range page {
				if !send(d) {
					return n, nil
				}
			}
			return n, nil
		}
		oldest, newest := msRange(page)
		if oldest.Equal(newest) {
			// One millisecond fills the batch: read all of it by offset.
			start := oldest
			if !q.Since.IsZero() && q.Since.After(start) {
				start = q.Since
			}
			for offset := 0; ; offset += batch {
				if err := ctx.Err(); err != nil {
					return n, err
				}
				part, err := db.GetEvents(ctx, database.EventFilter{Honeypots: q.Honeypots, StartTime: start, EndTime: minTime(lastOf(oldest), end), Limit: batch, Offset: offset})
				if err != nil {
					return n, fmt.Errorf("engagement: read events: %w", err)
				}
				for _, d := range part {
					if !send(d) {
						return n, nil
					}
				}
				if len(part) < batch {
					break
				}
			}
			end = oldest.Add(-time.Nanosecond)
			continue
		}
		for _, d := range page {
			if d != nil && d.Timestamp.Truncate(time.Millisecond).After(oldest) {
				if !send(d) {
					return n, nil
				}
			}
		}
		end = minTime(lastOf(oldest), end)
	}
	return n, nil
}

// msRange returns the oldest and newest millisecond of a non-empty page.
func msRange(page []*database.Event) (oldest, newest time.Time) {
	first := true
	for _, d := range page {
		if d == nil {
			continue
		}
		ms := d.Timestamp.Truncate(time.Millisecond)
		if first || ms.Before(oldest) {
			oldest = ms
		}
		if first || ms.After(newest) {
			newest = ms
		}
		first = false
	}
	return oldest, newest
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
