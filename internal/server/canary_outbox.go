package server

// The canary outbox: a canary trip's event and IOCs reach the database even
// when it is down or restarting when the trip happens, or the server never
// reached it.
//
// Before the first insert attempt, the trip's event and IOCs are written to
// a file of its own under <data>/canary-outbox and synced to disk. The file is
// removed once the database holds both; until then a loop retries every
// canaryOutboxRetry, and a server start replays what an earlier process left.
// Every event carries its trip's ID (metadata trip_id), and a replay first
// looks the event up by it, so an insert that reached the database before its
// reply was lost is not written a second time. IOCs are upserts keyed by type,
// value and honeypot, so a replay never adds an IOC row; after a lost reply
// on the IOC write, a backend that counts sightings additively (TimescaleDB)
// may count that trip's IOC sighting twice.
//
// At most maxCanaryOutbox trips wait. When that many are queued, a new trip
// is still tried against the database once, but not queued: the trips
// already waiting are kept (they are older), and the canary history
// (canaries.json) still records the new one.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/database"
)

// maxCanaryOutbox is how many trips may wait (a variable for tests).
var maxCanaryOutbox = 10000

const (
	canaryOutboxDir   = "canary-outbox"
	canaryOutboxRetry = 15 * time.Second
	// canaryLookupSlack is how far from the trip's time a stored event is
	// looked for (backends keep milliseconds or microseconds).
	canaryLookupSlack = 2 * time.Second
	// maxCanaryOutboxFile bounds a file read back from the outbox.
	maxCanaryOutboxFile = 4 << 20
)

var errCanaryOutboxFull = errors.New("canary outbox full")

// canaryOutboxEntry is one queued trip.
type canaryOutboxEntry struct {
	Version int             `json:"version"`
	TripID  string          `json:"trip_id"`
	Queued  time.Time       `json:"queued"`
	Event   *database.Event `json:"event"`
	IOCs    []*database.IOC `json:"iocs,omitempty"`
	// EventStored is set once the database holds the event, so a replay
	// writes only the IOCs.
	EventStored bool `json:"event_stored,omitempty"`
}

// canaryOutbox is the directory of queued trips.
type canaryOutbox struct {
	dir string

	mu       sync.Mutex
	inflight map[string]bool // trips being delivered right now
}

// newCanaryOutbox opens the outbox under the instance data directory.
func newCanaryOutbox(dataPath string) (*canaryOutbox, error) {
	if dataPath == "" {
		return nil, errors.New("no instance data directory")
	}
	dir := filepath.Join(dataPath, canaryOutboxDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create canary outbox: %w", err)
	}
	return &canaryOutbox{dir: dir, inflight: make(map[string]bool)}, nil
}

// validTripID reports whether id is a trip ID the canary store makes
// ("trip_" and hex): it names the entry's file.
func validTripID(id string) bool {
	rest, ok := strings.CutPrefix(id, "trip_")
	if !ok || rest == "" || len(rest) > 64 {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if c := rest[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (o *canaryOutbox) path(tripID string) string {
	return filepath.Join(o.dir, tripID+".json")
}

// put writes e to its file and syncs it (and the directory) to disk. A new
// entry is refused while maxCanaryOutbox are waiting; rewriting a queued one
// is not.
func (o *canaryOutbox) put(e *canaryOutboxEntry, isNew bool) error {
	if !validTripID(e.TripID) {
		return fmt.Errorf("canary outbox: invalid trip ID %q", e.TripID)
	}
	if isNew {
		names, err := o.names()
		if err != nil {
			return err
		}
		if len(names) >= maxCanaryOutbox {
			return errCanaryOutboxFull
		}
	}
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(o.dir, ".pending-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), o.path(e.TripID)); err != nil {
		return err
	}
	return syncDir(o.dir)
}

// remove deletes a delivered entry.
func (o *canaryOutbox) remove(tripID string) error {
	if err := os.Remove(o.path(tripID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(o.dir)
}

// names lists the queued trips' files.
func (o *canaryOutbox) names() ([]string, error) {
	entries, err := os.ReadDir(o.dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, de := range entries {
		name := de.Name()
		if de.Type().IsRegular() && strings.HasSuffix(name, ".json") && validTripID(strings.TrimSuffix(name, ".json")) {
			names = append(names, name)
		}
	}
	return names, nil
}

// pending reads the queued trips, oldest first. A file that cannot be read
// as an entry is renamed aside (*.bad) and reported, never deleted.
func (o *canaryOutbox) pending() ([]*canaryOutboxEntry, error) {
	names, err := o.names()
	if err != nil {
		return nil, err
	}
	var out []*canaryOutboxEntry
	for _, name := range names {
		e, err := o.read(name)
		if err != nil {
			slog.Error("canary outbox: unreadable entry set aside", "file", name, "error", err)
			_ = os.Rename(filepath.Join(o.dir, name), filepath.Join(o.dir, name+".bad"))
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Queued.Before(out[j].Queued) })
	return out, nil
}

func (o *canaryOutbox) read(name string) (*canaryOutboxEntry, error) {
	f, err := os.Open(filepath.Join(o.dir, name))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxCanaryOutboxFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCanaryOutboxFile {
		return nil, errors.New("entry too large")
	}
	var e canaryOutboxEntry
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, err
	}
	if e.TripID+".json" != name || e.Event == nil {
		return nil, errors.New("entry does not match its file")
	}
	return &e, nil
}

// claim marks a trip as being delivered; false when another delivery has it.
func (o *canaryOutbox) claim(tripID string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.inflight[tripID] {
		return false
	}
	o.inflight[tripID] = true
	return true
}

func (o *canaryOutbox) release(tripID string) {
	o.mu.Lock()
	delete(o.inflight, tripID)
	o.mu.Unlock()
}

// syncDir syncs a directory, so a rename or removal in it is on disk.
// Windows cannot sync a directory handle; there the rename is atomic.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// queueCanaryTrip writes the trip's event and IOCs to the outbox and tries to
// deliver them now. Without an outbox (it could not be created) it makes one
// direct attempt, as before the outbox existed.
func (s *Server) queueCanaryTrip(ctx context.Context, trip *canary.Trip, event *database.Event, iocs []*database.IOC) {
	e := &canaryOutboxEntry{Version: 1, TripID: trip.ID, Queued: time.Now().UTC(), Event: event, IOCs: iocs}
	if s.canaryOutbox != nil {
		err := s.canaryOutbox.put(e, true)
		switch {
		case err == nil:
			if s.db() == nil {
				slog.Warn("canary: no database yet; the trip waits in the outbox for the next start that reaches it", "trip_id", trip.ID)
				return
			}
			if err := s.deliverCanaryTrip(ctx, e); err != nil {
				slog.Warn("canary: trip not in the database yet; queued for retry", "trip_id", trip.ID, "error", err)
			}
			return
		case errors.Is(err, errCanaryOutboxFull):
			slog.Error("canary: outbox full; this trip is tried once and kept only in the canary history", "trip_id", trip.ID, "queued", maxCanaryOutbox)
		default:
			slog.Error("canary: trip could not be queued; trying the database once", "trip_id", trip.ID, "error", err)
		}
	}
	if s.db() == nil {
		return
	}
	insCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.db().InsertEvent(insCtx, event); err != nil {
		slog.Error("canary: failed to insert trip event", "trip_id", trip.ID, "error", err)
		return
	}
	if len(iocs) > 0 {
		if err := s.db().InsertIOCs(insCtx, iocs); err != nil {
			slog.Warn("canary: failed to insert trip IOCs", "trip_id", trip.ID, "error", err)
		}
	}
}

// deliverCanaryTrip writes a queued trip to the database and removes it from
// the outbox: the event unless the database already holds it, then the IOCs.
// A trip another delivery holds is left to it.
func (s *Server) deliverCanaryTrip(ctx context.Context, e *canaryOutboxEntry) error {
	o := s.canaryOutbox
	if !o.claim(e.TripID) {
		return nil
	}
	defer o.release(e.TripID)
	// The file is the truth: another delivery may have finished the trip, or
	// stored its event, since e was read.
	e, err := o.read(e.TripID + ".json")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read the queued trip: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if !e.EventStored {
		stored, err := s.canaryEventStored(ctx, e)
		if err != nil {
			return fmt.Errorf("look up the trip's event: %w", err)
		}
		if !stored {
			if err := s.db().InsertEvent(ctx, e.Event); err != nil {
				return fmt.Errorf("insert the trip's event: %w", err)
			}
		}
		e.EventStored = true
		if len(e.IOCs) > 0 {
			// Not fatal: without the mark, the next replay finds the event.
			if err := o.put(e, false); err != nil {
				slog.Warn("canary outbox: could not record the stored event", "trip_id", e.TripID, "error", err)
			}
		}
	}
	if len(e.IOCs) > 0 {
		if err := s.db().InsertIOCs(ctx, e.IOCs); err != nil {
			return fmt.Errorf("insert the trip's IOCs: %w", err)
		}
	}
	return o.remove(e.TripID)
}

// canaryEventStored reports whether the database holds the trip's event:
// a canary trip event near the trip's time with its trip ID.
func (s *Server) canaryEventStored(ctx context.Context, e *canaryOutboxEntry) (bool, error) {
	at := e.Event.Timestamp
	events, err := s.db().GetEvents(ctx, database.EventFilter{
		Honeypots:  []string{"canary"},
		EventTypes: []string{e.Event.EventType},
		StartTime:  at.Add(-canaryLookupSlack),
		EndTime:    at.Add(canaryLookupSlack),
		Limit:      10000,
	})
	if err != nil {
		return false, err
	}
	for _, ev := range events {
		if ev.Metadata["trip_id"] == e.TripID {
			return true, nil
		}
	}
	return false, nil
}

// replayCanaryOutbox delivers every queued trip it can, oldest first, and
// stops at the first failure (the database is most likely down).
func (s *Server) replayCanaryOutbox(ctx context.Context) {
	if s.canaryOutbox == nil || s.db() == nil {
		return
	}
	entries, err := s.canaryOutbox.pending()
	if err != nil {
		slog.Error("canary outbox: cannot list queued trips", "error", err)
		return
	}
	for i, e := range entries {
		if ctx.Err() != nil {
			return
		}
		if err := s.deliverCanaryTrip(ctx, e); err != nil {
			slog.Warn("canary outbox: trips still waiting for the database", "waiting", len(entries)-i, "error", err)
			return
		}
	}
	if len(entries) > 0 {
		slog.Info("canary outbox: queued trips written to the database", "trips", len(entries))
	}
}

// canaryOutboxLoop replays the outbox at once (trips an earlier process left)
// and then every canaryOutboxRetry until ctx ends.
func (s *Server) canaryOutboxLoop(ctx context.Context) {
	t := time.NewTicker(canaryOutboxRetry)
	defer t.Stop()
	for {
		s.replayCanaryOutbox(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
