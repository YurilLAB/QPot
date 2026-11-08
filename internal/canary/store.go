package canary

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultMaxTrips bounds the in-memory/persisted trip history so a sustained
// beacon flood (or a crawler that finds a web token) cannot grow canaries.json
// without limit. The newest trips are always retained.
const DefaultMaxTrips = 500

// persisted is the on-disk shape of the store (canaries.json).
type persisted struct {
	Version  int       `json:"version"`
	Canaries []*Canary `json:"canaries"`
	Trips    []*Trip   `json:"trips"`
}

// Store is the thread-safe registry of canaries and their trips, persisted to
// <dataPath>/canaries.json. All exported methods are safe for concurrent use:
// the HTTP beacon handler, the management API, and the intelligence worker all
// touch it from different goroutines.
type Store struct {
	mu       sync.RWMutex
	path     string
	maxTrips int

	canaries map[string]*Canary // id -> canary
	byToken  map[string]string  // beacon token -> id
	byValue  map[string]string  // watched credential value -> id
	trips    []*Trip            // oldest first, newest last; capped at maxTrips

	// eventHits are the captured events that already tripped a canary, by
	// canary ID and event key (see Observation.EventKey), with when. The same
	// event is scanned more than once - by the quick scan and again by the
	// intelligence worker - and must trip a canary only once. Kept in memory:
	// after a restart an event may trip again (at-least-once).
	eventHits map[string]time.Time
}

// eventHitRetention is how long an event's trip is remembered; maxEventHits
// bounds how many are, dropping those past the retention first.
const (
	eventHitRetention = 7 * 24 * time.Hour
	maxEventHits      = 20000
)

// NewStore opens (or initializes) the canary store under dataPath. A missing
// file is not an error — it yields an empty store. A corrupt file is reported
// so the operator can investigate rather than silently losing canaries.
func NewStore(dataPath string, maxTrips int) (*Store, error) {
	if maxTrips <= 0 {
		maxTrips = DefaultMaxTrips
	}
	s := &Store{
		path:     filepath.Join(dataPath, "canaries.json"),
		maxTrips: maxTrips,
		canaries: make(map[string]*Canary),
		byToken:  make(map[string]string),
		byValue:  make(map[string]string),

		eventHits: make(map[string]time.Time),
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("read canary store: %w", err)
	}
	var p persisted
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse canary store %s: %w", s.path, err)
	}
	for _, c := range p.Canaries {
		if c == nil || c.ID == "" {
			continue
		}
		s.index(c)
	}
	// Skip null entries as for canaries: every reader dereferences trips.
	for _, t := range p.Trips {
		if t != nil {
			s.trips = append(s.trips, t)
		}
	}
	s.capTripsLocked()
	return s, nil
}

// index wires a canary into the lookup maps. Caller holds the write lock (or is
// in single-threaded init).
func (s *Store) index(c *Canary) {
	s.canaries[c.ID] = c
	if c.Token != "" {
		s.byToken[c.Token] = c.ID
	}
	for _, v := range c.watchValues() {
		s.byValue[v] = c.ID
	}
}

// deindex removes a canary from the lookup maps. Caller holds the write lock.
func (s *Store) deindex(c *Canary) {
	delete(s.canaries, c.ID)
	delete(s.byToken, c.Token)
	for _, v := range c.watchValues() {
		delete(s.byValue, v)
	}
}

// Create mints, indexes, and persists a new canary.
func (s *Store) Create(kind Kind, name, memo string) (*Canary, error) {
	c, err := New(kind, name, memo)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.index(c)
	if err := s.saveLocked(); err != nil {
		// Roll back the in-memory index so disk and memory stay consistent.
		s.deindex(c)
		s.mu.Unlock()
		return nil, err
	}
	s.mu.Unlock()
	return c, nil
}

// Get returns a copy of the canary with the given id, or false.
func (s *Store) Get(id string) (*Canary, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.canaries[id]
	if !ok {
		return nil, false
	}
	cp := *c
	return &cp, true
}

// List returns copies of all canaries, newest first.
func (s *Store) List() []*Canary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Canary, 0, len(s.canaries))
	for _, c := range s.canaries {
		cp := *c
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out
}

// ErrPlanted is returned when deleting an active planted canary. Once absent
// from the desired bait plan it becomes historical and may be deleted, or its
// watch may be disabled at any time.
var ErrPlanted = errors.New("canary is active in QPot's desired honeypot bait plan; " +
	"remove it from the bait plan before deleting its historical watch")

// Delete removes a canary and persists. Returns false if it did not exist,
// and ErrPlanted for an active planted canary. Historical watches can be deleted.
func (s *Store) Delete(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.canaries[id]
	if !ok {
		return false, nil
	}
	if c.Planted && !c.Historical {
		return false, ErrPlanted
	}
	s.deindex(c)
	if err := s.saveLocked(); err != nil {
		// Re-index on save failure to avoid losing the canary in memory.
		s.index(c)
		return false, err
	}
	return true, nil
}

// SyncPlanted reconciles the desired bait plan without discarding earlier
// watches. Missing planted entries become historical: an old Cowrie process
// may still be running after a failed recreation, and copied values may be
// reused later. Desired entries become active and retain their enabled state,
// trip counts and creation time. Manual canaries are unchanged. A failed save
// restores the previous in-memory registry and lookup indexes.
func (s *Store) SyncPlanted(planned []*Canary) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	want := make(map[string]*Canary, len(planned))
	for _, p := range planned {
		if p == nil || !p.Planted || !strings.HasPrefix(p.ID, "cnry_") || !p.Kind.Valid() {
			return fmt.Errorf("not a planted canary: %+v", p)
		}
		if _, dup := want[p.ID]; dup {
			return fmt.Errorf("planted canary %s listed twice", p.ID)
		}
		want[p.ID] = p
	}
	previousCanaries, previousTokens, previousValues := s.canaries, s.byToken, s.byValue
	// Work on independent maps and replace changed records instead of mutating
	// their pointers, so a persistence failure can roll back every lookup.
	s.canaries, s.byToken, s.byValue = maps.Clone(s.canaries), maps.Clone(s.byToken), maps.Clone(s.byValue)
	restore := func() {
		s.canaries, s.byToken, s.byValue = previousCanaries, previousTokens, previousValues
	}
	changed := false
	for id, c := range previousCanaries {
		if c.Planted && want[id] == nil && !c.Historical {
			next := *c
			next.Historical = true
			s.index(&next)
			changed = true
		}
	}
	for _, p := range planned {
		cur, ok := s.canaries[p.ID]
		next := *p
		next.Historical = false
		next.Values = append([]string(nil), p.Values...)
		if ok {
			next.Enabled = cur.Enabled
			next.CreatedAt = cur.CreatedAt
			next.Trips = cur.Trips
			next.LastTrip = cur.LastTrip
			if plantedEqual(cur, &next) {
				continue
			}
			s.deindex(cur)
		} else {
			next.Enabled = true
			if next.CreatedAt.IsZero() {
				next.CreatedAt = time.Now().UTC()
			}
		}
		s.index(&next)
		changed = true
	}
	if !changed {
		restore()
		return nil
	}
	if err := s.saveLocked(); err != nil {
		restore()
		return err
	}
	return nil
}

// plantedEqual reports whether two versions of a planted canary are the same.
func plantedEqual(a, b *Canary) bool {
	return a.Kind == b.Kind && a.Name == b.Name && a.Memo == b.Memo && a.Token == b.Token && a.Historical == b.Historical &&
		a.AccessKeyID == b.AccessKeyID && a.SecretAccessKey == b.SecretAccessKey &&
		a.PublicKey == b.PublicKey && a.Planted == b.Planted && slices.Equal(a.Values, b.Values)
}

// SetEnabled toggles a canary's enabled state and persists.
func (s *Store) SetEnabled(id string, enabled bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.canaries[id]
	if !ok {
		return false, nil
	}
	prev := c.Enabled
	c.Enabled = enabled
	if err := s.saveLocked(); err != nil {
		c.Enabled = prev
		return false, err
	}
	return true, nil
}

// Trips returns copies of up to limit of the most recent trips, newest first.
// A non-positive limit returns all retained trips. Copies, because a repeat hit
// increments a stored trip's Repeats under the lock while the caller encodes
// what it got back without it.
func (s *Store) Trips(limit int) []*Trip {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := len(s.trips)
	out := make([]*Trip, 0, n)
	for i := n - 1; i >= 0; i-- { // newest first
		cp := *s.trips[i]
		out = append(out, &cp)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// recordTripLocked appends a trip, updates the canary counters, caps history,
// and persists. Caller holds the write lock.
// TripDedupeWindow folds repeat hits of one canary from one source (same
// channel) into the first trip. Without it, anyone holding a single token could
// replay it in a loop and turn every request into a new critical event, IOC
// insert and full rewrite of the store file.
var TripDedupeWindow = time.Minute

// recentTripLocked returns a trip of c from srcIP on channel within the dedupe
// window, if any.
func (s *Store) recentTripLocked(c *Canary, channel, srcIP string, now time.Time) *Trip {
	for i := len(s.trips) - 1; i >= 0; i-- {
		t := s.trips[i]
		if now.Sub(t.Time) > TripDedupeWindow {
			break // trips are appended in time order
		}
		if t.CanaryID == c.ID && t.SourceIP == srcIP && t.Channel == channel {
			return t
		}
	}
	return nil
}

// recordTripLocked records a trip, or returns nil when it repeats a recent one
// (counted in that trip's Repeats; persisted with the next save).
func (s *Store) recordTripLocked(c *Canary, channel, srcIP, ua, detail string, origin Origin) (*Trip, error) {
	now := time.Now().UTC()
	if prev := s.recentTripLocked(c, channel, srcIP, now); prev != nil {
		prev.Repeats++
		c.Trips++ // the lifetime counter still counts every hit
		c.LastTrip = now
		return nil, nil
	}
	t := &Trip{
		ID:        "trip_" + randHex(10),
		CanaryID:  c.ID,
		Token:     c.Token,
		Kind:      c.Kind,
		Name:      c.Name,
		Memo:      c.Memo,
		Channel:   channel,
		Time:      now,
		SourceIP:  srcIP,
		Country:   origin.Country,
		City:      origin.City,
		ASN:       origin.ASN,
		UserAgent: ua,
		Detail:    detail,
	}
	c.Trips++
	c.LastTrip = now
	s.trips = append(s.trips, t)
	s.capTripsLocked()
	if err := s.saveLocked(); err != nil {
		return t, err // trip is in memory; report the persistence failure
	}
	return t, nil
}

// TripByToken records an HTTP-channel trip for the canary owning token. Returns
// (nil, false, nil) when the token is unknown or its canary is disabled — the
// caller still serves an identical decoy so the endpoint reveals nothing.
func (s *Store) TripByToken(token, srcIP, ua, detail string, origin Origin) (*Trip, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byToken[token]
	if !ok {
		return nil, false, nil
	}
	c := s.canaries[id]
	if c == nil || !c.Enabled {
		return nil, false, nil
	}
	t, err := s.recordTripLocked(c, "http", srcIP, ua, detail, origin)
	if t == nil {
		return nil, false, nil // a repeat within the dedupe window: no new alert
	}
	cp := *t // the stored trip keeps changing (Repeats) after we unlock
	return &cp, true, err
}

// KnowsToken reports whether token is the beacon token of an enabled canary.
func (s *Store) KnowsToken(token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byToken[token]
	if !ok {
		return false
	}
	c := s.canaries[id]
	return c != nil && c.Enabled
}

// Match scans text for any watched credential value and records a
// honeypot-channel trip of each canary found (see MatchAll); it returns the
// first new one. Returns (nil, false, nil) when nothing new matched. detail
// describes where the value was seen (e.g. the honeypot name).
func (s *Store) Match(text, srcIP, detail string) (*Trip, bool, error) {
	trips, err := s.MatchAll(text, srcIP, detail)
	if len(trips) == 0 {
		return nil, false, err
	}
	return trips[0], true, err
}

// MatchAll scans text for every watched credential value and records a
// honeypot-channel trip of each enabled canary whose value is in it, in the
// order of their IDs: one command can use several stolen values (a script
// pasted back, the AWS key and the database password on one line), and a
// canary that tripped a moment ago from the same source (folded into that
// trip) must not hide another one. Returns the new trips (copies).
func (s *Store) MatchAll(text, srcIP, detail string) ([]*Trip, error) {
	return s.MatchObservation(Observation{Text: text, SourceIP: srcIP, Detail: detail})
}

// Observation is a captured event to scan for watched values.
type Observation struct {
	// Text is what the attacker sent: command, credentials, payload.
	Text     string
	SourceIP string
	// Detail says where it was seen, such as "matched in cowrie session".
	Detail string
	// EventKey identifies the captured event (empty when there is none). A
	// canary trips once per event however often the event is scanned.
	EventKey string
	// Origin is the source's place as the collector recorded it.
	Origin Origin
}

// MatchObservation is MatchAll for a captured event: the trips carry the
// event's origin, and an event that already tripped a canary does not trip
// it again (nor count as a repeat) when it is scanned a second time.
func (s *Store) MatchObservation(o Observation) ([]*Trip, error) {
	if o.Text == "" {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.byValue) == 0 {
		return nil, nil
	}
	var found []*Canary
	seen := map[string]bool{}
	for value, id := range s.byValue {
		if seen[id] || !strings.Contains(o.Text, value) {
			continue
		}
		if c := s.canaries[id]; c != nil && c.Enabled {
			seen[id] = true
			found = append(found, c)
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].ID < found[j].ID })
	var trips []*Trip
	var firstErr error
	now := time.Now()
	for _, c := range found {
		if o.EventKey != "" {
			hit := c.ID + "\x00" + o.EventKey
			if _, done := s.eventHits[hit]; done {
				continue // this event already tripped this canary
			}
			s.rememberEventHitLocked(hit, now)
		}
		t, err := s.recordTripLocked(c, "honeypot", o.SourceIP, "", o.Detail, o.Origin)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if t == nil {
			continue // repeat within the dedupe window
		}
		cp := *t
		trips = append(trips, &cp)
	}
	return trips, firstErr
}

// rememberEventHitLocked records that an event tripped a canary, first making
// room: hits past eventHitRetention go, then, if still full, the oldest.
// Caller holds s.mu.
func (s *Store) rememberEventHitLocked(hit string, now time.Time) {
	if s.eventHits == nil {
		s.eventHits = make(map[string]time.Time)
	}
	if len(s.eventHits) >= maxEventHits {
		for k, at := range s.eventHits {
			if now.Sub(at) > eventHitRetention {
				delete(s.eventHits, k)
			}
		}
		for len(s.eventHits) >= maxEventHits {
			oldest, oldestAt := "", now
			for k, at := range s.eventHits {
				if !at.After(oldestAt) {
					oldest, oldestAt = k, at
				}
			}
			delete(s.eventHits, oldest)
		}
	}
	s.eventHits[hit] = now
}

// HasWatchValues reports whether any enabled credential canary is being watched
// for. The intelligence worker uses this to skip the (cheap but non-zero) scan
// entirely when there is nothing to match.
func (s *Store) HasWatchValues() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byValue) > 0
}

// capTripsLocked trims the trip history to maxTrips, keeping the newest.
func (s *Store) capTripsLocked() {
	if len(s.trips) > s.maxTrips {
		s.trips = s.trips[len(s.trips)-s.maxTrips:]
	}
}

// saveLocked atomically writes the store to disk. Caller holds the write lock.
// It writes to a temp file in the same directory and renames over the target so
// a crash mid-write never leaves a truncated canaries.json.
func (s *Store) saveLocked() error {
	p := persisted{Version: 1, Trips: s.trips}
	for _, c := range s.canaries {
		p.Canaries = append(p.Canaries, c)
	}
	sort.Slice(p.Canaries, func(i, j int) bool {
		return p.Canaries[i].CreatedAt.Before(p.Canaries[j].CreatedAt)
	})
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal canary store: %w", err)
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create canary store dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "canaries-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp canary store: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp canary store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp canary store: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("rename canary store: %w", err)
	}
	return nil
}
