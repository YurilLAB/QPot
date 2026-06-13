package canary

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
}

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
	s.trips = p.Trips
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

// Delete removes a canary and persists. Returns false if it did not exist.
func (s *Store) Delete(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.canaries[id]
	if !ok {
		return false, nil
	}
	s.deindex(c)
	if err := s.saveLocked(); err != nil {
		// Re-index on save failure to avoid losing the canary in memory.
		s.index(c)
		return false, err
	}
	return true, nil
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

// Trips returns up to limit of the most recent trips, newest first. A non-
// positive limit returns all retained trips.
func (s *Store) Trips(limit int) []*Trip {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := len(s.trips)
	out := make([]*Trip, 0, n)
	for i := n - 1; i >= 0; i-- { // newest first
		out = append(out, s.trips[i])
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// recordTripLocked appends a trip, updates the canary counters, caps history,
// and persists. Caller holds the write lock.
func (s *Store) recordTripLocked(c *Canary, channel, srcIP, ua, detail string) (*Trip, error) {
	now := time.Now().UTC()
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
func (s *Store) TripByToken(token, srcIP, ua, detail string) (*Trip, bool, error) {
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
	t, err := s.recordTripLocked(c, "http", srcIP, ua, detail)
	return t, true, err
}

// Match scans text for any watched credential value and, on the first hit,
// records a honeypot-channel trip. Returns (nil, false, nil) when nothing
// matches. detail describes where the value was seen (e.g. the honeypot name).
func (s *Store) Match(text, srcIP, detail string) (*Trip, bool, error) {
	if text == "" {
		return nil, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.byValue) == 0 {
		return nil, false, nil
	}
	for value, id := range s.byValue {
		if !strings.Contains(text, value) {
			continue
		}
		c := s.canaries[id]
		if c == nil || !c.Enabled {
			continue
		}
		t, err := s.recordTripLocked(c, "honeypot", srcIP, "", detail)
		return t, true, err
	}
	return nil, false, nil
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
