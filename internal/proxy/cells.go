package proxy

import (
	"sync"
	"time"
)

// cellSet decides which backend (cell) a connection reaches. With a hold, a
// source - an IPv4 address or an IPv6 /64, as the limiter counts it - keeps
// its cell while any of its connections is open and for the hold after the
// last one closes, so its later connections see the state its earlier ones
// left, as on a real server. A cell's whole life is capped from its first
// connection; then, or when the hold runs out, it is freed: the host is asked
// to recreate it and the pool takes it back once that is seen. Without a hold
// every connection gets a cell of its own, freed when it closes.
//
// When the pool has no free cell, the cell idle the longest is freed first,
// and the connection that found none is turned away: freeing takes a
// recreation, and the broker never queues.
type cellSet struct {
	pool *Pool
	gate *GenerationGate
	hold time.Duration // how long an idle cell stays with its source; 0: per connection
	life time.Duration // a cell's whole life, from its first connection
	// free asks the host to recreate the cell and hands its backend back to
	// the pool. It can block for the whole recreation.
	free  func(c *cell, reason string)
	now   func() time.Time
	after func(time.Duration, func()) (stop func() bool)

	mu       sync.Mutex
	bySource map[string]*cell // the cell a source's new connections join
	held     map[*cell]bool
	closed   bool
}

// cell is one backend held for one source.
type cell struct {
	backend    Backend
	source     string
	generation *uint64 // the trusted counter snapshot from the cell's lease
	start      time.Time
	open       int
	idleSince  time.Time
	reason     string // why it is freed when its last connection closes
	quarantine bool   // a failed setup: quarantine rather than release
	stop       func() bool
	epoch      int // bumped on every join, so a stale idle timer does nothing
	done       bool
}

func newCellSet(pool *Pool, gate *GenerationGate, hold, life time.Duration, free func(*cell, string)) *cellSet {
	return &cellSet{
		pool: pool, gate: gate, hold: hold, life: life, free: free, now: time.Now,
		after:    func(d time.Duration, f func()) func() bool { return time.AfterFunc(d, f).Stop },
		bySource: map[string]*cell{}, held: map[*cell]bool{},
	}
}

// deadline is when the cell's life ends; its connections close then.
func (c *cell) deadline(life time.Duration) time.Time { return c.start.Add(life) }

// join returns the cell a new connection from source uses: the source's own
// cell while it may be joined, else a newly leased one. ErrNoBackend means the
// pool had none free; the cell idle the longest, if any, is being freed.
func (s *cellSet) join(source string) (*cell, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.hold > 0 {
		if c := s.bySource[source]; c != nil {
			if now.Before(c.deadline(s.life)) {
				c.open++
				c.epoch++
				if c.stop != nil {
					c.stop()
					c.stop = nil
				}
				return c, nil
			}
			// Past its life: its connections are closing. It is freed when
			// the last one has; the source starts afresh on another cell.
			if c.reason == "" {
				c.reason = ReasonSessionTimeout
			}
			delete(s.bySource, source)
		}
	}
	backend, err := s.pool.Lease()
	if err != nil {
		if s.closed {
			return nil, err
		}
		if victim := s.longestIdleLocked(); victim != nil {
			s.detachLocked(victim)
			go s.free(victim, ReasonCellEvicted)
		}
		return nil, err
	}
	c := &cell{backend: backend, source: source, start: now, open: 1}
	if s.gate != nil {
		if baseline, ok := s.gate.BaseGeneration(backend.ID); ok {
			c.generation = &baseline
		}
	}
	s.held[c] = true
	if s.hold > 0 {
		s.bySource[source] = c
	}
	return c, nil
}

// fail stops anyone else joining the cell and marks it to be freed when its
// last connection closes: its backend failed, so the source starts afresh.
func (s *cellSet) fail(c *cell, reason string, quarantine bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.reason = reason
	c.quarantine = c.quarantine || quarantine
	if s.bySource[c.source] == c {
		delete(s.bySource, c.source)
	}
}

// leave ends one connection's use of the cell. It returns why the caller must
// free the cell now, or "" when the cell stays held (or someone else frees it).
func (s *cellSet) leave(c *cell) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.open--
	if c.open > 0 || c.done {
		return ""
	}
	now := s.now()
	reason := c.reason
	switch {
	case reason != "":
	case s.hold <= 0:
		reason = ReasonClosed
	case !now.Before(c.deadline(s.life)):
		reason = ReasonSessionTimeout
	}
	if reason != "" || s.closed {
		s.detachLocked(c)
		return reason
	}
	c.idleSince = now
	wait := min(s.hold, c.deadline(s.life).Sub(now))
	epoch := c.epoch
	c.stop = s.after(wait, func() { s.expire(c, epoch) })
	return ""
}

// expire frees an idle cell whose hold (or life) ran out, unless the source
// came back in the meantime.
func (s *cellSet) expire(c *cell, epoch int) {
	s.mu.Lock()
	if s.closed || c.done || c.open > 0 || c.epoch != epoch {
		s.mu.Unlock()
		return
	}
	reason := ReasonCellIdle
	if !s.now().Before(c.deadline(s.life)) {
		reason = ReasonSessionTimeout
	}
	s.detachLocked(c)
	s.mu.Unlock()
	s.free(c, reason)
}

// longestIdleLocked returns the idle cell whose last connection closed first.
func (s *cellSet) longestIdleLocked() *cell {
	var oldest *cell
	for c := range s.held {
		if c.open > 0 || c.done {
			continue
		}
		if oldest == nil || c.idleSince.Before(oldest.idleSince) {
			oldest = c
		}
	}
	return oldest
}

func (s *cellSet) detachLocked(c *cell) {
	c.done = true
	if c.stop != nil {
		c.stop()
		c.stop = nil
	}
	delete(s.held, c)
	if s.bySource[c.source] == c {
		delete(s.bySource, c.source)
	}
}

// close stops the idle timers when the broker stops. Cells still held stay
// leased: a restarted broker quarantines every cell until the host resets it.
func (s *cellSet) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for c := range s.held {
		if c.stop != nil {
			c.stop()
			c.stop = nil
		}
	}
}

// heldCells reports how many cells are held and how many of them are idle.
func (s *cellSet) heldCells() (held, idle int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.held {
		held++
		if c.open == 0 {
			idle++
		}
	}
	return held, idle
}
