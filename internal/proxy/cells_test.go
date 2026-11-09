package proxy

import (
	"errors"
	"io"
	"net"
	"sort"
	"sync"
	"testing"
	"time"
)

// fakeTime is a manual clock and timer list for the cell set.
type fakeTime struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	at      time.Time
	f       func()
	stopped bool
}

func (ft *fakeTime) Now() time.Time {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	return ft.now
}

func (ft *fakeTime) After(d time.Duration, f func()) func() bool {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	timer := &fakeTimer{at: ft.now.Add(d), f: f}
	ft.timers = append(ft.timers, timer)
	return func() bool {
		ft.mu.Lock()
		defer ft.mu.Unlock()
		was := !timer.stopped
		timer.stopped = true
		return was
	}
}

// Advance moves the clock and runs the timers that came due, in order.
func (ft *fakeTime) Advance(d time.Duration) {
	ft.mu.Lock()
	ft.now = ft.now.Add(d)
	var due []*fakeTimer
	kept := ft.timers[:0]
	for _, timer := range ft.timers {
		if !timer.stopped && !timer.at.After(ft.now) {
			timer.stopped = true
			due = append(due, timer)
		} else if !timer.stopped {
			kept = append(kept, timer)
		}
	}
	ft.timers = kept
	ft.mu.Unlock()
	sort.Slice(due, func(i, j int) bool { return due[i].at.Before(due[j].at) })
	for _, timer := range due {
		timer.f()
	}
}

type freed struct {
	backend string
	reason  string
}

// testCells builds a cell set over n backends with a manual clock; freed cells
// are released to the pool (no reset hook) and reported on the channel.
func testCells(t *testing.T, n int, hold time.Duration) (*cellSet, *fakeTime, chan freed) {
	t.Helper()
	var backends []Backend
	for i := 0; i < n; i++ {
		id := string(rune('a' + i))
		backends = append(backends, Backend{ID: id, Addr: id + ":22"})
	}
	pool := NewPool(backends, nil)
	ft := &fakeTime{now: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	got := make(chan freed, 16)
	s := newCellSet(pool, nil, hold, 2*time.Hour, func(c *cell, reason string) {
		pool.Release(c.backend)
		got <- freed{c.backend.ID, reason}
	})
	s.now, s.after = ft.Now, ft.After
	return s, ft, got
}

func mustJoin(t *testing.T, s *cellSet, source string) *cell {
	t.Helper()
	c, err := s.join(source)
	if err != nil {
		t.Fatalf("join %s: %v", source, err)
	}
	return c
}

func expectFreed(t *testing.T, got chan freed, backend, reason string) {
	t.Helper()
	select {
	case f := <-got:
		if f.backend != backend || f.reason != reason {
			t.Fatalf("freed %+v, want %s for %s", f, backend, reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("%s was not freed for %s", backend, reason)
	}
}

func expectNothingFreed(t *testing.T, got chan freed) {
	t.Helper()
	select {
	case f := <-got:
		t.Fatalf("unexpectedly freed %+v", f)
	default:
	}
}

// A source's connections share its cell while any is open and for the hold
// after the last one closes; a return inside the hold finds the same cell.
func TestCellsKeepASourceOnItsCell(t *testing.T) {
	s, ft, got := testCells(t, 2, 30*time.Minute)
	first := mustJoin(t, s, "198.51.100.7")
	second := mustJoin(t, s, "198.51.100.7")
	if first != second {
		t.Fatal("two connections from one source reached different cells")
	}
	other := mustJoin(t, s, "203.0.113.9")
	if other.backend == first.backend {
		t.Fatal("another source reached the first source's cell")
	}
	if reason := s.leave(other); reason != "" {
		t.Fatalf("an idle cell inside its hold was freed: %s", reason)
	}
	if s.leave(first) != "" || s.leave(second) != "" {
		t.Fatal("a held cell was freed when its connections closed")
	}
	ft.Advance(29 * time.Minute)
	expectNothingFreed(t, got)
	again := mustJoin(t, s, "198.51.100.7")
	if again != first {
		t.Fatal("a source returning inside its hold reached another cell")
	}
	if held, idle := s.heldCells(); held != 2 || idle != 1 {
		t.Fatalf("held %d idle %d, want 2 and 1", held, idle)
	}
	// The other source's hold runs out; the return restarted the first
	// source's, so its first timer must not free it.
	ft.Advance(2 * time.Minute)
	expectFreed(t, got, other.backend.ID, ReasonCellIdle)
	expectNothingFreed(t, got)
	if s.leave(again) != "" {
		t.Fatal("cell freed on close inside its life")
	}
	ft.Advance(29 * time.Minute)
	expectNothingFreed(t, got)
	ft.Advance(time.Minute)
	expectFreed(t, got, first.backend.ID, ReasonCellIdle)
	if fresh := mustJoin(t, s, "198.51.100.7"); fresh == first {
		t.Fatal("a source returning after its hold found its old cell")
	}
}

// IPv6 sources are their /64, as the limiter counts them.
func TestCellsKeyIPv6SourcesByPrefix(t *testing.T) {
	s, _, _ := testCells(t, 2, time.Minute)
	a := mustJoin(t, s, sourceKey("2001:db8:1:2::10"))
	b := mustJoin(t, s, sourceKey("2001:db8:1:2:ffff::1"))
	if a != b {
		t.Fatal("addresses in one /64 reached different cells")
	}
	if c := mustJoin(t, s, sourceKey("2001:db8:1:3::10")); c == a {
		t.Fatal("another /64 shared the cell")
	}
}

// A cell lives at most its life from its first connection: the hold is cut
// to it, and once it has passed the source starts afresh on another cell.
func TestCellsLifeCapsTheHold(t *testing.T) {
	s, ft, got := testCells(t, 2, 30*time.Minute)
	c := mustJoin(t, s, "198.51.100.7")
	if !c.deadline(s.life).Equal(ft.Now().Add(2 * time.Hour)) {
		t.Fatal("a cell's life does not start at its first connection")
	}
	ft.Advance(110 * time.Minute)
	if s.leave(c) != "" {
		t.Fatal("cell freed inside its life")
	}
	ft.Advance(9 * time.Minute)
	expectNothingFreed(t, got)
	ft.Advance(time.Minute)
	expectFreed(t, got, c.backend.ID, ReasonSessionTimeout)

	// A connection open at the end of the life: the next connection gets a
	// new cell, and the old one is freed when its last connection closes.
	old := mustJoin(t, s, "198.51.100.7")
	ft.Advance(2 * time.Hour)
	fresh := mustJoin(t, s, "198.51.100.7")
	if fresh == old {
		t.Fatal("a connection joined a cell past its life")
	}
	if reason := s.leave(old); reason != ReasonSessionTimeout {
		t.Fatalf("a cell past its life was kept on close: %q", reason)
	}
	if s.leave(fresh) != "" {
		t.Fatal("the new cell was not held")
	}
}

// When no cell is free, the one idle the longest is freed and the connection
// that found none is turned away; a cell in use is never taken.
func TestCellsFreeTheLongestIdleWhenShort(t *testing.T) {
	s, ft, got := testCells(t, 2, 30*time.Minute)
	a := mustJoin(t, s, "198.51.100.1")
	b := mustJoin(t, s, "198.51.100.2")
	s.leave(a)
	ft.Advance(time.Minute)
	s.leave(b)
	if _, err := s.join("198.51.100.3"); !errors.Is(err, ErrNoBackend) {
		t.Fatalf("a full pool admitted a new source: %v", err)
	}
	expectFreed(t, got, a.backend.ID, ReasonCellEvicted)
	c := mustJoin(t, s, "198.51.100.3")
	if c.backend != a.backend {
		t.Fatal("the new source did not get the freed cell")
	}
	if again := mustJoin(t, s, "198.51.100.2"); again != b {
		t.Fatal("the more recently idle cell was taken")
	}
	if _, err := s.join("198.51.100.4"); !errors.Is(err, ErrNoBackend) {
		t.Fatal("a cell in use was handed to another source")
	}
	if held, idle := s.heldCells(); held != 2 || idle != 0 {
		t.Fatalf("a full pool of cells in use lost one: held %d, idle %d", held, idle)
	}
	expectNothingFreed(t, got)
	// The evicted cell's own timer must not free it a second time.
	ft.Advance(time.Hour)
	expectNothingFreed(t, got)
}

// Without a hold, every connection gets its own cell, freed when it closes.
func TestCellsWithoutHoldGiveEachConnectionItsOwn(t *testing.T) {
	s, _, got := testCells(t, 2, 0)
	a := mustJoin(t, s, "198.51.100.7")
	b := mustJoin(t, s, "198.51.100.7")
	if a.backend == b.backend {
		t.Fatal("two connections shared a cell without a hold")
	}
	if reason := s.leave(a); reason != ReasonClosed {
		t.Fatalf("a closed connection's cell was kept: %q", reason)
	}
	expectNothingFreed(t, got)
}

// A cell whose backend failed is not joined again and is freed with its
// last connection, quarantined when its setup failed.
func TestCellsFailedCellIsNotRejoined(t *testing.T) {
	s, _, _ := testCells(t, 3, 30*time.Minute)
	c := mustJoin(t, s, "198.51.100.7")
	open := mustJoin(t, s, "198.51.100.7")
	s.fail(c, ReasonBackendDialError, true)
	if fresh := mustJoin(t, s, "198.51.100.7"); fresh == c {
		t.Fatal("a failed cell took a new connection")
	}
	if s.leave(c) != "" {
		t.Fatal("a failed cell was freed under an open connection")
	}
	if reason := s.leave(open); reason != ReasonBackendDialError || !c.quarantine {
		t.Fatalf("failed cell freed for %q (quarantine %v)", reason, c.quarantine)
	}
}

// A timer from before the source came back does nothing, even if it fires.
func TestCellsIgnoreStaleTimers(t *testing.T) {
	s, _, got := testCells(t, 1, 30*time.Minute)
	c := mustJoin(t, s, "198.51.100.7")
	s.leave(c)
	stale := c.epoch
	mustJoin(t, s, "198.51.100.7")
	s.expire(c, stale)
	expectNothingFreed(t, got)
	if s.leave(c) != "" {
		t.Fatal("cell freed on close inside its hold")
	}
	s.expire(c, stale)
	expectNothingFreed(t, got)
	s.expire(c, c.epoch)
	expectFreed(t, got, c.backend.ID, ReasonCellIdle)
}

// After the broker stops, idle timers free nothing: a restarted broker
// quarantines every cell until the host resets it.
func TestCellsCloseStopsTimers(t *testing.T) {
	s, ft, got := testCells(t, 1, time.Minute)
	c := mustJoin(t, s, "198.51.100.7")
	s.leave(c)
	s.close()
	ft.Advance(time.Hour)
	s.expire(c, c.epoch)
	expectNothingFreed(t, got)
}

// End to end through the broker: a source's connections reach one backend
// and nothing is reset while it holds it; without a hold each connection's
// close asks the host to reset its cell, with the lease's generation.
func TestBrokerKeepsASourceOnItsCell(t *testing.T) {
	for _, hold := range []time.Duration{time.Hour, 0} {
		t.Run(hold.String(), func(t *testing.T) {
			a, stopA := echoBackend(t)
			defer stopA()
			b, stopB := echoBackend(t)
			defer stopB()
			sink := &capSink{}
			pool := NewPool([]Backend{{ID: "be1", Addr: a}, {ID: "be2", Addr: b}}, nil)
			addr, stop := startBroker(t, Config{Sink: sink, CellHold: hold}, pool)
			defer stop()
			roundTrip := func() {
				c, err := net.Dial("tcp", addr)
				if err != nil {
					t.Fatal(err)
				}
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err := c.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
					t.Fatal(err)
				}
				_ = c.Close()
			}
			roundTrip()
			roundTrip()
			deadline := time.Now().Add(2 * time.Second)
			var sessions, resets []Event
			for time.Now().Before(deadline) {
				sessions, resets = nil, nil
				for _, e := range sink.snapshot() {
					switch e.EventType {
					case EventSession:
						sessions = append(sessions, e)
					case EventCellReset:
						resets = append(resets, e)
					}
				}
				if len(sessions) == 2 && (hold > 0 || len(resets) == 2) {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			if len(sessions) != 2 {
				t.Fatalf("got %d sessions", len(sessions))
			}
			if hold > 0 {
				if sessions[0].Backend != sessions[1].Backend || len(resets) != 0 {
					t.Fatalf("held source: sessions %+v resets %+v", sessions, resets)
				}
				return
			}
			if len(resets) != 2 || resets[0].Reason != ReasonClosed {
				t.Fatalf("without a hold every close resets its cell: %+v", resets)
			}
		})
	}
}

// A connection that joins a cell late ends with the cell's life, not a whole
// session after it joined.
func TestBrokerEndsLateConnectionsWithTheirCell(t *testing.T) {
	backend, stopBackend := blackholeBackend(t)
	defer stopBackend()
	sink := &capSink{}
	pool := NewPool([]Backend{{ID: "be1", Addr: backend}}, nil)
	addr, stop := startBroker(t, Config{Sink: sink, CellHold: time.Hour, MaxSession: 800 * time.Millisecond, IdleTimeout: time.Minute}, pool)
	defer stop()
	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	sink.wait(t, EventConnect, 2*time.Second)
	time.Sleep(500 * time.Millisecond)
	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var sessions []Event
		for _, e := range sink.snapshot() {
			if e.EventType == EventSession {
				sessions = append(sessions, e)
			}
		}
		if len(sessions) == 2 {
			for _, s := range sessions {
				if s.Backend != "be1" || s.Reason != ReasonSessionTimeout {
					t.Fatalf("session %+v did not end with its cell", s)
				}
			}
			if late := min(sessions[0].DurationMs, sessions[1].DurationMs); late > 600 {
				t.Fatalf("the late connection lasted %d ms, past its cell's life", late)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("connections outlived their cell: %+v", sink.snapshot())
}
