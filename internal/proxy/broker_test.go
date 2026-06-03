package proxy

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// --- test helpers -----------------------------------------------------------

// capSink records emitted events for assertions.
type capSink struct {
	mu sync.Mutex
	ev []Event
}

func (c *capSink) Emit(e Event) {
	c.mu.Lock()
	c.ev = append(c.ev, e)
	c.mu.Unlock()
}

// wait polls until an event of the given type is recorded, or fails.
func (c *capSink) wait(t *testing.T, typ string, d time.Duration) Event {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		for _, e := range c.ev {
			if e.EventType == typ {
				c.mu.Unlock()
				return e
			}
		}
		c.mu.Unlock()
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("no %q event within %s; got %+v", typ, d, c.snapshot())
	return Event{}
}

func (c *capSink) snapshot() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Event(nil), c.ev...)
}

// echoBackend accepts TCP and echoes everything it reads back to the sender
// (stands in for a real sshd at the byte level for transparency tests).
func echoBackend(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// blackholeBackend accepts and holds connections without ever reading or
// writing (stands in for an idle session).
func blackholeBackend(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		var held []net.Conn
		for {
			c, err := ln.Accept()
			if err != nil {
				for _, h := range held {
					_ = h.Close()
				}
				return
			}
			held = append(held, c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close(); close(done) }
}

// startBroker runs a broker on an ephemeral port and returns its client-facing
// address plus a stop func that cancels and drains it.
func startBroker(t *testing.T, cfg Config, pool *Pool) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	b := NewBroker(cfg, pool)
	ctx, cancel := context.WithCancel(context.Background())
	doneServe := make(chan struct{})
	go func() { _ = b.Serve(ctx, ln); close(doneServe) }()
	return ln.Addr().String(), func() {
		cancel()
		select {
		case <-doneServe:
		case <-time.After(3 * time.Second):
			t.Error("broker Serve did not return after cancel")
		}
	}
}

// --- tests ------------------------------------------------------------------

// TestSpliceTransparentRoundTrip is the core guarantee: bytes the attacker sends
// reach the backend verbatim and the backend's reply returns verbatim, with no
// modification — proving the broker is a pure L4 splice (and thus cannot be
// SSH-fingerprinted, because it speaks no SSH).
func TestSpliceTransparentRoundTrip(t *testing.T) {
	beAddr, beStop := echoBackend(t)
	defer beStop()
	sink := &capSink{}
	cfg := Config{Honeypot: "ssh-proxy", Sink: sink, IdleTimeout: 2 * time.Second}
	pool := NewPool([]Backend{{ID: "be1", Addr: beAddr}}, nil)
	addr, stop := startBroker(t, cfg, pool)
	defer stop()

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Include NUL and high bytes to prove binary transparency (no text mangling).
	payload := []byte("SSH-2.0-OpenSSH_9.6\r\n\x00\xff\xfe\x01hello")
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("readback: %v", err)
	}
	for i := range payload {
		if got[i] != payload[i] {
			t.Fatalf("byte %d: got 0x%x want 0x%x (splice not transparent)", i, got[i], payload[i])
		}
	}
	_ = c.Close()

	e := sink.wait(t, EventSession, 2*time.Second)
	if e.Backend != "be1" {
		t.Errorf("session backend = %q, want be1", e.Backend)
	}
	if e.BytesIn != int64(len(payload)) || e.BytesOut != int64(len(payload)) {
		t.Errorf("byte accounting in=%d out=%d, want %d/%d", e.BytesIn, e.BytesOut, len(payload), len(payload))
	}
	if e.Honeypot != "ssh-proxy" {
		t.Errorf("honeypot=%q", e.Honeypot)
	}
}

// TestPoolExhaustionRejects verifies that when every backend is leased, further
// connections are rejected fast (not queued) and logged as such — the load bound
// that protects a finite, expensive backend pool.
func TestPoolExhaustionRejects(t *testing.T) {
	beAddr, beStop := blackholeBackend(t)
	defer beStop()
	sink := &capSink{}
	cfg := Config{Honeypot: "ssh-proxy", Sink: sink, IdleTimeout: 5 * time.Second, MaxConcurrentIP: 10}
	pool := NewPool([]Backend{{ID: "only", Addr: beAddr}}, nil)
	addr, stop := startBroker(t, cfg, pool)
	defer stop()

	// First connection leases the single backend and holds it.
	c1, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial1: %v", err)
	}
	defer c1.Close()
	_, _ = c1.Write([]byte("hold"))
	// Wait until the backend is actually leased.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, leased, _ := pool.Stats(); leased == 1 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if _, leased, _ := pool.Stats(); leased != 1 {
		t.Fatal("first session never leased the backend")
	}

	// Second connection must be rejected with pool-exhausted.
	c2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial2: %v", err)
	}
	defer c2.Close()
	e := sink.wait(t, EventRejected, 2*time.Second)
	if e.Reason != ReasonPoolExhausted {
		t.Errorf("reject reason = %q, want %q", e.Reason, ReasonPoolExhausted)
	}
}

// TestBackendDialErrorEmitsEvent verifies a dead backend yields a backend-error
// event (operational signal), not a crash.
func TestBackendDialErrorEmitsEvent(t *testing.T) {
	// Reserve a port then close it so the dial is refused deterministically.
	tmp, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := tmp.Addr().String()
	_ = tmp.Close()

	sink := &capSink{}
	cfg := Config{Honeypot: "ssh-proxy", Sink: sink, DialTimeout: 500 * time.Millisecond}
	pool := NewPool([]Backend{{ID: "dead", Addr: deadAddr}}, nil)
	addr, stop := startBroker(t, cfg, pool)
	defer stop()

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	e := sink.wait(t, EventBackendError, 2*time.Second)
	if e.Reason != ReasonBackendDialError || e.Backend != "dead" {
		t.Errorf("got reason=%q backend=%q", e.Reason, e.Backend)
	}
}

// TestIdleTimeoutTearsDown verifies an idle session is reclaimed and labelled as
// an idle timeout (so the backend is freed for reset/reuse).
func TestIdleTimeoutTearsDown(t *testing.T) {
	beAddr, beStop := blackholeBackend(t)
	defer beStop()
	sink := &capSink{}
	cfg := Config{Honeypot: "ssh-proxy", Sink: sink, IdleTimeout: 120 * time.Millisecond, MaxSession: 5 * time.Second}
	pool := NewPool([]Backend{{ID: "be", Addr: beAddr}}, nil)
	addr, stop := startBroker(t, cfg, pool)
	defer stop()

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	// Send nothing; neither side produces data, so the idle deadline fires.
	e := sink.wait(t, EventSession, 3*time.Second)
	if e.Reason != ReasonIdleTimeout {
		t.Errorf("idle session reason = %q, want %q", e.Reason, ReasonIdleTimeout)
	}
}

// TestNormalCloseReason verifies a clean client close is attributed to a normal
// close, NOT an idle timeout (regression guard for the teardown-attribution bug
// where forcing a deadline made the peer direction misreport a timeout).
func TestNormalCloseReason(t *testing.T) {
	beAddr, beStop := echoBackend(t)
	defer beStop()
	sink := &capSink{}
	cfg := Config{Honeypot: "ssh-proxy", Sink: sink, IdleTimeout: 10 * time.Second}
	pool := NewPool([]Backend{{ID: "be", Addr: beAddr}}, nil)
	addr, stop := startBroker(t, cfg, pool)
	defer stop()

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _ = c.Write([]byte("hi"))
	got := make([]byte, 2)
	_, _ = io.ReadFull(c, got)
	_ = c.Close() // clean close well within the idle window

	e := sink.wait(t, EventSession, 2*time.Second)
	if e.Reason != ReasonClosed {
		t.Errorf("clean close reason = %q, want %q", e.Reason, ReasonClosed)
	}
}

// TestGracefulShutdownDrains verifies cancelling the context drains active
// sessions and Serve returns.
func TestGracefulShutdownDrains(t *testing.T) {
	beAddr, beStop := echoBackend(t)
	defer beStop()
	sink := &capSink{}
	cfg := Config{Honeypot: "ssh-proxy", Sink: sink, IdleTimeout: 10 * time.Second}
	pool := NewPool([]Backend{{ID: "be", Addr: beAddr}}, nil)
	addr, stop := startBroker(t, cfg, pool)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _ = c.Write([]byte("x"))
	got := make([]byte, 1)
	_, _ = io.ReadFull(c, got)

	stop() // cancels ctx; must drain and return (asserted inside stop)
	_ = c.Close()
}
