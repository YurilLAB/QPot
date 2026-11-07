package proxy

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestDialErrorClosesTheClientBeforeTheReset: the attacker's connection was
// closed by the outermost defer, after Pool.Release had run the backend reset
// (up to minutes in production), so a failed dial left an accepted connection
// that sent nothing open for the whole reset - a hang a real sshd never shows.
// The client is now closed before the backend is reset, while its per-IP slot
// stays taken until the reset ends: a second connection from the same source
// meanwhile is turned away at its cap.
func TestDialErrorClosesTheClientBeforeTheReset(t *testing.T) {
	var backends []Backend
	for _, id := range []string{"be1", "be2"} {
		dead, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		backends = append(backends, Backend{ID: id, Addr: dead.Addr().String()})
		_ = dead.Close()
	}
	const resetTakes = 2 * time.Second
	pool := NewPool(backends, func(Backend) error { time.Sleep(resetTakes); return nil })
	sink := &capSink{}
	addr, stop := startBroker(t, Config{Honeypot: "ssh-proxy", Sink: sink, DialTimeout: 300 * time.Millisecond, MaxConcurrentIP: 1}, pool)
	defer stop()

	for i := 1; i <= 2; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Read(make([]byte, 1))
		el := time.Since(start)
		_ = c.Close()
		if el > resetTakes/2 {
			t.Fatalf("connection %d was held %v after the backend dial failed (reset takes %v)", i, el.Round(time.Millisecond), resetTakes)
		}
		if i == 1 {
			sink.wait(t, EventBackendError, time.Second)
		}
	}
	if e := sink.wait(t, EventRejected, time.Second); e.Reason != ReasonPerIPCap {
		t.Fatalf("second connection during the reset: %+v, want rejected at the per-IP cap", e)
	}
	var dialErrs int
	for _, e := range sink.snapshot() {
		if e.EventType == EventBackendError {
			dialErrs++
		}
	}
	if dialErrs != 1 {
		t.Fatalf("%d backend dial errors, want 1 (the second connection must not reach a backend): %+v", dialErrs, sink.snapshot())
	}
}

// TestOneSourceCannotDrainThePool: a source's limiter slot covers its backend
// until that backend's reset ends. Freed earlier, one source at a per-IP cap
// of 1 could connect and drop again and again, each drop parking another
// backend in a reset of minutes, until every other attacker was turned away
// with the pool exhausted.
func TestOneSourceCannotDrainThePool(t *testing.T) {
	beAddr, beStop := echoBackend(t)
	defer beStop()
	var resets atomic.Int32
	unblock := make(chan struct{})
	pool := NewPool([]Backend{{ID: "be1", Addr: beAddr}, {ID: "be2", Addr: beAddr}, {ID: "be3", Addr: beAddr}},
		func(Backend) error {
			resets.Add(1)
			select {
			case <-unblock:
			case <-time.After(10 * time.Second):
			}
			return nil
		})
	addr, stop := startBroker(t, Config{Honeypot: "ssh-proxy", Sink: &capSink{}, DialTimeout: time.Second,
		MaxConcurrentIP: 1, RatePerSecPerIP: 1000, BurstPerIP: 1000}, pool)
	defer stop()
	defer close(unblock)

	// served reports whether a connection from local reached a backend (its
	// byte came back) rather than being turned away (closed with nothing).
	served := func(local string) bool {
		t.Helper()
		d := net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(local)}}
		c, err := d.Dial("tcp", addr)
		if err != nil {
			t.Skipf("cannot connect from %s: %v", local, err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write([]byte("x")); err != nil {
			return false
		}
		buf := make([]byte, 1)
		_, err = io.ReadFull(c, buf)
		return err == nil && buf[0] == 'x'
	}

	got := 0
	for i := 0; i < 3; i++ {
		if !served("127.0.0.1") {
			continue
		}
		got++
		// Wait until the broker has ended that session and begun its reset.
		deadline := time.Now().Add(2 * time.Second)
		for resets.Load() < int32(got) {
			if time.Now().After(deadline) {
				t.Fatalf("no reset began after session %d", got)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	if got != 1 {
		t.Errorf("one source at a per-IP cap of 1 reached %d backends while their resets ran", got)
	}
	if avail, _, _ := pool.Stats(); avail < 2 {
		t.Errorf("one source holds %d of 3 backends (leased or resetting), want at most 1", 3-avail)
	}
	if !served("127.0.0.2") {
		t.Error("another source was turned away: the pool was drained by one source")
	}
}
