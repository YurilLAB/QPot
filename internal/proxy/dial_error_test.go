package proxy

import (
	"net"
	"testing"
	"time"
)

// TestDialErrorClosesTheClientBeforeTheReset: the attacker's connection was
// closed by the outermost defer, after Pool.Release had run the backend reset
// (up to minutes in production), so a failed dial left an accepted connection
// that sent nothing and its limiter slot open for the whole reset - a hang a
// real sshd never shows, and a source at its per-IP cap turned away meanwhile.
// The client is now closed, and its slot freed, before the backend is reset.
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
	}
	// The second connection, made while the first backend was still being
	// reset, reached the other backend: the first one's per-IP slot was free.
	deadline := time.Now().Add(2 * time.Second)
	for {
		var dialErrs int
		for _, e := range sink.snapshot() {
			if e.EventType == EventRejected {
				t.Fatalf("connection turned away while the first backend was reset: %+v", e)
			}
			if e.EventType == EventBackendError {
				dialErrs++
			}
		}
		if dialErrs == 2 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d backend dial errors recorded, want 2: %+v", dialErrs, sink.snapshot())
		}
		time.Sleep(5 * time.Millisecond)
	}
}
