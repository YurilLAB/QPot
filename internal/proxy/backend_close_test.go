package proxy

import (
	"io"
	"net"
	"testing"
	"time"
)

// TestBackendCloseEndsTheSession: when the backend closed (sshd's
// LoginGraceTime ran out, or the session ended) the broker only passed the FIN
// on to the attacker and kept the session - its backend lease, per-source and
// global slots - until the attacker's own idle timeout (15 minutes by
// default), so a few silent connections that ignore the FIN held a small pool.
// The session now ends shortly after the backend closes.
func TestBackendCloseEndsTheSession(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			_ = c.Close() // e.g. LoginGraceTime expired
		}
	}()
	defer func(g time.Duration) { backendCloseGrace = g }(backendCloseGrace)
	backendCloseGrace = 300 * time.Millisecond
	sink := &capSink{}
	const idle = 20 * time.Second
	pool := NewPool([]Backend{{ID: "be1", Addr: ln.Addr().String()}}, nil)
	addr, stop := startBroker(t, Config{Honeypot: "ssh-proxy", Sink: sink, IdleTimeout: idle}, pool)
	defer stop()

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close() // the attacker keeps its socket open and never sends
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, _ := io.ReadAll(c)
	if string(got) != "SSH-2.0-OpenSSH_9.6\r\n" {
		t.Fatalf("attacker read %q, want the banner then EOF", got)
	}

	start := time.Now()
	e := sink.wait(t, EventSession, 5*time.Second)
	if e.Reason != ReasonClosed {
		t.Errorf("session reason = %q, want %q", e.Reason, ReasonClosed)
	}
	for time.Since(start) < 2*time.Second {
		if _, leased, _ := pool.Stats(); leased == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the backend lease is still held after the session ended")
}

// TestBackendHalfCloseStillCarriesTheAttackersLastBytes: a backend that only
// shut its sending half still gets what the attacker sends right after the
// FIN, within the grace.
func TestBackendHalfCloseStillCarriesTheAttackersLastBytes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("bye\r\n"))
		_ = c.(*net.TCPConn).CloseWrite()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		b, _ := io.ReadAll(c)
		got <- string(b)
	}()
	defer func(g time.Duration) { backendCloseGrace = g }(backendCloseGrace)
	backendCloseGrace = 2 * time.Second
	pool := NewPool([]Backend{{ID: "be1", Addr: ln.Addr().String()}}, nil)
	addr, stop := startBroker(t, Config{Honeypot: "ssh-proxy", Sink: &capSink{}, IdleTimeout: 20 * time.Second}, pool)
	defer stop()

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if b, _ := io.ReadAll(c); string(b) != "bye\r\n" {
		t.Fatalf("attacker read %q", b)
	}
	if _, err := c.Write([]byte("last words")); err != nil {
		t.Fatal(err)
	}
	_ = c.(*net.TCPConn).CloseWrite()
	select {
	case s := <-got:
		if s != "last words" {
			t.Fatalf("backend got %q after its FIN, want the attacker's last bytes", s)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("backend never finished reading")
	}
}
