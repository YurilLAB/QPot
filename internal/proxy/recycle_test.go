package proxy

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeBackend is a restartable TCP server on a fixed address that greets with
// an SSH banner (or a non-SSH one).
type fakeBackend struct {
	addr   string
	banner string
	mu     sync.Mutex
	ln     net.Listener
}

func newFakeBackend(t *testing.T, banner string) *fakeBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeBackend{addr: ln.Addr().String(), banner: banner}
	f.serve(ln)
	t.Cleanup(f.stop)
	return f
}

func (f *fakeBackend) serve(ln net.Listener) {
	f.mu.Lock()
	f.ln = ln
	f.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte(f.banner))
			_ = c.Close()
		}
	}()
}

func (f *fakeBackend) stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ln != nil {
		_ = f.ln.Close()
		f.ln = nil
	}
}

func (f *fakeBackend) start(t *testing.T) {
	ln, err := net.Listen("tcp", f.addr)
	if err != nil {
		t.Errorf("restart listener: %v", err)
		return
	}
	f.serve(ln)
}

func fastRecycle() ResetFunc {
	return RecycleReset(RecycleOptions{DownWithin: time.Second, UpWithin: time.Second, Poll: 20 * time.Millisecond})
}

// A backend that is never recreated must not be returned to the pool.
func TestRecycleResetFailsWhenNotRecreated(t *testing.T) {
	f := newFakeBackend(t, "SSH-2.0-OpenSSH_9.2p1\r\n")
	if err := fastRecycle()(Backend{ID: "b", Addr: f.addr}); err == nil {
		t.Fatal("reset succeeded although the backend was never recreated")
	}
}

// Down then back up speaking SSH = recycled.
func TestRecycleResetSucceedsAfterRecreation(t *testing.T) {
	f := newFakeBackend(t, "SSH-2.0-OpenSSH_9.2p1\r\n")
	go func() {
		time.Sleep(150 * time.Millisecond)
		f.stop()
		time.Sleep(250 * time.Millisecond)
		f.start(t)
	}()
	if err := fastRecycle()(Backend{ID: "b", Addr: f.addr}); err != nil {
		t.Fatalf("reset after recreation: %v", err)
	}
}

// Coming back as something that is not sshd is not a successful recycle.
func TestRecycleResetRequiresSSHBanner(t *testing.T) {
	f := newFakeBackend(t, "HTTP/1.1 200 OK\r\n")
	go func() {
		time.Sleep(100 * time.Millisecond)
		f.stop()
		time.Sleep(100 * time.Millisecond)
		f.start(t)
	}()
	if err := fastRecycle()(Backend{ID: "b", Addr: f.addr}); err == nil {
		t.Fatal("reset accepted a backend that came back without an SSH banner")
	}
}

// End to end through the pool: a used backend is quarantined until a
// recreation is observed, then WatchQuarantined returns it to rotation.
func TestPoolQuarantinesUntilRecycled(t *testing.T) {
	f := newFakeBackend(t, "SSH-2.0-OpenSSH_9.2p1\r\n")
	p := NewPool([]Backend{{ID: "b", Addr: f.addr}}, fastRecycle())
	b, err := p.Lease()
	if err != nil {
		t.Fatal(err)
	}
	p.Release(b) // no recreation -> quarantined
	if avail, _, q := p.Stats(); avail != 0 || q != 1 {
		t.Fatalf("after unrecycled release: available=%d quarantined=%d", avail, q)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.WatchQuarantined(ctx, 50*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	f.stop()
	time.Sleep(200 * time.Millisecond)
	f.start(t)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if avail, _, q := p.Stats(); avail == 1 && q == 0 {
			return
		}
		if time.Now().After(deadline) {
			a, l, q := p.Stats()
			t.Fatalf("recycled backend not returned: available=%d leased=%d quarantined=%d", a, l, q)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
