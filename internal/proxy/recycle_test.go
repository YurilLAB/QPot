package proxy

import (
	"context"
	"net"
	"runtime"
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

// The banner probe talks to a backend an attacker had root on (a restart
// staged from inside answers it). It read up to the first newline with no
// size limit for 2s, so a fake service streaming bytes without one made the
// broker buffer all of it, against a 128 MiB container limit.
func TestRecycleBannerProbeIsBounded(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const streamed = 64 << 20
	chunk := make([]byte, 1<<20)
	for i := range chunk {
		chunk[i] = 'A'
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for sent := 0; sent < streamed; sent += len(chunk) {
					if _, err := c.Write(chunk); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	dir := t.TempDir()
	writeGen(t, dir, "b", 1)
	g := NewGenerationGate(dir)
	b := Backend{ID: "b", Addr: ln.Addr().String()}
	g.OnLease(b)
	writeGen(t, dir, "b", 2) // recreated: straight to the banner probe
	reset := RecycleReset(RecycleOptions{DownWithin: time.Second, UpWithin: 200 * time.Millisecond, Poll: 20 * time.Millisecond, Gate: g})

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if err := reset(b); err == nil {
		t.Fatal("a backend without an SSH banner passed the reset")
	}
	runtime.ReadMemStats(&after)
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 8<<20 {
		t.Fatalf("banner probe allocated %d MiB reading a newline-free stream", grew>>20)
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
