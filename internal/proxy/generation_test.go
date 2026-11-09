package proxy

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

func gatedRecycle(g *GenerationGate) ResetFunc {
	return RecycleReset(RecycleOptions{DownWithin: time.Second, UpWithin: time.Second, Poll: 20 * time.Millisecond, Gate: g})
}

func writeGen(t *testing.T, dir, id string, n int) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, id), []byte(strconv.Itoa(n)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A restart staged from inside the backend (sshd killed and brought back, no
// recreation by the host) looks like a reset by reachability alone; with the
// generation gate it must be refused, so the dirty backend stays out of
// rotation.
func TestGenerationGateRejectsStagedRestart(t *testing.T) {
	dir := t.TempDir()
	writeGen(t, dir, "b", 3)
	g := NewGenerationGate(dir)
	f := newFakeBackend(t, "SSH-2.0-OpenSSH_9.2p1\r\n")
	b := Backend{ID: "b", Addr: f.addr}
	g.OnLease(b)
	go func() { // the attacker's `kill 1`: down, then back up, same box
		time.Sleep(100 * time.Millisecond)
		f.stop()
		time.Sleep(100 * time.Millisecond)
		f.start(t)
	}()
	if err := gatedRecycle(g)(b); err == nil {
		t.Fatal("a restart without a host recreation was accepted as a reset")
	}
}

func TestGenerationGateAcceptsHostRecreation(t *testing.T) {
	dir := t.TempDir()
	writeGen(t, dir, "b", 3)
	g := NewGenerationGate(dir)
	f := newFakeBackend(t, "SSH-2.0-OpenSSH_9.2p1\r\n")
	b := Backend{ID: "b", Addr: f.addr}
	g.OnLease(b)
	go func() { // the host recycler: recreate, then record it
		time.Sleep(100 * time.Millisecond)
		f.stop()
		time.Sleep(100 * time.Millisecond)
		f.start(t)
		writeGen(t, dir, "b", 4)
	}()
	if err := gatedRecycle(g)(b); err != nil {
		t.Fatalf("host recreation not accepted: %v", err)
	}
}

// A recreation the reset did not watch happen (it finished after the reset
// gave up, or between two WatchQuarantined retries) is already proven by the
// generation counter, and the backend is back up. Waiting to see it go down
// AGAIN kept a clean backend quarantined for the broker's lifetime, because
// nothing recreates it a second time.
func TestGenerationGateAcceptsRecreationAlreadyDone(t *testing.T) {
	dir := t.TempDir()
	writeGen(t, dir, "b", 3)
	g := NewGenerationGate(dir)
	f := newFakeBackend(t, "SSH-2.0-OpenSSH_9.2p1\r\n")
	b := Backend{ID: "b", Addr: f.addr}
	g.OnLease(b)
	writeGen(t, dir, "b", 4) // recreated and back up before the reset looks
	if err := gatedRecycle(g)(b); err != nil {
		t.Fatalf("completed host recreation not accepted: %v", err)
	}
}

// End to end: a backend quarantined because its recreation came late rejoins
// the pool once WatchQuarantined sees the counter moved.
func TestPoolRecoversLateRecreation(t *testing.T) {
	dir := t.TempDir()
	writeGen(t, dir, "b", 1)
	g := NewGenerationGate(dir)
	f := newFakeBackend(t, "SSH-2.0-OpenSSH_9.2p1\r\n")
	p := NewPool([]Backend{{ID: "b", Addr: f.addr}}, gatedRecycle(g))
	p.SetLeaseHook(g.OnLease)
	b, err := p.Lease()
	if err != nil {
		t.Fatal(err)
	}
	p.Release(b) // the host is late: nothing seen in time -> quarantined
	if avail, _, q := p.Stats(); avail != 0 || q != 1 {
		t.Fatalf("after unrecycled release: available=%d quarantined=%d", avail, q)
	}
	// The recreation lands now, while no reset is watching.
	f.stop()
	f.start(t)
	writeGen(t, dir, "b", 2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.WatchQuarantined(ctx, 50*time.Millisecond)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if avail, _, q := p.Stats(); avail == 1 && q == 0 {
			return
		}
		if time.Now().After(deadline) {
			a, l, q := p.Stats()
			t.Fatalf("recreated backend never left quarantine: available=%d leased=%d quarantined=%d", a, l, q)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Without a counter bump the shortcut must not apply: an up backend that was
// never recreated stays out of rotation.
func TestGenerationGateUpButNotRecreatedFails(t *testing.T) {
	dir := t.TempDir()
	writeGen(t, dir, "b", 3)
	g := NewGenerationGate(dir)
	f := newFakeBackend(t, "SSH-2.0-OpenSSH_9.2p1\r\n")
	b := Backend{ID: "b", Addr: f.addr}
	g.OnLease(b)
	if err := gatedRecycle(g)(b); err == nil {
		t.Fatal("a backend that was never recreated passed the reset")
	}
}

// A recreation that happened BEFORE the lease (e.g. the recycler's start-up
// pass) must not count for the session that followed it.
func TestGenerationGateUsesLeaseSnapshot(t *testing.T) {
	dir := t.TempDir()
	writeGen(t, dir, "b", 1)
	g := NewGenerationGate(dir)
	writeGen(t, dir, "b", 2) // start-up recycle, before any session
	b := Backend{ID: "b"}
	g.OnLease(b) // session starts at generation 2
	if g.Advanced(b) {
		t.Fatal("a recreation from before the lease counted as this session's reset")
	}
	writeGen(t, dir, "b", 3)
	if !g.Advanced(b) {
		t.Fatal("recreation after the lease not seen")
	}
}

func TestGenerationGateIgnoresPathIDs(t *testing.T) {
	dir := t.TempDir()
	g := NewGenerationGate(filepath.Join(dir, "gen"))
	writeGen(t, dir, "secret", 99)
	for _, id := range []string{"../secret", "..", "", `..\secret`} {
		if n := g.Generation(id); n != 0 {
			t.Errorf("Generation(%q) = %d, read outside the directory", id, n)
		}
	}
}

// On a case-insensitive or aliasing filesystem (Windows, macOS, a Docker
// Desktop bind mount) another spelling of an id opened the same counter file,
// so two backends whose ids differ only in case shared one counter and a
// recreation of one passed the other's gate. Found by FuzzGenerationID.
func TestGenerationGateExactIDs(t *testing.T) {
	dir := t.TempDir()
	writeGen(t, dir, "be1", 7)
	g := NewGenerationGate(dir)
	if n := g.Generation("be1"); n != 7 {
		t.Fatalf("Generation(be1) = %d, want 7", n)
	}
	for _, id := range []string{"BE1", "Be1", "be1.", "be1 ", "be1::$DATA"} {
		if n := g.Generation(id); n != 0 {
			t.Errorf("Generation(%q) = %d, read be1's counter", id, n)
		}
	}
}

// The pool calls the lease hook so the gate snapshots each session's start.
func TestPoolLeaseHook(t *testing.T) {
	p := NewPool([]Backend{{ID: "a", Addr: "x:22"}}, nil)
	var got []string
	p.SetLeaseHook(func(b Backend) { got = append(got, b.ID) })
	b, err := p.Lease()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != b.ID {
		t.Fatalf("lease hook calls = %v", got)
	}
}

// A broker process restart does not clean its backend. Even a reachable sshd
// and an already-existing counter must stay quarantined until a newer trusted
// recreation; then exactly one first lease becomes possible.
func TestStartupQuarantineRequiresFreshGeneration(t *testing.T) {
	dir := t.TempDir()
	writeGen(t, dir, "b", 7)
	g := NewGenerationGate(dir)
	f := newFakeBackend(t, "SSH-2.0-OpenSSH_9.2p1\r\n")
	b := Backend{ID: "b", Addr: f.addr}
	g.OnLease(b)
	reset := RecycleReset(RecycleOptions{DownWithin: 30 * time.Millisecond, UpWithin: time.Second,
		Poll: 5 * time.Millisecond, Gate: g})
	p := NewPool([]Backend{b}, reset, PoolOptions{StartQuarantined: true})
	p.SetLeaseHook(g.OnLease)
	if _, err := p.Lease(); err != ErrNoBackend {
		t.Fatalf("first lease before startup reset: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.WatchQuarantined(ctx, 5*time.Millisecond)
	time.Sleep(80 * time.Millisecond)
	if _, err := p.Lease(); err != ErrNoBackend {
		t.Fatalf("reachable backend with old counter became available: %v", err)
	}
	writeGen(t, dir, "b", 8)
	deadline := time.Now().Add(2 * time.Second)
	for {
		leased, err := p.Lease()
		if err == nil {
			if leased.ID != "b" {
				t.Fatalf("leased %+v", leased)
			}
			if baseline, ok := g.BaseGeneration("b"); !ok || baseline != 8 {
				t.Fatalf("first session baseline=%d present=%v", baseline, ok)
			}
			if g.Advanced(leased) {
				t.Fatal("startup recreation also counted as a later session reset")
			}
			if _, err := p.Lease(); err != ErrNoBackend {
				t.Fatalf("same backend leased twice: %v", err)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("new trusted recreation never released startup quarantine")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestStartupQuarantineDoesNotTrustPriorRecreation(t *testing.T) {
	dir := t.TempDir()
	writeGen(t, dir, "b", 1)
	g := NewGenerationGate(dir)
	writeGen(t, dir, "b", 2) // host startup pass completed before this broker started
	b := Backend{ID: "b", Addr: "127.0.0.1:22"}
	g.OnLease(b)
	p := NewPool([]Backend{b}, nil, PoolOptions{StartQuarantined: true})
	if _, err := p.Lease(); err != ErrNoBackend || g.Advanced(b) {
		t.Fatal("a pre-startup recreation opened a new broker's first lease")
	}
	if baseline, ok := g.BaseGeneration("b"); !ok || baseline != 2 {
		t.Fatalf("baseline=%d present=%v", baseline, ok)
	}
	if _, ok := g.BaseGeneration("unknown"); ok {
		t.Fatal("unknown backend has a generation baseline")
	}
}

func TestStartupQuarantineDoesNotRunDuplicateConcurrentResets(t *testing.T) {
	const count = 4
	var backends []Backend
	for _, id := range []string{"a", "b", "c", "d"} {
		backends = append(backends, Backend{ID: id, Addr: "127.0.0.1:22"})
	}
	var mu sync.Mutex
	calls := map[string]int{}
	started := make(chan struct{}, count)
	unblock := make(chan struct{})
	reset := func(b Backend) error {
		mu.Lock()
		calls[b.ID]++
		mu.Unlock()
		started <- struct{}{}
		<-unblock
		return nil
	}
	p := NewPool(backends, reset, PoolOptions{StartQuarantined: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.WatchQuarantined(ctx, time.Millisecond)
	for range count {
		select {
		case <-started:
		case <-time.After(time.Second):
			close(unblock)
			t.Fatal("startup reset was not scheduled")
		}
	}
	time.Sleep(20 * time.Millisecond) // several watcher ticks while every reset is still active
	mu.Lock()
	for id, n := range calls {
		if n != 1 {
			t.Errorf("concurrent resets for %s: %d", id, n)
		}
	}
	mu.Unlock()
	close(unblock)
	deadline := time.Now().Add(time.Second)
	for {
		if available, leased, quarantined := p.Stats(); available == count && leased == 0 && quarantined == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("completed startup resets did not rejoin the pool")
		}
		time.Sleep(time.Millisecond)
	}
	seen := map[string]bool{}
	for range count {
		b, err := p.Lease()
		if err != nil || seen[b.ID] {
			t.Fatalf("startup admission returned duplicate or missing backend: %+v %v", b, err)
		}
		seen[b.ID] = true
	}
}
