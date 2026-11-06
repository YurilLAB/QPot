package proxy

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
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
