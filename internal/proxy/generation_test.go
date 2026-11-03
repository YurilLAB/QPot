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

// A fast recreation can finish between reset probes, or before a quarantined
// backend is retried. The trusted generation record must let the broker recover
// capacity even if it missed the brief interval when the backend was down.
func TestGenerationGateAcceptsRecreationBeforeResetProbe(t *testing.T) {
	dir := t.TempDir()
	writeGen(t, dir, "b", 3)
	g := NewGenerationGate(dir)
	f := newFakeBackend(t, "SSH-2.0-OpenSSH_9.2p1\r\n")
	b := Backend{ID: "b", Addr: f.addr}
	g.OnLease(b)
	f.stop()
	f.start(t)
	writeGen(t, dir, "b", 4)
	reset := RecycleReset(RecycleOptions{
		DownWithin: 20 * time.Millisecond,
		UpWithin:   20 * time.Millisecond,
		Poll:       time.Millisecond,
		Gate:       g,
	})
	if err := reset(b); err != nil {
		t.Fatalf("recorded recreation before probe was rejected: %v", err)
	}
}

// A counter alone is insufficient: a recreated service that is not speaking
// SSH must stay out of the pool.
func TestGenerationGateStillRequiresSSHAfterMissedDowntime(t *testing.T) {
	dir := t.TempDir()
	writeGen(t, dir, "b", 3)
	g := NewGenerationGate(dir)
	f := newFakeBackend(t, "HTTP/1.1 200 OK\r\n")
	b := Backend{ID: "b", Addr: f.addr}
	g.OnLease(b)
	writeGen(t, dir, "b", 4)
	reset := RecycleReset(RecycleOptions{
		DownWithin: 20 * time.Millisecond,
		UpWithin:   20 * time.Millisecond,
		Poll:       time.Millisecond,
		Gate:       g,
	})
	if err := reset(b); err == nil {
		t.Fatal("recreated non-SSH backend was returned to the pool")
	}
}

func TestQuarantinedBackendRecoversAfterCompletedRecreation(t *testing.T) {
	dir := t.TempDir()
	writeGen(t, dir, "b", 3)
	g := NewGenerationGate(dir)
	f := newFakeBackend(t, "SSH-2.0-OpenSSH_9.2p1\r\n")
	reset := RecycleReset(RecycleOptions{
		DownWithin: 10 * time.Millisecond,
		UpWithin:   10 * time.Millisecond,
		Poll:       time.Millisecond,
		Gate:       g,
	})
	p := NewPool([]Backend{{ID: "b", Addr: f.addr}}, reset)
	p.SetLeaseHook(g.OnLease)
	b, err := p.Lease()
	if err != nil {
		t.Fatal(err)
	}
	p.Release(b) // no reset yet: correctly quarantined
	if a, l, q := p.Stats(); a != 0 || l != 0 || q != 1 {
		t.Fatalf("before recreation: available=%d leased=%d quarantined=%d", a, l, q)
	}

	// The host completes a late reset while the quarantine watcher is between
	// retries. There will be no further outage until this backend is used again.
	f.stop()
	f.start(t)
	writeGen(t, dir, "b", 4)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.WatchQuarantined(ctx, time.Millisecond)
	}()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if a, l, q := p.Stats(); a == 1 && l == 0 && q == 0 {
			return
		}
		if time.Now().After(deadline) {
			a, l, q := p.Stats()
			t.Fatalf("clean backend remained quarantined: available=%d leased=%d quarantined=%d", a, l, q)
		}
		time.Sleep(time.Millisecond)
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
