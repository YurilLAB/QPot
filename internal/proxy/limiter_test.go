package proxy

import (
	"sync"
	"testing"
	"time"
)

func TestLimiterGlobalCap(t *testing.T) {
	l := newLimiter(0, 0, 0, 2) // only a global cap of 2
	_, _, r1 := l.admit("1.1.1.1")
	_, _, r2 := l.admit("2.2.2.2")
	if r1 == nil || r2 == nil {
		t.Fatal("first two admissions should succeed")
	}
	ok, reason, r3 := l.admit("3.3.3.3")
	if ok || reason != ReasonGlobalCap || r3 != nil {
		t.Fatalf("third admit ok=%v reason=%q want rejected/%s", ok, reason, ReasonGlobalCap)
	}
	r1() // free one slot
	ok, _, r4 := l.admit("3.3.3.3")
	if !ok {
		t.Fatal("admit should succeed after a release freed a global slot")
	}
	r4()
	r2()
	if l.activeGlobal() != 0 {
		t.Fatalf("global=%d want 0 after all released", l.activeGlobal())
	}
}

func TestLimiterPerIPConcurrency(t *testing.T) {
	l := newLimiter(0, 0, 2, 0) // 2 concurrent per IP, no rate/global
	_, _, ra := l.admit("9.9.9.9")
	_, _, rb := l.admit("9.9.9.9")
	if ra == nil || rb == nil {
		t.Fatal("first two from same IP should be admitted")
	}
	ok, reason, _ := l.admit("9.9.9.9")
	if ok || reason != ReasonPerIPCap {
		t.Fatalf("third from same IP ok=%v reason=%q want rejected/%s", ok, reason, ReasonPerIPCap)
	}
	// A different IP is unaffected.
	if ok, _, _ := l.admit("8.8.8.8"); !ok {
		t.Fatal("a different IP must not be blocked by another IP's concurrency")
	}
	ra()
	if ok, _, _ := l.admit("9.9.9.9"); !ok {
		t.Fatal("slot should free up after release")
	}
	_ = rb
}

func TestLimiterRateBucketWithClock(t *testing.T) {
	l := newLimiter(2, 3, 0, 0) // 2/sec, burst 3
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }

	// Burst of 3 should pass, 4th rejected (bucket empty).
	for i := 0; i < 3; i++ {
		if ok, reason, rel := l.admit("5.5.5.5"); !ok {
			t.Fatalf("burst admit %d rejected: %s", i, reason)
		} else {
			rel() // release so concurrency never interferes (no per-IP cap set)
		}
	}
	if ok, reason, _ := l.admit("5.5.5.5"); ok || reason != ReasonRateLimited {
		t.Fatalf("4th admit ok=%v reason=%q want rejected/%s", ok, reason, ReasonRateLimited)
	}
	// Advance 1s -> +2 tokens.
	now = now.Add(time.Second)
	for i := 0; i < 2; i++ {
		if ok, reason, rel := l.admit("5.5.5.5"); !ok {
			t.Fatalf("post-refill admit %d rejected: %s", i, reason)
		} else {
			rel()
		}
	}
	if ok, _, _ := l.admit("5.5.5.5"); ok {
		t.Fatal("tokens should be exhausted again")
	}
}

func TestLimiterReleaseIdempotent(t *testing.T) {
	l := newLimiter(0, 0, 1, 5)
	ok, _, rel := l.admit("7.7.7.7")
	if !ok {
		t.Fatal("admit failed")
	}
	rel()
	rel() // double release must not underflow counters
	if l.activeGlobal() != 0 {
		t.Fatalf("global=%d want 0", l.activeGlobal())
	}
	// Concurrency slot must be free exactly once (not twice).
	if ok, _, _ := l.admit("7.7.7.7"); !ok {
		t.Fatal("should admit after release")
	}
	if ok, reason, _ := l.admit("7.7.7.7"); ok || reason != ReasonPerIPCap {
		t.Fatalf("second concurrent admit ok=%v reason=%q want per-IP cap (double release must not have freed two slots)", ok, reason)
	}
}

func TestLimiterSweepEvictsIdle(t *testing.T) {
	l := newLimiter(1, 1, 0, 0)
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }
	l.idleEviction = time.Minute

	ok, _, rel := l.admit("1.2.3.4")
	if !ok {
		t.Fatal("admit failed")
	}
	rel()
	// Not yet past the eviction window.
	if n := l.sweep(); n != 0 {
		t.Fatalf("swept %d, want 0 (not idle long enough)", n)
	}
	now = now.Add(2 * time.Minute)
	if n := l.sweep(); n != 1 {
		t.Fatalf("swept %d, want 1 (idle bucket should be evicted)", n)
	}
}

// TestLimiterDoesNotEvictActive ensures a bucket with a live connection is never
// swept (which would lose its concurrency accounting).
func TestLimiterDoesNotEvictActive(t *testing.T) {
	l := newLimiter(0, 0, 2, 0)
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }
	l.idleEviction = time.Second

	_, _, rel := l.admit("1.1.1.1") // stays active
	now = now.Add(time.Hour)
	if n := l.sweep(); n != 0 {
		t.Fatalf("swept %d active bucket(s), want 0", n)
	}
	rel()
}

// TestLimiterConcurrentAdmit is a race exercise.
func TestLimiterConcurrentAdmit(t *testing.T) {
	l := newLimiter(0, 0, 0, 50)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if ok, _, rel := l.admit("same-ip"); ok {
					rel()
				}
			}
		}()
	}
	wg.Wait()
	if g := l.activeGlobal(); g != 0 {
		t.Fatalf("global leak: %d active after all released", g)
	}
}
