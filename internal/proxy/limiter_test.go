package proxy

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// One IPv6 host is normally handed a whole /64 (often a /56 or /48), so it can
// pick a fresh source address for every connection. Keyed on the full address,
// the per-IP caps and rate limit did nothing against it.
func TestLimiterGroupsIPv6By64(t *testing.T) {
	l := newLimiter(0, 0, 1, 0) // one concurrent connection per source
	ok, _, rel := l.admit("2001:db8:1:2::1")
	if !ok {
		t.Fatal("first admit rejected")
	}
	defer rel()
	if ok, reason, _ := l.admit("2001:db8:1:2:dead:beef:0:1"); ok || reason != ReasonPerIPCap {
		t.Fatalf("second address in the same /64: ok=%v reason=%q, want %s", ok, reason, ReasonPerIPCap)
	}
	if ok, _, r := l.admit("2001:db8:1:3::1"); !ok {
		t.Fatal("a different /64 was blocked")
	} else {
		r()
	}
	// IPv4 keeps per-address granularity, and an IPv4-mapped form is the same
	// source as the plain address.
	ok4, _, r4 := l.admit("192.0.2.1")
	if !ok4 {
		t.Fatal("IPv4 admit rejected")
	}
	defer r4()
	if ok, reason, _ := l.admit("::ffff:192.0.2.1"); ok || reason != ReasonPerIPCap {
		t.Fatalf("IPv4-mapped form: ok=%v reason=%q, want %s", ok, reason, ReasonPerIPCap)
	}
	if ok, _, r := l.admit("192.0.2.2"); !ok {
		t.Fatal("neighbouring IPv4 address was blocked")
	} else {
		r()
	}
}

func TestLimiterLogRejectionBudgets(t *testing.T) {
	l := newLimiter(1, 1, 1, 0)
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }

	// One source: the first rejection in a second is logged, repeats are not.
	if !l.logRejection("203.0.113.5") {
		t.Fatal("first rejection not logged")
	}
	for i := 0; i < 50; i++ {
		if l.logRejection("203.0.113.5") {
			t.Fatalf("repeat %d within the second was logged", i)
		}
	}
	// The same /64 is the same source.
	if !l.logRejection("2001:db8::1") || l.logRejection("2001:db8::2") {
		t.Fatal("IPv6 rejections not thinned per /64")
	}
	now = now.Add(rejectLogEvery)
	if !l.logRejection("203.0.113.5") {
		t.Fatal("rejection a second later not logged")
	}

	// Many sources at once: at most rejectLogRate a second overall.
	now = now.Add(10 * time.Second)
	logged := 0
	for i := 0; i < 1000; i++ {
		if l.logRejection(fmt.Sprintf("10.0.%d.%d", i>>8, i&255)) {
			logged++
		}
	}
	if logged != rejectLogRate {
		t.Fatalf("%d of 1000 distinct sources logged in one instant, want %d", logged, rejectLogRate)
	}
}

// Every new source address used to add a map entry that only the minute
// sweeper removed, after 10 idle minutes: a flood of fresh sources (trivial
// with IPv6) grew the map without bound in between, toward the broker's
// 128 MiB memory limit.
func TestLimiterBoundsTrackedSources(t *testing.T) {
	l := newLimiter(5, 10, 3, 0)
	const bound = 1 << 16
	for i := 0; i < 3*bound; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)
		ok, reason, rel := l.admit(ip)
		if !ok {
			t.Fatalf("admit %s rejected: %s", ip, reason)
		}
		rel()
	}
	l.mu.Lock()
	n := len(l.ips)
	l.mu.Unlock()
	if n > bound {
		t.Fatalf("limiter tracks %d sources after churn, want at most %d", n, bound)
	}
}

// Making room for new sources must never drop a source that still holds
// connections, or its concurrency cap would reset.
func TestLimiterBoundKeepsActiveSources(t *testing.T) {
	l := newLimiter(0, 0, 1, 0)
	ok, _, rel := l.admit("198.51.100.7")
	if !ok {
		t.Fatal("admit rejected")
	}
	defer rel()
	for i := 0; i < 3<<16; i++ {
		_, _, r := l.admit(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))
		r()
	}
	if ok, reason, _ := l.admit("198.51.100.7"); ok || reason != ReasonPerIPCap {
		t.Fatalf("active source lost its accounting: ok=%v reason=%q", ok, reason)
	}
}

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
