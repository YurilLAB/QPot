package proxy

import (
	"errors"
	"sync"
	"testing"
)

func TestParseBackends(t *testing.T) {
	t.Run("auto ids", func(t *testing.T) {
		bs, err := ParseBackends("h1:22, h2:2222")
		if err != nil {
			t.Fatal(err)
		}
		if len(bs) != 2 || bs[0].ID != "be1" || bs[0].Addr != "h1:22" || bs[1].ID != "be2" {
			t.Fatalf("got %+v", bs)
		}
	})
	t.Run("explicit ids", func(t *testing.T) {
		bs, err := ParseBackends("a=h1:22,b=h2:22")
		if err != nil || bs[0].ID != "a" || bs[1].ID != "b" {
			t.Fatalf("got %+v err %v", bs, err)
		}
	})
	t.Run("rejects bad addr", func(t *testing.T) {
		for _, in := range []string{"noport", "h:0", "h:99999", "h:-1", ""} {
			if _, err := ParseBackends(in); err == nil {
				t.Errorf("ParseBackends(%q) should error", in)
			}
		}
	})
	t.Run("rejects duplicate id", func(t *testing.T) {
		if _, err := ParseBackends("x=h1:22,x=h2:22"); err == nil {
			t.Error("duplicate id should error")
		}
	})
}

func TestPoolLeaseRelease(t *testing.T) {
	p := NewPool([]Backend{{ID: "a", Addr: "a:22"}, {ID: "b", Addr: "b:22"}}, nil)
	if p.Size() != 2 {
		t.Fatalf("size=%d want 2", p.Size())
	}
	b1, err := p.Lease()
	if err != nil {
		t.Fatalf("lease1: %v", err)
	}
	b2, err := p.Lease()
	if err != nil {
		t.Fatalf("lease2: %v", err)
	}
	if b1.ID == b2.ID {
		t.Fatal("lease handed out the same backend twice")
	}
	if _, err := p.Lease(); !errors.Is(err, ErrNoBackend) {
		t.Fatalf("third lease err=%v want ErrNoBackend", err)
	}
	if avail, leased, _ := p.Stats(); avail != 0 || leased != 2 {
		t.Fatalf("stats avail=%d leased=%d want 0/2", avail, leased)
	}
	p.Release(b1)
	if avail, leased, _ := p.Stats(); avail != 1 || leased != 1 {
		t.Fatalf("after release stats avail=%d leased=%d want 1/1", avail, leased)
	}
	// A backend can be leased again after release.
	if _, err := p.Lease(); err != nil {
		t.Fatalf("re-lease: %v", err)
	}
}

func TestPoolResetHookRunsAndQuarantinesOnFailure(t *testing.T) {
	var resetIDs []string
	var mu sync.Mutex
	failFor := "bad"
	reset := func(b Backend) error {
		mu.Lock()
		resetIDs = append(resetIDs, b.ID)
		mu.Unlock()
		if b.ID == failFor {
			return errors.New("reset failed")
		}
		return nil
	}
	p := NewPool([]Backend{{ID: "good", Addr: "g:22"}, {ID: "bad", Addr: "b:22"}}, reset)

	good, _ := p.Lease()
	for good.ID != "good" { // ensure we hold 'good'
		p.Release(good)
		good, _ = p.Lease()
	}
	bad, _ := p.Lease()

	p.Release(good) // reset succeeds -> back to available
	p.Release(bad)  // reset fails    -> quarantined

	mu.Lock()
	gotReset := len(resetIDs)
	mu.Unlock()
	if gotReset != 2 {
		t.Errorf("reset called %d times, want 2", gotReset)
	}
	avail, leased, quar := p.Stats()
	if quar != 1 {
		t.Errorf("quarantined=%d want 1 (failed reset must not rejoin rotation)", quar)
	}
	if leased != 0 {
		t.Errorf("leased=%d want 0", leased)
	}
	if avail != 1 {
		t.Errorf("available=%d want 1 (only the good backend)", avail)
	}
	// A quarantined backend is out of rotation, so Size shrank.
	if p.Size() != 1 {
		t.Errorf("size=%d want 1 after quarantine", p.Size())
	}
}

func TestPoolIgnoresMalformedAndDuplicate(t *testing.T) {
	p := NewPool([]Backend{
		{ID: "a", Addr: "a:22"},
		{ID: "", Addr: "x:22"},   // no id
		{ID: "b", Addr: ""},      // no addr
		{ID: "a", Addr: "a2:22"}, // duplicate id
	}, nil)
	if p.Size() != 1 {
		t.Fatalf("size=%d want 1 (only the one well-formed unique backend)", p.Size())
	}
}

func TestPoolReleaseUnknownIsNoop(t *testing.T) {
	p := NewPool([]Backend{{ID: "a", Addr: "a:22"}}, nil)
	p.Release(Backend{ID: "ghost", Addr: "g:22"}) // must not panic or corrupt state
	if avail, leased, _ := p.Stats(); avail != 1 || leased != 0 {
		t.Fatalf("stats avail=%d leased=%d want 1/0", avail, leased)
	}
}

// TestPoolConcurrentLeaseRelease is a race-detector exercise: many goroutines
// lease and release; no backend is ever double-leased and counts stay coherent.
func TestPoolConcurrentLeaseRelease(t *testing.T) {
	const n = 8
	backends := make([]Backend, n)
	for i := range backends {
		backends[i] = Backend{ID: string(rune('a' + i)), Addr: "x:22"}
	}
	p := NewPool(backends, nil)

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				b, err := p.Lease()
				if err != nil {
					continue
				}
				p.Release(b)
			}
		}()
	}
	wg.Wait()
	if avail, leased, quar := p.Stats(); avail != n || leased != 0 || quar != 0 {
		t.Fatalf("final stats avail=%d leased=%d quar=%d want %d/0/0", avail, leased, quar, n)
	}
}
