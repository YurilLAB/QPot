package database

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestPoolLastUsedNoRace exercises concurrent Acquire/Release (which write
// lastUsedAt without holding the pool lock) against the maintenance cleanup
// goroutine (which reads lastUsedAt). With lastUsedAt as a plain time.Time,
// `go test -race` reports a data race here.
func TestPoolLastUsedNoRace(t *testing.T) {
	cfg := &PoolConfig{
		MaxOpenConns:        8,
		MaxIdleConns:        4,
		ConnMaxLifetime:     time.Hour,
		ConnMaxIdleTime:     time.Nanosecond,  // every idle conn is "expired" -> cleanup reads lastUsedAt
		HealthCheckInterval: time.Millisecond, // run cleanup very frequently
		AcquireTimeout:      2 * time.Second,
	}
	p, err := NewPool(cfg, mockFactory)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer p.Close()

	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				c, err := p.Acquire(ctx)
				if err != nil {
					continue
				}
				c.Release()
			}
		}()
	}
	wg.Wait()
}

// TestPoolNeverExceedsMaxOpen hammers Acquire from many goroutines and asserts
// the pool never creates more than MaxOpenConns connections, even though the
// limit pre-check and the connection dial happen without holding the lock.
func TestPoolNeverExceedsMaxOpen(t *testing.T) {
	const maxOpen = 6
	cfg := &PoolConfig{
		MaxOpenConns:        maxOpen,
		MaxIdleConns:        2,
		ConnMaxLifetime:     time.Hour,
		ConnMaxIdleTime:     time.Hour,
		HealthCheckInterval: time.Hour,
		AcquireTimeout:      500 * time.Millisecond,
	}
	p, err := NewPool(cfg, mockFactory)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer p.Close()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Sampler: continuously assert the cap holds.
	var breached atomic.Bool
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if p.Stats().TotalConnections > maxOpen {
				breached.Store(true)
				return
			}
		}
	}()

	// Many concurrent acquirers that hold briefly.
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				c, err := p.Acquire(context.Background())
				if err != nil {
					continue
				}
				c.Release()
			}
		}()
	}

	// Let the workers run, then stop the sampler.
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	if breached.Load() {
		t.Error("pool exceeded MaxOpenConns under concurrency")
	}
	if got := p.Stats().TotalConnections; got > maxOpen {
		t.Errorf("final TotalConnections=%d exceeds MaxOpenConns=%d", got, maxOpen)
	}
}
