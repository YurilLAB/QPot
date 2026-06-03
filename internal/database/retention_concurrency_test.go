package database

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestRetentionManagerConcurrentAccess is the regression guard for the
// unsynchronized maps in RetentionManager: RunScheduledChecks ranged
// rm.policies while RegisterPolicy/DeletePolicy wrote it, which aborts the
// process with "fatal error: concurrent map read and map write" (and -race
// flags it). Policies are kept disabled so RunScheduledChecks/ExecutePolicy do
// no DB I/O (nil db) - the test targets the map synchronization only.
func TestRetentionManagerConcurrentAccess(t *testing.T) {
	rm := NewRetentionManager(nil, t.TempDir())
	const workers = 8
	const iters = 400
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		id := fmt.Sprintf("p%d", i)
		wg.Add(3)
		go func() { // writer: register
			defer wg.Done()
			for j := 0; j < iters; j++ {
				_ = rm.RegisterPolicy(&RetentionPolicy{ID: id, HotRetention: time.Hour, Enabled: false})
			}
		}()
		go func() { // writer: delete
			defer wg.Done()
			for j := 0; j < iters; j++ {
				rm.DeletePolicy(id)
			}
		}()
		go func() { // readers: list / get / scheduled scan
			defer wg.Done()
			for j := 0; j < iters; j++ {
				_ = rm.ListPolicies()
				_, _ = rm.GetPolicy(id)
				_, _ = rm.RunScheduledChecks(context.Background())
			}
		}()
	}
	wg.Wait()
}
