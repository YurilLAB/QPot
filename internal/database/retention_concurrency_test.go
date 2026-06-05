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

// stubRetentionDB satisfies Database by embedding the (nil) interface and only
// overriding RetentionCleanup, which is the single method ExecutePolicy's
// delete path calls. Any other method would panic if called - none are, because
// the test policy has no ArchiveConfig.
type stubRetentionDB struct{ Database }

func (stubRetentionDB) RetentionCleanup(context.Context, time.Time) error { return nil }

// TestRetentionExecutePolicyStatsRace guards the data race where ExecutePolicy
// mutated the shared *RetentionPolicy's stat fields (TotalArchived/TotalDeleted/
// LastRun/NextRun) WITHOUT the lock that ListPolicies/GetPolicy/RunScheduledChecks
// read them under. Run executes concurrently with readers; -race must stay clean.
func TestRetentionExecutePolicyStatsRace(t *testing.T) {
	rm := NewRetentionManager(stubRetentionDB{}, t.TempDir())
	if err := rm.RegisterPolicy(&RetentionPolicy{
		ID: "p1", Name: "p1", HotRetention: time.Hour, Schedule: "0 2 * * *", Enabled: true,
	}); err != nil {
		t.Fatalf("RegisterPolicy: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() { // executor: mutates the policy's stats
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_, _ = rm.ExecutePolicy(context.Background(), "p1")
			}
		}()
		go func() { // readers: read the same stat fields
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = rm.ListPolicies()
				_, _ = rm.GetPolicy("p1")
				_, _ = rm.RunScheduledChecks(context.Background())
			}
		}()
	}
	wg.Wait()
}
