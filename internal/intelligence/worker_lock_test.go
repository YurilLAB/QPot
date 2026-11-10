package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/hostsetup"
)

func lockTestConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("HOME", dir)
}

func TestWorkerLocalOwnershipExcludesSecondProcess(t *testing.T) {
	if os.Getenv("QPOT_TEST_WORKER_LOCK_CHILD") == "1" {
		if _, err := acquireWorkerLock("shared-test-database"); err == nil {
			os.Exit(3)
		}
		return
	}
	lockTestConfig(t)
	lock, err := acquireWorkerLock("shared-test-database")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestWorkerLocalOwnershipExcludesSecondProcess$")
	cmd.Env = append(os.Environ(), "QPOT_TEST_WORKER_LOCK_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("second process acquired owned database: %v %s", err, out)
	}
	w := recoveryWorker(t, recoveryStore(1))
	w.ownershipKey = "shared-test-database"
	w.Run(context.Background())
	var coded *hostsetup.Error
	if !errors.As(w.LastError(), &coded) || coded.Code != CodeOwnership {
		t.Fatalf("ownership error=%v", w.LastError())
	}
	if state, lastError := w.Status(); state != "stopped" || lastError != w.LastError() {
		t.Fatalf("ownership failure must report stopped, not retrying: %s %v", state, lastError)
	}
	if err = lock.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := acquireWorkerLock("shared-test-database")
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	_ = next.Close()
}

func TestWorkerRevisionReservationSurvivesRestart(t *testing.T) {
	lockTestConfig(t)
	first, err := acquireWorkerLock("revision-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeWorkerRevision(first, 1); err != nil {
		t.Fatal(err)
	}
	one, err := readWorkerRevision(first)
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	second, err := acquireWorkerLock("revision-test")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	previous, err := readWorkerRevision(second)
	if err != nil {
		t.Fatal(err)
	}
	two := previous + 1
	if err := writeWorkerRevision(second, two); err != nil {
		t.Fatal(err)
	}
	if two <= one {
		t.Fatalf("reused unacknowledged revision: %d then %d", one, two)
	}
	if _, err = second.WriteAt([]byte{0xff}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err = readWorkerRevision(second); err == nil {
		t.Fatal("torn reservation did not fail closed")
	}
}

// The original server operation may commit after its process died. It must not
// replace a newer checkpoint or make its successor count those events again.
func TestWorkerDelayedCheckpointCommitAfterRestart(t *testing.T) {
	lockTestConfig(t)
	authority := newWorkerLeaseAuthority(1)
	d := authority.raw
	d.failStage = "checkpoint"
	firstDB := authority.client("delayed-save-first-account")
	w := leasedTestWorker(t, firstDB)
	closeFirst := ownTestWorker(t, w)
	defer closeFirst()
	w.runOnce(context.Background())
	data, err := json.Marshal(w.pending)
	if err != nil {
		t.Fatal(err)
	}
	var delayed database.IntelligenceCheckpoint
	if err = json.Unmarshal(data, &delayed); err != nil {
		t.Fatal(err)
	}
	// A crashed account leaves no usable lease after its database expiry.
	// The successor uses a separate local account/routing identity and still
	// obtains its revision floor from the shared database control record.
	authority.mu.Lock()
	authority.clockOffset += time.Minute
	d.failStage = ""
	authority.mu.Unlock()
	w = leasedTestWorker(t, authority.client("delayed-save-successor-account"))
	closeSecond := ownTestWorker(t, w)
	defer closeSecond()
	w.runOnce(context.Background())
	before, _ := d.LoadIntelligenceCheckpoint(context.Background())
	if before.Revision <= delayed.Revision {
		t.Fatal("new prepare reused old revision")
	}
	if err = firstDB.SaveIntelligenceCheckpoint(context.Background(), &delayed); !errors.Is(err, database.ErrIntelligenceLeaseLost) {
		t.Fatalf("delayed old-owner publication was not fenced: %v", err)
	}
	after, _ := d.LoadIntelligenceCheckpoint(context.Background())
	if after.Revision != before.Revision || !after.Complete {
		t.Fatal("delayed save replaced current checkpoint")
	}
	assertRecovery(t, d, 1)
}
