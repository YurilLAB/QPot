package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"testing"

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
	w := &Worker{ownershipKey: "revision-test", ownershipLock: first}
	one, err := w.nextRevision(0)
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	second, err := acquireWorkerLock("revision-test")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	w = &Worker{ownershipKey: "revision-test", ownershipLock: second}
	two, err := w.nextRevision(0)
	if err != nil {
		t.Fatal(err)
	}
	if two <= one {
		t.Fatalf("reused unacknowledged revision: %d then %d", one, two)
	}
	if _, err = second.WriteAt([]byte{0xff}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err = w.nextRevision(two); err == nil {
		t.Fatal("torn reservation did not fail closed")
	}
}

// The original server operation may commit after its process died. It must not
// replace a newer checkpoint or make its successor count those events again.
func TestWorkerDelayedCheckpointCommitAfterRestart(t *testing.T) {
	lockTestConfig(t)
	d := recoveryStore(1)
	d.failStage = "checkpoint"
	first, err := acquireWorkerLock("delayed-save")
	if err != nil {
		t.Fatal(err)
	}
	w := recoveryWorker(t, d)
	w.ownershipKey = "delayed-save"
	w.ownershipLock = first
	w.runOnce(context.Background())
	data, err := json.Marshal(w.pending)
	if err != nil {
		t.Fatal(err)
	}
	var delayed database.IntelligenceCheckpoint
	if err = json.Unmarshal(data, &delayed); err != nil {
		t.Fatal(err)
	}
	_ = first.Close() // abrupt process exit, no shutdown drain
	second, err := acquireWorkerLock("delayed-save")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	d.failStage = ""
	w = recoveryWorker(t, d)
	w.ownershipKey = "delayed-save"
	w.ownershipLock = second
	w.runOnce(context.Background())
	before, _ := d.LoadIntelligenceCheckpoint(context.Background())
	if before.Revision <= delayed.Revision {
		t.Fatal("new prepare reused old revision")
	}
	if err = d.fakeDB.SaveIntelligenceCheckpoint(context.Background(), &delayed); err != nil {
		t.Fatal(err)
	}
	after, _ := d.LoadIntelligenceCheckpoint(context.Background())
	if after.Revision != before.Revision || !after.Complete {
		t.Fatal("delayed save replaced current checkpoint")
	}
	assertRecovery(t, d, 1)
}
