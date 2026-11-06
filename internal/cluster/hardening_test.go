package cluster

import (
	"strings"
	"testing"
)

// TestInitRejectsPasswordBcryptCannotHash: bcrypt only takes 72 bytes. A longer
// cluster password (a generated passphrase) was accepted, stored as the hash
// "invalid", and the cluster could never be unlocked again: the control plane
// logged "Cluster not started" on every start and no node could join.
func TestInitRejectsPasswordBcryptCannotHash(t *testing.T) {
	pw := strings.Repeat("correct-horse-", 6) // 84 bytes
	dir := t.TempDir()
	m := NewManager(dir)
	if _, err := m.InitCluster("c", pw, DefaultClusterConfig()); err == nil {
		// Accepting it is only fine if the cluster then works with it.
		restored := NewManager(dir)
		if _, err := restored.LoadCluster(); err != nil {
			t.Fatal(err)
		}
		if err := restored.UnlockPassword(pw); err != nil {
			t.Fatalf("InitCluster accepted a %d-byte password that can never unlock the cluster: %v", len(pw), err)
		}
	}
	// 72 bytes is still fine.
	ok := strings.Repeat("x", 72)
	m = NewManager(t.TempDir())
	if _, err := m.InitCluster("c", ok, DefaultClusterConfig()); err != nil {
		t.Fatalf("72-byte password rejected: %v", err)
	}
}
