package cluster

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// This helper exits without running any deferred cleanup. It models process
// termination, not a machine power loss or a storage device that lies on fsync.
func TestUpgradeCrashHelper(t *testing.T) {
	mode := os.Getenv("QPOT_TEST_UPGRADE_CRASH")
	if mode == "" {
		return
	}
	m := NewManager(os.Getenv("QPOT_TEST_UPGRADE_PATH"))
	if _, err := m.LoadCluster(); err != nil {
		t.Fatal(err)
	}
	if err := m.UnlockPassword("password123"); err != nil {
		t.Fatal(err)
	}
	writes := 0
	m.upgradeWrite = func(file *os.File, data []byte) error {
		writes++
		if (mode == "partial-backup" && writes == 1) || (mode == "partial-stage" && writes == 2) {
			if _, err := file.Write(data[:len(data)/2]); err != nil {
				return err
			}
			if err := file.Sync(); err != nil {
				return err
			}
			os.Exit(93)
		}
		return writeUpgradeFile(file, data)
	}
	m.upgradeActivate = func(staged, active string) error {
		if mode == "before-activation" {
			os.Exit(93)
		}
		if err := os.Rename(staged, active); err != nil {
			return err
		}
		if mode == "after-activation" {
			os.Exit(93)
		}
		return nil
	}
	_, _, err := m.UpgradeCluster()
	t.Fatalf("crash hook was not reached: %v", err)
}

func TestUpgradeCrashBoundariesPreserveRecoverableState(t *testing.T) {
	for _, mode := range []string{"partial-backup", "partial-stage", "before-activation", "after-activation"} {
		t.Run(mode, func(t *testing.T) {
			m, old, raw := testLegacyCluster(t)
			dataPath := filepath.Join(m.dataPath, "events.data")
			data := []byte("existing event data and settings")
			if err := os.WriteFile(dataPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUpgradeCrashHelper$")
			cmd.Env = append(os.Environ(), "QPOT_TEST_UPGRADE_CRASH="+mode, "QPOT_TEST_UPGRADE_PATH="+m.dataPath)
			output, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 93 {
				t.Fatalf("helper did not stop at crash boundary: %v\n%s", err, output)
			}
			if got, err := os.ReadFile(dataPath); err != nil || !bytes.Equal(got, data) {
				t.Fatal("upgrade changed local event data")
			}
			if got, err := os.ReadFile(filepath.Join(m.dataPath, secretFile)); err != nil || string(got) != "password123" {
				t.Fatal("upgrade changed the existing password secret")
			}
			if _, err := os.Stat(filepath.Join(m.dataPath, "cluster.upgrade.lock")); err != nil {
				t.Fatal("crash unexpectedly removed operator recovery lock")
			}
			restarted := NewManager(m.dataPath)
			loaded, err := restarted.LoadCluster()
			if err != nil || loaded == nil {
				t.Fatalf("active state unreadable after process crash: %v", err)
			}
			if mode == "after-activation" {
				if loaded.Version != ProtocolVersion || loaded.ID == old.ID || loaded.CAKey == old.CAKey || loaded.MemberKey == old.MemberKey {
					t.Fatal("post-activation crash restored old trust")
				}
				if _, err := nodeCertificate(loaded.ID, loaded.LocalNode.ID, loaded.NodeCertificate, loaded.NodeKey); err != nil {
					t.Fatal(err)
				}
				if loaded.Name != old.Name || *loaded.Config != *old.Config || loaded.LocalNode.QPotID != old.LocalNode.QPotID || len(loaded.Nodes) != 1 {
					t.Fatal("post-activation crash lost local settings or retained old members")
				}
			} else {
				got, err := os.ReadFile(filepath.Join(m.dataPath, "cluster.json"))
				if err != nil || !bytes.Equal(got, raw) || loaded.ID != old.ID || loaded.Version != old.Version {
					t.Fatal("pre-activation crash changed active state or adopted staging")
				}
				if err := restarted.UnlockPassword("password123"); err != nil {
					t.Fatal(err)
				}
				_, _, err = restarted.UpgradeCluster()
				requireClusterCode(t, err, "QP-CLUSTER-006")
				// A deliberate operator recovery, after verifying the owner exited,
				// allows a fresh transaction. Orphaned staging is never reused.
				if err := os.Remove(filepath.Join(m.dataPath, "cluster.upgrade.lock")); err != nil {
					t.Fatal(err)
				}
				upgraded, _, err := restarted.UpgradeCluster()
				if err != nil || upgraded == nil || upgraded.ID == old.ID {
					t.Fatalf("recovery failed: %v", err)
				}
			}
			if mode != "partial-backup" {
				backups, err := filepath.Glob(filepath.Join(m.dataPath, "cluster.legacy-*.json"))
				if err != nil || len(backups) == 0 {
					t.Fatal("recoverable backup missing")
				}
				for _, path := range backups {
					got, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(got, raw) {
						t.Fatal("backup is not exact original state")
					}
					if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
						t.Fatal("backup permissions expose recovery credentials")
					}
				}
			}
		})
	}
}
