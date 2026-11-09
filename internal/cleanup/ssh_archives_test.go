package cleanup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSSHArchiveRetentionPrunesClosedTreesAndPreservesLiveAndFreshLogs(t *testing.T) {
	for _, dry := range []bool{false, true} {
		t.Run(map[bool]string{false: "actual", true: "dry run"}[dry], func(t *testing.T) {
			cfg := testInstance(t)
			base := "honeypots/ssh-proxy/logs/cells/ssh-backend-1/"
			expired := "archive-g42-123456789/"
			// A prior visitor can forge a future timestamp on the recording.
			victim := putLog(t, cfg, base+expired+"logs/0/events.json", 1, 128, -day)
			deliver(t, cfg, "ssh_backend", victim, -1)
			archive := filepath.Dir(filepath.Dir(filepath.Dir(victim)))
			old := now.Add(-40 * day)
			if err := os.Chtimes(archive, old, old); err != nil {
				t.Fatal(err)
			}
			current := put(t, cfg, base+"current/0/events.json", 32, day)
			fresh := put(t, cfg, base+"archive-g43-987654321/logs/0/events.json", 32, day)
			unknown := put(t, cfg, base+"archive-untrusted/logs/0/events.json", 32, day)
			report := Run(context.Background(), cfg, limits(), Options{Now: now, DryRun: dry, CollectorRunning: true})
			if len(report.Errors) != 0 {
				t.Fatalf("archive cleanup failed: %v", report.Errors)
			}
			if exists(archive) != dry || exists(victim) != dry {
				t.Fatal("expired archive was not removed only during actual cleanup")
			}
			for _, file := range []string{current, fresh, unknown} {
				if !exists(file) {
					t.Fatalf("archive retention removed live, fresh or unknown storage: %s", file)
				}
			}
			if report.Freed < 128 {
				t.Fatal("archive bytes were not included in normal retention accounting")
			}
		})
	}
}

func TestSSHArchiveRetentionNeverFollowsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions depend on Windows host policy")
	}
	cfg := testInstance(t)
	outside := t.TempDir()
	untouched := filepath.Join(outside, "untouched")
	if err := os.WriteFile(untouched, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(cfg.DataPath, "honeypots/ssh-proxy/logs/cells/ssh-backend-16-backup/archive-g0-123456789")
	if err := os.MkdirAll(filepath.Join(archive, "logs/1001/empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(archive, "logs/1001/link")); err != nil {
		t.Fatal(err)
	}
	old := now.Add(-40 * day)
	if err := os.Chtimes(archive, old, old); err != nil {
		t.Fatal(err)
	}
	report := Run(context.Background(), cfg, limits(), Options{Now: now})
	if len(report.Errors) != 0 || exists(archive) || !exists(untouched) {
		t.Fatalf("expired empty directories/link cleanup escaped or failed: %v", report.Errors)
	}
	// Replacing the entire trusted archive name by a link must never make
	// retention follow it, even when that name matches the archive grammar.
	if err := os.Symlink(outside, archive); err != nil {
		t.Fatal(err)
	}
	Run(context.Background(), cfg, limits(), Options{Now: now})
	if !exists(archive) || !exists(untouched) {
		t.Fatal("archive-name symlink was followed")
	}
}

func TestSSHArchiveRetentionCanBeDisabledAndHasBoundedWork(t *testing.T) {
	cfg := testInstance(t)
	archive := filepath.Join(cfg.DataPath, "honeypots/ssh-proxy/logs/cells/ssh-backend-1-db/archive-g0-123456789")
	if err := os.MkdirAll(filepath.Join(archive, "logs/999/empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	old := now.Add(-40 * day)
	_ = os.Chtimes(archive, old, old)
	lim := limits()
	lim.MaxAge = 0
	Run(context.Background(), cfg, lim, Options{Now: now})
	if !exists(archive) {
		t.Fatal("disabled age retention removed an archive")
	}
	root, err := os.OpenRoot(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	budget := 1
	if err := removeSSHArchive(context.Background(), root, "logs", &budget, 0); err == nil || budget < 0 {
		t.Fatal("archive traversal did not stop at its work limit")
	}
	if !exists(filepath.Join(archive, "logs/999/empty")) {
		t.Fatal("bounded cleanup traversed beyond its budget")
	}
	for _, name := range []string{"archive-g0-123456789", "archive-g18446744073709551615-1"} {
		if !sshArchiveName(name) {
			t.Fatalf("valid trusted archive name rejected: %s", name)
		}
	}
	for _, name := range []string{"current", "archive-g-1", "archive-g-1-1", "archive-g0-../current", "archive-g0-123x", "archive-g18446744073709551616-1"} {
		if sshArchiveName(name) {
			t.Fatalf("untrusted archive name accepted: %s", name)
		}
	}
}

func TestSSHArchiveScanDoesNotStarveLaterSlots(t *testing.T) {
	cfg := testInstance(t)
	hp := filepath.Join(cfg.DataPath, "honeypots", "ssh-proxy")
	busy := filepath.Join(hp, "logs/cells/ssh-backend-1")
	if err := os.MkdirAll(busy, 0o750); err != nil {
		t.Fatal(err)
	}
	// More fresh headers than one complete scan can inspect. The last slot's
	// expired archive must still receive a share of every cleanup pass.
	for index := 0; index <= maxSSHArchiveEntries; index++ {
		if err := os.Mkdir(filepath.Join(busy, fmt.Sprintf("archive-g0-%d", index)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	late := filepath.Join(hp, "logs/cells/ssh-backend-16-backup/archive-g0-123456789")
	if err := os.MkdirAll(filepath.Join(late, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	old := now.Add(-40 * day)
	if err := os.Chtimes(late, old, old); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(hp)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	archives := expiredSSHArchives(context.Background(), root, now.Add(-30*day))
	if len(archives) != 1 || archives[0].service != "ssh-backend-16-backup" {
		t.Fatal("busy first slot starved retention for a later retired slot")
	}
}

func TestSSHArchiveRemovalRetainsEvidenceWhenInventoryExceedsBound(t *testing.T) {
	cfg := testInstance(t)
	hp := filepath.Join(cfg.DataPath, "honeypots", "ssh-proxy")
	busy := filepath.Join(hp, "logs/cells/ssh-backend-1/archive-g0-123456789/logs")
	if err := os.MkdirAll(busy, 0o700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index <= maxSSHArchiveEntries; index++ {
		if err := os.Mkdir(filepath.Join(busy, fmt.Sprint(index)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	late := filepath.Join(hp, "logs/cells/ssh-backend-16-backup/archive-g0-987654321")
	if err := os.MkdirAll(filepath.Join(late, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	old := now.Add(-40 * day)
	_ = os.Chtimes(filepath.Dir(busy), old, old)
	_ = os.Chtimes(late, old, old)
	root, err := os.OpenRoot(hp)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	archives := expiredSSHArchives(context.Background(), root, now.Add(-30*day))
	pruneSSHArchives(context.Background(), &Report{}, &Area{}, root, hp, archives, Options{})
	if !exists(late) {
		t.Fatal("incomplete delivery inventory authorized archive deletion")
	}
	if !exists(filepath.Dir(busy)) {
		t.Fatal("archive deletion exceeded the per-service bounded work budget")
	}
}

func TestSSHArchiveRetentionRequiresNativeAcknowledgementAndUnambiguousLogs(t *testing.T) {
	for _, scenario := range []string{"stopped", "missing", "partial", "wrong-source", "duplicate", "delivered"} {
		t.Run(scenario, func(t *testing.T) {
			cfg := testInstance(t)
			rel := "honeypots/ssh-proxy/logs/cells/ssh-backend-1/archive-g1-123/logs/0/events.json"
			victim := putLog(t, cfg, rel, 3, 128, day)
			archive := filepath.Dir(filepath.Dir(filepath.Dir(victim)))
			old := now.Add(-40 * day)
			if err := os.Chtimes(archive, old, old); err != nil {
				t.Fatal(err)
			}
			running := scenario != "stopped"
			switch scenario {
			case "stopped", "delivered", "duplicate":
				deliver(t, cfg, "ssh_backend", victim, -1)
			case "partial":
				deliver(t, cfg, "ssh_backend", victim, 1)
			case "wrong-source":
				deliver(t, cfg, "ssh-proxy", victim, -1)
			}
			if scenario == "duplicate" {
				data, err := os.ReadFile(victim)
				if err != nil {
					t.Fatal(err)
				}
				copy := filepath.Join(cfg.DataPath, "honeypots/ssh-proxy/logs/cells/ssh-backend-2/current/0/other.json")
				if err := os.MkdirAll(filepath.Dir(copy), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(copy, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			// Storage pressure and forged old capture timestamps must not bypass
			// archive acknowledgement through the ordinary file-pruning path.
			lim := limits()
			lim.HoneypotLimit = func(string) int64 { return 1 }
			report := Run(context.Background(), cfg, lim, Options{Now: now, CollectorRunning: running})
			if len(report.Errors) > 0 {
				t.Fatal(report.Errors)
			}
			if exists(victim) != (scenario != "delivered") {
				t.Fatalf("archive state wrong for %s", scenario)
			}
		})
	}
}

func TestSSHInventoryHelperRejectsIncompleteAmbiguousAndOversizedFraming(t *testing.T) {
	for _, input := range []string{"", "complete\nextra\n", "2e2e2f657363617065 1 1 -\ncomplete\n", "61 1 1 -\n61 1 1 -\ncomplete\n", "61 -1 1 -\ncomplete\n"} {
		if _, err := decodeSSHInventory([]byte(input)); err == nil {
			t.Fatalf("invalid inventory accepted: %q", input)
		}
	}
	called := false
	helper := &DockerHelper{Image: "trusted", Run: func(ctx context.Context, args ...string) ([]byte, error) {
		called = true
		joined := strings.Join(args, " ")
		for _, required := range []string{"--network none", "--read-only", "--cap-drop ALL", "--cap-add DAC_OVERRIDE", "--pids-limit 16", "--memory 64m", "target=/c,readonly", "/tmp:rw,nosuid,nodev,noexec,size=1m"} {
			if !strings.Contains(joined, required) {
				t.Errorf("helper missing %s", required)
			}
		}
		if strings.Contains(joined, "--privileged") || strings.Contains(joined, "SYS_ADMIN") || strings.Contains(joined, "docker.sock") {
			t.Fatal("helper widened trust")
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 31*time.Second {
			t.Fatal("helper deadline missing")
		}
		return []byte("complete\n"), nil
	}}
	if _, err := helper.SSHInventory(context.Background(), t.TempDir()); err != nil || !called {
		t.Fatalf("bounded helper call failed: %v", err)
	}
}

// The deliverable victim is chosen from actual filesystem iteration order,
// not assumptions about name sorting or creation order on a particular OS.
func TestSameCellUndeliveredArchivePrefixCannotStarveAcknowledgedArchive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native Windows cannot prove link counts; helper fallback is required for nonempty archive pruning")
	}
	cfg := testInstance(t)
	const count = 200 // one cell; complete evidence inventory stays below8192
	cell := filepath.Join(cfg.DataPath, "honeypots", "ssh-proxy", "logs", "cells", "ssh-backend-1")
	original := map[string][]byte{}
	old := now.Add(-40 * day)
	for index := 0; index < count; index++ {
		name := fmt.Sprintf("archive-g1-%d", index+1)
		rel := filepath.ToSlash(filepath.Join("honeypots", "ssh-proxy", "logs", "cells", "ssh-backend-1", name, "logs", "uid-1001", "events.json"))
		file := putLog(t, cfg, rel, 1, 128, day)
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		original[name] = data
		if err := os.Chtimes(filepath.Join(cell, name), old, old); err != nil {
			t.Fatal(err)
		}
	}
	directory, err := os.Open(cell)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := directory.ReadDir(-1)
	closeErr := directory.Close()
	if err != nil || closeErr != nil || len(entries) != count {
		t.Fatalf("bounded fixture inventory: %v %v %d", err, closeErr, len(entries))
	}
	selected := entries[len(entries)-1].Name()
	victim := filepath.Join(cell, selected, "logs", "uid-1001", "events.json")
	deliver(t, cfg, "ssh_backend", victim, -1)
	report := Run(t.Context(), cfg, limits(), Options{Now: now, CollectorRunning: true})
	if len(report.Errors) > 0 {
		t.Fatalf("closed evidence cleanup failed: %v", report.Errors)
	}
	if exists(filepath.Join(cell, selected)) {
		t.Fatalf("same-cell unacknowledged prefix starved a fully acknowledged expired archive: %s", selected)
	}
	for _, entry := range entries {
		if entry.Name() == selected {
			continue
		}
		data, err := os.ReadFile(filepath.Join(cell, entry.Name(), "logs", "uid-1001", "events.json"))
		if err != nil || string(data) != string(original[entry.Name()]) {
			t.Fatalf("unacknowledged prefix evidence changed: %s %v", entry.Name(), err)
		}
	}
}

func TestSSHArchiveSelectionReusesBudgetAndClosesCellHandles(t *testing.T) {
	cfg := testInstance(t)
	hp := filepath.Join(cfg.DataPath, "honeypots", "ssh-proxy")
	cell := filepath.Join(hp, "logs", "cells", "ssh-backend-1")
	old := now.Add(-40 * day)
	for index := 0; index < 200; index++ {
		header := filepath.Join(cell, fmt.Sprintf("archive-g1-%d", index+1))
		if err := os.MkdirAll(filepath.Join(header, "logs"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(header, old, old); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(hp)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	archives := expiredSSHArchives(t.Context(), root, now.Add(-30*day), cfg.DataPath)
	if len(archives) != 200 {
		t.Fatalf("unused global scan budget did not reach all200 bounded same-cell headers: %d", len(archives))
	}
	var report Report
	var area Area
	pruneSSHArchives(t.Context(), &report, &area, root, hp, archives, Options{})
	if len(report.Errors) > 0 || area.Removed == 0 || exists(filepath.Join(hp, filepath.FromSlash(archives[0].rel))) {
		t.Fatalf("returned cell handles prevented actual empty-archive deletion: %v", report.Errors)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(hp); err != nil {
		t.Fatalf("archive selection leaked directory handles: %v", err)
	}
}

type archiveCancelAfterChecks struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *archiveCancelAfterChecks) Err() error {
	c.checks++
	if c.checks == 4 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestSSHArchiveSelectionCancellationClosesCellHandles(t *testing.T) {
	cfg := testInstance(t)
	hp := filepath.Join(cfg.DataPath, "honeypots", "ssh-proxy")
	header := filepath.Join(hp, "logs", "cells", "ssh-backend-1", "archive-g1-1")
	if err := os.MkdirAll(filepath.Join(header, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(hp)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	checked := &archiveCancelAfterChecks{Context: ctx, cancel: cancel}
	_ = expiredSSHArchives(checked, root, now, cfg.DataPath)
	if ctx.Err() != context.Canceled {
		t.Fatal("fixture failed to cancel while scanning finite cells")
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(hp); err != nil {
		t.Fatalf("cancelled archive scan leaked a directory handle: %v", err)
	}
}
