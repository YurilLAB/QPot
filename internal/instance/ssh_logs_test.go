package instance

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/vectorstate"
)

func requireSSHLogDir(t *testing.T, cfg *config.Config, service string) string {
	t.Helper()
	dir, err := sshBackendLogDir(cfg, service)
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func requireSSHLogDirAt(t *testing.T, dataPath, service string) string {
	t.Helper()
	dir, err := sshBackendLogDirAt(dataPath, service)
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func requireSSHOrgCells(t *testing.T, cfg *config.Config) []sshOrgCell {
	t.Helper()
	cells, err := sshOrgCells(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return cells
}

func requireBackendRecycler(t *testing.T, cfg *config.Config) *BackendRecycler {
	t.Helper()
	recycler, err := NewBackendRecycler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return recycler
}

func requireCollectorMounts(t *testing.T, cfg *config.Config) []collectorMount {
	t.Helper()
	mounts, err := collectorMounts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return mounts
}

func requireCollectorSources(t *testing.T, cfg *config.Config) []vectorstate.Source {
	t.Helper()
	sources, err := CollectorSources(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return sources
}

func prepareSSHStoreForTest(t *testing.T, cfg *config.Config) {
	t.Helper()
	lock, err := lockSSHCells(context.Background(), cfg.DataPath)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, err := prepareSSHStore(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestSSHResetArchivesPriorVisitorLogsAndMigratesLegacyLogs(t *testing.T) {
	cfg := organizationTestConfig(t)
	record := organizationFakeDocker(t)
	if err := os.WriteFile(cfg.GetDockerComposePath(), organizationComposeFixture(t, cfg.InstanceName, 2, true), 0o600); err != nil {
		t.Fatal(err)
	}
	members := sshCellServiceNames(cfg, "ssh-backend-1")
	oldDirs := map[string]os.FileInfo{}
	for _, service := range members {
		if err := prepareSSHLogDir(cfg.DataPath, service); err != nil {
			t.Fatal(err)
		}
		current := requireSSHLogDir(t, cfg, service)
		oldDirs[service], _ = os.Stat(current)
		if err := os.WriteFile(filepath.Join(current, "prior.json"), []byte("prior visitor: "+service), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	legacy := filepath.Join(cfg.DataPath, "honeypots", sshBackendDataDir, "ssh-backend-1", "logs")
	if err := os.MkdirAll(legacy, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "legacy.json"), []byte("legacy visitor"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := requireBackendRecycler(t, cfg)
	generation := uint64(0)
	if err := r.resetCell(context.Background(), "ssh-backend-1", &generation); err != nil {
		t.Fatal(err)
	}
	commands, _ := os.ReadFile(record)
	text := string(commands)
	if stop, up := strings.Index(text, "\nstop\n--timeout\n10\n"), strings.Index(text, "\nup\n"); stop < 0 || up <= stop || r.generation("ssh-backend-1") != 1 {
		t.Fatalf("whole cell was not stopped before recreation: %s", text)
	}
	for _, service := range members {
		current := requireSSHLogDir(t, cfg, service)
		entries, err := os.ReadDir(current)
		info, statErr := os.Stat(current)
		if err != nil || statErr != nil || len(entries) != 0 || os.SameFile(oldDirs[service], info) {
			t.Fatalf("new visitor retained the prior %s recording directory", service)
		}
		archives, err := filepath.Glob(filepath.Join(filepath.Dir(current), "archive-g0-*", "logs", "prior.json"))
		if err != nil || len(archives) != 1 {
			t.Fatalf("prior %s evidence was not retained privately: %v", service, err)
		}
		data, _ := os.ReadFile(archives[0])
		parent, _ := os.Stat(filepath.Dir(filepath.Dir(archives[0])))
		if string(data) != "prior visitor: "+service || (runtime.GOOS != "windows" && parent.Mode().Perm() != 0o700) {
			t.Fatal("archive changed captured bytes or was not host-private")
		}
	}
	archives, _ := filepath.Glob(filepath.Join(filepath.Dir(requireSSHLogDir(t, cfg, "ssh-backend-1")), "archive-g0-*", "logs", "legacy.json"))
	if len(archives) != 1 {
		t.Fatal("legacy backend recordings were not migrated to retained host-only storage")
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("legacy log directory remained a future guest mount candidate")
	}
}

func TestSSHArchiveFailureStopsWithoutRecreatingOrAdvancing(t *testing.T) {
	for _, failure := range []string{"not a directory", "symlink", "stop failure"} {
		t.Run(failure, func(t *testing.T) {
			cfg := organizationTestConfig(t)
			record := organizationFakeDocker(t)
			if err := os.WriteFile(cfg.GetDockerComposePath(), organizationComposeFixture(t, cfg.InstanceName, 1, true), 0o600); err != nil {
				t.Fatal(err)
			}
			current := requireSSHLogDir(t, cfg, "ssh-backend-1")
			if err := os.MkdirAll(filepath.Dir(current), 0o750); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(t.TempDir(), "untouched")
			if err := os.WriteFile(outside, []byte("unrelated data"), 0o600); err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "not a directory":
				if err := os.WriteFile(current, []byte("obstruction"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Dir(outside), current); err != nil {
					t.Fatal(err)
				}
			case "stop failure":
				t.Setenv("SSH_TEST_EXIT", "19")
				if err := os.Mkdir(current, 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(current, "prior.json"), []byte("keep prior evidence"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			r := requireBackendRecycler(t, cfg)
			generation := uint64(0)
			if err := r.resetCell(context.Background(), "ssh-backend-1", &generation); err == nil || r.generation("ssh-backend-1") != 0 {
				t.Fatal("failed archival/stop allowed a new guest or signalled a fresh cell")
			}
			commands, _ := os.ReadFile(record)
			if !strings.Contains(string(commands), "\nstop\n") || strings.Contains(string(commands), "\nup\n") {
				t.Fatal("archive failure created a replacement guest")
			}
			data, _ := os.ReadFile(outside)
			if string(data) != "unrelated data" {
				t.Fatal("archive followed an attacker-controlled symlink")
			}
		})
	}
}

func TestSSHOperatorRecreateAlsoArchivesPriorVisitorLogs(t *testing.T) {
	cfg := organizationTestConfig(t)
	record := organizationFakeDocker(t)
	if err := prepareSSHLogDir(cfg.DataPath, "ssh-backend-1"); err != nil {
		t.Fatal(err)
	}
	current := requireSSHLogDir(t, cfg, "ssh-backend-1")
	if err := os.WriteFile(filepath.Join(current, "prior.json"), []byte("prior operator deployment"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.RecreateHoneypot(context.Background(), sshProxyHoneypot); err != nil {
		t.Fatal(err)
	}
	commands, _ := os.ReadFile(record)
	text := string(commands)
	if stop, up := strings.Index(text, "\nstop\n"), strings.Index(text, "\nup\n"); stop < 0 || up <= stop || !strings.Contains(text[stop:up], "\nssh-proxy\n") {
		t.Fatal("operator deployment did not stop ingress before preparing a fresh cell")
	}
	entries, _ := os.ReadDir(current)
	archives, _ := filepath.Glob(filepath.Join(filepath.Dir(current), "archive-g0-*", "logs", "prior.json"))
	if len(entries) != 0 || len(archives) != 1 {
		t.Fatal("operator recreation exposed previous visitor transcripts")
	}
}
