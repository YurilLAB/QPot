package instance

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/proxy"
	"github.com/qpot/qpot/internal/sshcapture"
)

// The drain converts every backend it can and names the ones it could not;
// a backend with no container has nothing to convert.
func TestDrainConvertsWhatItCanAndReportsTheRest(t *testing.T) {
	cfg := organizationTestConfig(t)
	prepareSSHStoreForTest(t, cfg)
	for _, service := range []string{"ssh-backend-1", "ssh-backend-2"} {
		if err := prepareSSHLogDir(cfg.DataPath, service); err != nil {
			t.Fatal(err)
		}
	}
	converter := &sshcapture.Converter{
		Inspect: func(_ context.Context, name string) (sshcapture.Container, error) {
			if strings.HasSuffix(name, "_ssh-backend-3") {
				return sshcapture.Container{}, nil
			}
			return sshcapture.Container{ID: name + "-id", Created: time.Now().Add(-time.Hour)}, nil
		},
		Stream: func(_ context.Context, id string, _ bool) (io.ReadCloser, io.ReadCloser, func() error, error) {
			if strings.HasSuffix(id, "_ssh-backend-1-id") {
				return nil, nil, nil, errors.New("the daemon is unavailable")
			}
			return io.NopCloser(strings.NewReader("")), io.NopCloser(strings.NewReader("Accepted password for root from 172.30.0.10 port 40000 ssh2\r\n")), func() error { return nil }, nil
		},
	}
	brokerLog := filepath.Join(t.TempDir(), "sessions.json")
	err := drainSSHCapturesWith(t.Context(), converter, cfg.DataPath, cfg.InstanceName, brokerLog,
		[]string{"ssh-backend-1", "ssh-backend-1-db", "ssh-backend-2", "ssh-backend-3"})
	if err == nil || !strings.Contains(err.Error(), "ssh-backend-1: ") || strings.Contains(err.Error(), "ssh-backend-2") || strings.Contains(err.Error(), "ssh-backend-3") {
		t.Fatalf("drain did not name exactly the backend it could not convert: %v", err)
	}
	dir, err := sshBackendLogDirAt(cfg.DataPath, "ssh-backend-2")
	if err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(dir, sshcapture.AuthLog)); err != nil || !strings.Contains(string(data), "Accepted password") {
		t.Fatalf("one backend's failure stopped the others' conversion: %v %q", err, data)
	}
	if err := drainSSHCapturesWith(t.Context(), converter, cfg.DataPath, cfg.InstanceName, brokerLog, []string{"ssh-backend-3"}); err != nil {
		t.Fatalf("a backend without a container failed the drain: %v", err)
	}
}

// Removing a backend container loses the sessions only its log holds. When
// they cannot be converted, every path that removes cells keeps them: the
// reset neither archives nor recreates, deployment and retirement remove
// nothing, and stopping the instance takes nothing down.
func TestSSHCellRemovalKeepsUnconvertedContainers(t *testing.T) {
	for _, path := range []string{"reset", "deploy", "stop", "retire"} {
		for _, convertible := range []bool{false, true} {
			t.Run(path+map[bool]string{false: "/logs fail", true: "/logs read"}[convertible], func(t *testing.T) {
				cfg := organizationTestConfig(t)
				trace := organizationFakeDocker(t)
				prepareSSHStoreForTest(t, cfg)
				cells := 1
				if path == "retire" {
					cells = 2
				}
				compose := organizationComposeFixture(t, cfg.InstanceName, cells, true)
				if err := os.WriteFile(cfg.GetDockerComposePath(), compose, 0o600); err != nil {
					t.Fatal(err)
				}
				for _, service := range SSHCellLogServices()[:3*cells] {
					if err := prepareSSHLogDir(cfg.DataPath, service); err != nil {
						t.Fatal(err)
					}
				}
				t.Setenv("SSH_TEST_CONTAINER", "1")
				if !convertible {
					t.Setenv("SSH_TEST_LOGS_EXIT", "7")
				}
				manager, err := NewManager(cfg)
				if err != nil {
					t.Fatal(err)
				}
				recycler := requireBackendRecycler(t, cfg)
				removal := "rm"
				switch path {
				case "reset":
					err = recycler.composeRecreate(t.Context(), "ssh-backend-1")
					removal = "up"
				case "deploy":
					err = manager.prepareSSHDeployment(t.Context())
				case "stop":
					err = manager.Stop(t.Context())
					removal = "down"
				case "retire":
					hp := cfg.Honeypots[sshProxyHoneypot]
					hp.CustomConfig["backends"] = "1"
					cfg.Honeypots[sshProxyHoneypot] = hp
					err = retireSSHCells(t.Context(), cfg, compose)
				}
				commands, _ := os.ReadFile(trace)
				if !strings.Contains(string(commands), "\nlogs\n") {
					t.Fatalf("%s removed cells without reading their capture: %v\n%s", path, err, commands)
				}
				archives, _ := filepath.Glob(filepath.Join(filepath.Dir(requireSSHLogDir(t, cfg, "ssh-backend-1")), "archive-g*"))
				if !convertible {
					if err == nil || !strings.Contains(err.Error(), "not yet converted") {
						t.Fatalf("%s carried on after a failed conversion: %v", path, err)
					}
					if strings.Contains(string(commands), "\n"+removal+"\n") || len(archives) != 0 || recycler.generation("ssh-backend-1") != 0 {
						t.Fatalf("%s removed or archived unconverted cells (archives %v):\n%s", path, archives, commands)
					}
					return
				}
				if err != nil && strings.Contains(err.Error(), "not yet converted") {
					t.Fatalf("%s reported a conversion failure with readable logs: %v", path, err)
				}
				// The control: with readable logs the path goes on to its
				// archive or removal (a reset stops later, at the fixture's
				// unverifiable images, after archiving).
				if path == "reset" {
					if len(archives) == 0 {
						t.Fatalf("reset did not archive after a successful conversion: %v", err)
					}
				} else if !strings.Contains(string(commands), "\n"+removal+"\n") {
					t.Fatalf("%s did not remove the cells after a successful conversion: %v\n%s", path, err, commands)
				}
			})
		}
	}
}

// The lifecycle lock holds the folders lock too, so nothing writes a cell's
// evidence while a holder drains or archives it; releasing the folders lets
// the capture followers write while the lifecycle stays held.
func TestSSHCellLockHoldsFoldersUntilReleased(t *testing.T) {
	dir := t.TempDir()
	waitBriefly := func() context.Context {
		ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
		t.Cleanup(cancel)
		return ctx
	}
	lock, err := lockSSHCells(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockSSHFolders(waitBriefly(), dir); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a follower could write while the lifecycle holder owns the folders: %v", err)
	}
	if err := lock.releaseFolders(); err != nil {
		t.Fatal(err)
	}
	folders, err := lockSSHFolders(waitBriefly(), dir)
	if err != nil {
		t.Fatalf("released folders stayed locked: %v", err)
	}
	if _, err := lockSSHCells(waitBriefly(), dir); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("releasing the folders released the lifecycle: %v", err)
	}
	if err := folders.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := lockSSHCells(waitBriefly(), dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = again.Close()
}

// A reset recreates its cell's containers with the folders lock released:
// the other cells' followers keep converting meanwhile, instead of stalling
// for minutes while their containers' logs grow and rotate.
func TestSSHResetLetsFollowersWriteWhileItRecreates(t *testing.T) {
	cfg := organizationTestConfig(t)
	organizationFakeDocker(t)
	if err := os.WriteFile(cfg.GetDockerComposePath(), organizationComposeFixture(t, cfg.InstanceName, 2, true), 0o600); err != nil {
		t.Fatal(err)
	}
	r := requireBackendRecycler(t, cfg)
	if err := os.MkdirAll(r.GenerationDir, 0o750); err != nil {
		t.Fatal(err)
	}
	started, release := filepath.Join(t.TempDir(), "up-started"), filepath.Join(t.TempDir(), "up-release")
	t.Setenv("SSH_TEST_UP_STARTED", started)
	t.Setenv("SSH_TEST_UP_RELEASE", release)
	done := make(chan error, 1)
	go func() { done <- r.composeRecreate(t.Context(), "ssh-backend-1") }()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = os.WriteFile(release, nil, 0o600)
			t.Fatalf("the reset never reached its recreation: %v", <-done)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	folders, err := lockSSHFolders(ctx, cfg.DataPath)
	cancel()
	if err != nil {
		_ = os.WriteFile(release, nil, 0o600)
		<-done
		t.Fatalf("followers stall behind a cell's recreation: %v", err)
	}
	_ = folders.Close()
	ctx, cancel = context.WithTimeout(t.Context(), 150*time.Millisecond)
	if lock, err := lockSSHCells(ctx, cfg.DataPath); err == nil {
		_ = lock.Close()
		t.Error("the recreation ran without the lifecycle lock")
	}
	cancel()
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// The control plane's capture loop keeps the broker's capture gate open, with
// a heartbeat the broker's non-root user can read, and stops beating with it.
func TestRunCaptureKeepsTheBrokerGateOpen(t *testing.T) {
	dir := t.TempDir()
	r := &BackendRecycler{
		InstanceName:  "beat",
		ComposeFile:   filepath.Join(dir, "missing-compose.yml"),
		LogPath:       filepath.Join(dir, "sessions.json"),
		GenerationDir: filepath.Join(dir, "generations"),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.RunCapture(ctx) }()
	defer func() { cancel(); <-done }()

	gate := proxy.NewGenerationGate(r.GenerationDir)
	watchCtx, stopWatch := context.WithCancel(context.Background())
	defer stopWatch()
	go gate.WatchCapture(watchCtx, 20*time.Millisecond)
	deadline := time.Now().Add(3 * captureHeartbeatEvery)
	for !gate.CaptureLive() {
		if time.Now().After(deadline) {
			t.Fatal("the broker never saw capture running")
		}
		time.Sleep(50 * time.Millisecond)
	}
	info, err := os.Stat(filepath.Join(r.GenerationDir, proxy.CaptureHeartbeat))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
		t.Errorf("heartbeat mode %v: the broker's user cannot read it", info.Mode().Perm())
	}

	cancel()
	<-done
	before, err := os.ReadFile(filepath.Join(r.GenerationDir, proxy.CaptureHeartbeat))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(captureHeartbeatEvery + time.Second)
	after, err := os.ReadFile(filepath.Join(r.GenerationDir, proxy.CaptureHeartbeat))
	if err != nil || string(after) != string(before) {
		t.Fatalf("the heartbeat changed after capture stopped (%v)", err)
	}
}
