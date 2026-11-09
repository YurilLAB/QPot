package instance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// RestartHoneypot runs `docker compose restart` for the honeypot and its
// companions only, and passes no unknown name to docker.
func TestRestartHoneypotArgv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in docker is a shell script")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\necho \"$*\" >> " + log + "\nif [ \"$1\" = info ]; then printf '%s\\n' '" + sshSupportedResourceInfo + "'; fi\ncase \"$*\" in *fail-me*) echo boom >&2; exit 1 ;; esac\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil { // #nosec G306 -- test stand-in must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cfg := settingsTestConfig(t, "restart-argv")
	cfg.Security.SandboxMode = "none"
	cfg.EnableHoneypot("ssh-proxy")
	cfg.SetHoneypotCustomConfig(sshProxyHoneypot, map[string]string{"image_source": "local"})
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	prepareSSHStoreForTest(t, cfg)
	storageWrite(t, cfg.GetDockerComposePath(), organizationComposeFixture(t, cfg.InstanceName, 2, false), 0o600)
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := m.RestartHoneypot(ctx, "ssh-proxy"); err != nil {
		t.Fatal(err)
	}
	if err := m.RestartHoneypot(ctx, "--project-name=fail-me"); err == nil || !strings.Contains(err.Error(), "unknown honeypot") {
		t.Fatalf("unknown name: %v", err)
	}
	data, _ := os.ReadFile(log)
	want := "info --format " + sshResourceInfoFormat + "\ncompose -f " + cfg.GetDockerComposePath() + " restart ssh-proxy ssh-backend-1 ssh-backend-2\n"
	if string(data) != want {
		t.Fatalf("docker calls:\n%q\nwant\n%q", data, want)
	}
}

func TestSSHRestartWaitsForLifecycleLockAndLeavesOtherHoneypotsIndependent(t *testing.T) {
	cfg := organizationTestConfig(t)
	storageWrite(t, cfg.GetDockerComposePath(), organizationComposeFixture(t, cfg.InstanceName, 2, true), 0o600)
	cfg.Security.SandboxMode = "none"
	record := organizationFakeDocker(t)
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := lockSSHCells(context.Background(), cfg.DataPath)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		done <- m.RestartHoneypot(ctx, sshProxyHoneypot)
	}()
	<-started
	select {
	case err := <-done:
		t.Fatalf("SSH restart passed a held lifecycle lock: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	commands, _ := os.ReadFile(record)
	if len(commands) != 0 {
		t.Fatalf("blocked SSH restart reached Docker: %s", commands)
	}
	if err := m.RestartHoneypot(ctx, "cowrie"); err != nil {
		t.Fatalf("unrelated honeypot restart waited for SSH lifecycle: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("SSH restart did not resume after lifecycle lock release")
	}
	commands, _ = os.ReadFile(record)
	if !strings.Contains(string(commands), "\nrestart\ncowrie\n") || !strings.Contains(string(commands), "\nrestart\nssh-proxy\n") {
		t.Fatalf("missing independent/released restart calls: %s", commands)
	}
}

func TestSSHRestartCancellationWhileWaitingNeverCallsDocker(t *testing.T) {
	cfg := organizationTestConfig(t)
	storageWrite(t, cfg.GetDockerComposePath(), organizationComposeFixture(t, cfg.InstanceName, 2, true), 0o600)
	cfg.Security.SandboxMode = "none"
	record := organizationFakeDocker(t)
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := lockSSHCells(context.Background(), cfg.DataPath)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := m.RestartHoneypot(ctx, sshProxyHoneypot); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting restart did not preserve cancellation: %v", err)
	}
	if commands, _ := os.ReadFile(record); len(commands) != 0 {
		t.Fatalf("canceled SSH restart reached Docker: %s", commands)
	}
}

func TestSSHRestartHoldsLifecycleLockThroughDockerCommand(t *testing.T) {
	cfg := organizationTestConfig(t)
	storageWrite(t, cfg.GetDockerComposePath(), organizationComposeFixture(t, cfg.InstanceName, 2, true), 0o600)
	cfg.Security.SandboxMode = "none"
	organizationFakeDocker(t)
	started, release := filepath.Join(t.TempDir(), "started"), filepath.Join(t.TempDir(), "release")
	t.Setenv("SSH_TEST_RESTART_STARTED", started)
	t.Setenv("SSH_TEST_RESTART_RELEASE", release)
	t.Cleanup(func() { _ = os.WriteFile(release, nil, 0o600) })
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.RestartHoneypot(ctx, sshProxyHoneypot) }()
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("SSH restart did not reach Docker")
		}
		time.Sleep(5 * time.Millisecond)
	}
	waitCtx, stopWaiting := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer stopWaiting()
	if lock, err := lockSSHCells(waitCtx, cfg.DataPath); !errors.Is(err, context.DeadlineExceeded) {
		if lock != nil {
			_ = lock.Close()
		}
		t.Fatalf("lifecycle lock was released before Docker restart completed: %v", err)
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	lock, err := lockSSHCells(ctx, cfg.DataPath)
	if err != nil {
		t.Fatal("completed SSH restart did not release lifecycle lock")
	}
	_ = lock.Close()
}
