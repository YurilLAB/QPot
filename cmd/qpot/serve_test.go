package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
)

// TestHelperServeProcess stands in for a running `qpot serve -i <name>`: the
// test binary re-runs itself with these arguments and just waits.
func TestHelperServeProcess(t *testing.T) {
	if os.Getenv("QPOT_HELPER_SERVE") != "1" {
		t.Skip("helper process")
	}
	time.Sleep(60 * time.Second)
}

// startServeHelper starts a stand-in `qpot serve -i <name>` and returns once
// its command line shows: exec.Cmd.Start can return before the kernel has set
// up the new program's arguments, and /proc/<pid>/cmdline reads empty until
// then, so a check made straight away sees no control plane at all.
func startServeHelper(t *testing.T, name string) *exec.Cmd {
	t.Helper()
	c := exec.Command(os.Args[0], "-test.run=^TestHelperServeProcess$", "--", "serve", "-i", name)
	c.Env = append(os.Environ(), "QPOT_HELPER_SERVE=1")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
	for deadline := time.Now().Add(10 * time.Second); !isServeProcess(c.Process.Pid, name); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the helper process never showed its command line")
		}
	}
	return c
}

// TestStalePIDFileDoesNotNameANewerProcess: a pid file left by a control plane
// that crashed (or by a reboot) can name a PID the OS has since given to an
// unrelated program. On Windows the pid file was trusted as is, so `qpot down`
// killed that program and `qpot up -d` reported it as the running control
// plane. A process that started after the pid file was written cannot be the
// one that wrote it.
func TestStalePIDFileDoesNotNameANewerProcess(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	cfg := config.Default("stale-pid")
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	pidPath := servePIDPath(cfg)

	// An unrelated program that happens to have the recorded PID.
	other := startServeHelper(t, "stale-pid")
	if err := writeServePID(pidPath, other.Process.Pid); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(pidPath, old, old); err != nil { // written long before it started
		t.Fatal(err)
	}

	if pid := runningServePID(cfg); pid != 0 {
		t.Fatalf("a process started after the pid file was written is taken for the control plane (pid %d)", pid)
	}
	stopBackgroundServe(cfg)
	if !processAlive(other.Process.Pid) {
		t.Fatal("qpot down killed an unrelated process named by a stale pid file")
	}
}

// TestServeRefusesSecondControlPlane: a second `qpot serve` for an instance
// whose control plane already runs overwrote the pid file, failed on the busy
// web UI port, and then deleted the pid file on the way out. `qpot down`
// could no longer find the first control plane, which kept serving and
// recreating HiFi backends after the containers were stopped.
func TestServeRefusesSecondControlPlane(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	const name = "serve-twice"

	// The running control plane holds the web UI port...
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := config.Default(name)
	cfg.WebUI.BindAddr, cfg.WebUI.Port = "127.0.0.1", ln.Addr().(*net.TCPAddr).Port
	cfg.Security.SandboxMode = "none"
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}

	// ...and is registered in the pid file.
	first := startServeHelper(t, name)
	pidPath := servePIDPath(cfg)
	if err := writeServePID(pidPath, first.Process.Pid); err != nil {
		t.Fatal(err)
	}
	if runningServePID(cfg) != first.Process.Pid {
		t.Fatal("helper process not recognised as the instance's control plane")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := newServeCommand()
	cmd.SetArgs([]string{"-i", name})
	if err := cmd.ExecuteContext(ctx); err == nil {
		t.Fatal("a second control plane for a running instance must fail")
	}
	if got, err := readServePID(pidPath); err != nil || got != first.Process.Pid {
		t.Fatalf("pid file after the failed second serve: %d, %v; want the running control plane %d", got, err, first.Process.Pid)
	}
}
