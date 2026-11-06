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
	first := exec.Command(os.Args[0], "-test.run=^TestHelperServeProcess$", "--", "serve", "-i", name)
	first.Env = append(os.Environ(), "QPOT_HELPER_SERVE=1")
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Process.Kill(); _ = first.Wait() }()
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
