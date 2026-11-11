package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

// partialDocker installs a stand-in docker whose compose project has the
// collector running and the database, both honeypots and the egress guard
// exited (what an unclean stop left behind: only the collector came back),
// until `compose up -d` runs; with allUp everything runs from the start. It
// returns the file each docker call is logged to.
func partialDocker(t *testing.T, allUp bool) string {
	t.Helper()
	bin := t.TempDir()
	calls := filepath.Join(bin, "calls.log")
	upDone := filepath.Join(bin, "up.done")
	if allUp {
		if err := os.WriteFile(upDone, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Builtins only: PATH holds nothing but this stand-in.
	script := fmt.Sprintf(`#!/bin/sh
echo "$*" >> %[1]s
case "$*" in
  info*CgroupDriver*) echo '{"CgroupDriver":"systemd","MemoryLimit":true,"SwapLimit":true,"PidsLimit":true,"CPUCfsQuota":true}' ;;
  *" ps -q"*) echo 0123456789ab ;;
  *" ps --all --format json"*|*" ps -a --format json"*)
    if [ -f %[2]s ]; then
      for s in collector database cowrie endlessh netguard; do echo "{\"Service\":\"$s\",\"State\":\"running\",\"Health\":\"healthy\"}"; done
    else
      echo '{"Service":"collector","State":"running"}'
      for s in database cowrie endlessh netguard; do echo "{\"Service\":\"$s\",\"State\":\"exited\",\"ExitCode\":255}"; done
    fi ;;
  *" up -d"*) : > %[2]s ;;
esac
exit 0
`, calls, upDone)
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil { // #nosec G306 -- test stand-in must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	return calls
}

// partialInstance saves an instance running cowrie and endlessh.
func partialInstance(t *testing.T, name string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	cfg := config.Default(name)
	cfg.Security.SandboxMode = "none"
	cfg.Intelligence.FetchATTCK = false
	for hp, h := range cfg.Honeypots {
		h.Enabled = hp == "cowrie" || hp == "endlessh"
		cfg.Honeypots[hp] = h
	}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
}

// runUp runs `qpot up -d -i name` with the background control plane stood in,
// and returns its output and how often the control plane was started.
func runUp(t *testing.T, name string) (string, int) {
	t.Helper()
	serves := 0
	orig := backgroundServe
	backgroundServe = func(*config.Config) (int, string, error) { serves++; return 4242, "", nil }
	defer func() { backgroundServe = orig }()
	out := captureStdout(t, func() {
		cmd := newUpCommand()
		cmd.SetArgs([]string{"-d", "-i", name})
		if err := cmd.Execute(); err != nil {
			t.Errorf("qpot up: %v", err)
		}
	})
	return out, serves
}

// TestUpStartsStoppedServices: `qpot up` asked docker only whether ANY
// container ran, so after an unclean stop that brought back the collector
// alone it said "Containers are already running; attaching the control plane"
// and never ran compose up: the database, the honeypots and the egress guard
// stayed down. Now compose up -d runs whenever a service the instance should
// run is not running.
func TestUpStartsStoppedServices(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in docker is a shell script")
	}
	partialInstance(t, "partial-up")
	calls := partialDocker(t, false)
	out, serves := runUp(t, "partial-up")

	data, _ := os.ReadFile(calls)
	if !strings.Contains(string(data), " up -d\n") {
		t.Fatalf("compose up -d never ran with only the collector running; output:\n%s\ndocker calls:\n%s", out, data)
	}
	if strings.Contains(out, "already running") {
		t.Errorf("reported as already running:\n%s", out)
	}
	for _, svc := range []string{"cowrie", "database", "endlessh", "netguard"} {
		if !strings.Contains(out, svc) {
			t.Errorf("the output does not name the stopped %s:\n%s", svc, out)
		}
	}
	if serves != 1 {
		t.Errorf("control plane started %d times, want 1", serves)
	}
}

// TestUpAttachesToARunningStack: with every service running, up starts no
// container and only attaches the control plane.
func TestUpAttachesToARunningStack(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in docker is a shell script")
	}
	partialInstance(t, "full-up")
	calls := partialDocker(t, true)
	out, serves := runUp(t, "full-up")

	data, _ := os.ReadFile(calls)
	if strings.Contains(string(data), " up -d\n") || strings.Contains(string(data), " pull\n") {
		t.Errorf("containers started on a running stack; docker calls:\n%s", data)
	}
	if !strings.Contains(out, "Containers are already running; attaching the control plane") {
		t.Errorf("output:\n%s", out)
	}
	if serves != 1 {
		t.Errorf("control plane started %d times, want 1", serves)
	}
}
