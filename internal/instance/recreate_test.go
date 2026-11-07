package instance

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// argsDocker installs a stand-in docker that records each call's arguments,
// one line per call, and succeeds. It returns the log's path.
func argsDocker(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(bin, "calls.log")
	script := "#!/bin/sh\necho \"$*\" >> " + log + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil { // #nosec G306 -- test stand-in must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

// composeUps returns the `compose ... up` calls in a stand-in docker's log.
func composeUps(t *testing.T, log string) []string {
	t.Helper()
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	var ups []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.Contains(line, " up -d") {
			ups = append(ups, line)
		}
	}
	return ups
}

// TestRecreateHoneypotForcesANewContainer: a settings change must reach the
// honeypot even when the compose service is unchanged. Cowrie's bait setting
// changes only a file Cowrie reads at start, and `compose up -d cowrie` kept
// the running container, which went on serving the bait files whose canaries
// had just been deleted. Starting a honeypot still leaves a running one alone.
func TestRecreateHoneypotForcesANewContainer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in docker is a shell script")
	}
	cfg := settingsTestConfig(t, "recreate")
	cfg.Security.SandboxMode = "none"
	enableOnly(cfg, "cowrie", "tanner")
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	log := argsDocker(t)
	if err := m.RecreateHoneypot(ctx, "cowrie"); err != nil {
		t.Fatal(err)
	}
	ups := composeUps(t, log)
	if len(ups) != 1 || !strings.HasSuffix(ups[0], " up -d --force-recreate --no-deps cowrie") {
		t.Fatalf("recreate ran %q, want one `up -d --force-recreate --no-deps cowrie`", ups)
	}

	// A honeypot with companions recreates them with it, by name.
	log = argsDocker(t)
	if err := m.RecreateHoneypot(ctx, "tanner"); err != nil {
		t.Fatal(err)
	}
	ups = composeUps(t, log)
	if len(ups) != 1 || !strings.Contains(ups[0], " up -d --force-recreate --no-deps tanner ") ||
		!strings.Contains(ups[0], "snare") {
		t.Fatalf("recreate of tanner ran %q, want its companions recreated with it", ups)
	}

	// Starting is unchanged: compose keeps a container whose service is the same.
	log = argsDocker(t)
	if err := m.StartHoneypot(ctx, "cowrie"); err != nil {
		t.Fatal(err)
	}
	ups = composeUps(t, log)
	if len(ups) != 1 || strings.Contains(ups[0], "--force-recreate") || !strings.HasSuffix(ups[0], " up -d cowrie") {
		t.Fatalf("start ran %q, want a plain `up -d cowrie`", ups)
	}
}
