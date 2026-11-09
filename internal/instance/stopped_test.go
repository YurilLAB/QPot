package instance

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// psDocker installs a stand-in docker whose `compose ps --all --format json`
// prints rows (JSON lines), or fails when rows is "fail".
func psDocker(t *testing.T, rows string) {
	t.Helper()
	bin := t.TempDir()
	out := filepath.Join(bin, "ps.json")
	if err := os.WriteFile(out, []byte(rows), 0o600); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/sh\ncase \"$*\" in *\" ps --all --format json\"*) [ \"$(cat %[1]s)\" = fail ] && exit 1; cat %[1]s ;; esac\nexit 0\n", out)
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil { // #nosec G306 -- test stand-in must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func psRows(state string, services ...string) string {
	var b strings.Builder
	for _, s := range services {
		fmt.Fprintf(&b, "{\"Service\":%q,\"State\":%q}\n", s, state)
	}
	return b.String()
}

// TestStoppedServices: every service the instance should run counts - the
// database, the collector, the egress guard, each enabled honeypot and its
// companions (tanner's stack, the HiFi backends) - whether it exited, was
// only created or was never created; a disabled honeypot does not.
func TestStoppedServices(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in docker is a shell script")
	}
	cfg := settingsTestConfig(t, "stopped")
	cfg.Security.SandboxMode = "none"
	enableOnly(cfg, "cowrie", "tanner", "ssh-proxy")
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	all := []string{"collector", "cowrie", "database", "netguard", "snare", "ssh-backend-1", "ssh-backend-2",
		"ssh-proxy", "tanner", "tanner_api", "tanner_phpox", "tanner_redis"}

	check := func(rows string, want []string) {
		t.Helper()
		psDocker(t, rows)
		got, err := m.StoppedServices(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, want) {
			t.Errorf("stopped %v, want %v", got, want)
		}
		if m.AllRunning(ctx) != (len(want) == 0) {
			t.Errorf("AllRunning %v with %v stopped", m.AllRunning(ctx), want)
		}
	}

	// Everything up, plus a disabled honeypot's leftover container.
	check(psRows("running", append(all, "dionaea")...), nil)
	// Each expected service on its own: exited, only created, never created.
	for _, svc := range all {
		var rest []string
		for _, s := range all {
			if s != svc {
				rest = append(rest, s)
			}
		}
		check(psRows("running", rest...)+psRows("exited", svc), []string{svc})
		check(psRows("running", rest...)+psRows("created", svc), []string{svc})
		check(psRows("running", rest...), []string{svc})
	}
	// What an unclean stop left: the collector alone.
	check(psRows("running", "collector")+psRows("exited", "database", "cowrie", "netguard"),
		[]string{"cowrie", "database", "netguard", "snare", "ssh-backend-1", "ssh-backend-2", "ssh-proxy",
			"tanner", "tanner_api", "tanner_phpox", "tanner_redis"})

	// No database container for Elasticsearch. HiFi's cell guard remains
	// mandatory even when the ordinary honeypot egress override is permissive.
	cfg.Database.Type = "elasticsearch"
	cfg.Security.NetworkIsolation.AllowPrivateEgress = true
	cfg.Security.NetworkIsolation.BlockOutbound = false
	check(psRows("running", "collector", "cowrie", "netguard", "snare", "ssh-backend-1", "ssh-backend-2", "ssh-proxy",
		"tanner", "tanner_api", "tanner_phpox", "tanner_redis"), nil)
	// With HiFi disabled, the ordinary override can omit the egress guard.
	hp := cfg.Honeypots[sshProxyHoneypot]
	hp.Enabled = false
	cfg.Honeypots[sshProxyHoneypot] = hp
	check(psRows("running", "collector", "cowrie", "snare", "tanner", "tanner_api", "tanner_phpox", "tanner_redis"), nil)

	// docker cannot be asked: not all running, and the error is returned.
	psDocker(t, "fail")
	if _, err := m.StoppedServices(ctx); err == nil {
		t.Error("no error when docker compose ps fails")
	}
	if m.AllRunning(ctx) {
		t.Error("AllRunning when docker compose ps fails")
	}
}
