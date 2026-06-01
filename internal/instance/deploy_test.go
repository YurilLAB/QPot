package instance

import (
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
)

func TestDeployProfileCowrie(t *testing.T) {
	d := deployProfileFor("cowrie")
	if !d.NeedsNetBind() {
		t.Error("cowrie binds 22/23 internally and must need NET_BIND_SERVICE")
	}
	// Must have an etc volume (host keys + cowrie.cfg) and a logs volume.
	var hasEtc, hasLogs bool
	for _, v := range d.Volumes {
		if v.ContainerPath == "/home/cowrie/cowrie/etc" {
			hasEtc = true
		}
		if v.HostSubdir == "logs" {
			hasLogs = true
		}
	}
	if !hasEtc || !hasLogs {
		t.Errorf("cowrie profile missing etc/logs volumes: %+v", d.Volumes)
	}
	if len(d.Tmpfs) == 0 {
		t.Error("cowrie needs tmpfs /tmp/cowrie")
	}
	if d.ConfigSubdir != "etc" {
		t.Errorf("cowrie config must land in etc, got %q", d.ConfigSubdir)
	}
}

func TestDeployProfileEndlessh(t *testing.T) {
	d := deployProfileFor("endlessh")
	if d.NeedsNetBind() {
		t.Error("endlessh listens on 2222 (non-privileged) and should not need NET_BIND_SERVICE")
	}
	if len(d.Volumes) != 1 || d.Volumes[0].ContainerPath != "/var/log/endlessh" {
		t.Errorf("endlessh must mount logs at /var/log/endlessh, got %+v", d.Volumes)
	}
}

// TestComposeNoInvalidKeys guards the compose-breaking bugs found by running
// docker compose: pid:"private" (invalid PID mode) and device_read_bps /
// device_write_bps (not valid compose service keys).
func TestComposeNoInvalidKeys(t *testing.T) {
	cfg := config.Default("compose-valid")
	cfg.QPotID = "qp_composevalidcomposeval1"
	sb, _ := security.NewSandbox(&cfg.Security)
	g := &ComposeGenerator{Config: cfg, Sandbox: sb}
	out, err := g.Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`pid: "private"`, "device_read_bps", "device_write_bps", `user: "1000:1000"`} {
		if strings.Contains(out, bad) {
			t.Errorf("generated compose contains invalid/removed key %q", bad)
		}
	}
}

// TestComposeCowrieRuntime checks the cowrie service renders the verified
// runtime requirements: ports 22+23, the etc/logs/dl mounts, tmpfs /tmp/cowrie,
// and NET_BIND_SERVICE.
func TestComposeCowrieRuntime(t *testing.T) {
	cfg := config.Default("cowrie-runtime")
	cfg.QPotID = "qp_cowrieruntimecowrierun1"
	sb, _ := security.NewSandbox(&cfg.Security)
	g := &ComposeGenerator{Config: cfg, Sandbox: sb}
	out, err := g.Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`:22"`, `:23"`,
		"/home/cowrie/cowrie/etc",
		"/home/cowrie/cowrie/log",
		"/tmp/cowrie:uid=2000,gid=2000",
		"NET_BIND_SERVICE",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("cowrie service missing expected %q", want)
		}
	}
}
