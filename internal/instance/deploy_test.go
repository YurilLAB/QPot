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

func TestBridgeNameWithinLinuxLimit(t *testing.T) {
	// Linux interface names are capped at 15 chars; br-<honeypot> overflows for
	// names >12 chars and docker rejects the network.
	for _, hp := range []string{"cowrie", "endlessh", "redishoneypot", "citrixhoneypot", "redishoneypot"} {
		bn := bridgeName(hp)
		if len(bn) > 15 {
			t.Errorf("bridgeName(%q)=%q is %d chars (>15)", hp, bn, len(bn))
		}
	}
	// Long names must still be unique to each other.
	if bridgeName("redishoneypot") == bridgeName("citrixhoneypot") {
		t.Error("bridge names collide for distinct honeypots")
	}
	// Short names keep the readable form.
	if bridgeName("cowrie") != "br-cowrie" {
		t.Errorf("short bridge name changed: %q", bridgeName("cowrie"))
	}
}

func TestDeployProfilesRedisAdbhoney(t *testing.T) {
	r := deployProfileFor("redishoneypot")
	if len(r.Ports) != 1 || r.Ports[0] != 6379 {
		t.Errorf("redishoneypot ports = %v, want [6379]", r.Ports)
	}
	a := deployProfileFor("adbhoney")
	if len(a.Ports) != 1 || a.Ports[0] != 5555 {
		t.Errorf("adbhoney ports = %v, want [5555]", a.Ports)
	}
	for _, p := range []honeypotDeploy{r, a} {
		if len(p.Volumes) == 0 || p.Volumes[0].HostSubdir != "logs" {
			t.Errorf("profile missing logs volume: %+v", p.Volumes)
		}
	}
}


func TestAllHoneypotsHaveProfiles(t *testing.T) {
	// Every honeypot QPot ships an image for must have a non-generic deploy
	// profile (a logs volume) so it actually runs.
	for _, hp := range []string{
		"cowrie", "endlessh", "redishoneypot", "adbhoney", "dionaea", "conpot",
		"heralding", "mailoney", "ddospot", "ciscoasa", "citrixhoneypot",
		"elasticpot", "ipphoney", "medpot", "dicompot", "honeyaml",
	} {
		d := deployProfileFor(hp)
		if len(d.Ports) == 0 && len(d.UDPPorts) == 0 {
			t.Errorf("%s: profile exposes no ports", hp)
		}
		var hasLogs bool
		for _, v := range d.Volumes {
			if v.HostSubdir == "logs" {
				hasLogs = true
			}
		}
		if !hasLogs {
			t.Errorf("%s: profile has no logs volume (collector can't read it)", hp)
		}
	}
}

func TestConpotHasRequiredEnv(t *testing.T) {
	d := deployProfileFor("conpot")
	for _, k := range []string{"CONPOT_TEMPLATE", "CONPOT_CONFIG", "CONPOT_TMP", "CONPOT_LOG"} {
		if d.Env[k] == "" {
			t.Errorf("conpot profile missing required env %q", k)
		}
	}
}

func TestDionaeaUDPAndNetBind(t *testing.T) {
	d := deployProfileFor("dionaea")
	if len(d.UDPPorts) == 0 {
		t.Error("dionaea should expose UDP ports")
	}
	if !d.NeedsNetBind() {
		t.Error("dionaea binds privileged ports (21, 443) and needs NET_BIND_SERVICE")
	}
}

// allSupportedHoneypots is every honeypot QPot ships an image for.
var allSupportedHoneypots = []string{
	"cowrie", "dionaea", "conpot", "tanner", "adbhoney", "endlessh",
	"heralding", "honeyaml", "elasticpot", "ciscoasa", "citrixhoneypot",
	"ddospot", "ipphoney", "mailoney", "medpot", "redishoneypot",
	"beelzebub", "galah", "go-pot", "h0neytr4p", "hellpot", "log4pot",
	"miniprint", "sentrypeer", "wordpot",
}

// TestEverySupportedHoneypotIsFullyWired guards that every shipped honeypot has
// an image, passes ValidateHoneypot, has a deploy profile with at least one
// port + a logs volume, and is present in config.Default so it can be enabled.
func TestEverySupportedHoneypotIsFullyWired(t *testing.T) {
	cfg := config.Default("wired")
	g := &ComposeGenerator{Config: cfg}
	for _, n := range allSupportedHoneypots {
		if GetHoneypotImage(n) == "" {
			t.Errorf("%s: no image", n)
		}
		if err := g.ValidateHoneypot(n); err != nil {
			t.Errorf("%s: ValidateHoneypot: %v", n, err)
		}
		d := deployProfileFor(n)
		if len(d.Ports) == 0 && len(d.UDPPorts) == 0 {
			t.Errorf("%s: deploy profile exposes no ports", n)
		}
		var hasLogs bool
		for _, v := range d.Volumes {
			if v.HostSubdir == "logs" {
				hasLogs = true
			}
		}
		if !hasLogs {
			t.Errorf("%s: no logs volume", n)
		}
		if _, ok := cfg.Honeypots[n]; !ok {
			t.Errorf("%s: missing from config.Default (cannot be enabled)", n)
		}
	}
}
