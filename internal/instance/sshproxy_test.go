package instance

import (
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
)

// enableSSHProxy returns a default config with ssh-proxy enabled and a stable id.
func enableSSHProxy(t *testing.T, inst string) *config.Config {
	t.Helper()
	cfg := config.Default(inst)
	cfg.QPotID = "qp_" + inst + "000000000000000000"
	hp := cfg.Honeypots[sshProxyHoneypot]
	hp.Enabled = true
	cfg.Honeypots[sshProxyHoneypot] = hp
	return cfg
}

func renderComposeCfg(t *testing.T, cfg *config.Config) string {
	t.Helper()
	sb, err := security.NewSandbox(&cfg.Security)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}
	g := &ComposeGenerator{Config: cfg, Sandbox: sb}
	out, err := g.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return out
}

// TestSSHProxyHelpers covers the pure wiring helpers.
func TestSSHProxyHelpers(t *testing.T) {
	cfg := enableSSHProxy(t, "h")
	if !sshProxyEnabled(cfg) {
		t.Fatal("sshProxyEnabled should be true")
	}
	if n := sshBackendCount(cfg); n != 2 {
		t.Errorf("default backend count = %d, want 2", n)
	}
	names := sshBackendServiceNames(cfg)
	if len(names) != 2 || names[0] != "ssh-backend-1" || names[1] != "ssh-backend-2" {
		t.Errorf("backend names = %v", names)
	}
	csv := sshBackendCSV(cfg)
	if csv != "ssh-backend-1=ssh-backend-1:22,ssh-backend-2=ssh-backend-2:22" {
		t.Errorf("backend CSV = %q", csv)
	}
	// The broker must be able to parse its own generated BACKENDS string.
	// (Re-parse here to guard the two formats never drift.)
	if !strings.Contains(csv, "ssh-backend-1:22") {
		t.Error("CSV missing host:port form")
	}
}

func TestSSHBackendCountClamping(t *testing.T) {
	cfg := enableSSHProxy(t, "clamp")
	hp := cfg.Honeypots[sshProxyHoneypot]
	hp.CustomConfig = map[string]string{"backends": "999"}
	cfg.Honeypots[sshProxyHoneypot] = hp
	if n := sshBackendCount(cfg); n != maxSSHBackends {
		t.Errorf("count=%d, want clamp to %d", n, maxSSHBackends)
	}
	hp.CustomConfig["backends"] = "0"
	cfg.Honeypots[sshProxyHoneypot] = hp
	if n := sshBackendCount(cfg); n != 1 {
		t.Errorf("count=%d, want clamp to 1", n)
	}
	hp.CustomConfig["backends"] = "garbage"
	cfg.Honeypots[sshProxyHoneypot] = hp
	if n := sshBackendCount(cfg); n != defaultSSHBackends {
		t.Errorf("count=%d on garbage, want default %d", n, defaultSSHBackends)
	}
}

func TestSSHBackendUsersCSVSafe(t *testing.T) {
	cfg := enableSSHProxy(t, "users")
	csv := sshBackendUsersCSV(cfg)
	if csv == "" {
		t.Fatal("users CSV must never be empty")
	}
	// Every pair must be user:pass with no delimiter corruption.
	for _, pair := range strings.Split(csv, ",") {
		parts := strings.Split(pair, ":")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			t.Errorf("malformed user pair %q in %q", pair, csv)
		}
	}
}

func TestSSHSafeToken(t *testing.T) {
	good := []string{"admin", "root", "Ubuntu1", "p@ssw0rd!", "a"}
	bad := []string{"", "a,b", "a:b", "a=b", "a b", "a\nb", "a\x00b", strings.Repeat("x", 65)}
	for _, g := range good {
		if !sshSafeToken(g) {
			t.Errorf("sshSafeToken(%q) = false, want true", g)
		}
	}
	for _, b := range bad {
		if sshSafeToken(b) {
			t.Errorf("sshSafeToken(%q) = true, want false", b)
		}
	}
}

// TestSSHProxyComposeRender is the integration guard: enabling ssh-proxy renders
// a broker that publishes the SSH port plus real-OpenSSH backends that DON'T,
// all on an egress-locked internal network. These are the security-critical
// invariants of HiFi mode.
func TestSSHProxyComposeRender(t *testing.T) {
	cfg := enableSSHProxy(t, "render")
	out := renderComposeCfg(t, cfg)

	mustContain := map[string]string{
		"broker service":            "\n  ssh-proxy:\n",
		"backend-1 service":         "\n  ssh-backend-1:\n",
		"backend-2 service":         "\n  ssh-backend-2:\n",
		"egress-locked backend net": "ssh-proxy_backend:\n    internal: true",
		"broker BACKENDS env":       "QPOT_SSHPROXY_BACKENDS=ssh-backend-1=ssh-backend-1:22",
		"broker on backend net":     "- ssh-proxy_backend",
		"backend image":             "qpot-ssh-backend",
		"broker image":              "qpot-ssh-proxy",
		"backend users env":         "BACKEND_USERS=",
	}
	for desc, want := range mustContain {
		if !strings.Contains(out, want) {
			t.Errorf("compose missing %s (%q)", desc, want)
		}
	}

	// The broker (distroless, no shell) must NOT get the shell healthcheck.
	brokerBlock := serviceBlock(out, "ssh-proxy")
	if strings.Contains(brokerBlock, "healthcheck:") {
		t.Error("ssh-proxy broker must not have a shell healthcheck (distroless image)")
	}

	// CRITICAL: backends must NOT publish any host port (only the broker faces
	// the internet). A `ports:` key on a backend would expose real RCE directly.
	for _, svc := range []string{"ssh-backend-1", "ssh-backend-2"} {
		blk := serviceBlock(out, svc)
		if strings.Contains(blk, "ports:") {
			t.Errorf("%s must not publish host ports (real-RCE backend exposed!):\n%s", svc, blk)
		}
		if !strings.Contains(blk, "ssh-proxy_backend") {
			t.Errorf("%s must be on the egress-locked ssh-proxy_backend network", svc)
		}
		if strings.Contains(blk, "qpot_internal") {
			t.Errorf("%s must NOT be on qpot_internal (it should reach nothing but the broker)", svc)
		}
		// sshd privilege separation needs these caps; cap_drop ALL alone breaks auth.
		if !strings.Contains(blk, "cap_drop:") || !strings.Contains(blk, "- SETUID") {
			t.Errorf("%s missing expected capability hardening", svc)
		}
	}
}

// TestSSHProxyDisabledRendersNothing verifies the backend services/network are
// absent when ssh-proxy is disabled (the default).
func TestSSHProxyDisabledRendersNothing(t *testing.T) {
	cfg := config.Default("off")
	cfg.QPotID = "qp_off0000000000000000000"
	out := renderComposeCfg(t, cfg)
	for _, s := range []string{"ssh-backend-1", "ssh-proxy_backend", "QPOT_SSHPROXY_BACKENDS"} {
		if strings.Contains(out, s) {
			t.Errorf("disabled ssh-proxy still rendered %q", s)
		}
	}
}

// TestSSHProxyBackendCountRendersN verifies custom_config["backends"] controls
// how many backend services are emitted.
func TestSSHProxyBackendCountRendersN(t *testing.T) {
	cfg := enableSSHProxy(t, "count")
	hp := cfg.Honeypots[sshProxyHoneypot]
	hp.CustomConfig = map[string]string{"backends": "4"}
	cfg.Honeypots[sshProxyHoneypot] = hp
	out := renderComposeCfg(t, cfg)
	for i := 1; i <= 4; i++ {
		name := "ssh-backend-" + string(rune('0'+i))
		if !strings.Contains(out, "\n  "+name+":\n") {
			t.Errorf("expected backend service %s", name)
		}
	}
	if strings.Contains(out, "\n  ssh-backend-5:\n") {
		t.Error("rendered more backends than configured")
	}
	// And the broker's BACKENDS env should list all four.
	if !strings.Contains(out, "ssh-backend-4=ssh-backend-4:22") {
		t.Error("broker BACKENDS env should include the 4th backend")
	}
}

// serviceBlock returns the YAML text of one service (from its "  <name>:" header
// to the next top-level "  <other>:" header), for targeted assertions.
func serviceBlock(compose, name string) string {
	start := strings.Index(compose, "\n  "+name+":\n")
	if start < 0 {
		return ""
	}
	rest := compose[start+1:]
	// Find the next service header at the same indentation (two spaces, not more).
	lines := strings.Split(rest, "\n")
	var b strings.Builder
	for i, ln := range lines {
		if i > 0 && len(ln) > 2 && ln[0] == ' ' && ln[1] == ' ' && ln[2] != ' ' && strings.HasSuffix(strings.TrimRight(ln, " "), ":") {
			break
		}
		b.WriteString(ln)
		b.WriteString("\n")
	}
	return b.String()
}
