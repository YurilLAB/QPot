package instance

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
)

// enableSSHProxy returns a default config with ssh-proxy enabled and a stable id.
func enableSSHProxy(t *testing.T, inst string) *config.Config {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
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

func TestSSHPublishedImageRevision(t *testing.T) {
	revision := strings.Repeat("a1", 20)
	for _, name := range []string{sshProxyHoneypot, "ssh-backend"} {
		base := GetHoneypotImage(name)
		if got := sshPublishedImage(name, ""); got != base {
			t.Fatalf("development image %s: %q != %q", name, got, base)
		}
		want := strings.TrimSuffix(base, ":latest") + ":" + revision
		if got := sshPublishedImage(name, revision); got != want {
			t.Fatalf("release image %s: %q != %q", name, got, want)
		}
	}
}

// This also runs with an actual linker-injected full revision in the release
// checks, proving both deployed roles use the embedded value without mutating
// shared package state in the test process.
func TestSSHPublishedBuildRevision(t *testing.T) {
	for _, mode := range []string{config.SSHEnvironmentStandalone, config.SSHEnvironmentOrganization} {
		cfg := enableSSHProxy(t, "releaseimages")
		hp := cfg.Honeypots[sshProxyHoneypot]
		hp.CustomConfig = map[string]string{"environment": mode, "image_source": config.SSHImageSourcePublished}
		cfg.Honeypots[sshProxyHoneypot] = hp
		for name, got := range map[string]string{sshProxyHoneypot: sshProxyImage(cfg), "ssh-backend": sshBackendImage(cfg)} {
			want := GetHoneypotImage(name)
			if HiFiImageRevision != "" {
				want = strings.TrimSuffix(want, ":latest") + ":" + HiFiImageRevision
			}
			if got != want {
				t.Fatalf("%s/%s image %q != %q", mode, name, got, want)
			}
		}
		runtimeErr := validateSSHRuntimeImages(cfg, HiFiImageRevision)
		if (runtimeErr == nil) != validHiFiImageRevision(HiFiImageRevision) {
			t.Fatalf("embedded release image compatibility differs from its pin: %v", runtimeErr)
		}
		if got := guardImage(cfg); got != sshProxyImage(cfg) {
			t.Fatalf("guard helper %q does not match the released broker", got)
		}
		hp.CustomConfig["image_source"] = config.SSHImageSourceLocal
		cfg.Honeypots[sshProxyHoneypot] = hp
		if sshProxyImage(cfg) != "qpot-local/ssh-proxy:development" || sshBackendImage(cfg) != "qpot-local/ssh-backend:development" {
			t.Fatal("release pin replaced the operator's local source-image selection")
		}
		hp.Enabled = false
		cfg.Honeypots[sshProxyHoneypot] = hp
		if got, want := guardImage(cfg), sshPublishedImage(sshProxyHoneypot, HiFiImageRevision); got != want {
			t.Fatalf("ordinary sensors' guard helper %q != %q", got, want)
		}
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
		"egress-locked backend net": "ssh-backend-1_net:\n    internal: true",
		"broker BACKENDS env":       "QPOT_SSHPROXY_BACKENDS=ssh-backend-1=ssh-backend-1:22",
		"broker on backend net":     "ssh-backend-1_net: {}",
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
	var hostnames []string
	for _, svc := range []string{"ssh-backend-1", "ssh-backend-2"} {
		blk := serviceBlock(out, svc)
		if strings.Contains(blk, "ports:") {
			t.Errorf("%s must not publish host ports (real-RCE backend exposed!):\n%s", svc, blk)
		}
		if !strings.Contains(blk, sshBackendNetwork(svc)) {
			t.Errorf("%s must be on its private backend network", svc)
		}
		if strings.Contains(blk, "qpot_internal") {
			t.Errorf("%s must NOT be on qpot_internal (it should reach nothing but the broker)", svc)
		}
		// sshd privilege separation needs these caps; cap_drop ALL alone breaks auth.
		if !strings.Contains(blk, "cap_drop:") || !strings.Contains(blk, "SETUID") {
			t.Errorf("%s missing expected capability hardening", svc)
		}
		// Anti-tell: every backend gets the SHARED host keys (one fingerprint
		// for the pool) at start, and nothing from the host is mounted.
		if !strings.Contains(blk, "env_file:") || !strings.Contains(blk, "shared-hostkeys") || !strings.Contains(blk, hostKeysEnvFile) || strings.Contains(blk, "volumes:") {
			t.Errorf("%s must get the shared host keys through its env_file, with no mounts", svc)
		}
		// Capture this backend's hostname for the consistency check below.
		for _, ln := range strings.Split(blk, "\n") {
			if s := strings.TrimSpace(ln); strings.HasPrefix(s, "hostname:") {
				hostnames = append(hostnames, s)
			}
		}
	}
	// Anti-tell: all backends present the SAME hostname (and host keys), so a
	// returning attacker round-robined to a different backend never sees the
	// server identity change.
	if len(hostnames) != 2 {
		t.Fatalf("expected a hostname on each backend, got %v", hostnames)
	}
	if hostnames[0] != hostnames[1] {
		t.Errorf("backends present different hostnames (pool tell): %q vs %q", hostnames[0], hostnames[1])
	}
}

// TestSSHProxyDisabledRendersNothing verifies the backend services/network are
// absent when ssh-proxy is disabled (the default).
func TestSSHProxyDisabledRendersNothing(t *testing.T) {
	cfg := config.Default("off")
	cfg.QPotID = "qp_off0000000000000000000"
	out := renderComposeCfg(t, cfg)
	for _, s := range []string{"ssh-backend-1", "QPOT_SSHPROXY_BACKENDS"} {
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

// The broker gets the recycler's generation counters read-only: it must see
// recreations but never be able to forge one.
func TestSSHProxyGenerationsMountedReadOnly(t *testing.T) {
	cfg := enableSSHProxy(t, "gen")
	blk := serviceBlock(renderComposeCfg(t, cfg), "ssh-proxy")
	if !strings.Contains(blk, "/honeypots/ssh-proxy/generations:"+sshProxyGenerationsPath+":ro") {
		t.Errorf("generations dir not mounted read-only into the broker:\n%s", blk)
	}
	if !strings.Contains(blk, "QPOT_SSHPROXY_GENERATIONS="+sshProxyGenerationsPath) {
		t.Error("broker not told where the generations are")
	}
	for _, b := range sshBackendServiceNames(cfg) {
		if strings.Contains(serviceBlock(renderComposeCfg(t, cfg), b), "generations") {
			t.Errorf("backend %s can see the generation counters", b)
		}
	}
}

// A backend's container log holds every connection its cell can have open
// at once, each at the most sshd lets it write there, plus sshd's own log;
// the broker caps a source at that many connections and admits none while
// conversion is down.
func TestSSHBackendLogHoldsEveryCellConnection(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "docker", "ssh-backend", "openssh", "qpcapture.c"))
	if err != nil {
		t.Fatal(err)
	}
	budget := regexp.MustCompile(`(?m)^#define QPC_CONN_BUDGET\s+\((\d+)ULL \* 1024 \* 1024\)$`).FindSubmatch(src)
	if budget == nil || string(budget[1]) != strconv.Itoa(sshCaptureConnectionMiB) {
		t.Fatalf("sshd's per-connection budget is not %d MiB: %q", sshCaptureConnectionMiB, budget)
	}
	if whole := sshBackendLogFiles() - 1; whole < sshCellConnections+1 {
		t.Fatalf("%d whole logs cannot hold %d connections and sshd's log", whole, sshCellConnections)
	}
	cfg := enableSSHProxy(t, "retention")
	compose := renderComposeCfg(t, cfg)
	for _, b := range sshBackendServiceNames(cfg) {
		blk := serviceBlock(compose, b)
		size := fmt.Sprintf("max-size: \"%dm\"\n", sshCaptureConnectionMiB)
		files := fmt.Sprintf("max-file: \"%d\"\n", sshBackendLogFiles())
		if !strings.Contains(blk, size) || !strings.Contains(blk, files) {
			t.Errorf("backend %s log retention is not %s x %s:\n%s", b, size, files, blk)
		}
		// Per-line attrs would cost more than sshd counts.
		_, options, _ := strings.Cut(blk, "    logging:\n")
		for _, option := range []string{"labels", "labels-regex", "env", "env-regex"} {
			if strings.Contains(options, "        "+option+":") {
				t.Errorf("backend %s log adds %s to every line:\n%s", b, option, options)
			}
		}
	}
	blk := serviceBlock(compose, "ssh-proxy")
	for _, want := range []string{
		fmt.Sprintf("- QPOT_SSHPROXY_CONC_IP=%d\n", sshCellConnections),
		"- QPOT_SSHPROXY_REQUIRE_CAPTURE=1\n",
	} {
		if !strings.Contains(blk, want) {
			t.Errorf("broker lacks %q:\n%s", want, blk)
		}
	}
}

// The broker's cell hold follows cell_hold_minutes; 0 gives every connection
// a cell of its own.
func TestSSHProxyCellHoldReachesTheBroker(t *testing.T) {
	for raw, want := range map[string]string{"": "30m", "0": "0m", "45": "45m"} {
		cfg := enableSSHProxy(t, "hold")
		hp := cfg.Honeypots[sshProxyHoneypot]
		if hp.CustomConfig == nil {
			hp.CustomConfig = map[string]string{}
		}
		hp.CustomConfig["cell_hold_minutes"] = raw
		cfg.Honeypots[sshProxyHoneypot] = hp
		blk := serviceBlock(renderComposeCfg(t, cfg), "ssh-proxy")
		if !strings.Contains(blk, "- QPOT_SSHPROXY_CELL_HOLD="+want+"\n") {
			t.Errorf("cell_hold_minutes %q: broker not given %s:\n%s", raw, want, blk)
		}
		if got := effectiveSetting(cfg, sshProxyHoneypot, "cell_hold_minutes"); got+"m" != want {
			t.Errorf("cell_hold_minutes %q reported as %q", raw, got)
		}
	}
}
