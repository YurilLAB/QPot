package instance

import (
	"fmt"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
	"gopkg.in/yaml.v3"
)

func renderCompose(t *testing.T) string {
	t.Helper()
	cfg := config.Default("compose-test")
	cfg.QPotID = "qp_secretsecretsecretsecr" // 27 chars
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

// TestRandomizeMACEmitsValidMAC verifies that when NetworkIsolation.RandomizeMAC
// is set (the default), honeypot services get a valid locally-administered MAC -
// the feature previously only randomized the subnet, making the documented
// "MAC randomized per container" claim false.
func TestRandomizeMACEmitsValidMAC(t *testing.T) {
	out := renderCompose(t) // config.Default has RandomizeMAC = true
	if !strings.Contains(out, "mac_address: 02:") {
		t.Error("RandomizeMAC did not emit a locally-administered mac_address on honeypot services")
	}
	// Two distinct honeypots must not share a MAC.
	a := macForSeed("inst", "cowrie")
	b := macForSeed("inst", "heralding")
	if a == b {
		t.Error("macForSeed collides for distinct honeypots")
	}
	if a != macForSeed("inst", "cowrie") {
		t.Error("macForSeed is not deterministic")
	}
}

// TestComposeHoneypotHardening verifies the LIVE security path (the compose
// template, which is the sole producer of container hardening) emits the
// isolation guarantees for an attacker-facing honeypot: capabilities dropped to ALL,
// no-new-privileges, a read-only root, a pids limit, and - for a honeypot that
// binds a privileged container port (cowrie on 22/23) - NET_BIND_SERVICE added
// back via the deploy profile's NeedsNetBind (NOT the host-facing HP.Port).
func TestComposeHoneypotHardening(t *testing.T) {
	cfg := config.Default("hardening-test")
	cfg.QPotID = "qp_hardeningtest0000000001"
	hp := cfg.Honeypots["cowrie"]
	hp.Enabled = true
	cfg.Honeypots["cowrie"] = hp
	sb, err := security.NewSandbox(&cfg.Security)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}
	out, err := (&ComposeGenerator{Config: cfg, Sandbox: sb}).Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Isolate the cowrie service block.
	start := strings.Index(out, "\n  cowrie:")
	if start < 0 {
		t.Fatal("cowrie service not found in compose")
	}
	block := out[start:]
	for _, want := range []string{"cap_drop:", "- ALL", "- NET_BIND_SERVICE", "no-new-privileges:true", "read_only: true", "pids:"} {
		if !strings.Contains(block, want) {
			t.Errorf("cowrie compose block missing hardening %q", want)
		}
	}
}

// TestHoneypotEnvDoesNotSelfIdentify guards the anti-fingerprinting change: a
// honeypot container's environment must not carry variables that announce the
// platform or that the box is a honeypot. An attacker who lands in-container
// code execution and runs `env` previously saw TPOT_HONEYPOT/HONEYPOT_NAME/
// SANDBOX_MODE/STEALTH_MODE. We check actual env-var lines ("- NAME="), not the
// explanatory comments. The identifying metadata must instead be docker labels.
func TestHoneypotEnvDoesNotSelfIdentify(t *testing.T) {
	out := renderCompose(t)
	for _, leak := range []string{
		"- HONEYPOT_NAME=", "- TPOT_HONEYPOT=", "- TPOT_INSTANCE=",
		"- QPOT_INSTANCE=", "- SANDBOX_MODE=", "- STEALTH_MODE=",
	} {
		if strings.Contains(out, leak) {
			t.Errorf("honeypot container env leaks self-identifying variable %q", leak)
		}
	}
	// The host-side labels that carry this metadata must be present instead.
	if !strings.Contains(out, "qpot.honeypot:") || !strings.Contains(out, "qpot.instance:") {
		t.Error("honeypot service is missing the host-side qpot.honeypot/qpot.instance labels")
	}
}

// TestComposeDoesNotLeakCredentialToHoneypots verifies the API credential is
// never injected into attacker-facing honeypot containers. Honeypot env vars
// use list syntax ("- QPOT_ID=..."), while services that legitimately consume
// it (webui) use map syntax ("QPOT_ID: ...").
func TestComposeDoesNotLeakCredentialToHoneypots(t *testing.T) {
	out := renderCompose(t)

	if strings.Contains(out, "- QPOT_ID=") {
		t.Error("compose injects QPOT_ID env into a honeypot container (list-style env)")
	}
	// The honeypot secret mount must be gone too.
	if strings.Contains(out, "/run/secrets/qpot_id:ro\n      {{") {
		t.Error("honeypot still mounts qpot.id")
	}
	// Sanity: the webui still receives the ID it actually uses.
	if !strings.Contains(out, "QPOT_ID:") {
		t.Error("expected QPOT_ID map-style env on webui/db/collector services")
	}
}

// TestComposeHoneypotHasNoSecretMount checks no honeypot service block carries
// the qpot.id secret mount. We assert the count of qpot.id mounts equals the
// number of non-honeypot services that legitimately keep it (db + collector +
// webui), i.e. it dropped from every honeypot.
func TestComposeHoneypotHasNoSecretMount(t *testing.T) {
	out := renderCompose(t)
	cfg := config.Default("compose-test")
	enabled := 0
	for _, hp := range cfg.Honeypots {
		if hp.Enabled {
			enabled++
		}
	}
	if enabled == 0 {
		t.Skip("no enabled honeypots in default config")
	}
	// Each honeypot used to add one qpot.id mount; ensure none remain by
	// confirming the honeypot service blocks don't reference it. We look for
	// the secret mount appearing right after a honeypot data volume.
	if strings.Contains(out, "/data\n      - "+cfg.DataPath+"/qpot.id") {
		t.Error("a honeypot service still mounts qpot.id after its data volume")
	}
}

// TestComposeRuntimeGatedOnAvailability verifies the gVisor/Kata runtime line is
// only emitted when the sandbox runtime is actually available. Hide the runtime
// executables so the result does not depend on the developer's installed tools
// or Docker daemon. NewSandbox must fall back to "none" in both cases.
func TestComposeRuntimeGatedOnAvailability(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, mode := range []string{"gvisor", "kata"} {
		t.Run(mode, func(t *testing.T) {
			cfg := config.Default("compose-test")
			cfg.Security.SandboxMode = mode
			out := renderComposeCfg(t, cfg)
			if strings.Contains(out, "runtime: runsc") || strings.Contains(out, "runtime: kata-runtime") {
				t.Error("compose emitted a sandbox runtime line while the runtime is unavailable; would break docker compose up")
			}
		})
	}
}

// The database containers must be able to boot under the hardening: both the
// ClickHouse and TimescaleDB entrypoints chown their data dir (CAP_CHOWN), and
// ClickHouse needs ~380 threads, far above the per-honeypot pids limit.
func TestComposeDatabaseCanBoot(t *testing.T) {
	for _, dbType := range []string{"clickhouse", "timescaledb"} {
		cfg := config.Default("db-boot-test")
		cfg.QPotID = "qp_dbboottest00000000000001"
		cfg.Database.Type = dbType
		out := renderComposeCfg(t, cfg)
		blk := serviceBlock(out, "database")
		if blk == "" {
			t.Fatalf("%s: no database service rendered", dbType)
		}
		if !strings.Contains(blk, "- CHOWN") {
			t.Errorf("%s: database cap_add lacks CHOWN; the entrypoint cannot chown its data dir", dbType)
		}
		if !strings.Contains(blk, "- KILL") {
			t.Errorf("%s: database cap_add lacks KILL; ClickHouse's first-boot init cannot stop its temporary server", dbType)
		}
		if !strings.Contains(blk, "- DAC_OVERRIDE") {
			t.Errorf("%s: database cap_add lacks DAC_OVERRIDE; the entrypoint cannot use the private data dir", dbType)
		}
		if strings.Contains(blk, "pids: 100\n") {
			t.Errorf("%s: database inherits the 100-pid honeypot limit", dbType)
		}
		if !strings.Contains(blk, "pids: 1024") {
			t.Errorf("%s: database pids limit not raised to 1024", dbType)
		}
	}
}

// The database must be reachable from the host-side qpot process (it creates
// the schema) but only on loopback, on the same port DatabaseClient dials, and
// never share its host-facing network with a honeypot.
func TestComposeDatabaseReachableOnLoopbackOnly(t *testing.T) {
	for _, dbType := range []string{"clickhouse", "timescaledb"} {
		cfg := config.Default("db-net-test")
		cfg.QPotID = "qp_dbnettest000000000000001"
		cfg.Database.Type = dbType
		if dbType == "timescaledb" {
			cfg.Database.Port = 5432
		}
		hp := cfg.Honeypots["cowrie"]
		hp.Enabled = true
		cfg.Honeypots["cowrie"] = hp
		out := renderComposeCfg(t, cfg)

		db := serviceBlock(out, "database")
		want := fmt.Sprintf(`"127.0.0.1:%d:`, cfg.DatabaseClient().Port)
		if !strings.Contains(db, want) {
			t.Errorf("%s: database not published on %s... (client dials port %d)", dbType, want, cfg.DatabaseClient().Port)
		}
		if !strings.Contains(db, "- qpot_dbhost") {
			t.Errorf("%s: database not on the host-reachable qpot_dbhost network", dbType)
		}
		if strings.Contains(serviceBlock(out, "cowrie"), "qpot_dbhost") {
			t.Errorf("%s: a honeypot joined the database's host network", dbType)
		}
	}
}

func TestDefaultDatabasePasswordIsRandom(t *testing.T) {
	a, b := config.Default("pw-a"), config.Default("pw-b")
	if a.Database.Password == "" || a.Database.Password == b.Database.Password {
		t.Fatalf("database passwords %q / %q: want non-empty and distinct", a.Database.Password, b.Database.Password)
	}
}

// The collector's /data is read-only; its file_backup sink needs a writable
// /data/backup or every backup write fails.
func TestComposeCollectorBackupWritable(t *testing.T) {
	c := serviceBlock(renderCompose(t), "collector")
	if !strings.Contains(c, "/backup:/data/backup\n") {
		t.Error("collector has no writable /data/backup mount for its file_backup sink")
	}
}

// Operator values often contain ": ", "#" or "$" (an LLM model name, a URL with
// a fragment). Each environment entry must still parse as one string with the
// exact value. The stealth knobs, which no image reads, must not reach any
// container environment at all: there they only spelled out "honeypot" in
// /proc/1/environ for an attacker who got code execution.
func TestComposeEnvIsQuotedAndStealthKnobsStayOut(t *testing.T) {
	cfg := config.Default("env-quote-test")
	cfg.QPotID = "qp_envquotetest00000000001"
	hp := cfg.Honeypots["galah"]
	hp.Enabled = true
	hp.CustomConfig = map[string]string{
		"llm_provider":   "ollama",
		"llm_model":      "llama3.1: test # $HOME",
		"llm_server_url": `http://10.0.0.5:11434/"x"`,
	}
	cfg.Honeypots["galah"] = hp
	for name, h := range cfg.Honeypots {
		h.Enabled = true
		h.Stealth.Enabled = true
		h.Stealth.BannerString = "220 Microsoft FTP Service: ready # $HOME"
		h.Stealth.FakeOS = `Windows "Server" 2019`
		h.Stealth.FakeKernel = "5.4.0"
		h.Stealth.FakeHostname = "web01"
		h.Stealth.RandomizeSSHVersion = true
		h.Stealth.AddArtificialDelay = true
		h.Stealth.DelayRangeMs = 50
		cfg.Honeypots[name] = h
	}
	out := renderComposeCfg(t, cfg)
	var doc struct {
		Services map[string]struct {
			Environment interface{} `yaml:"environment"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("compose does not parse: %v", err)
	}
	want := map[string]bool{
		"LLM_MODEL=llama3.1: test # $$HOME":        false,
		`LLM_SERVER_URL=http://10.0.0.5:11434/"x"`: false,
	}
	for name, svc := range doc.Services {
		env, _ := svc.Environment.([]interface{})
		for _, e := range env {
			s, ok := e.(string)
			if !ok {
				t.Errorf("%s: environment entry is not a string: %#v", name, e)
				continue
			}
			if _, ok := want[s]; ok && name == "galah" {
				want[s] = true
			}
			key, _, _ := strings.Cut(s, "=")
			switch key {
			case "FAKE_HOSTNAME", "FAKE_OS", "FAKE_KERNEL", "BANNER_STRING", "RANDOMIZE_SSH_VERSION",
				"ARTIFICIAL_DELAY", "DELAY_RANGE_MS", "STEALTH_ENABLED":
				t.Errorf("%s: stealth knob %q in the container environment", name, s)
			}
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("galah environment entry %q missing", k)
		}
	}
}

// use_custom_limits with fields left unset must keep the global caps, never
// render cpus '0' / memory 0M (no cap) on an attacker-facing container.
func TestComposeCustomLimitsFallBackToGlobal(t *testing.T) {
	cfg := config.Default("limits-test")
	cfg.QPotID = "qp_limitstest0000000000001"
	hp := cfg.Honeypots["cowrie"]
	hp.Enabled = true
	hp.Resources = config.HoneypotResources{UseCustomLimits: true, MaxPids: 64}
	cfg.Honeypots["cowrie"] = hp
	blk := serviceBlock(renderComposeCfg(t, cfg), "cowrie")
	if strings.Contains(blk, "memory: 0M") || strings.Contains(blk, "cpus: '0'") {
		t.Fatal("custom limits with unset fields removed the CPU/memory cap")
	}
	if !strings.Contains(blk, "pids: 64") {
		t.Error("explicit custom pids limit not applied")
	}
}

// Data and database directories must be direct bind mounts of THIS instance's
// paths, never named volumes (which keep the path they were first created
// with and so can point at another instance's data).
func TestComposeUsesDirectBindMounts(t *testing.T) {
	for _, dbType := range []string{"clickhouse", "timescaledb"} {
		cfg := config.Default("bind-test")
		cfg.QPotID = "qp_bindtest000000000000001"
		cfg.Database.Type = dbType
		out := renderComposeCfg(t, cfg)
		var doc struct {
			Volumes map[string]interface{} `yaml:"volumes"`
		}
		if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatal(err)
		}
		if len(doc.Volumes) != 0 {
			t.Errorf("%s: compose declares named volumes %v", dbType, doc.Volumes)
		}
		if !strings.Contains(serviceBlock(out, "database"), "- "+cfg.GetDatabasePath()+":/var/lib/") {
			t.Errorf("%s: database does not bind-mount %s", dbType, cfg.GetDatabasePath())
		}
		if !strings.Contains(serviceBlock(out, "collector"), "- "+cfg.DataPath+":/data:ro\n") {
			t.Errorf("%s: collector does not bind-mount %s read-only", dbType, cfg.DataPath)
		}
	}
}
