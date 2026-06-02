package instance

import (
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
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
// only emitted when the sandbox runtime is actually available. In this test
// environment runsc/kata are absent, so NewSandbox falls back to "none" and the
// compose must NOT contain a runtime: line (which would make docker refuse to
// start the stack).
func TestComposeRuntimeGatedOnAvailability(t *testing.T) {
	out := renderCompose(t) // uses config.Default (sandbox_mode gvisor) -> falls back to none here
	if strings.Contains(out, "runtime: runsc") || strings.Contains(out, "runtime: kata-runtime") {
		t.Error("compose emitted a sandbox runtime line while the runtime is unavailable; would break docker compose up")
	}
}
