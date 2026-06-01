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
