package instance

import (
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
)

// BenchmarkGenerateAllHoneypots measures full compose generation with every
// honeypot enabled, including the collision-free host-port and subnet
// assignment. This runs on every `qpot up` / config change.
func BenchmarkGenerateAllHoneypots(b *testing.B) {
	cfg := config.Default("bench")
	cfg.QPotID = "qp_benchbenchbenchbenchben"
	cfg.Security.NetworkIsolation.RandomizeMAC = true
	for name, hp := range cfg.Honeypots {
		hp.Enabled = true
		cfg.Honeypots[name] = hp
	}
	sb, err := security.NewSandbox(&cfg.Security)
	if err != nil {
		b.Fatalf("NewSandbox: %v", err)
	}
	g := &ComposeGenerator{Config: cfg, Sandbox: sb}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := g.Generate(); err != nil {
			b.Fatalf("Generate: %v", err)
		}
	}
}
