package instance

import (
	"regexp"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
)

// TestAllHoneypotsComposeTogether enables every supported honeypot at once and
// asserts the generated stack is internally consistent - no two honeypots
// collide on a host port, a Linux bridge name, or a container name, and each
// resolves to a real image. This is the config-level guarantee that all the
// honeypots run together (the runtime smoke run lives in CI and manual tests).
func TestAllHoneypotsComposeTogether(t *testing.T) {
	// Run across several instance seeds: host-port assignment is seed-derived,
	// so a regression in the collision-free allocator might only surface for
	// some seeds.
	for _, inst := range []string{"all-together", "prod-sensor", "edge-1", "qp-east-2", "lab"} {
		t.Run(inst, func(t *testing.T) {
			cfg := config.Default(inst)
			cfg.QPotID = "qp_" + inst + "00000000000000000"
			cfg.Security.NetworkIsolation.RandomizeMAC = true

			enabled := 0
			for name, hp := range cfg.Honeypots {
				hp.Enabled = true
				cfg.Honeypots[name] = hp
				enabled++
			}
			if enabled < 20 {
				t.Fatalf("expected 20+ honeypots in the default config, got %d", enabled)
			}

			sb, err := security.NewSandbox(&cfg.Security)
			if err != nil {
				t.Fatalf("NewSandbox: %v", err)
			}
			g := &ComposeGenerator{Config: cfg, Sandbox: sb}
			out, err := g.Generate()
			if err != nil {
				t.Fatalf("Generate with all honeypots enabled: %v", err)
			}

			// Host ports must be unique per protocol (a TCP and a UDP mapping may
			// legitimately share a host port number, so check them separately).
			assertUnique(t, "TCP host port", regexp.MustCompile(`-\s+"(\d+):\d+"`), out)
			assertUnique(t, "UDP host port", regexp.MustCompile(`-\s+"(\d+):\d+/udp"`), out)
			// Linux bridge names and container names must be unique.
			assertUnique(t, "bridge name", regexp.MustCompile(`com\.docker\.network\.bridge\.name:\s+(\S+)`), out)
			assertUnique(t, "container name", regexp.MustCompile(`container_name:\s+(\S+)`), out)
			// Network /24 subnets must be unique, or docker rejects the second
			// with "Pool overlaps with other one on this address space".
			assertUnique(t, "subnet", regexp.MustCompile(`-\s+subnet:\s+(\S+)`), out)

			// Every enabled honeypot must resolve to a real image.
			imgRe := regexp.MustCompile(`image:\s+(\S+)`)
			if m := imgRe.FindAllStringSubmatch(out, -1); len(m) < enabled {
				t.Errorf("found %d image: lines, want >= %d", len(m), enabled)
			}
			for name := range cfg.Honeypots {
				if img := GetHoneypotImage(name); img == "" {
					t.Errorf("honeypot %q resolves to an empty image", name)
				}
			}
		})
	}
}

// assertUnique extracts capture group 1 of re from s and fails if any value
// repeats, reporting the offending value.
func assertUnique(t *testing.T, kind string, re *regexp.Regexp, s string) {
	t.Helper()
	seen := map[string]bool{}
	matches := re.FindAllStringSubmatch(s, -1)
	if len(matches) == 0 {
		t.Errorf("no %s entries found in generated compose", kind)
		return
	}
	for _, m := range matches {
		v := m[1]
		if seen[v] {
			t.Errorf("duplicate %s %q in generated compose (honeypots collide)", kind, v)
		}
		seen[v] = true
	}
}
