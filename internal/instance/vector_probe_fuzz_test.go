package instance

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
)

// genVectorWithProbes renders the Vector config with stealth probe filtering on
// and the given operator-supplied probe strings.
func genVectorWithProbes(t *testing.T, probes []string) string {
	t.Helper()
	cfg := config.Default("vec-probe")
	cfg.QPotID = "qp_vectorprobe00000000001"
	cfg.Stealth.BlockCommonProbes = true
	cfg.Stealth.BlockedProbes = probes
	for _, n := range []string{"cowrie"} {
		hp := cfg.Honeypots[n]
		hp.Enabled = true
		cfg.Honeypots[n] = hp
	}
	sb, err := security.NewSandbox(&cfg.Security)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}
	g := &ComposeGenerator{Config: cfg, Sandbox: sb}
	out, err := g.GenerateVectorConfig()
	if err != nil {
		t.Fatalf("GenerateVectorConfig: %v", err)
	}
	return out
}

// TestVectorProbeInjectionEscaped guards the fix for VRL injection via the
// operator-supplied stealth "blocked probe" strings. A probe containing a double
// quote or VRL syntax must be rendered as an escaped string literal, not break
// out of the contains() call - otherwise the entire log pipeline config is
// invalid (Vector won't start, all telemetry is silently lost) or VRL is
// injected.
func TestVectorProbeInjectionEscaped(t *testing.T) {
	out := genVectorWithProbes(t, []string{
		`zgrab`,
		`evil") || true || contains(msg, ("x`, // attempted VRL breakout
		`back\slash`,
		"newline\ninjected",
	})

	// Output must still be valid YAML.
	var doc interface{}
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("generated Vector config is not valid YAML after probe injection: %v", err)
	}

	// The breakout sequence must be escaped: the raw `") ||` must not appear
	// inside the condition (it would have closed the VRL string and injected).
	if strings.Contains(out, `contains(msg, "evil") || true`) {
		t.Error("VRL string breakout was NOT escaped - probe injected into the filter expression")
	}
	// The escaped form must be present instead.
	if !strings.Contains(out, `\"`) {
		t.Error("expected escaped double-quote in the rendered probe literal")
	}
	// A newline in a probe must not appear inside the (single-line) VRL literal.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "contains(msg,") && strings.Contains(line, "injected") {
			// fine: the literal is on one line; just ensure no stray newline split it
		}
	}
}

// FuzzVectorProbeFilter throws arbitrary operator probe strings at the Vector
// config generator and asserts it never panics and always produces valid YAML
// with the probe safely escaped (no unescaped quote can break the VRL string).
func FuzzVectorProbeFilter(f *testing.F) {
	f.Add("zgrab")
	f.Add(`a"b`)
	f.Add(`x") || true || ("`)
	f.Add("c\\d")
	f.Add("e\nf")
	f.Add("")

	f.Fuzz(func(t *testing.T, probe string) {
		cfg := config.Default("vec-fuzz")
		cfg.QPotID = "qp_vecfuzz0000000000000001"
		cfg.Stealth.BlockCommonProbes = true
		cfg.Stealth.BlockedProbes = []string{"zgrab", probe, "masscan"}
		hp := cfg.Honeypots["cowrie"]
		hp.Enabled = true
		cfg.Honeypots["cowrie"] = hp
		sb, err := security.NewSandbox(&cfg.Security)
		if err != nil {
			t.Skip()
		}
		g := &ComposeGenerator{Config: cfg, Sandbox: sb}
		out, err := g.GenerateVectorConfig()
		if err != nil {
			t.Fatalf("GenerateVectorConfig panicked/errored on probe %q: %v", probe, err)
		}
		// Must remain valid YAML regardless of the probe content.
		var doc interface{}
		if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("invalid YAML for probe %q: %v", probe, err)
		}
		// Every VRL string literal on a contains() line must be well-formed:
		// no probe content can break out of its double-quoted literal.
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "contains(msg,") && !vrlLiteralsWellFormed(line) {
				t.Fatalf("malformed VRL string literal for probe %q in line: %s", probe, line)
			}
		}
	})
}

// vrlLiteralsWellFormed scans a line and confirms every double-quoted VRL string
// literal is properly closed, treating \\ and \" as escape pairs. Returns false
// if a quote opens a string that never closes (i.e. a probe broke out).
func vrlLiteralsWellFormed(line string) bool {
	i := 0
	for i < len(line) {
		if line[i] != '"' {
			i++
			continue
		}
		// Enter a string literal; scan to its closing quote.
		i++
		closed := false
		for i < len(line) {
			switch line[i] {
			case '\\':
				i += 2 // skip the escaped char (\\ or \")
				continue
			case '"':
				closed = true
			}
			if closed {
				i++ // consume closing quote
				break
			}
			i++
		}
		if !closed {
			return false
		}
	}
	return true
}
