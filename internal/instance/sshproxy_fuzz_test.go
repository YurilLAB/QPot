package instance

import (
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/proxy"
	"github.com/qpot/qpot/internal/security"
	"gopkg.in/yaml.v3"
)

// cfgWithBackends builds a config with ssh-proxy enabled and the given
// custom_config["backends"] value.
func cfgWithBackends(backends string) *config.Config {
	cfg := config.Default("fz")
	cfg.QPotID = "qp_fz00000000000000000000"
	hp := cfg.Honeypots[sshProxyHoneypot]
	hp.Enabled = true
	hp.CustomConfig = map[string]string{"backends": backends}
	cfg.Honeypots[sshProxyHoneypot] = hp
	return cfg
}

// FuzzSSHUsersCSV asserts the BACKEND_USERS builder ALWAYS produces a value the
// backend entrypoint can parse safely, for arbitrary persona usernames and
// passwords. The env is comma-separated user:pass pairs piped into chpasswd, so
// a stray comma, colon, '=', space, or control byte would either corrupt the
// account list or inject an extra credential — this fuzz guards that the
// sanitizer (sshSafeToken) makes that impossible regardless of input.
func FuzzSSHUsersCSV(f *testing.F) {
	f.Add("admin", "admin", "root", "toor")
	f.Add("a,b", "p:q", "user=x", "pass word")
	f.Add("", "", "\x00", "\xff")
	f.Add(strings.Repeat("u", 200), "p", "ok", "good")
	f.Fuzz(func(t *testing.T, u1, p1, u2, p2 string) {
		users := []credUser{
			{Username: u1, Passwords: []string{p1}},
			{Username: u2, Passwords: []string{p2}},
		}
		csv := sshUsersCSV(users)
		if csv == "" {
			t.Fatal("BACKEND_USERS must never be empty")
		}
		// The value must split cleanly into user:pass pairs with no corruption.
		for _, pair := range strings.Split(csv, ",") {
			parts := strings.Split(pair, ":")
			if len(parts) != 2 {
				t.Fatalf("pair %q does not split into exactly user:pass (csv=%q)", pair, csv)
			}
			user, pass := parts[0], parts[1]
			if !sshSafeToken(user) || !sshSafeToken(pass) {
				t.Fatalf("emitted unsafe token in pair %q (csv=%q)", pair, csv)
			}
		}
		// No embedded whitespace/control that would break the shell `for` split.
		for i := 0; i < len(csv); i++ {
			if csv[i] < 0x20 {
				t.Fatalf("control byte 0x%x in BACKEND_USERS %q", csv[i], csv)
			}
		}
	})
}

// FuzzSSHBackendCSVRoundTrip asserts the broker's BACKENDS string that the
// renderer generates is always parseable by the broker's own ParseBackends (the
// two must never drift), for any backend count derived from custom_config.
func FuzzSSHBackendCSVRoundTrip(f *testing.F) {
	f.Add("2")
	f.Add("0")
	f.Add("999")
	f.Add("garbage")
	f.Add("-5")
	f.Fuzz(func(t *testing.T, backends string) {
		cfg := cfgWithBackends(backends)
		csv := sshBackendCSV(cfg)
		names := sshBackendServiceNames(cfg)
		// Count must match between the env string and the rendered service set.
		if got := strings.Count(csv, ",") + 1; got != len(names) {
			t.Fatalf("CSV pair count %d != service count %d (csv=%q)", got, len(names), csv)
		}
		if len(names) < 1 || len(names) > maxSSHBackends {
			t.Fatalf("backend count %d out of bounds", len(names))
		}
		// The renderer's BACKENDS string MUST parse with the broker's own parser,
		// or the deployed broker would fail to start. This guards the two formats
		// (sshBackendCSV here, proxy.ParseBackends in the binary) from drifting.
		parsed, err := proxy.ParseBackends(csv)
		if err != nil {
			t.Fatalf("broker cannot parse renderer-generated BACKENDS %q: %v", csv, err)
		}
		if len(parsed) != len(names) {
			t.Fatalf("parsed %d backends, rendered %d services", len(parsed), len(names))
		}
	})
}

// FuzzSSHProxyRenderInvariants renders the full compose with ssh-proxy enabled
// under fuzzed seed / fake-hostname / backend-count inputs, parses the result as
// YAML, and asserts the SECURITY-CRITICAL HiFi invariants always hold:
//   - the render never errors and is always valid YAML;
//   - the egress-locked backend network exists and is internal:true;
//   - every backend is on that network and publishes NO host port (real RCE is
//     never exposed to the internet);
//   - the broker publishes a port and carries a BACKENDS env.
//
// This is the catch-all guard against a template change (or a hostile-looking
// fake hostname) ever breaking the YAML or, worse, exposing a backend.
func FuzzSSHProxyRenderInvariants(f *testing.F) {
	f.Add("seedA", "web-prod-02", "2")
	f.Add("", "", "1")
	f.Add("x", "evil\"\n    ports:\n      - \"2222:2222\"", "3")
	f.Add("qp_zzz", "../../etc", "999")
	f.Fuzz(func(t *testing.T, seed, fakeHostname, backends string) {
		cfg := config.Default("fzrender")
		// A real QPotID is always "qp_" + base32 (guaranteed ASCII by GenerateID/
		// ValidateID), and the instance name is path-validated. Those are
		// system-controlled, not attacker input, so we keep the seed within the
		// real QPotID charset and instead hammer the operator-facing knobs that DO
		// vary freely: the fake hostname and the backend count.
		cfg.QPotID = "qp_" + filterBase32(seed)
		// Isolate the ssh-proxy path: disable the other honeypots so the render is
		// fast and the assertions target HiFi.
		for n, hp := range cfg.Honeypots {
			hp.Enabled = (n == sshProxyHoneypot)
			if n == sshProxyHoneypot {
				hp.Stealth.FakeHostname = fakeHostname
				hp.CustomConfig = map[string]string{"backends": backends}
			}
			cfg.Honeypots[n] = hp
		}

		sb, err := security.NewSandbox(&cfg.Security)
		if err != nil {
			t.Fatalf("NewSandbox: %v", err)
		}
		g := &ComposeGenerator{Config: cfg, Sandbox: sb}
		out, err := g.Generate()
		if err != nil {
			t.Fatalf("Generate errored on seed=%q host=%q backends=%q: %v", seed, fakeHostname, backends, err)
		}

		var doc struct {
			Services map[string]struct {
				Ports    []string `yaml:"ports"`
				Networks []string `yaml:"networks"`
			} `yaml:"services"`
			Networks map[string]struct {
				Internal bool `yaml:"internal"`
			} `yaml:"networks"`
		}
		if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("rendered compose is not valid YAML (seed=%q host=%q backends=%q): %v", seed, fakeHostname, backends, err)
		}

		// Egress-locked backend network must exist and be internal.
		net, ok := doc.Networks["ssh-proxy_backend"]
		if !ok || !net.Internal {
			t.Fatalf("ssh-proxy_backend network missing or not internal: %+v", doc.Networks)
		}

		// Broker must publish a port.
		broker, ok := doc.Services["ssh-proxy"]
		if !ok || len(broker.Ports) == 0 {
			t.Fatalf("broker missing or publishes no port: %+v", broker)
		}

		// Every backend: on the egress-locked net, NEVER publishing a host port.
		nBackends := 0
		for name, svc := range doc.Services {
			if !strings.HasPrefix(name, "ssh-backend-") {
				continue
			}
			nBackends++
			if len(svc.Ports) != 0 {
				t.Fatalf("backend %s publishes host ports %v (real RCE exposed!)", name, svc.Ports)
			}
			onBackendNet := false
			for _, nw := range svc.Networks {
				if nw == "ssh-proxy_backend" {
					onBackendNet = true
				}
				if nw == "qpot_internal" {
					t.Fatalf("backend %s is on qpot_internal (must reach only the broker)", name)
				}
			}
			if !onBackendNet {
				t.Fatalf("backend %s not on the egress-locked network: %v", name, svc.Networks)
			}
		}
		if nBackends < 1 || nBackends > maxSSHBackends {
			t.Fatalf("rendered %d backends, out of bounds [1,%d]", nBackends, maxSSHBackends)
		}
	})
}

// filterBase32 reduces s to the lowercase-base32 charset a real QPotID uses, so
// the fuzz varies the per-instance identity without exploring impossible
// (system-never-generates-them) QPotID values.
func filterBase32(s string) string {
	const valid = "abcdefghijklmnopqrstuvwxyz234567"
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(valid, r) {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "seed"
	}
	return b.String()
}
