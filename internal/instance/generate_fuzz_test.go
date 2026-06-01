package instance

import (
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
)

// FuzzGenerators feeds arbitrary values into the config fields that flow into
// generated artifacts (compose YAML, vector.yaml, cowrie.cfg, userdb.txt) and
// asserts the generators never panic. Config is operator-controlled, but odd
// values (newlines, quotes, template metacharacters, huge strings) must not
// crash generation or be silently dropped.
func FuzzGenerators(f *testing.F) {
	f.Add("default", "qp_aaaaaaaaaaaaaaaaaaaaaaaa", "webserver", "OpenSSH_8.9", "5.15.0")
	f.Add("inst-1", "qp_x", "host\ninjected = bad", "ver\"quote", "k\x00ernel")
	f.Add("", "", "", "", "")
	f.Add("a{{.X}}b", "qp_{{evil}}", "$(whoami)", "ver`cmd`", "../../etc")

	f.Fuzz(func(t *testing.T, inst, qpotID, hostname, banner, kernel string) {
		cfg := config.Default("fuzz")
		if inst != "" {
			cfg.InstanceName = inst
		}
		cfg.QPotID = qpotID
		hp := cfg.Honeypots["cowrie"]
		hp.Enabled = true
		hp.Stealth.Enabled = true
		hp.Stealth.FakeHostname = hostname
		hp.Stealth.BannerString = banner
		hp.Stealth.FakeKernel = kernel
		cfg.Honeypots["cowrie"] = hp

		sb, err := security.NewSandbox(&cfg.Security)
		if err != nil {
			t.Skip()
		}
		g := &ComposeGenerator{Config: cfg, Sandbox: sb}

		// None of these may panic on arbitrary string input.
		if _, err := g.Generate(); err != nil {
			// A template error is acceptable (returned, not panicked); just
			// don't crash.
			_ = err
		}
		if _, err := g.GenerateVectorConfig(); err != nil {
			_ = err
		}
		ccfg := g.generateCowrieConfig(hp)
		udb := g.generateCowrieUserDB()

		// cowrie.cfg must always contain exactly one of each core section even
		// when fed hostile stealth strings — a hostname with an embedded newline
		// must not be able to inject a second [ssh]/[telnet] section.
		if n := strings.Count(ccfg, "\n[ssh]\n"); n != 1 {
			t.Errorf("cowrie.cfg has %d [ssh] sections (config injection via stealth string?), hostname=%q", n, hostname)
		}
		if n := strings.Count(ccfg, "\n[telnet]\n"); n != 1 {
			t.Errorf("cowrie.cfg has %d [telnet] sections, hostname=%q", n, hostname)
		}
		_ = udb
	})
}
