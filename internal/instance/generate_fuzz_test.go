package instance

import (
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
)

// FuzzGenerators feeds arbitrary values into the config fields that flow into
// generated artifacts (compose YAML, vector.yaml) and asserts the
// generators never panic. Config is operator-controlled, but odd
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
		cp := cfg.Honeypots["conpot"]
		cp.Enabled = true
		cfg.Honeypots["conpot"] = cp

		sb, err := security.NewSandbox(&cfg.Security)
		if err != nil {
			t.Skip()
		}
		g := &ComposeGenerator{Config: cfg, Sandbox: sb}

		// None of these may panic on arbitrary string input.
		out, err := g.Generate()
		if err == nil {
			// Whatever the instance identity, conpot runs one deployed
			// template: the seed only chooses which.
			svc := composeService(t, out, "conpot")
			if n := strings.Count(svc, "- CONPOT_TEMPLATE="); n != 1 {
				t.Errorf("conpot service has %d CONPOT_TEMPLATE lines, qpotID=%q", n, qpotID)
			}
		}
		if _, err := g.GenerateVectorConfig(); err != nil {
			_ = err
		}
	})
}
