package instance

import (
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

// FuzzCowrieConfigStealth drives the cowrie.cfg + userdb generators with
// attacker-/typo-controlled stealth strings (fake hostname/kernel, advertised
// banner, credential persona name). These are interpolated into an INI-style
// config and a line-oriented userdb, so the security invariant is that no value
// can inject an extra config directive or break the format: sanitizeConfigValue
// must keep every value on one printable-ASCII line.
func FuzzCowrieConfigStealth(f *testing.F) {
	f.Add("web01", "5.10.0-27-amd64", "OpenSSH_8.4p1", "web-hosting")
	f.Add("x\nauth_class = none", "k\n[ssh]\nenabled = false", "b\"; rm -rf", "evil\npersona")
	f.Add("\x00\x07ctrl", "héllo-ünïcode", "", "")
	f.Add(strings.Repeat("A", 5000), "", "", "doesnotexist")

	f.Fuzz(func(t *testing.T, host, kernel, banner, persona string) {
		cfg := config.Default("cowrie-stealth-fuzz")
		cfg.QPotID = "qp_cowriestealthfuzz0000001"
		hp := cfg.Honeypots["cowrie"]
		hp.Enabled = true
		hp.Stealth.Enabled = true
		hp.Stealth.FakeHostname = host
		hp.Stealth.FakeKernel = kernel
		hp.Stealth.BannerString = banner
		hp.Stealth.CredentialTemplate = persona
		cfg.Honeypots["cowrie"] = hp

		g := &ComposeGenerator{Config: cfg}
		cfgOut := g.generateCowrieConfig(hp) // must not panic
		userdb := g.generateCowrieUserDB()

		// (1) Exactly one auth_class line, and it must stay UserDB - a stealth
		// value that injected a newline + directive would add or change this.
		if n := countLinesWithPrefix(cfgOut, "auth_class ="); n != 1 {
			t.Fatalf("cowrie.cfg has %d auth_class lines (want 1) - directive injection? host=%q", n, host)
		}
		if !strings.Contains(cfgOut, "auth_class = UserDB") {
			t.Fatalf("auth_class is no longer UserDB; a stealth field overrode it")
		}
		// (2) Exactly one hostname directive.
		if n := countLinesWithPrefix(cfgOut, "hostname ="); n != 1 {
			t.Fatalf("cowrie.cfg has %d hostname lines (want 1); host=%q", n, host)
		}
		// (3) Every line of both files must be printable ASCII (sanitize strips
		// the rest). A non-ASCII byte would otherwise abort cowrie's ASCII parse
		// of the whole file, silently disabling it.
		assertPrintableASCIILines(t, "cowrie.cfg", cfgOut)
		assertPrintableASCIILines(t, "userdb.txt", userdb)
	})
}

func countLinesWithPrefix(s, prefix string) int {
	n := 0
	for _, ln := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), prefix) {
			n++
		}
	}
	return n
}

func assertPrintableASCIILines(t *testing.T, name, s string) {
	t.Helper()
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\n' {
			continue
		}
		if c < 0x20 || c > 0x7e {
			t.Fatalf("%s contains a non-printable-ASCII byte 0x%02x (config injection / parse-abort risk)", name, c)
		}
	}
}
