package instance

import (
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/proxy"
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
