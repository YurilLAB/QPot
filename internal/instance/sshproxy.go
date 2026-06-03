package instance

// sshproxy.go wires the high-interaction SSH proxy ("HiFi") mode into compose
// generation and the manager. The HiFi honeypot is unusual: enabling the single
// honeypot `ssh-proxy` stands up TWO kinds of container —
//
//   - the attacker-facing BROKER (cmd/qpot-sshproxy): a transparent L4 splice
//     that publishes the SSH port and forwards opaque bytes; and
//   - one or more real-OpenSSH BACKENDS (docker/ssh-backend) on an EGRESS-LOCKED
//     internal network, where the attacker's handshake actually terminates.
//
// Keeping the backend wiring here (rather than scattered through compose.go)
// makes the one-honeypot-two-service shape explicit and unit-testable. See
// doc/ssh-hifi-proxy.md for the architecture and security model.

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/qpot/qpot/internal/config"
)

const (
	// sshProxyHoneypot is the honeypot name operators enable.
	sshProxyHoneypot = "ssh-proxy"
	// sshBackendDataDir is the honeypots/ subdir under which each backend's
	// persisted host keys and logs live (honeypots/ssh-backend/<service>/...).
	sshBackendDataDir = "ssh-backend"

	defaultSSHBackends = 2  // backends per ssh-proxy when unspecified
	maxSSHBackends     = 16 // hard cap so a typo can't fork-bomb the host
	sshBackendPort     = 22 // the port real sshd listens on inside each backend
)

// sshBackend describes one HiFi backend companion service for rendering.
type sshBackend struct {
	// Service is the compose service name AND its network alias, e.g.
	// "ssh-backend-1". The broker dials this name on the internal network.
	Service string
	// UsersCSV is the BACKEND_USERS env value (user:pass,user:pass,…).
	UsersCSV string
}

// sshProxyEnabled reports whether the HiFi ssh-proxy honeypot is enabled.
func sshProxyEnabled(cfg *config.Config) bool {
	hp, ok := cfg.Honeypots[sshProxyHoneypot]
	return ok && hp.Enabled
}

// sshBackendCount returns the number of backends to run for ssh-proxy. It is
// taken from custom_config["backends"], defaulting to 2 and clamped to
// [1, maxSSHBackends] so a misconfiguration can never spawn an unbounded number
// of real-RCE containers.
func sshBackendCount(cfg *config.Config) int {
	n := defaultSSHBackends
	if hp, ok := cfg.Honeypots[sshProxyHoneypot]; ok {
		if v := strings.TrimSpace(hp.CustomConfig["backends"]); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil {
				n = parsed
			}
		}
	}
	if n < 1 {
		n = 1
	}
	if n > maxSSHBackends {
		n = maxSSHBackends
	}
	return n
}

// sshBackendServiceNames returns the deterministic backend service names
// ("ssh-backend-1", …). Shared by the compose renderer (to emit the services)
// and the manager (to start/stop them alongside the broker).
func sshBackendServiceNames(cfg *config.Config) []string {
	n := sshBackendCount(cfg)
	names := make([]string, n)
	for i := 0; i < n; i++ {
		names[i] = fmt.Sprintf("ssh-backend-%d", i+1)
	}
	return names
}

// sshProxyBackends returns the backend descriptors the compose template renders.
func sshProxyBackends(cfg *config.Config) []sshBackend {
	users := sshBackendUsersCSV(cfg)
	names := sshBackendServiceNames(cfg)
	out := make([]sshBackend, 0, len(names))
	for _, name := range names {
		out = append(out, sshBackend{Service: name, UsersCSV: users})
	}
	return out
}

// sshBackendHostname returns the single hostname EVERY backend in the pool
// presents. All backends must agree (same as they share host keys), or a
// returning attacker round-robined to a different backend would see `hostname`
// change under the same IP — a pool/honeypot tell. Derived from the per-instance
// seed via the same hostname pool as the rest of QPot's identity deception, or
// pinned via the ssh-proxy stealth FakeHostname.
func sshBackendHostname(cfg *config.Config) string {
	if hp, ok := cfg.Honeypots[sshProxyHoneypot]; ok && hp.Stealth.FakeHostname != "" {
		return sanitizeConfigValue(hp.Stealth.FakeHostname)
	}
	seed := cfg.QPotID
	if seed == "" {
		seed = cfg.InstanceName
	}
	return hostnameForSeed(seed)
}

// sshBackendCSV returns the broker's QPOT_SSHPROXY_BACKENDS value, e.g.
// "ssh-backend-1=ssh-backend-1:22,ssh-backend-2=ssh-backend-2:22". The id and
// dial host are both the service name, which docker DNS resolves on the shared
// internal network.
func sshBackendCSV(cfg *config.Config) string {
	names := sshBackendServiceNames(cfg)
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = fmt.Sprintf("%s=%s:%d", n, n, sshBackendPort)
	}
	return strings.Join(parts, ",")
}

// sshBackendUsersCSV derives the backend's seedable login persona (BACKEND_USERS)
// from the SAME credential-persona system as the rest of QPot's deception, so the
// HiFi box accepts the same realistic weak credentials advertised elsewhere. Each
// value is sanitized so nothing can break the comma/colon-delimited env format
// (an injection-safety as well as a correctness measure); if the persona yields
// no safe pair, a sensible default is used so the backend is never credential-less.
func sshBackendUsersCSV(cfg *config.Config) string {
	seed := cfg.QPotID
	if seed == "" {
		seed = cfg.InstanceName
	}
	explicit := ""
	if hp, ok := cfg.Honeypots[sshProxyHoneypot]; ok {
		explicit = hp.Stealth.CredentialTemplate
	}
	tmpl := selectCredentialTemplate(explicit, seed)
	return sshUsersCSV(tmpl.Users)
}

// sshUsersCSV turns persona accounts into a sanitized BACKEND_USERS value. Each
// user takes its first password; any account whose username or password is not a
// safe token (would corrupt the comma/colon-delimited env or the downstream
// chpasswd) is skipped, and at most a handful are emitted. If nothing safe
// remains, a sensible default is returned so the backend is never login-less.
// Factored out so the sanitization invariant can be fuzzed directly.
func sshUsersCSV(users []credUser) string {
	var pairs []string
	seen := map[string]bool{}
	for _, u := range users {
		if len(u.Passwords) == 0 {
			continue
		}
		user, pass := u.Username, u.Passwords[0]
		if !sshSafeToken(user) || !sshSafeToken(pass) || seen[user] {
			continue
		}
		seen[user] = true
		pairs = append(pairs, user+":"+pass)
		if len(pairs) >= 6 { // a handful of accounts is plenty; keep the env small
			break
		}
	}
	if len(pairs) == 0 {
		return "admin:admin,ubuntu:ubuntu,root:root123"
	}
	return strings.Join(pairs, ",")
}

// sshSafeToken reports whether s is a safe BACKEND_USERS token: non-empty,
// bounded length, printable ASCII, and free of the delimiters (',', ':', '=')
// and whitespace that would corrupt the env value or the downstream chpasswd.
func sshSafeToken(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if r == ',' || r == ':' || r == '=' || r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}
