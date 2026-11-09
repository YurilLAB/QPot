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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/hostsetup"
)

const sshResourceInfoFormat = `{"CgroupDriver":{{json .CgroupDriver}},"MemoryLimit":{{json .MemoryLimit}},"PidsLimit":{{json .PidsLimit}},"CPUCfsQuota":{{json .CPUCfsQuota}}}`

type sshResourceInfoBuffer struct {
	data     []byte
	overflow bool
}

func (b *sshResourceInfoBuffer) Write(p []byte) (int, error) {
	const limit = 16 << 10
	room := limit - len(b.data)
	if len(p) > room {
		b.overflow = true
	}
	b.data = append(b.data, p[:min(len(p), room)]...)
	return len(p), nil
}

// validateSSHRuntimeResources checks the same selected daemon used by Compose.
// Accepted HostConfig fields alone do not establish enforcement: rootless Docker
// without delegated cgroups can retain limits while the guest remains unbounded.
func validateSSHRuntimeResources(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var output sshResourceInfoBuffer
	cmd := exec.CommandContext(ctx, "docker", "info", "--format", sshResourceInfoFormat)
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return hostsetup.E("QP-RES-005").WithWhy("Docker could not report its CPU, memory and PID cgroup capabilities.").Wrap(err)
	}
	if output.overflow {
		return hostsetup.E("QP-RES-005").WithWhy("Docker's resource capability response exceeded the size limit.")
	}
	return validateSSHResourceInfo(output.data)
}

func validateSSHResourceInfo(data []byte) error {
	var info struct {
		CgroupDriver string
		MemoryLimit  *bool
		PidsLimit    *bool
		CPUCfsQuota  *bool
	}
	if len(data) > 16<<10 {
		return hostsetup.E("QP-RES-005").WithWhy("Docker's resource capability response exceeded the size limit.")
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return hostsetup.E("QP-RES-005").WithWhy("Docker's resource capability response was not valid typed JSON.").Wrap(err)
	}
	var missing []string
	if info.CgroupDriver != "systemd" && info.CgroupDriver != "cgroupfs" {
		missing = append(missing, "a supported cgroup driver")
	}
	for _, capability := range []struct {
		name  string
		value *bool
	}{
		{"memory limits", info.MemoryLimit},
		{"PID limits", info.PidsLimit},
		{"CPU CFS quotas", info.CPUCfsQuota},
	} {
		if capability.value == nil || !*capability.value {
			missing = append(missing, capability.name)
		}
	}
	if len(missing) != 0 {
		return hostsetup.E("QP-RES-005").WithWhy("Docker did not confirm %s.", strings.Join(missing, ", "))
	}
	return nil
}

const (
	// sshProxyHoneypot is the honeypot name operators enable.
	sshProxyHoneypot = "ssh-proxy"
	// sshBackendDataDir identifies the legacy honeypots/ directory migrated
	// into the persistent neutral store before an upgraded cell starts.
	sshBackendDataDir = "ssh-backend"

	defaultSSHBackends = 2  // backends per ssh-proxy when unspecified
	maxSSHBackends     = 16 // hard cap so a typo can't fork-bomb the host
	sshBackendPort     = 22 // the port real sshd listens on inside each backend
)

// HiFiImageRevision is set to the full source commit by the release builder.
// Release binaries use matching source-commit image tags; ordinary development
// builds retain legacy references for offline rendering when it is empty;
// starting this newer HiFi wiring then requires explicitly built local images.
var HiFiImageRevision string

// validHiFiImageRevision accepts only the canonical full source revision used
// by the release image publisher. Offline rendering retains legacy references;
// runtime entry points must not start them with this newer wiring.
func validHiFiImageRevision(revision string) bool {
	if len(revision) != 40 {
		return false
	}
	for _, r := range revision {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func validateSSHRuntimeImages(cfg *config.Config, revision string) error {
	if sshLocalImages(cfg) || validHiFiImageRevision(revision) {
		return nil
	}
	return hostsetup.E("QP-INST-013").WithWhy("This source-built QPot has no valid full release image revision, and its HiFi configuration selects the preserved legacy published images.")
}

// Restart and recycling reuse an existing Compose document. Its actual owned
// broker/app/backup images must agree; a newly saved config alone cannot prove
// that the running document implements the new context and scene contracts.
func validateSSHLayoutImages(layout sshLayout, revision string) error {
	if !layout.Broker || len(layout.Groups) == 0 {
		return hostsetup.E("QP-INST-013").WithWhy("The existing Compose document has no complete owned HiFi broker/cell layout.")
	}
	broker := layout.Images[sshProxyHoneypot]
	backend := "qpot-local/ssh-backend:development"
	if broker != "qpot-local/ssh-proxy:development" {
		if !validHiFiImageRevision(revision) || broker != sshPublishedImage(sshProxyHoneypot, revision) {
			return hostsetup.E("QP-INST-013").WithWhy("The existing HiFi broker image is not a compatible local image or this release's source-commit image.")
		}
		backend = sshPublishedImage("ssh-backend", revision)
	}
	for app, members := range layout.Groups {
		if !containsSSHService(members, app) {
			return hostsetup.E("QP-INST-013").WithWhy("The existing HiFi cell %s has no owned application service.", app)
		}
		for _, service := range members {
			if strings.HasSuffix(service, "-db") {
				continue
			}
			if layout.Images[service] != backend {
				return hostsetup.E("QP-INST-013").WithWhy("The existing HiFi image for %s does not match its broker's compatible image source.", service)
			}
		}
	}
	return nil
}

// sshBackend describes one HiFi backend companion service for rendering.
type sshBackend struct {
	// Service is the compose service name AND its network alias, e.g.
	// "ssh-backend-1". The broker dials this name on the internal network.
	Service string
	// Network belongs to this lease alone. Pool slots never share a bridge.
	Network string
	// UsersCSV is the BACKEND_USERS env value (user:pass,user:pass,…).
	UsersCSV string
}

// sshProxyEnabled reports whether the HiFi ssh-proxy honeypot is enabled.
func sshProxyEnabled(cfg *config.Config) bool {
	hp, ok := cfg.GetHoneypotConfig(sshProxyHoneypot)
	return ok && hp.Enabled
}

// sshBackendCount returns the number of backends to run for ssh-proxy. It is
// taken from custom_config["backends"], defaulting to 2 and clamped to
// [1, maxSSHBackends] so a misconfiguration can never spawn an unbounded number
// of real-RCE containers.
func sshBackendCount(cfg *config.Config) int {
	n := defaultSSHBackends
	if hp, ok := cfg.GetHoneypotConfig(sshProxyHoneypot); ok {
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
		out = append(out, sshBackend{Service: name, Network: sshBackendNetwork(name), UsersCSV: users})
	}
	return out
}

// sshBackendNetwork names a slot's private network. Its only trusted member is
// the broker; optional organization companions belong to the same slot.
func sshBackendNetwork(service string) string { return service + "_net" }

// Keep the slot number in the readable bridge prefix. Passing ssh-backend-N
// directly would truncate all slot prefixes to the same eight characters.
func sshCellBridge(instance, service string) string {
	return bridgeName(instance, "hifi-"+strings.TrimPrefix(service, "ssh-backend-"))
}

func sshProxyImage(cfg *config.Config) string {
	if config.SSHImageSource(cfg) == config.SSHImageSourceLocal {
		return "qpot-local/ssh-proxy:development"
	}
	return sshPublishedImage(sshProxyHoneypot, HiFiImageRevision)
}

func sshBackendImage(cfg *config.Config) string {
	if config.SSHImageSource(cfg) == config.SSHImageSourceLocal {
		return "qpot-local/ssh-backend:development"
	}
	return sshPublishedImage("ssh-backend", HiFiImageRevision)
}

func sshPublishedImage(name, revision string) string {
	image := GetHoneypotImage(name)
	if revision == "" {
		return image
	}
	return strings.TrimSuffix(image, ":latest") + ":" + revision
}

func sshLocalImages(cfg *config.Config) bool {
	return config.SSHImageSource(cfg) == config.SSHImageSourceLocal
}

// Runtime decoys must not inherit the Docker client's proxy endpoints or
// credentials. Build-time proxy/CA configuration remains independent.
func runtimeProxyKeys() []string {
	return []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY",
		"http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "no_proxy"}
}

// sshBackendHostname returns the single hostname EVERY backend in the pool
// presents. All backends must agree (same as they share host keys), or a
// returning attacker round-robined to a different backend would see `hostname`
// change under the same IP — a pool/honeypot tell. Derived from the per-instance
// seed via the same hostname pool as the rest of QPot's identity deception, or
// pinned via the ssh-proxy stealth FakeHostname.
func sshBackendHostname(cfg *config.Config) string {
	if hp, ok := cfg.GetHoneypotConfig(sshProxyHoneypot); ok && hp.Stealth.FakeHostname != "" {
		if h := sanitizeHostname(hp.Stealth.FakeHostname); h != "" {
			return h
		}
	}
	seed := deceptionSeed(cfg)
	// Coherent with the same credential persona the backends enforce
	// (sshBackendUsersCSV), so the hostname an attacker sees matches the accounts
	// that work - the pool tells one consistent story instead of pairing, say, a
	// PBX login set with a "db-prod" prompt.
	explicit := ""
	if hp, ok := cfg.GetHoneypotConfig(sshProxyHoneypot); ok {
		explicit = hp.Stealth.CredentialTemplate
	}
	return hostnameForPersona(selectCredentialTemplate(explicit, seed), seed)
}

// sanitizeHostname reduces s to a valid DNS/Linux hostname: only letters,
// digits, '-' and '.', no leading/trailing separators, max 63 chars. This both
// keeps the value realistic and guarantees it cannot carry characters (quotes,
// spaces, colons, newlines) that would break the quoted `hostname:` field it is
// rendered into. Returns "" if nothing valid remains (caller falls back).
func sanitizeHostname(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		}
		if b.Len() >= 63 {
			break
		}
	}
	return strings.Trim(b.String(), "-.")
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
	seed := deceptionSeed(cfg)
	explicit := ""
	if hp, ok := cfg.GetHoneypotConfig(sshProxyHoneypot); ok {
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
