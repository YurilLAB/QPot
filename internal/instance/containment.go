package instance

// containment.go is the start gate for containment that a setting or a host
// can take away. The hardening every container gets (read-only root, no
// capabilities, no-new-privileges, its own bridge, resource limits in the
// compose file) is rendered unconditionally and needs no gate: see
// config.MandatoryControls. What is left depends on the host or on an
// operator's choice, and is checked here for the honeypots that need it.
//
// QPot sorts honeypots into two classes:
//
//   - reviewed emulators (cowrie, conpot, refrigeration): Python or Go
//     programs that answer from a script and never run what a visitor sends;
//   - sensitive workloads (everything else): real services and third-party
//     native code that parse, relay or run attacker input - HiFi SSH's real
//     OpenSSH, Tanner's PHP sandbox, dionaea, and any honeypot QPot has not
//     reviewed.
//
// A sensitive workload starts only when all of this holds:
//
//   - the isolation runtime the policy asks for is registered and used
//     (resolveSandbox; QP-DOCKER-010/011/012);
//   - the egress guard covers it (QP-INST-015);
//   - Docker confirms it enforces CPU, memory, swap and PID limits
//     (QP-RES-005 for HiFi, QP-RES-007 for the rest).
//
// Emulators may run without the last two, by the operator's explicit choice
// (allow_private_egress) or with a doctor warning (QP-RES-006).

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/hostsetup"
)

// reviewedEmulator reports whether name is one of the honeypots reviewed as
// never executing attacker input. Every other name is a sensitive workload.
func reviewedEmulator(name string) bool {
	switch name {
	case "cowrie", "conpot", "refrigeration":
		return true
	}
	return false
}

// sensitiveWorkloads returns, sorted, the honeypots concerned that are not
// reviewed emulators: the targets when an operation names them (it starts or
// restarts only those), every enabled honeypot otherwise.
func sensitiveWorkloads(cfg *config.Config, targets ...string) []string {
	concerned := targets
	if len(concerned) == 0 {
		concerned = cfg.GetEnabledHoneypots()
	}
	seen := map[string]bool{}
	for _, name := range concerned {
		if !reviewedEmulator(name) {
			seen[name] = true
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// checkContainmentSettings refuses the settings that leave a sensitive
// workload uncontained. It asks nothing of Docker, so rendering and the
// doctor can call it too.
func checkContainmentSettings(cfg *config.Config, targets ...string) error {
	ni := cfg.Security.NetworkIsolation
	if !ni.AllowPrivateEgress || ni.BlockOutbound {
		return nil
	}
	// HiFi SSH keeps its own guard whatever this setting says (egressGuardFor).
	var open []string
	for _, name := range sensitiveWorkloads(cfg, targets...) {
		if name != sshProxyHoneypot {
			open = append(open, name)
		}
	}
	if len(open) == 0 {
		return nil
	}
	return hostsetup.E("QP-INST-015").WithWhy(
		"security.network_isolation.allow_private_egress switches the egress guard off, and %s could then reach your network, the Docker host and cloud metadata addresses.",
		strings.Join(open, ", ")).
		WithFix("Set security.network_isolation.allow_private_egress: false (qpot config), or turn off %s. Only cowrie, conpot and refrigeration may run with the egress guard off.",
			strings.Join(open, ", "))
}

// CheckContainmentSettings is checkContainmentSettings for the doctor.
func CheckContainmentSettings(cfg *config.Config) error { return checkContainmentSettings(cfg) }

// GeneratedFilesCarryQPotID reports whether the instance's compose file or
// collector configuration, as they are on disk, contain the QPot ID: they did
// until the collector stopped being given it, and do until the next start.
func GeneratedFilesCarryQPotID(cfg *config.Config) bool {
	if cfg.QPotID == "" {
		return false
	}
	for _, path := range []string{cfg.GetDockerComposePath(), filepath.Join(cfg.DataPath, "vector.yaml")} {
		data, err := os.ReadFile(path)
		if err == nil && bytes.Contains(data, []byte(cfg.QPotID)) {
			return true
		}
	}
	return false
}

// checkContainment is the start gate: the settings check, then, for sensitive
// workloads other than HiFi SSH (which has its own, stricter gate), Docker's
// own word that it enforces the limits the compose file asks for.
func checkContainment(ctx context.Context, cfg *config.Config, targets ...string) error {
	if err := checkContainmentSettings(cfg, targets...); err != nil {
		return err
	}
	for _, name := range sensitiveWorkloads(cfg, targets...) {
		if name != sshProxyHoneypot {
			return validateRuntimeResources(ctx, "QP-RES-007")
		}
	}
	return nil
}
