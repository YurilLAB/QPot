package instance

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strings"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/netguard"
)

// egressGuard is the compose view of an instance's egress guard (see
// internal/netguard and cmd/qpot-netguard).
type egressGuard struct {
	Enabled bool
	Table   string
	Ifaces  string // comma-separated bridge names
	Mode    netguard.Mode
	Image   string
}

// netguardImage carries the qpot-netguard binary. It ships in QPot's public
// helper image next to the HiFi broker, so no extra package has to be
// published before an instance can pull it.
func netguardImage() string { return GetHoneypotImage("ssh-proxy") }

// egressGuardTable names the instance's nftables table. Instances share the
// host's network namespace, so each owns its own table.
func egressGuardTable(instanceName string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(instanceName))
	return fmt.Sprintf("qpot_egress_%08x", h.Sum32())
}

// egressGuardFor returns the guard the compose renders for cfg: on unless the
// operator set allow_private_egress (and not block_outbound), covering the
// bridge of every enabled honeypot. The spec is validated here, so a compose
// is never written with a guard that would refuse to start.
func egressGuardFor(cfg *config.Config) (egressGuard, error) {
	ni := cfg.Security.NetworkIsolation
	if ni.AllowPrivateEgress && !ni.BlockOutbound {
		return egressGuard{}, nil
	}
	var ifaces []string
	for name, hp := range cfg.Honeypots {
		if hp.Enabled {
			ifaces = append(ifaces, bridgeName(cfg.InstanceName, name))
		}
	}
	if len(ifaces) == 0 {
		return egressGuard{}, nil
	}
	sort.Strings(ifaces)
	mode := netguard.ModePrivate
	if ni.BlockOutbound {
		mode = netguard.ModeAll
	}
	spec := netguard.Spec{Table: egressGuardTable(cfg.InstanceName), Ifaces: ifaces, Mode: mode}
	if err := spec.Validate(); err != nil {
		return egressGuard{}, fmt.Errorf("egress guard: %w", err)
	}
	return egressGuard{
		Enabled: true,
		Table:   spec.Table,
		Ifaces:  strings.Join(ifaces, ","),
		Mode:    mode,
		Image:   netguardImage(),
	}, nil
}
