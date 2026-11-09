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
	Cells   string // private HiFi bridges, always protected even with private egress allowed
	Mode    netguard.Mode
	Image   string
}

// netguardImage carries the qpot-netguard binary. It ships in QPot's public
// helper image next to the HiFi broker, so no extra package has to be
// published before an instance can pull it.
func netguardImage() string { return sshPublishedImage(sshProxyHoneypot, HiFiImageRevision) }

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
	protectOrdinary := !ni.AllowPrivateEgress || ni.BlockOutbound
	if !protectOrdinary && !sshProxyEnabled(cfg) {
		return egressGuard{}, nil
	}
	var ifaces []string
	for name, hp := range cfg.Honeypots {
		if hp.Enabled && (protectOrdinary || name == sshProxyHoneypot) {
			ifaces = append(ifaces, bridgeName(cfg.InstanceName, name))
		}
	}
	var cells []string
	if sshProxyEnabled(cfg) {
		for _, service := range sshBackendServiceNames(cfg) {
			cells = append(cells, sshCellBridge(cfg.InstanceName, service))
		}
		ifaces = append(ifaces, cells...)
	}
	if len(ifaces) == 0 {
		return egressGuard{}, nil
	}
	sort.Strings(ifaces)
	sort.Strings(cells)
	mode := netguard.ModePrivate
	if ni.BlockOutbound {
		mode = netguard.ModeAll
	}
	spec := netguard.Spec{Table: egressGuardTable(cfg.InstanceName), Ifaces: ifaces, Cells: cells, Mode: mode}
	if err := spec.Validate(); err != nil {
		return egressGuard{}, fmt.Errorf("egress guard: %w", err)
	}
	return egressGuard{
		Enabled: true,
		Table:   spec.Table,
		Ifaces:  strings.Join(ifaces, ","),
		Cells:   strings.Join(cells, ","),
		Mode:    mode,
		Image:   guardImage(cfg),
	}, nil
}

func guardImage(cfg *config.Config) string {
	if sshProxyEnabled(cfg) {
		return sshProxyImage(cfg)
	}
	return netguardImage()
}
