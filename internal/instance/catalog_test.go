package instance

import (
	"testing"
)

// Every honeypot QPot ships has a description for `qpot honeypot list` and
// the web UI.
func TestEveryHoneypotHasADescription(t *testing.T) {
	cfg := settingsTestConfig(t, "cat-desc")
	for name := range cfg.SnapshotHoneypots() {
		if HoneypotDescription(name) == "" {
			t.Errorf("%s has no description", name)
		}
	}
	if HoneypotDescription("nosuch") != "" {
		t.Error("a name QPot does not ship has a description")
	}
}

// HostPortMappings lists the host ports the compose file publishes, for
// enabled honeypots only, and nothing for a honeypot another service
// publishes for (tanner).
func TestHostPortMappings(t *testing.T) {
	cfg := settingsTestConfig(t, "cat-ports")
	for _, n := range []string{"cowrie", "dionaea", "ddospot", "tanner"} {
		cfg.EnableHoneypot(n)
	}
	cfg.DisableHoneypot("heralding")
	got := HostPortMappings(cfg)
	assigned := PublishedHostPorts(cfg)

	if _, ok := got["heralding"]; ok {
		t.Error("a disabled honeypot has ports")
	}
	if _, ok := got["tanner"]; ok {
		t.Error("tanner has ports of its own (snare publishes them)")
	}
	for _, n := range []string{"cowrie", "dionaea", "ddospot"} {
		ms := got[n]
		if len(ms) == 0 {
			t.Fatalf("%s: no ports", n)
		}
		for i, m := range ms {
			if h, ok := assigned[portKey(n, m.ContainerPort)]; !ok || h != m.HostPort {
				t.Errorf("%s %d/%s: host port %d, compose has %d (%v)", n, m.ContainerPort, m.Protocol, m.HostPort, h, ok)
			}
			if m.Protocol != "tcp" && m.Protocol != "udp" {
				t.Errorf("%s: protocol %q", n, m.Protocol)
			}
			if i > 0 && ms[i-1].ContainerPort > m.ContainerPort {
				t.Errorf("%s: ports not sorted: %v", n, ms)
			}
		}
	}
	udp := false
	for _, m := range got["ddospot"] {
		udp = udp || m.Protocol == "udp"
	}
	if !udp {
		t.Errorf("ddospot publishes no UDP port: %v", got["ddospot"])
	}
}
