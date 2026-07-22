package instance

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// TestLeHexEncoding checks the little-endian hex encoding /proc/net/tcp uses
// against known kernel values.
func TestLeHexEncoding(t *testing.T) {
	cases := map[string][4]int{
		"0100007F": {127, 0, 0, 1},
		"0500000A": {10, 0, 0, 5},
		"00000000": {0, 0, 0, 0},
		"0101A8C0": {192, 168, 1, 1},
	}
	for want, ip := range cases {
		if got := leHex(ip); got != want {
			t.Errorf("leHex(%v) = %q, want %q", ip, got, want)
		}
	}
}

// decodeLE reverses leHex back to an IP for consistency checks.
func decodeLE(h string) [4]int {
	var ip [4]int
	if len(h) != 8 {
		return ip
	}
	for i := 0; i < 4; i++ {
		v, _ := strconv.ParseInt(h[i*2:i*2+2], 16, 32)
		ip[3-i] = int(v)
	}
	return ip
}

// TestNetIdentityVariesAndIsPrivate guards that the per-instance network identity
// is deterministic, drawn from a MIXTURE of the RFC-1918 ranges, and internally
// consistent (host and gateway on the same /24).
func TestNetIdentityVariesAndIsPrivate(t *testing.T) {
	ipsSeen := map[string]bool{}
	rangesSeen := map[int]bool{}
	ifacesSeen := map[string]bool{}
	seeds := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"}
	for _, s := range seeds {
		id := netIdentityForSeed(s)
		// Private ranges only.
		priv := id.IP[0] == 10 ||
			(id.IP[0] == 172 && id.IP[1] >= 16 && id.IP[1] <= 31) ||
			(id.IP[0] == 192 && id.IP[1] == 168)
		if !priv {
			t.Errorf("seed %s: IP %s is not RFC-1918", s, id.ipString())
		}
		// Host and gateway share the /24, gateway is .1, host is not .1.
		if id.Gateway[0] != id.IP[0] || id.Gateway[1] != id.IP[1] || id.Gateway[2] != id.IP[2] || id.Gateway[3] != 1 {
			t.Errorf("seed %s: gateway %s not .1 of host subnet %s", s, id.gwString(), id.ipString())
		}
		if id.IP[3] == 1 {
			t.Errorf("seed %s: host cannot be .1 (that's the gateway)", s)
		}
		// MAC shape.
		if strings.Count(id.MAC, ":") != 5 {
			t.Errorf("seed %s: MAC %q malformed", s, id.MAC)
		}
		ipsSeen[id.ipString()] = true
		rangesSeen[id.IP[0]] = true
		ifacesSeen[id.Iface] = true
	}
	if len(ipsSeen) < len(seeds)-1 {
		t.Errorf("IPs should be nearly all distinct across seeds, got %d/%d", len(ipsSeen), len(seeds))
	}
	if len(rangesSeen) < 2 {
		t.Errorf("network range should be a MIXTURE across seeds, got %d distinct first-octets", len(rangesSeen))
	}
	if len(ifacesSeen) < 2 {
		t.Errorf("interface name should vary across seeds, got %d distinct", len(ifacesSeen))
	}
	// Deterministic per seed.
	if a, b := netIdentityForSeed("stable").ipString(), netIdentityForSeed("stable").ipString(); a != b {
		t.Error("netIdentityForSeed must be deterministic")
	}
}

// TestProcNetTCPConsistent guards that /proc/net/tcp has the header, an sshd
// listener (port 22 = 0016), the persona services, and that its addresses decode
// to the box's own IP / localhost / 0.0.0.0 (never a leaked host address).
func TestProcNetTCPConsistent(t *testing.T) {
	for _, name := range []string{"db-server", "mail-server", "jump-bastion", "web-hosting"} {
		tmpl, _ := credentialTemplateByName(name)
		id := netIdentityForSeed("seedN")
		svcs := servicesForPersona(tmpl)
		out := procNetTCP(id, svcs, "seedN")
		if !strings.HasPrefix(out, "  sl  local_address") {
			t.Errorf("%s: /proc/net/tcp missing header", name)
		}
		if !strings.Contains(out, ":0016 ") {
			t.Errorf("%s: /proc/net/tcp has no sshd (port 22 = 0016) listener", name)
		}
		// Every local_address must be 0.0.0.0, 127.0.0.x or the box IP - never a
		// random/host-leaked address.
		for _, ln := range strings.Split(out, "\n") {
			f := strings.Fields(ln)
			if len(f) < 3 || !strings.HasSuffix(f[0], ":") {
				continue
			}
			la := strings.Split(f[1], ":")[0]
			ip := decodeLE(la)
			ok := (ip == [4]int{0, 0, 0, 0}) || ip[0] == 127 || ip == id.IP
			if !ok {
				t.Errorf("%s: /proc/net/tcp local address %v leaks a non-local IP", name, ip)
			}
		}
	}
	// Persona-specific service ports actually appear.
	checkPort := func(persona string, port int) {
		tmpl, _ := credentialTemplateByName(persona)
		out := procNetTCP(netIdentityForSeed("x"), servicesForPersona(tmpl), "x") +
			procNetUDP(netIdentityForSeed("x"), servicesForPersona(tmpl), "x")
		if !strings.Contains(out, fmt.Sprintf(":%04X ", port)) {
			t.Errorf("persona %s: expected service port %d not in /proc/net", persona, port)
		}
	}
	checkPort("db-server", 5432)
	checkPort("mail-server", 25)
	checkPort("nas-storage", 445)
	checkPort("voip-pbx", 5060)
}

// TestProcNetRouteArpConsistent guards route/arp reference the same gateway/iface
// as the identity, so `ip route`/`arp -a` recon agrees with the interface.
func TestProcNetRouteArpConsistent(t *testing.T) {
	id := netIdentityForSeed("seedR")
	route := procNetRoute(id)
	if !strings.Contains(route, id.Iface) {
		t.Errorf("route does not reference iface %q", id.Iface)
	}
	if !strings.Contains(route, "\t"+leHex(id.Gateway)+"\t") {
		t.Errorf("route default gateway %s (%s) not present:\n%s", id.gwString(), leHex(id.Gateway), route)
	}
	arp := procNetArp(id, "seedR")
	if !strings.Contains(arp, id.gwString()) {
		t.Errorf("arp cache does not list the gateway %s:\n%s", id.gwString(), arp)
	}
	if !strings.Contains(arp, id.Iface) {
		t.Errorf("arp does not reference iface %q", id.Iface)
	}
}

// TestNetConfigMatchesDistroAndIP guards the network config file is
// distro-appropriate and carries the identity's IP/gateway.
func TestNetConfigMatchesDistroAndIP(t *testing.T) {
	tmpl, _ := credentialTemplateByName("corp-ubuntu")
	for _, p := range distroProfiles {
		files := embeddedNetworkFiles(tmpl, p, "seedC")
		var cfg embeddedFile
		var found bool
		for _, f := range files {
			if strings.Contains(f.Path, "netplan") || strings.Contains(f.Path, "network/interfaces") {
				cfg, found = f, true
			}
		}
		if !found {
			t.Fatalf("%q: no network config emitted", p.OSPretty)
		}
		id := netIdentityForSeed("seedC")
		if !strings.Contains(cfg.Content, id.ipString()) {
			t.Errorf("%q: network config missing IP %s", p.OSPretty, id.ipString())
		}
		ubuntu := strings.Contains(strings.ToLower(p.OSPretty), "ubuntu")
		if ubuntu && !strings.Contains(cfg.Path, "netplan") {
			t.Errorf("%q: Ubuntu must use netplan, got %s", p.OSPretty, cfg.Path)
		}
		if !ubuntu && strings.Contains(cfg.Path, "netplan") {
			t.Errorf("%q: non-Ubuntu must not use netplan", p.OSPretty)
		}
	}
}

// TestProcNetNeverEmpty guards none of the /proc/net files come out empty (an
// empty file on a networked box is the tell we are fixing).
func TestProcNetNeverEmpty(t *testing.T) {
	tmpl, _ := credentialTemplateByName("corp-ubuntu")
	for _, f := range embeddedNetworkFiles(tmpl, distroProfiles[0], "seedE") {
		if strings.TrimSpace(f.Content) == "" {
			t.Errorf("%s came out empty", f.Path)
		}
	}
}
