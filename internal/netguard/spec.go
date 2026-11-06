// Package netguard keeps honeypot containers from reaching the networks around
// the host. Every QPot honeypot sits on its own docker bridge with a normal
// gateway, because published ports need one. Without a guard, a honeypot that
// fetches what an attacker asks for (cowrie's wget and curl, dionaea's and
// adbhoney's downloaders) or one an attacker breaks out of can open connections
// to the owner's LAN, router, other containers, the docker host and cloud
// metadata endpoints.
//
// The guard is an nftables table in the host's network namespace that matches
// traffic entering the host from the instance's honeypot bridges and drops new
// connections to non-public addresses and to the host itself. Replies to
// attackers' connections still flow, and public destinations stay reachable
// unless the table blocks all outbound connections. DNS stays possible to the
// host's resolvers, which docker's embedded DNS server queries from the
// container's namespace.
package netguard

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// Mode selects what the guard blocks.
type Mode string

const (
	// ModePrivate drops new connections to non-public addresses and to the
	// host; public destinations stay reachable.
	ModePrivate Mode = "private"
	// ModeAll drops every new outbound connection except DNS to the host's
	// resolvers.
	ModeAll Mode = "all"
)

// Spec describes one instance's guard.
type Spec struct {
	// Table is the nftables table (family inet) the guard owns.
	Table string
	// Ifaces are the host-side bridge interfaces of the honeypot networks.
	Ifaces []string
	Mode   Mode
	// DNS are the resolvers honeypot containers may reach on port 53.
	DNS []netip.Addr
}

var (
	tableRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	ifaceRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)
)

// MaxIfaces bounds the bridge list (one per honeypot of an instance).
const MaxIfaces = 256

// Validate rejects a spec the guard must not apply.
func (s Spec) Validate() error {
	if !tableRe.MatchString(s.Table) {
		return fmt.Errorf("netguard: bad table name %q", s.Table)
	}
	if s.Mode != ModePrivate && s.Mode != ModeAll {
		return fmt.Errorf("netguard: bad mode %q", s.Mode)
	}
	if len(s.Ifaces) == 0 || len(s.Ifaces) > MaxIfaces {
		return fmt.Errorf("netguard: need 1-%d interfaces, got %d", MaxIfaces, len(s.Ifaces))
	}
	seen := map[string]bool{}
	for _, i := range s.Ifaces {
		if !ifaceRe.MatchString(i) {
			return fmt.Errorf("netguard: bad interface name %q", i)
		}
		if seen[i] {
			return fmt.Errorf("netguard: interface %q listed twice", i)
		}
		seen[i] = true
	}
	for _, a := range s.DNS {
		if !a.IsValid() || a.Zone() != "" || a.Is4In6() {
			return fmt.Errorf("netguard: bad resolver %v", a)
		}
	}
	return nil
}

// ParseIfaces splits a comma-separated interface list, dropping blanks.
func ParseIfaces(v string) []string {
	var out []string
	for _, f := range strings.Split(v, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// ParseResolvConf returns the nameservers of a resolv.conf that honeypot
// containers' DNS may be forwarded to: loopback resolvers are left out, since
// docker queries those from the host's namespace, where the guard does not
// apply. Zones are dropped and IPv4-mapped addresses unmapped.
func ParseResolvConf(r io.Reader) ([]netip.Addr, error) {
	var out []netip.Addr
	sc := bufio.NewScanner(io.LimitReader(r, 1<<16))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		a, err := netip.ParseAddr(f[1])
		if err != nil {
			continue
		}
		a = a.WithZone("").Unmap()
		if a.IsLoopback() || a.IsUnspecified() || slices.Contains(out, a) {
			continue
		}
		out = append(out, a)
		if len(out) == 16 {
			break
		}
	}
	return out, sc.Err()
}

// blocked4 and blocked6 are the destinations a honeypot must not open new
// connections to in ModePrivate: everything that is not ordinary public
// address space (RFC 6890 special-purpose blocks).
var (
	blocked4 = mustPrefixes(
		"0.0.0.0/8",      // "this network"
		"10.0.0.0/8",     // private
		"100.64.0.0/10",  // carrier-grade NAT
		"127.0.0.0/8",    // loopback
		"169.254.0.0/16", // link-local, cloud metadata (169.254.169.254)
		"172.16.0.0/12",  // private, docker's default pools
		"192.0.0.0/24",   // IETF protocol assignments
		"192.168.0.0/16", // private
		"198.18.0.0/15",  // benchmarking
		"224.0.0.0/4",    // multicast
		"240.0.0.0/4",    // reserved, broadcast
	)
	blocked6 = mustPrefixes(
		"::/127",         // unspecified, loopback
		"::ffff:0:0/96",  // IPv4-mapped
		"64:ff9b:1::/48", // local-use NAT64
		"fc00::/7",       // unique local
		"fe80::/10",      // link-local
		"ff00::/8",       // multicast
	)
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// Blocked reports whether ModePrivate drops a new connection to a: the
// reference the nftables rules implement, used by the tests.
func Blocked(a netip.Addr) bool {
	a = a.Unmap()
	list := blocked6
	if a.Is4() {
		list = blocked4
	}
	for _, p := range list {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
