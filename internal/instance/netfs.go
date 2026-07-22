package instance

// netfs.go generates a per-instance network stack for Cowrie's fake filesystem:
// /proc/net/{tcp,tcp6,udp,route,arp,dev} and the distro's network config. These
// are the files `cat /proc/net/tcp`, `ip route` readers, `arp -a` and interface
// recon actually read, and stock Cowrie ships them empty (or globally identical),
// so a box the attacker just SSH'd into appears to have NO sockets, NO routes and
// NO neighbours - a direct tell.
//
// The whole stack is derived from ONE per-instance network identity (a private
// IP drawn from a MIXTURE of the three RFC-1918 ranges, a seed-picked interface
// name and a virtualization-vendor MAC) plus a persona-driven MIXTURE of listening
// services, so:
//   - no two QPot deployments present the same IP / MAC / interface / socket set
//     (defeats signature-matching that keys on identical network responses), and
//   - every file agrees with the others and with the on-disk evidence: the routes,
//     ARP gateway and interface counters all reference the same IP/subnet, and the
//     open ports match the persona's service accounts in /etc/passwd.
//
// Content is served through the same realfile mechanism as the rest of the fake
// fs (see cowriefs.go), so these are added to the container-start patch.

import (
	"fmt"
	"hash/fnv"
	"strings"
)

// netIdentity is one instance's coherent network identity. Everything else in
// /proc/net derives from it, so the whole stack tells one story.
type netIdentity struct {
	Iface     string // interface name (eth0/ens3/enp0s3/...)
	IP        [4]int // this host's private IPv4
	PrefixLen int    // subnet prefix (usually 24)
	Gateway   [4]int // default gateway (.1 of the subnet)
	MAC       string // interface hardware address
}

// ifaceNames is a MIXTURE of the interface-naming conventions real Linux boxes
// use: classic eth0, systemd predictable names on cloud/KVM (ens3/ens5), and
// PCI-slot names (enp0s3). The seed picks one so deployments differ.
var ifaceNames = []string{"eth0", "ens3", "ens5", "enp0s3", "enp1s0", "eth0"}

// macOUIs is a MIXTURE of hypervisor MAC prefixes (the cpuinfo already presents a
// KVM guest, so these are all virtualization vendors): QEMU/KVM 52:54:00, Xen
// 00:16:3e, VMware 00:0c:29 / 00:50:56, and a locally-administered 02: prefix
// (common on cloud instances). The seed picks one.
var macOUIs = []string{"52:54:00", "00:16:3e", "00:0c:29", "00:50:56", "02:42:ac", "52:54:00"}

// privateRanges is the MIXTURE of RFC-1918 space instances are placed in: the
// 10/8 (cloud/corp), 172.16/12 and 192.168/16 (SOHO). The seed picks a family
// and then the specific octets, so two deployments almost never share a subnet.
func netIdentityForSeed(seed string) netIdentity {
	h := func(salt string) uint32 {
		f := fnv.New32a()
		_, _ = f.Write([]byte(salt + ":" + seed))
		return f.Sum32()
	}
	var ip, gw [4]int
	switch seededIndex("netrange:"+seed, 3) {
	case 0: // 10.a.b.0/24
		a, b := int(h("na")%256), int(h("nb")%256)
		ip = [4]int{10, a, b, 2 + int(h("nh")%250)}
		gw = [4]int{10, a, b, 1}
	case 1: // 172.(16-31).b.0/24
		a, b := 16+int(h("na")%16), int(h("nb")%256)
		ip = [4]int{172, a, b, 2 + int(h("nh")%250)}
		gw = [4]int{172, a, b, 1}
	default: // 192.168.b.0/24
		b := int(h("nb") % 256)
		ip = [4]int{192, 168, b, 2 + int(h("nh")%250)}
		gw = [4]int{192, 168, b, 1}
	}
	oui := macOUIs[seededIndex("macoui:"+seed, len(macOUIs))]
	m := h("mac")
	mac := fmt.Sprintf("%s:%02x:%02x:%02x", oui, (m>>16)&0xff, (m>>8)&0xff, m&0xff)
	return netIdentity{
		Iface:     ifaceNames[seededIndex("iface:"+seed, len(ifaceNames))],
		IP:        ip,
		PrefixLen: 24,
		Gateway:   gw,
		MAC:       mac,
	}
}

func (n netIdentity) ipString() string {
	return fmt.Sprintf("%d.%d.%d.%d", n.IP[0], n.IP[1], n.IP[2], n.IP[3])
}
func (n netIdentity) gwString() string {
	return fmt.Sprintf("%d.%d.%d.%d", n.Gateway[0], n.Gateway[1], n.Gateway[2], n.Gateway[3])
}

// leHex renders an IPv4 as the little-endian 8-hex-digit form /proc/net/tcp uses
// (e.g. 127.0.0.1 -> "0100007F", 10.0.0.5 -> "0500000A").
func leHex(ip [4]int) string {
	return fmt.Sprintf("%02X%02X%02X%02X", ip[3]&0xff, ip[2]&0xff, ip[1]&0xff, ip[0]&0xff)
}

// service is one listening socket the box exposes.
type service struct {
	Port  int
	Bind  [4]int // 0.0.0.0 (all) or 127.0.0.1 (localhost-only)
	Proto string // "tcp" or "udp"
}

var (
	anyAddr   = [4]int{0, 0, 0, 0}
	localAddr = [4]int{127, 0, 0, 1}
	stubDNS   = [4]int{127, 0, 0, 53} // systemd-resolved stub
)

// personaServices maps a persona to the MIXTURE of services it listens on, tied
// to the role its /etc/passwd service accounts imply. sshd(22) is added for every
// box; systemd-resolved's 127.0.0.53:53 is added for the Ubuntu-style resolver.
// Localhost-only binds (databases, metrics) vs 0.0.0.0 binds add realism.
var personaServices = map[string][]service{
	"web-hosting":      {{80, anyAddr, "tcp"}, {443, anyAddr, "tcp"}, {3306, localAddr, "tcp"}, {2083, anyAddr, "tcp"}},
	"wordpress-lamp":   {{80, anyAddr, "tcp"}, {443, anyAddr, "tcp"}, {3306, localAddr, "tcp"}},
	"nextcloud":        {{80, anyAddr, "tcp"}, {443, anyAddr, "tcp"}, {3306, localAddr, "tcp"}, {6379, localAddr, "tcp"}},
	"db-server":        {{5432, anyAddr, "tcp"}, {3306, localAddr, "tcp"}, {1521, anyAddr, "tcp"}},
	"mail-server":      {{25, anyAddr, "tcp"}, {587, anyAddr, "tcp"}, {143, anyAddr, "tcp"}, {993, anyAddr, "tcp"}, {110, anyAddr, "tcp"}, {995, anyAddr, "tcp"}},
	"k8s-node":         {{10250, anyAddr, "tcp"}, {10256, anyAddr, "tcp"}, {6443, anyAddr, "tcp"}},
	"monitoring-stack": {{3000, anyAddr, "tcp"}, {9090, anyAddr, "tcp"}, {9100, anyAddr, "tcp"}, {10051, anyAddr, "tcp"}},
	"gitlab-devops":    {{80, anyAddr, "tcp"}, {443, anyAddr, "tcp"}, {5432, localAddr, "tcp"}, {6379, localAddr, "tcp"}},
	"docker-host":      {{2375, localAddr, "tcp"}, {80, anyAddr, "tcp"}},
	"proxmox-host":     {{8006, anyAddr, "tcp"}, {3128, anyAddr, "tcp"}},
	"voip-pbx":         {{5060, anyAddr, "udp"}, {5061, anyAddr, "tcp"}, {80, anyAddr, "tcp"}, {10000, anyAddr, "udp"}},
	"ftp-fileserver":   {{21, anyAddr, "tcp"}, {20, anyAddr, "tcp"}},
	"nas-storage":      {{80, anyAddr, "tcp"}, {443, anyAddr, "tcp"}, {445, anyAddr, "tcp"}, {139, anyAddr, "tcp"}, {2049, anyAddr, "tcp"}},
	"media-server":     {{32400, anyAddr, "tcp"}, {8096, anyAddr, "tcp"}},
	"message-broker":   {{9092, anyAddr, "tcp"}, {2181, anyAddr, "tcp"}, {5672, anyAddr, "tcp"}},
	"vpn-gateway":      {{1194, anyAddr, "udp"}, {51820, anyAddr, "udp"}, {443, anyAddr, "tcp"}},
	"unifi-controller": {{8443, anyAddr, "tcp"}, {8080, anyAddr, "tcp"}, {8843, anyAddr, "tcp"}},
	"home-assistant":   {{8123, anyAddr, "tcp"}},
	"corp-ubuntu":      {{80, anyAddr, "tcp"}, {8080, anyAddr, "tcp"}},
	"dev-ci":           {{8080, anyAddr, "tcp"}, {3000, anyAddr, "tcp"}},
	"jump-bastion":     {},
	"edge-router":      {{80, anyAddr, "tcp"}, {443, anyAddr, "tcp"}, {53, anyAddr, "udp"}},
	"soho-router":      {{80, anyAddr, "tcp"}, {53, anyAddr, "udp"}},
}

// servicesForPersona returns the box's full listening set: sshd(22), the
// systemd-resolved stub, and the persona's role services. The result is stable
// per persona (a real box's listener set does not change between logins) but
// differs across personas - a MIXTURE, not one universal set.
func servicesForPersona(t credentialTemplate) []service {
	out := []service{{22, anyAddr, "tcp"}} // sshd, always
	out = append(out, service{53, stubDNS, "udp"}, service{53, stubDNS, "tcp"})
	out = append(out, personaServices[t.Name]...)
	return out
}

// procNetTCP renders /proc/net/tcp: the header, sshd + persona TCP listeners, and
// a couple of ESTABLISHED sessions to the internal hosts the ~/.ssh/known_hosts
// breadcrumbs reference (so the network state corroborates the shell history).
func procNetTCP(id netIdentity, svcs []service, seed string) string {
	var b strings.Builder
	b.WriteString("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	sl := 0
	inode := 10000 + seededIndex("tcpinode:"+seed, 40000)
	line := func(la [4]int, lport int, ra [4]int, rport, st, uid int) {
		fmt.Fprintf(&b, "%4d: %s:%04X %s:%04X %02X 00000000:00000000 00:00000000 00000000 %5d        0 %d 1 0000000000000000 100 0 0 10 0\n",
			sl, leHex(la), lport, leHex(ra), rport, st, uid, inode)
		sl++
		inode += 7 + seededIndex(fmt.Sprintf("in:%d:", sl)+seed, 90)
	}
	for _, s := range svcs {
		if s.Proto != "tcp" {
			continue
		}
		uid := 0
		if s.Port == 22 {
			uid = 0
		} else if s.Port >= 1024 {
			uid = 1000 // user-run service
		}
		line(s.Bind, s.Port, anyAddr, 0, 0x0A, uid) // 0A = LISTEN
	}
	// An established outbound admin session to an internal host (10.0.0.5-style),
	// matching the known_hosts/history breadcrumbs; and the current inbound ssh.
	line(id.IP, 22, id.Gateway, 40000+seededIndex("rp1:"+seed, 20000), 0x01, 0)
	line(id.IP, 51000+seededIndex("lp:"+seed, 4000), [4]int{10, 0, 0, 5}, 22, 0x01, 1000)
	return b.String()
}

// procNetTCP6 renders a minimal but present /proc/net/tcp6 (sshd on :: and the
// loopback), so a modern dual-stack box does not show an empty file.
func procNetTCP6(seed string) string {
	var b strings.Builder
	b.WriteString("  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	inode := 12000 + seededIndex("tcp6inode:"+seed, 30000)
	// sshd on [::]:22 LISTEN.
	fmt.Fprintf(&b, "   0: %032X:0016 %032X:0000 0A 00000000:00000000 00:00000000 00000000     0        0 %d 1 0000000000000000 100 0 0 10 0\n", 0, 0, inode)
	return b.String()
}

// procNetUDP renders /proc/net/udp for the box's UDP listeners (systemd-resolved
// and any persona UDP services).
func procNetUDP(id netIdentity, svcs []service, seed string) string {
	var b strings.Builder
	b.WriteString("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n")
	sl := 0
	inode := 9000 + seededIndex("udpinode:"+seed, 40000)
	for _, s := range svcs {
		if s.Proto != "udp" {
			continue
		}
		uid := 0
		if s.Port >= 1024 {
			uid = 1000
		}
		fmt.Fprintf(&b, "%4d: %s:%04X 00000000:0000 07 00000000:00000000 00:00000000 00000000 %5d        0 %d 2 0000000000000000 0\n",
			sl, leHex(s.Bind), s.Port, uid, inode)
		sl++
		inode += 11
	}
	return b.String()
}

// procNetRoute renders /proc/net/route: the default route via the gateway and the
// on-link subnet, both on the box's interface. `ip route` and `route -n` readers
// (and `cat /proc/net/route`) expect this; an empty file on a box that is reachable
// is a tell. Addresses are little-endian hex, as the kernel writes them.
func procNetRoute(id netIdentity) string {
	iface := id.Iface
	// Destination 00000000 = default; Gateway = gw LE hex; Flags 0003 (UP|GATEWAY).
	// Subnet route: Destination = network LE hex, Gateway 0, Flags 0001 (UP), Mask /24.
	net := [4]int{id.IP[0], id.IP[1], id.IP[2], 0}
	var b strings.Builder
	b.WriteString("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n")
	fmt.Fprintf(&b, "%s\t00000000\t%s\t0003\t0\t0\t100\t00000000\t0\t0\t0\n", iface, leHex(id.Gateway))
	fmt.Fprintf(&b, "%s\t%s\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n", iface, leHex(net))
	return b.String()
}

// procNetArp renders /proc/net/arp: the default gateway plus a neighbour or two,
// with per-instance MACs. `arp -a`/`ip neigh` and `cat /proc/net/arp` read this.
func procNetArp(id netIdentity, seed string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte("arpmac:" + seed))
	v := h.Sum32()
	gwMAC := fmt.Sprintf("00:16:3e:%02x:%02x:%02x", (v>>16)&0xff, (v>>8)&0xff, v&0xff)
	peer := [4]int{id.IP[0], id.IP[1], id.IP[2], 3 + seededIndex("peer:"+seed, 200)}
	peerMAC := fmt.Sprintf("52:54:00:%02x:%02x:%02x", (v>>8)&0xff, v&0xff, (v>>20)&0xff)
	var b strings.Builder
	b.WriteString("IP address       HW type     Flags       HW address            Mask     Device\n")
	fmt.Fprintf(&b, "%-16s 0x1         0x2         %-21s *        %s\n", id.gwString(), gwMAC, id.Iface)
	fmt.Fprintf(&b, "%-16s 0x1         0x2         %-21s *        %s\n",
		fmt.Sprintf("%d.%d.%d.%d", peer[0], peer[1], peer[2], peer[3]), peerMAC, id.Iface)
	return b.String()
}

// procNetDev renders /proc/net/dev interface counters for lo and the box's
// interface, with per-instance (believable, non-round) byte/packet totals so two
// deployments never report identical traffic and the box looks genuinely used.
func procNetDev(id netIdentity, seed string) string {
	h := func(s string) uint32 {
		f := fnv.New32a()
		_, _ = f.Write([]byte(s + ":" + seed))
		return f.Sum32()
	}
	rxB := 1_000_000 + int64(h("rxb"))%900_000_000
	txB := 800_000 + int64(h("txb"))%700_000_000
	rxP := 5000 + int64(h("rxp"))%4_000_000
	txP := 4000 + int64(h("txp"))%3_000_000
	loB := 100_000 + int64(h("lob"))%5_000_000
	loP := 1000 + int64(h("lop"))%40000
	var b strings.Builder
	b.WriteString("Inter-|   Receive                                                |  Transmit\n")
	b.WriteString(" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n")
	fmt.Fprintf(&b, "    lo: %8d %7d    0    0    0     0          0         0 %8d %7d    0    0    0     0       0          0\n", loB, loP, loB, loP)
	fmt.Fprintf(&b, "%6s: %8d %7d    0    0    0     0          0     %5d %8d %7d    0    0    0     0       0          0\n",
		id.Iface, rxB, rxP, seededIndex("mc:"+seed, 900), txB, txP)
	return b.String()
}

// netplanYAML / interfacesFile render the distro's network configuration
// consistent with the identity: Ubuntu uses netplan, Debian uses
// /etc/network/interfaces. `cat` of these is common recon and an empty config on
// a box with a working network is a tell.
func netplanYAML(id netIdentity) string {
	return fmt.Sprintf(`# This is the network config written by 'subiquity'
network:
  version: 2
  ethernets:
    %s:
      dhcp4: false
      addresses:
        - %s/%d
      routes:
        - to: default
          via: %s
      nameservers:
        addresses:
          - %s
          - 1.1.1.1
`, id.Iface, id.ipString(), id.PrefixLen, id.gwString(), id.gwString())
}

func interfacesFile(id netIdentity) string {
	return fmt.Sprintf(`# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto %s
iface %s inet static
    address %s
    netmask 255.255.255.0
    gateway %s
    dns-nameservers %s 1.1.1.1
`, id.Iface, id.Iface, id.ipString(), id.gwString(), id.gwString())
}

// embeddedNetworkFiles returns the per-instance /proc/net stack and network
// config as embedded files (served via the fs-patch realfile mechanism).
func embeddedNetworkFiles(t credentialTemplate, p distroProfile, seed string) []embeddedFile {
	id := netIdentityForSeed(seed)
	svcs := servicesForPersona(t)
	files := []embeddedFile{
		{Path: "/proc/net/tcp", UID: 0, GID: 0, Mode: 0o100444, Content: procNetTCP(id, svcs, seed)},
		{Path: "/proc/net/tcp6", UID: 0, GID: 0, Mode: 0o100444, Content: procNetTCP6(seed)},
		{Path: "/proc/net/udp", UID: 0, GID: 0, Mode: 0o100444, Content: procNetUDP(id, svcs, seed)},
		{Path: "/proc/net/route", UID: 0, GID: 0, Mode: 0o100444, Content: procNetRoute(id)},
		{Path: "/proc/net/arp", UID: 0, GID: 0, Mode: 0o100444, Content: procNetArp(id, seed)},
		{Path: "/proc/net/dev", UID: 0, GID: 0, Mode: 0o100444, Content: procNetDev(id, seed)},
	}
	// Distro-appropriate network config (Ubuntu: netplan, Debian: interfaces).
	if strings.Contains(strings.ToLower(p.OSPretty), "ubuntu") {
		files = append(files, embeddedFile{Path: "/etc/netplan/00-installer-config.yaml", UID: 0, GID: 0, Mode: 0o100600, Content: netplanYAML(id)})
	} else {
		files = append(files, embeddedFile{Path: "/etc/network/interfaces", UID: 0, GID: 0, Mode: 0o100644, Content: interfacesFile(id)})
	}
	return files
}
