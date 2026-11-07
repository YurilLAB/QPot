package netguard

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	ok := Spec{Table: "qpot_egress_ab12", Ifaces: []string{"br-cowrie1a2b", "br-conpot99ff"}, Mode: ModePrivate,
		DNS: []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("fd00::53")}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}
	all := ok
	all.Mode = ModeAll
	if err := all.Validate(); err != nil {
		t.Fatalf("ModeAll rejected: %v", err)
	}
	bad := map[string]Spec{
		"empty table":      {Table: "", Ifaces: ok.Ifaces, Mode: ModePrivate},
		"table injection":  {Table: "x; flush ruleset", Ifaces: ok.Ifaces, Mode: ModePrivate},
		"table uppercase":  {Table: "Qpot", Ifaces: ok.Ifaces, Mode: ModePrivate},
		"table too long":   {Table: "q" + strings.Repeat("a", 32), Ifaces: ok.Ifaces, Mode: ModePrivate},
		"no ifaces":        {Table: "t", Mode: ModePrivate},
		"iface too long":   {Table: "t", Ifaces: []string{"br-0123456789abc"}, Mode: ModePrivate},
		"iface wildcard":   {Table: "t", Ifaces: []string{"br-*"}, Mode: ModePrivate},
		"iface space":      {Table: "t", Ifaces: []string{"br x"}, Mode: ModePrivate},
		"iface duplicated": {Table: "t", Ifaces: []string{"br-a", "br-a"}, Mode: ModePrivate},
		"bad mode":         {Table: "t", Ifaces: ok.Ifaces, Mode: "off"},
		"empty mode":       {Table: "t", Ifaces: ok.Ifaces},
		"zoned resolver":   {Table: "t", Ifaces: ok.Ifaces, Mode: ModePrivate, DNS: []netip.Addr{netip.MustParseAddr("fe80::1%eth0")}},
		"mapped resolver":  {Table: "t", Ifaces: ok.Ifaces, Mode: ModePrivate, DNS: []netip.Addr{netip.MustParseAddr("::ffff:10.0.0.1")}},
		"invalid resolver": {Table: "t", Ifaces: ok.Ifaces, Mode: ModePrivate, DNS: []netip.Addr{{}}},
	}
	for name, s := range bad {
		if err := s.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	many := Spec{Table: "t", Mode: ModePrivate}
	for i := 0; i <= MaxIfaces; i++ {
		many.Ifaces = append(many.Ifaces, "br-"+strings.Repeat("x", 1)+string(rune('a'+i%26))+strings.Repeat("y", i%5)+itoa(i))
	}
	if err := many.Validate(); err == nil {
		t.Error("more than MaxIfaces interfaces accepted")
	}
}

func itoa(i int) string {
	const d = "0123456789"
	if i < 10 {
		return d[i : i+1]
	}
	return itoa(i/10) + d[i%10:i%10+1]
}

func TestParseIfaces(t *testing.T) {
	got := ParseIfaces(" br-a, ,br-b,,")
	if len(got) != 2 || got[0] != "br-a" || got[1] != "br-b" {
		t.Fatalf("ParseIfaces = %q", got)
	}
}

func TestParseResolvConf(t *testing.T) {
	in := `# comment
nameserver 127.0.0.53
nameserver 192.168.1.1
nameserver 192.168.1.1
nameserver fe80::1%eth0
nameserver ::ffff:10.0.0.2
nameserver ::1
nameserver 0.0.0.0
nameserver not-an-ip
search lan
options edns0
nameserver 9.9.9.9
`
	got, err := ParseResolvConf(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.168.1.1", "fe80::1", "10.0.0.2", "9.9.9.9"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i].String() != w {
			t.Errorf("resolver %d = %v, want %s", i, got[i], w)
		}
	}
	// Whatever it returns must pass Validate.
	s := Spec{Table: "t", Ifaces: []string{"br-a"}, Mode: ModePrivate, DNS: got}
	if err := s.Validate(); err != nil {
		t.Errorf("parsed resolvers fail Validate: %v", err)
	}
}

func TestBlocked(t *testing.T) {
	cases := map[string]bool{
		"10.1.2.3":             true,
		"172.16.0.1":           true,
		"172.31.255.255":       true,
		"172.32.0.1":           false,
		"192.168.1.1":          true,
		"169.254.169.254":      true, // cloud metadata
		"100.64.0.1":           true,
		"100.128.0.1":          false,
		"127.0.0.1":            true,
		"0.0.0.0":              true,
		"224.0.0.251":          true,
		"255.255.255.255":      true,
		"8.8.8.8":              false,
		"1.1.1.1":              false,
		"192.0.2.1":            false, // documentation range, not reachable but public space
		"fd12::1":              true,
		"fe80::1":              true,
		"::1":                  true,
		"ff02::1":              true,
		"::ffff:10.0.0.1":      true,
		"::ffff:8.8.8.8":       false,
		"2001:4860:4860::8888": false,

		// Cloud platform endpoints.
		"168.63.129.16":   true, // Azure WireServer
		"168.63.129.15":   false,
		"168.63.129.17":   false,
		"169.254.0.23":    true, // Tencent metadata
		"100.100.100.200": true, // Alibaba metadata
		"169.254.169.123": true, // AWS time sync
		"fd00:ec2::254":   true, // AWS metadata over IPv6
		"fd00:ec2::253":   true, // AWS resolver over IPv6
	}
	for a, want := range cases {
		if got := Blocked(netip.MustParseAddr(a)); got != want {
			t.Errorf("Blocked(%s) = %v, want %v", a, got, want)
		}
	}
}

// TestResolversKeepAzureDNS: the WireServer is blocked, so DNS to it must be
// accepted whatever the host's resolv.conf says, or honeypots on Azure lose
// DNS; and listing it among the resolvers changes nothing.
func TestResolversKeepAzureDNS(t *testing.T) {
	if !Blocked(AzureWireServer) {
		t.Fatal("the Azure WireServer is not blocked")
	}
	home := []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("fd00::53")}
	for name, dns := range map[string][]netip.Addr{
		"no resolvers":       nil,
		"home router":        home,
		"azure resolv.conf":  {AzureWireServer},
		"wireserver and lan": {netip.MustParseAddr("10.0.0.2"), AzureWireServer},
	} {
		s := Spec{Table: "t", Ifaces: []string{"br-a"}, Mode: ModePrivate, DNS: slices.Clone(dns)}
		got := s.Resolvers()
		if n := countAddr(got, AzureWireServer); n != 1 {
			t.Errorf("%s: the WireServer is listed %d times in %v", name, n, got)
		}
		if !slices.Equal(got[:len(dns)], dns) {
			t.Errorf("%s: resolvers %v do not start with the host's %v", name, got, dns)
		}
		if !slices.Equal(s.DNS, dns) {
			t.Errorf("%s: Resolvers changed s.DNS to %v", name, s.DNS)
		}
		if err := (Spec{Table: "t", Ifaces: []string{"br-a"}, Mode: ModeAll, DNS: got}).Validate(); err != nil {
			t.Errorf("%s: resolvers fail Validate: %v", name, err)
		}
	}
}

func countAddr(list []netip.Addr, a netip.Addr) int {
	n := 0
	for _, x := range list {
		if x == a {
			n++
		}
	}
	return n
}

// TestBlockedPrefixesAreCanonical: the nftables rules match "daddr & mask ==
// prefix address", which only works when the prefix has no host bits set.
func TestBlockedPrefixesAreCanonical(t *testing.T) {
	for _, p := range append(append([]netip.Prefix{}, blocked4...), blocked6...) {
		if p != p.Masked() {
			t.Errorf("%v is not canonical (%v)", p, p.Masked())
		}
	}
}

func FuzzParseResolvConf(f *testing.F) {
	f.Add("nameserver 192.168.1.1\n")
	f.Add("nameserver fe80::1%eth0\nnameserver ::ffff:1.2.3.4\n")
	f.Add(strings.Repeat("nameserver 10.0.0.1\n", 40))
	f.Fuzz(func(t *testing.T, in string) {
		got, err := ParseResolvConf(strings.NewReader(in))
		if err != nil {
			return
		}
		if len(got) > 16 {
			t.Fatalf("%d resolvers", len(got))
		}
		s := Spec{Table: "t", Ifaces: []string{"br-a"}, Mode: ModePrivate, DNS: got}
		if err := s.Validate(); err != nil {
			t.Fatalf("parsed resolvers %v fail Validate: %v", got, err)
		}
	})
}

func FuzzValidate(f *testing.F) {
	f.Add("qpot_egress_1", "br-cowrie1a2b,br-x", "private")
	f.Add("x;y", "br-*", "all")
	f.Fuzz(func(t *testing.T, table, ifaces, mode string) {
		s := Spec{Table: table, Ifaces: ParseIfaces(ifaces), Mode: Mode(mode)}
		if s.Validate() != nil {
			return
		}
		// Anything accepted is safe to hand to netlink as names.
		if !tableRe.MatchString(s.Table) || len(s.Table) > 32 {
			t.Fatalf("table %q accepted", s.Table)
		}
		for _, i := range s.Ifaces {
			if len(i) > 15 || strings.ContainsAny(i, " *;,\x00") {
				t.Fatalf("interface %q accepted", i)
			}
		}
	})
}
