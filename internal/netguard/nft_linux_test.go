//go:build linux

package netguard

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func TestPrivateCellHealthRejectsBroaderAndReorderedRules(t *testing.T) {
	iface := "br-cell01"
	allow := &nftables.Rule{Exprs: cellAccept(iface)}
	deny := &nftables.Rule{Exprs: jumpIfIface(iface, chainGuardCell)}
	if !validCellBaseRules([]*nftables.Rule{allow, deny}, iface, true) ||
		!validCellBaseRules([]*nftables.Rule{deny}, iface, false) {
		t.Fatal("same-cell forwarding and host-denial rules must be recognized")
	}
	if validCellBaseRules([]*nftables.Rule{deny, allow}, iface, true) {
		t.Fatal("drop before the in-cell exception is not a working cell")
	}
	cross := cellAccept(iface)
	cross[3] = &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameKey("br-cell02")}
	if validCellBaseRules([]*nftables.Rule{{Exprs: cross}, deny}, iface, true) {
		t.Fatal("a cross-cell allow must not pass the healthcheck")
	}
	legacy := &nftables.Rule{Exprs: jumpIfIface(iface, chainGuardForward)}
	if validCellBaseRules([]*nftables.Rule{allow, legacy}, iface, true) ||
		validCellBaseRules([]*nftables.Rule{legacy}, iface, false) {
		t.Fatal("ordinary egress/DNS policy is not the private-cell policy")
	}
	guard := []*nftables.Rule{{Exprs: ctEstablishedAccept()}, {Exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}}}}
	if !validCellGuard(guard) {
		t.Fatal("established replies followed by drop must be recognized")
	}
	guard[1].Exprs[1] = &expr.Verdict{Kind: expr.VerdictAccept}
	if validCellGuard(guard) {
		t.Fatal("a permissive final verdict must fail private-cell health")
	}
}

// TestResolverElementsHoldWireServer: the dns4 set always holds the Azure
// WireServer, also when the host's resolv.conf names no resolver at all.
func TestResolverElementsHoldWireServer(t *testing.T) {
	wire := AzureWireServer.As4()
	for _, dns := range [][]netip.Addr{nil, {netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("fd00::53")}} {
		d4, d6 := resolverElements(Spec{DNS: dns})
		found := 0
		for _, e := range d4 {
			if bytes.Equal(e.Key, wire[:]) {
				found++
			}
		}
		if found != 1 {
			t.Errorf("DNS %v: the WireServer is in dns4 %d times", dns, found)
		}
		if len(d4)+len(d6) != len(dns)+1 {
			t.Errorf("DNS %v: %d+%d set elements", dns, len(d4), len(d6))
		}
	}
}

// TestGuardRulesAcceptDNSBeforeDrops: in both chains and both modes the DNS
// accepts come before every drop, so DNS to a blocked resolver (the
// WireServer, a resolver on the LAN) still passes, and the WireServer's
// other ports meet a drop in guard_forward.
func TestGuardRulesAcceptDNSBeforeDrops(t *testing.T) {
	dns4 := &nftables.Set{Name: "dns4"}
	dns6 := &nftables.Set{Name: "dns6"}
	wire := AzureWireServer.As4()
	for _, mode := range []Mode{ModePrivate, ModeAll} {
		for _, forward := range []bool{true, false} {
			rules := guardRules(Spec{Mode: mode}, forward, dns4, dns6)
			lastDNS, firstDrop, dnsRules, wireDrop := -1, len(rules), 0, false
			for i, r := range rules {
				v, ok := r[len(r)-1].(*expr.Verdict)
				if !ok {
					t.Fatalf("%s forward=%v: rule %d has no verdict", mode, forward, i)
				}
				switch {
				case v.Kind == expr.VerdictAccept && usesSet(r):
					dnsRules++
					lastDNS = i
				case v.Kind == expr.VerdictDrop:
					firstDrop = min(firstDrop, i)
					if dropsExactly(r, wire[:]) {
						wireDrop = true
					}
				}
			}
			if dnsRules != 4 || lastDNS > firstDrop {
				t.Errorf("%s forward=%v: %d DNS accepts, last at %d, first drop at %d", mode, forward, dnsRules, lastDNS, firstDrop)
			}
			if firstDrop == len(rules) {
				t.Errorf("%s forward=%v: no drop", mode, forward)
			}
			// ModePrivate's forward chain drops by prefix; the others drop
			// everything left, the WireServer included.
			if mode == ModePrivate && forward && !wireDrop {
				t.Errorf("guard_forward has no drop for %v/32", AzureWireServer)
			}
		}
	}
}

func usesSet(r []expr.Any) bool {
	for _, e := range r {
		if _, ok := e.(*expr.Lookup); ok {
			return true
		}
	}
	return false
}

// dropsExactly reports whether r is a dropPrefix rule for addr/32.
func dropsExactly(r []expr.Any, addr []byte) bool {
	full := false
	for _, e := range r {
		switch x := e.(type) {
		case *expr.Bitwise:
			full = bytes.Equal(x.Mask, []byte{0xff, 0xff, 0xff, 0xff})
		case *expr.Cmp:
			if full && bytes.Equal(x.Data, addr) {
				return true
			}
		}
	}
	return false
}
