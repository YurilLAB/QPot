//go:build linux

package netguard

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// The guard's table holds two base chains that send traffic from the honeypot
// bridges to its own chains:
//
//	table inet <name> {
//	  set dns4 { type ipv4_addr }         the host's resolvers
//	  set dns6 { type ipv6_addr }
//	  chain forward { type filter hook forward priority -10; iifname "<bridge>" jump guard_forward ... }
//	  chain input   { type filter hook input   priority -10; iifname "<bridge>" jump guard_input ... }
//	  chain guard_forward { ct state established,related accept; DNS to @dns4/@dns6 accept;
//	                        ip daddr <blocked prefix> counter drop ... (ModeAll: counter drop) }
//	  chain guard_input   { ct state established,related accept; DNS to @dns4/@dns6 accept; counter drop }
//	}
//
// The base chains' policy is accept, so the table never drops anything that
// does not come from a honeypot bridge, and docker's own chains still run.
const (
	chainForward      = "forward"
	chainInput        = "input"
	chainGuardForward = "guard_forward"
	chainGuardInput   = "guard_input"
	basePriority      = -10
)

// Apply installs or replaces the guard's table in one netlink transaction, so
// there is no moment without rules once the table first exists.
func Apply(s Spec) error {
	if err := s.Validate(); err != nil {
		return err
	}
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("netguard: netlink: %w", err)
	}
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: s.Table}
	// Add (no-op if present), delete, re-create: the usual atomic replace.
	c.AddTable(t)
	c.DelTable(t)
	t = c.AddTable(t)

	dns4 := &nftables.Set{Table: t, Name: "dns4", KeyType: nftables.TypeIPAddr}
	dns6 := &nftables.Set{Table: t, Name: "dns6", KeyType: nftables.TypeIP6Addr}
	d4, d6 := resolverElements(s)
	if err := c.AddSet(dns4, d4); err != nil {
		return fmt.Errorf("netguard: set dns4: %w", err)
	}
	if err := c.AddSet(dns6, d6); err != nil {
		return fmt.Errorf("netguard: set dns6: %w", err)
	}

	prio := nftables.ChainPriorityRef(basePriority)
	accept := nftables.ChainPolicyAccept
	fwd := c.AddChain(&nftables.Chain{Name: chainForward, Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward, Priority: prio, Policy: &accept})
	in := c.AddChain(&nftables.Chain{Name: chainInput, Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: prio, Policy: &accept})
	gFwd := c.AddChain(&nftables.Chain{Name: chainGuardForward, Table: t})
	gIn := c.AddChain(&nftables.Chain{Name: chainGuardInput, Table: t})

	// One rule per bridge rather than an ifname set: nft lists ifname set
	// elements written over netlink byte-reversed (as ""), which would make
	// the table unreadable to anyone checking it.
	for _, i := range s.Ifaces {
		c.AddRule(&nftables.Rule{Table: t, Chain: fwd, Exprs: jumpIfIface(i, chainGuardForward)})
		c.AddRule(&nftables.Rule{Table: t, Chain: in, Exprs: jumpIfIface(i, chainGuardInput)})
	}

	for _, ch := range []*nftables.Chain{gFwd, gIn} {
		for _, r := range guardRules(s, ch == gFwd, dns4, dns6) {
			c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: r})
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("netguard: apply table %s: %w", s.Table, err)
	}
	return nil
}

// Check verifies the table is in place as Apply builds it for s.
func Check(s Spec) error {
	if err := s.Validate(); err != nil {
		return err
	}
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("netguard: netlink: %w", err)
	}
	t, err := c.ListTableOfFamily(s.Table, nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("netguard: table %s missing: %w", s.Table, err)
	}
	want := map[string]int{
		chainForward:      len(s.Ifaces),
		chainInput:        len(s.Ifaces),
		chainGuardForward: len(guardRules(s, true, nil, nil)),
		chainGuardInput:   len(guardRules(s, false, nil, nil)),
	}
	for name, n := range want {
		ch, err := c.ListChain(t, name)
		if err != nil {
			return fmt.Errorf("netguard: chain %s missing: %w", name, err)
		}
		rules, err := c.GetRules(t, ch)
		if err != nil {
			return fmt.Errorf("netguard: chain %s: %w", name, err)
		}
		if len(rules) != n {
			return fmt.Errorf("netguard: chain %s has %d rules, want %d", name, len(rules), n)
		}
		if name != chainForward && name != chainInput {
			continue
		}
		if ch.Hooknum == nil || ch.Priority == nil || *ch.Priority != basePriority {
			return fmt.Errorf("netguard: chain %s not hooked", name)
		}
		guarded := map[string]bool{}
		for _, r := range rules {
			if name, ok := ruleIface(r); ok {
				guarded[name] = true
			}
		}
		for _, i := range s.Ifaces {
			if !guarded[i] {
				return fmt.Errorf("netguard: chain %s does not guard %s", ch.Name, i)
			}
		}
	}
	return nil
}

// ruleIface returns the interface a base-chain rule built by jumpIfIface
// matches.
func ruleIface(r *nftables.Rule) (string, bool) {
	for i, e := range r.Exprs {
		m, ok := e.(*expr.Meta)
		if !ok || m.Key != expr.MetaKeyIIFNAME || i+1 >= len(r.Exprs) {
			continue
		}
		if c, ok := r.Exprs[i+1].(*expr.Cmp); ok && c.Op == expr.CmpOpEq {
			return strings.TrimRight(string(c.Data), "\x00"), true
		}
	}
	return "", false
}

// Remove deletes the guard's table (used by tests and `qpot` teardown).
func Remove(table string) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	t, err := c.ListTableOfFamily(table, nftables.TableFamilyINet)
	if err != nil {
		return nil // already gone
	}
	c.DelTable(t)
	return c.Flush()
}

// resolverElements returns the elements of the dns4 and dns6 sets: every
// address of s.Resolvers(), so the Azure WireServer is always among them.
func resolverElements(s Spec) (d4, d6 []nftables.SetElement) {
	for _, a := range s.Resolvers() {
		if a.Is4() {
			b := a.As4()
			d4 = append(d4, nftables.SetElement{Key: b[:]})
		} else {
			b := a.As16()
			d6 = append(d6, nftables.SetElement{Key: b[:]})
		}
	}
	return d4, d6
}

// guardRules returns the rules of guard_forward (forward=true) or guard_input.
// The sets are only referenced by name and ID, so nil sets give the right
// count for Check.
func guardRules(s Spec, forward bool, dns4, dns6 *nftables.Set) [][]expr.Any {
	rules := [][]expr.Any{ctEstablishedAccept()}
	for _, fam := range []struct {
		proto byte
		set   *nftables.Set
	}{{unix.NFPROTO_IPV4, dns4}, {unix.NFPROTO_IPV6, dns6}} {
		for _, l4 := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
			rules = append(rules, dnsAccept(fam.proto, fam.set, l4))
		}
	}
	if !forward || s.Mode == ModeAll {
		// Nothing a honeypot starts may reach the host, and in ModeAll
		// nothing may leave at all.
		return append(rules, []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}})
	}
	for _, p := range blocked4 {
		rules = append(rules, dropPrefix(p))
	}
	for _, p := range blocked6 {
		rules = append(rules, dropPrefix(p))
	}
	return rules
}

func ifnameKey(name string) []byte {
	b := make([]byte, 16)
	copy(b, name)
	return b
}

func jumpIfIface(iface, chain string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameKey(iface)},
		&expr.Verdict{Kind: expr.VerdictJump, Chain: chain},
	}
}

func ctEstablishedAccept() []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
			Xor:  binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// dnsAccept accepts l4 (UDP or TCP) to port 53 of an address in the family's
// resolver set.
func dnsAccept(nfproto byte, set *nftables.Set, l4 byte) []expr.Any {
	off, n := uint32(16), uint32(4)
	if nfproto == unix.NFPROTO_IPV6 {
		off, n = 24, 16
	}
	var name string
	var id uint32
	if set != nil {
		name, id = set.Name, set.ID
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nfproto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: n},
		&expr.Lookup{SourceRegister: 1, SetName: name, SetID: id},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{l4}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(53)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// dropPrefix drops packets whose destination lies in p.
func dropPrefix(p netip.Prefix) []expr.Any {
	nfproto, off, n := byte(unix.NFPROTO_IPV4), uint32(16), uint32(4)
	addr := p.Masked().Addr().AsSlice()
	if p.Addr().Is6() {
		nfproto, off, n = unix.NFPROTO_IPV6, 24, 16
	}
	mask := make([]byte, n)
	for i := 0; i < p.Bits(); i++ {
		mask[i/8] |= 0x80 >> (i % 8)
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nfproto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: n},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: n, Mask: mask, Xor: make([]byte, n)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}
