package engagement

import (
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestSamplerKeepsTheSmallestKeys: whatever order the sessions come in, the
// sampler holds the values of the limit smallest keys and never more.
func TestSamplerKeepsTheSmallestKeys(t *testing.T) {
	rng := rand.New(rand.NewSource(13))
	type item struct {
		key   sampleKey
		value int64
	}
	items := make([]item, 500)
	for i := range items {
		// Few distinct h values, so the order also rests on b and seg.
		items[i] = item{sampleKey{h: uint64(rng.Intn(40)), b: uint64(rng.Intn(5)), seg: uint64(i)}, int64(rng.Intn(1000))}
	}
	for _, limit := range []int{1, 2, 7, 64, 499, 500, 501} {
		byKey := append([]item(nil), items...)
		sort.Slice(byKey, func(i, j int) bool { return lessSampleKey(byKey[i].key, byKey[j].key) })
		var want []int64
		for _, it := range byKey[:min(limit, len(byKey))] {
			want = append(want, it.value)
		}
		sortInt64(want)
		for round := 0; round < 5; round++ {
			rng.Shuffle(len(items), func(i, j int) { items[i], items[j] = items[j], items[i] })
			s := newSampler(limit)
			for _, it := range items {
				s.add(it.key, it.value)
				if len(s.keys) > limit || len(s.vals) != len(s.keys) {
					t.Fatalf("limit %d: the sampler holds %d keys and %d values", limit, len(s.keys), len(s.vals))
				}
			}
			if got := s.values(); !reflect.DeepEqual(got, want) || s.over() != (limit < len(items)) || s.total != int64(len(items)) {
				t.Fatalf("limit %d, round %d: kept %v (over %v), want %v", limit, round, got, s.over(), want)
			}
		}
	}
	if s := newSampler(3); s.values() != nil || s.over() {
		t.Errorf("an empty sampler: %v, over %v", s.values(), s.over())
	}

	// The key of a session spreads the runs of one source over the order
	// and is different for every run.
	seen := map[sampleKey]bool{}
	key := groupKey{a: 0x1234, b: 0x5678}
	for seg := 0; seg < 1000; seg++ {
		k := sampleKeyOf(key, seg)
		if seen[k] || k.b != key.b || k.seg != uint64(seg) {
			t.Fatalf("run %d has the key %+v", seg, k)
		}
		seen[k] = true
	}
	if a, b := sampleKeyOf(key, 0), sampleKeyOf(groupKey{a: 0x1235, b: 0x5678}, 0); a == b {
		t.Errorf("two groups share the key %+v", a)
	}
}

func TestSourceKeyOf(t *testing.T) {
	cases := []struct {
		raw    string
		key    string
		public bool
	}{
		{"203.0.113.5", "203.0.113.5", true},
		{" 203.0.113.5 ", "203.0.113.5", true},
		{"8.8.8.8", "8.8.8.8", true},
		{"::ffff:203.0.113.5", "203.0.113.5", true},    // IPv4-mapped
		{"2001:db8:1:2::a", "2001:db8:1:2::/64", true}, // an IPv6 address is its /64
		{"2001:db8:1:2:ffff::1", "2001:db8:1:2::/64", true},
		{"2001:db8:1:3::a", "2001:db8:1:3::/64", true},
		{"2a00:1450:4001:81b::200e", "2a00:1450:4001:81b::/64", true},
		{"fe80::1%eth0", "fe80::/64", false}, // link-local, zone dropped
		{"10.0.0.1", "10.0.0.1", false},      // private
		{"172.17.0.1", "172.17.0.1", false},  // Docker's default bridge
		{"172.32.0.1", "172.32.0.1", true},   // just outside 172.16/12
		{"192.168.1.1", "192.168.1.1", false},
		{"127.0.0.1", "127.0.0.1", false}, // loopback
		{"::1", "::/64", false},
		{"169.254.10.10", "169.254.10.10", false}, // link-local
		{"100.64.0.1", "100.64.0.1", false},       // carrier-grade NAT
		{"100.128.0.1", "100.128.0.1", true},      // just outside it
		{"0.0.0.0", "0.0.0.0", false},             // unspecified
		{"0.1.2.3", "0.1.2.3", false},             // "this network"
		{"::", "::/64", false},
		{"224.0.0.1", "224.0.0.1", false}, // multicast
		{"ff02::1", "ff02::/64", false},
		{"240.0.0.1", "240.0.0.1", false},             // reserved
		{"255.255.255.255", "255.255.255.255", false}, // broadcast
		{"198.18.0.1", "198.18.0.1", false},           // benchmarking
		{"192.0.0.8", "192.0.0.8", false},             // IETF protocol assignments
		{"fd00::1", "fd00::/64", false},               // unique local
		{"::ffff:10.0.0.1", "10.0.0.1", false},        // a mapped private address
		{"not an address", "text:not an address", false},
		{"203.0.113.5:22", "text:203.0.113.5:22", false},
	}
	for _, c := range cases {
		key, public := sourceKeyOf(c.raw)
		if key != c.key || public != c.public {
			t.Errorf("sourceKeyOf(%q) = %q, %v, want %q, %v", c.raw, key, public, c.key, c.public)
		}
	}
}

// sharedScenario is two deployments whose shared sources and what each did
// are set by hand; TestSharedSources works the expected counts out.
func sharedScenario() (a, b []visit) {
	n := 0
	add := func(list *[]visit, v visit) {
		n++
		v.sid = fmt.Sprint("s", n)
		v.start = float64(n * 10)
		if v.seconds == 0 {
			v.seconds = 5
		}
		*list = append(*list, v)
	}
	// S1: logs in on A only.
	add(&a, visit{src: "203.0.113.1", login: true})
	add(&b, visit{src: "203.0.113.1"})
	// S2: on B it logs in and runs 3 commands; on A it only connects.
	add(&a, visit{src: "203.0.113.2"})
	add(&b, visit{src: "203.0.113.2", login: true, cmds: 3})
	// S3: logs in on both; 5 and 2 commands in two sessions on A, 4 on B.
	add(&a, visit{src: "203.0.113.3", login: true, cmds: 5})
	add(&a, visit{src: "203.0.113.3", login: true, cmds: 2})
	add(&b, visit{src: "203.0.113.3", login: true, cmds: 4})
	// S4: fetches a payload on A only.
	add(&a, visit{src: "203.0.113.4", payload: true})
	add(&b, visit{src: "203.0.113.4"})
	// S5: the same on both.
	add(&a, visit{src: "203.0.113.5", login: true, cmds: 1})
	add(&b, visit{src: "203.0.113.5", login: true, cmds: 1})
	// S6: stays 50 s on A and 80 s on B, over two sessions there.
	add(&a, visit{src: "203.0.113.6", seconds: 50})
	add(&b, visit{src: "203.0.113.6", seconds: 80})
	add(&b, visit{src: "203.0.113.6", seconds: 7})
	// S7: two addresses of one IPv6 /64, and the same IPv4 address written
	// as IPv4-mapped IPv6 on B (S8). Both tied.
	add(&a, visit{src: "2001:db8:1:2::a"})
	add(&b, visit{src: "2001:db8:1:2:ffff::9"})
	add(&a, visit{src: "203.0.113.8"})
	add(&b, visit{src: "::ffff:203.0.113.8"})
	// Not shared: neighbouring /64s, and addresses only one side saw.
	add(&a, visit{src: "2001:db8:1:3::a"})
	add(&b, visit{src: "2001:db8:1:4::a"})
	for i := 1; i <= 4; i++ {
		add(&a, visit{src: fmt.Sprintf("198.51.100.%d", i), login: true, cmds: 2})
	}
	for i := 1; i <= 2; i++ {
		add(&b, visit{src: fmt.Sprintf("192.0.2.%d", i)})
	}
	// Seen by both, but never a visitor: these would all count for A.
	for _, reserved := range []string{"10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "fe80::1", "100.64.0.1", "fd00::5", "not-an-address"} {
		add(&a, visit{src: reserved, login: true, cmds: 9, payload: true, seconds: 900})
		add(&b, visit{src: reserved})
	}
	return a, b
}

func TestSharedSources(t *testing.T) {
	va, vb := sharedScenario()
	a, b := deployment(t, "treat", Options{}, va), deployment(t, "control", Options{}, vb)

	// A: 8 shared + 1 IPv6 + 4 own public sources, 8 reserved, 22 sessions.
	wantA := SourceSummary{Sources: 21, Public: 13, Reserved: 8, SessionsFromReserved: 8, BusiestSessions: 2, BusiestPercent: 9.09}
	if a.Sources != wantA {
		t.Errorf("sources of A = %+v, want %+v", a.Sources, wantA)
	}
	// B: 8 shared + 1 IPv6 + 2 own public sources, 8 reserved, 20 sessions.
	wantB := SourceSummary{Sources: 19, Public: 11, Reserved: 8, SessionsFromReserved: 8, BusiestSessions: 2, BusiestPercent: 10}
	if b.Sources != wantB {
		t.Errorf("sources of B = %+v, want %+v", b.Sources, wantB)
	}

	c := Compare(*a, *b)
	e := c.Exposure
	// 8 shared of 13 + 11 - 8 = 16 public sources.
	if !e.SourcesKnown || e.SharedSources != 8 || e.Jaccard != 0.5 || e.ComparedA != 13 || e.ComparedB != 11 || e.SourcesSampled {
		t.Errorf("exposure = %+v", e)
	}
	p := c.Paired
	if p.Skipped || p.Reason != "" || p.Shared != 8 || p.Sampled {
		t.Fatalf("shared sources = %+v", p)
	}
	//                  A further      B further   tied
	// logged in        S1             S2          6
	// ran a command    -              S2          7
	// payload          S4             -           7
	// most commands    S3 (5 > 4)     S2          6
	// longest session  -              S6          7
	want := []PairedMeasure{
		{Key: "logged_in", Name: "Logged in", AFurther: 1, BFurther: 1, Tied: 6, PValue: 1},
		{Key: "ran_command", Name: "Ran a command", AFurther: 0, BFurther: 1, Tied: 7, PValue: 1},
		{Key: "payload", Name: "Fetched or uploaded a payload", AFurther: 1, BFurther: 0, Tied: 7, PValue: 1},
		{Key: "max_commands", Name: "Most commands in one session", AFurther: 1, BFurther: 1, Tied: 6, PValue: 1},
		{Key: "longest_session", Name: "Longest session", AFurther: 0, BFurther: 1, Tied: 7, PValue: 1},
	}
	for i := range want {
		want[i].PAdjusted, want[i].Verdict = 1, VerdictNone
	}
	if !reflect.DeepEqual(p.Measures, want) {
		t.Errorf("measures:\n got %+v\nwant %+v", p.Measures, want)
	}
}

// TestSharedSourcesVerdict gives every shared source the same advantage on
// one side, so the exact test has a known answer.
func TestSharedSourcesVerdict(t *testing.T) {
	var va, vb []visit
	for i := 0; i < 12; i++ {
		src := fmt.Sprintf("203.0.113.%d", i+1)
		// On A all twelve log in; ten run 3 commands. On B nobody logs in.
		v := visit{src: src, sid: fmt.Sprint("a", i), start: float64(i * 10), login: true, seconds: 5}
		if i < 10 {
			v.cmds = 3
		}
		va = append(va, v)
		// Three of the twelve stay longer on B, nine stay longer on A.
		seconds := 2.0
		if i < 3 {
			seconds = 9
		}
		vb = append(vb, visit{src: src, sid: fmt.Sprint("b", i), start: float64(i * 10), seconds: seconds})
	}
	c := Compare(*deployment(t, "a", Options{}, va), *deployment(t, "b", Options{}, vb))
	p := c.Paired
	if p.Skipped || p.Shared != 12 {
		t.Fatalf("shared sources = %+v", p)
	}
	// Exact two-sided sign test: 12 to 0 is 2/4096, 10 to 0 is 2/1024,
	// 0 to 0 is 1, and 9 to 3 is 2*(1+12+66+220)/4096.
	raw := []float64{2.0 / 4096, 2.0 / 1024, 1, 2.0 / 1024, 2.0 * 299 / 4096}
	counts := [][3]int64{{12, 0, 0}, {10, 0, 2}, {0, 0, 12}, {10, 0, 2}, {9, 3, 0}}
	// Holm over five: the smallest times 5, the next two (tied) times 4 and
	// 3 with the larger kept, then 0.146 times 2, then 1.
	adjusted := []float64{5 * 2.0 / 4096, 4 * 2.0 / 1024, 1, 4 * 2.0 / 1024, 2 * 2.0 * 299 / 4096}
	verdicts := []string{VerdictClear, VerdictClear, VerdictNone, VerdictClear, VerdictNone}
	for i, m := range p.Measures {
		if [3]int64{m.AFurther, m.BFurther, m.Tied} != counts[i] || !near(m.PValue, raw[i], 1e-15) || !near(m.PAdjusted, adjusted[i], 1e-15) || m.Verdict != verdicts[i] {
			t.Errorf("%s = %+v, want counts %v, p %v, adjusted %v, %q", m.Key, m, counts[i], raw[i], adjusted[i], verdicts[i])
		}
	}
}

func TestSharedSourcesCollapsed(t *testing.T) {
	spread := crowd("b", 40, 20, 10, 2, 5)
	// One address carries 21 of 41 sessions: just over half.
	var gateway []visit
	for i := 0; i < 21; i++ {
		gateway = append(gateway, visit{src: "198.51.0.1", sid: fmt.Sprint("g", i), start: float64(i * 60), login: true, cmds: 1, seconds: 5})
	}
	collapsed := deployment(t, "nat", Options{}, append(gateway, crowd("a", 21, 5, 0, 0, 5)[1:]...))
	clean := deployment(t, "clean", Options{}, spread)
	if s := collapsed.Sources; !s.Collapsed || s.BusiestSessions != 21 || s.BusiestPercent != 51.22 ||
		s.CollapsedReason != "one source address carries 21 of 41 sessions (51.2%, limit 50%)" {
		t.Fatalf("sources = %+v", s)
	}
	if clean.Sources.Collapsed {
		t.Fatalf("sources of the clean side = %+v", clean.Sources)
	}
	for _, c := range []Comparison{Compare(*collapsed, *clean), Compare(*clean, *collapsed)} {
		p := c.Paired
		want := "In nat one source address carries 21 of 41 sessions (51.2%, limit 50%). Its source addresses may be a gateway or proxy, not the visitors."
		if !p.Skipped || p.Reason != want || len(p.Measures) != 0 {
			t.Errorf("shared sources = %+v", p)
		}
		// The overlap is still counted: 198.51.0.1 .. 198.51.0.21.
		if p.Shared != 21 || c.Exposure.SharedSources != 21 {
			t.Errorf("shared = %d, want 21", p.Shared)
		}
		found := false
		for _, n := range c.Notes {
			found = found || strings.Contains(n, "In nat one source address carries 21 of 41 sessions") && strings.Contains(n, "returning sources row says nothing")
		}
		if !found {
			t.Errorf("notes = %q", c.Notes)
		}
	}

	// Exactly half is not collapsed.
	half := deployment(t, "half", Options{}, append(gateway[:20], crowd("a", 21, 5, 0, 0, 5)[1:]...))
	if s := half.Sources; s.Collapsed || s.BusiestPercent != 50 {
		t.Errorf("exactly half: %+v", s)
	}

	// Many private addresses, none busy alone: the reserved ones together
	// carry 30 of 50 sessions.
	var bridge []visit
	for i := 0; i < 30; i++ {
		bridge = append(bridge, visit{src: fmt.Sprintf("172.18.0.%d", i+2), sid: fmt.Sprint("p", i), start: float64(i * 60), seconds: 5})
	}
	private := deployment(t, "bridge", Options{}, append(bridge, crowd("a", 20, 5, 0, 0, 5)...))
	if s := private.Sources; !s.Collapsed || s.SessionsFromReserved != 30 || s.Reserved != 30 || s.Public != 20 ||
		s.CollapsedReason != "private and reserved addresses carry 30 of 50 sessions (60.0%, limit 50%)" {
		t.Fatalf("sources = %+v", s)
	}
	if p := Compare(*clean, *private).Paired; !p.Skipped || !strings.HasPrefix(p.Reason, "In bridge private and reserved addresses carry 30 of 50 sessions") || p.Shared != 20 {
		t.Errorf("shared sources = %+v", p)
	}

	// Sessions without any source address are counted as such.
	var anonymous []visit
	for i := 0; i < 5; i++ {
		anonymous = append(anonymous, visit{sid: fmt.Sprint("n", i), start: float64(i), seconds: 1})
	}
	if s := deployment(t, "anon", Options{}, append(anonymous, spread...)).Sources; s.SessionsWithoutSource != 5 || s.Sources != 40 || s.Collapsed {
		t.Errorf("sources with anonymous sessions = %+v", s)
	}
}

func TestSharedSourcesNone(t *testing.T) {
	a := deployment(t, "a", Options{}, crowd("a", 40, 20, 10, 2, 5))
	var other []visit
	for i := 0; i < 40; i++ {
		other = append(other, visit{src: fmt.Sprintf("203.0.113.%d", i+1), sid: fmt.Sprint("b", i), start: float64(i * 60), seconds: 5})
	}
	c := Compare(*a, *deployment(t, "b", Options{}, other))
	if p := c.Paired; !p.Skipped || p.Reason != "No public source address was seen by both." || p.Shared != 0 {
		t.Errorf("shared sources = %+v", p)
	}
	if e := c.Exposure; e.SharedSources != 0 || e.Jaccard != 0 || e.ComparedA != 40 || e.ComparedB != 40 || !e.Comparable {
		t.Errorf("exposure = %+v", e)
	}
}

// TestSharedSourcesSampled: past the source limit each report keeps the
// sources with the smallest key hashes, so two reports keep the same part of
// the address space and their overlap there is exact.
func TestSharedSourcesSampled(t *testing.T) {
	// A sees 203.0.113.1..60, B sees 203.0.113.31..90: 30 shared. On B every
	// shared source logs in; on A none does.
	var va, vb []visit
	for i := 1; i <= 90; i++ {
		src := fmt.Sprintf("203.0.113.%d", i)
		if i <= 60 {
			va = append(va, visit{src: src, sid: fmt.Sprint("a", i), start: float64(i * 60), seconds: 5})
		}
		if i > 30 {
			vb = append(vb, visit{src: src, sid: fmt.Sprint("b", i), start: float64(i * 60), login: true, seconds: 5})
		}
	}
	fullA, fullB := deployment(t, "a", Options{}, va), deployment(t, "b", Options{}, vb)
	if full := Compare(*fullA, *fullB); full.Exposure.SharedSources != 30 || full.Exposure.Jaccard != round(30.0/90, 4) || full.Paired.Sampled {
		t.Fatalf("without a limit: %+v", full.Exposure)
	}

	for _, limits := range [][2]int{{20, 20}, {20, 0}, {0, 25}, {12, 40}, {60, 60}} {
		name := fmt.Sprint(limits)
		a := deployment(t, "a", Options{SourceLimit: limits[0]}, va)
		b := deployment(t, "b", Options{SourceLimit: limits[1]}, vb)
		// Work the expected figures out from the complete tables: everything
		// up to the smallest cut-off key.
		var bound *groupKey
		for i, limit := range limits {
			full := [2]*Report{fullA, fullB}[i].detail.sources
			if limit > 0 && limit < len(full) {
				cut := full[limit-1].key
				if bound == nil || lessGroupKey(cut, *bound) {
					bound = &cut
				}
			}
		}
		inside := func(d *detail) map[groupKey]bool {
			out := map[groupKey]bool{}
			for _, s := range d.sources {
				if bound == nil || !lessGroupKey(*bound, s.key) {
					out[s.key] = true
				}
			}
			return out
		}
		inA, inB := inside(fullA.detail), inside(fullB.detail)
		shared := int64(0)
		for k := range inA {
			if inB[k] {
				shared++
			}
		}
		sampled := bound != nil
		if a.Limits.PairedSourcesReached != (limits[0] > 0 && limits[0] < 60) || b.Limits.PairedSourcesReached != (limits[1] > 0 && limits[1] < 60) {
			t.Errorf("%s: limits reached = %v and %v", name, a.Limits.PairedSourcesReached, b.Limits.PairedSourcesReached)
		}
		// The summary still counts every source.
		if a.Sources.Sources != 60 || b.Sources.Public != 60 {
			t.Errorf("%s: source counts = %d and %d, want 60", name, a.Sources.Sources, b.Sources.Public)
		}
		c := Compare(*a, *b)
		e := c.Exposure
		if e.SourcesSampled != sampled || e.ComparedA != int64(len(inA)) || e.ComparedB != int64(len(inB)) || e.SharedSources != shared ||
			e.Jaccard != round(float64(shared)/float64(int64(len(inA)+len(inB))-shared), 4) {
			t.Errorf("%s: exposure = %+v, want %d and %d compared, %d shared", name, e, len(inA), len(inB), shared)
		}
		p := c.Paired
		if p.Sampled != sampled || p.Shared != shared {
			t.Errorf("%s: shared sources = %+v, want %d", name, p, shared)
		}
		if shared > 0 {
			// Every shared source logged in on B only.
			if p.Skipped || p.Measures[0].AFurther != 0 || p.Measures[0].BFurther != shared {
				t.Errorf("%s: measure = %+v, want %d further on B", name, p.Measures, shared)
			}
		}
		if sampled {
			if shared == 0 || shared >= 30 {
				t.Errorf("%s: %d shared sources in the sample, expected some but not all 30", name, shared)
			}
			found := false
			for _, n := range c.Notes {
				found = found || strings.Contains(n, "same fixed part of the address space")
			}
			if !found || !strings.Contains(strings.Join(append(a.Notes, b.Notes...), " "), "source addresses: the source overlap") {
				t.Errorf("%s: the limit is not reported: %q, %q, %q", name, c.Notes, a.Notes, b.Notes)
			}
		} else if shared != 30 {
			t.Errorf("%s: %d shared sources without sampling, want 30", name, shared)
		}
	}
}
