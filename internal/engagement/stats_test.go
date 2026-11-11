package engagement

import (
	"math"
	"math/big"
	"math/rand"
	"sort"
	"testing"
)

func near(got, want, tolerance float64) bool {
	return math.Abs(got-want) <= tolerance
}

// TestWilsonAgainstPublished checks the Wilson score interval against the
// worked examples of R. G. Newcombe, "Two-sided confidence intervals for the
// single proportion: comparison of seven methods", Statistics in Medicine 17
// (1998) 857-872, table I, method 3 (score method, no continuity
// correction).
func TestWilsonAgainstPublished(t *testing.T) {
	cases := []struct {
		k, n   int64
		lo, hi float64
	}{
		{81, 263, 0.2553, 0.3662},
		{15, 148, 0.0624, 0.1605},
		{0, 20, 0.0000, 0.1611},
		{1, 29, 0.0061, 0.1718},
	}
	for _, c := range cases {
		lo, hi, ok := wilson(c.k, c.n)
		if !ok || !near(lo, c.lo, 0.00005) || !near(hi, c.hi, 0.00005) {
			t.Errorf("wilson(%d, %d) = %.4f to %.4f, published %.4f to %.4f", c.k, c.n, lo, hi, c.lo, c.hi)
		}
	}
}

// TestWilsonSolvesItsEquation derives the interval another way: its two ends
// are the values of p at which the observed share is exactly z95 standard
// errors away, the standard error taken at p.
func TestWilsonSolvesItsEquation(t *testing.T) {
	for n := int64(1); n <= 60; n++ {
		for k := int64(0); k <= n; k++ {
			lo, hi, ok := wilson(k, n)
			if !ok || lo < 0 || hi > 1 || lo > hi {
				t.Fatalf("wilson(%d, %d) = %v to %v, %v", k, n, lo, hi, ok)
			}
			obs := float64(k) / float64(n)
			if lo > obs || hi < obs {
				t.Fatalf("wilson(%d, %d) = %v to %v does not hold the share %v", k, n, lo, hi, obs)
			}
			for _, p := range []float64{lo, hi} {
				left := (obs - p) * (obs - p)
				right := z95 * z95 * p * (1 - p) / float64(n)
				if !near(left, right, 1e-12) {
					t.Fatalf("wilson(%d, %d): the end %v does not solve the score equation: %v against %v", k, n, p, left, right)
				}
			}
			// The mirror share has the mirror interval.
			mlo, mhi, _ := wilson(n-k, n)
			if !near(mlo, 1-hi, 1e-12) || !near(mhi, 1-lo, 1e-12) {
				t.Fatalf("wilson(%d, %d) is not the mirror of wilson(%d, %d)", n-k, n, k, n)
			}
		}
	}
	if _, _, ok := wilson(0, 0); ok {
		t.Error("a share of nothing has no interval")
	}
}

// TestNewcombeAgainstPublished checks the interval of a difference against
// the worked examples of R. G. Newcombe, "Interval estimation for the
// difference between independent proportions: comparison of eleven methods",
// Statistics in Medicine 17 (1998) 873-890, table II, method 10 (the hybrid
// score interval). The paper gives the first share minus the second.
func TestNewcombeAgainstPublished(t *testing.T) {
	cases := []struct {
		k1, n1, k2, n2 int64
		lo, hi         float64
	}{
		{56, 70, 48, 80, 0.0524, 0.3339},
		{9, 10, 3, 10, 0.1705, 0.8090},
		{6, 7, 2, 7, 0.0582, 0.8062},
		{5, 56, 0, 29, -0.0381, 0.1926},
		{0, 10, 0, 20, -0.1611, 0.2775},
		{0, 10, 0, 10, -0.2775, 0.2775},
		{10, 10, 0, 20, 0.6791, 1.0000},
		{10, 10, 0, 10, 0.6075, 1.0000},
	}
	for _, c := range cases {
		lo, hi, ok := newcombe(c.k2, c.n2, c.k1, c.n1)
		if !ok || !near(lo, c.lo, 0.00005) || !near(hi, c.hi, 0.00005) {
			t.Errorf("%d/%d - %d/%d = %.4f to %.4f, published %.4f to %.4f", c.k1, c.n1, c.k2, c.n2, lo, hi, c.lo, c.hi)
		}
		// Swapping the two shares mirrors the interval exactly.
		mlo, mhi, _ := newcombe(c.k1, c.n1, c.k2, c.n2)
		if mlo != -hi || mhi != -lo {
			t.Errorf("%d/%d against %d/%d: swapped interval %v to %v is not the mirror of %v to %v", c.k1, c.n1, c.k2, c.n2, mlo, mhi, lo, hi)
		}
	}
	if _, _, ok := newcombe(1, 2, 0, 0); ok {
		t.Error("a difference with an empty base has no interval")
	}
	for n := int64(1); n <= 25; n++ {
		for k := int64(0); k <= n; k++ {
			lo, hi, _ := newcombe(k, n, n-k, n+3)
			d := float64(n-k)/float64(n+3) - float64(k)/float64(n)
			if lo < -1 || hi > 1 || lo > d || hi < d {
				t.Fatalf("newcombe(%d, %d, %d, %d) = %v to %v around %v", k, n, n-k, n+3, lo, hi, d)
			}
		}
	}
}

// choose returns the binomial coefficient exactly.
func choose(n, k int64) *big.Int {
	return new(big.Int).Binomial(n, k)
}

// fisherByEnumeration is Fisher's exact test worked out in exact fractions:
// the probability of every table with the same margins, and the sum of those
// no larger than the probability of the table seen.
func fisherByEnumeration(k1, n1, k2, n2 int64) float64 {
	total := k1 + k2
	weight := func(x int64) *big.Int {
		return new(big.Int).Mul(choose(n1, x), choose(n2, total-x))
	}
	seen := weight(k1)
	sum, tail := new(big.Int), new(big.Int)
	for x := max(0, total-n2); x <= min(total, n1); x++ {
		w := weight(x)
		sum.Add(sum, w)
		if w.Cmp(seen) <= 0 {
			tail.Add(tail, w)
		}
	}
	p, _ := new(big.Rat).SetFrac(tail, sum).Float64()
	return p
}

func TestFisherExact(t *testing.T) {
	// R. A. Fisher's tea-tasting table, 3 of 4 against 1 of 4: 34/70.
	if p := fisherExact(3, 4, 1, 4); !near(p, 34.0/70, 1e-12) {
		t.Errorf("tea tasting: p = %v, want %v", p, 34.0/70)
	}
	// 1 of 12 against 9 of 12: both tails are C(12,1)C(12,9) + C(12,0)C(12,10)
	// tables out of C(24,10), so p = 2 * (2640 + 66) / 1961256.
	if p, want := fisherExact(1, 12, 9, 12), 2.0*(2640+66)/1961256; !near(p, want, 1e-12) {
		t.Errorf("1/12 against 9/12: p = %v, want %v", p, want)
	}

	for n1 := int64(0); n1 <= 11; n1++ {
		for n2 := int64(0); n2 <= 11; n2++ {
			for k1 := int64(0); k1 <= n1; k1++ {
				for k2 := int64(0); k2 <= n2; k2++ {
					got := fisherExact(k1, n1, k2, n2)
					want := 1.0
					if n1 > 0 && n2 > 0 {
						want = fisherByEnumeration(k1, n1, k2, n2)
					}
					if !near(got, want, 1e-12) {
						t.Fatalf("fisherExact(%d, %d, %d, %d) = %v, enumeration gives %v", k1, n1, k2, n2, got, want)
					}
					if swapped := fisherExact(k2, n2, k1, n1); swapped != got {
						t.Fatalf("fisherExact(%d, %d, %d, %d) = %v but %v with the rows swapped", k1, n1, k2, n2, got, swapped)
					}
					if k1 == k2 && n1 == n2 && got != 1 {
						t.Fatalf("fisherExact(%d, %d, %d, %d) = %v for equal rows, want 1", k1, n1, k2, n2, got)
					}
				}
			}
		}
	}

	// Larger tables, still against exact fractions.
	rng := rand.New(rand.NewSource(3))
	for i := 0; i < 60; i++ {
		n1, n2 := int64(1+rng.Intn(400)), int64(1+rng.Intn(400))
		k1, k2 := rng.Int63n(n1+1), rng.Int63n(n2+1)
		got, want := fisherExact(k1, n1, k2, n2), fisherByEnumeration(k1, n1, k2, n2)
		if math.Abs(got-want) > 1e-9*math.Max(want, 1e-300) && !near(got, want, 1e-300) {
			t.Fatalf("fisherExact(%d, %d, %d, %d) = %v, enumeration gives %v", k1, n1, k2, n2, got, want)
		}
	}

	// A base of millions returns at once and stays a probability.
	for _, c := range [][4]int64{{1000, 2000000, 1100, 2000000}, {0, 2000000, 2000000, 2000000}, {999999, 2000000, 1000001, 2000000}} {
		p := fisherExact(c[0], c[1], c[2], c[3])
		if math.IsNaN(p) || p < 0 || p > 1 {
			t.Errorf("fisherExact%v = %v", c, p)
		}
	}
	// 1000 against 1100 of two million each: the pooled two-share z test
	// gives z = 2.18, p = 0.029. The exact test must be close.
	if p := fisherExact(1000, 2000000, 1100, 2000000); !near(p, 0.029, 0.003) {
		t.Errorf("1000 against 1100 of two million: p = %v, want about 0.029", p)
	}
}

// binomHalfExact returns P(X <= j) for X binomial(n, 1/2) and every j from 0
// to n, in exact fractions: the running sum of the binomial coefficients over
// 2^n.
func binomHalfExact(n int64) []float64 {
	out := make([]float64, n+1)
	all := new(big.Int).Lsh(big.NewInt(1), uint(n))
	coefficient, sum := big.NewInt(1), new(big.Int)
	for k := int64(0); k <= n; k++ {
		sum.Add(sum, coefficient)
		out[k], _ = new(big.Rat).SetFrac(sum, all).Float64()
		// C(n, k+1) = C(n, k) * (n-k) / (k+1), which divides exactly.
		coefficient.Mul(coefficient, big.NewInt(n-k))
		coefficient.Quo(coefficient, big.NewInt(k+1))
	}
	return out
}

func TestBinomHalfTailAndSignTest(t *testing.T) {
	for n := int64(0); n <= 70; n++ {
		exact := binomHalfExact(n)
		for j := int64(0); j <= n; j++ {
			got, want := binomHalfTail(j, n), exact[j]
			if math.Abs(got-want) > 1e-12*want+1e-15 {
				t.Fatalf("binomHalfTail(%d, %d) = %v, exact %v", j, n, got, want)
			}
		}
		if below, above := binomHalfTail(-1, n), binomHalfTail(n+1, n); below != 0 || above != 1 {
			t.Fatalf("binomHalfTail outside 0..%d = %v and %v, want 0 and 1", n, below, above)
		}
	}
	for _, n := range []int64{500, 1500, 4001} {
		exact := binomHalfExact(n)
		for _, j := range []int64{0, 1, n / 4, n/2 - 30, n/2 - 1, n / 2} {
			got, want := binomHalfTail(j, n), exact[j]
			if math.Abs(got-want) > 1e-10*want {
				t.Fatalf("binomHalfTail(%d, %d) = %v, exact %v", j, n, got, want)
			}
		}
	}

	// The sign test by hand: twice the chance of a split at least as uneven.
	known := []struct {
		a, b int64
		p    float64
	}{
		{8, 2, 2.0 * (1 + 10 + 45) / 1024},
		{1, 9, 2.0 * (1 + 10) / 1024},
		{0, 6, 2.0 / 64},
		{0, 5, 2.0 / 32},
		{0, 1, 1},
		{5, 5, 1},
		{0, 0, 1},
		{7, 0, 2.0 / 128},
	}
	for _, c := range known {
		if p := signTest(c.a, c.b); !near(p, c.p, 1e-13) {
			t.Errorf("signTest(%d, %d) = %v, want %v", c.a, c.b, p, c.p)
		}
	}
	// And by enumeration: the exact binomial sum, for every split of up to
	// 40 pairs. Swapping the sides changes nothing.
	for n := int64(0); n <= 40; n++ {
		exact := binomHalfExact(n)
		for a := int64(0); a <= n; a++ {
			b := n - a
			want := math.Min(1, 2*exact[min(a, b)])
			if a == b {
				want = 1
			}
			got := signTest(a, b)
			if !near(got, want, 1e-12) || got != signTest(b, a) || got < 0 || got > 1 {
				t.Fatalf("signTest(%d, %d) = %v, exact %v, swapped %v", a, b, got, want, signTest(b, a))
			}
		}
	}
	// Many pairs: the normal approximation with continuity correction,
	// z = (200 - 1) / sqrt(10000) = 1.99, gives p = 0.0466.
	if p := signTest(4900, 5100); !near(p, 0.0466, 0.0005) {
		t.Errorf("signTest(4900, 5100) = %v, want about 0.0466", p)
	}
	if p := signTest(0, 3000000); p < 0 || p > 1e-300 {
		t.Errorf("signTest(0, 3000000) = %v", p)
	}
}

func TestMedianRank(t *testing.T) {
	// By enumeration: the largest r with P(X <= r-1) <= 2.5%.
	for n := int64(0); n <= 400; n++ {
		exact := binomHalfExact(n)
		want := int64(0)
		for r := int64(1); r <= n/2 && exact[r-1] <= 0.025; r++ {
			want = r
		}
		got, ok := medianRank(n)
		if ok != (want > 0) || got != want {
			t.Fatalf("medianRank(%d) = %d, %v, enumeration gives %d", n, got, ok, want)
		}
	}
	// The ranks tables of the confidence interval of a median list, for
	// example 2 and 9 of 10 values and 40 and 61 of 100: worked out here as
	// P(X <= 1) = 11/1024 = 1.07% but P(X <= 2) = 56/1024 = 5.47% for 10.
	for n, want := range map[int64]int64{6: 1, 10: 2, 20: 6, 30: 10, 50: 18, 100: 40} {
		if got, _ := medianRank(n); got != want {
			t.Errorf("medianRank(%d) = %d, want %d", n, got, want)
		}
	}
	// A large sample: the interval still covers at least 95% and the next
	// rank would not.
	for _, n := range []int64{10001, 250000, 2000000} {
		r, ok := medianRank(n)
		if !ok || binomHalfTail(r-1, n) > 0.025 || binomHalfTail(r, n) <= 0.025 {
			t.Errorf("medianRank(%d) = %d: tails %v and %v", n, r, binomHalfTail(r-1, n), binomHalfTail(r, n))
		}
	}

	v := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	if lo, hi, ok := medianInterval(v); !ok || lo != 2 || hi != 9 {
		t.Errorf("median interval of 1..10 = %d to %d, %v, want 2 to 9", lo, hi, ok)
	}
	if _, _, ok := medianInterval(v[:5]); ok {
		t.Error("five values cannot give a 95% interval")
	}
}

// uByCounting is U of b: the pairs in which the value of b is larger, a tie
// counting as half.
func uByCounting(a, b []int64) float64 {
	u := 0.0
	for _, x := range a {
		for _, y := range b {
			switch {
			case y > x:
				u++
			case y == x:
				u += 0.5
			}
		}
	}
	return u
}

// permutationMoments walks every way of dealing the pooled values into a
// group of len(a) and a group of len(b) and returns the mean and variance of
// U over them, and the share of deals with U at least as far from the mean
// as the one seen: the exact permutation test.
func permutationMoments(a, b []int64) (mean, variance, exactP float64) {
	pool := append(append([]int64(nil), a...), b...)
	seen := uByCounting(a, b)
	centre := float64(len(a)*len(b)) / 2
	var us []float64
	pick := make([]bool, len(pool))
	var walk func(from, left int)
	walk = func(from, left int) {
		if left == 0 {
			var x, y []int64
			for i, v := range pool {
				if pick[i] {
					x = append(x, v)
				} else {
					y = append(y, v)
				}
			}
			us = append(us, uByCounting(x, y))
			return
		}
		for i := from; i <= len(pool)-left; i++ {
			pick[i] = true
			walk(i+1, left-1)
			pick[i] = false
		}
	}
	walk(0, len(a))
	extreme := 0
	for _, u := range us {
		mean += u
		if math.Abs(u-centre) >= math.Abs(seen-centre) {
			extreme++
		}
	}
	mean /= float64(len(us))
	for _, u := range us {
		variance += (u - mean) * (u - mean)
	}
	return mean, variance / float64(len(us)), float64(extreme) / float64(len(us))
}

func sorted(v ...int64) []int64 {
	out := append([]int64(nil), v...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func TestMannWhitneyByBruteForce(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	for round := 0; round < 300; round++ {
		na, nb := 1+rng.Intn(6), 1+rng.Intn(6)
		spread := int64(1 + rng.Intn(8)) // a small spread makes many ties
		a, b := make([]int64, na), make([]int64, nb)
		for i := range a {
			a[i] = rng.Int63n(spread)
		}
		for i := range b {
			b[i] = rng.Int63n(spread) + int64(rng.Intn(2))
		}
		a, b = sorted(a...), sorted(b...)

		p, larger := mannWhitney(a, b)
		u := uByCounting(a, b)
		if !near(larger, u/float64(na*nb), 1e-15) {
			t.Fatalf("%v against %v: share of pairs %v, counting gives %v", a, b, larger, u/float64(na*nb))
		}
		// The tie-corrected variance is the exact variance of U over all
		// deals of the pooled values, so the p-value must follow from the
		// moments found by walking every deal.
		mean, variance, _ := permutationMoments(a, b)
		want := 1.0
		if variance > 1e-12 {
			if z := (math.Abs(u-mean) - 0.5) / math.Sqrt(variance); z > 0 {
				want = math.Erfc(z / math.Sqrt2)
			}
		}
		if !near(mean, float64(na*nb)/2, 1e-9) || !near(p, want, 1e-9) {
			t.Fatalf("%v against %v: p = %v, the moments of all deals give %v (mean %v, variance %v)", a, b, p, want, mean, variance)
		}
		// Swapping the samples keeps the p-value and mirrors the share.
		ps, ls := mannWhitney(b, a)
		if ps != p || !near(ls+larger, 1, 1e-15) {
			t.Fatalf("%v against %v: swapped p = %v and share %v, from p = %v and share %v", a, b, ps, ls, p, larger)
		}
	}
}

func TestMannWhitneyKnownCases(t *testing.T) {
	// No ties, 3 against 4, every value of b above every value of a:
	// U = 12, mean 6, variance 3*4*8/12 = 8, z = 5.5/sqrt(8).
	p, larger := mannWhitney(sorted(1, 2, 3), sorted(4, 5, 6, 7))
	if want := math.Erfc(5.5 / math.Sqrt(8) / math.Sqrt2); !near(p, want, 1e-15) || larger != 1 {
		t.Errorf("separated samples: p = %v, share = %v, want %v and 1", p, larger, want)
	}
	// The same sample twice: U is its mean and nothing is shown.
	if p, larger := mannWhitney(sorted(1, 2, 2, 5, 9), sorted(1, 2, 2, 5, 9)); p != 1 || larger != 0.5 {
		t.Errorf("identical samples: p = %v, share = %v, want 1 and 0.5", p, larger)
	}
	// Every value equal: no variance at all.
	if p, larger := mannWhitney(sorted(4, 4, 4), sorted(4, 4)); p != 1 || larger != 0.5 {
		t.Errorf("all tied: p = %v, share = %v, want 1 and 0.5", p, larger)
	}
	if p, _ := mannWhitney(nil, sorted(1)); p != 1 {
		t.Errorf("an empty sample: p = %v, want 1", p)
	}

	// The normal approximation stays close to the exact permutation test on
	// samples small enough to walk: 7 against 8 values without ties.
	rng := rand.New(rand.NewSource(5))
	for round := 0; round < 12; round++ {
		values := rng.Perm(15)
		var a, b []int64
		for i, v := range values {
			// Shift b upwards in some rounds so that both ends of the scale
			// of p-values are met.
			if i < 7 {
				a = append(a, int64(v))
			} else {
				b = append(b, int64(v)+int64(round%4)*3)
			}
		}
		// Break the ties the shift made.
		for i := range a {
			a[i] = a[i]*100 + int64(i)
		}
		for i := range b {
			b[i] = b[i]*100 + 50 + int64(i)
		}
		a, b = sorted(a...), sorted(b...)
		p, _ := mannWhitney(a, b)
		_, _, exact := permutationMoments(a, b)
		if !near(p, exact, 0.02) {
			t.Errorf("round %d: normal approximation p = %v, exact permutation p = %v", round, p, exact)
		}
	}

	// Large samples: a p-value is a probability, also far out in the tail.
	plain := make([]int64, 100000)
	shifted := make([]int64, 100000)
	for i := range plain {
		plain[i] = int64(i)
		shifted[i] = int64(i) + 50000
	}
	if p, larger := mannWhitney(plain, shifted); p < 0 || p > 1e-100 || !near(larger, 0.875, 1e-3) {
		t.Errorf("shifted large samples: p = %v, share = %v", p, larger)
	}
}

func TestHolm(t *testing.T) {
	// Four tests: 0.005*4, 0.01*3, 0.03*2, then 0.04*1 raised to the value
	// before it.
	got := holm([]float64{0.01, 0.04, 0.03, 0.005})
	want := []float64{0.03, 0.06, 0.06, 0.02}
	for i := range want {
		if !near(got[i], want[i], 1e-15) {
			t.Fatalf("holm = %v, want %v", got, want)
		}
	}
	if got := holm([]float64{0.5, 0.9}); got[0] != 1 || got[1] != 1 {
		t.Errorf("adjusted values stop at 1: %v", got)
	}
	if got := holm(nil); len(got) != 0 {
		t.Errorf("holm of nothing = %v", got)
	}
	if got := holm([]float64{0.02}); got[0] != 0.02 {
		t.Errorf("one test is not adjusted: %v", got)
	}

	// The adjusted values keep the order of the raw ones, are never below
	// them, and do not depend on the order the tests are given in.
	rng := rand.New(rand.NewSource(9))
	for round := 0; round < 200; round++ {
		p := make([]float64, 1+rng.Intn(9))
		for i := range p {
			p[i] = math.Round(rng.Float64()*20) / 20 // ties are common
		}
		adj := holm(p)
		for i := range p {
			if adj[i] < p[i] || adj[i] > 1 {
				t.Fatalf("holm(%v) = %v", p, adj)
			}
			for j := range p {
				if p[i] < p[j] && adj[i] > adj[j] {
					t.Fatalf("holm(%v) = %v reverses %d and %d", p, adj, i, j)
				}
				if p[i] == p[j] && adj[i] != adj[j] {
					t.Fatalf("holm(%v) = %v splits the tie of %d and %d", p, adj, i, j)
				}
			}
		}
		perm := rng.Perm(len(p))
		shuffled := make([]float64, len(p))
		for i, from := range perm {
			shuffled[i] = p[from]
		}
		again := holm(shuffled)
		for i, from := range perm {
			if again[i] != adj[from] {
				t.Fatalf("holm(%v) = %v but holm(%v) = %v", p, adj, shuffled, again)
			}
		}
	}
}
