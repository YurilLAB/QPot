package engagement

import (
	"math"
	"sort"
)

// Alpha is the level every verdict of a comparison is given at, after Holm's
// correction: 5%.
const Alpha = 0.05

// MinCompare is the smallest number of sessions (or, for returning sources,
// of sources) each report must have in the base of a row for the row to get a
// verdict. Below it the row says "too few to compare".
const MinCompare = 30

// z95 is the 97.5th percentile of the standard normal distribution: the
// half-width, in standard deviations, of a two-sided 95% interval.
const z95 = 1.959963984540054

// tailEach is the probability a two-sided 95% interval leaves on each side.
const tailEach = (1 - 0.95) / 2

func clampUnit(x float64) float64 {
	return math.Max(0, math.Min(1, x))
}

// wilson returns the Wilson score 95% interval of the share k of n, as
// fractions. ok is false when n is zero.
func wilson(k, n int64) (lo, hi float64, ok bool) {
	if n <= 0 || k < 0 || k > n {
		return 0, 0, false
	}
	nn := float64(n)
	p := float64(k) / nn
	z2 := z95 * z95
	denom := 1 + z2/nn
	centre := (p + z2/(2*nn)) / denom
	half := z95 * math.Sqrt(p*(1-p)/nn+z2/(4*nn*nn)) / denom
	lo, hi = clampUnit(centre-half), clampUnit(centre+half)
	// The exact bounds at the ends, which rounding would miss.
	if k == 0 {
		lo = 0
	}
	if k == n {
		hi = 1
	}
	return lo, hi, true
}

// newcombe returns the 95% interval of the difference of two shares, kb of nb
// minus ka of na, as fractions: Newcombe's hybrid score interval, which
// combines the Wilson intervals of the two shares. ok is false when either
// base is zero.
func newcombe(ka, na, kb, nb int64) (lo, hi float64, ok bool) {
	la, ua, okA := wilson(ka, na)
	lb, ub, okB := wilson(kb, nb)
	if !okA || !okB {
		return 0, 0, false
	}
	pa, pb := float64(ka)/float64(na), float64(kb)/float64(nb)
	d := pb - pa
	sq := func(x float64) float64 { return x * x }
	lo = d - math.Sqrt(sq(pb-lb)+sq(ua-pa))
	hi = d + math.Sqrt(sq(ub-pb)+sq(pa-la))
	return math.Max(-1, lo), math.Min(1, hi), true
}

// fisherExact returns the two-sided p-value of Fisher's exact test that the
// shares k1 of n1 and k2 of n2 are equal: the probability, with all four
// margins fixed, of a table no more likely than the one seen.
//
// The probabilities are computed as ratios to the most likely table, stepping
// outwards from it, so nothing overflows and a base of millions costs a walk
// over the tables that matter.
func fisherExact(k1, n1, k2, n2 int64) float64 {
	// One order for both ways round, so swapping the reports gives the same
	// sums bit for bit.
	if n1 > n2 || (n1 == n2 && k1 > k2) {
		k1, n1, k2, n2 = k2, n2, k1, n1
	}
	total, all := k1+k2, n1+n2
	if n1 <= 0 || n2 <= 0 || total <= 0 || total >= all {
		return 1
	}
	// x is the count in the first row. It runs from low to high.
	low, high := max(0, total-n2), min(total, n1)
	mode := (total + 1) * (n1 + 1) / (all + 2)
	mode = max(low, min(high, mode))
	up := func(x int64) float64 { // P(x+1) / P(x)
		return float64(n1-x) * float64(total-x) / (float64(x+1) * float64(n2-total+x+1))
	}
	down := func(x int64) float64 { // P(x-1) / P(x)
		return float64(x) * float64(n2-total+x) / (float64(n1-x+1) * float64(total-x+1))
	}

	seen := 1.0
	for x := mode; x < k1 && seen > 0; x++ {
		seen *= up(x)
	}
	for x := mode; x > k1 && seen > 0; x-- {
		seen *= down(x)
	}
	// A table counts as "no more likely" within a relative 1e-7, the
	// tolerance R's fisher.test uses for the same comparison.
	limit := seen * (1 + 1e-7)
	sum, tail := 0.0, 0.0
	add := func(r float64) {
		sum += r
		if r <= limit {
			tail += r
		}
	}
	add(1)
	for x, r := mode, 1.0; x < high; x++ {
		if r *= up(x); r == 0 {
			break
		}
		add(r)
	}
	for x, r := mode, 1.0; x > low; x-- {
		if r *= down(x); r == 0 {
			break
		}
		add(r)
	}
	return clampUnit(tail / sum)
}

// binomHalfTail returns P(X <= j) for X binomial with n trials of chance
// one half.
func binomHalfTail(j, n int64) float64 {
	switch {
	case j < 0:
		return 0
	case j >= n:
		return 1
	case 2*j >= n:
		// The upper half: one minus the mirrored lower tail.
		return clampUnit(1 - binomHalfTail(n-j-1, n))
	}
	lg := func(x int64) float64 {
		v, _ := math.Lgamma(float64(x) + 1)
		return v
	}
	logTop := lg(n) - lg(j) - lg(n-j) - float64(n)*math.Ln2
	sum, term := 1.0, 1.0
	for k := j; k > 0; k-- {
		term *= float64(k) / float64(n-k+1)
		sum += term
		if term < sum*1e-17 {
			break
		}
	}
	return clampUnit(math.Exp(logTop) * sum)
}

// signTest returns the exact two-sided p-value of the sign test for a pairs
// going one way and b pairs going the other, ties left out: twice the chance
// of a split at least this uneven when each pair goes either way with equal
// chance. For a yes/no measure this is the exact McNemar test.
func signTest(a, b int64) float64 {
	if a < 0 || b < 0 || a == b {
		return 1
	}
	return clampUnit(2 * binomHalfTail(min(a, b), a+b))
}

// medianRank returns the rank r, counting from 1, for which the r-th smallest
// and the r-th largest of n values enclose the median of the population with
// a confidence of at least 95%, whatever its distribution: the largest r with
// P(X < r) <= 2.5% for X binomial(n, 1/2). ok is false when n is below 6,
// where even the smallest and the largest value do not reach 95%.
func medianRank(n int64) (r int64, ok bool) {
	if n < 6 {
		return 0, false
	}
	r = int64(math.Floor(float64(n)/2 - z95*math.Sqrt(float64(n))/2))
	r = max(1, min(n/2, r))
	for r > 1 && binomHalfTail(r-1, n) > tailEach {
		r--
	}
	for r < n/2 && binomHalfTail(r, n) <= tailEach {
		r++
	}
	return r, true
}

// medianInterval returns the distribution-free 95% interval of the median of
// the ascending values v.
func medianInterval(v []int64) (lo, hi int64, ok bool) {
	n := int64(len(v))
	r, ok := medianRank(n)
	if !ok {
		return 0, 0, false
	}
	return v[r-1], v[n-r], true
}

// mannWhitney runs the Mann-Whitney U test on two ascending, non-empty
// samples. It returns the two-sided p-value from the normal approximation,
// with the variance corrected for ties and a continuity correction of one
// half, and the chance that a value drawn from b is larger than one drawn
// from a, a tie counting as half: U of b divided by the number of pairs.
func mannWhitney(a, b []int64) (p, bLarger float64) {
	na, nb := float64(len(a)), float64(len(b))
	if na == 0 || nb == 0 {
		return 1, 0.5
	}
	// Walk the two samples together, one group of equal values at a time.
	// Every figure is a multiple of one half far below 2^53, so the sums are
	// exact and do not depend on which sample is called a.
	var rankB, ties float64
	i, j, before := 0, 0, 0.0
	for i < len(a) || j < len(b) {
		var v int64
		switch {
		case i >= len(a):
			v = b[j]
		case j >= len(b):
			v = a[i]
		default:
			v = min(a[i], b[j])
		}
		ca, cb := 0, 0
		for i < len(a) && a[i] == v {
			i++
			ca++
		}
		for j < len(b) && b[j] == v {
			j++
			cb++
		}
		t := float64(ca + cb)
		rankB += float64(cb) * (before + (t+1)/2)
		ties += t*t*t - t
		before += t
	}
	n := na + nb
	u := rankB - nb*(nb+1)/2
	bLarger = clampUnit(u / (na * nb))
	variance := na * nb / 12 * ((n + 1) - ties/(n*(n-1)))
	if variance <= 0 {
		return 1, bLarger // every value is the same
	}
	z := (math.Abs(u-na*nb/2) - 0.5) / math.Sqrt(variance)
	if z <= 0 {
		return 1, bLarger
	}
	return clampUnit(math.Erfc(z / math.Sqrt2)), bLarger
}

// holm returns the p-values adjusted by Holm's step-down method, in the order
// given: the smallest is multiplied by the number of tests, the next by one
// less, and so on, never falling below the one before and never above 1.
// Comparing an adjusted value with Alpha keeps the chance of any false "clear
// difference" among the tests at Alpha or below.
func holm(p []float64) []float64 {
	order := make([]int, len(p))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(x, y int) bool { return p[order[x]] < p[order[y]] })
	adjusted := make([]float64, len(p))
	running := 0.0
	for rank, i := range order {
		running = math.Max(running, math.Min(1, float64(len(p)-rank)*p[i]))
		adjusted[i] = running
	}
	return adjusted
}
