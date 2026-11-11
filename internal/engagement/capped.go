package engagement

import "sort"

// capped is a map that keeps memory bounded on hostile input and still gives
// the same answer whatever order the keys arrive in. It never holds more than
// 2*limit keys and, after finish, holds at most limit: the smallest ones in
// less order.
//
// Once it has shrunk, a key greater than the largest kept key is refused. A
// dropped or refused key can never come back, because the largest kept key
// only ever gets smaller. So a key that is kept at the end was never dropped,
// and its value saw every add: values of kept keys are exact, and over is true
// exactly when more than limit distinct keys were seen.
type capped[K comparable, V any] struct {
	limit   int
	less    func(a, b K) bool
	m       map[K]*V
	bounded bool
	max     K
	over    bool
}

func newCapped[K comparable, V any](limit int, less func(a, b K) bool) *capped[K, V] {
	if limit < 1 {
		limit = 1
	}
	return &capped[K, V]{limit: limit, less: less, m: make(map[K]*V)}
}

// slot returns the value kept for k, creating it when k is new. It returns
// nil when k is refused.
func (c *capped[K, V]) slot(k K) *V {
	if v, ok := c.m[k]; ok {
		return v
	}
	if c.bounded && c.less(c.max, k) {
		return nil
	}
	v := new(V)
	c.m[k] = v
	if len(c.m) > 2*c.limit {
		c.shrink()
		return c.m[k]
	}
	return v
}

// shrink keeps the limit smallest keys.
func (c *capped[K, V]) shrink() {
	keys := c.keys()
	for _, k := range keys[c.limit:] {
		delete(c.m, k)
	}
	c.max = keys[c.limit-1]
	c.bounded = true
	c.over = true
}

// finish brings the map down to its limit. Call it once, before reading.
func (c *capped[K, V]) finish() {
	if len(c.m) > c.limit {
		c.shrink()
	}
}

// keys returns the kept keys in less order.
func (c *capped[K, V]) keys() []K {
	keys := make([]K, 0, len(c.m))
	for k := range c.m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return c.less(keys[i], keys[j]) })
	return keys
}

func lessUint64(a, b uint64) bool { return a < b }

func lessString(a, b string) bool { return a < b }
