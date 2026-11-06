package proxy

import (
	"net/netip"
	"sync"
	"time"
)

// maxTrackedSources bounds the per-source map between sweeps. A flood of fresh
// source addresses would otherwise grow it for the whole idle-eviction window.
const maxTrackedSources = 1 << 16

// sourceKey is the unit the per-IP limits apply to. An IPv4 address is its own
// source; an IPv6 address counts as its /64, the smallest prefix a single host
// is routinely given, so rotating addresses inside it does not reset the
// limits. IPv4-mapped IPv6 is the IPv4 address. Unparseable input is used as is.
func sourceKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return a.String()
	}
	p, err := a.Prefix(64)
	if err != nil {
		return ip
	}
	return p.String()
}

// limiter bounds how much load a single attacker (or the internet at large) can
// place on the broker and its finite backend pool. A high-interaction honeypot
// is a genuinely expensive, genuinely dangerous resource (real containers, real
// code execution), so admission control is a security control, not just QoS:
// without it a trivial connection flood would exhaust the backend pool and deny
// the honeypot to everyone, or pin host CPU/memory.
//
// It enforces three independent limits:
//   - a per-source-IP token bucket (new connections per second, with burst),
//   - a per-source-IP concurrent-connection cap,
//   - a global concurrent-connection cap (also implicitly bounded by pool size).
//
// All three are checked atomically at admission; the global and per-IP counters
// are decremented when the connection finishes via the returned release func.
type limiter struct {
	mu sync.Mutex

	// configuration (immutable after construction)
	ratePerSec   float64       // sustained new-conns/sec per IP; <=0 disables rate limiting
	burst        float64       // max token bucket depth per IP
	perIPMax     int           // max concurrent conns per IP; <=0 disables
	globalMax    int           // max concurrent conns overall; <=0 disables
	idleEviction time.Duration // drop idle per-IP buckets after this long
	maxSources   int           // most per-source buckets kept at once

	// state
	global int
	ips    map[string]*ipState

	rejectTokens float64   // overall budget for logging rejections
	rejectLast   time.Time // last refill of rejectTokens

	now func() time.Time // injectable clock for deterministic tests
}

type ipState struct {
	tokens     float64   // current bucket tokens
	last       time.Time // last refill time
	active     int       // concurrent connections from this IP
	lastSeen   time.Time // for idle eviction
	lastReject time.Time // last rejection from this source that was logged
}

// Rejected connections are logged at most once per source per
// rejectLogEvery, and at most rejectLogRate times a second overall.
const (
	rejectLogEvery = time.Second
	rejectLogRate  = 100
)

// logRejection reports whether a connection from ip that was turned away
// should be written to the session log. Each logged rejection is a log line
// and, after ingestion, a database row, while it costs the sender only a TCP
// handshake; logging all of them let a flood the limits rejected fill the
// disk anyway.
func (l *limiter) logRejection(ip string) bool {
	key := sourceKey(ip)

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	st := l.ips[key]
	if st == nil {
		if len(l.ips) >= l.maxSources {
			l.makeRoomLocked(now)
		}
		st = &ipState{tokens: l.burst, last: now, lastSeen: now}
		l.ips[key] = st
	}
	if !st.lastReject.IsZero() && now.Sub(st.lastReject) < rejectLogEvery {
		return false
	}
	if el := now.Sub(l.rejectLast); el > 0 {
		l.rejectTokens += el.Seconds() * rejectLogRate
		if l.rejectTokens > rejectLogRate {
			l.rejectTokens = rejectLogRate
		}
		l.rejectLast = now
	}
	if l.rejectTokens < 1 {
		return false
	}
	l.rejectTokens--
	st.lastReject = now
	return true
}

func newLimiter(ratePerSec, burst float64, perIPMax, globalMax int) *limiter {
	return &limiter{
		ratePerSec:   ratePerSec,
		burst:        burst,
		perIPMax:     perIPMax,
		globalMax:    globalMax,
		idleEviction: 10 * time.Minute,
		maxSources:   maxTrackedSources,
		ips:          make(map[string]*ipState),
		now:          time.Now,
	}
}

// admit attempts to admit one new connection from ip. On success it returns
// (true, "", release); the caller MUST invoke release exactly once when the
// connection ends. On rejection it returns (false, reason, nil) where reason is
// one of the Reason* constants. release is safe to call once and only once.
func (l *limiter) admit(ip string) (bool, string, func()) {
	key := sourceKey(ip)

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()

	// Global concurrency cap first: cheapest rejection, protects the whole stack.
	if l.globalMax > 0 && l.global >= l.globalMax {
		return false, ReasonGlobalCap, nil
	}

	st := l.ips[key]
	if st == nil {
		if len(l.ips) >= l.maxSources {
			l.makeRoomLocked(now)
		}
		st = &ipState{tokens: l.burst, last: now}
		l.ips[key] = st
	}

	// Per-IP concurrency cap.
	if l.perIPMax > 0 && st.active >= l.perIPMax {
		st.lastSeen = now
		return false, ReasonPerIPCap, nil
	}

	// Per-IP token-bucket rate limit. Refill by elapsed time, then spend one.
	if l.ratePerSec > 0 {
		elapsed := now.Sub(st.last).Seconds()
		if elapsed > 0 {
			st.tokens += elapsed * l.ratePerSec
			if st.tokens > l.burst {
				st.tokens = l.burst
			}
			st.last = now
		}
		if st.tokens < 1 {
			st.lastSeen = now
			return false, ReasonRateLimited, nil
		}
		st.tokens--
	}

	// Admitted: account for it.
	st.active++
	st.lastSeen = now
	l.global++

	released := false
	release := func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if released {
			return
		}
		released = true
		if l.global > 0 {
			l.global--
		}
		if s := l.ips[key]; s != nil {
			if s.active > 0 {
				s.active--
			}
			s.lastSeen = l.now()
		}
	}
	return true, "", release
}

// sweep evicts per-IP buckets that have been idle longer than idleEviction and
// hold no active connections, so a churn of unique source IPs cannot grow the
// map without bound (a memory-exhaustion vector). Returns the number evicted.
func (l *limiter) sweep() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.evictLocked(l.now().Add(-l.idleEviction))
}

// evictLocked drops buckets with no live connection last seen before cutoff.
func (l *limiter) evictLocked(cutoff time.Time) int {
	n := 0
	for ip, st := range l.ips {
		if st.active == 0 && st.lastSeen.Before(cutoff) {
			delete(l.ips, ip)
			n++
		}
	}
	return n
}

// makeRoomLocked runs when the map is full and drops every bucket without a
// live connection. That forgets those sources' rate-limit tokens, which only
// helps someone who already controls this many sources; buckets with live
// connections (at most the global cap) are kept so concurrency accounting
// stays exact. Emptying the map rather than one slot keeps the scan amortized.
func (l *limiter) makeRoomLocked(now time.Time) {
	l.evictLocked(now.Add(time.Nanosecond))
}

// activeGlobal reports the current global concurrent-connection count (tests).
func (l *limiter) activeGlobal() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.global
}
