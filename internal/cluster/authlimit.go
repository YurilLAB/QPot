package cluster

import (
	"net"
	"sync"
	"time"
)

// Password-guessing limits for the cluster API. The peer endpoints are
// authenticated by the cluster password alone and the cluster port is open to
// the network, so a source that keeps sending wrong passwords is refused for
// the rest of the window, whatever it sends. Successful checks are not
// counted, so members are never affected.
//
// At most authFailSources sources are tracked. A source still inside its
// window is never dropped to make room (one guessing from enough addresses
// could otherwise clear its own block): while the table is full, every source
// it does not hold shares one overflow allowance of authFailLimit failures.
// Trusted sources (this host, and the exact addresses of the cluster's nodes)
// are counted in a table of their own instead, so the shared allowance cannot
// lock members out while many addresses guess, and a trusted source is still
// held to authFailLimit.
const (
	authFailLimit   = 20
	authFailWindow  = 10 * time.Minute
	authFailSources = 4096
)

// errTooManyAttempts is the join error for a throttled source.
const errTooManyAttempts = "too many failed attempts; try again later"

type authFailures struct {
	count int
	first time.Time
}

// authLimiter counts failed password checks per source. The zero value is
// ready to use.
type authLimiter struct {
	mu       sync.Mutex
	fails    map[string]*authFailures
	trusted  map[string]*authFailures // trusted sources, by authKey
	overflow authFailures             // failures of the sources a full table does not hold
}

// authSource keys a peer address: the IPv4 address, or the IPv6 /64 (one
// host can use a whole /64). addr may carry a port.
func authSource(addr string) string {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// authKey keys a source for the limiter: authSource for an untrusted one; the
// exact address for a trusted one, with every loopback address as one key (a
// local program can send from any 127.x address).
func authKey(addr string, trusted bool) string {
	if !trusted {
		return authSource(addr)
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	switch {
	case ip == nil:
		return host
	case ip.IsLoopback():
		return "loopback"
	default:
		return ip.String()
	}
}

// live returns src's entry in table while it is inside its window, dropping
// an expired one.
func live(table map[string]*authFailures, src string, now time.Time) *authFailures {
	f := table[src]
	if f != nil && now.Sub(f.first) > authFailWindow {
		delete(table, src)
		return nil
	}
	return f
}

// prune drops the expired entries of a full table.
func prune(table map[string]*authFailures, now time.Time) {
	if len(table) < authFailSources {
		return
	}
	for k, f := range table {
		if now.Sub(f.first) > authFailWindow {
			delete(table, k)
		}
	}
}

// blocked reports whether src has used up its failed attempts. A trusted src
// (keyed by authKey) is held to its own count; an untrusted one the table does
// not hold, to the shared overflow allowance.
func (l *authLimiter) blocked(src string, now time.Time, trusted bool) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if trusted {
		if f := live(l.trusted, src, now); f != nil {
			return f.count >= authFailLimit
		}
		if len(l.trusted) < authFailSources {
			return false // its failures will have a counter of their own
		}
	}
	if f := live(l.fails, src, now); f != nil {
		return f.count >= authFailLimit
	}
	if now.Sub(l.overflow.first) > authFailWindow {
		return false
	}
	return l.overflow.count >= authFailLimit
}

// failed records a failed password check from src (keyed by authKey).
func (l *authLimiter) failed(src string, now time.Time, trusted bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if trusted {
		if l.trusted == nil {
			l.trusted = make(map[string]*authFailures)
		}
		if f := live(l.trusted, src, now); f != nil {
			f.count++
			return
		}
		prune(l.trusted, now)
		if len(l.trusted) < authFailSources {
			l.trusted[src] = &authFailures{count: 1, first: now}
			return
		}
		// Unreachable in practice (trusted keys are this host and the nodes):
		// a full table counts it as untrusted below.
	}
	if l.fails == nil {
		l.fails = make(map[string]*authFailures)
	}
	if f := live(l.fails, src, now); f != nil {
		f.count++
		return
	}
	prune(l.fails, now)
	if len(l.fails) >= authFailSources {
		if now.Sub(l.overflow.first) > authFailWindow {
			l.overflow = authFailures{first: now}
		}
		l.overflow.count++
		return
	}
	l.fails[src] = &authFailures{count: 1, first: now}
}
