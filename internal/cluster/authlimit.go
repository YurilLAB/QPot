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
// it does not hold shares one overflow allowance of authFailLimit failures,
// which does not apply to trusted sources (members and this host).
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
	overflow authFailures // failures of the sources a full table does not hold
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

// blocked reports whether src has used up its failed attempts, or, for a
// source the table does not hold, whether the shared overflow allowance is
// used up. A trusted source is held only to its own count.
func (l *authLimiter) blocked(src string, now time.Time, trusted bool) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if f := l.fails[src]; f != nil {
		if now.Sub(f.first) <= authFailWindow {
			return f.count >= authFailLimit
		}
		delete(l.fails, src)
	}
	if trusted || now.Sub(l.overflow.first) > authFailWindow {
		return false
	}
	return l.overflow.count >= authFailLimit
}

// failed records a failed password check from src.
func (l *authLimiter) failed(src string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fails == nil {
		l.fails = make(map[string]*authFailures)
	}
	if f := l.fails[src]; f != nil && now.Sub(f.first) <= authFailWindow {
		f.count++
		return
	}
	if len(l.fails) >= authFailSources {
		for k, f := range l.fails {
			if now.Sub(f.first) > authFailWindow {
				delete(l.fails, k)
			}
		}
	}
	if len(l.fails) >= authFailSources {
		if now.Sub(l.overflow.first) > authFailWindow {
			l.overflow = authFailures{first: now}
		}
		l.overflow.count++
		return
	}
	l.fails[src] = &authFailures{count: 1, first: now}
}
