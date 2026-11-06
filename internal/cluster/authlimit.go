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
const (
	authFailLimit   = 20
	authFailWindow  = 10 * time.Minute
	authFailSources = 4096 // tracked sources; the oldest is dropped beyond this
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
	mu    sync.Mutex
	fails map[string]*authFailures
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

// blocked reports whether src has used up its failed attempts.
func (l *authLimiter) blocked(src string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.fails[src]
	if f == nil {
		return false
	}
	if now.Sub(f.first) > authFailWindow {
		delete(l.fails, src)
		return false
	}
	return f.count >= authFailLimit
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
		var oldest string
		for k, f := range l.fails {
			if now.Sub(f.first) > authFailWindow {
				delete(l.fails, k)
				continue
			}
			if oldest == "" || f.first.Before(l.fails[oldest].first) {
				oldest = k
			}
		}
		if len(l.fails) >= authFailSources {
			delete(l.fails, oldest)
		}
	}
	l.fails[src] = &authFailures{count: 1, first: now}
}
