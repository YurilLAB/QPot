package proxy

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
)

// Backend identifies one real-OpenSSH backend the broker can splice a session
// to. Addr is a fixed, operator-configured dial target (e.g. "ssh-backend-1:22"
// on the internal docker network) — it is NEVER derived from attacker input, so
// the broker cannot be turned into an SSRF primitive.
type Backend struct {
	ID   string // stable identifier, used in events and for reset
	Addr string // host:port to dial (internal network only)
}

// ErrNoBackend is returned by Lease when every backend is currently in use. The
// broker treats this as a load signal and rejects the connection rather than
// queueing unboundedly (which would be a DoS amplifier).
var ErrNoBackend = errors.New("proxy: no backend available")

// ResetFunc is invoked (in its own goroutine) after a session on a backend ends,
// before that backend is returned to the available set. It is the hook the
// orchestration layer uses to restore the backend to a pristine state — e.g.
// `docker restart` or a snapshot rollback — so no attacker ever inherits the
// previous attacker's changes (persistence, planted creds, dropped tooling).
// A nil ResetFunc means "reuse as-is" (acceptable only for stateless backends).
type ResetFunc func(Backend) error

// Pool hands out backends one session at a time. A backend that is leased is
// removed from the available set; releasing it runs the reset hook and then
// (only if reset succeeded) returns it to rotation. A backend whose reset fails
// is quarantined (kept out of rotation) so a wedged box is never handed to a new
// attacker — better to shrink capacity than to serve a dirty backend.
type Pool struct {
	mu          sync.Mutex
	available   []Backend
	leased      map[string]Backend
	quarantined map[string]Backend
	reset       ResetFunc
}

// ParseBackends parses an operator-supplied backend list of the form
//
//	"id1=host1:22,id2=host2:22"   (explicit ids)
//	"host1:22,host2:22"           (ids auto-assigned be1, be2, …)
//
// into validated Backend values. Every address must be a syntactically valid
// host:port. This is OPERATOR configuration, not attacker input, but it is
// validated and fuzzed anyway so a typo fails loudly at startup rather than
// silently producing a broker that dials nowhere. Duplicate or empty entries are
// rejected so the pool size is exactly what the operator wrote.
func ParseBackends(s string) ([]Backend, error) {
	var out []Backend
	seen := map[string]bool{}
	for i, raw := range strings.Split(s, ",") {
		field := strings.TrimSpace(raw)
		if field == "" {
			continue
		}
		id, addr := "", field
		if eq := strings.IndexByte(field, '='); eq >= 0 {
			id = strings.TrimSpace(field[:eq])
			addr = strings.TrimSpace(field[eq+1:])
		}
		if id == "" {
			id = fmt.Sprintf("be%d", i+1)
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil || host == "" || port == "" {
			return nil, fmt.Errorf("proxy: invalid backend address %q", addr)
		}
		if p := 0; func() bool { _, e := fmt.Sscanf(port, "%d", &p); return e != nil || p < 1 || p > 65535 }() {
			return nil, fmt.Errorf("proxy: invalid backend port in %q", addr)
		}
		if seen[id] {
			return nil, fmt.Errorf("proxy: duplicate backend id %q", id)
		}
		seen[id] = true
		out = append(out, Backend{ID: id, Addr: addr})
	}
	if len(out) == 0 {
		return nil, errors.New("proxy: no backends configured")
	}
	return out, nil
}

// NewPool builds a Pool over a fixed backend set. reset may be nil.
func NewPool(backends []Backend, reset ResetFunc) *Pool {
	p := &Pool{
		available:   make([]Backend, 0, len(backends)),
		leased:      make(map[string]Backend),
		quarantined: make(map[string]Backend),
		reset:       reset,
	}
	seen := map[string]bool{}
	for _, b := range backends {
		if b.ID == "" || b.Addr == "" || seen[b.ID] {
			continue // ignore malformed/duplicate entries defensively
		}
		seen[b.ID] = true
		p.available = append(p.available, b)
	}
	return p
}

// Lease removes and returns an available backend, or ErrNoBackend if none are
// free. Non-blocking by design: capacity is bounded, so the broker fails fast
// instead of building an unbounded waiter queue.
func (p *Pool) Lease() (Backend, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(p.available)
	if n == 0 {
		return Backend{}, ErrNoBackend
	}
	b := p.available[n-1]
	p.available = p.available[:n-1]
	p.leased[b.ID] = b
	return b, nil
}

// Release ends a lease. The reset hook (if any) runs synchronously here; on
// success the backend rejoins the available set, on failure it is quarantined.
// Releasing a backend that is not currently leased is a no-op.
func (p *Pool) Release(b Backend) {
	p.mu.Lock()
	if _, ok := p.leased[b.ID]; !ok {
		p.mu.Unlock()
		return
	}
	delete(p.leased, b.ID)
	reset := p.reset
	p.mu.Unlock()

	if reset != nil {
		if err := reset(b); err != nil {
			p.mu.Lock()
			p.quarantined[b.ID] = b
			p.mu.Unlock()
			return
		}
	}

	p.mu.Lock()
	p.available = append(p.available, b)
	p.mu.Unlock()
}

// Stats reports pool occupancy (available, leased, quarantined) for health
// endpoints and tests.
func (p *Pool) Stats() (available, leased, quarantined int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.available), len(p.leased), len(p.quarantined)
}

// Size is the total number of backends the pool was built with that are still
// in rotation (available + leased; excludes quarantined).
func (p *Pool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.available) + len(p.leased)
}
