package proxy

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// GenerationGate lets the broker tell a REAL backend recreation apart from one
// an attacker staged. The trusted host-side recycler bumps a per-backend
// counter file after every recreation it performs (see
// instance.BackendRecycler); the directory is mounted read-only into the
// broker and is not reachable from any backend.
//
// Reachability alone is not proof: a root attacker inside a backend can leave
// `(sleep 2; kill 1) &` running so sshd goes away and comes back (restart
// policy), which looked exactly like a recreation. With the gate, a reset only
// counts once the counter has moved past its value when the backend was leased
// to the session being cleaned up.
type GenerationGate struct {
	dir  string
	mu   sync.Mutex
	base map[string]uint64 // backend ID -> generation when it was leased
}

// NewGenerationGate reads generations from dir.
func NewGenerationGate(dir string) *GenerationGate {
	return &GenerationGate{dir: dir, base: map[string]uint64{}}
}

// Generation returns the backend's current generation (0 if none recorded).
func (g *GenerationGate) Generation(id string) uint64 {
	// Backend IDs come from operator config and are validated, but never let
	// one name a path outside the directory.
	if id == "" || strings.ContainsAny(id, `/\`) || id == "." || id == ".." {
		return 0
	}
	// Open only an entry named exactly id. On a case-insensitive or aliasing
	// filesystem (Windows, macOS, Docker Desktop bind mounts) "BE1", "be1."
	// or "be1::$DATA" open be1's counter, so two backends could share one.
	entries, err := os.ReadDir(g.dir)
	if err != nil {
		return 0
	}
	found := false
	for _, e := range entries {
		if e.Name() == id {
			found = true
			break
		}
	}
	if !found {
		return 0
	}
	b, err := os.ReadFile(filepath.Join(g.dir, id))
	if err != nil {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// OnLease records the backend's generation as it is handed to a session.
func (g *GenerationGate) OnLease(b Backend) {
	gen := g.Generation(b.ID)
	g.mu.Lock()
	g.base[b.ID] = gen
	g.mu.Unlock()
}

// BaseGeneration returns the immutable generation snapshot captured for id by
// OnLease. Events must carry this value, rather than a later read of the counter,
// so a delayed or replayed reset request cannot reset a newer active session.
func (g *GenerationGate) BaseGeneration(id string) (uint64, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	n, ok := g.base[id]
	return n, ok
}

// Advanced reports whether the backend has been recreated by the host since
// it was last leased.
func (g *GenerationGate) Advanced(b Backend) bool {
	base, ok := g.BaseGeneration(b.ID)
	return ok && g.Generation(b.ID) > base
}
