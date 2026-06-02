package cluster

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newInitializedManager returns a Manager with a freshly initialized cluster,
// ready to exercise the HTTP handlers.
func newInitializedManager(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(t.TempDir())
	if _, err := m.InitCluster("fuzz-cluster", "correct-horse-battery", DefaultClusterConfig()); err != nil {
		t.Fatalf("InitCluster: %v", err)
	}
	return m
}

// TestGossipHandlerRejectsMalformedNodes feeds the gossip handler node digests
// that JSON-decode to nil pointers or to nodes with empty IDs / invalid ports.
// The handler must not panic and must not pollute the node table with junk
// entries (e.g. a node keyed by ""), which would corrupt cluster membership.
func TestGossipHandlerRejectsMalformedNodes(t *testing.T) {
	m := newInitializedManager(t)
	pw := "correct-horse-battery"

	bodies := []string{
		`{"sender_id":"x","node_digest":[null]}`,                                      // nil *Node -> would nil-deref
		`{"sender_id":"x","node_digest":[{"id":"","address":"1.2.3.4","port":7946}]}`, // empty ID
		`{"sender_id":"x","node_digest":[{"id":"n1","address":"","port":7946}]}`,      // empty address
		`{"sender_id":"x","node_digest":[{"id":"n2","address":"1.2.3.4","port":0}]}`,  // bad port
		`{"sender_id":"x","node_digest":[{"id":"n3","address":"1.2.3.4","port":99999}]}`,
	}
	for _, b := range bodies {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/gossip", bytes.NewBufferString(b))
		req.Header.Set("X-Cluster-Password", pw)
		rec := httptest.NewRecorder()
		m.withClusterAuth(m.handleGossipHTTP)(rec, req) // must not panic
		if rec.Code != http.StatusOK {
			t.Errorf("body %q: status = %d, want 200", b, rec.Code)
		}
	}

	// No junk node should have been admitted (only the local node remains).
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.cluster.Nodes[""]; ok {
		t.Error("gossip admitted a node with empty ID")
	}
	for id, n := range m.cluster.Nodes {
		if n == nil {
			t.Errorf("nil node admitted under id %q", id)
			continue
		}
		if m.cluster.LocalNode != nil && id == m.cluster.LocalNode.ID {
			continue
		}
		if !validPeerNode(n) {
			t.Errorf("invalid peer node admitted: id=%q addr=%q port=%d", n.ID, n.Address, n.Port)
		}
	}
}

// FuzzClusterHandlers throws arbitrary bodies at the three network-facing JSON
// handlers (join, gossip, intel). None may panic regardless of input.
func FuzzClusterHandlers(f *testing.F) {
	seeds := []string{
		`{}`,
		`{"node_digest":[null,null]}`,
		`{"cluster_id":"x","password":"y"}`,
		`{"top_ips":[{"ip":"1.1.1.1","count":-5}]}`,
		`[]`, `null`, `not json`, `{"node_digest":123}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	// Initialize the cluster ONCE. InitCluster runs bcrypt, so doing it per
	// iteration capped the fuzzer at a few dozen execs; the handlers lock the
	// manager mutex internally, so a single shared manager is safe and lets the
	// fuzzer reach tens of thousands of executions.
	const pw = "correct-horse-battery"
	m := NewManager(f.TempDir())
	if _, err := m.InitCluster("fz", pw, DefaultClusterConfig()); err != nil {
		f.Fatalf("InitCluster: %v", err)
	}
	f.Fuzz(func(t *testing.T, body string) {
		// Call the handlers directly (not through withClusterAuth) so the fuzzer
		// exercises the JSON parsing and node/intel merge logic at full speed -
		// the bcrypt in the auth gate is slow and is covered separately by
		// TestGossipHandlerRejectsMalformedNodes. handleJoinHTTP self-rejects on
		// the cluster-ID check before any bcrypt, so it stays fast too.
		for _, h := range []struct {
			path    string
			handler http.HandlerFunc
		}{
			{"/api/v1/cluster/join", m.handleJoinHTTP},
			{"/api/v1/cluster/gossip", m.handleGossipHTTP},
			{"/api/v1/cluster/intel", m.handleIntelHTTP},
		} {
			req := httptest.NewRequest(http.MethodPost, h.path, bytes.NewBufferString(body))
			req.Header.Set("X-Cluster-Password", pw)
			rec := httptest.NewRecorder()
			h.handler(rec, req) // must not panic
		}
	})
}
