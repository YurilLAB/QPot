package cluster

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// recordingPeer is a peer API that records the paths it was asked for.
type recordingPeer struct {
	mu    sync.Mutex
	paths []string
}

func (p *recordingPeer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.paths = append(p.paths, r.URL.Path)
	p.mu.Unlock()
	_ = json.NewEncoder(w).Encode(GossipMessage{SenderID: "qn_peer"})
}

func (p *recordingPeer) got() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.paths...)
}

func plainCluster(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(t.TempDir())
	cfg := DefaultClusterConfig()
	cfg.EnableEncryption = false
	if _, err := m.InitCluster("c", "password123", cfg); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestGossipedAddressCannotRewriteRequests: a node address learned from a
// gossip digest was pasted into "scheme://%s:%d/api/v1/cluster/gossip", so an
// address like "10.0.0.5:8080/admin/reset?" made every member POST (with the
// cluster password header) to an arbitrary host, port and path.
func TestGossipedAddressCannotRewriteRequests(t *testing.T) {
	peer := &recordingPeer{}
	srv := httptest.NewServer(peer)
	defer srv.Close()
	hostPort := strings.TrimPrefix(srv.URL, "http://")

	m := plainCluster(t)
	digest, _ := json.Marshal(GossipMessage{SenderID: "qn_x", NodeDigest: []*Node{
		{ID: "qn_evil", Address: hostPort + "/admin/reset?", Port: 7946, Status: NodeStatusHealthy},
		{ID: "qn_evil2", Address: "user@" + hostPort + "#", Port: 7946, Status: NodeStatusHealthy},
	}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/gossip", bytes.NewReader(digest))
	req.Header.Set("X-Cluster-Password", "password123")
	rec := httptest.NewRecorder()
	m.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("gossip: %d %s", rec.Code, rec.Body.String())
	}
	m.gossip()
	for _, p := range peer.got() {
		if p != "/api/v1/cluster/gossip" {
			t.Fatalf("a gossiped node address redirected a member's request to %q", p)
		}
	}
	for _, n := range m.GetNodes() {
		if strings.ContainsAny(n.Address, "/?#@") {
			t.Errorf("node %s with address %q was accepted", n.ID, n.Address)
		}
	}
}

// FuzzPeerURL: any address a peer can get accepted yields a URL for exactly
// that host and port and the intended API path.
func FuzzPeerURL(f *testing.F) {
	for _, s := range []string{"10.0.0.5", "::1", "fe80::1", "node-1.example.com", "a/b", "h:1", "x?y", "u@h", "[::1]", "-bad", "ok-", "a..b", "1.2.3.4.5"} {
		f.Add(s, 7946)
	}
	f.Fuzz(func(t *testing.T, addr string, port int) {
		n := &Node{ID: "qn_f", Address: addr, Port: port}
		if !validPeerNode(n) {
			return
		}
		raw := peerURL("https", addr, port, "/api/v1/cluster/gossip")
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("peerURL(%q, %d) = %q does not parse: %v", addr, port, raw, err)
		}
		if u.Path != "/api/v1/cluster/gossip" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			t.Fatalf("address %q changed the request: %q", addr, raw)
		}
		if u.Hostname() != addr || u.Port() != strconv.Itoa(port) {
			t.Fatalf("address %q, port %d: URL %q targets %q:%q", addr, port, raw, u.Hostname(), u.Port())
		}
	})
}

// TestJoinQueueIsBounded: every password-holding join request with a new
// hostname added a pending entry (up to 1 MiB of metadata each) and a
// decision record that were never removed, so the host's memory grew with
// every request.
func TestJoinQueueIsBounded(t *testing.T) {
	const pw = "correct-horse-battery"
	m := NewManager(t.TempDir())
	cl, err := m.InitCluster("c", pw, DefaultClusterConfig())
	if err != nil {
		t.Fatal(err)
	}
	const n = 3000
	for i := 0; i < n; i++ {
		m.HandleJoinRequest(&JoinRequest{ClusterID: cl.ID, Password: pw, NodeName: "flood-" + strconv.Itoa(i),
			NodeAddress: "10.0.0.9", NodePort: 7946}, "198.51.100.7")
	}
	m.mu.RLock()
	pending, outcomes := len(m.pendingJoins), len(m.joinOutcomes)
	m.mu.RUnlock()
	if pending > maxPendingJoins || outcomes > maxPendingJoins+maxJoinOutcomes {
		t.Fatalf("%d join requests left %d pending entries and %d outcomes", n, pending, outcomes)
	}

	// Decided requests are dropped once the joiner can no longer be polling.
	for _, p := range m.ListPendingJoins() {
		if err := m.DenyJoin(p.RequestID); err != nil {
			t.Fatal(err)
		}
	}
	m.mu.Lock()
	for _, o := range m.joinOutcomes {
		o.DecidedAt = o.DecidedAt.Add(-2 * joinRequestTTL)
	}
	m.mu.Unlock()
	m.HandleJoinRequest(&JoinRequest{ClusterID: cl.ID, Password: pw, NodeName: "late", NodeAddress: "10.0.0.9", NodePort: 7946}, "198.51.100.8")
	m.mu.RLock()
	outcomes = len(m.joinOutcomes)
	m.mu.RUnlock()
	if outcomes != 1 {
		t.Fatalf("%d expired outcomes kept", outcomes-1)
	}
}

// TestPeerIntelOnlyFromMembers: intel was stored under whatever node_id the
// body named, so one password holder could fill the map with any number of
// 1 MiB entries.
func TestPeerIntelOnlyFromMembers(t *testing.T) {
	m := plainCluster(t)
	h := m.apiHandler()
	for i := 0; i < 500; i++ {
		body, _ := json.Marshal(ThreatIntel{NodeID: "qn_fake" + strconv.Itoa(i), TopSourceIPs: []IPCount{{IP: "203.0.113.1", Count: 1}}})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/intel", bytes.NewReader(body))
		req.Header.Set("X-Cluster-Password", "password123")
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	m.mu.RLock()
	got := len(m.peerIntel)
	m.mu.RUnlock()
	if got != 0 {
		t.Fatalf("stored intel for %d nodes that are not members", got)
	}

	// A member's intel is still kept.
	m.mu.Lock()
	m.cluster.Nodes["qn_member"] = &Node{ID: "qn_member", Address: "10.0.0.2", Port: 7946, Status: NodeStatusHealthy}
	m.mu.Unlock()
	body, _ := json.Marshal(ThreatIntel{NodeID: "qn_member"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/intel", bytes.NewReader(body))
	req.Header.Set("X-Cluster-Password", "password123")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if len(m.GetThreatIntel()) != 1 {
		t.Fatal("member intel was not stored")
	}
}

// TestGossipReachesIPv6Peer: peer URLs were built with "%s:%d", which gives
// "http://::1:7946/..." for an IPv6 member, so IPv6 peers were never reached
// and were marked failed.
func TestGossipReachesIPv6Peer(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback")
	}
	peer := &recordingPeer{}
	srv := &http.Server{Handler: peer}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	m := plainCluster(t)
	m.mu.Lock()
	m.cluster.Nodes["qn_v6"] = &Node{ID: "qn_v6", Address: "::1", Port: ln.Addr().(*net.TCPAddr).Port, Status: NodeStatusHealthy}
	m.mu.Unlock()
	m.gossip()
	if len(peer.got()) == 0 {
		t.Fatal("gossip never reached the IPv6 peer")
	}
	for _, n := range m.GetNodes() {
		if n.ID == "qn_v6" && n.Status != NodeStatusHealthy {
			t.Fatalf("IPv6 peer marked %s", n.Status)
		}
	}
}

// TestInitRejectsPasswordBcryptCannotHash: bcrypt only takes 72 bytes. A longer
// cluster password (a generated passphrase) was accepted, stored as the hash
// "invalid", and the cluster could never be unlocked again: the control plane
// logged "Cluster not started" on every start and no node could join.
func TestInitRejectsPasswordBcryptCannotHash(t *testing.T) {
	pw := strings.Repeat("correct-horse-", 6) // 84 bytes
	dir := t.TempDir()
	m := NewManager(dir)
	if _, err := m.InitCluster("c", pw, DefaultClusterConfig()); err == nil {
		// Accepting it is only fine if the cluster then works with it.
		restored := NewManager(dir)
		if _, err := restored.LoadCluster(); err != nil {
			t.Fatal(err)
		}
		if err := restored.UnlockPassword(pw); err != nil {
			t.Fatalf("InitCluster accepted a %d-byte password that can never unlock the cluster: %v", len(pw), err)
		}
	}
	// 72 bytes is still fine.
	ok := strings.Repeat("x", 72)
	m = NewManager(t.TempDir())
	if _, err := m.InitCluster("c", ok, DefaultClusterConfig()); err != nil {
		t.Fatalf("72-byte password rejected: %v", err)
	}
}
