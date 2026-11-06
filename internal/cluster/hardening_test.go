package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
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
	setPeerAuth(req, "password123", m.memberKey())
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
		setPeerAuth(req, "password123", m.memberKey())
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
	setPeerAuth(req, "password123", m.memberKey())
	h.ServeHTTP(httptest.NewRecorder(), req)
	if len(m.GetThreatIntel()) != 1 {
		t.Fatal("member intel was not stored")
	}
}

// loopGoroutines counts running goroutines whose stack is in fn.
func loopGoroutines(fn string) int {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	n := 0
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, fn) {
			n++
		}
	}
	return n
}

// TestRestartDoesNotShareLoopState: Start re-creates stopCh and the tickers so
// a stopped manager can start again, but the gossip and sync loops read those
// fields on every turn. A loop that was mid-round during Stop+Start picked up
// the new channel and ticker and kept running next to the loop the new Start
// launched, so each restart added another gossip and sync loop.
func TestRestartDoesNotShareLoopState(t *testing.T) {
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(GossipMessage{SenderID: "qn_peer"})
	})
	srv := httptest.NewServer(slow)
	defer srv.Close()
	host, port := peerAddr(t, srv.URL)

	m := NewManager(t.TempDir())
	cfg := DefaultClusterConfig()
	cfg.EnableEncryption = false
	cfg.BindAddr, cfg.BindPort = "127.0.0.1", 0
	cfg.GossipInterval = 10 * time.Millisecond
	cfg.SyncInterval = 10 * time.Millisecond
	if _, err := m.InitCluster("c", "password123", cfg); err != nil {
		t.Fatal(err)
	}
	m.UpdateThreatIntel([]IPCount{{IP: "203.0.113.5", Count: 1}})
	m.mu.Lock()
	m.cluster.Nodes["qn_peer"] = &Node{ID: "qn_peer", Address: host, Port: port, Status: NodeStatusHealthy}
	m.mu.Unlock()

	for i := 0; i < 3; i++ {
		if err := m.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(60 * time.Millisecond) // a round is in flight
		if err := m.Stop(); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	time.Sleep(500 * time.Millisecond) // the stopped rounds finish
	if g, s := loopGoroutines("(*Manager).gossipLoop"), loopGoroutines("(*Manager).syncLoop"); g != 1 || s != 1 {
		t.Fatalf("after restarts: %d gossip loops and %d sync loops running, want 1 each", g, s)
	}
}

// TestHostOnlyAcceptsOwnAddressOnly: the host check admits loopback and a
// connection from this host's own address (a cluster bound to one address),
// never another machine on the same network.
func TestHostOnlyAcceptsOwnAddressOnly(t *testing.T) {
	cases := []struct {
		remote, local string
		want          bool
	}{
		{"127.0.0.1:5000", "127.0.0.1:7946", true},
		{"[::1]:5000", "[::1]:7946", true},
		{"10.0.0.5:5000", "10.0.0.5:7946", true},
		{"10.0.0.6:5000", "10.0.0.5:7946", false},
		{"192.0.2.1:5000", "", false},
		{"0.0.0.0:5000", "0.0.0.0:7946", false},
		{"garbage", "10.0.0.5:7946", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/cluster/pending", nil)
		r.RemoteAddr = c.remote
		if c.local != "" {
			la, err := net.ResolveTCPAddr("tcp", c.local)
			if err != nil {
				t.Fatal(err)
			}
			r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, net.Addr(la)))
		}
		if got := fromThisHost(r); got != c.want {
			t.Errorf("remote %s, local %s: fromThisHost = %v, want %v", c.remote, c.local, got, c.want)
		}
	}
}

// TestPasswordGuessingIsThrottled: the peer endpoints check only
// X-Cluster-Password (no cluster ID), the cluster port listens on 0.0.0.0, and
// a running node compares passwords in constant time, so anyone who could
// reach the port could try passwords as fast as the network allowed. A source
// that keeps failing must be cut off, without locking out other sources.
func TestPasswordGuessingIsThrottled(t *testing.T) {
	const pw = "correct-horse-battery"
	m := NewManager(t.TempDir())
	cl, err := m.InitCluster("c", pw, DefaultClusterConfig())
	if err != nil {
		t.Fatal(err)
	}
	h := m.apiHandler()
	status := func(remote, password string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/cluster/status", nil)
		req.RemoteAddr = remote
		setPeerAuth(req, password, m.memberKey())
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	const attacker = "198.51.100.66:40000"
	for i := 0; i < 500; i++ {
		status(attacker, "guess-"+strconv.Itoa(i))
	}
	if code := status(attacker, pw); code == http.StatusOK {
		t.Fatal("after 500 wrong passwords the same source can still test guesses (the right one answered 200)")
	}
	join := func(remote, password string) *JoinResponse {
		return m.HandleJoinRequest(&JoinRequest{ClusterID: cl.ID, Password: password, NodeName: "n",
			NodeAddress: "10.0.0.7", NodePort: 7946}, remote)
	}
	if r := join("198.51.100.66", pw); r.Status == "pending" || r.Success {
		t.Fatal("throttled source got its join request queued")
	}

	// One IPv6 host owns a whole /64: rotating addresses in it does not reset
	// the count.
	for i := 0; i < authFailLimit; i++ {
		status("[2001:db8:1:2::"+strconv.FormatInt(int64(i+1), 16)+"]:4000", "guess")
	}
	if code := status("[2001:db8:1:2:ffff::9]:4000", pw); code == http.StatusOK {
		t.Fatal("rotating through one IPv6 /64 escaped the limit")
	}

	// Another source with the right password is unaffected.
	if code := status("203.0.113.10:5000", pw); code != http.StatusOK {
		t.Fatalf("an honest member was locked out: %d", code)
	}
	if r := join("203.0.113.10", pw); r.Status != "pending" {
		t.Fatalf("an honest joiner was refused: %+v", r)
	}
}

// TestDeniedJoinerCannotGossipItselfIn: "joining needs the password and the
// host's approval", but the gossip, intel, leave, nodes and status endpoints
// only checked the password, which every joiner has. A joiner the host denied
// could post a gossip digest naming its own node and was a member, could read
// every member's QPot ID from /nodes, and could remove members via /leave.
func TestDeniedJoinerCannotGossipItselfIn(t *testing.T) {
	const pw = "correct-horse-battery"
	host := NewManager(t.TempDir())
	cl, err := host.InitCluster("prod", pw, DefaultClusterConfig())
	if err != nil {
		t.Fatal(err)
	}
	host.mu.Lock()
	host.cluster.LocalNode.QPotID = "qp_hostsecretidhostsecretid"
	host.mu.Unlock()
	jr := host.HandleJoinRequest(&JoinRequest{ClusterID: cl.ID, Password: pw, NodeName: "evil",
		NodeAddress: "10.6.6.6", NodePort: 7946}, "10.6.6.6")
	if jr.Status != "pending" {
		t.Fatalf("join: %+v", jr)
	}
	if err := host.DenyJoin(jr.RequestID); err != nil {
		t.Fatal(err)
	}

	h := host.apiHandler()
	send := func(method, path string, body any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(method, path, bytes.NewReader(b))
		req.RemoteAddr = "10.6.6.6:50000"
		req.Header.Set("X-Cluster-Password", pw)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	send(http.MethodPost, "/api/v1/cluster/gossip", GossipMessage{SenderID: "qn_evil", NodeDigest: []*Node{
		{ID: "qn_evil", Name: "evil", Address: "10.6.6.6", Port: 7946, Status: NodeStatusHealthy, LastSeen: time.Now()},
	}})
	for _, n := range host.GetNodes() {
		if n.ID == "qn_evil" {
			t.Fatal("the denied joiner added itself to the membership through gossip")
		}
	}
	if rec := send(http.MethodGet, "/api/v1/cluster/nodes", nil); strings.Contains(rec.Body.String(), "qp_hostsecretid") {
		t.Fatal("the denied joiner read the members' QPot IDs from /nodes")
	}
	send(http.MethodPost, "/api/v1/cluster/leave", map[string]string{"node_id": cl.LocalNode.ID})
	if len(host.GetNodes()) != 1 {
		t.Fatal("the denied joiner removed the host's own node via /leave")
	}
}

// TestClusterWithoutMemberKeyKeepsPasswordPeers: a cluster.json written before
// the member key existed has none, and its members never received one; they
// must keep working on the password alone.
func TestClusterWithoutMemberKeyKeepsPasswordPeers(t *testing.T) {
	m := plainCluster(t)
	m.mu.Lock()
	m.cluster.MemberKey = ""
	m.mu.Unlock()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/cluster/status", nil)
	req.Header.Set("X-Cluster-Password", "password123")
	rec := httptest.NewRecorder()
	m.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("password-only peer of an older cluster: %d", rec.Code)
	}
}

// TestApprovedMemberStillGossips is the positive control for the member key:
// a node admitted by the host gossips with it over the real API.
func TestApprovedMemberStillGossips(t *testing.T) {
	const pw = "correct-horse-battery"
	host := NewManager(t.TempDir())
	cfg := DefaultClusterConfig()
	cfg.EnableEncryption = false
	cfg.RequireApproval = false
	cl, err := host.InitCluster("prod", pw, cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(host.apiHandler())
	defer srv.Close()
	hostIP, hostPort := peerAddr(t, srv.URL)
	host.mu.Lock()
	host.cluster.LocalNode.Address, host.cluster.LocalNode.Port = hostIP, hostPort
	host.mu.Unlock()

	member := NewManager(t.TempDir())
	if _, err := member.JoinCluster(cl.ID, pw, &Node{Name: "m1", Address: "127.0.0.1", Port: 7999}, []string{srv.URL}); err != nil {
		t.Fatal(err)
	}
	member.gossip()
	for _, n := range member.GetNodes() {
		if n.Address == hostIP && n.Port == hostPort && n.Status != NodeStatusHealthy {
			t.Fatalf("member's gossip to the host failed: host marked %s", n.Status)
		}
	}
	member.UpdateThreatIntel([]IPCount{{IP: "203.0.113.4", Count: 3}})
	member.sync()
	if len(host.GetThreatIntel()) != 1 {
		t.Fatal("the host did not take intel from an admitted member")
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
