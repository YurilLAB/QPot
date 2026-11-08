package cluster

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// approvingHost starts an enrollment host whose joins need its approval.
func approvingHost(t *testing.T) (*Manager, *Cluster, int) {
	t.Helper()
	m := NewManager(t.TempDir())
	cfg := DefaultClusterConfig()
	cfg.BindAddr, cfg.AdvertiseAddr = "127.0.0.1", "127.0.0.1"
	cfg.GossipInterval = 50 * time.Millisecond
	c, err := m.InitCluster("prod", idPassword, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return m, c, startOn(t, m)
}

// approvedMember joins a node through host, which approves it, and starts it.
func approvedMember(t *testing.T, host *Manager, c *Cluster, hostPort int, name string) (*Manager, string) {
	t.Helper()
	m := NewManager(t.TempDir())
	m.joinPollInterval = 20 * time.Millisecond
	m.joinPollTimeout = 5 * time.Second
	port := freePort(t)
	done := make(chan error, 1)
	go func() {
		_, err := m.JoinCluster(c.ID, idPassword, &Node{Name: name, Address: "127.0.0.1", Port: port},
			[]string{"127.0.0.1:" + strconv.Itoa(hostPort)})
		done <- err
	}()
	eventuallyTrue(t, name+"'s join never reached the host", func() bool { return len(host.ListPendingJoins()) > 0 })
	if _, err := host.ApproveJoin(host.ListPendingJoins()[0].RequestID); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("%s joins: %v", name, err)
	}
	if err := m.SaveSecret(); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.cluster.Config.BindAddr = "127.0.0.1"
	m.mu.Unlock()
	if err := m.Start(); err != nil {
		t.Fatalf("%s starts: %v", name, err)
	}
	t.Cleanup(func() { _ = m.Stop() })
	waitListening(t, port)
	return m, m.LocalNodeID()
}

// TestGossipAddsOnlyEnrolledNodes: a member's gossip digest added any node
// record that passed a shape check, so a compromised member could put nodes
// the enrollment host never admitted into every member's roster.
func TestGossipAddsOnlyEnrolledNodes(t *testing.T) {
	host, c, hostPort := approvingHost(t)
	a, aID := approvedMember(t, host, c, hostPort, "a")
	b, _ := approvedMember(t, host, c, hostPort, "b")
	eventuallyTrue(t, "b does not know a", func() bool { return isMember(b, aID) })
	credsA := credsOf(t, a)

	ghost := &Node{ID: testNodeID(t), Name: "ghost", Address: "127.0.0.1", Port: freePort(t),
		Status: NodeStatusHealthy, LastSeen: time.Now(), Stats: NodeStats{TotalEvents: 1_000_000_000}}
	before := host.GetStatus()
	code, body := peerCall(t, hostPort, "/api/v1/cluster/gossip",
		GossipMessage{SenderID: aID, Timestamp: time.Now(), NodeDigest: []*Node{ghost}}, credsA)
	if code != http.StatusOK {
		t.Fatalf("a, a member, was not heard: %d %s", code, body)
	}
	after := host.GetStatus()
	t.Logf("host: members %d -> %d, total events %d -> %d", before.NodeCount, after.NodeCount, before.TotalEvents, after.TotalEvents)
	if isMember(host, ghost.ID) {
		t.Errorf("the host added %s, a node it never enrolled, from a's gossip", ghost.ID)
	}
	time.Sleep(400 * time.Millisecond) // several gossip rounds
	if isMember(b, ghost.ID) {
		t.Errorf("b took %s, a node never enrolled, from the host's gossip", ghost.ID)
	}

	// Certificates a cannot pass off as the ghost's: its own, which names a,
	// and one from another cluster's CA.
	other := plainCluster(t)
	otherChain, _ := issueFor(t, other, ghost.ID)
	for name, cert := range map[string]string{
		"a's own certificate":           leafCertificate(credsA.NodeCertificate),
		"another cluster's certificate": leafCertificate(otherChain),
	} {
		g := *ghost
		g.Certificate = cert
		if code, body := peerCall(t, hostPort, "/api/v1/cluster/gossip",
			GossipMessage{SenderID: aID, Timestamp: time.Now(), NodeDigest: []*Node{&g}}, credsA); code != http.StatusOK {
			t.Fatalf("a: %d %s", code, body)
		}
		if isMember(host, ghost.ID) {
			t.Errorf("the host added the ghost carrying %s", name)
		}
	}

	// Negative control: a node the host's CA did issue a certificate for is
	// taken from a's gossip by b, which had not heard of it.
	admitted := enrolled(t, host, &Node{ID: testNodeID(t), Name: "admitted", Address: "127.0.0.1", Port: freePort(t),
		Status: NodeStatusHealthy, LastSeen: time.Now()})
	if code, body := peerCall(t, b.GetCluster().LocalNode.Port, "/api/v1/cluster/gossip",
		GossipMessage{SenderID: aID, Timestamp: time.Now(), NodeDigest: []*Node{admitted}}, credsA); code != http.StatusOK {
		t.Fatalf("a to b: %d %s", code, body)
	}
	if !isMember(b, admitted.ID) {
		t.Error("b did not take a node with a certificate from the cluster CA")
	}
}

// TestDiscoveryNeedsTheNodesCertificate: a node new to this node is added
// only with a certificate the cluster CA issued for exactly that node, valid
// now, of a node not removed.
func TestDiscoveryNeedsTheNodesCertificate(t *testing.T) {
	m := plainCluster(t)
	y := addMember(m, testNodeID(t), "10.0.0.6", 7946)
	m.mu.RLock()
	clusterID, caKey := m.cluster.ID, m.cluster.CAKey
	m.mu.RUnlock()
	yChain, _ := issueFor(t, m, y.ID)
	other := plainCluster(t)
	now := time.Now()

	record := func(id, cert string) *Node {
		return &Node{ID: id, Name: "x", Address: "10.0.0.5", Port: 7946, Status: NodeStatusHealthy,
			LastSeen: now.Add(time.Hour), Stats: NodeStats{TotalEvents: 1_000_000}, Certificate: cert}
	}
	merge := func(n *Node, at time.Time) bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.mergeDigestLocked([]*Node{n}, m.cluster.LocalNode.ID, y.ID, at)
		_, ok := m.cluster.Nodes[n.ID]
		return ok
	}
	cert := func(owner *Manager, id string) string {
		chain, _ := issueFor(t, owner, id)
		return leafCertificate(chain)
	}

	removed := testNodeID(t)
	m.mu.Lock()
	m.applyRevocationsLocked([]Revocation{signedRevocation(t, clusterID, caKey, removed, now)}, now)
	m.mu.Unlock()
	for _, c := range []struct {
		name string
		n    *Node
		at   time.Time
	}{
		{"no certificate", record(testNodeID(t), ""), now},
		{"y's certificate", record(testNodeID(t), leafCertificate(yChain)), now},
		{"another cluster's certificate", func() *Node { id := testNodeID(t); return record(id, cert(other, id)) }(), now},
		{"a certificate that does not parse", record(testNodeID(t), "bm90IGEgY2VydGlmaWNhdGU="), now},
		{"an expired certificate", func() *Node { id := testNodeID(t); return record(id, cert(m, id)) }(), now.Add(nodeCertLifetime + time.Hour)},
		{"a certificate not valid yet", func() *Node { id := testNodeID(t); return record(id, cert(m, id)) }(), now.Add(-2 * time.Hour)},
		{"the certificate of a removed node", record(removed, cert(m, removed)), now},
	} {
		if merge(c.n, c.at) {
			t.Errorf("a node with %s was added", c.name)
		}
	}

	// Negative control: the node's own certificate from this cluster's CA.
	x := record(testNodeID(t), "")
	x.Certificate = cert(m, x.ID)
	if !merge(x, now) {
		t.Fatal("a node with its certificate from the cluster CA was not added")
	}
	m.mu.RLock()
	got := *m.cluster.Nodes[x.ID]
	m.mu.RUnlock()
	if got.Stats.TotalEvents != 0 || got.LastSeen.After(now) {
		t.Errorf("another member's record set x's stats or dated it ahead: %+v %s", got.Stats, got.LastSeen)
	}
}

// TestNewNodesCheckedPerMessageAreBounded: certificates are checked under
// the manager lock, so a digest has at most newNodesPerMessage checked; the
// rest are learnt from the next messages.
func TestNewNodesCheckedPerMessageAreBounded(t *testing.T) {
	m := plainCluster(t)
	y := addMember(m, testNodeID(t), "10.0.0.6", 7946)
	var digest []*Node
	for i := 0; i < newNodesPerMessage; i++ {
		digest = append(digest, &Node{ID: testNodeID(t), Address: "10.0.0.7", Port: 7946, Status: NodeStatusHealthy,
			Certificate: "bm90IGEgY2VydGlmaWNhdGU="})
	}
	x := enrolled(t, m, &Node{ID: testNodeID(t), Address: "10.0.0.5", Port: 7946, Status: NodeStatusHealthy})
	pushGossip(t, m, GossipMessage{SenderID: y.ID, NodeDigest: append(digest, x)})
	if isMember(m, x.ID) {
		t.Errorf("more than %d certificates were checked for one message", newNodesPerMessage)
	}
	pushGossip(t, m, GossipMessage{SenderID: y.ID, NodeDigest: []*Node{x}})
	if !isMember(m, x.ID) {
		t.Error("the node was not learnt from the next message")
	}
}

// TestNodesOwnRecordIsTheNodes: what another member says of a node it passes
// on - its name and address - stands only until the node says otherwise, and
// its stats come only from the node.
func TestNodesOwnRecordIsTheNodes(t *testing.T) {
	m := plainCluster(t)
	y := addMember(m, testNodeID(t), "10.0.0.6", 7946)
	x := enrolled(t, m, &Node{ID: testNodeID(t), Name: "renamed", Address: "10.6.6.6", Port: 1, InstanceName: "evil",
		Status: NodeStatusHealthy, LastSeen: time.Now(), Stats: NodeStats{TotalEvents: 999}})
	pushGossip(t, m, GossipMessage{SenderID: y.ID, NodeDigest: []*Node{x}})
	if !isMember(m, x.ID) {
		t.Fatal("y's record of x, with x's certificate, was not taken")
	}

	// x itself.
	pushGossip(t, m, GossipMessage{SenderID: x.ID, NodeDigest: []*Node{
		{ID: x.ID, Name: "x", Address: "10.0.0.5", Port: 7946, InstanceName: "edge", Status: NodeStatusHealthy,
			LastSeen: time.Now(), Stats: NodeStats{TotalEvents: 42}}}})
	check := func(when string) {
		t.Helper()
		m.mu.RLock()
		got := *m.cluster.Nodes[x.ID]
		m.mu.RUnlock()
		if got.Name != "x" || got.Address != "10.0.0.5" || got.Port != 7946 || got.InstanceName != "edge" || got.Stats.TotalEvents != 42 {
			t.Errorf("%s: x's record is %q %s:%d %q %+v, want x's own", when, got.Name, got.Address, got.Port, got.InstanceName, got.Stats)
		}
		if got.Certificate != x.Certificate {
			t.Errorf("%s: x's certificate was lost", when)
		}
	}
	check("after x's own record")

	// y again, newer than this node's last word of x: changes none of it.
	m.mu.Lock()
	m.cluster.Nodes[x.ID].LastSeen = time.Now().Add(-time.Minute)
	m.mu.Unlock()
	pushGossip(t, m, GossipMessage{SenderID: y.ID, NodeDigest: []*Node{
		{ID: x.ID, Name: "renamed", Address: "10.6.6.6", Port: 1, InstanceName: "evil", Status: "pwned",
			LastSeen: time.Now().Add(time.Hour), Stats: NodeStats{TotalEvents: 999}}}})
	check("after y's record")
	m.mu.RLock()
	status := m.cluster.Nodes[x.ID].Status
	m.mu.RUnlock()
	if status != NodeStatusHealthy {
		t.Errorf("y's record gave x the status %q", status)
	}
}

// TestCertificateTakenFromTheNodesRequests: a record saved without a
// certificate (by an older version) gets the one its node presents.
func TestCertificateTakenFromTheNodesRequests(t *testing.T) {
	m := plainCluster(t)
	x := addMember(m, testNodeID(t), "10.0.0.5", 7946)
	chain, _ := issueFor(t, m, x.ID)
	digest, _ := json.Marshal(GossipMessage{SenderID: x.ID, NodeDigest: []*Node{
		{ID: x.ID, Name: "x", Address: "10.0.0.5", Port: 7946, Status: NodeStatusHealthy}}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/gossip", bytes.NewReader(digest))
	setPeerAuth(req, "password123", m.memberKey())
	req.TLS = &tls.ConnectionState{PeerCertificates: parseChain(t, chain)}
	rec := httptest.NewRecorder()
	m.apiHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("x's gossip: %d %s", rec.Code, rec.Body)
	}
	m.mu.RLock()
	got := m.cluster.Nodes[x.ID].Certificate
	m.mu.RUnlock()
	if got != leafCertificate(chain) {
		t.Fatal("x's record did not take the certificate x presented")
	}
	reloaded := NewManager(m.dataPath)
	if _, err := reloaded.LoadCluster(); err != nil {
		t.Fatal(err)
	}
	if reloaded.GetCluster().Nodes[x.ID].Certificate != got {
		t.Error("the certificate was not saved")
	}
}

// TestNewMemberReachesAMemberThatWasOffline: a node admitted while a member
// was offline reaches it through another member's gossip, with the host down
// by then: members pass on the certificates the host issued.
func TestNewMemberReachesAMemberThatWasOffline(t *testing.T) {
	host, c, hostPort := approvingHost(t)
	a, _ := approvedMember(t, host, c, hostPort, "a")
	b, bID := approvedMember(t, host, c, hostPort, "b")
	bPort := b.GetCluster().LocalNode.Port
	eventuallyTrue(t, "a does not know b", func() bool { return isMember(a, bID) })

	_ = b.Stop()
	_, cID := approvedMember(t, host, c, hostPort, "c")
	eventuallyTrue(t, "a does not know c", func() bool { return isMember(a, cID) })
	_ = host.Stop()
	if isMember(b, cID) {
		t.Fatal("b, offline, knows c")
	}
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	waitListening(t, bPort)
	eventuallyTrue(t, "b never learnt of c from a", func() bool { return isMember(b, cID) })
	eventuallyTrue(t, "c is not healthy at b", func() bool {
		for _, n := range b.GetNodes() {
			if n.ID == cID {
				return n.Status == NodeStatusHealthy
			}
		}
		return false
	})
}

// TestFullRosterFitsOneMessage: a full cluster's digest, every member's
// record with its certificate and every record kept of a node that left,
// fits in one gossip message.
func TestFullRosterFitsOneMessage(t *testing.T) {
	m := plainCluster(t)
	chain, _ := issueFor(t, m, testNodeID(t))
	cert := leafCertificate(chain)
	now := time.Now()
	m.mu.Lock()
	for i := len(m.cluster.Nodes); i < maxClusterNodes; i++ {
		id := testNodeID(t)
		m.cluster.Nodes[id] = &Node{ID: id, Name: "sensor-" + strconv.Itoa(i), Address: "203.0.113.200", Port: 7946,
			InstanceName: "default", Status: NodeStatusHealthy, LastSeen: now, JoinedAt: now, Certificate: cert,
			Stats: NodeStats{TotalEvents: 1 << 40, ActiveAttacks: 1 << 20, Uptime: time.Hour, LastSync: now}}
	}
	for i := 0; i < maxLeftNodes; i++ {
		id := testNodeID(t)
		m.cluster.Nodes[id] = &Node{ID: id, Name: "gone-" + strconv.Itoa(i), Address: "203.0.113.201", Port: 7946,
			InstanceName: "default", Status: NodeStatusLeft, LastSeen: now, JoinedAt: now, Certificate: cert}
	}
	digest := m.snapshotNodesLocked()
	m.mu.Unlock()
	body, err := json.Marshal(GossipMessage{SenderID: testNodeID(t), Timestamp: now, NodeDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("full roster: %d bytes, limit %d", len(body), maxRosterBodyBytes)
	if len(body) > maxRosterBodyBytes {
		t.Errorf("a full roster is %d bytes, over the %d a gossip message may carry", len(body), maxRosterBodyBytes)
	}
}

// TestFabricatedNodesCannotFillTheCluster: enough fabricated records from one
// member took every place in the cluster, so the host admitted no one.
func TestFabricatedNodesCannotFillTheCluster(t *testing.T) {
	m := plainCluster(t)
	m.mu.Lock()
	m.cluster.Config.RequireApproval = false
	m.mu.Unlock()
	x := addMember(m, testNodeID(t), "10.0.0.5", 7946)
	for batch := 0; batch < 4; batch++ { // each message under the body cap
		var digest []*Node
		for i := 0; i < maxClusterNodes/4; i++ {
			digest = append(digest, &Node{ID: testNodeID(t), Address: "127.0.0.1", Port: 1 + i, Status: NodeStatusHealthy})
		}
		if rec := pushGossip(t, m, GossipMessage{SenderID: x.ID, Timestamp: time.Now(), NodeDigest: digest}); rec.Code != http.StatusOK {
			t.Fatalf("x's digest: %d %s", rec.Code, rec.Body)
		}
	}
	m.mu.RLock()
	members := m.memberCountLocked()
	m.mu.RUnlock()
	t.Logf("members after x's digests: %d (cap %d)", members, maxClusterNodes)
	r := m.HandleJoinRequest(&JoinRequest{Version: ProtocolVersion, NodeCSR: testNodeCSR(t), ClusterID: m.cluster.ID,
		Password: "password123", PollSecret: testPollSecret, NodeName: "joiner", NodeAddress: "127.0.0.1", NodePort: 7964}, "127.0.0.1")
	if !r.Success {
		t.Errorf("a real node was refused after x's digest: %s", r.Error)
	}
}

// TestOthersCannotRewriteANodesRecord: another member's record of a node
// replaced the node's own stats whenever it was dated later, also ahead of
// this node's clock, which then froze the record.
func TestOthersCannotRewriteANodesRecord(t *testing.T) {
	m := plainCluster(t)
	x := addMember(m, testNodeID(t), "10.0.0.5", 7946)
	y := addMember(m, testNodeID(t), "10.0.0.6", 7946)
	now := time.Now()
	heard := now.Add(-time.Minute) // this node last heard x a minute ago
	m.mu.Lock()
	x.Name, x.InstanceName, x.LastSeen, x.Stats = "x", "edge", heard, NodeStats{TotalEvents: 10, ActiveAttacks: 1}
	m.mu.Unlock()

	ahead := now.Add(24 * time.Hour)
	pushGossip(t, m, GossipMessage{SenderID: y.ID, Timestamp: now, NodeDigest: []*Node{
		{ID: x.ID, Name: "renamed", Address: "10.6.6.6", Port: 1, InstanceName: "evil", Status: NodeStatusHealthy,
			LastSeen: ahead, Stats: NodeStats{TotalEvents: 999_999_999, ActiveAttacks: 5000}}}})
	m.mu.RLock()
	got := *x
	m.mu.RUnlock()
	t.Logf("x after y's record: name %q address %s:%d instance %q stats %+v last seen %s",
		got.Name, got.Address, got.Port, got.InstanceName, got.Stats, got.LastSeen.Format(time.RFC3339))
	if got.Name != "x" || got.Address != "10.0.0.5" || got.Port != 7946 || got.InstanceName != "edge" {
		t.Errorf("y's record changed x's name, address or instance")
	}
	if got.Stats.TotalEvents != 10 || got.Stats.ActiveAttacks != 1 {
		t.Errorf("y's record replaced x's own stats: %+v", got.Stats)
	}
	if got.LastSeen.After(time.Now()) {
		t.Errorf("y's record dated x's last contact ahead of this node's clock: %s", got.LastSeen)
	}
	// Negative control: y's word that x is up, newer than this node's, counts.
	if !got.LastSeen.After(heard) {
		t.Errorf("y's newer record that x is up was not taken")
	}
}
