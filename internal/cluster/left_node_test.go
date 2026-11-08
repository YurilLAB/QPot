package cluster

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// isMember reports whether m lists the node as a member.
func isMember(m *Manager, id string) bool {
	for _, n := range m.GetNodes() {
		if n.ID == id {
			return true
		}
	}
	return false
}

// leaveFrom sends m a leave request naming id, authenticated as sender.
func leaveFrom(m *Manager, id, sender string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/leave", strings.NewReader(`{"node_id":"`+id+`"}`))
	rec := httptest.NewRecorder()
	m.handleLeaveHTTP(rec, fromPeer(req, sender))
	return rec
}

// pushGossip sends m msg, authenticated as its sender.
func pushGossip(t *testing.T, m *Manager, msg GossipMessage) *httptest.ResponseRecorder {
	t.Helper()
	return pushGossipAs(t, m, msg.SenderID, msg)
}

// pushGossipAs sends m msg, authenticated as sender.
func pushGossipAs(t *testing.T, m *Manager, sender string, msg GossipMessage) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	m.handleGossipHTTP(rec, fromPeer(httptest.NewRequest(http.MethodPost, "/api/v1/cluster/gossip", bytes.NewReader(b)), sender))
	return rec
}

// TestLeftNodeIsNotGossipedBackIn: a member's /leave only deleted the node
// from memory, so it came back from cluster.json at the next start, and any
// member that had missed the leave (or the node itself, still running)
// gossiped it straight back in as a newly discovered node.
func TestLeftNodeIsNotGossipedBackIn(t *testing.T) {
	// y stands for a member that missed the leave: its digest still has x.
	var yDigest []*Node
	y := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(GossipMessage{SenderID: "qn_y", Timestamp: time.Now(), NodeDigest: yDigest})
	}))
	defer y.Close()
	yHost, yPortStr, _ := net.SplitHostPort(strings.TrimPrefix(y.URL, "http://"))
	yPort, _ := strconv.Atoi(yPortStr)

	m := plainCluster(t)
	now := time.Now()
	x := func(at time.Time) *Node {
		return &Node{ID: "qn_x", Name: "x", Address: "127.0.0.1", Port: 7950, Status: NodeStatusHealthy, LastSeen: at}
	}
	m.mu.Lock()
	m.cluster.Nodes["qn_x"] = x(now)
	m.cluster.Nodes["qn_y"] = &Node{ID: "qn_y", Name: "y", Address: yHost, Port: yPort, Status: NodeStatusHealthy, LastSeen: now}
	if err := m.saveClusterLocked(); err != nil {
		t.Fatal(err)
	}
	m.mu.Unlock()

	rec := leaveFrom(m, "qn_x", "qn_x")
	if rec.Code != http.StatusOK || isMember(m, "qn_x") {
		t.Fatalf("x is still a member right after leaving: %d", rec.Code)
	}
	if st := m.GetStatus(); st.NodeCount != 2 {
		t.Errorf("node count %d after x left, want 2 (this node and y)", st.NodeCount)
	}
	if r := NewManager(m.dataPath); func() bool { _, err := r.LoadCluster(); return err != nil }() || isMember(r, "qn_x") {
		t.Error("a restart brought x back from cluster.json")
	}

	// y, which missed the leave, pushes its digest: x with a fresh time.
	later := time.Now().Add(time.Second)
	zID := testNodeID(t)
	pushGossip(t, m, GossipMessage{SenderID: "qn_y", Timestamp: later, NodeDigest: []*Node{x(later),
		enrolled(t, m, &Node{ID: zID, Name: "z", Address: "127.0.0.1", Port: 7952, Status: NodeStatusHealthy, LastSeen: later})}})
	if isMember(m, "qn_x") {
		t.Error("a member that missed the leave gossiped x back in")
	}
	if !isMember(m, zID) {
		t.Error("a node new to the cluster was not discovered by gossip any more")
	}
	// y says z left: only z's own word counts (TestLeftRecordOnlyFromTheNodeItself).
	pushGossip(t, m, GossipMessage{SenderID: "qn_y", Timestamp: later, NodeDigest: []*Node{
		{ID: zID, Name: "z", Address: "127.0.0.1", Port: 7952, Status: NodeStatusLeft, LastSeen: later}}})
	if !isMember(m, zID) {
		t.Error("another member's record marked z as left")
	}
	// No member marks this node as left.
	leaveFrom(m, m.LocalNodeID(), "qn_y")
	if !isMember(m, m.LocalNodeID()) {
		t.Error("another member's /leave marked this node as left")
	}
	// x itself, still running, gossips.
	pushGossip(t, m, GossipMessage{SenderID: "qn_x", Timestamp: later, NodeDigest: []*Node{x(later)}})
	if isMember(m, "qn_x") {
		t.Error("x, still running after it left, gossiped itself back in")
	}
	// y answers this node's gossip round with x in its digest.
	yDigest = []*Node{x(time.Now().Add(2 * time.Second))}
	m.gossip()
	if isMember(m, "qn_x") {
		t.Error("y's answer to a gossip round brought x back")
	}
	if r := NewManager(m.dataPath); func() bool { _, err := r.LoadCluster(); return err != nil }() || isMember(r, "qn_x") {
		t.Error("x is back in cluster.json")
	}
}

// TestLeaveWhileServeRuns: `qpot cluster leave` runs in its own process next
// to `qpot serve`, whose manager still held the cluster: it kept gossiping as
// the node that had left, so the host added it back, and its save on stop
// wrote cluster.json again, so the next start rejoined.
func TestLeaveWhileServeRuns(t *testing.T) {
	const password = "correct-horse-battery"
	free := func() int {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		return ln.Addr().(*net.TCPAddr).Port
	}
	hostPort, nodePort := free(), free()

	host := NewManager(t.TempDir())
	cfg := DefaultClusterConfig()
	cfg.RequireApproval = false
	cfg.BindAddr, cfg.BindPort, cfg.AdvertiseAddr = "127.0.0.1", hostPort, "127.0.0.1"
	cfg.GossipInterval = 50 * time.Millisecond
	cl, err := host.InitCluster("prod", password, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := host.Start(); err != nil {
		t.Fatal(err)
	}
	defer host.Stop()
	waitListening(t, hostPort)

	// The node joins and its control plane (qpot serve) runs the cluster.
	nodeDir := t.TempDir()
	serve := NewManager(nodeDir)
	joined, err := serve.JoinCluster(cl.ID, password, &Node{Name: "sensor", Address: "127.0.0.1", Port: nodePort},
		[]string{"127.0.0.1:" + itoa(hostPort)})
	if err != nil {
		t.Fatal(err)
	}
	nodeID := joined.LocalNode.ID
	if err := serve.SaveSecret(); err != nil {
		t.Fatal(err)
	}
	serve.mu.Lock()
	serve.cluster.Config.BindAddr = "127.0.0.1"
	serve.mu.Unlock()
	if err := serve.Start(); err != nil {
		t.Fatal(err)
	}
	defer serve.Stop()
	waitListening(t, nodePort)

	// `qpot cluster leave`, in another process.
	cli := NewManager(nodeDir)
	if c, err := cli.LoadCluster(); err != nil || c == nil {
		t.Fatalf("load: %v", err)
	}
	if err := cli.LeaveCluster(); err != nil {
		t.Fatal(err)
	}

	time.Sleep(500 * time.Millisecond) // ten gossip rounds of each side
	if isMember(host, nodeID) {
		t.Error("the host took the node back while its control plane kept running")
	}
	if serve.GetStatus() != nil {
		t.Error("the control plane still runs the cluster the node left")
	}
	_ = serve.Stop() // the control plane shuts down
	if _, err := os.Stat(filepath.Join(nodeDir, "cluster.json")); err == nil {
		t.Error("the control plane wrote cluster.json again: the next start rejoins")
	}
}

// TestRunningManagerDoesNotRewriteRemovedClusterFile: between `qpot cluster
// leave` removing cluster.json and the control plane's next gossip round, a
// save (a node discovered, the control plane stopping) wrote it again.
func TestRunningManagerDoesNotRewriteRemovedClusterFile(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	m := NewManager(t.TempDir())
	cfg := DefaultClusterConfig()
	cfg.BindAddr, cfg.BindPort = "127.0.0.1", port
	cfg.GossipInterval = time.Hour // no gossip round in this test
	if _, err := m.InitCluster("prod", "correct-horse-battery", cfg); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	path := filepath.Join(m.dataPath, "cluster.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	newID := testNodeID(t)
	pushGossip(t, m, GossipMessage{SenderID: "qn_y", Timestamp: time.Now(), NodeDigest: []*Node{
		enrolled(t, m, &Node{ID: newID, Name: "new", Address: "127.0.0.1", Port: 7953, Status: NodeStatusHealthy, LastSeen: time.Now()})}})
	if !isMember(m, newID) {
		t.Fatal("the node was not discovered, so nothing was saved")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a discovered node wrote the removed cluster.json again")
	}
	_ = m.Stop()
	if _, err := os.Stat(path); err == nil {
		t.Fatal("stopping wrote the removed cluster.json again")
	}
}

// TestLeftRecordsArePruned: a node that left is remembered as left for
// leftRetention, then its record is dropped.
func TestLeftRecordsArePruned(t *testing.T) {
	m := plainCluster(t)
	now := time.Now()
	m.mu.Lock()
	m.cluster.Nodes["qn_old"] = &Node{ID: "qn_old", Address: "127.0.0.1", Port: 7954, Status: NodeStatusLeft, LastSeen: now.Add(-leftRetention - time.Hour)}
	m.cluster.Nodes["qn_recent"] = &Node{ID: "qn_recent", Address: "127.0.0.1", Port: 7955, Status: NodeStatusLeft, LastSeen: now.Add(-leftRetention + time.Hour)}
	m.cluster.Nodes["qn_x"] = &Node{ID: "qn_x", Address: "127.0.0.1", Port: 7956, Status: NodeStatusHealthy, LastSeen: now}
	m.mu.Unlock()
	if rec := leaveFrom(m, "qn_x", "qn_x"); rec.Code != http.StatusOK {
		t.Fatalf("x's leave: %d", rec.Code)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.cluster.Nodes["qn_old"]; ok {
		t.Error("a node that left longer ago than the retention is still remembered")
	}
	for _, id := range []string{"qn_recent", "qn_x"} {
		if n, ok := m.cluster.Nodes[id]; !ok || n.Status != NodeStatusLeft {
			t.Errorf("%s is no longer remembered as left", id)
		}
	}
}

// knownNodes returns how many records (members and nodes that left) m holds.
func knownNodes(m *Manager) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.cluster.Nodes)
}

func leftNode(id string, port int, at time.Time) *Node {
	return &Node{ID: id, Name: id, Address: "127.0.0.1", Port: port, Status: NodeStatusLeft, LastSeen: at}
}

// TestLeftRecordOnlyFromTheNodeItself: any member's digest could mark a node
// as left, and create a left record for a node never seen; with left records
// final for 30 days, one bad digest evicted a node cluster-wide and random IDs
// filled the member cap. A node is marked left only on its own word: its
// leave request, or its own answer when gossiped with.
func TestLeftRecordOnlyFromTheNodeItself(t *testing.T) {
	var zDigest []*Node
	z := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(GossipMessage{SenderID: "qn_z", Timestamp: time.Now(), NodeDigest: zDigest})
	}))
	defer z.Close()
	zHost, zPortStr, _ := net.SplitHostPort(strings.TrimPrefix(z.URL, "http://"))
	zPort, _ := strconv.Atoi(zPortStr)

	m := plainCluster(t)
	now := time.Now()
	m.mu.Lock()
	for _, n := range []*Node{
		{ID: "qn_x", Name: "x", Address: "127.0.0.1", Port: 7960, Status: NodeStatusFailed, LastSeen: now},
		{ID: "qn_y", Name: "y", Address: "127.0.0.1", Port: 7961, Status: NodeStatusFailed, LastSeen: now},
		{ID: "qn_z", Name: "z", Address: zHost, Port: zPort, Status: NodeStatusHealthy, LastSeen: now},
	} {
		m.cluster.Nodes[n.ID] = n
	}
	m.mu.Unlock()
	later := now.Add(time.Second)

	// y says x left: not taken.
	pushGossip(t, m, GossipMessage{SenderID: "qn_y", Timestamp: later, NodeDigest: []*Node{leftNode("qn_x", 7960, later)}})
	if !isMember(m, "qn_x") {
		t.Error("another member's record marked x as left")
	}
	// y names nodes never seen as left: nothing is created.
	before := knownNodes(m)
	var unknown []*Node
	for i := 0; i < 50; i++ {
		unknown = append(unknown, leftNode("qn_unknown"+strconv.Itoa(i), 8000+i, later))
	}
	pushGossip(t, m, GossipMessage{SenderID: "qn_y", Timestamp: later, NodeDigest: unknown})
	if got := knownNodes(m); got != before {
		t.Errorf("left records of unknown nodes added %d records", got-before)
	}
	// z, answering this node's gossip round, says y left: not taken; that
	// z itself left: taken.
	zDigest = []*Node{leftNode("qn_y", 7961, later)}
	m.gossip()
	if !isMember(m, "qn_y") {
		t.Error("the answering peer's record marked y as left")
	}
	zDigest = []*Node{leftNode("qn_z", zPort, later)}
	m.gossip()
	if isMember(m, "qn_z") {
		t.Error("z's own answer that it left was not taken")
	}
	// y pushes a digest naming x as its sender, saying x left: a push is
	// taken only as from the node that sent it.
	if rec := pushGossipAs(t, m, "qn_y", GossipMessage{SenderID: "qn_x", Timestamp: later, NodeDigest: []*Node{leftNode("qn_x", 7960, later)}}); rec.Code != http.StatusForbidden {
		t.Errorf("a push from y as x: %d, want 403", rec.Code)
	}
	if !isMember(m, "qn_x") {
		t.Error("a pushed digest claiming to come from x marked x as left")
	}
	// x itself pushes that it left: taken.
	pushGossip(t, m, GossipMessage{SenderID: "qn_x", Timestamp: later, NodeDigest: []*Node{leftNode("qn_x", 7960, later)}})
	if isMember(m, "qn_x") {
		t.Error("x's own pushed record that it left was not taken")
	}
}

// TestLeaveTakenOnlyFromTheNode: any member could send a leave naming any
// node, and then one sharing the node's address. A leave is now taken only
// from the node it names, as its certificate shows.
func TestLeaveTakenOnlyFromTheNode(t *testing.T) {
	m := plainCluster(t)
	now := time.Now()
	m.mu.Lock()
	for _, n := range []*Node{
		{ID: "qn_x", Name: "x", Address: "10.1.1.1", Port: 7970, Status: NodeStatusHealthy, LastSeen: now},
		{ID: "qn_y", Name: "y", Address: "10.1.1.1", Port: 7971, Status: NodeStatusHealthy, LastSeen: now},
	} {
		m.cluster.Nodes[n.ID] = n
	}
	m.mu.Unlock()

	if rec := leaveFrom(m, "qn_x", "qn_y"); rec.Code != http.StatusForbidden || !isMember(m, "qn_x") {
		t.Errorf("y's leave naming x (same address): %d, x a member %v; want 403 and x kept", rec.Code, isMember(m, "qn_x"))
	}
	if rec := leaveFrom(m, m.LocalNodeID(), "qn_y"); rec.Code != http.StatusForbidden || !isMember(m, m.LocalNodeID()) {
		t.Errorf("y's leave naming this node: %d; want 403 and this node kept", rec.Code)
	}
	if rec := leaveFrom(m, "qn_x", "qn_x"); rec.Code != http.StatusOK || isMember(m, "qn_x") {
		t.Errorf("x's own leave: %d, x a member %v; want 200 and x gone", rec.Code, isMember(m, "qn_x"))
	}
	// Without an authenticated sender nothing is taken.
	rec := httptest.NewRecorder()
	m.handleLeaveHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/cluster/leave", strings.NewReader(`{"node_id":"qn_y"}`)))
	if rec.Code != http.StatusUnauthorized || !isMember(m, "qn_y") {
		t.Errorf("a leave without an authenticated sender: %d, y a member %v", rec.Code, isMember(m, "qn_y"))
	}
}

// TestNodesThatLeftDoNotFillTheCluster: left records counted toward the
// member cap, so enough of them stopped any node being discovered or admitted
// for 30 days. They are bounded on their own, the oldest dropped first.
func TestNodesThatLeftDoNotFillTheCluster(t *testing.T) {
	m := plainCluster(t)
	now := time.Now()
	m.mu.Lock()
	m.cluster.Config.RequireApproval = false
	for i := 0; i < maxClusterNodes; i++ {
		id := "qn_gone" + strconv.Itoa(i)
		m.cluster.Nodes[id] = leftNode(id, 7000+i%1000, now.Add(-time.Hour+time.Duration(i)*time.Millisecond))
	}
	m.cluster.Nodes["qn_x"] = &Node{ID: "qn_x", Name: "x", Address: "127.0.0.1", Port: 7962, Status: NodeStatusHealthy, LastSeen: now}
	m.mu.Unlock()

	newID := testNodeID(t)
	pushGossip(t, m, GossipMessage{SenderID: "qn_x", Timestamp: now, NodeDigest: []*Node{
		enrolled(t, m, &Node{ID: newID, Name: "new", Address: "127.0.0.1", Port: 7963, Status: NodeStatusHealthy, LastSeen: now})}})
	if !isMember(m, newID) {
		t.Error("a new node was not discovered: the records of nodes that left filled the cluster")
	}
	if r := m.HandleJoinRequest(&JoinRequest{Version: ProtocolVersion, NodeCSR: testNodeCSR(t), ClusterID: m.cluster.ID, Password: "password123", PollSecret: testPollSecret,
		NodeName: "joiner", NodeAddress: "127.0.0.1", NodePort: 7964}, "127.0.0.1"); !r.Success {
		t.Errorf("a join was refused: the records of nodes that left filled the cluster: %+v", r)
	}

	if rec := leaveFrom(m, "qn_x", "qn_x"); rec.Code != http.StatusOK {
		t.Fatalf("x's leave: %d", rec.Code)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	left := 0
	for _, n := range m.cluster.Nodes {
		if n.Status == NodeStatusLeft {
			left++
		}
	}
	if left > maxClusterNodes {
		t.Errorf("%d records of nodes that left, want at most %d", left, maxClusterNodes)
	}
	if n, ok := m.cluster.Nodes["qn_x"]; !ok || n.Status != NodeStatusLeft {
		t.Error("the node that just left is not remembered")
	}
	if _, ok := m.cluster.Nodes["qn_gone0"]; ok {
		t.Error("the oldest record of a node that left was kept over the newest")
	}
}

// TestLeaveWithAMemberOffline: with left records taken only from the node
// itself, a member that was offline during a leave cannot gossip the node
// back in where the leave arrived; it stops counting the node healthy once
// it cannot reach it. Joining again, approved, makes the node a member again
// everywhere.
func TestLeaveWithAMemberOffline(t *testing.T) {
	const password = "correct-horse-battery"
	free := func() int {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		return ln.Addr().(*net.TCPAddr).Port
	}
	hostPort := free()
	host := NewManager(t.TempDir())
	cfg := DefaultClusterConfig()
	cfg.BindAddr, cfg.BindPort, cfg.AdvertiseAddr = "127.0.0.1", hostPort, "127.0.0.1"
	cfg.GossipInterval = 50 * time.Millisecond
	cl, err := host.InitCluster("prod", password, cfg) // joins need approval
	if err != nil {
		t.Fatal(err)
	}
	if err := host.Start(); err != nil {
		t.Fatal(err)
	}
	defer host.Stop()
	waitListening(t, hostPort)
	seed := []string{"127.0.0.1:" + itoa(hostPort)}

	// join admits a new node through the host's approval and starts it.
	join := func(name string) (*Manager, string) {
		t.Helper()
		port := free()
		m := NewManager(t.TempDir())
		m.joinPollInterval = 20 * time.Millisecond
		m.joinPollTimeout = 5 * time.Second
		done := make(chan error, 1)
		go func() {
			_, err := m.JoinCluster(cl.ID, password, &Node{Name: name, Address: "127.0.0.1", Port: port}, seed)
			done <- err
		}()
		deadline := time.Now().Add(3 * time.Second)
		for len(host.ListPendingJoins()) == 0 {
			if time.Now().After(deadline) {
				t.Fatalf("%s's join never reached the host", name)
			}
			time.Sleep(10 * time.Millisecond)
		}
		if _, err := host.ApproveJoin(host.ListPendingJoins()[0].RequestID); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		m.mu.Lock()
		m.cluster.Config.BindAddr = "127.0.0.1"
		m.mu.Unlock()
		if err := m.Start(); err != nil {
			t.Fatal(err)
		}
		waitListening(t, port)
		return m, m.LocalNodeID()
	}
	statusOf := func(m *Manager, id string) NodeStatus {
		for _, n := range m.GetNodes() {
			if n.ID == id {
				return n.Status
			}
		}
		return ""
	}
	eventually := func(what string, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !ok() {
			if time.Now().After(deadline) {
				t.Fatal(what)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	b, bID := join("b")
	defer b.Stop()
	x, xID := join("x")
	eventually("b never learnt of x", func() bool { return statusOf(b, xID) == NodeStatusHealthy })

	// b goes offline; x leaves; b comes back.
	if err := b.Stop(); err != nil {
		t.Fatal(err)
	}
	_ = x.Stop()
	if err := x.LeaveCluster(); err == nil {
		t.Fatal("x's leave reached b, which was offline")
	}
	if isMember(host, xID) {
		t.Fatal("x is still a member at the host after leaving")
	}
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	eventually("b is not back in touch with the host", func() bool { return statusOf(host, bID) == NodeStatusHealthy })
	time.Sleep(300 * time.Millisecond) // several gossip rounds both ways
	if isMember(host, xID) {
		t.Error("b, offline during the leave, gossiped x back in at the host")
	}
	eventually("b still counts x healthy though it cannot reach it", func() bool {
		s := statusOf(b, xID)
		return s != NodeStatusHealthy
	})

	// x joins again: a member everywhere, under its new node ID.
	x2, x2ID := join("x")
	defer x2.Stop()
	if x2ID == xID {
		t.Fatal("the rejoined node has the old node ID")
	}
	eventually("the rejoined node is not a member at the host", func() bool { return statusOf(host, x2ID) == NodeStatusHealthy })
	eventually("the rejoined node is not a member at b", func() bool { return statusOf(b, x2ID) == NodeStatusHealthy })
}
