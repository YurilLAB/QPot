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

func pushGossip(t *testing.T, m *Manager, msg GossipMessage) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	m.handleGossipHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/cluster/gossip", bytes.NewReader(b)))
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

	rec := httptest.NewRecorder()
	m.handleLeaveHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/cluster/leave", strings.NewReader(`{"node_id":"qn_x"}`)))
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
	pushGossip(t, m, GossipMessage{SenderID: "qn_y", Timestamp: later, NodeDigest: []*Node{x(later),
		{ID: "qn_z", Name: "z", Address: "127.0.0.1", Port: 7952, Status: NodeStatusHealthy, LastSeen: later}}})
	if isMember(m, "qn_x") {
		t.Error("a member that missed the leave gossiped x back in")
	}
	if !isMember(m, "qn_z") {
		t.Error("a node new to the cluster was not discovered by gossip any more")
	}
	// y learnt that z left: so does this node.
	pushGossip(t, m, GossipMessage{SenderID: "qn_y", Timestamp: later, NodeDigest: []*Node{
		{ID: "qn_z", Name: "z", Address: "127.0.0.1", Port: 7952, Status: NodeStatusLeft, LastSeen: later}}})
	if isMember(m, "qn_z") {
		t.Error("a member's record that z left was not taken")
	}
	// No member marks this node as left.
	rec = httptest.NewRecorder()
	m.handleLeaveHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/cluster/leave",
		strings.NewReader(`{"node_id":"`+m.LocalNodeID()+`"}`)))
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
	cfg.EnableEncryption = false
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
		[]string{"http://127.0.0.1:" + itoa(hostPort)})
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
	cfg.EnableEncryption = false
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
	pushGossip(t, m, GossipMessage{SenderID: "qn_y", Timestamp: time.Now(), NodeDigest: []*Node{
		{ID: "qn_new", Name: "new", Address: "127.0.0.1", Port: 7953, Status: NodeStatusHealthy, LastSeen: time.Now()}}})
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
	rec := httptest.NewRecorder()
	m.handleLeaveHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/cluster/leave", strings.NewReader(`{"node_id":"qn_x"}`)))
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
