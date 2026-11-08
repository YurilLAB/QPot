package cluster

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// TestNodesOwnStatsDespiteClockSkew: a node's stats were taken from gossip
// only when its record was newer than this node's last contact with it, by
// the sender's clock, so a node whose clock ran behind never had its event
// counts seen. A node's own record, from the node itself, is now taken.
func TestNodesOwnStatsDespiteClockSkew(t *testing.T) {
	m := plainCluster(t)
	x := addMember(m, testNodeID(t), "10.0.0.5", 7946)
	m.mu.Lock()
	x.LastSeen = time.Now() // this node last heard x just now
	m.mu.Unlock()
	behind := time.Now().Add(-time.Hour) // x's clock is an hour behind
	pushGossip(t, m, GossipMessage{SenderID: x.ID, Timestamp: behind, NodeDigest: []*Node{
		{ID: x.ID, Name: "x", Address: "10.0.0.5", Port: 7946, Status: NodeStatusHealthy, LastSeen: behind,
			Stats: NodeStats{TotalEvents: 4321, ActiveAttacks: 9, Uptime: time.Hour}}}})
	m.mu.RLock()
	got := x.Stats
	m.mu.RUnlock()
	if got.TotalEvents != 4321 || got.ActiveAttacks != 9 || got.Uptime != time.Hour {
		t.Fatalf("x's own stats were not taken: %+v", got)
	}
	// Another member's record of x does not change them.
	y := addMember(m, testNodeID(t), "10.0.0.6", 7946)
	pushGossip(t, m, GossipMessage{SenderID: y.ID, Timestamp: time.Now(), NodeDigest: []*Node{
		{ID: x.ID, Name: "x", Address: "10.0.0.5", Port: 7946, Status: NodeStatusHealthy, LastSeen: behind.Add(time.Minute),
			Stats: NodeStats{TotalEvents: 1}}}})
	m.mu.RLock()
	got = x.Stats
	m.mu.RUnlock()
	if got.TotalEvents != 4321 {
		t.Fatalf("an older record from another member replaced x's stats: %+v", got)
	}
}

// TestSharedAttackersMergesTheNodes: the attackers the nodes share are
// merged by IP, those seen by the most nodes first; intel from a node that
// left, or too old, is left out.
func TestSharedAttackersMergesTheNodes(t *testing.T) {
	m := plainCluster(t)
	a := addMember(m, testNodeID(t), "10.0.0.5", 7946)
	b := addMember(m, testNodeID(t), "10.0.0.6", 7946)
	gone := addMember(m, testNodeID(t), "10.0.0.7", 7946)
	stale := addMember(m, testNodeID(t), "10.0.0.8", 7946)
	now := time.Now()
	m.UpdateThreatIntel([]IPCount{{IP: "198.51.100.1", Count: 5}, {IP: "198.51.100.2", Count: 50}})
	m.mu.Lock()
	m.storePeerIntelLocked(&ThreatIntel{NodeID: a.ID, Timestamp: now, TopSourceIPs: []IPCount{{IP: "198.51.100.1", Count: 7}}})
	m.storePeerIntelLocked(&ThreatIntel{NodeID: b.ID, Timestamp: now, TopSourceIPs: []IPCount{{IP: "198.51.100.1", Count: 1}, {IP: "198.51.100.3", Count: 2}}})
	m.storePeerIntelLocked(&ThreatIntel{NodeID: gone.ID, Timestamp: now, TopSourceIPs: []IPCount{{IP: "203.0.113.66", Count: 999}}})
	m.storePeerIntelLocked(&ThreatIntel{NodeID: stale.ID, Timestamp: now.Add(-3 * time.Hour), TopSourceIPs: []IPCount{{IP: "203.0.113.77", Count: 999}}})
	gone.Status = NodeStatusLeft
	m.mu.Unlock()

	got := m.SharedAttackers(10)
	want := []SharedAttacker{{IP: "198.51.100.1", Events: 13, Nodes: 3}, {IP: "198.51.100.2", Events: 50, Nodes: 1}, {IP: "198.51.100.3", Events: 2, Nodes: 1}}
	if len(got) != len(want) {
		t.Fatalf("shared attackers %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("shared attackers %+v, want %+v", got, want)
		}
	}
	if top := m.SharedAttackers(1); len(top) != 1 || top[0].IP != "198.51.100.1" {
		t.Fatalf("limit 1: %+v", top)
	}
}

// TestPeerIntelIsBounded: a member's intel keeps at most maxIntelSources
// sources.
func TestPeerIntelIsBounded(t *testing.T) {
	m := plainCluster(t)
	a := addMember(m, testNodeID(t), "10.0.0.5", 7946)
	var many []IPCount
	for i := 0; i < 3*maxIntelSources; i++ {
		many = append(many, IPCount{IP: "198.51.100.1", Count: 1})
	}
	m.mu.Lock()
	m.storePeerIntelLocked(&ThreatIntel{NodeID: a.ID, Timestamp: time.Now(), TopSourceIPs: many})
	n := len(m.peerIntel[a.ID].TopSourceIPs)
	m.mu.Unlock()
	if n != maxIntelSources {
		t.Fatalf("kept %d sources of a member's intel, want %d", n, maxIntelSources)
	}
}

// TestSyncKeepsTheGossipedTotal: a peer's event count is its own (the last
// day's, from gossip); sync replaced it with the sum of the peer's top
// attackers of the last hour, so the two kept overwriting each other.
func TestSyncKeepsTheGossipedTotal(t *testing.T) {
	m := NewManager(t.TempDir())
	if _, err := m.InitCluster("prod", idPassword, DefaultClusterConfig()); err != nil {
		t.Fatal(err)
	}
	peerID := testNodeID(t)
	peer := servePeerAs(t, m, peerID, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ThreatIntel{NodeID: peerID, Timestamp: time.Now(),
			TopSourceIPs: []IPCount{{IP: "1.2.3.4", Count: 100}}})
	}))
	h, p := urlHostPort(t, peer.URL)
	n := addMember(m, peerID, h, p)
	m.mu.Lock()
	n.Stats.TotalEvents = 5000 // what the peer gossiped
	m.mu.Unlock()
	m.UpdateThreatIntel([]IPCount{{IP: "5.6.7.8", Count: 1}})
	m.sync()
	m.mu.RLock()
	got, synced := n.Stats.TotalEvents, n.Stats.LastSync
	m.mu.RUnlock()
	if got != 5000 {
		t.Errorf("sync changed the peer's gossiped event count to %d", got)
	}
	if synced.IsZero() {
		t.Error("sync did not record when it last heard the peer")
	}
	var stored bool
	for _, in := range m.GetThreatIntel() {
		stored = stored || in.NodeID == peerID
	}
	if !stored {
		t.Error("the peer's intel was not kept")
	}
}
