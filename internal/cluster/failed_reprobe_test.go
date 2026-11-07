package cluster

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestFailedPeerIsProbedAgain: gossip and sync skipped a peer once it was
// marked failed, and the status is saved, so after any outage longer than the
// failure deadline (24s by default) - a reboot, a network blip - neither side
// of a two-node cluster ever contacted the other again, restart or not. A
// failed peer is now probed again once per sync interval, and comes back.
func TestFailedPeerIsProbedAgain(t *testing.T) {
	var down atomic.Bool
	var hits atomic.Int64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(GossipMessage{SenderID: "qn_peer"})
	}))
	defer peer.Close()
	ip, port := peerAddr(t, peer.URL)

	dir := t.TempDir()
	m := NewManager(dir)
	cfg := DefaultClusterConfig()
	cfg.EnableEncryption = false
	cfg.GossipInterval = time.Millisecond
	cfg.SuspicionMult = 1 // failure deadline: 3 * 1ms * 10 = 30ms
	cfg.SyncInterval = 300 * time.Millisecond
	if _, err := m.InitCluster("c", "password123", cfg); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.cluster.Nodes["qn_peer"] = &Node{ID: "qn_peer", Address: ip, Port: port, Status: NodeStatusHealthy, LastSeen: time.Now()}
	m.mu.Unlock()
	status := func() NodeStatus {
		for _, n := range m.GetNodes() {
			if n.ID == "qn_peer" {
				return n.Status
			}
		}
		return ""
	}

	down.Store(true) // the outage
	m.gossip()
	time.Sleep(60 * time.Millisecond)
	m.gossip()
	if s := status(); s != NodeStatusFailed {
		t.Fatalf("setup: peer is %s, want failed", s)
	}
	// A failed peer is not contacted on every round.
	hits.Store(0)
	for i := 0; i < 50; i++ {
		m.gossip()
	}
	if n := hits.Load(); n > 1 {
		t.Fatalf("a failed peer was contacted %d times in 50 quick rounds", n)
	}

	down.Store(false) // the network is back
	deadline := time.Now().Add(3 * time.Second)
	for status() != NodeStatusHealthy {
		if time.Now().After(deadline) {
			t.Fatalf("the peer stays %s once the network is back (%d requests reached it)", status(), hits.Load())
		}
		m.gossip()
		m.sync()
		time.Sleep(10 * time.Millisecond)
	}
}
