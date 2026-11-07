package cluster

import (
	"fmt"
	"testing"
)

// TestAdmissionRespectsTheNodeCap: gossip refused to grow the member map past
// maxClusterNodes, but admission did not: with approval off, any password
// holder could add members (and rewrite cluster.json each time) without
// limit, and every member then gossiped to the addresses they named. A full
// cluster now refuses the join, whether open or approved by the host.
func TestAdmissionRespectsTheNodeCap(t *testing.T) {
	const pw = "password123"
	for _, approval := range []bool{false, true} {
		m := NewManager(t.TempDir())
		cfg := DefaultClusterConfig()
		cfg.EnableEncryption = false
		cfg.RequireApproval = approval
		cl, err := m.InitCluster("c", pw, cfg)
		if err != nil {
			t.Fatal(err)
		}
		m.mu.Lock()
		for i := len(m.cluster.Nodes); i < maxClusterNodes; i++ {
			id := fmt.Sprintf("qn_fill%05d", i)
			m.cluster.Nodes[id] = &Node{ID: id, Address: "10.0.0.1", Port: 7946}
		}
		m.mu.Unlock()
		for i := 0; i < 5; i++ {
			r := m.HandleJoinRequest(&JoinRequest{Version: ProtocolVersion, NodeCSR: testNodeCSR(t), ClusterID: cl.ID, Password: pw, PollSecret: testPollSecret,
				NodeName: "x", NodeAddress: "10.9.9.9", NodePort: 7946}, fmt.Sprintf("198.51.100.%d", i+1))
			if approval && r.Status == "pending" {
				_, _ = m.ApproveJoin(r.RequestID)
			}
		}
		if n := len(m.GetNodes()); n > maxClusterNodes {
			t.Fatalf("approval %v: admission grew the member map past maxClusterNodes: %d", approval, n)
		}
	}
}
