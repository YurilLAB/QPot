package cluster

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestApproveResponseDoesNotShareTheLiveNode: /approve encoded the admitted
// node's live record after the manager lock was released, while the new
// member's first gossip (or the failure detector) writes its status and last
// seen under the lock - a data race the race detector reports. ApproveJoin now
// returns a copy. Run with -race.
func TestApproveResponseDoesNotShareTheLiveNode(t *testing.T) {
	const pw = "password123"
	m := NewManager(t.TempDir())
	cfg := DefaultClusterConfig()
	cfg.EnableEncryption = false
	cl, err := m.InitCluster("c", pw, cfg)
	if err != nil {
		t.Fatal(err)
	}
	jr := m.HandleJoinRequest(&JoinRequest{Version: ProtocolVersion, NodeCSR: testNodeCSR(t), ClusterID: cl.ID, Password: pw, PollSecret: testPollSecret,
		NodeName: "n", NodeAddress: "10.0.0.7", NodePort: 7946}, "10.0.0.7")
	if jr.Status != "pending" {
		t.Fatalf("join: %+v", jr)
	}
	h := m.apiHandler()
	key := m.memberKey()
	done := make(chan struct{})
	// Started before the approval, so nothing orders its write after the
	// handler's encode: the new member's first gossip ping.
	go func() {
		defer close(done)
		for i := 0; i < 1_000_000; i++ {
			for _, n := range m.GetNodes() {
				if n.Address == "10.0.0.7" {
					b, _ := json.Marshal(GossipMessage{SenderID: n.ID})
					req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/gossip", bytes.NewReader(b))
					req.RemoteAddr = "10.0.0.7:40000"
					req.Header.Set("X-Cluster-Password", pw)
					req.Header.Set(memberKeyHeader, key)
					h.ServeHTTP(httptest.NewRecorder(), req)
					return
				}
			}
		}
	}()
	b, _ := json.Marshal(map[string]string{"request_id": jr.RequestID})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/approve", bytes.NewReader(b))
	req.RemoteAddr = "127.0.0.1:40000"
	req.Header.Set("X-Cluster-Password", pw)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	<-done
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}

	// And the node it returns is a copy: changing it leaves the member alone.
	node, err := func() (*Node, error) {
		jr2 := m.HandleJoinRequest(&JoinRequest{Version: ProtocolVersion, NodeCSR: testNodeCSR(t), ClusterID: cl.ID, Password: pw, PollSecret: testPollSecret,
			NodeName: "n2", NodeAddress: "10.0.0.8", NodePort: 7946}, "10.0.0.8")
		return m.ApproveJoin(jr2.RequestID)
	}()
	if err != nil {
		t.Fatal(err)
	}
	node.Status = "tampered"
	for _, n := range m.GetNodes() {
		if n.ID == node.ID && n.Status == "tampered" {
			t.Fatal("ApproveJoin returned the member's live record")
		}
	}
}
