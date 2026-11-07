package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/cluster"
)

// clusterSecrets are the secrets a test cluster.json carries.
type clusterSecrets struct{ passwordHash, memberKey, caKey string }

// withTestCluster gives a server a cluster whose local node is "node-local"
// (sensor-1) with one peer, "node-peer" (sensor-2), loaded from a
// cluster.json as a paired node's server loads it.
func withTestCluster(t *testing.T, s *Server) clusterSecrets {
	t.Helper()
	sec := clusterSecrets{
		passwordHash: "phash-" + strings.Repeat("h", 16),
		memberKey:    "mkey-" + strings.Repeat("m", 16),
		caKey:        "cakey-" + strings.Repeat("c", 16),
	}
	now := time.Now().UTC()
	local := &cluster.Node{ID: "node-local", Name: "sensor-1", Address: "10.0.0.1", Port: 7946, Status: cluster.NodeStatusHealthy, JoinedAt: now}
	peer := &cluster.Node{ID: "node-peer", Name: "sensor-2", Address: "10.0.0.2", Port: 7946, Status: cluster.NodeStatusHealthy, JoinedAt: now}
	c := cluster.Cluster{
		ID: "cl-test", Name: "lab", PasswordHash: sec.passwordHash, MemberKey: sec.memberKey, CAKey: sec.caKey,
		CreatedAt: now, UpdatedAt: now, LocalNode: local,
		Nodes: map[string]*cluster.Node{local.ID: local, peer.ID: peer},
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cluster.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	cm := cluster.NewManager(dir)
	if loaded, err := cm.LoadCluster(); err != nil || loaded == nil {
		t.Fatalf("LoadCluster: %v", err)
	}
	s.cluster = cm
	return sec
}

// GET /api/cluster marks this server's own node, and only it; it never
// carries the cluster's password hash, member key or CA key.
func TestClusterMarksTheLocalNode(t *testing.T) {
	a := newAPITestServer(t, "api-cluster", nil)
	sec := withTestCluster(t, a.s)
	rec := a.do(http.MethodGet, "/api/cluster", "")
	var out struct {
		Clustered bool `json:"clustered"`
		Nodes     []struct {
			Name    string `json:"name"`
			IsLocal bool   `json:"is_local"`
		} `json:"nodes"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || !out.Clustered || len(out.Nodes) != 2 {
		t.Fatalf("GET /api/cluster: %d %s", rec.Code, rec.Body.String())
	}
	local := map[string]bool{}
	for _, n := range out.Nodes {
		local[n.Name] = n.IsLocal
	}
	if !local["sensor-1"] || local["sensor-2"] {
		t.Fatalf("is_local: %v, want only sensor-1", local)
	}
	for what, v := range map[string]string{"password hash": sec.passwordHash, "member key": sec.memberKey, "CA key": sec.caKey, "QPot ID": validTestID} {
		if strings.Contains(rec.Body.String(), v) {
			t.Errorf("the answer carries the cluster's %s", what)
		}
	}
}

// A cluster.json without a local node marks none, also a member whose ID is
// empty.
func TestClusterWithoutLocalNodeMarksNone(t *testing.T) {
	a := newAPITestServer(t, "api-cluster-nolocal", nil)
	now := time.Now().UTC()
	data, err := json.Marshal(cluster.Cluster{ID: "cl-test", Name: "lab", CreatedAt: now, UpdatedAt: now,
		Nodes: map[string]*cluster.Node{"": {Name: "odd", Status: cluster.NodeStatusHealthy}}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cluster.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	cm := cluster.NewManager(dir)
	if _, err := cm.LoadCluster(); err != nil {
		t.Fatal(err)
	}
	a.s.cluster = cm
	rec := a.do(http.MethodGet, "/api/cluster", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"name":"odd"`) || strings.Contains(rec.Body.String(), `"is_local":true`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}
