package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	local := &cluster.Node{ID: "node-local", Name: "sensor-1", Address: "10.0.0.1", Port: 7946, Status: cluster.NodeStatusHealthy, JoinedAt: now, InstanceName: "edge"}
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

// startedTestCluster creates and starts a real cluster that requires host
// approval, on a free loopback port; pw is its password.
func startedTestCluster(t *testing.T) (cm *cluster.Manager, c *cluster.Cluster, pw string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	cfg := cluster.DefaultClusterConfig()
	cfg.BindAddr, cfg.BindPort, cfg.EnableEncryption, cfg.RequireApproval = "127.0.0.1", port, false, true
	pw = "pw-" + strings.Repeat("c", 12)
	cm = cluster.NewManager(t.TempDir())
	if c, err = cm.InitCluster("lab", pw, cfg); err != nil {
		t.Fatal(err)
	}
	if err := cm.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cm.Stop() })
	return cm, c, pw
}

// A join waiting for the host's approval in the cluster this control plane
// runs shows in GET /api/cluster/requests, with the host commands and
// without the joiner's secrets.
func TestClusterRequestsLive(t *testing.T) {
	a := newAPITestServer(t, "api-cluster-live", nil)
	cm, c, pw := startedTestCluster(t)
	poll := strings.Repeat("p", 40)
	resp := cm.HandleJoinRequest(&cluster.JoinRequest{Version: cluster.ProtocolVersion, NodeCSR: testNodeCSR(t), ClusterID: c.ID, Password: pw, NodeName: "sensor-9",
		NodeAddress: "198.51.100.7", NodePort: 7946, InstanceName: "far", PollSecret: poll}, "203.0.113.9")
	if resp.Status != "pending" || resp.RequestID == "" {
		t.Fatalf("join: %+v", resp)
	}
	a.s.SetCluster(cm)
	assertAuthRequired(t, a.h, http.MethodGet, "/api/cluster/requests", "")
	if rec := a.do(http.MethodPost, "/api/cluster/requests", `{}`); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d (approval stays on the host)", rec.Code)
	}

	rec := a.do(http.MethodGet, "/api/cluster/requests", "")
	var out joinRequestsAnswer
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || !out.Clustered || !out.Live || len(out.Requests) != 1 {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body.String())
	}
	r := out.Requests[0]
	if r.RequestID != resp.RequestID || r.NodeName != "sensor-9" || r.SourceIP != "203.0.113.9" || r.ClaimedAddress != "198.51.100.7" ||
		r.RequestedAt.IsZero() || r.ApproveCommand != "qpot cluster approve "+resp.RequestID || r.DenyCommand != "qpot cluster deny "+resp.RequestID {
		t.Fatalf("request: %+v", r)
	}
	sum := sha256.Sum256([]byte(poll))
	for what, v := range map[string]string{"cluster password": pw, "poll secret": poll, "poll secret hash": hex.EncodeToString(sum[:]),
		"member key": c.MemberKey, "CA key": c.CAKey, "QPot ID": validTestID} {
		if v != "" && strings.Contains(rec.Body.String(), v) {
			t.Errorf("the answer carries the %s", what)
		}
	}
	if strings.Contains(rec.Body.String(), "poll") || strings.Contains(rec.Body.String(), "instance_name") {
		t.Errorf("the answer carries more than the view: %s", rec.Body.String())
	}

	// /api/cluster and /api/instance say the membership is live.
	rec = a.do(http.MethodGet, "/api/cluster", "")
	if !strings.Contains(rec.Body.String(), `"live":true`) || !strings.Contains(rec.Body.String(), `"is_local":true`) {
		t.Fatalf("GET /api/cluster: %s", rec.Body.String())
	}
	rec = a.do(http.MethodGet, "/api/instance", "")
	if !strings.Contains(rec.Body.String(), `"live":true`) {
		t.Fatalf("GET /api/instance: %s", rec.Body.String())
	}
	// The overview names the running cluster (no cluster.json snapshot here).
	rec = a.do(http.MethodGet, "/api/overview", "")
	if !strings.Contains(rec.Body.String(), `"id":"`+c.ID+`","name":"lab"`) {
		t.Fatalf("GET /api/overview: %s", rec.Body.String())
	}
}

// Without a running cluster here the snapshot answers, and says which
// instance's web UI shows the join requests.
func TestClusterRequestsElsewhere(t *testing.T) {
	a := newAPITestServer(t, "api-cluster-else", nil)
	rec := a.do(http.MethodGet, "/api/cluster/requests", "")
	if rec.Code != http.StatusOK || rec.Body.String() != `{"clustered":false,"live":false,"requests":[]}`+"\n" {
		t.Fatalf("standalone: %d %s", rec.Code, rec.Body.String())
	}
	withTestCluster(t, a.s)
	var out joinRequestsAnswer
	rec = a.do(http.MethodGet, "/api/cluster/requests", "")
	if json.Unmarshal(rec.Body.Bytes(), &out) != nil || !out.Clustered || out.Live || out.RunsOn != "edge" ||
		!strings.Contains(out.Message, `instance "edge"`) || len(out.Requests) != 0 {
		t.Fatalf("snapshot: %s", rec.Body.String())
	}
	rec = a.do(http.MethodGet, "/api/cluster", "")
	if !strings.Contains(rec.Body.String(), `"live":false`) {
		t.Fatalf("GET /api/cluster: %s", rec.Body.String())
	}
}

// The running manager arrives while the API is being read (the control plane
// starts the cluster and the web server independently). Run with -race.
func TestSetClusterWhileReading(t *testing.T) {
	a := newAPITestServer(t, "api-cluster-race", nil)
	withTestCluster(t, a.s)
	cm, _, _ := startedTestCluster(t)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				for _, p := range []string{"/api/cluster", "/api/cluster/requests", "/api/instance"} {
					if rec := a.do(http.MethodGet, p, ""); rec.Code != http.StatusOK {
						t.Errorf("%s: %d", p, rec.Code)
					}
				}
			}
		}()
	}
	for j := 0; j < 25; j++ {
		a.s.SetCluster(cm)
	}
	wg.Wait()
	if _, live := a.s.clusterView(); !live {
		t.Fatal("the running manager was not taken")
	}
}

// Only an ID that looks like the cluster's own goes on a command line the
// operator copies.
func TestJoinCommands(t *testing.T) {
	for _, id := range []string{"req-0123abcd", "req_9", "R", strings.Repeat("a", 64)} {
		if a, d := joinCommands(id); a != "qpot cluster approve "+id || d != "qpot cluster deny "+id {
			t.Errorf("%q: %q %q", id, a, d)
		}
	}
	for _, id := range []string{"", "-rf", "_x", "a b", "a;b", "a" + string(rune(10)) + "qpot up", "a$(id)", "a/b", "a.b", strings.Repeat("a", 65), "é"} {
		if a, d := joinCommands(id); a != "" || d != "" {
			t.Errorf("%q gave %q %q", id, a, d)
		}
	}
}

// testNodeCSR makes the certificate request a joining node sends.
func testNodeCSR(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}
