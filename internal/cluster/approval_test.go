package cluster

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// testPollSecret is a joiner's poll secret for tests that file join requests
// directly.
var testPollSecret = strings.Repeat("p", minPollSecret)

// startSeedServer stands up the cluster API for a seed manager on a free port
// and returns its base URL.
func startSeedServer(t *testing.T, seed *Manager) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/cluster/join", seed.handleJoinHTTP)
	mux.HandleFunc("/api/v1/cluster/join/status", seed.withClusterAuth(seed.handleJoinStatusHTTP))
	mux.HandleFunc("/api/v1/cluster/pending", seed.withClusterAuth(seed.handlePendingHTTP))
	mux.HandleFunc("/api/v1/cluster/approve", seed.withClusterAuth(seed.handleApproveHTTP))
	mux.HandleFunc("/api/v1/cluster/deny", seed.withClusterAuth(seed.handleDenyHTTP))
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	waitListening(t, port)
	return "http://127.0.0.1:" + itoa(port)
}

// TestJoinApprovalFlow drives the full host-approval path over HTTP: a node
// joins with the correct password, is queued as pending (not admitted), the
// host sees the request with the real source IP + hostname, approves it, and
// the joiner's poll then completes with full membership.
func TestJoinApprovalFlow(t *testing.T) {
	const password = "correct-horse-battery"
	seedDir := t.TempDir()
	seed := NewManager(seedDir)
	cl, err := seed.InitCluster("prod", password, DefaultClusterConfig()) // RequireApproval defaults true
	if err != nil {
		t.Fatalf("InitCluster: %v", err)
	}
	base := startSeedServer(t, seed)

	joiner := NewManager(t.TempDir())
	joiner.joinPollInterval = 20 * time.Millisecond
	joiner.joinPollTimeout = 5 * time.Second
	local := &Node{Name: "sensor-7", Address: "10.9.9.9", Port: 7947}

	// Join in the background - it blocks polling for approval.
	var wg sync.WaitGroup
	wg.Add(1)
	var joined *Cluster
	var joinErr error
	go func() {
		defer wg.Done()
		joined, joinErr = joiner.JoinCluster(cl.ID, password, local, []string{base})
	}()

	// The host should see exactly one pending request, carrying the claimed
	// hostname and a real (loopback) source IP.
	var reqID string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		pending := seed.ListPendingJoins()
		if len(pending) == 1 {
			p := pending[0]
			if p.NodeName != "sensor-7" {
				t.Errorf("pending node name = %q, want sensor-7", p.NodeName)
			}
			if p.ClaimedAddress != "10.9.9.9" {
				t.Errorf("claimed address = %q, want 10.9.9.9", p.ClaimedAddress)
			}
			if p.SourceIP != "127.0.0.1" {
				t.Errorf("source IP = %q, want 127.0.0.1 (authoritative peer addr)", p.SourceIP)
			}
			reqID = p.RequestID
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if reqID == "" {
		t.Fatal("host never saw the pending join request")
	}

	// The joiner must NOT be a member yet (still awaiting approval).
	seed.mu.RLock()
	n := len(seed.cluster.Nodes)
	seed.mu.RUnlock()
	if n != 1 {
		t.Errorf("cluster has %d nodes before approval, want 1 (seed only)", n)
	}

	// Approve it; the joiner's poll should then complete.
	if _, err := seed.ApproveJoin(reqID); err != nil {
		t.Fatalf("ApproveJoin: %v", err)
	}
	wg.Wait()
	if joinErr != nil {
		t.Fatalf("join did not complete after approval: %v", joinErr)
	}
	if joined == nil || joined.ID != cl.ID {
		t.Fatalf("joiner did not receive cluster membership")
	}
	// The joiner listens on ITS node port/address, not the seed's.
	if c := joined.Config; c.BindPort != 7947 || c.BindAddr != "0.0.0.0" || c.AdvertiseAddr != "10.9.9.9" {
		t.Errorf("joiner config bind=%s:%d advertise=%s, want 0.0.0.0:7947 advertise 10.9.9.9",
			c.BindAddr, c.BindPort, c.AdvertiseAddr)
	}
	seed.mu.RLock()
	n = len(seed.cluster.Nodes)
	seed.mu.RUnlock()
	if n != 2 {
		t.Errorf("cluster has %d nodes after approval, want 2", n)
	}
	// The host persisted the new member (a restart must not forget it).
	reloaded, err := NewManager(seedDir).LoadCluster()
	if err != nil || reloaded == nil || len(reloaded.Nodes) != 2 {
		t.Errorf("cluster.json after approval: err=%v nodes=%v, want 2 nodes", err, reloaded)
	}
}

// TestJoinDenied verifies a denied request makes the joiner fail fast.
func TestJoinDenied(t *testing.T) {
	const password = "correct-horse-battery"
	seed := NewManager(t.TempDir())
	cl, _ := seed.InitCluster("prod", password, DefaultClusterConfig())
	base := startSeedServer(t, seed)

	joiner := NewManager(t.TempDir())
	joiner.joinPollInterval = 20 * time.Millisecond
	joiner.joinPollTimeout = 5 * time.Second
	local := &Node{Name: "n2", Address: "127.0.0.1", Port: 7947}

	var wg sync.WaitGroup
	wg.Add(1)
	var joinErr error
	go func() {
		defer wg.Done()
		_, joinErr = joiner.JoinCluster(cl.ID, password, local, []string{base})
	}()

	var reqID string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if p := seed.ListPendingJoins(); len(p) == 1 {
			reqID = p[0].RequestID
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if reqID == "" {
		t.Fatal("no pending request appeared")
	}
	if err := seed.DenyJoin(reqID); err != nil {
		t.Fatalf("DenyJoin: %v", err)
	}
	wg.Wait()
	if joinErr == nil {
		t.Error("join succeeded despite being denied")
	}
}

// TestApproveUnknownRequest guards the error path.
func TestApproveUnknownRequest(t *testing.T) {
	seed := NewManager(t.TempDir())
	if _, err := seed.InitCluster("c", "correct-horse-battery", DefaultClusterConfig()); err != nil {
		t.Fatal(err)
	}
	if _, err := seed.ApproveJoin("req_does_not_exist"); err == nil {
		t.Error("ApproveJoin of unknown request should error")
	}
	if err := seed.DenyJoin("req_does_not_exist"); err == nil {
		t.Error("DenyJoin of unknown request should error")
	}
}

// TestJoinOutcomeGoesOnlyToTheJoiner: an approved join's outcome carries the
// member key and its signed node certificate. The request ID is no secret (it is logged
// and listed to the host), so anyone with the password and that ID could
// collect the outcome, and a request from the joiner's address under its names
// was handed the same ID. Only the joiner's poll secret collects it now.
func TestJoinOutcomeGoesOnlyToTheJoiner(t *testing.T) {
	const pw = "correct-horse-battery"
	host := NewManager(t.TempDir())
	cl, err := host.InitCluster("prod", pw, DefaultClusterConfig())
	if err != nil {
		t.Fatal(err)
	}
	join := func(secret string) *JoinResponse {
		return host.HandleJoinRequest(&JoinRequest{Version: ProtocolVersion, NodeCSR: testNodeCSR(t), ClusterID: cl.ID, Password: pw, PollSecret: secret,
			NodeName: "sensor-7", QPotID: "qp_sensor7", NodeAddress: "10.9.9.9", NodePort: 7946}, "10.9.9.9")
	}
	if r := join(""); r.Status == "pending" || r.RequestID != "" || r.Error != errNoPollSecret {
		t.Fatalf("a join without a poll secret: %+v", r)
	}
	otherSecret := strings.Repeat("q", minPollSecret)
	mine := join(testPollSecret)
	if mine.Status != "pending" || mine.RequestID == "" {
		t.Fatalf("join: %+v", mine)
	}
	if again := join(testPollSecret); again.RequestID != mine.RequestID {
		t.Fatalf("the joiner's retry got request %q, not its own %q", again.RequestID, mine.RequestID)
	}
	if other := join(otherSecret); other.RequestID == mine.RequestID {
		t.Fatal("another sender from the joiner's address and names was given its request ID")
	}
	if _, err := host.ApproveJoin(mine.RequestID); err != nil {
		t.Fatal(err)
	}

	h := host.apiHandler()
	poll := func(secret string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/cluster/join/status?request_id="+mine.RequestID, nil)
		req.RemoteAddr = "203.0.113.50:40000"
		req.Header.Set("X-Cluster-Password", pw)
		if secret != "" {
			req.Header.Set(pollSecretHeader, secret)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for _, secret := range []string{"", otherSecret} {
		if rec := poll(secret); rec.Code != http.StatusNotFound ||
			strings.Contains(rec.Body.String(), cl.CAKey) || strings.Contains(rec.Body.String(), cl.MemberKey) {
			t.Fatalf("a password holder without the joiner's poll secret got %d %q", rec.Code, rec.Body.String())
		}
	}
	rec := poll(testPollSecret)
	var got JoinResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil ||
		got.NodeCertificate == "" || strings.Contains(rec.Body.String(), cl.CAKey) ||
		strings.Contains(rec.Body.String(), "PRIVATE KEY") || got.MemberKey != cl.MemberKey || got.NodeID == "" {
		t.Fatalf("the joiner's own poll: %d %q", rec.Code, rec.Body.String())
	}
}
