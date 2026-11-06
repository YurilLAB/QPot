package cluster

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Approving joiners is a host operation: a joiner holds the cluster password
// too, so it must not be able to approve itself over the network. The CLI
// connects over loopback.
func TestClusterApprovalIsHostOnly(t *testing.T) {
	const pw = "correct-horse-battery"
	seed := NewManager(t.TempDir())
	cl, err := seed.InitCluster("prod", pw, DefaultClusterConfig())
	if err != nil {
		t.Fatal(err)
	}
	h := seed.apiHandler()
	body, _ := json.Marshal(JoinRequest{ClusterID: cl.ID, Password: pw, NodeName: "evil", NodeAddress: "10.6.6.6", NodePort: 7946})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/cluster/join", bytes.NewReader(body)))
	var jr JoinResponse
	if err := json.NewDecoder(rec.Body).Decode(&jr); err != nil || jr.RequestID == "" {
		t.Fatalf("join: %d %+v %v", rec.Code, jr, err)
	}

	for _, path := range []string{"/api/v1/cluster/approve", "/api/v1/cluster/deny", "/api/v1/cluster/pending"} {
		ab, _ := json.Marshal(map[string]string{"request_id": jr.RequestID})
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(ab)) // RemoteAddr 192.0.2.1
		req.Header.Set("X-Cluster-Password", pw)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s from a remote address: %d, want 403", path, rec.Code)
		}
	}
	if n := len(seed.GetNodes()); n != 1 {
		t.Fatalf("joiner admitted itself: %d nodes", n)
	}

	// The host (loopback) can still approve.
	ab, _ := json.Marshal(map[string]string{"request_id": jr.RequestID})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/approve", bytes.NewReader(ab))
	req.RemoteAddr = "127.0.0.1:50000"
	req.Header.Set("X-Cluster-Password", pw)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || len(seed.GetNodes()) != 2 {
		t.Fatalf("host approve: %d, nodes %d: %s", rec.Code, len(seed.GetNodes()), rec.Body.String())
	}
}

// A CA-trusted certificate for some other name must not be accepted from a
// peer addressed by IP (seeds and gossip peers usually are): the cluster
// password would be sent to it.
func TestClusterTLSChecksIPPeerName(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Public Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafT := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "attacker.example"},
		DNSNames: []string{"attacker.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafT, ca, &leafKey.PublicKey, caKey)

	var gotPw atomic.Value
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotPw.Store(string(b))
	})}
	go srv.Serve(ln)
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(ca) // stands in for the system roots / operator CA
	c := clusterHTTPClient(5*time.Second, "qc_x", pool)
	resp, err := c.Post("https://"+ln.Addr().String()+"/api/v1/cluster/join", "application/json", bytes.NewReader([]byte(`{"password":"secret-pass"}`)))
	if err == nil {
		resp.Body.Close()
		t.Fatalf("certificate for attacker.example accepted at 127.0.0.1; server got %v", gotPw.Load())
	}
	if gotPw.Load() != nil {
		t.Fatalf("password reached an untrusted peer: %v", gotPw.Load())
	}
}

// Start must fail when the cluster port is taken instead of gossiping as if
// it served.
func TestClusterStartFailsWhenPortTaken(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	cfg := DefaultClusterConfig()
	cfg.BindAddr = "127.0.0.1"
	cfg.BindPort = ln.Addr().(*net.TCPAddr).Port
	m := NewManager(t.TempDir())
	if _, err := m.InitCluster("x", "password123", cfg); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err == nil {
		t.Errorf("Start returned nil although port %d is in use; running=%v", cfg.BindPort, m.GetStatus().IsRunning)
	}
	if m.GetStatus().IsRunning {
		t.Error("manager reports running after a failed Start")
	}
	m.Stop()
}

// Each gossip round builds its own client; its idle connections must not pile
// up across rounds.
func TestGossipDoesNotPileUpConnections(t *testing.T) {
	const pw = "password123"
	peer := NewManager(t.TempDir())
	pc := DefaultClusterConfig()
	pc.EnableEncryption = false
	pcl, _ := peer.InitCluster("x", pw, pc)
	var open, total int64
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/cluster/gossip", peer.withClusterAuth(peer.handleGossipHTTP))
	srv := &http.Server{Handler: mux, ReadTimeout: 15 * time.Second, ConnState: func(c net.Conn, s http.ConnState) {
		switch s {
		case http.StateNew:
			atomic.AddInt64(&open, 1)
			atomic.AddInt64(&total, 1)
		case http.StateClosed, http.StateHijacked:
			atomic.AddInt64(&open, -1)
		}
	}}
	go srv.Serve(ln)
	defer srv.Close()

	m := NewManager(t.TempDir())
	mc := DefaultClusterConfig()
	mc.EnableEncryption = false
	m.cluster = &Cluster{ID: pcl.ID, Config: mc, Nodes: map[string]*Node{}}
	m.plainPassword = pw
	local := &Node{ID: "qn_local", Address: "127.0.0.1", Port: 1}
	m.cluster.LocalNode = local
	m.cluster.Nodes[local.ID] = local
	m.cluster.Nodes["qn_peer"] = &Node{ID: "qn_peer", Address: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, Status: NodeStatusHealthy}
	g0 := runtime.NumGoroutine()
	for i := 0; i < 50; i++ { // 50 rounds = 10s of default 200ms gossip
		m.gossip()
	}
	time.Sleep(100 * time.Millisecond)
	t.Logf("after 50 gossip rounds to ONE peer: server conns open=%d total=%d, client goroutines +%d",
		atomic.LoadInt64(&open), atomic.LoadInt64(&total), runtime.NumGoroutine()-g0)
	if atomic.LoadInt64(&open) > 5 {
		t.Errorf("%d idle keep-alive conns to a single peer", atomic.LoadInt64(&open))
	}
}

// `qpot cluster leave` loads the membership from disk (only the bcrypt hash)
// and must still authenticate to peers, and must report peers it could not
// notify instead of claiming success.
func TestLeaveAfterLoadNotifiesPeers(t *testing.T) {
	const pw = "password123"
	dir := t.TempDir()
	var gotAuth atomic.Value
	gotAuth.Store("")
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("X-Cluster-Password"))
	}))
	defer ok.Close()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer down.Close()
	port := func(s *httptest.Server) int { return s.Listener.Addr().(*net.TCPAddr).Port }

	m := NewManager(dir)
	cfg := DefaultClusterConfig()
	cfg.EnableEncryption = false
	if _, err := m.InitCluster("x", pw, cfg); err != nil {
		t.Fatal(err)
	}
	if err := m.SaveSecret(); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.cluster.Nodes["qn_ok"] = &Node{ID: "qn_ok", Address: "127.0.0.1", Port: port(ok)}
	m.cluster.Nodes["qn_down"] = &Node{ID: "qn_down", Address: "127.0.0.1", Port: port(down)}
	if err := m.saveClusterLocked(); err != nil {
		t.Fatal(err)
	}
	m.mu.Unlock()

	m2 := NewManager(dir)
	if _, err := m2.LoadCluster(); err != nil {
		t.Fatal(err)
	}
	err := m2.LeaveCluster()
	if gotAuth.Load() != pw {
		t.Errorf("peer saw password header %q", gotAuth.Load())
	}
	if err == nil || !strings.Contains(err.Error(), "1 of 2 peers were not notified") {
		t.Errorf("LeaveCluster error = %v, want the unreached peer reported", err)
	}
}
