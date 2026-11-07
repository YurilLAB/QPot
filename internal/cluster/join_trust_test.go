package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// impostorSeed answers /join and /join/status as a seed of the cluster would,
// serving a certificate a public CA (stood in for by systemRoots) issued for
// 127.0.0.1, and records every request body and poll it gets.
func impostorSeed(t *testing.T, clusterID, caKey string) (*publicPeer, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	p := newPublicPeerServing(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		mu.Lock()
		seen = append(seen, r.URL.Path+" "+string(b)+" "+r.Header.Get("X-Cluster-Password"))
		mu.Unlock()
		resp := JoinResponse{Status: "pending", RequestID: "jr_1"}
		if r.URL.Path == "/api/v1/cluster/join/status" {
			resp = JoinResponse{Success: true, Status: "approved", ClusterName: "c",
				NodeID: "qn_joiner", CAKey: caKey, MemberKey: "member-key-from-the-seed", Config: DefaultClusterConfig()}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	return p, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

// TestJoinTrustsOnlyTheClusterCAByDefault: the join request and the approval
// polls carry the cluster password and the poll secret, and the approval hands
// over the CA and member keys, yet the joiner accepted any seed whose
// certificate the system roots trust for the address dialled - the pin the
// cluster ID gives it was bypassed. A joiner now trusts the cluster CA alone
// unless told to accept operator certificates.
func TestJoinTrustsOnlyTheClusterCAByDefault(t *testing.T) {
	caKey, clusterID, err := newClusterCA()
	if err != nil {
		t.Fatal(err)
	}
	seed, seen := impostorSeed(t, clusterID, caKey)
	defer func(f func() (*x509.CertPool, error)) { systemRoots = f }(systemRoots)
	systemRoots = func() (*x509.CertPool, error) {
		pool := x509.NewCertPool()
		pool.AddCert(seed.ca)
		return pool, nil
	}
	addr := strings.TrimPrefix(seed.srv.URL, "https://")
	const pw = "join-password-1"

	joiner := NewManager(t.TempDir())
	joiner.joinPollInterval, joiner.joinPollTimeout = 10*time.Millisecond, 2*time.Second
	local := &Node{Name: "j", Address: "10.0.0.9", Port: 7946}
	if _, err := joiner.JoinCluster(clusterID, pw, local, []string{addr}); err == nil {
		t.Fatal("joined through a seed outside the cluster CA")
	}
	if got := seen(); len(got) != 0 {
		t.Fatalf("a seed outside the cluster CA received %d requests: %q", len(got), got)
	}

	// Opted in, the operator-certificate seed is accepted: the join and the
	// poll reach it, and the node keeps trusting operator certificates.
	op := NewManager(t.TempDir())
	op.joinPollInterval, op.joinPollTimeout = 10*time.Millisecond, 2*time.Second
	joined, err := op.JoinClusterTrusting(clusterID, pw, &Node{Name: "j", Address: "10.0.0.9", Port: 7946},
		[]string{addr}, JoinTrust{OperatorCerts: true})
	if err != nil {
		t.Fatalf("join with operator certificates allowed: %v", err)
	}
	got := seen()
	if len(got) < 2 || !strings.Contains(got[0], pw) || !strings.HasPrefix(got[1], "/api/v1/cluster/join/status") {
		t.Fatalf("seed saw %q, want the join then a poll", got)
	}
	if !joined.Config.TrustOperatorCerts || joined.Config.CACertPath != "" {
		t.Fatalf("joined config trusts operator certs %v, CA bundle %q", joined.Config.TrustOperatorCerts, joined.Config.CACertPath)
	}
	// As a member it still reaches peers serving operator certificates.
	member := newPublicPeer(t)
	systemRoots = func() (*x509.CertPool, error) {
		pool := x509.NewCertPool()
		pool.AddCert(member.ca)
		return pool, nil
	}
	gossipTo(op, member)
	if mpw, _ := member.received(); mpw != pw {
		t.Fatalf("a member that joined with operator certificates allowed did not reach such a peer (got %q)", mpw)
	}

	// A CA bundle given for the join is used for it, and kept.
	bundle := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: seed.ca.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	systemRoots = func() (*x509.CertPool, error) { return x509.NewCertPool(), nil } // nothing trusted there
	bm := NewManager(t.TempDir())
	bm.joinPollInterval, bm.joinPollTimeout = 10*time.Millisecond, 2*time.Second
	joined, err = bm.JoinClusterTrusting(clusterID, pw, &Node{Name: "j", Address: "10.0.0.9", Port: 7946},
		[]string{addr}, JoinTrust{CAFile: bundle})
	if err != nil {
		t.Fatalf("join with a CA bundle: %v", err)
	}
	if !joined.Config.TrustOperatorCerts || joined.Config.CACertPath != bundle {
		t.Fatalf("joined config trusts operator certs %v, CA bundle %q", joined.Config.TrustOperatorCerts, joined.Config.CACertPath)
	}
}

// TestJoinThroughTheClusterCAByDefault: a seed serving the cluster CA's
// certificate is joined, approval and all, without any opt-in.
func TestJoinThroughTheClusterCAByDefault(t *testing.T) {
	const pw = "join-password-2"
	seed, c, base := startTLSNode(t, "ca-join", pw)
	seed.mu.Lock()
	seed.cluster.Config.TrustOperatorCerts = true // the seed's own choice, not the joiner's
	seed.mu.Unlock()
	joiner := NewManager(t.TempDir())
	joiner.joinPollInterval, joiner.joinPollTimeout = 20*time.Millisecond, 5*time.Second
	done := make(chan error, 1)
	go func() {
		_, err := joiner.JoinCluster(c.ID, pw, &Node{Name: "j", Address: "10.0.0.9", Port: 7946}, []string{base})
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for len(seed.ListPendingJoins()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the seed never saw the join request")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := seed.ApproveJoin(seed.ListPendingJoins()[0].RequestID); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("join through the cluster CA: %v", err)
	}
	if cl := joiner.GetCluster(); cl == nil || cl.Config.TrustOperatorCerts {
		t.Fatalf("joined cluster %+v trusts operator certificates without being asked", cl)
	}
}

// TestJoinPollTrustsOnlyTheClusterCA: the approval polls carry the password
// and the poll secret and bring back the CA and member keys. A seed that
// answered the join with the cluster CA's certificate but whose address
// later serves another certificate - one the system roots trust - gets no
// poll.
func TestJoinPollTrustsOnlyTheClusterCA(t *testing.T) {
	caKey, clusterID, err := newClusterCA()
	if err != nil {
		t.Fatal(err)
	}
	node, err := newNodeCertificate(caKey, "qn_seed")
	if err != nil {
		t.Fatal(err)
	}
	impostor := newPublicPeer(t) // only for its public certificate
	defer func(f func() (*x509.CertPool, error)) { systemRoots = f }(systemRoots)
	systemRoots = func() (*x509.CertPool, error) {
		pool := x509.NewCertPool()
		pool.AddCert(impostor.ca)
		return pool, nil
	}
	var mu sync.Mutex
	var polls []string
	var conns int
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close") // every request on a new connection
		if r.URL.Path == "/api/v1/cluster/join/status" {
			mu.Lock()
			polls = append(polls, r.URL.RawQuery+" "+r.Header.Get("X-Cluster-Password"))
			mu.Unlock()
		}
		_ = json.NewEncoder(w).Encode(JoinResponse{Status: "pending", RequestID: "jr_1"})
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			defer mu.Unlock()
			conns++
			cert := impostor.srv.TLS.Certificates[0] // the polls: someone else's
			if conns == 1 {
				cert = node // the join: the cluster CA's node certificate
			}
			return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}, nil
		}}
	srv.StartTLS()
	defer srv.Close()

	joiner := NewManager(t.TempDir())
	joiner.joinPollInterval, joiner.joinPollTimeout = 10*time.Millisecond, 300*time.Millisecond
	if _, err := joiner.JoinCluster(clusterID, "join-password-3", &Node{Name: "j", Address: "10.0.0.9", Port: 7946},
		[]string{strings.TrimPrefix(srv.URL, "https://")}); err == nil {
		t.Fatal("the join completed")
	}
	mu.Lock()
	defer mu.Unlock()
	if conns < 2 {
		t.Fatalf("the joiner never polled (%d connections)", conns)
	}
	if len(polls) != 0 {
		t.Fatalf("a poll reached a certificate outside the cluster CA: %q", polls)
	}
}
