package cluster

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// publicPeer serves gossip with a certificate for 127.0.0.1 from a CA that
// stands in for a public one, and records the credentials it is sent.
type publicPeer struct {
	ca       *x509.Certificate
	srv      *httptest.Server
	mu       sync.Mutex
	password string
	member   string
}

func newPublicPeer(t *testing.T) *publicPeer {
	t.Helper()
	return newPublicPeerServing(t, nil)
}

// newPublicPeerServing is newPublicPeer with handler, when not nil, serving
// instead of the recording gossip handler.
func newPublicPeerServing(t *testing.T, handler http.Handler) *publicPeer {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Some Public CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafT := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafT, ca, &leafKey.PublicKey, caKey)

	p := &publicPeer{ca: ca}
	if handler == nil {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p.mu.Lock()
			p.password, p.member = r.Header.Get("X-Cluster-Password"), r.Header.Get(memberKeyHeader)
			p.mu.Unlock()
			_ = json.NewEncoder(w).Encode(GossipMessage{})
		})
	}
	p.srv = httptest.NewUnstartedServer(handler)
	p.srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	p.srv.StartTLS()
	t.Cleanup(p.srv.Close)
	return p
}

func (p *publicPeer) received() (string, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.password, p.member
}

// gossipTo makes the peer a member of m's cluster and runs one gossip round.
func gossipTo(m *Manager, p *publicPeer) {
	port := p.srv.Listener.Addr().(*net.TCPAddr).Port
	m.mu.Lock()
	m.cluster.Nodes["qn_peer"] = &Node{ID: "qn_peer", Address: "127.0.0.1", Port: port,
		Status: NodeStatusHealthy, LastSeen: time.Now()}
	m.mu.Unlock()
	m.gossip()
}

// TestAutoTLSMembersTrustOnlyTheClusterCA: a cluster on automatic TLS (no
// operator certificate, no CA bundle) still accepted any peer whose
// certificate the system roots trust for the address it dialled, and sent
// it the cluster password and member key on every gossip round. Anyone who
// can get a publicly trusted certificate for a member's name or IP - an
// on-path attacker can, for traffic it intercepts - collected both. Such a
// cluster now trusts its own CA alone; one that names a CA bundle still
// accepts operator certificates from it.
func TestAutoTLSMembersTrustOnlyTheClusterCA(t *testing.T) {
	peer := newPublicPeer(t)
	defer func(f func() (*x509.CertPool, error)) { systemRoots = f }(systemRoots)
	systemRoots = func() (*x509.CertPool, error) { // the system trust store holds the peer's CA
		pool := x509.NewCertPool()
		pool.AddCert(peer.ca)
		return pool, nil
	}

	m := NewManager(t.TempDir())
	if _, err := m.InitCluster("c", "password123", DefaultClusterConfig()); err != nil { // automatic TLS
		t.Fatal(err)
	}
	gossipTo(m, peer)
	if pw, key := peer.received(); pw != "" || key != "" {
		t.Fatalf("an automatic-TLS cluster sent password %q (member key set: %v) to a peer outside its CA", pw, key != "")
	}

	// A cluster that names a CA bundle trusts certificates from it.
	bundle := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: peer.ca.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultClusterConfig()
	cfg.CACertPath = bundle
	op := NewManager(t.TempDir())
	if _, err := op.InitCluster("c", "password123", cfg); err != nil {
		t.Fatal(err)
	}
	gossipTo(op, peer)
	if pw, _ := peer.received(); pw != "password123" {
		t.Fatalf("a cluster with a CA bundle did not reach a peer certified by it (got %q)", pw)
	}

	// One that names an operator certificate and no bundle checks peers
	// against the system trust store.
	peer2 := newPublicPeer(t)
	systemRoots = func() (*x509.CertPool, error) {
		pool := x509.NewCertPool()
		pool.AddCert(peer2.ca)
		return pool, nil
	}
	cfg = DefaultClusterConfig()
	cfg.TLSCertPath, cfg.TLSKeyPath = "/etc/qpot/cluster.crt", "/etc/qpot/cluster.key"
	sys := NewManager(t.TempDir())
	if _, err := sys.InitCluster("c", "password123", cfg); err != nil {
		t.Fatal(err)
	}
	gossipTo(sys, peer2)
	if pw, _ := peer2.received(); pw != "password123" {
		t.Fatalf("a cluster with an operator certificate did not reach a peer the system roots trust (got %q)", pw)
	}
}
