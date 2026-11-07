package cluster

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// TestClusterCAIsRandomAndNamedByTheID: every init makes a new CA, the ID is
// its fingerprint, every node rebuilds the same CA certificate from the key,
// and nothing about it comes from the password.
func TestClusterCAIsRandomAndNamedByTheID(t *testing.T) {
	keyA, idA, err := newClusterCA()
	if err != nil {
		t.Fatal(err)
	}
	keyB, idB, _ := newClusterCA()
	if keyA == keyB || idA == idB {
		t.Fatal("two clusters got the same CA")
	}
	if len(idA) != len(ClusterIDPrefix)+ClusterIDLength || idA[:len(ClusterIDPrefix)] != ClusterIDPrefix {
		t.Fatalf("cluster ID %q", idA)
	}
	priv, a, err := clusterCA(keyA)
	if err != nil {
		t.Fatal(err)
	}
	_, b, _ := clusterCA(keyA)
	if !bytes.Equal(a.Raw, b.Raw) {
		t.Fatal("two nodes built different CA certificates from the same key")
	}
	if clusterIDFor(priv.Public().(ed25519.PublicKey)) != idA || checkClusterCA(idA, keyA) != nil {
		t.Fatal("the CA key does not give its cluster ID")
	}
	if checkClusterCA(idB, keyA) == nil || checkClusterCA(idA, "") != errOldClusterFormat || checkClusterCA(idA, "bm90IGEga2V5") == nil {
		t.Fatal("a wrong, missing or malformed CA key was accepted")
	}
}

// startTLSNode starts a cluster host with automatic TLS on a free port.
func startTLSNode(t *testing.T, name, password string) (*Manager, *Cluster, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	m := NewManager(t.TempDir())
	cfg := DefaultClusterConfig() // EnableEncryption = true, no cert files
	cfg.BindAddr = "127.0.0.1"
	cfg.BindPort = port
	c, err := m.InitCluster(name, password, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start with automatic TLS: %v", err)
	}
	t.Cleanup(func() { m.Stop() })
	waitListening(t, port)
	return m, c, "https://127.0.0.1:" + strconv.Itoa(port)
}

// A node with encryption on and no certificate files serves a certificate
// from its cluster's CA: a client that knows the cluster ID trusts it, one
// pinned to another cluster and plain system roots do not.
func TestAutoTLSServesAndVerifies(t *testing.T) {
	_, c, base := startTLSNode(t, "tls-test", "password123")
	get := func(client *http.Client) (int, error) {
		req, _ := http.NewRequest(http.MethodGet, base+"/api/v1/cluster/status", nil)
		setPeerAuth(req, "password123", c.MemberKey)
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	if code, err := get(clusterHTTPClient(3*time.Second, c.ID, nil, true)); err != nil || code != http.StatusOK {
		t.Fatalf("member client: code=%d err=%v", code, err)
	}
	_, other, _ := newClusterCA()
	if _, err := get(clusterHTTPClient(3*time.Second, other, nil, true)); err == nil {
		t.Fatal("a client of another cluster trusted the node")
	}
	plain := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	if _, err := get(plain); err == nil {
		t.Fatal("system-roots client trusted the cluster-CA certificate")
	}
}

// TestPasswordHolderCannotPoseAsANode: the cluster CA used to be derived from
// the password, so anyone who knew it could serve a node certificate, take a
// joiner's password and member key, or collect a member's. A node now needs
// the CA key, which the ID pins: an impostor with the password, its own CA
// and the right node name gets no request at all.
func TestPasswordHolderCannotPoseAsANode(t *testing.T) {
	const pw = "password123"
	m := NewManager(t.TempDir())
	c, err := m.InitCluster("impostor-test", pw, DefaultClusterConfig())
	if err != nil {
		t.Fatal(err)
	}
	ownKey, _, _ := newClusterCA()
	cert, err := newNodeCertificate(ownKey, c.LocalNode.ID)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan string, 4)
	impostor := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("X-Cluster-Password") + "|" + r.Header.Get(memberKeyHeader)
	}))
	impostor.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	impostor.StartTLS()
	defer impostor.Close()

	member, _ := http.NewRequest(http.MethodPost, impostor.URL+"/api/v1/cluster/gossip", nil)
	setPeerAuth(member, pw, c.MemberKey)
	if resp, err := m.peerHTTPClient(3 * time.Second).Do(member); err == nil {
		resp.Body.Close()
		t.Fatal("a member trusted a node outside the cluster's CA")
	}
	join, _ := http.NewRequest(http.MethodPost, impostor.URL+"/api/v1/cluster/join", bytes.NewReader([]byte(`{"password":"`+pw+`"}`)))
	if resp, err := clusterHTTPClient(3*time.Second, c.ID, nil, true).Do(join); err == nil {
		resp.Body.Close()
		t.Fatal("a joiner trusted a node outside the cluster's CA")
	}
	select {
	case got := <-seen:
		t.Fatalf("the impostor received a request (%q)", got)
	default:
	}
}

// TestNodeServesNothingToGuessPasswordsAgainst: a node's certificate chain
// must not depend on the password, or anyone who connects can test guesses
// offline. Two clusters with the same password and two nodes of one cluster
// with different passwords show the chain is the CA's alone.
func TestNodeServesNothingToGuessPasswordsAgainst(t *testing.T) {
	_, c1, base1 := startTLSNode(t, "one", "same-password")
	_, c2, base2 := startTLSNode(t, "two", "same-password")
	chain := func(base string) []*x509.Certificate {
		conn, err := tls.Dial("tcp", base[len("https://"):], &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- reading the chain
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates
	}
	a, b := chain(base1), chain(base2)
	if len(a) != 2 || len(b) != 2 {
		t.Fatalf("chains of %d and %d certificates, want leaf + CA", len(a), len(b))
	}
	if bytes.Equal(a[1].Raw, b[1].Raw) {
		t.Fatal("two clusters with the same password serve the same CA")
	}
	if verifyClusterPeer(c1.ID, a) != nil || verifyClusterPeer(c2.ID, b) != nil || verifyClusterPeer(c1.ID, b) == nil {
		t.Fatal("a chain verifies against the wrong cluster ID, or not its own")
	}
	// The offline check the old scheme allowed: derive the CA key from the ID
	// and a guess (here the right password) and compare it with the served
	// CA. It must not match.
	seed, err := hkdf.Key(sha256.New, []byte("same-password"), []byte(c1.ID), "qpot-cluster-ca-v1", ed25519.SeedSize)
	if err != nil {
		t.Fatal(err)
	}
	guessed := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if served, ok := a[1].PublicKey.(ed25519.PublicKey); !ok || served.Equal(guessed) {
		t.Fatal("the served CA is derived from the password: guesses can be checked offline")
	}
}

// TestOldFormatClusterRefusesToStart: a cluster saved before clusters had
// their own CA rests on the password-derived one; it does not start, and says
// to re-create it.
func TestOldFormatClusterRefusesToStart(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)
	if _, err := m.InitCluster("old", "password123", DefaultClusterConfig()); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.cluster.CAKey = ""
	if err := m.saveClusterLocked(); err != nil {
		t.Fatal(err)
	}
	m.mu.Unlock()

	loaded := NewManager(dir)
	if c, err := loaded.LoadCluster(); err != nil || c == nil {
		t.Fatalf("an old cluster file no longer loads (leave and status need it): %v", err)
	}
	if err := loaded.UnlockPassword("password123"); err != nil {
		t.Fatal(err)
	}
	if err := loaded.Start(); err != errOldClusterFormat {
		t.Fatalf("Start of an old-format cluster: %v", err)
	}
}
