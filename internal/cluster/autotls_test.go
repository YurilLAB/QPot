package cluster

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/hostsetup"
)

// TestClusterCAIsRandomAndNamedByTheID: every init makes a new CA, the ID is
// its fingerprint, the authority rebuilds the same CA certificate from the key,
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
		t.Fatal("the authority rebuilt different CA certificates from the same key")
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
	m, c, base := startTLSNode(t, "tls-test", "password123")
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
	// A member presents its own node certificate (the host is the only one).
	m.mu.RLock()
	own, err := nodeCertificate(c.ID, c.LocalNode.ID, c.NodeCertificate, c.NodeKey)
	m.mu.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	if code, err := get(clusterPeerClient(3*time.Second, c.ID, nil, true, &own)); err != nil || code != http.StatusOK {
		t.Fatalf("member client: code=%d err=%v", code, err)
	}
	// Without a node certificate the password and member key are not enough.
	if code, err := get(clusterHTTPClient(3*time.Second, c.ID, nil, true)); err != nil || code != http.StatusUnauthorized {
		t.Fatalf("client without a node certificate: code=%d err=%v", code, err)
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
// a certificate from the CA, which the ID pins: an impostor with the password, its own CA
// and the right node name gets no request at all.
func TestPasswordHolderCannotPoseAsANode(t *testing.T) {
	const pw = "password123"
	m := NewManager(t.TempDir())
	c, err := m.InitCluster("impostor-test", pw, DefaultClusterConfig())
	if err != nil {
		t.Fatal(err)
	}
	ownKey, _, _ := newClusterCA()
	nodeKey, csr, err := newNodeRequest()
	if err != nil {
		t.Fatal(err)
	}
	chain, err := issueNodeCertificate(ownKey, c.LocalNode.ID, csr)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair([]byte(chain), []byte(nodeKey))
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
	m.cluster.NodeKey, m.cluster.NodeCertificate = "", ""
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

func testNodeCSR(t *testing.T) string {
	t.Helper()
	_, csr, err := newNodeRequest()
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func testResignNode(t *testing.T, caKey, chain string, change func(*x509.Certificate)) string {
	t.Helper()
	block, _ := pem.Decode([]byte(chain))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	change(cert)
	signer, ca, err := clusterCA(caKey)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, ca, cert.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))
}

// An enrollment response carries only the leaf, public chain and existing
// member credential. Neither the CA key nor any node private key is exported.
func TestEnrollmentResponseContainsNoPrivateSigningKey(t *testing.T) {
	m := NewManager(t.TempDir())
	cfg := DefaultClusterConfig()
	cfg.RequireApproval = false
	c, err := m.InitCluster("authority", "password123", cfg)
	if err != nil {
		t.Fatal(err)
	}
	nodeKey, csr, err := newNodeRequest()
	if err != nil {
		t.Fatal(err)
	}
	resp := m.HandleJoinRequest(&JoinRequest{Version: ProtocolVersion, ClusterID: c.ID, Password: "password123", NodeCSR: csr,
		NodeName: "sensor", NodeAddress: "127.0.0.1", NodePort: 7947}, "127.0.0.1")
	if !resp.Success {
		t.Fatalf("enroll: %+v", resp)
	}
	wire, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{c.CAKey, c.NodeKey, nodeKey, "ca_key", "node_key", "PRIVATE KEY"} {
		if bytes.Contains(wire, []byte(forbidden)) {
			t.Fatal("enrollment response contains private signing material")
		}
	}
	if _, err := nodeCertificate(c.ID, resp.NodeID, resp.NodeCertificate, nodeKey); err != nil {
		t.Fatalf("response is not the joiner's signed identity: %v", err)
	}
}

func TestEnrollmentRejectsInvalidNodeRequestsBeforeAdmission(t *testing.T) {
	valid := testNodeCSR(t)
	block, _ := pem.Decode([]byte(valid))
	block.Bytes[len(block.Bytes)-1] ^= 1
	badSignature := string(pem.EncodeToMemory(block))
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, approval := range []bool{false, true} {
		m := NewManager(t.TempDir())
		cfg := DefaultClusterConfig()
		cfg.RequireApproval = approval
		c, err := m.InitCluster("authority", "password123", cfg)
		if err != nil {
			t.Fatal(err)
		}
		for name, csr := range map[string]string{
			"old-client": "", "malformed": "not a CSR", "oversized": strings.Repeat("x", maxNodeCSRBytes+1),
			"invalid-signature": badSignature, "extra-block": valid + valid,
			"unsupported-key": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: otherDER})),
		} {
			t.Run(strconv.FormatBool(approval)+"/"+name, func(t *testing.T) {
				resp := m.HandleJoinRequest(&JoinRequest{Version: ProtocolVersion, ClusterID: c.ID, Password: "password123", NodeCSR: csr,
					PollSecret: testPollSecret, NodeName: "sensor", NodeAddress: "127.0.0.1", NodePort: 7947}, "127.0.0.1")
				if resp.Success || resp.Status == "pending" || resp.Error == "" || len(m.GetNodes()) != 1 || len(m.ListPendingJoins()) != 0 {
					t.Fatalf("invalid CSR mutated enrollment state: %+v", resp)
				}
			})
		}
	}
}

func TestEnrollmentIgnoresCSRIdentityAndCAExtensions(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	constraints, err := asn1.Marshal(struct{ IsCA bool }{true})
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "qpot-node victim"}, DNSNames: []string{"attacker.example"},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: constraints}},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	caKey, id, err := newClusterCA()
	if err != nil {
		t.Fatal(err)
	}
	chain, err := issueNodeCertificate(caKey, "qn_assigned", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})))
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := nodeCertificate(id, "qn_assigned", chain, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "qpot-cluster-node" || leaf.Subject.CommonName != "qpot-node qn_assigned" {
		t.Fatalf("CSR chose privileges or identity: %+v", leaf)
	}
	// A compromised member can sign bytes using its leaf private key, but it
	// cannot mint another node that chains to the pinned enrollment authority.
	_, ca, err := clusterCA(caKey)
	if err != nil {
		t.Fatal(err)
	}
	forgedTemplate := *leaf
	forgedTemplate.SignatureAlgorithm = x509.ECDSAWithSHA256
	forgedTemplate.Subject.CommonName = "qpot-node forged"
	forgedDER, err := x509.CreateCertificate(rand.Reader, &forgedTemplate, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := x509.ParseCertificate(forgedDER)
	if err != nil {
		t.Fatal(err)
	}
	if verifyClusterPeer(id, []*x509.Certificate{forged, leaf, ca}) == nil {
		t.Fatal("member's key issued a trusted node certificate")
	}
}

func TestJoinRejectsSubstitutedOrLegacyNodeIdentity(t *testing.T) {
	caKey, id, err := newClusterCA()
	if err != nil {
		t.Fatal(err)
	}
	otherCA, _, err := newClusterCA()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "wrong-key", "wrong-node", "wrong-ca", "expired", "ca-privilege", "legacy", "future-version", "missing-member-key"} {
		t.Run(mode, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req JoinRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				issuer, nodeID, csr := caKey, "qn_assigned", req.NodeCSR
				switch mode {
				case "wrong-key":
					csr = testNodeCSR(t)
				case "wrong-node":
					nodeID = "qn_other"
				case "wrong-ca":
					issuer = otherCA
				}
				chain, err := issueNodeCertificate(issuer, nodeID, csr)
				if err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if mode == "expired" {
					chain = testResignNode(t, caKey, chain, func(c *x509.Certificate) {
						c.NotBefore, c.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)
					})
				}
				if mode == "ca-privilege" {
					chain = testResignNode(t, caKey, chain, func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign })
				}
				if mode == "legacy" {
					json.NewEncoder(w).Encode(map[string]any{"success": true, "node_id": "qn_assigned", "ca_key": caKey})
					return
				}
				version, memberKey := ProtocolVersion, "qk_test-membership-credential"
				if mode == "future-version" {
					version++
				}
				if mode == "missing-member-key" {
					memberKey = ""
				}
				json.NewEncoder(w).Encode(JoinResponse{Version: version, Success: true, NodeID: "qn_assigned", NodeCertificate: chain, MemberKey: memberKey})
			}))
			defer srv.Close()
			m := NewManager(t.TempDir())
			c, err := m.JoinCluster(id, "password123", &Node{Address: "127.0.0.1", Port: 7947}, []string{srv.URL})
			if mode == "valid" {
				if err != nil || c == nil || c.CAKey != "" {
					t.Fatalf("valid enrollment: %v", err)
				}
				return
			}
			if err == nil || c != nil || m.GetCluster() != nil {
				t.Fatal("substituted/legacy identity was accepted")
			}
			if _, err := os.Stat(filepath.Join(m.dataPath, "cluster.json")); !os.IsNotExist(err) {
				t.Fatal("rejected enrollment persisted cluster state")
			}
		})
	}
}

func TestLegacySharedCAClusterRequiresNewTrustRoot(t *testing.T) {
	m := NewManager(t.TempDir())
	c, err := m.InitCluster("old", "password123", DefaultClusterConfig())
	if err != nil {
		t.Fatal(err)
	}
	// The shared-CA format had a CA key but no enrolled local identity. It
	// must not be silently promoted into an authority or auto-migrated.
	c.NodeCertificate, c.NodeKey = "", ""
	if err := m.Start(); err != errOldClusterFormat {
		t.Fatalf("legacy shared-CA startup: %v", err)
	}
	resp := m.HandleJoinRequest(&JoinRequest{Version: ProtocolVersion, ClusterID: c.ID, Password: "password123", NodeCSR: testNodeCSR(t),
		NodeAddress: "127.0.0.1", NodePort: 7947}, "127.0.0.1")
	if resp.Success || resp.Status == "pending" || !strings.Contains(resp.Error, "upgrade") {
		t.Fatalf("legacy state enrolled a new node: %+v", resp)
	}
	if c.NodeCertificate != "" || c.NodeKey != "" {
		t.Fatal("legacy signing material was silently migrated")
	}
}

func TestAuthorityRenewsOnlyItsOwnValidatedIdentity(t *testing.T) {
	for _, mode := range []string{"expired", "expiring", "fresh", "wrong-key", "wrong-node", "wrong-ca", "member"} {
		t.Run(mode, func(t *testing.T) {
			m := NewManager(t.TempDir())
			cfg := DefaultClusterConfig()
			cfg.BindAddr, cfg.BindPort = "127.0.0.1", 0
			c, err := m.InitCluster("authority", "password123", cfg)
			if err != nil {
				t.Fatal(err)
			}
			keyBefore := c.NodeKey
			if mode != "fresh" {
				c.NodeCertificate = testResignNode(t, c.CAKey, c.NodeCertificate, func(cert *x509.Certificate) {
					cert.NotBefore = time.Now().Add(-366 * 24 * time.Hour)
					cert.NotAfter = time.Now().Add(-time.Hour)
					if mode == "expiring" {
						cert.NotAfter = time.Now().Add(24 * time.Hour)
					}
				})
			}
			switch mode {
			case "wrong-key":
				c.NodeKey, _, err = newNodeRequest()
				if err != nil {
					t.Fatal(err)
				}
			case "wrong-node":
				c.LocalNode.ID = "qn_not-this-node"
			case "wrong-ca":
				c.CAKey, _, err = newClusterCA()
				if err != nil {
					t.Fatal(err)
				}
			case "member":
				c.CAKey = ""
			}
			before := c.NodeCertificate
			err = m.Start()
			switch mode {
			case "expired", "expiring", "fresh":
				if err != nil {
					t.Fatal(err)
				}
				defer m.Stop()
				if _, err := nodeCertificate(c.ID, c.LocalNode.ID, c.NodeCertificate, c.NodeKey); err != nil || c.NodeKey != keyBefore {
					t.Fatalf("authority renewal changed key or issued invalid cert: %v", err)
				}
				if (c.NodeCertificate == before) != (mode == "fresh") {
					t.Fatal("authority renewal did not respect remaining lifetime")
				}
				saved, err := NewManager(m.dataPath).LoadCluster()
				if err != nil || saved.NodeCertificate != c.NodeCertificate {
					t.Fatalf("renewal was not persisted: %v", err)
				}
			default:
				if err == nil {
					m.Stop()
					t.Fatal("untrusted or ordinary member identity was renewed")
				}
				if c.NodeCertificate != before {
					t.Fatal("failed renewal changed the saved identity")
				}
			}
		})
	}
}

func testLegacyCluster(t *testing.T) (*Manager, *Cluster, []byte) {
	t.Helper()
	m, c, raw, ln := testLegacyClusterListening(t)
	ln.Close()
	return m, c, raw
}

// testLegacyClusterListening is testLegacyCluster with the cluster's port still
// held open, for a test that needs a live listener on it. Closing the port and
// binding it again lets a parallel process take it in between.
func testLegacyClusterListening(t *testing.T) (*Manager, *Cluster, []byte, net.Listener) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	cfg := DefaultClusterConfig()
	cfg.BindAddr, cfg.AdvertiseAddr = "127.0.0.1", "127.0.0.1"
	cfg.BindPort = ln.Addr().(*net.TCPAddr).Port
	cfg.RequireApproval = false // preserve operator settings during upgrade
	m := NewManager(t.TempDir())
	c, err := m.InitCluster("preserved-production", "password123", cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.Version = 0
	c.NodeKey, c.NodeCertificate = "", ""
	c.Metadata["operator-setting"] = "preserve"
	c.LocalNode.Name, c.LocalNode.InstanceName = "sensor", "existing-instance"
	c.LocalNode.Stats.TotalEvents = 37
	c.Nodes["qn_old-peer"] = &Node{ID: "qn_old-peer", Address: "127.0.0.2", Port: 7946}
	if err := m.saveCluster(); err != nil {
		t.Fatal(err)
	}
	if err := m.SaveSecret(); err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(filepath.Join(m.dataPath, "cluster.json"))
	if err != nil {
		t.Fatal(err)
	}
	return m, c, old, ln
}

func requireClusterCode(t *testing.T, err error, code string) {
	t.Helper()
	var coded *hostsetup.Error
	if !errors.As(err, &coded) || coded.Code != code {
		t.Fatalf("error %v, want %s", err, code)
	}
}

func TestClusterUpgradePreservesSettingsAndDataWithNewTrust(t *testing.T) {
	m, old, raw := testLegacyCluster(t)
	instancePath := filepath.Join(m.dataPath, "existing-instance.data")
	instanceData := []byte("honeypot events and instance settings remain here")
	if err := os.WriteFile(instancePath, instanceData, 0600); err != nil {
		t.Fatal(err)
	}
	oldKey, csr, err := newNodeRequest()
	if err != nil {
		t.Fatal(err)
	}
	oldChain, err := issueNodeCertificate(old.CAKey, old.LocalNode.ID, csr)
	if err != nil {
		t.Fatal(err)
	}
	oldCert, err := nodeCertificate(old.ID, old.LocalNode.ID, oldChain, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	upgraded, backup, err := m.UpgradeCluster()
	if err != nil {
		t.Fatal(err)
	}
	if upgraded.Version != ProtocolVersion || upgraded.ID == old.ID || upgraded.CAKey == old.CAKey || upgraded.MemberKey == old.MemberKey {
		t.Fatal("upgrade retained legacy trust or protocol")
	}
	if upgraded.Name != old.Name || !upgraded.CreatedAt.Equal(old.CreatedAt) || *upgraded.Config != *old.Config ||
		upgraded.Metadata["operator-setting"] != "preserve" || upgraded.LocalNode.ID != old.LocalNode.ID ||
		upgraded.LocalNode.InstanceName != "existing-instance" || upgraded.LocalNode.Name != "sensor" || upgraded.LocalNode.Stats.TotalEvents != 37 {
		t.Fatal("upgrade lost cluster settings or local instance information")
	}
	if len(upgraded.Nodes) != 1 || upgraded.Nodes[upgraded.LocalNode.ID] == nil {
		t.Fatal("legacy members were silently retained in new trust")
	}
	backedUp, err := os.ReadFile(backup)
	if err != nil || !bytes.Equal(backedUp, raw) {
		t.Fatalf("old configuration was not preserved byte-for-byte: %v", err)
	}
	if info, err := os.Stat(backup); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("backup is not private: %v", err)
	}
	if data, err := os.ReadFile(instancePath); err != nil || !bytes.Equal(data, instanceData) {
		t.Fatal("upgrade changed instance/event data")
	}
	if data, err := os.ReadFile(filepath.Join(m.dataPath, secretFile)); err != nil || string(data) != "password123" {
		t.Fatal("upgrade lost the existing password secret")
	}
	var oldPeer []*x509.Certificate
	for _, der := range oldCert.Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		oldPeer = append(oldPeer, cert)
	}
	if verifyClusterPeer(upgraded.ID, oldPeer) == nil {
		t.Fatal("upgraded cluster trusts the old shared CA")
	}
	restarted := NewManager(m.dataPath)
	loaded, err := restarted.LoadCluster()
	if err != nil || loaded.ID != upgraded.ID || loaded.Version != ProtocolVersion {
		t.Fatalf("upgraded state did not survive reload: %v", err)
	}
	if err := restarted.UnlockFromSecret(); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Start(); err != nil {
		t.Fatal(err)
	}
	defer restarted.Stop()
	for _, version := range []int{0, ProtocolVersion - 1, ProtocolVersion + 1} {
		response := restarted.HandleJoinRequest(&JoinRequest{Version: version, ClusterID: upgraded.ID,
			Password: "password123", NodeCSR: testNodeCSR(t), NodeAddress: "127.0.0.1", NodePort: 7947}, "127.0.0.1")
		if response.Success || response.ErrorCode != "QP-CLUSTER-002" {
			t.Fatalf("incompatible peer version admitted: %+v", response)
		}
	}
}

func TestClusterUpgradeFailuresLeaveActiveStateUntouched(t *testing.T) {
	for _, mode := range []string{"locked", "active-listener", "stale-lock", "changed-config", "operator-tls", "backup-write", "stage-write", "backup-sync", "concurrent-change", "activation-failure", "interrupted-staging"} {
		t.Run(mode, func(t *testing.T) {
			m, old, raw, held := testLegacyClusterListening(t)
			if mode != "active-listener" {
				held.Close()
			}
			wantCode := "QP-CLUSTER-006"
			switch mode {
			case "locked":
				m.plainPassword = ""
			case "active-listener":
				// held, the cluster port's own listener, stays open.
			case "stale-lock":
				if err := os.WriteFile(filepath.Join(m.dataPath, "cluster.upgrade.lock"), []byte("interrupted owner"), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed-config":
				var saved Cluster
				if err := json.Unmarshal(raw, &saved); err != nil {
					t.Fatal(err)
				}
				saved.Config.GossipInterval *= 2
				raw, _ = json.Marshal(&saved)
				if err := os.WriteFile(filepath.Join(m.dataPath, "cluster.json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
				wantCode = "QP-CLUSTER-007"
			case "operator-tls":
				old.Config.TLSCertPath = filepath.Join(m.dataPath, "missing-cert.pem")
				old.Config.TLSKeyPath = filepath.Join(m.dataPath, "missing-key.pem")
				if err := m.saveCluster(); err != nil {
					t.Fatal(err)
				}
				raw, _ = os.ReadFile(filepath.Join(m.dataPath, "cluster.json"))
			case "backup-write", "stage-write", "concurrent-change":
				wantCode = "QP-CLUSTER-008"
				calls := 0
				m.upgradeWrite = func(file *os.File, data []byte) error {
					calls++
					if (mode == "backup-write" && calls == 1) || (mode == "stage-write" && calls == 2) {
						file.Close()
						return errors.New("injected write failure")
					}
					if mode == "concurrent-change" && calls == 2 {
						raw = append(raw, '\n')
						if err := os.WriteFile(filepath.Join(m.dataPath, "cluster.json"), raw, 0600); err != nil {
							t.Error(err)
						}
					}
					return writeUpgradeFile(file, data)
				}
				if mode == "concurrent-change" {
					wantCode = "QP-CLUSTER-007"
				}
			case "backup-sync":
				wantCode = "QP-CLUSTER-008"
				m.upgradeSyncDirectory = func(string) error { return errors.New("injected directory sync failure") }
			case "activation-failure", "interrupted-staging":
				wantCode = "QP-CLUSTER-008"
				m.upgradeActivate = func(staged, active string) error {
					current, err := os.ReadFile(active)
					if err != nil || !bytes.Equal(current, raw) {
						t.Error("old instance changed before activation")
					}
					candidateBytes, err := os.ReadFile(staged)
					if err != nil {
						t.Error(err)
					}
					var candidate Cluster
					if err := json.Unmarshal(candidateBytes, &candidate); err != nil || candidate.Version != ProtocolVersion {
						t.Error("candidate not fully staged")
					}
					if mode == "interrupted-staging" {
						// A crashed process can leave staging/lock files. None is
						// an active state file or loaded as a fallback trust root.
						os.WriteFile(filepath.Join(m.dataPath, "cluster.upgrade-interrupted.tmp"), candidateBytes, 0600)
					}
					return errors.New("injected activation I/O failure")
				}
			}
			result, backup, err := m.UpgradeCluster()
			requireClusterCode(t, err, wantCode)
			if result != nil || m.cluster != old || m.cluster.Version != 0 {
				t.Fatal("failed upgrade changed in-memory active instance")
			}
			current, readErr := os.ReadFile(filepath.Join(m.dataPath, "cluster.json"))
			if readErr != nil || !bytes.Equal(current, raw) {
				t.Fatal("failed upgrade replaced the original active state")
			}
			if backup != "" {
				data, err := os.ReadFile(backup)
				if err != nil || !bytes.Equal(bytes.TrimSpace(data), bytes.TrimSpace(raw)) {
					t.Fatal("rollback backup is not the unchanged original")
				}
			}
			reloaded, err := NewManager(m.dataPath).LoadCluster()
			if err != nil || reloaded.Version != 0 || reloaded.ID != old.ID {
				t.Fatal("interrupted staging or backup was activated automatically")
			}
		})
	}
}

func TestClusterErrorCodesAreActionableAndContainNoKeys(t *testing.T) {
	m, c, _ := testLegacyCluster(t)
	requireClusterCode(t, m.Start(), "QP-CLUSTER-001")
	c.Version = ProtocolVersion + 1
	requireClusterCode(t, m.Start(), "QP-CLUSTER-002")
	_, err := parseNodeRequest("not a CSR")
	requireClusterCode(t, err, "QP-CLUSTER-003")
	_, err = nodeCertificate(c.ID, c.LocalNode.ID, "broken", "private key must not be echoed")
	requireClusterCode(t, err, "QP-CLUSTER-005")
	if strings.Contains(err.Error(), "private key must not be echoed") || strings.Contains(err.Error(), c.CAKey) {
		t.Fatal("error message exposed private signing material")
	}
}

func TestMemberEndpointsRejectIncompatibleProtocol(t *testing.T) {
	m := NewManager(t.TempDir())
	c, err := m.InitCluster("versioned", "password123", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"", "1", "3", "not-a-version", strconv.Itoa(ProtocolVersion)} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/cluster/status", nil)
		setPeerAuth(req, "password123", c.MemberKey)
		req.Header.Set(clusterVersionHeader, version)
		req.TLS = hostTLS(t, m)
		recorder := httptest.NewRecorder()
		m.apiHandler().ServeHTTP(recorder, req)
		if version == strconv.Itoa(ProtocolVersion) {
			if recorder.Code != http.StatusOK {
				t.Fatalf("current version refused: %d", recorder.Code)
			}
			continue
		}
		var failure JoinResponse
		if recorder.Code != http.StatusUpgradeRequired || json.Unmarshal(recorder.Body.Bytes(), &failure) != nil || failure.ErrorCode != "QP-CLUSTER-002" {
			t.Fatalf("incompatible peer version %q accepted or uncoded: %d %s", version, recorder.Code, recorder.Body.String())
		}
	}
}

func TestClusterUpgradePostActivationSyncFailureKeepsNewTrust(t *testing.T) {
	m, old, raw := testLegacyCluster(t)
	calls := 0
	m.upgradeSyncDirectory = func(string) error {
		calls++
		if calls == 2 {
			return errors.New("injected post-activation sync failure")
		}
		return nil
	}
	active, backup, err := m.UpgradeCluster()
	requireClusterCode(t, err, "QP-CLUSTER-009")
	if active == nil || m.cluster != active || active.Version != ProtocolVersion || active.ID == old.ID {
		t.Fatal("post-activation uncertainty rolled back or lost the new active state")
	}
	loaded, loadErr := NewManager(m.dataPath).LoadCluster()
	if loadErr != nil || loaded.ID != active.ID || loaded.CAKey == old.CAKey {
		t.Fatal("in-memory and on-disk state disagree after activation")
	}
	original, readErr := os.ReadFile(backup)
	if readErr != nil || !bytes.Equal(original, raw) {
		t.Fatal("post-activation failure lost original recovery material")
	}
	if _, _, retryErr := m.UpgradeCluster(); retryErr == nil {
		t.Fatal("uncertain activation allowed blind rerun")
	}
}

func TestAuthorityStartupCodesCorruptSigningMaterial(t *testing.T) {
	for _, field := range []string{"ca", "certificate", "node-key"} {
		t.Run(field, func(t *testing.T) {
			m := NewManager(t.TempDir())
			c, err := m.InitCluster("authority", "password123", nil)
			if err != nil {
				t.Fatal(err)
			}
			const corruptSecret = "private-corrupted-signing-material"
			switch field {
			case "ca":
				c.CAKey = corruptSecret
			case "certificate":
				c.NodeCertificate = corruptSecret
			case "node-key":
				c.NodeKey = corruptSecret
			}
			err = m.Start()
			requireClusterCode(t, err, "QP-CLUSTER-005")
			if strings.Contains(err.Error(), corruptSecret) {
				t.Fatal("startup error exposed signing material")
			}
		})
	}
}
