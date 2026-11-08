package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

// Helpers for tests of the peer endpoints, which serve a request only with
// the sending member's node certificate (see peerauth.go).

// parseChain parses a PEM certificate chain.
func parseChain(t *testing.T, chain string) []*x509.Certificate {
	t.Helper()
	certs, err := parseChainPEM(chain)
	if err != nil {
		t.Fatal(err)
	}
	return certs
}

func parseChainPEM(chain string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(chain)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificate in the chain")
	}
	return certs, nil
}

// issueFor returns a node certificate chain and key for nodeID from the CA
// of host, the enrollment host.
func issueFor(t *testing.T, host *Manager, nodeID string) (chain, key string) {
	t.Helper()
	host.mu.RLock()
	caKey := host.cluster.CAKey
	host.mu.RUnlock()
	key, csr, err := newNodeRequest()
	if err != nil {
		t.Fatal(err)
	}
	chain, err = issueNodeCertificate(caKey, nodeID, csr)
	if err != nil {
		t.Fatal(err)
	}
	return chain, key
}

// enrolled returns n carrying a certificate from host's CA for n.ID, as
// gossip carries it: a node the enrollment host admitted.
func enrolled(t *testing.T, host *Manager, n *Node) *Node {
	t.Helper()
	chain, _ := issueFor(t, host, n.ID)
	n.Certificate = leafCertificate(chain)
	return n
}

// nodeTLS is the TLS state of a request whose client presented a certificate
// for nodeID from host's CA.
func nodeTLS(t *testing.T, host *Manager, nodeID string) *tls.ConnectionState {
	t.Helper()
	chain, _ := issueFor(t, host, nodeID)
	return &tls.ConnectionState{PeerCertificates: parseChain(t, chain)}
}

// hostTLS is the TLS state of a request presenting m's own node certificate,
// as m's own CLI does.
func hostTLS(t *testing.T, m *Manager) *tls.ConnectionState {
	t.Helper()
	m.mu.RLock()
	chain := m.cluster.NodeCertificate
	m.mu.RUnlock()
	return &tls.ConnectionState{PeerCertificates: parseChain(t, chain)}
}

// testNodeID returns a node ID of the form generateNodeID gives.
func testNodeID(t *testing.T) string {
	t.Helper()
	id, err := generateNodeID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// addMember adds a healthy member record to m and returns it.
func addMember(m *Manager, id, addr string, port int) *Node {
	n := &Node{ID: id, Name: id, Address: addr, Port: port, Status: NodeStatusHealthy}
	m.mu.Lock()
	m.cluster.Nodes[id] = n
	m.mu.Unlock()
	return n
}

// fromPeer marks req, sent straight to a handler, as authenticated as nodeID
// (what withMemberAuth does for a request with that node's certificate).
func fromPeer(req *http.Request, nodeID string) *http.Request {
	return withPeerNode(req, nodeID)
}

// serveTLS serves m's cluster API over TLS with m's node certificate, asking
// clients for theirs, as Start does.
func serveTLS(t *testing.T, m *Manager) *httptest.Server {
	t.Helper()
	m.mu.RLock()
	cert, err := nodeCertificate(m.cluster.ID, m.cluster.LocalNode.ID, m.cluster.NodeCertificate, m.cluster.NodeKey)
	m.mu.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(m.apiHandler())
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// servePeerTLS serves handler over TLS as a node of host's cluster (a
// certificate from host's CA for a new node ID).
func servePeerTLS(t *testing.T, host *Manager, handler http.Handler) *httptest.Server {
	t.Helper()
	return servePeerAs(t, host, testNodeID(t), handler)
}

// servePeerAs serves handler over TLS as node nodeID of host's cluster, for a
// fake peer that members accept as that node.
func servePeerAs(t *testing.T, host *Manager, nodeID string, handler http.Handler) *httptest.Server {
	t.Helper()
	chain, key := issueFor(t, host, nodeID)
	cert, err := tls.X509KeyPair([]byte(chain), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// urlHostPort splits a test server's URL into host and port.
func urlHostPort(t *testing.T, u string) (string, int) {
	t.Helper()
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}
