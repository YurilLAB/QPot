package cluster

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/hostsetup"
)

// Cluster TLS.
//
// Each cluster has a certificate authority of its own: a random Ed25519 key
// made by `cluster init` (Cluster.CAKey), kept only by that enrollment host.
// Joiners make their own private keys and receive signed leaf certificates,
// never the CA key. The cluster ID is derived from the CA's public key, so whoever
// knows the ID - a joiner as much as a member - checks that a node presents a
// certificate from that CA, and no node serves anything derived from the
// password: nothing to test password guesses against offline. Someone who
// knows the password but not the CA key can neither pass as a node nor
// collect the password, or the member key a joiner is given, on the way.

// Old clusters either derived TLS from the password or distributed the CA
// key. Removing local copies cannot revoke those keys, so use a new CA/ID.
var errOldClusterFormat = hostsetup.E("QP-CLUSTER-001").WithWhy("this cluster uses legacy shared signing credentials: " +
	"stop the old control planes, update all nodes, run 'qpot cluster upgrade' on the enrollment host, " +
	"then leave and rejoin the other nodes using the new cluster ID")

const maxNodeCSRBytes = 4096

// nodeCertLifetime is how long a node certificate is valid. A node that left
// or was removed is remembered for longer (leftRetention), so no certificate
// it kept outlives the record that refuses it.
const nodeCertLifetime = 365 * 24 * time.Hour

func checkClusterVersion(version int) error {
	if version < ProtocolVersion {
		return errOldClusterFormat
	}
	if version != ProtocolVersion {
		return hostsetup.E("QP-CLUSTER-002").WithWhy("Unsupported cluster protocol version %d; update QPot before starting this cluster.", version)
	}
	return nil
}

func identityFailure(err error) error {
	var coded *hostsetup.Error
	if errors.As(err, &coded) {
		return err
	}
	return hostsetup.E("QP-CLUSTER-005").WithWhy("The local cluster signing identity could not be validated or renewed; restore trusted state or re-enroll the node.").Wrap(err)
}

// clusterIDFor returns the cluster ID of a CA public key: ClusterIDPrefix and
// the first ClusterIDLength base32 characters (120 bits) of its SHA-256.
func clusterIDFor(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	return ClusterIDPrefix + strings.ToLower(enc[:ClusterIDLength])
}

// newClusterCA makes a cluster CA key (Cluster.CAKey) and the cluster ID it
// gives.
func newClusterCA() (caKey, clusterID string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv.Seed()), clusterIDFor(pub), nil
}

// clusterCA rebuilds the enrollment authority's key and certificate.
func clusterCA(caKey string) (ed25519.PrivateKey, *x509.Certificate, error) {
	seed, err := base64.StdEncoding.DecodeString(caKey)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, nil, errors.New("cluster TLS: malformed cluster CA key")
	}
	key := ed25519.NewKeyFromSeed(seed)
	id := clusterIDFor(key.Public().(ed25519.PublicKey))
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "QPot cluster CA " + id},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2120, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	ca, err := x509.ParseCertificate(der)
	return key, ca, err
}

// checkClusterCA reports whether caKey is the CA of clusterID.
func checkClusterCA(clusterID, caKey string) error {
	if caKey == "" {
		return errOldClusterFormat
	}
	key, _, err := clusterCA(caKey)
	if err != nil {
		return err
	}
	if clusterIDFor(key.Public().(ed25519.PublicKey)) != clusterID {
		return fmt.Errorf("cluster TLS: the CA key is not that of cluster %s", clusterID)
	}
	return nil
}

// newNodeRequest makes a private key and proof-of-possession CSR locally. Only
// the CSR leaves the node; the key is persisted in its private cluster state.
func newNodeRequest() (keyPEM, csrPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	csrPEM, err = nodeRequestForKey(keyPEM)
	return keyPEM, csrPEM, err
}

func nodeRequestForKey(keyPEM string) (string, error) {
	block, rest := pem.Decode([]byte(keyPEM))
	if block == nil || block.Type != "EC PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return "", errors.New("cluster TLS: malformed node private key")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil || key.Curve != elliptic.P256() {
		return "", errors.New("cluster TLS: node private key must use P-256")
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), nil
}

func parseNodeRequest(csrPEM string) (request *x509.CertificateRequest, resultErr error) {
	defer func() {
		if resultErr != nil {
			resultErr = hostsetup.E("QP-CLUSTER-003").WithWhy("The node certificate request is invalid; update the joining QPot and retry.").Wrap(resultErr)
		}
	}()
	if len(csrPEM) == 0 || len(csrPEM) > maxNodeCSRBytes {
		return nil, errors.New("cluster TLS: a node certificate request is required (update the joining QPot)")
	}
	block, rest := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("cluster TLS: malformed node certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cluster TLS: parse node certificate request: %w", err)
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("cluster TLS: node certificate request must use P-256")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("cluster TLS: invalid node certificate request signature: %w", err)
	}
	return csr, nil
}

// issueNodeCertificate signs only the CSR's public key. Identity, lifetime,
// usages and constraints are fixed here, never copied from requested extensions.
func issueNodeCertificate(caKey, nodeID, csrPEM string) (string, error) {
	csr, err := parseNodeRequest(csrPEM)
	if err != nil {
		return "", err
	}
	signer, ca, err := clusterCA(caKey)
	if err != nil {
		return "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "qpot-node " + nodeID},
		DNSNames:              []string{"qpot-cluster-node"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(nodeCertLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, csr.PublicKey, signer)
	if err != nil {
		return "", err
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})...)
	return string(chain), nil
}

// nodeCertificate checks the persisted or newly enrolled identity before use.
// In particular, a seed cannot substitute a certificate for a different key,
// node or cluster, or grant a joining member certificate-signing powers.
func nodeCertificate(clusterID, nodeID, certPEM, keyPEM string) (tls.Certificate, error) {
	return nodeCertificateAt(clusterID, nodeID, certPEM, keyPEM, time.Now())
}

func nodeCertificateAt(clusterID, nodeID, certPEM, keyPEM string, now time.Time) (certificate tls.Certificate, resultErr error) {
	defer func() {
		if resultErr != nil && !errors.Is(resultErr, errOldClusterFormat) {
			resultErr = hostsetup.E("QP-CLUSTER-005").WithWhy("The node identity is invalid or expired; re-enroll through the enrollment host.").Wrap(resultErr)
		}
	}()
	if certPEM == "" || keyPEM == "" {
		return tls.Certificate{}, errOldClusterFormat
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cluster TLS: invalid node identity: %w", err)
	}
	chain := make([]*x509.Certificate, 0, len(cert.Certificate))
	for _, der := range cert.Certificate {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return tls.Certificate{}, err
		}
		chain = append(chain, c)
	}
	if len(chain) != 2 || nodeID == "" || chain[0].Subject.CommonName != "qpot-node "+nodeID ||
		chain[0].IsCA || chain[0].KeyUsage&x509.KeyUsageCertSign != 0 {
		return tls.Certificate{}, errors.New("cluster TLS: certificate is not this node's leaf identity")
	}
	if err := verifyClusterPeerAt(clusterID, chain, now); err != nil {
		return tls.Certificate{}, fmt.Errorf("cluster TLS: invalid or expired node certificate; re-enroll this node: %w", err)
	}
	return cert, nil
}

// renewAuthorityCertificateLocked renews only this enrollment host's own
// identity, near expiry or after downtime. Validate its existing key, assigned
// identity and chain at issuance time before using the authority key. Ordinary
// members have no signing key and must re-enroll. Caller holds m.mu.
func (m *Manager) renewAuthorityCertificateLocked() error {
	c := m.cluster
	if c.CAKey == "" || c.NodeCertificate == "" || c.NodeKey == "" || c.LocalNode == nil {
		return nil
	}
	if err := checkClusterCA(c.ID, c.CAKey); err != nil {
		return err
	}
	block, _ := pem.Decode([]byte(c.NodeCertificate))
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("cluster TLS: malformed enrollment host certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if time.Until(leaf.NotAfter) > 30*24*time.Hour {
		return nil
	}
	if _, err := nodeCertificateAt(c.ID, c.LocalNode.ID, c.NodeCertificate, c.NodeKey, leaf.NotBefore); err != nil {
		return err
	}
	csr, err := nodeRequestForKey(c.NodeKey)
	if err != nil {
		return err
	}
	certificate, err := issueNodeCertificate(c.CAKey, c.LocalNode.ID, csr)
	if err != nil {
		return err
	}
	previous := c.NodeCertificate
	c.NodeCertificate = certificate
	if err := m.saveClusterLocked(); err != nil {
		c.NodeCertificate = previous
		return fmt.Errorf("cluster TLS: save renewed enrollment host certificate: %w", err)
	}
	return nil
}

// verifyClusterPeer checks that certs (a peer's chain) end in a certificate
// signed by the CA whose public key gives clusterID.
func verifyClusterPeer(clusterID string, certs []*x509.Certificate) error {
	return verifyClusterPeerAt(clusterID, certs, time.Now())
}

func verifyClusterPeerAt(clusterID string, certs []*x509.Certificate, now time.Time) error {
	return verifyClusterChain(clusterID, certs, now, x509.ExtKeyUsageServerAuth)
}

// verifyClusterChain checks that certs[0] is signed by the CA whose public key
// gives clusterID (one of certs[1:]) and may be used for usage.
func verifyClusterChain(clusterID string, certs []*x509.Certificate, now time.Time, usage x509.ExtKeyUsage) error {
	if len(certs) == 0 {
		return errors.New("cluster TLS: peer sent no certificate")
	}
	for _, c := range certs[1:] {
		pub, ok := c.PublicKey.(ed25519.PublicKey)
		if !ok || clusterIDFor(pub) != clusterID {
			continue
		}
		roots := x509.NewCertPool()
		roots.AddCert(c)
		if _, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{usage}}); err == nil {
			return nil
		}
	}
	return fmt.Errorf("cluster TLS: the peer's certificate is not from the CA of cluster %s", clusterID)
}

// verifyClusterClient returns the node ID a client certificate chain proves:
// a leaf from the CA of clusterID, for client use, naming one node. The TLS
// handshake has already checked that the client holds the leaf's key.
func verifyClusterClient(clusterID string, certs []*x509.Certificate, now time.Time) (string, error) {
	return verifyClusterNode(clusterID, certs, now, x509.ExtKeyUsageClientAuth)
}

// verifyClusterNode returns the node a chain from the CA of clusterID names,
// for usage.
func verifyClusterNode(clusterID string, certs []*x509.Certificate, now time.Time, usage x509.ExtKeyUsage) (string, error) {
	if err := verifyClusterChain(clusterID, certs, now, usage); err != nil {
		return "", err
	}
	id, ok := leafNodeID(certs[0])
	if !ok {
		return "", errors.New("cluster TLS: the peer's certificate names no node")
	}
	return id, nil
}

// leafNodeID returns the node ID a node certificate names.
func leafNodeID(leaf *x509.Certificate) (string, bool) {
	id, ok := strings.CutPrefix(leaf.Subject.CommonName, "qpot-node ")
	if !ok || leaf.IsCA || !validNodeID(id) {
		return "", false
	}
	return id, true
}

// validNodeID reports whether id has the form generateNodeID gives.
func validNodeID(id string) bool {
	rest, ok := strings.CutPrefix(id, NodeIDPrefix)
	if !ok || len(rest) != NodeIDLength {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if c := rest[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// systemRoots is the trust store an operator certificate is checked against
// when the cluster names no CA bundle (a variable so tests can stand one in).
var systemRoots = x509.SystemCertPool

// peerTLSClientConfig verifies a peer by the cluster CA (automatic TLS: the
// CA is pinned by clusterID) and, only when operatorCerts is set, also accepts
// a peer serving an operator certificate, verified against caPool (nil =
// system roots) with the normal hostname check against dialHost - the host
// (name or IP) actually dialled. dialHost must be passed explicitly: for an
// IP-literal peer (seeds and gossip peers usually are) Go leaves
// ConnectionState.ServerName empty, and verifying against "" skips the name
// check entirely, so any CA-signed certificate for any name would pass.
//
// Members of a cluster that names no operator certificate and no CA bundle
// pass operatorCerts=false: their peers all serve cluster-CA certificates,
// and accepting the system roots as well sent the password and member key to
// anyone holding a publicly trusted certificate for a member's address (an
// on-path attacker can get one for a name or an IP it intercepts).
//
// expect, when not nil, is handed the node ID a cluster-CA certificate names
// and refuses the connection by returning an error: a member contacting
// another checks that the node answering is the one it dialled, and still a
// member. A peer serving an operator certificate names no node and is
// checked by its host name alone.
func peerTLSClientConfig(clusterID string, caPool *x509.CertPool, dialHost string, operatorCerts bool, expect func(nodeID string) error) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Verification is done in VerifyConnection: the cluster-CA path skips
		// the hostname check on purpose (any certificate from the cluster CA
		// is a node, whatever address it was reached on).
		InsecureSkipVerify: true, // #nosec G402 -- replaced by VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			certs := cs.PeerCertificates
			if len(certs) == 0 {
				return errors.New("cluster TLS: peer sent no certificate")
			}
			if err := verifyClusterPeer(clusterID, certs); err == nil || !operatorCerts {
				if err != nil || expect == nil {
					return err
				}
				id, ok := leafNodeID(certs[0])
				if !ok {
					return errors.New("cluster TLS: the peer's certificate names no node")
				}
				return expect(id)
			}
			roots := caPool
			if roots == nil {
				var err error
				if roots, err = systemRoots(); err != nil {
					return fmt.Errorf("cluster TLS: system roots: %w", err)
				}
			}
			inter := x509.NewCertPool()
			for _, c := range certs[1:] {
				inter.AddCert(c)
			}
			name := dialHost
			if name == "" {
				name = cs.ServerName
			}
			if name == "" {
				return errors.New("cluster TLS: no peer name to verify the certificate against")
			}
			if _, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: name}); err != nil {
				return fmt.Errorf("cluster TLS: peer certificate not trusted: %w", err)
			}
			return nil
		},
	}
}

// clusterHTTPClient returns an HTTP client that trusts cluster peers as
// described for peerTLSClientConfig and presents no certificate of its own
// (a joiner, which has none yet).
func clusterHTTPClient(timeout time.Duration, clusterID string, caPool *x509.CertPool, operatorCerts bool) *http.Client {
	return clusterPeerClient(timeout, clusterID, caPool, operatorCerts, nil, nil)
}

// clusterPeerClient is clusterHTTPClient presenting node, this node's
// certificate, when a peer asks for one: peers serve a member's request only
// when it comes with the member's own certificate (see peerauth.go). expect,
// when not nil, checks the node the peer's certificate names (see
// peerTLSClientConfig).
func clusterPeerClient(timeout time.Duration, clusterID string, caPool *x509.CertPool, operatorCerts bool, node *tls.Certificate, expect func(nodeID string) error) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Cluster peers are reached directly. A web proxy's CONNECT path bypasses
	// DialTLSContext below, losing the cluster/node verification and client
	// certificate setup; ambient HTTP(S)_PROXY must not change that contract.
	transport.Proxy = nil
	// Dial TLS ourselves so each connection verifies against the host it was
	// actually opened to (see peerTLSClientConfig).
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		cfg := peerTLSClientConfig(clusterID, caPool, host, operatorCerts, expect)
		if node != nil {
			cfg.Certificates = []tls.Certificate{*node}
		}
		d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: cfg}
		return d.DialContext(ctx, network, addr)
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}
