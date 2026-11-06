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
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"
)

// Cluster TLS.
//
// Each cluster has a certificate authority of its own: a random Ed25519 key
// made by `cluster init` (Cluster.CAKey), which a node receives when it is
// admitted. The cluster ID is derived from the CA's public key, so whoever
// knows the ID - a joiner as much as a member - checks that a node presents a
// certificate from that CA, and no node serves anything derived from the
// password: nothing to test password guesses against offline. Someone who
// knows the password but not the CA key can neither pass as a node nor
// collect the password, or the member key a joiner is given, on the way.

// errOldClusterFormat stops a cluster created before clusters had their own
// CA: its TLS rested on the password, and it cannot be moved over in place.
var errOldClusterFormat = errors.New("this cluster was created by an older QPot, whose cluster TLS is " +
	"derived from the password: re-create it ('qpot cluster leave' on every node, then " +
	"'qpot cluster init' and 'qpot cluster join')")

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

// clusterCA rebuilds the CA key and certificate from Cluster.CAKey. Ed25519
// signing is deterministic, so every node builds the same certificate.
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

// newNodeCertificate issues a node certificate (a fresh key, kept in memory)
// signed by the cluster CA. The CA certificate goes in the chain, so a peer
// can match its public key with the cluster ID.
func newNodeCertificate(caKey, nodeID string) (tls.Certificate, error) {
	signer, ca, err := clusterCA(caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "qpot-node " + nodeID},
		DNSNames:     []string{"qpot-cluster-node"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, signer)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}, nil
}

// verifyClusterPeer checks that certs (a peer's chain) end in a certificate
// signed by the CA whose public key gives clusterID.
func verifyClusterPeer(clusterID string, certs []*x509.Certificate) error {
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
		if _, err := certs[0].Verify(x509.VerifyOptions{Roots: roots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
			return nil
		}
	}
	return fmt.Errorf("cluster TLS: the peer's certificate is not from the CA of cluster %s", clusterID)
}

// clusterTLSClientConfig verifies a peer either by the cluster CA (automatic
// TLS: the CA is pinned by clusterID) or, for a peer serving an operator
// certificate, against caPool (nil = system roots) with the normal hostname
// check against dialHost - the host (name or IP) actually dialled. dialHost
// must be passed explicitly: for an IP-literal peer (seeds and gossip peers
// usually are) Go leaves ConnectionState.ServerName empty, and verifying
// against "" skips the name check entirely, so any CA-signed certificate for
// any name would pass.
func clusterTLSClientConfig(clusterID string, caPool *x509.CertPool, dialHost string) *tls.Config {
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
			if verifyClusterPeer(clusterID, certs) == nil {
				return nil
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
			if _, err := certs[0].Verify(x509.VerifyOptions{Roots: caPool, Intermediates: inter, DNSName: name}); err != nil {
				return fmt.Errorf("cluster TLS: peer certificate not trusted: %w", err)
			}
			return nil
		},
	}
}

// clusterHTTPClient returns an HTTP client that trusts cluster peers as
// described for clusterTLSClientConfig.
func clusterHTTPClient(timeout time.Duration, clusterID string, caPool *x509.CertPool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Dial TLS ourselves so each connection verifies against the host it was
	// actually opened to (see clusterTLSClientConfig).
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second},
			Config: clusterTLSClientConfig(clusterID, caPool, host)}
		return d.DialContext(ctx, network, addr)
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}
