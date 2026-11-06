package cluster

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"time"
)

// Automatic cluster TLS.
//
// With encryption enabled but no operator certificate configured, every member
// derives the SAME cluster CA key from the cluster password and cluster ID
// (HKDF-SHA256 -> Ed25519 seed), signs a fresh node certificate with it, and
// accepts only peers whose certificate chains to that CA. No CA file has to be
// distributed, a node joining over the network verifies the seed node from its
// very first connection, and an on-path attacker without the cluster password
// cannot impersonate a node to harvest the X-Cluster-Password header.
//
// The password does not make a node a member (the host approves joiners), so
// a member's own calls, which carry the member key, trust a second CA derived
// from the password AND the member key: only admitted nodes can sign for it.
// A member asks for it by the TLS server name memberServerName; a joiner, who
// has no member key yet, gets the password-CA certificate. Someone with the
// password alone, on the path between members, can then neither pass as a
// member to a member nor collect the member key from one.

const (
	autoTLSInfo       = "qpot-cluster-ca-v1"
	autoTLSMemberInfo = "qpot-cluster-member-ca-v1"
	memberServerName  = "qpot-cluster-member"
)

// deriveClusterCA returns the deterministic cluster CA key and certificate.
func deriveClusterCA(clusterID, password string) (ed25519.PrivateKey, *x509.Certificate, error) {
	if clusterID == "" || password == "" {
		return nil, nil, errors.New("cluster TLS: cluster id and password are required")
	}
	return deriveCA(clusterID, password, autoTLSInfo, "QPot cluster CA "+clusterID)
}

// deriveMemberCA returns the CA only admitted members can derive: from the
// password and the member key.
func deriveMemberCA(clusterID, password, memberKey string) (ed25519.PrivateKey, *x509.Certificate, error) {
	if clusterID == "" || password == "" || memberKey == "" {
		return nil, nil, errors.New("cluster TLS: cluster id, password and member key are required")
	}
	return deriveCA(clusterID, password+"\x00"+memberKey, autoTLSMemberInfo, "QPot cluster member CA "+clusterID)
}

// deriveCA derives a CA key from secret and builds its certificate.
func deriveCA(clusterID, secret, info, name string) (ed25519.PrivateKey, *x509.Certificate, error) {
	seed, err := hkdf.Key(sha256.New, []byte(secret), []byte(clusterID), info, ed25519.SeedSize)
	if err != nil {
		return nil, nil, err
	}
	key := ed25519.NewKeyFromSeed(seed)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2120, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	// Ed25519 signing is deterministic, so every member builds an identical CA.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	ca, err := x509.ParseCertificate(der)
	return key, ca, err
}

// newNodeCertificate issues a short-lived node certificate (fresh key) signed
// by the derived cluster CA. It lives in memory only.
func newNodeCertificate(clusterID, password, nodeID string) (tls.Certificate, error) {
	caKey, ca, err := deriveClusterCA(clusterID, password)
	if err != nil {
		return tls.Certificate{}, err
	}
	return issueNodeCertificate(caKey, ca, nodeID)
}

// newMemberCertificate issues a node certificate signed by the member CA.
func newMemberCertificate(clusterID, password, memberKey, nodeID string) (tls.Certificate, error) {
	caKey, ca, err := deriveMemberCA(clusterID, password, memberKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return issueNodeCertificate(caKey, ca, nodeID)
}

func issueNodeCertificate(caKey ed25519.PrivateKey, ca *x509.Certificate, nodeID string) (tls.Certificate, error) {
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
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// clusterTLSClientConfig verifies a peer either against the derived cluster CA
// (automatic TLS; the member CA when memberKey is set, asked for by its server
// name) or, for a peer serving an operator certificate, against
// caPool (nil = system roots) with the normal hostname check against
// dialHost - the host (name or IP) actually dialled. dialHost must be passed
// explicitly: for an IP-literal peer (seeds and gossip peers usually are) Go
// leaves ConnectionState.ServerName empty, and verifying against "" skips the
// name check entirely, so any CA-signed certificate for any name would pass.
func clusterTLSClientConfig(clusterID, password, memberKey string, caPool *x509.CertPool, dialHost string) *tls.Config {
	var derived *x509.CertPool
	_, ca, err := deriveClusterCA(clusterID, password)
	serverName := ""
	if memberKey != "" {
		// Never fall back to the password CA: anyone with the password can
		// sign for it, and this connection will carry the member key.
		_, ca, err = deriveMemberCA(clusterID, password, memberKey)
		serverName = memberServerName
	}
	if err == nil {
		derived = x509.NewCertPool()
		derived.AddCert(ca)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
		// Verification is done in VerifyConnection: the derived-CA path skips
		// the hostname check on purpose (any certificate signed by the cluster
		// CA is a member, whatever address it was reached on).
		InsecureSkipVerify: true, // #nosec G402 -- replaced by VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			certs := cs.PeerCertificates
			if len(certs) == 0 {
				return errors.New("cluster TLS: peer sent no certificate")
			}
			inter := x509.NewCertPool()
			for _, c := range certs[1:] {
				inter.AddCert(c)
			}
			if derived != nil {
				if _, err := certs[0].Verify(x509.VerifyOptions{Roots: derived, Intermediates: inter,
					KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
					return nil
				}
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
func clusterHTTPClient(timeout time.Duration, clusterID, password, memberKey string, caPool *x509.CertPool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Dial TLS ourselves so each connection verifies against the host it was
	// actually opened to (see clusterTLSClientConfig).
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second},
			Config: clusterTLSClientConfig(clusterID, password, memberKey, caPool, host)}
		return d.DialContext(ctx, network, addr)
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}
