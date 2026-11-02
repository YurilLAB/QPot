package cluster

import (
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
// cannot impersonate a node to harvest the X-Cluster-Password header. (Anyone
// who has the password can already join, so it confers nothing extra.)

const autoTLSInfo = "qpot-cluster-ca-v1"

// deriveClusterCA returns the deterministic cluster CA key and certificate.
func deriveClusterCA(clusterID, password string) (ed25519.PrivateKey, *x509.Certificate, error) {
	if clusterID == "" || password == "" {
		return nil, nil, errors.New("cluster TLS: cluster id and password are required")
	}
	seed, err := hkdf.Key(sha256.New, []byte(password), []byte(clusterID), autoTLSInfo, ed25519.SeedSize)
	if err != nil {
		return nil, nil, err
	}
	key := ed25519.NewKeyFromSeed(seed)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "QPot cluster CA " + clusterID},
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
// (automatic TLS) or, for a peer serving an operator certificate, against
// caPool (nil = system roots) with the normal hostname check.
func clusterTLSClientConfig(clusterID, password string, caPool *x509.CertPool) *tls.Config {
	var derived *x509.CertPool
	if _, ca, err := deriveClusterCA(clusterID, password); err == nil {
		derived = x509.NewCertPool()
		derived.AddCert(ca)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
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
			if _, err := certs[0].Verify(x509.VerifyOptions{Roots: caPool, Intermediates: inter, DNSName: cs.ServerName}); err != nil {
				return fmt.Errorf("cluster TLS: peer certificate not trusted: %w", err)
			}
			return nil
		},
	}
}

// clusterHTTPClient returns an HTTP client that trusts cluster peers as
// described for clusterTLSClientConfig.
func clusterHTTPClient(timeout time.Duration, clusterID, password string, caPool *x509.CertPool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = clusterTLSClientConfig(clusterID, password, caPool)
	return &http.Client{Timeout: timeout, Transport: transport}
}
