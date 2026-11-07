package cluster

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"strings"
	"testing"
)

// Include a real version-2 CSR. Older join fuzz seeds are rejected at the
// protocol gate and do not exercise enrollment's proof-of-possession parser.
func FuzzNodeCertificateRequest(f *testing.F) {
	_, csr, err := newNodeRequest()
	if err != nil {
		f.Fatal(err)
	}
	for _, input := range []string{csr, "", "not a request", csr + csr, strings.Repeat("x", maxNodeCSRBytes+1)} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		request, err := parseNodeRequest(input)
		if err != nil {
			return
		}
		if request == nil || len(input) > maxNodeCSRBytes {
			t.Fatal("parser accepted absent or oversized CSR")
		}
		key, ok := request.PublicKey.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() || request.CheckSignature() != nil {
			t.Fatal("parser accepted an unsupported key or unproven private-key possession")
		}
	})
}
