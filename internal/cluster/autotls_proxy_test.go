package cluster

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// Cluster peer TLS uses an explicitly verified direct connection. An ambient
// web proxy must not divert it to CONNECT, where net/http bypasses the custom
// DialTLSContext responsible for cluster and node identity verification.
func TestClusterPeerClientIgnoresAmbientProxyAndPreservesVerification(t *testing.T) {
	m, cluster, base := startTLSNode(t, "proxy-regression", "local-test-password")
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHits.Add(1)
		http.Error(w, "owned test proxy must not receive cluster traffic", http.StatusBadGateway)
	}))
	t.Cleanup(proxy.Close)
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	// A forced default proxy avoids ProxyFromEnvironment's process-wide cache
	// and loopback exception while exercising exactly what Clone would inherit.
	original := http.DefaultTransport
	defaultWithProxy := original.(*http.Transport).Clone()
	defaultWithProxy.Proxy = http.ProxyURL(proxyURL)
	http.DefaultTransport = defaultWithProxy
	t.Cleanup(func() {
		http.DefaultTransport = original
		defaultWithProxy.CloseIdleConnections()
	})
	m.mu.RLock()
	own, err := nodeCertificate(cluster.ID, cluster.LocalNode.ID, cluster.NodeCertificate, cluster.NodeKey)
	m.mu.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	request := func(clusterID string, expected func(string) error) (int, error) {
		client := clusterPeerClient(3*time.Second, clusterID, nil, false, &own, expected)
		t.Cleanup(client.CloseIdleConnections)
		req, err := http.NewRequest(http.MethodGet, base+"/api/v1/cluster/status", nil)
		if err != nil {
			return 0, err
		}
		setPeerAuth(req, "local-test-password", cluster.MemberKey)
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		return resp.StatusCode, nil
	}
	var verifiedNodes atomic.Int32
	if code, err := request(cluster.ID, func(id string) error {
		verifiedNodes.Add(1)
		if id != cluster.LocalNode.ID {
			return errors.New("unexpected node")
		}
		return nil
	}); err != nil || code != http.StatusOK {
		t.Fatalf("direct authenticated cluster request: code=%d error=%v", code, err)
	}
	if verifiedNodes.Load() != 1 {
		t.Fatal("successful request bypassed expected-node verification")
	}
	_, otherCluster, err := newClusterCA()
	if err != nil {
		t.Fatal(err)
	}
	if code, err := request(otherCluster, nil); err == nil {
		t.Fatalf("wrong cluster was trusted: status=%d", code)
	}
	expectedFailure := errors.New("requested node does not match")
	if code, err := request(cluster.ID, func(string) error { return expectedFailure }); !errors.Is(err, expectedFailure) {
		t.Fatalf("wrong-node verifier was not enforced: status=%d error=%v", code, err)
	}
	if proxyHits.Load() != 0 {
		t.Fatalf("cluster requests reached the web proxy %d times", proxyHits.Load())
	}
}
