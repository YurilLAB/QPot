package cluster

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUpgradedAuthorityReenrollsMemberOverTLS(t *testing.T) {
	authority, legacy, _ := testLegacyCluster(t)
	legacy.Config.RequireApproval = true
	if err := authority.saveCluster(); err != nil {
		t.Fatal(err)
	}
	upgraded, _, err := authority.UpgradeCluster()
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { authority.Stop() })
	address := net.JoinHostPort("127.0.0.1", fmt.Sprint(upgraded.Config.BindPort))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	memberPort := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	member := NewManager(t.TempDir())
	markerPath := filepath.Join(member.dataPath, "existing-instance.events")
	marker := []byte("existing sensor data")
	if err := os.WriteFile(markerPath, marker, 0600); err != nil {
		t.Fatal(err)
	}
	member.joinPollInterval, member.joinPollTimeout = 20*time.Millisecond, 5*time.Second
	type result struct {
		cluster *Cluster
		err     error
	}
	done := make(chan result, 1)
	go func() {
		c, err := member.JoinCluster(upgraded.ID, "password123", &Node{
			Name: "existing-sensor", Address: "127.0.0.1", Port: memberPort, InstanceName: "existing-instance",
		}, []string{address})
		done <- result{c, err}
	}()
	deadline := time.Now().Add(4 * time.Second)
	var requestID string
	for time.Now().Before(deadline) {
		if pending := authority.ListPendingJoins(); len(pending) == 1 {
			requestID = pending[0].RequestID
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if requestID == "" {
		t.Fatal("upgraded authority did not receive TLS enrollment request")
	}
	if len(authority.GetNodes()) != 1 {
		t.Fatal("upgrade bypassed the saved approval policy")
	}
	if _, err := authority.ApproveJoin(requestID); err != nil {
		t.Fatal(err)
	}
	var joined *Cluster
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		joined = r.cluster
	case <-time.After(6 * time.Second):
		t.Fatal("approved TLS enrollment did not complete")
	}
	if joined == nil || joined.CAKey != "" || joined.MemberKey != upgraded.MemberKey || joined.NodeKey == upgraded.NodeKey || joined.LocalNode.InstanceName != "existing-instance" {
		t.Fatal("member enrollment lost local identity or shared private signing material")
	}
	if got, err := os.ReadFile(markerPath); err != nil || !bytes.Equal(got, marker) {
		t.Fatal("re-enrollment changed existing sensor data")
	}
	joined.Config.BindAddr = "127.0.0.1"
	if err := member.saveCluster(); err != nil {
		t.Fatal(err)
	}
	if err := member.SaveSecret(); err != nil {
		t.Fatal(err)
	}
	restarted := NewManager(member.dataPath)
	loaded, err := restarted.LoadCluster()
	if err != nil || loaded == nil || loaded.NodeKey != joined.NodeKey || loaded.NodeCertificate != joined.NodeCertificate {
		t.Fatal("re-enrolled identity did not survive restart")
	}
	if err := restarted.UnlockFromSecret(); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restarted.Stop() })
	for _, check := range []struct {
		from *Manager
		port int
		key  string
		want int
	}{
		{restarted, upgraded.Config.BindPort, upgraded.MemberKey, http.StatusOK},
		{authority, memberPort, upgraded.MemberKey, http.StatusOK},
		{restarted, upgraded.Config.BindPort, legacy.MemberKey, http.StatusUnauthorized},
	} {
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/api/v1/cluster/nodes", check.port), nil)
		if err != nil {
			t.Fatal(err)
		}
		setPeerAuth(req, "password123", check.key)
		client := check.from.HTTPClient(2 * time.Second)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		client.CloseIdleConnections()
		if resp.StatusCode != check.want {
			t.Fatalf("member API status %d, want %d", resp.StatusCode, check.want)
		}
	}
	oldTrustClient := clusterHTTPClient(2*time.Second, legacy.ID, nil, false)
	defer oldTrustClient.CloseIdleConnections()
	if resp, err := oldTrustClient.Get("https://" + address + "/api/v1/cluster/nodes"); err == nil {
		resp.Body.Close()
		t.Fatal("old cluster trust accepted upgraded authority over TLS")
	}
}
