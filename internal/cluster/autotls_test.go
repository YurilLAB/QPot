package cluster

import (
	"bytes"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestDeriveClusterCADeterministic(t *testing.T) {
	_, a, err := deriveClusterCA("qc_1", "password123")
	if err != nil {
		t.Fatal(err)
	}
	_, b, _ := deriveClusterCA("qc_1", "password123")
	if !bytes.Equal(a.Raw, b.Raw) {
		t.Fatal("two members derived different cluster CAs from the same secret")
	}
	_, c, _ := deriveClusterCA("qc_1", "other-password")
	_, d, _ := deriveClusterCA("qc_2", "password123")
	if bytes.Equal(a.Raw, c.Raw) || bytes.Equal(a.Raw, d.Raw) {
		t.Fatal("different secrets/clusters share a CA")
	}
	if _, _, err := deriveClusterCA("qc_1", ""); err == nil {
		t.Fatal("derived a CA from an empty password")
	}
}

// A node with encryption on and no certificate files serves the cluster-CA
// certificate; a client with the cluster secret trusts it, a client with a
// different secret (an impostor's view) and plain HTTP do not.
func TestAutoTLSServesAndVerifies(t *testing.T) {
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
	c, err := m.InitCluster("tls-test", "password123", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start with automatic TLS: %v", err)
	}
	defer m.Stop()

	url := "https://127.0.0.1:" + strconv.Itoa(port) + "/api/v1/cluster/status"
	get := func(client *http.Client) (int, error) {
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		setPeerAuth(req, "password123", c.MemberKey)
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	var code int
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, err = get(clusterHTTPClient(3*time.Second, c.ID, "password123", c.MemberKey, nil))
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil || code != http.StatusOK {
		t.Fatalf("member client: code=%d err=%v", code, err)
	}
	if _, err := get(clusterHTTPClient(3*time.Second, c.ID, "wrong-password", c.MemberKey, nil)); err == nil {
		t.Fatal("client with the wrong cluster secret trusted the node")
	}
	plain := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	if _, err := get(plain); err == nil {
		t.Fatal("system-roots client trusted the cluster-CA certificate")
	}
}

// TestMemberKeyNeverReachesPasswordOnlyImpostor: the password-derived CA can
// be derived by anyone with the password, admitted or not. A member's calls
// carry the member key, so a non-member on the path between members could
// serve a password-CA certificate and collect the key. Member calls now trust
// only the member CA (password and member key); joiners still reach a node.
func TestMemberKeyNeverReachesPasswordOnlyImpostor(t *testing.T) {
	const pw = "password123"
	m := NewManager(t.TempDir())
	c, err := m.InitCluster("impostor-test", pw, DefaultClusterConfig())
	if err != nil {
		t.Fatal(err)
	}
	if c.MemberKey == "" {
		t.Fatal("a new cluster has no member key")
	}
	cert, err := newNodeCertificate(c.ID, pw, "impostor")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan string, 4)
	impostor := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get(memberKeyHeader)
	}))
	impostor.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	impostor.StartTLS()
	defer impostor.Close()

	req, _ := http.NewRequest(http.MethodPost, impostor.URL+"/api/v1/cluster/gossip", nil)
	setPeerAuth(req, pw, c.MemberKey)
	if resp, err := m.peerHTTPClient(3 * time.Second).Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("a member trusted a node that only knows the password")
	}
	select {
	case key := <-seen:
		t.Fatalf("the impostor received a request (member key %q)", key)
	default:
	}

	// A joiner has no member key yet and still verifies a node by the password CA.
	join, _ := http.NewRequest(http.MethodGet, impostor.URL+"/api/v1/cluster/join/status", nil)
	resp, err := clusterHTTPClient(3*time.Second, c.ID, pw, "", nil).Do(join)
	if err != nil {
		t.Fatalf("a joiner could not reach a password-CA node: %v", err)
	}
	resp.Body.Close()
	if key := <-seen; key != "" {
		t.Fatalf("a joiner sent a member key: %q", key)
	}
}

// TestAutoTLSServesJoinersAndMembers: one node serves both: the member-CA
// certificate to members, the password-CA one to joiners.
func TestAutoTLSServesJoinersAndMembers(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	const pw = "password123"
	m := NewManager(t.TempDir())
	cfg := DefaultClusterConfig()
	cfg.BindAddr = "127.0.0.1"
	cfg.BindPort = port
	c, err := m.InitCluster("both-test", pw, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	base := "https://127.0.0.1:" + strconv.Itoa(port)
	do := func(client *http.Client, path string, memberKey string) (int, error) {
		req, _ := http.NewRequest(http.MethodGet, base+path, nil)
		setPeerAuth(req, pw, memberKey)
		var resp *http.Response
		var err error
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
			if resp, err = client.Do(req); err == nil || time.Now().After(deadline) {
				break
			}
		}
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	if code, err := do(m.peerHTTPClient(3*time.Second), "/api/v1/cluster/status", c.MemberKey); err != nil || code != http.StatusOK {
		t.Fatalf("member: code=%d err=%v", code, err)
	}
	if code, err := do(clusterHTTPClient(3*time.Second, c.ID, pw, "", nil), "/api/v1/cluster/join/status?request_id=x", ""); err != nil || code == 0 {
		t.Fatalf("joiner: code=%d err=%v", code, err)
	}
	if _, err := do(clusterHTTPClient(3*time.Second, c.ID, pw, "qk_not-the-member-key", nil), "/api/v1/cluster/status", "qk_not-the-member-key"); err == nil {
		t.Fatal("a client with a wrong member key trusted the node's member certificate")
	}
}
