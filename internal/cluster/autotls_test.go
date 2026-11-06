package cluster

import (
	"bytes"
	"crypto/tls"
	"net"
	"net/http"
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
		code, err = get(clusterHTTPClient(3*time.Second, c.ID, "password123", nil))
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil || code != http.StatusOK {
		t.Fatalf("member client: code=%d err=%v", code, err)
	}
	if _, err := get(clusterHTTPClient(3*time.Second, c.ID, "wrong-password", nil)); err == nil {
		t.Fatal("client with the wrong cluster secret trusted the node")
	}
	plain := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	if _, err := get(plain); err == nil {
		t.Fatal("system-roots client trusted the cluster-CA certificate")
	}
}
