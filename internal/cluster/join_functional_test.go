package cluster

import (
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestTwoNodeJoinOverHTTP stands up a real cluster API server for the seed node
// and drives a second node through the actual JoinCluster -> attemptJoin ->
// handleJoinHTTP path over the loopback network, exercising password auth,
// cluster-ID validation, and node registration end to end.
func TestTwoNodeJoinOverHTTP(t *testing.T) {
	const password = "correct-horse-battery"

	// Seed node: init a cluster and start its API server on a free port.
	seed := NewManager(t.TempDir())
	cl, err := seed.InitCluster("prod", password, DefaultClusterConfig())
	if err != nil {
		t.Fatalf("InitCluster: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/cluster/join", seed.handleJoinHTTP)
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()
	waitListening(t, port)

	seedAddr := "http://127.0.0.1:" + itoa(port)
	localNode := &Node{Name: "node-2", Address: "127.0.0.1", Port: 7947}

	// Wrong password must be rejected.
	if _, err := newJoiner(t).JoinCluster(cl.ID, "wrong-password-xxxx", localNode, []string{seedAddr}); err == nil {
		t.Error("join with wrong password succeeded; want failure")
	}

	// Wrong cluster ID must be rejected.
	if _, err := newJoiner(t).JoinCluster("cl_does_not_exist", password, localNode, []string{seedAddr}); err == nil {
		t.Error("join with wrong cluster ID succeeded; want failure")
	}

	// Correct credentials must succeed and register the node on the seed.
	joiner := newJoiner(t)
	joined, err := joiner.JoinCluster(cl.ID, password, localNode, []string{seedAddr})
	if err != nil {
		t.Fatalf("valid join failed: %v", err)
	}
	if joined.ID != cl.ID {
		t.Errorf("joined cluster ID = %q, want %q", joined.ID, cl.ID)
	}

	seed.mu.Lock()
	n := len(seed.cluster.Nodes)
	seed.mu.Unlock()
	if n != 2 { // local seed node + the joiner
		t.Errorf("seed cluster has %d nodes after join, want 2", n)
	}
}

func newJoiner(t *testing.T) *Manager { t.Helper(); return NewManager(t.TempDir()) }

func waitListening(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+itoa(port), 100*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server on port %d never came up", port)
}

func itoa(i int) string {
	var b strings.Builder
	if i == 0 {
		return "0"
	}
	var digits []byte
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	b.Write(digits)
	return b.String()
}
