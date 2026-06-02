package cluster

import (
	"net"
	"net/http"
	"testing"
	"time"
)

// FuzzJoinClientResponse fuzzes the CLIENT side of joining a cluster: a node
// calls JoinCluster against a seed, and the seed (here, attacker-controlled)
// returns an arbitrary body. The joining node parses JoinResponse and merges
// the seed's node list, so a hostile or MITM'd seed must never be able to panic
// the joiner or corrupt its membership table - it may only fail the join.
func FuzzJoinClientResponse(f *testing.F) {
	seeds := []string{
		`{"success":true,"node_id":"n1","cluster_name":"c","nodes":[null]}`,
		`{"success":true,"nodes":[{"id":"","address":"","port":0}]}`,
		`{"success":true,"node_id":"x","nodes":[{"id":"a","address":"1.2.3.4","port":7946}]}`,
		`{"success":false,"error":"nope"}`,
		`{"success":true,"config":null,"nodes":[]}`,
		`{"success":true,"config":{"gossip_interval_ms":-1,"heartbeat_timeout_ms":0}}`,
		`not json`, `{}`, `[]`, `null`,
		`{"success":true,"nodes":[{"id":"a","address":"1.2.3.4","port":99999}]}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, body string) {
		// A seed server that always returns the fuzzed body with 200.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skip()
		}
		defer ln.Close()
		port := ln.Addr().(*net.TCPAddr).Port
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		})}
		go srv.Serve(ln)
		defer srv.Close()

		m := NewManager(t.TempDir())
		// Keep a fuzzed "pending" response from making the joiner poll for the
		// full production 5 minutes.
		m.joinPollInterval = time.Millisecond
		m.joinPollTimeout = 30 * time.Millisecond
		local := &Node{Name: "joiner", Address: "127.0.0.1", Port: 7000}
		seedAddr := "http://127.0.0.1:" + itoa(port)

		// Must not panic regardless of what the seed returns. On success, the
		// resulting membership must contain no invalid nodes.
		cl, err := m.attemptJoin(seedAddr, "cl_whatever", "password123", local)
		if err == nil && cl != nil {
			for id, n := range cl.Nodes {
				if n == nil {
					t.Fatalf("join admitted a nil node under id %q", id)
				}
				if id == local.ID {
					continue
				}
				if !validPeerNode(n) {
					t.Fatalf("join admitted invalid node: id=%q addr=%q port=%d", n.ID, n.Address, n.Port)
				}
			}
		}
	})
}
