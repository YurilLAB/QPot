package cluster

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Passwords accepted at initialization must remain usable after a restart.
// bcrypt's limit is bytes, not Unicode code points.
func TestInitClusterPasswordHashBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password string
		valid    bool
	}{
		{"ascii-72-bytes", strings.Repeat("a", 72), true},
		{"ascii-73-bytes", strings.Repeat("a", 73), false},
		{"unicode-72-bytes", strings.Repeat("\u00e9", 36), true},
		{"unicode-74-bytes", strings.Repeat("\u00e9", 37), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			m := NewManager(dir)
			c, err := m.InitCluster("test", tc.password, DefaultClusterConfig())
			if !tc.valid {
				if err == nil || c != nil {
					t.Errorf("accepted a %d-byte password that cannot be bcrypt-hashed", len(tc.password))
				}
				if m.GetCluster() != nil {
					t.Error("rejected password changed in-memory cluster state")
				}
				if _, statErr := os.Stat(filepath.Join(dir, "cluster.json")); !os.IsNotExist(statErr) {
					t.Errorf("rejected password persisted cluster state: %v", statErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			reloaded := NewManager(dir)
			if _, err := reloaded.LoadCluster(); err != nil {
				t.Fatal(err)
			}
			if err := reloaded.UnlockPassword(tc.password); err != nil {
				t.Fatalf("accepted password failed after restart: %v", err)
			}
		})
	}
}

func TestJoinClusterRejectsUnhashablePasswordBeforeContactingSeed(t *testing.T) {
	var requests atomic.Int64
	seed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"node_id":"qn_joined","cluster_name":"test"}`))
	}))
	defer seed.Close()
	for _, password := range []string{strings.Repeat("a", 73), strings.Repeat("\u00e9", 37)} {
		dir := t.TempDir()
		m := NewManager(dir)
		local := &Node{ID: "qn_original", Name: "sensor", Address: "192.0.2.10", Port: 7946}
		c, err := m.JoinCluster("qc_test", password, local, []string{seed.URL})
		if err == nil || c != nil {
			t.Errorf("joined with a %d-byte password that cannot be bcrypt-hashed", len(password))
		}
		if m.GetCluster() != nil || local.ID != "qn_original" {
			t.Error("rejected password changed local membership state")
		}
		if _, statErr := os.Stat(filepath.Join(dir, "cluster.json")); !os.IsNotExist(statErr) {
			t.Errorf("rejected password persisted cluster state: %v", statErr)
		}
	}
	if got := requests.Load(); got != 0 {
		t.Errorf("sent %d join requests before validating the password", got)
	}
}

func TestSanitizeClusterConfigNil(t *testing.T) {
	c := sanitizeClusterConfig(nil)
	if c == nil || c.GossipInterval <= 0 || c.SyncInterval <= 0 || c.SuspicionMult < 1 {
		t.Fatalf("nil config not defaulted to a sane config: %+v", c)
	}
}

func TestSanitizeClusterConfigClampsHostileValues(t *testing.T) {
	bad := &ClusterConfig{
		GossipInterval: 0,                // would panic time.NewTicker
		SyncInterval:   -5 * time.Second, // negative
		SuspicionMult:  1 << 30,          // overflow driver for the failure deadline
		ProbeInterval:  0,
		ProbeTimeout:   0,
		RetransmitMult: -1,
	}
	c := sanitizeClusterConfig(bad)

	if c.GossipInterval <= 0 || c.GossipInterval > maxGossipInterval {
		t.Errorf("GossipInterval not clamped: %v", c.GossipInterval)
	}
	if c.SyncInterval <= 0 {
		t.Errorf("SyncInterval not clamped: %v", c.SyncInterval)
	}
	if c.SuspicionMult < minSuspicionMult || c.SuspicionMult > maxSuspicionMult {
		t.Errorf("SuspicionMult not clamped: %d", c.SuspicionMult)
	}

	// The failure-detection deadline computation (gossip()) must not overflow
	// to a future/negative time with the clamped values.
	deadline := time.Now().Add(-3 * c.GossipInterval * time.Duration(c.SuspicionMult*10))
	if !deadline.Before(time.Now()) {
		t.Errorf("failure deadline is not in the past (overflow): %v", deadline)
	}
}

// TestClusterJoinBodyLimit ensures an oversized join body is rejected rather
// than read entirely into memory (DoS guard on the unauthenticated endpoint).
func TestClusterJoinBodyLimit(t *testing.T) {
	m := &Manager{}
	huge := strings.NewReader(strings.Repeat("A", maxClusterBodyBytes+1024))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/join", huge)
	rec := httptest.NewRecorder()

	m.handleJoinHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Errorf("oversized join body was accepted (status 200); MaxBytesReader not enforced")
	}
}

func TestValidPeerNode(t *testing.T) {
	cases := []struct {
		n    *Node
		want bool
	}{
		{nil, false},
		{&Node{ID: "", Address: "10.0.0.1", Port: 7946}, false},
		{&Node{ID: "qn_x", Address: "", Port: 7946}, false},
		{&Node{ID: "qn_x", Address: "10.0.0.1", Port: 0}, false},
		{&Node{ID: "qn_x", Address: "10.0.0.1", Port: 70000}, false},
		{&Node{ID: "qn_x", Address: "10.0.0.1", Port: -1}, false},
		{&Node{ID: "qn_x", Address: "10.0.0.1", Port: 7946}, true},
		{&Node{ID: "qn_x", Address: "host.example", Port: 443}, true},
	}
	for i, c := range cases {
		if got := validPeerNode(c.n); got != c.want {
			t.Errorf("case %d: validPeerNode = %v, want %v", i, got, c.want)
		}
	}
}
