package cluster

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

func peerAddr(t *testing.T, u string) (string, int) {
	h, p, _ := net.SplitHostPort(u[len("http://"):])
	pn, _ := strconv.Atoi(p)
	return h, pn
}

// gossip() must encode a snapshot, not live *Node records that
// UpdateNodeStats mutates concurrently (run with -race).
func TestGossipSnapshotNoRace(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)
	cfg := DefaultClusterConfig()
	cfg.EnableEncryption = false
	if _, err := m.InitCluster("c", "password123", cfg); err != nil {
		t.Fatal(err)
	}
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(GossipMessage{SenderID: "qn_peer"})
	}))
	defer peer.Close()
	h, p := peerAddr(t, peer.URL)
	m.mu.Lock()
	m.cluster.Nodes["qn_peer"] = &Node{ID: "qn_peer", Address: h, Port: p, Status: NodeStatusHealthy}
	m.mu.Unlock()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			m.UpdateNodeStats(NodeStats{TotalEvents: int64(i)})
		}
	}()
	for i := 0; i < 20; i++ {
		m.gossip()
	}
	close(stop)
	wg.Wait()
}

// The inbound gossip handler must honour maxClusterNodes like gossip() does.
func TestGossipHandlerEnforcesNodeCap(t *testing.T) {
	m := NewManager(t.TempDir())
	cfg := DefaultClusterConfig()
	cfg.EnableEncryption = false
	m.InitCluster("c", "password123", cfg)
	// Hand-written minimal JSON so each POST stays under the 1 MiB body cap.
	for batch := 0; batch < 3; batch++ {
		var buf bytes.Buffer
		buf.WriteString(`{"sender_id":"x","node_digest":[`)
		for i := 0; i < 2000; i++ {
			if i > 0 {
				buf.WriteByte(',')
			}
			fmt.Fprintf(&buf, `{"id":"n%d_%d","address":"a","port":1}`, batch, i)
		}
		buf.WriteString(`]}`)
		req := fromPeer(httptest.NewRequest(http.MethodPost, "/api/v1/cluster/gossip", &buf), "x")
		rec := httptest.NewRecorder()
		m.handleGossipHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("status %d", rec.Code)
		}
	}
	n := len(m.GetNodes())
	t.Logf("nodes after gossip POSTs: %d (cap %d)", n, maxClusterNodes)
	if n > maxClusterNodes {
		t.Errorf("member map exceeded maxClusterNodes")
	}
}

// sync() must replace a peer's last-hour total, not add it up every tick.
func TestSyncReplacesPeerTotal(t *testing.T) {
	m := NewManager(t.TempDir())
	cfg := DefaultClusterConfig()
	cfg.EnableEncryption = false
	m.InitCluster("c", "password123", cfg)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ThreatIntel{NodeID: "qn_peer", Timestamp: time.Now(),
			TopSourceIPs: []IPCount{{IP: "1.2.3.4", Count: 100}}})
	}))
	defer peer.Close()
	h, p := peerAddr(t, peer.URL)
	m.mu.Lock()
	m.cluster.Nodes["qn_peer"] = &Node{ID: "qn_peer", Address: h, Port: p, Status: NodeStatusHealthy}
	m.mu.Unlock()
	m.UpdateThreatIntel([]IPCount{{IP: "5.6.7.8", Count: 1}})
	for i := 0; i < 3; i++ {
		m.sync()
	}
	got := m.GetCluster().Nodes["qn_peer"].Stats.TotalEvents
	t.Logf("peer reports constant 100 last-hour hits; after 3 syncs TotalEvents=%d", got)
	if got != 100 {
		t.Errorf("TotalEvents accumulates snapshot counts: %d", got)
	}
}

// A cluster restored from disk has only the password hash: Start must refuse
// until UnlockPassword supplies the right password, and gossip must then
// authenticate with it.
func TestLoadedClusterNeedsPasswordUnlock(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)
	cfg := DefaultClusterConfig()
	cfg.EnableEncryption = false
	if _, err := m.InitCluster("c", "password123", cfg); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Get("X-Cluster-Password")
		mu.Unlock()
		json.NewEncoder(w).Encode(GossipMessage{})
	}))
	defer peer.Close()
	h, p := peerAddr(t, peer.URL)
	m.mu.Lock()
	m.cluster.Nodes["qn_peer"] = &Node{ID: "qn_peer", Address: h, Port: p, Status: NodeStatusHealthy}
	m.mu.Unlock()
	if err := m.saveCluster(); err != nil {
		t.Fatal(err)
	}

	m2 := NewManager(dir) // simulated restart
	if _, err := m2.LoadCluster(); err != nil {
		t.Fatal(err)
	}
	if err := m2.Start(); err == nil {
		m2.Stop()
		t.Fatal("Start succeeded without a cluster password")
	}
	if err := m2.UnlockPassword("wrong-password"); err == nil {
		t.Fatal("UnlockPassword accepted a wrong password")
	}
	if err := m2.UnlockPassword("password123"); err != nil {
		t.Fatalf("UnlockPassword: %v", err)
	}
	m2.gossip()
	mu.Lock()
	defer mu.Unlock()
	if got != "password123" {
		t.Fatalf("gossip sent X-Cluster-Password=%q, want the cluster password", got)
	}
}

// A node restarted from disk must be able to resume membership: the password
// is stored 0600 next to cluster.json (or supplied via env), and leaving
// removes it.
func TestClusterSecretPersistsAndUnlocks(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)
	cfg := DefaultClusterConfig()
	cfg.EnableEncryption = false
	if _, err := m.InitCluster("c", "password123", cfg); err != nil {
		t.Fatal(err)
	}
	if err := m.SaveSecret(); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, secretFile))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("secret file: %v mode=%v, want 0600", err, st.Mode().Perm())
	}

	m2 := NewManager(dir)
	if _, err := m2.LoadCluster(); err != nil {
		t.Fatal(err)
	}
	if err := m2.UnlockFromSecret(); err != nil {
		t.Fatalf("UnlockFromSecret: %v", err)
	}
	if m2.plainPassword != "password123" {
		t.Fatal("password not restored from the secret file")
	}

	// The env var overrides the file; a wrong one is rejected.
	t.Setenv(ClusterPasswordEnv, "wrong-password")
	m3 := NewManager(dir)
	if _, err := m3.LoadCluster(); err != nil {
		t.Fatal(err)
	}
	if err := m3.UnlockFromSecret(); err == nil {
		t.Fatal("wrong password from env accepted")
	}
	t.Setenv(ClusterPasswordEnv, "")

	if err := m2.LeaveCluster(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, secretFile)); !os.IsNotExist(err) {
		t.Fatal("cluster secret left behind after leaving the cluster")
	}
}

// Wrong-password join attempts (the cluster ID is not secret) must not
// serialize the manager behind bcrypt: membership reads stay responsive.
func TestJoinFloodDoesNotStallManager(t *testing.T) {
	m := NewManager(t.TempDir())
	cfg := DefaultClusterConfig()
	cfg.EnableEncryption = false
	c, err := m.InitCluster("c", "password123", cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a restarted node that has only the hash (bcrypt path).
	m.mu.Lock()
	m.plainPassword = ""
	m.mu.Unlock()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				m.HandleJoinRequest(&JoinRequest{ClusterID: c.ID, Password: "wrong-password"}, "198.51.100.1")
			}
		}()
	}
	time.Sleep(200 * time.Millisecond)
	var worst time.Duration
	for i := 0; i < 20; i++ {
		start := time.Now()
		m.GetNodes()
		m.UpdateNodeStats(NodeStats{})
		if d := time.Since(start); d > worst {
			worst = d
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	if worst > 250*time.Millisecond {
		t.Fatalf("membership calls stalled up to %v behind bcrypt in join handling", worst)
	}
}
