package cluster

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A QPot ID is the instance's web API credential. These stand for the IDs of
// three instances; built at run time so no credential-shaped literal is in
// the source.
var (
	joinerQPotID = "qp_" + strings.Repeat("j", 24)
	oldLocalID   = "qp_" + strings.Repeat("l", 24)
	oldPeerID    = "qp_" + strings.Repeat("o", 24)
	gossipPeerID = "qp_" + strings.Repeat("g", 24)
)

// noQPotID fails when data carries any of the QPot IDs, or the field.
func noQPotID(t *testing.T, what string, data []byte) {
	t.Helper()
	for _, id := range []string{joinerQPotID, oldLocalID, oldPeerID, gossipPeerID} {
		if bytes.Contains(data, []byte(id)) {
			t.Errorf("%s carries a QPot ID (the web API credential): %s", what, data)
			return
		}
	}
	if bytes.Contains(data, []byte(`"qpot_id"`)) {
		t.Errorf("%s still has a qpot_id field: %s", what, data)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestJoinKeepsTheJoinersQPotID: a joiner sent its QPot ID with its join
// request, the host listed it with the pending request, put it on the node it
// admitted and so in cluster.json, the join answer and every gossip digest:
// every member learnt every other member's web API credential. A request
// that still sends it is accepted and the ID dropped.
func TestJoinKeepsTheJoinersQPotID(t *testing.T) {
	const password = "correct-horse-battery"
	seedDir := t.TempDir()
	seed := NewManager(seedDir)
	cl, err := seed.InitCluster("prod", password, DefaultClusterConfig())
	if err != nil {
		t.Fatal(err)
	}
	base := startSeedServer(t, seed)

	body := mustJSON(t, map[string]any{
		"version": ProtocolVersion, "node_csr": testNodeCSR(t),
		"cluster_id": cl.ID, "password": password, "node_name": "old-sensor",
		"node_address": "10.9.9.9", "node_port": 7947, "qpot_id": joinerQPotID,
		"instance_name": "default", "poll_secret": testPollSecret,
	})
	resp, err := http.Post(base+"/api/v1/cluster/join", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	answer, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var pending JoinResponse
	if err := json.Unmarshal(answer, &pending); err != nil || pending.Status != "pending" {
		t.Fatalf("a request carrying a QPot ID was not queued: %d %s", resp.StatusCode, answer)
	}
	noQPotID(t, "the pending list", mustJSON(t, seed.ListPendingJoins()))

	node, err := seed.ApproveJoin(pending.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	noQPotID(t, "the admitted node", mustJSON(t, node))
	noQPotID(t, "the member list", mustJSON(t, seed.GetNodes()))
	data, err := os.ReadFile(filepath.Join(seedDir, "cluster.json"))
	if err != nil {
		t.Fatal(err)
	}
	noQPotID(t, "the host's cluster.json", data)

	// The joiner's poll gets the join answer.
	req, _ := http.NewRequest(http.MethodGet, base+"/api/v1/cluster/join/status?request_id="+pending.RequestID, nil)
	setPeerAuth(req, password, "")
	req.Header.Set(pollSecretHeader, testPollSecret)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	answer, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Contains(answer, []byte(node.ID)) {
		t.Fatalf("join status did not answer with the admitted node: %d %s", resp.StatusCode, answer)
	}
	noQPotID(t, "the join answer", answer)
}

// TestOldClusterFileLosesQPotIDs: a cluster.json written by an older node
// holds its own and other members' QPot IDs. Loading it drops them from the
// file at once, and they are not gossiped; an older peer whose digest still
// carries them is merged with them dropped.
func TestOldClusterFileLosesQPotIDs(t *testing.T) {
	// A peer that records what it is sent and answers like an older node.
	var mu sync.Mutex
	var got [][]byte
	// A node the peer passes on, with its certificate from the cluster CA.
	var gossiped *Node
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, b)
		rec := *gossiped
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sender_id": "node_oldpeer", "timestamp": time.Now(),
			"node_digest": []map[string]any{{
				"id": rec.ID, "name": "older", "address": "127.0.0.1", "port": 7949, "certificate": rec.Certificate,
				"qpot_id": gossipPeerID, "status": "healthy", "last_seen": time.Now(),
			}},
		})
	}))
	defer peer.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(peer.URL, "http://"))

	dir := t.TempDir()
	cfg := DefaultClusterConfig()
	cfg.EnableEncryption = false
	authority := NewManager(dir)
	if _, err := authority.InitCluster("prod", "correct-horse-battery", cfg); err != nil {
		t.Fatal(err)
	}
	g := enrolled(t, authority, &Node{ID: testNodeID(t)})
	pushed := enrolled(t, authority, &Node{ID: testNodeID(t)})
	mu.Lock()
	gossiped = g
	mu.Unlock()
	// Rewrite it as an older node wrote it: QPot IDs on the nodes.
	path := filepath.Join(dir, "cluster.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	local := doc["local_node"].(map[string]any)
	local["qpot_id"] = oldLocalID
	nodes := doc["nodes"].(map[string]any)
	nodes[local["id"].(string)] = local
	nodes["node_oldpeer"] = map[string]any{
		"id": "node_oldpeer", "name": "peer", "address": host, "port": json.Number(portStr),
		"qpot_id": oldPeerID, "status": "healthy", "last_seen": time.Now(),
	}
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	// A record from an older node decodes, without its QPot ID.
	var older Node
	if err := json.Unmarshal(mustJSON(t, nodes["node_oldpeer"]), &older); err != nil || older.ID != "node_oldpeer" {
		t.Fatalf("an older node's record did not decode: %v %+v", err, older)
	}
	noQPotID(t, "an older node's record once decoded", mustJSON(t, &older))

	m := NewManager(dir)
	if c, err := m.LoadCluster(); err != nil || c == nil {
		t.Fatalf("an older cluster.json did not load: %v", err)
	}
	data, _ := os.ReadFile(path)
	noQPotID(t, "cluster.json once loaded", data)
	if got := m.LocalNodeID(); got != local["id"] {
		t.Errorf("LocalNodeID %q, want %q", got, local["id"])
	}
	if got := NewManager(t.TempDir()).LocalNodeID(); got != "" {
		t.Errorf("LocalNodeID %q outside a cluster", got)
	}
	noQPotID(t, "the member list", mustJSON(t, m.GetNodes()))

	m.gossip()
	mu.Lock()
	if len(got) == 0 {
		mu.Unlock()
		t.Fatal("the peer was not gossiped to")
	}
	for _, b := range got {
		noQPotID(t, "the gossip digest", b)
	}
	mu.Unlock()
	data, _ = os.ReadFile(path)
	if !bytes.Contains(data, []byte(g.ID)) {
		t.Fatalf("the older peer's digest was not merged: %s", data)
	}
	noQPotID(t, "cluster.json after an older peer's digest", data)

	// An older peer gossiping to us: accepted, its QPot IDs dropped.
	in := mustJSON(t, map[string]any{
		"sender_id": "node_oldpeer", "timestamp": time.Now(),
		"node_digest": []map[string]any{{
			"id": pushed.ID, "name": "older2", "address": "127.0.0.1", "port": 7950, "certificate": pushed.Certificate,
			"qpot_id": gossipPeerID, "status": "healthy", "last_seen": time.Now(),
		}},
	})
	rec := httptest.NewRecorder()
	m.handleGossipHTTP(rec, fromPeer(httptest.NewRequest(http.MethodPost, "/api/v1/cluster/gossip", bytes.NewReader(in)), "node_oldpeer"))
	if rec.Code != http.StatusOK {
		t.Fatalf("an older peer's gossip was refused: %d %s", rec.Code, rec.Body)
	}
	noQPotID(t, "the gossip answer", rec.Body.Bytes())
	data, _ = os.ReadFile(path)
	if !bytes.Contains(data, []byte(pushed.ID)) {
		t.Fatalf("the older peer's pushed digest was not merged: %s", data)
	}
	noQPotID(t, "cluster.json after an older peer's push", data)
}
