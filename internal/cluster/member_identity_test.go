package cluster

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests check that a peer request is taken only from the node it comes
// from, and only while that node is a member: every member used to share the
// password and member key, and nothing in a request said which node sent it.

const idPassword = "correct-horse-battery"

// startOn starts m on a free loopback port, trying again when another test
// took the port between choosing and binding it.
func startOn(t *testing.T, m *Manager) int {
	t.Helper()
	for attempt := 0; ; attempt++ {
		port := freePort(t)
		m.mu.Lock()
		m.cluster.Config.BindAddr = "127.0.0.1"
		m.cluster.Config.BindPort = port
		m.cluster.LocalNode.Address = "127.0.0.1"
		m.cluster.LocalNode.Port = port
		m.mu.Unlock()
		err := m.Start()
		if err == nil {
			t.Cleanup(func() { _ = m.Stop() })
			waitListening(t, port)
			return port
		}
		if attempt == 5 || !strings.Contains(err.Error(), "cluster API") {
			t.Fatalf("start: %v", err)
		}
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// idHost starts an enrollment host (automatic TLS, no approval step).
func idHost(t *testing.T) (*Manager, *Cluster, int) {
	t.Helper()
	m := NewManager(t.TempDir())
	cfg := DefaultClusterConfig()
	cfg.RequireApproval = false
	cfg.BindAddr, cfg.AdvertiseAddr = "127.0.0.1", "127.0.0.1"
	cfg.GossipInterval = 50 * time.Millisecond
	c, err := m.InitCluster("prod", idPassword, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return m, c, startOn(t, m)
}

// idMember joins a node through the host and starts it on the port it
// joined with.
func idMember(t *testing.T, c *Cluster, hostPort int, name string) (*Manager, string) {
	t.Helper()
	m := NewManager(t.TempDir())
	port := freePort(t)
	if _, err := m.JoinCluster(c.ID, idPassword, &Node{Name: name, Address: "127.0.0.1", Port: port},
		[]string{"127.0.0.1:" + strconv.Itoa(hostPort)}); err != nil {
		t.Fatalf("%s joins: %v", name, err)
	}
	if err := m.SaveSecret(); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.cluster.Config.BindAddr = "127.0.0.1"
	m.mu.Unlock()
	if err := m.Start(); err != nil {
		t.Fatalf("%s starts: %v", name, err)
	}
	t.Cleanup(func() { _ = m.Stop() })
	waitListening(t, port)
	return m, m.LocalNodeID()
}

// peerCreds is everything a member holds that a peer request can carry.
type peerCreds struct {
	MemberKey       string `json:"member_key"`
	NodeKey         string `json:"node_key"`
	NodeCertificate string `json:"node_certificate"`
	CAKey           string `json:"ca_key"`
}

// credsOf reads a node's credentials from its saved state, as a node that
// keeps a copy of them after leaving or being removed would.
func credsOf(t *testing.T, m *Manager) peerCreds {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(m.dataPath, "cluster.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c peerCreds
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	if c.MemberKey == "" || c.NodeKey == "" || c.NodeCertificate == "" {
		t.Fatal("saved state lacks the member credentials")
	}
	return c
}

// peerCall sends a peer request to the node on port with creds: the password,
// the member key and, in the TLS handshake, the node certificate.
func peerCall(t *testing.T, port int, path string, body any, creds peerCreds) (int, string) {
	t.Helper()
	cert, err := tls.X509KeyPair([]byte(creds.NodeCertificate), []byte(creds.NodeKey))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		// The node's certificate is what is under test, not the server's.
		InsecureSkipVerify: true, // #nosec G402 -- test client
	}}}
	defer client.CloseIdleConnections()
	method, rd := http.MethodGet, io.Reader(nil)
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		method, rd = http.MethodPost, bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "https://127.0.0.1:"+strconv.Itoa(port)+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	setPeerAuth(req, idPassword, creds.MemberKey)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, string(out)
}

// eventuallyTrue waits up to 5 s for ok.
func eventuallyTrue(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func refused(code int) bool { return code == http.StatusUnauthorized || code == http.StatusForbidden }

// TestLeftNodeCredentialsAreRefused: a node that left kept working
// credentials, since the cluster checked only the shared password and member
// key. It could read the membership, push gossip and intel under any member's
// ID, and add nodes of its own making.
func TestLeftNodeCredentialsAreRefused(t *testing.T) {
	host, c, hostPort := idHost(t)
	a, aID := idMember(t, c, hostPort, "a")
	b, bID := idMember(t, c, hostPort, "b")
	credsA, credsB := credsOf(t, a), credsOf(t, b)
	eventuallyTrue(t, "the host does not list b", func() bool { return isMember(host, bID) })

	_ = b.Stop()
	if err := b.LeaveCluster(); err != nil {
		t.Logf("leave: %v", err) // a peer may not have heard of b yet
	}
	if isMember(host, bID) {
		t.Fatal("b is still a member at the host after leaving")
	}

	// Negative control: a, still a member, is answered.
	if code, body := peerCall(t, hostPort, "/api/v1/cluster/nodes", nil, credsA); code != http.StatusOK {
		t.Fatalf("an active member's request: %d %s", code, body)
	}
	if code, _ := peerCall(t, hostPort, "/api/v1/cluster/nodes", nil, credsB); !refused(code) {
		t.Errorf("b, which left, read the membership with its old credentials: %d", code)
	}
	evil := &Node{ID: "qn_evil0000000000", Name: "evil", Address: "127.0.0.1", Port: 7999, Status: NodeStatusHealthy, LastSeen: time.Now()}
	code, _ := peerCall(t, hostPort, "/api/v1/cluster/gossip", GossipMessage{SenderID: aID, Timestamp: time.Now(),
		NodeDigest: []*Node{evil}}, credsB)
	if !refused(code) || isMember(host, evil.ID) {
		t.Errorf("b, which left, pushed gossip as a: %d, fabricated node added %v", code, isMember(host, evil.ID))
	}
	code, _ = peerCall(t, hostPort, "/api/v1/cluster/intel", ThreatIntel{NodeID: aID, Timestamp: time.Now(),
		TopSourceIPs: []IPCount{{IP: "198.51.100.66", Count: 999}}}, credsB)
	if !refused(code) {
		t.Errorf("b, which left, sent intel as a: %d", code)
	}
	for _, in := range host.GetThreatIntel() {
		if in.NodeID == aID && len(in.TopSourceIPs) > 0 && in.TopSourceIPs[0].IP == "198.51.100.66" {
			t.Error("the host keeps intel b forged under a's ID")
		}
	}
}

// TestMemberCannotRemoveAnotherMember: a leave naming another node was taken
// when it came from that node's address, so members sharing an address (one
// host, one NAT) could remove each other. Gossip and intel carried a sender
// ID the sender chose.
func TestMemberCannotRemoveAnotherMember(t *testing.T) {
	host, c, hostPort := idHost(t)
	a, aID := idMember(t, c, hostPort, "a")
	b, bID := idMember(t, c, hostPort, "b")
	credsA, credsB := credsOf(t, a), credsOf(t, b)
	eventuallyTrue(t, "the host does not list a and b", func() bool { return isMember(host, aID) && isMember(host, bID) })

	if code, _ := peerCall(t, hostPort, "/api/v1/cluster/leave", map[string]string{"node_id": bID}, credsA); code != http.StatusForbidden || !isMember(host, bID) {
		t.Errorf("a's leave naming b: %d, b a member %v; want 403 and b kept", code, isMember(host, bID))
	}
	if code, _ := peerCall(t, hostPort, "/api/v1/cluster/gossip", GossipMessage{SenderID: bID, Timestamp: time.Now(),
		NodeDigest: []*Node{{ID: bID, Name: "b", Address: "127.0.0.1", Port: 1, Status: NodeStatusLeft, LastSeen: time.Now()}}}, credsA); code != http.StatusForbidden || !isMember(host, bID) {
		t.Errorf("a's gossip as b saying b left: %d, b a member %v; want 403 and b kept", code, isMember(host, bID))
	}
	if code, _ := peerCall(t, hostPort, "/api/v1/cluster/intel", ThreatIntel{NodeID: bID, Timestamp: time.Now()}, credsA); code != http.StatusForbidden {
		t.Errorf("a's intel as b: %d, want 403", code)
	}

	// Negative control: b's own leave is taken.
	if code, body := peerCall(t, hostPort, "/api/v1/cluster/leave", map[string]string{"node_id": bID}, credsB); code != http.StatusOK || isMember(host, bID) {
		t.Errorf("b's own leave: %d %s, b a member %v; want 200 and b gone", code, body, isMember(host, bID))
	}
	_ = b
}

// removeNode asks the cluster API on port, from this host, to remove id,
// presenting the node certificate in creds as the operator's CLI does.
func removeNode(t *testing.T, port int, id string, creds peerCreds) (int, string) {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"node_id": id})
	req, err := http.NewRequest(http.MethodPost, "https://127.0.0.1:"+strconv.Itoa(port)+"/api/v1/cluster/remove", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Cluster-Password", idPassword)
	cert, err := tls.X509KeyPair([]byte(creds.NodeCertificate), []byte(creds.NodeKey))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert},
		InsecureSkipVerify: true}}} // #nosec G402 -- test client
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

// TestLeftAndRemovedNodesStayGone: a node that left, and one the host
// removed, are refused and not members, also after the host restarts, and
// the removal reaches the other members.
func TestLeftAndRemovedNodesStayGone(t *testing.T) {
	host, c, hostPort := idHost(t)
	a, aID := idMember(t, c, hostPort, "a")
	b, bID := idMember(t, c, hostPort, "b")
	x, xID := idMember(t, c, hostPort, "x")
	credsA, credsB, credsX := credsOf(t, a), credsOf(t, b), credsOf(t, x)
	aPort := a.GetCluster().LocalNode.Port
	eventuallyTrue(t, "a does not know x", func() bool { return isMember(a, xID) && isMember(a, bID) })

	_ = b.Stop()
	_ = b.LeaveCluster()
	if code, body := removeNode(t, hostPort, xID, credsOf(t, host)); code != http.StatusOK {
		t.Fatalf("the host's removal of x: %d %s", code, body)
	}
	if isMember(host, xID) {
		t.Fatal("x is still a member after the host removed it")
	}
	if code, _ := peerCall(t, hostPort, "/api/v1/cluster/nodes", nil, credsX); !refused(code) {
		t.Errorf("x, removed, is answered: %d", code)
	}
	eventuallyTrue(t, "the removal of x did not reach a", func() bool { return !isMember(a, xID) })
	if code, _ := peerCall(t, aPort, "/api/v1/cluster/nodes", nil, credsX); !refused(code) {
		t.Errorf("x, removed, is answered by a: %d", code)
	}

	// The host restarts.
	_ = host.Stop()
	restarted := NewManager(host.dataPath)
	if _, err := restarted.LoadCluster(); err != nil {
		t.Fatal(err)
	}
	if err := restarted.UnlockPassword(idPassword); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Stop() })
	waitListening(t, hostPort)
	for _, id := range []string{bID, xID} {
		if isMember(restarted, id) {
			t.Errorf("%s is a member again after the host restarted", id)
		}
	}
	// Negative control: a, still a member, is answered after the restart.
	if code, body := peerCall(t, hostPort, "/api/v1/cluster/nodes", nil, credsA); code != http.StatusOK {
		t.Fatalf("an active member after the restart: %d %s", code, body)
	}
	for name, creds := range map[string]peerCreds{"b (left)": credsB, "x (removed)": credsX} {
		if code, _ := peerCall(t, hostPort, "/api/v1/cluster/nodes", nil, creds); !refused(code) {
			t.Errorf("%s is answered after the host restarted: %d", name, code)
		}
	}

	// So does a member that restarts: it saved the removal it gossiped.
	_ = a.Stop()
	ra := NewManager(a.dataPath)
	if _, err := ra.LoadCluster(); err != nil {
		t.Fatal(err)
	}
	if isMember(ra, xID) {
		t.Error("x is a member again at a after a restart")
	}
	if err := ra.UnlockPassword(idPassword); err != nil {
		t.Fatal(err)
	}
	if err := ra.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ra.Stop() })
	waitListening(t, aPort)
	if code, _ := peerCall(t, aPort, "/api/v1/cluster/nodes", nil, credsX); !refused(code) {
		t.Errorf("x, removed, is answered by a after a restart: %d", code)
	}
	if code, body := peerCall(t, aPort, "/api/v1/cluster/nodes", nil, credsA); code != http.StatusOK {
		t.Errorf("a's own certificate after a restart: %d %s", code, body)
	}
	_ = aID
}

// TestRemoveIsTheHostsOnly: only the enrollment host's operator removes a
// node. Members hold the password too, and one on the host's machine passes
// the from-this-host check, so the request must present the host's own node
// certificate; an ordinary member has no authority to sign a removal.
func TestRemoveIsTheHostsOnly(t *testing.T) {
	host, c, hostPort := idHost(t)
	a, _ := idMember(t, c, hostPort, "a")
	_, bID := idMember(t, c, hostPort, "b")
	credsA := credsOf(t, a)
	eventuallyTrue(t, "a does not know b", func() bool { return isMember(a, bID) })
	if code, _ := removeNode(t, hostPort, bID, credsA); code == http.StatusOK || !isMember(host, bID) {
		t.Errorf("member a's removal of b at the host, from the host's machine: %d, b a member %v", code, isMember(host, bID))
	}
	// An ordinary member's own API cannot sign one.
	if code, _ := removeNode(t, a.GetCluster().LocalNode.Port, bID, credsA); code == http.StatusOK {
		t.Errorf("an ordinary member removed b: %d", code)
	}
	if !isMember(a, bID) || !isMember(host, bID) {
		t.Error("b was removed")
	}
	// Negative control: the host's operator can.
	if code, body := removeNode(t, hostPort, bID, credsOf(t, host)); code != http.StatusOK || isMember(host, bID) {
		t.Errorf("the host's removal of b: %d %s", code, body)
	}
}

// TestOrdinaryMemberHasNoCAKey: the CA key stays on the enrollment host.
func TestOrdinaryMemberHasNoCAKey(t *testing.T) {
	host, c, hostPort := idHost(t)
	a, _ := idMember(t, c, hostPort, "a")
	hostState, err := os.ReadFile(filepath.Join(host.dataPath, "cluster.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Negative control: the host's state does hold it.
	if c.CAKey == "" || !bytes.Contains(hostState, []byte(c.CAKey)) {
		t.Fatal("the enrollment host's state does not hold the CA key")
	}
	_ = a.Stop()
	memberState, err := os.ReadFile(filepath.Join(a.dataPath, "cluster.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(memberState, []byte(c.CAKey)) || bytes.Contains(memberState, []byte(`"ca_key"`)) {
		t.Error("an ordinary member's saved state holds the CA key")
	}
	if creds := credsOf(t, a); creds.CAKey != "" {
		t.Error("an ordinary member holds a CA key")
	}
}

// TestPlainClusterRefusesToStart: without TLS no request can say which member
// sent it, so a cluster with encryption off does not start.
func TestPlainClusterRefusesToStart(t *testing.T) {
	m := plainCluster(t)
	err := m.Start()
	if err == nil {
		_ = m.Stop()
		t.Fatal("a cluster with encryption off started")
	}
	requireClusterCode(t, err, "QP-CLUSTER-010")
}

// signedRevocation is a revocation of nodeID signed with caKey.
func signedRevocation(t *testing.T, clusterID, caKey, nodeID string, at time.Time) Revocation {
	t.Helper()
	key, _, err := clusterCA(caKey)
	if err != nil {
		t.Fatal(err)
	}
	rv := Revocation{NodeID: nodeID, RevokedAt: at.UTC()}
	rv.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, revocationMessage(clusterID, rv)))
	return rv
}

// TestRevocationNeedsTheClusterCA: a removal is taken only when the cluster
// CA signed it, whichever member gossips it, and it is saved.
func TestRevocationNeedsTheClusterCA(t *testing.T) {
	m := plainCluster(t)
	x := addMember(m, testNodeID(t), "10.0.0.5", 7946)
	y := addMember(m, testNodeID(t), "10.0.0.6", 7946)
	m.mu.RLock()
	clusterID, caKey := m.cluster.ID, m.cluster.CAKey
	m.mu.RUnlock()
	now := time.Now()

	otherCA, _, err := newClusterCA()
	if err != nil {
		t.Fatal(err)
	}
	forged := []Revocation{
		signedRevocation(t, clusterID, otherCA, x.ID, now),        // another CA
		signedRevocation(t, "qc_other", caKey, x.ID, now),         // another cluster
		{NodeID: x.ID, RevokedAt: now, Signature: "bm90IGEgc2ln"}, // garbage
	}
	tampered := signedRevocation(t, clusterID, caKey, x.ID, now)
	tampered.NodeID = y.ID // signed for x, claims y
	forged = append(forged, tampered)
	pushGossip(t, m, GossipMessage{SenderID: y.ID, Timestamp: now, Revocations: forged})
	if !isMember(m, x.ID) || !isMember(m, y.ID) {
		t.Fatal("a revocation the cluster CA did not sign removed a node")
	}

	pushGossip(t, m, GossipMessage{SenderID: y.ID, Timestamp: now,
		Revocations: []Revocation{signedRevocation(t, clusterID, caKey, x.ID, now)}})
	if isMember(m, x.ID) {
		t.Fatal("a revocation the cluster CA signed was not taken")
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/cluster/nodes", nil)
	req.TLS = nodeTLS(t, m, x.ID)
	if _, err := m.authenticatePeer(req); err == nil {
		t.Fatal("the removed node is still authenticated")
	}

	// Saved: a restart keeps it, and gossip cannot bring the node back.
	r := NewManager(m.dataPath)
	if _, err := r.LoadCluster(); err != nil {
		t.Fatal(err)
	}
	if isMember(r, x.ID) {
		t.Fatal("the removed node is a member again after a restart")
	}
	pushGossip(t, r, GossipMessage{SenderID: y.ID, Timestamp: time.Now(), NodeDigest: []*Node{
		{ID: x.ID, Name: "x", Address: "10.0.0.5", Port: 7946, Status: NodeStatusHealthy, LastSeen: time.Now().Add(time.Hour)}}})
	if isMember(r, x.ID) {
		t.Fatal("gossip brought the removed node back")
	}
	if _, err := r.authenticatePeer(req); err == nil {
		t.Fatal("the removed node is authenticated after a restart")
	}
}

// TestLeaveReachesAMemberThatMissedIt: a leave was only a request to the
// members the node reached; one that was offline kept the node as a member
// and took its certificate, and its gossip could put the node back where it
// was unknown. A leave is now a revocation signed with the leaving node's own
// key, which every member checks and gossips on.
func TestLeaveReachesAMemberThatMissedIt(t *testing.T) {
	host, c, hostPort := idHost(t)
	b, _ := idMember(t, c, hostPort, "b")
	x, xID := idMember(t, c, hostPort, "x")
	credsX := credsOf(t, x)
	bPort := b.GetCluster().LocalNode.Port
	eventuallyTrue(t, "b does not know x", func() bool { return isMember(b, xID) })

	// b goes offline; x leaves; b comes back.
	_ = b.Stop()
	_ = x.Stop()
	_ = x.LeaveCluster() // b is not reached
	if isMember(host, xID) {
		t.Fatal("x is still a member at the host after leaving")
	}
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	waitListening(t, bPort)
	eventuallyTrue(t, "b still lists x as a member after gossiping with the host", func() bool { return !isMember(b, xID) })
	if code, _ := peerCall(t, bPort, "/api/v1/cluster/nodes", nil, credsX); !refused(code) {
		t.Errorf("x, which left, is answered by b, which missed the leave: %d", code)
	}
}

// TestGossipAnswerOnlyFromTheNodeDialled: a member checked only that the node
// it gossiped with had a certificate from the cluster CA, so any node with
// one - a node that left or was removed, or another member - answering at a
// member's address had its answer taken as that member's: it could say the
// member left, add nodes, or post intel in its name.
func TestGossipAnswerOnlyFromTheNodeDialled(t *testing.T) {
	m := NewManager(t.TempDir())
	if _, err := m.InitCluster("prod", idPassword, DefaultClusterConfig()); err != nil {
		t.Fatal(err)
	}
	m.UpdateThreatIntel([]IPCount{{IP: "203.0.113.5", Count: 1}})
	y := addMember(m, testNodeID(t), "127.0.0.1", 1)
	evil := &Node{ID: "qn_evil0000000000", Name: "evil", Address: "127.0.0.1", Port: 7999, Status: NodeStatusHealthy, LastSeen: time.Now()}
	// Another node of the cluster answers at y's address.
	impostor := servePeerTLS(t, m, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/intel") {
			_ = json.NewEncoder(w).Encode(ThreatIntel{NodeID: y.ID, Timestamp: time.Now(), TopSourceIPs: []IPCount{{IP: "198.51.100.66", Count: 999}}})
			return
		}
		_ = json.NewEncoder(w).Encode(GossipMessage{SenderID: y.ID, Timestamp: time.Now(), NodeDigest: []*Node{
			{ID: y.ID, Name: "y", Address: "127.0.0.1", Port: 1, Status: NodeStatusLeft, LastSeen: time.Now().Add(time.Hour)}, evil}})
	}))
	m.mu.Lock()
	y.Address, y.Port = urlHostPort(t, impostor.URL)
	m.mu.Unlock()

	m.gossip()
	m.sync()
	if !isMember(m, y.ID) {
		t.Error("another node answering at y's address said y left, and was believed")
	}
	if isMember(m, evil.ID) {
		t.Error("another node answering at y's address added a node")
	}
	for _, in := range m.GetThreatIntel() {
		if in.NodeID == y.ID {
			t.Error("another node answering at y's address posted intel as y")
		}
	}

	// Negative control: y itself, at its address, is heard.
	m2 := NewManager(t.TempDir())
	if _, err := m2.InitCluster("prod", idPassword, DefaultClusterConfig()); err != nil {
		t.Fatal(err)
	}
	real := addMember(m2, testNodeID(t), "127.0.0.1", 1)
	chain, key := issueFor(t, m2, real.ID)
	cert, err := tls.X509KeyPair([]byte(chain), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(GossipMessage{SenderID: real.ID, Timestamp: time.Now(), NodeDigest: []*Node{
			{ID: "qn_0123456789abcdef", Name: "new", Address: "127.0.0.1", Port: 7998, Status: NodeStatusHealthy, LastSeen: time.Now()}}})
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()
	m2.mu.Lock()
	real.Address, real.Port = urlHostPort(t, srv.URL)
	m2.mu.Unlock()
	m2.gossip()
	if !isMember(m2, "qn_0123456789abcdef") {
		t.Error("the node dialled, answering for itself, was not heard")
	}
}

// selfLeave is a leave of nodeID signed with key, carrying chain's leaf.
func selfLeave(t *testing.T, clusterID, nodeID, chain, key string, at time.Time) Revocation {
	t.Helper()
	m := &Manager{cluster: &Cluster{ID: clusterID, NodeCertificate: chain, NodeKey: key, LocalNode: &Node{ID: nodeID}}}
	rv, err := m.leaveRevocationLocked(at)
	if err != nil {
		t.Fatal(err)
	}
	return rv
}

// TestSignedLeaveOnlyFromTheNodeItself: a leave gossiped on is taken only
// when the node that left signed it, with a certificate from the cluster CA;
// a member that never knew the node then does not take it from gossip.
func TestSignedLeaveOnlyFromTheNodeItself(t *testing.T) {
	m := plainCluster(t)
	y := addMember(m, testNodeID(t), "10.0.0.6", 7946)
	xID := testNodeID(t)
	m.mu.RLock()
	clusterID := m.cluster.ID
	m.mu.RUnlock()
	xChain, xKey := issueFor(t, m, xID)
	yChain, yKey := issueFor(t, m, y.ID)
	now := time.Now()

	other := plainCluster(t) // another cluster's CA
	oChain, oKey := issueFor(t, other, xID)
	future := selfLeave(t, clusterID, xID, xChain, xKey, now.Add(48*time.Hour))
	swapped := selfLeave(t, clusterID, xID, xChain, xKey, now)
	swapped.Certificate = selfLeave(t, clusterID, y.ID, yChain, yKey, now).Certificate
	for name, rv := range map[string]Revocation{
		"y's key, naming x":        func() Revocation { r := selfLeave(t, clusterID, y.ID, yChain, yKey, now); r.NodeID = xID; return r }(),
		"another CA's certificate": selfLeave(t, clusterID, xID, oChain, oKey, now),
		"dated two days ahead":     future,
		"y's certificate":          swapped,
	} {
		pushGossip(t, m, GossipMessage{SenderID: y.ID, Timestamp: now, Revocations: []Revocation{rv}})
		m.mu.RLock()
		got := m.revokedLocked(xID)
		m.mu.RUnlock()
		if got {
			t.Fatalf("a leave of x with %s was taken", name)
		}
	}

	// x's own signed leave, gossiped on by y: x was never known here, and
	// gossip does not add it afterwards.
	pushGossip(t, m, GossipMessage{SenderID: y.ID, Timestamp: now, Revocations: []Revocation{selfLeave(t, clusterID, xID, xChain, xKey, now)}})
	pushGossip(t, m, GossipMessage{SenderID: y.ID, Timestamp: now, NodeDigest: []*Node{
		{ID: xID, Name: "x", Address: "10.0.0.5", Port: 7946, Status: NodeStatusHealthy, LastSeen: now.Add(time.Hour)}}})
	if isMember(m, xID) {
		t.Fatal("gossip added a node whose signed leave this node holds")
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/cluster/nodes", nil)
	req.TLS = nodeTLS(t, m, xID)
	if _, err := m.authenticatePeer(req); err == nil {
		t.Fatal("a node that left is authenticated")
	}
}

// TestManyRevocationsAllGossiped: past revocationsPerMessage, successive
// gossip messages carry the rest in turn.
func TestManyRevocationsAllGossiped(t *testing.T) {
	m := plainCluster(t)
	m.mu.RLock()
	clusterID, caKey := m.cluster.ID, m.cluster.CAKey
	m.mu.RUnlock()
	now := time.Now()
	var all []Revocation
	for i := 0; i < 3*revocationsPerMessage+5; i++ {
		all = append(all, signedRevocation(t, clusterID, caKey, testNodeID(t), now))
	}
	m.mu.Lock()
	m.cluster.Revocations = all
	m.mu.Unlock()
	seen := map[string]bool{}
	for round := 0; round < 4; round++ {
		m.mu.RLock()
		msg := m.revocationsLocked()
		m.mu.RUnlock()
		if len(msg) > revocationsPerMessage {
			t.Fatalf("a message carries %d revocations", len(msg))
		}
		for _, rv := range msg {
			seen[rv.NodeID] = true
		}
	}
	if len(seen) != len(all) {
		t.Fatalf("four messages carried %d of %d revocations", len(seen), len(all))
	}
}
