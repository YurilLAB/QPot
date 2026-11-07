package cluster

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

// Refusing the temporary state file simulates a full/unwritable state volume
// without relying on permission bits (tests may run as root).
func blockClusterSave(t *testing.T, m *Manager) {
	t.Helper()
	path := filepath.Join(m.dataPath, "cluster.json.tmp")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
}

func TestInitClusterSaveFailureDoesNotActivateIdentity(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "new", true: "existing"}[existing], func(t *testing.T) {
			m := NewManager(t.TempDir())
			var previous *Cluster
			var before []byte
			if existing {
				var err error
				previous, err = m.InitCluster("previous", "previous-password", nil)
				if err != nil {
					t.Fatal(err)
				}
				before, err = os.ReadFile(filepath.Join(m.dataPath, "cluster.json"))
				if err != nil {
					t.Fatal(err)
				}
			}
			password := m.plainPassword
			blockClusterSave(t, m)
			c, err := m.InitCluster("unsaved", "different-password", nil)
			if err == nil || c != nil {
				t.Fatal("initialization acknowledged an unsaved identity")
			}
			if m.GetCluster() != previous || m.plainPassword != password {
				t.Fatal("failed initialization activated an unsaved identity or password")
			}
			got, readErr := os.ReadFile(filepath.Join(m.dataPath, "cluster.json"))
			if existing && (readErr != nil || !bytes.Equal(got, before)) {
				t.Fatal("failed initialization changed saved identity")
			}
			if !existing && !os.IsNotExist(readErr) {
				t.Fatalf("unexpected saved state: %v", readErr)
			}
		})
	}
}

func TestJoinClusterSaveFailureDoesNotAcknowledgeOrRetry(t *testing.T) {
	const password = "password123"
	host := NewManager(t.TempDir())
	cfg := DefaultClusterConfig()
	cfg.RequireApproval = false
	c, err := host.InitCluster("authority", password, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		host.handleJoinHTTP(w, r)
	}))
	defer server.Close()
	joiner := NewManager(t.TempDir())
	previous, err := joiner.InitCluster("previous", "previous-password", nil)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(joiner.dataPath, "cluster.json"))
	if err != nil {
		t.Fatal(err)
	}
	blockClusterSave(t, joiner)
	local := &Node{Name: "sensor", Address: "127.0.0.1", Port: 7947}
	original := *local
	joined, err := joiner.JoinCluster(c.ID, password, local, []string{server.URL, server.URL})
	if err == nil || joined != nil || !strings.Contains(err.Error(), "save") {
		t.Fatalf("join acknowledged an unsaved leaf identity: joined=%t error=%v", joined != nil, err)
	}
	if requests.Load() != 1 {
		t.Fatalf("local save failure retried enrollment: %d requests", requests.Load())
	}
	if joiner.GetCluster() != previous || joiner.plainPassword != "previous-password" || !reflect.DeepEqual(*local, original) {
		t.Fatal("failed join replaced local state, password or caller's node")
	}
	after, err := os.ReadFile(filepath.Join(joiner.dataPath, "cluster.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed join changed saved state")
	}
}

func TestEnrollmentSaveFailureDoesNotReleaseCredentials(t *testing.T) {
	for _, approval := range []bool{false, true} {
		t.Run(map[bool]string{false: "immediate", true: "approval"}[approval], func(t *testing.T) {
			m := NewManager(t.TempDir())
			cfg := DefaultClusterConfig()
			cfg.RequireApproval = approval
			c, err := m.InitCluster("authority", "password123", cfg)
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(m.dataPath, "cluster.json"))
			if err != nil {
				t.Fatal(err)
			}
			updated := c.UpdatedAt
			blockClusterSave(t, m)
			request := &JoinRequest{Version: ProtocolVersion, ClusterID: c.ID, Password: "password123", NodeCSR: testNodeCSR(t),
				PollSecret: testPollSecret, NodeName: "sensor", NodeAddress: "127.0.0.1", NodePort: 7947}
			resp := m.HandleJoinRequest(request, "127.0.0.1")
			if approval {
				if resp.Status != "pending" {
					t.Fatalf("request was not queued: %+v", resp)
				}
				if node, err := m.ApproveJoin(resp.RequestID); err == nil || node != nil {
					t.Fatal("approval acknowledged unsaved membership")
				}
				outcome, ok := m.joinOutcome(resp.RequestID)
				if !ok || outcome.Status != "pending" || len(m.ListPendingJoins()) != 1 {
					t.Fatal("failed approval consumed the retryable request")
				}
			} else if resp.Success || resp.MemberKey != "" || resp.NodeCertificate != "" || !strings.Contains(resp.Error, "persist") {
				t.Fatal("failed membership save released enrollment credentials")
			}
			if len(m.GetNodes()) != 1 || !c.UpdatedAt.Equal(updated) {
				t.Fatal("failed save activated in-memory membership")
			}
			after, err := os.ReadFile(filepath.Join(m.dataPath, "cluster.json"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed enrollment changed saved state")
			}
			if err := os.Remove(filepath.Join(m.dataPath, "cluster.json.tmp")); err != nil {
				t.Fatal(err)
			}
			if approval {
				if _, err := m.ApproveJoin(resp.RequestID); err != nil {
					t.Fatal(err)
				}
			} else if retry := m.HandleJoinRequest(request, "127.0.0.1"); !retry.Success {
				t.Fatalf("retry failed: %s", retry.Error)
			}
			reloaded, err := NewManager(m.dataPath).LoadCluster()
			if err != nil || reloaded == nil || len(reloaded.Nodes) != 2 {
				t.Fatal("successful retry did not persist membership")
			}
		})
	}
}

func TestMissingMemberCredentialFailsClosed(t *testing.T) {
	for _, approval := range []bool{false, true} {
		m := NewManager(t.TempDir())
		cfg := DefaultClusterConfig()
		cfg.RequireApproval = approval
		cfg.BindAddr, cfg.BindPort = "127.0.0.1", 0
		c, err := m.InitCluster("authority", "password123", cfg)
		if err != nil {
			t.Fatal(err)
		}
		c.MemberKey = ""
		if err := m.Start(); err == nil {
			m.Stop()
			t.Error("started a node without membership credentials")
		}
		resp := m.HandleJoinRequest(&JoinRequest{Version: ProtocolVersion, ClusterID: c.ID, Password: "password123",
			NodeCSR: testNodeCSR(t), PollSecret: testPollSecret, NodeAddress: "127.0.0.1", NodePort: 7947}, "127.0.0.1")
		if resp.Success || resp.Status == "pending" || resp.ErrorCode != "QP-CLUSTER-005" || len(m.ListPendingJoins()) != 0 || len(m.GetNodes()) != 1 {
			t.Error("authority without membership credentials enrolled or queued a node")
		}
	}
}
