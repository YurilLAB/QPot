package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// attackersDB answers GetTopAttackers with fixed rows.
type attackersDB struct {
	*fakeDB
	top   []*database.AttackerStats
	since time.Time
}

func (d *attackersDB) GetTopAttackers(_ context.Context, limit int, since time.Time) ([]*database.AttackerStats, error) {
	d.since = since
	if len(d.top) > limit {
		return d.top[:limit], nil
	}
	return d.top, nil
}

// TestClusterIntelFromLiveEvents: the cluster shares each node's most active
// attackers of the last hour (Manager.UpdateThreatIntel), but nothing in the
// control plane called it, so no node ever had any to share.
func TestClusterIntelFromLiveEvents(t *testing.T) {
	a := newAPITestServer(t, "api-cluster-intel", nil)
	withTestCluster(t, a.s)
	db := &attackersDB{fakeDB: &fakeDB{}, top: []*database.AttackerStats{
		{SourceIP: "198.51.100.7", AttackCount: 40},
		{SourceIP: "203.0.113.9", AttackCount: 12},
		{SourceIP: "", AttackCount: 3},
	}}
	a.s.database = db
	a.s.SetCluster(a.s.cluster)
	a.s.updateNodeStats(context.Background())

	if since := time.Since(db.since); since < 59*time.Minute || since > 61*time.Minute {
		t.Errorf("attackers counted since %s ago, want the last hour", since)
	}
	var local []string
	for _, in := range a.s.cluster.GetThreatIntel() {
		if in.NodeID == a.s.cluster.LocalNodeID() {
			for _, ip := range in.TopSourceIPs {
				local = append(local, ip.IP)
			}
		}
	}
	if len(local) != 2 || local[0] != "198.51.100.7" || local[1] != "203.0.113.9" {
		t.Fatalf("this node shares %v with its cluster, want its two most active sources", local)
	}

	// GET /api/cluster shows the attackers the nodes share.
	rec := a.do(http.MethodGet, "/api/cluster", "")
	var out struct {
		Shared []struct {
			IP     string `json:"ip"`
			Events int64  `json:"events"`
			Nodes  int    `json:"nodes"`
		} `json:"shared_attackers"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
		t.Fatalf("GET /api/cluster: %d %s", rec.Code, rec.Body.String())
	}
	if len(out.Shared) != 2 || out.Shared[0].IP != "198.51.100.7" || out.Shared[0].Events != 40 || out.Shared[0].Nodes != 1 {
		t.Fatalf("shared attackers: %+v", out.Shared)
	}
}
