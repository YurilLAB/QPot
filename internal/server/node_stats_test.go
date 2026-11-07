package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// statsDB answers GetStats with fixed counts: day for a window of an hour or
// more, recent for a shorter one; err fails every call.
type statsDB struct {
	*fakeDB
	day, recent database.Stats
	err         error
}

func (d *statsDB) GetStats(_ context.Context, since time.Time) (*database.Stats, error) {
	if d.err != nil {
		return nil, d.err
	}
	if time.Since(since) >= time.Hour {
		return &d.day, nil
	}
	return &d.recent, nil
}

// TestNodeStatsReachTheCluster: this node's uptime and events go to the
// running cluster, so the Pairing tab, the group totals and, by gossip, the
// other nodes see them. Nothing called UpdateNodeStats, and every node showed
// "0m" and 0 events however long it had run.
func TestNodeStatsReachTheCluster(t *testing.T) {
	a := newAPITestServer(t, "api-node-stats", nil)
	withTestCluster(t, a.s)
	db := &statsDB{fakeDB: &fakeDB{}, day: database.Stats{TotalEvents: 2535}, recent: database.Stats{UniqueIPs: 7}}
	a.s.database = db
	a.s.startedAt = time.Now().Add(-77 * time.Second)

	type node struct {
		Name          string `json:"name"`
		IsLocal       bool   `json:"is_local"`
		UptimeSecs    int64  `json:"uptime_seconds"`
		TotalEvents   int64  `json:"total_events"`
		ActiveAttacks int64  `json:"active_attacks"`
	}
	nodes := func() map[string]node {
		t.Helper()
		rec := a.do(http.MethodGet, "/api/cluster", "")
		var out struct {
			Nodes []node `json:"nodes"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("GET /api/cluster: %d %s", rec.Code, rec.Body.String())
		}
		m := map[string]node{}
		for _, n := range out.Nodes {
			m[n.Name] = n
		}
		return m
	}

	// Not running the cluster: nothing to update, and nothing panics.
	a.s.updateNodeStats(context.Background())

	a.s.SetCluster(a.s.cluster)
	a.s.updateNodeStats(context.Background())
	got := nodes()
	local, peer := got["sensor-1"], got["sensor-2"]
	if !local.IsLocal || local.UptimeSecs < 77 || local.TotalEvents != 2535 || local.ActiveAttacks != 7 {
		t.Fatalf("this node: %+v, want up 77 s or more, 2535 events, 7 active", local)
	}
	if peer.TotalEvents != 0 || peer.UptimeSecs != 0 {
		t.Fatalf("the peer took this node's stats: %+v", peer)
	}

	// A failing database keeps the last counts; the uptime still moves.
	db.err = errors.New("database down")
	a.s.startedAt = a.s.startedAt.Add(-time.Minute)
	a.s.updateNodeStats(context.Background())
	if local = nodes()["sensor-1"]; local.TotalEvents != 2535 || local.UptimeSecs < 137 {
		t.Fatalf("after a failed query: %+v, want the last 2535 events and up 137 s or more", local)
	}
}
