package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/qpot/qpot/internal/cluster"
)

const (
	// clusterIntelSources is how many of its most active sources of the last
	// hour this node shares with its cluster.
	clusterIntelSources = 20
	// sharedAttackersShown is how many of the cluster's shared sources
	// GET /api/cluster lists.
	sharedAttackersShown = 20
)

// updateClusterIntel gives the running cluster this node's most active
// sources of the last hour, which sync shares with the other members (the
// control plane calls it with the node stats, every nodeStatsInterval). A
// failed query keeps the last ones.
func (s *Server) updateClusterIntel(ctx context.Context, cm *cluster.Manager, now time.Time) {
	if s.database == nil {
		return
	}
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	top, err := s.database.GetTopAttackers(qctx, clusterIntelSources, now.Add(-time.Hour))
	if err != nil {
		slog.Debug("Cluster intel: failed to read the most active sources", "error", err)
		return
	}
	// The same source can come back once per country it was placed in.
	ips := make([]cluster.IPCount, 0, len(top))
	at := map[string]int{}
	for _, a := range top {
		if a == nil || a.SourceIP == "" || a.AttackCount <= 0 {
			continue
		}
		if i, ok := at[a.SourceIP]; ok {
			ips[i].Count += a.AttackCount
			continue
		}
		at[a.SourceIP] = len(ips)
		ips = append(ips, cluster.IPCount{IP: a.SourceIP, Count: a.AttackCount})
	}
	cm.UpdateThreatIntel(ips)
}
