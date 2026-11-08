package cluster

import (
	"sort"
	"time"
)

const (
	// intelMaxAge is how old a node's shared intel may be and still count:
	// the control plane sends it every 30 s, so older intel is from a node
	// that stopped sending.
	intelMaxAge = 2 * time.Hour
	// maxIntelSources bounds the sources kept of one member's intel.
	maxIntelSources = 100
)

// SharedAttacker is a source IP in the cluster's shared intel: how many
// events the nodes counted from it in their last hour, and how many nodes
// saw it.
type SharedAttacker struct {
	IP     string `json:"ip"`
	Events int64  `json:"events"`
	Nodes  int    `json:"nodes"`
}

// SharedAttackers merges this node's intel and its members' (see
// UpdateThreatIntel and sync): the limit most active sources, those seen by
// the most nodes first. Intel older than intelMaxAge, or from a node that is
// no longer a member, is left out.
func (m *Manager) SharedAttackers(limit int) []SharedAttacker {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cluster == nil || limit <= 0 {
		return nil
	}
	now := time.Now()
	byIP := map[string]*SharedAttacker{}
	add := func(in *ThreatIntel) {
		if in == nil || now.Sub(in.Timestamp) > intelMaxAge {
			return
		}
		seen := map[string]bool{}
		for _, ip := range in.TopSourceIPs {
			if ip.IP == "" || ip.Count <= 0 {
				continue
			}
			a := byIP[ip.IP]
			if a == nil {
				a = &SharedAttacker{IP: ip.IP}
				byIP[ip.IP] = a
			}
			a.Events += ip.Count
			if !seen[ip.IP] {
				seen[ip.IP] = true
				a.Nodes++
			}
		}
	}
	add(m.localIntel)
	for id, in := range m.peerIntel {
		if n, ok := m.cluster.Nodes[id]; ok && n.Status != NodeStatusLeft && !m.revokedLocked(id) {
			add(in)
		}
	}
	out := make([]SharedAttacker, 0, len(byIP))
	for _, a := range byIP {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Nodes != out[j].Nodes {
			return out[i].Nodes > out[j].Nodes
		}
		if out[i].Events != out[j].Events {
			return out[i].Events > out[j].Events
		}
		return out[i].IP < out[j].IP
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
