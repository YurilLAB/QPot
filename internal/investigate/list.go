package investigate

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// List limits.
const (
	DefaultList = 100
	MaxList     = 500
	// listedSources is how many addresses a row shows.
	listedSources = 5
)

// SessionRow is one stored session in a listing.
type SessionRow struct {
	SessionID   string    `json:"session_id"`
	Campaign    string    `json:"campaign_fingerprint"`
	Sources     []string  `json:"source_ips"`
	MoreSources int       `json:"more_source_ips,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Events      int64     `json:"event_count"`
	Techniques  []string  `json:"techniques"`
	KillChain   []string  `json:"kill_chain_stages"`
	Confidence  float64   `json:"confidence"`
	Shared      bool      `json:"shared_infrastructure"`
	// CampaignSessions is how many of the sessions looked through carry
	// this session's campaign fingerprint, itself included.
	CampaignSessions int `json:"campaign_sessions"`
}

// CampaignRow is one campaign in a listing: the sessions that carry one
// fingerprint.
type CampaignRow struct {
	Fingerprint string    `json:"campaign_fingerprint"`
	Sessions    int       `json:"sessions"`
	Sources     []string  `json:"source_ips"`
	MoreSources int       `json:"more_source_ips,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Events      int64     `json:"event_count"`
	Techniques  []string  `json:"techniques"`
	Confidence  float64   `json:"confidence"`
}

// Listing is what there is to investigate: the most recent sessions, and
// the campaigns they form.
type Listing struct {
	Sessions  []SessionRow  `json:"sessions"`
	Campaigns []CampaignRow `json:"campaigns"`
	// Scanned is how many stored sessions were looked through; More is true
	// when there may be older ones.
	Scanned int  `json:"scanned"`
	More    bool `json:"more"`
}

// List returns the limit most recently active sessions and the limit most
// recently active campaigns with more than one session.
func List(ctx context.Context, db Reader, limit int) (*Listing, error) {
	switch {
	case limit <= 0:
		limit = DefaultList
	case limit > MaxList:
		limit = MaxList
	}
	sessions, err := db.GetTTPSessions(ctx, SessionScan)
	if err != nil {
		return nil, fmt.Errorf("investigate: read sessions: %w", err)
	}
	out := &Listing{Sessions: []SessionRow{}, Campaigns: []CampaignRow{}, Scanned: len(sessions), More: len(sessions) >= SessionScan}
	type group struct {
		row        CampaignRow
		sources    *set
		techniques *set
	}
	groups := map[string]*group{}
	var order []string
	for _, s := range sessions {
		if s == nil || s.CampaignFingerprint == "" {
			continue
		}
		g := groups[s.CampaignFingerprint]
		if g == nil {
			g = &group{row: CampaignRow{Fingerprint: s.CampaignFingerprint, FirstSeen: s.FirstSeen, LastSeen: s.LastSeen}, sources: newSet(), techniques: newSet()}
			groups[s.CampaignFingerprint] = g
			order = append(order, s.CampaignFingerprint)
		}
		g.row.Sessions++
		g.row.Events += s.EventCount
		if s.FirstSeen.Before(g.row.FirstSeen) {
			g.row.FirstSeen = s.FirstSeen
		}
		if s.LastSeen.After(g.row.LastSeen) {
			g.row.LastSeen = s.LastSeen
		}
		if s.Confidence > g.row.Confidence {
			g.row.Confidence = s.Confidence
		}
		g.sources.add(s.SourceIPs...)
		g.techniques.add(s.Techniques...)
	}
	for _, s := range sessions {
		if s == nil {
			continue
		}
		if len(out.Sessions) >= limit {
			break
		}
		row := SessionRow{SessionID: s.SessionID, Campaign: s.CampaignFingerprint, FirstSeen: s.FirstSeen, LastSeen: s.LastSeen,
			Events: s.EventCount, Techniques: orEmpty(s.Techniques), KillChain: orEmpty(s.KillChainStages), Confidence: s.Confidence,
			Shared: s.SharedInfrastructure, CampaignSessions: 1}
		row.Sources = orEmpty(s.SourceIPs)
		if len(row.Sources) > listedSources {
			row.MoreSources = len(row.Sources) - listedSources
			row.Sources = row.Sources[:listedSources]
		}
		if g := groups[s.CampaignFingerprint]; g != nil {
			row.CampaignSessions = g.row.Sessions
		}
		out.Sessions = append(out.Sessions, row)
	}
	for _, fp := range order {
		g := groups[fp]
		if g.row.Sessions < 2 {
			continue
		}
		g.row.Sources, g.row.MoreSources = g.sources.first(listedSources)
		g.row.Techniques, _ = g.techniques.first(maxListed)
		out.Campaigns = append(out.Campaigns, g.row)
	}
	sort.SliceStable(out.Campaigns, func(i, j int) bool {
		a, b := out.Campaigns[i], out.Campaigns[j]
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		return a.Fingerprint < b.Fingerprint
	})
	if len(out.Campaigns) > limit {
		out.Campaigns = out.Campaigns[:limit]
	}
	return out, nil
}

func orEmpty(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

// compile-time check that the database satisfies Reader.
var _ Reader = database.Database(nil)
