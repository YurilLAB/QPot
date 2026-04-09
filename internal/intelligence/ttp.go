package intelligence

import (
	"fmt"
	"hash/fnv"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// BehavioralFingerprint captures the behavioral signals of an attack campaign.
type BehavioralFingerprint struct {
	CredentialSetHash string   // FNV-1a hash of sorted unique usernames seen
	ToolSignatures    []string // unique download domains + user agents
	CommandStems      []string // first word of each unique command seen
	TargetHoneypots   []string // honeypots targeted
}

// sessionState tracks mutable session accumulation state.
type sessionState struct {
	session   *database.TTPSession
	usernames map[string]bool
	tools     map[string]bool
	stems     map[string]bool
	honeypots map[string]bool
	ips       map[string]bool
	lastSeen  time.Time
}

// TTPBuilder builds and updates TTP sessions using behavioral fingerprinting.
type TTPBuilder struct {
	mu               sync.RWMutex
	sessions         map[string]*sessionState // keyed by CampaignFingerprint
	inactivityWindow time.Duration
}

// NewTTPBuilder creates a TTPBuilder with the given inactivity window.
func NewTTPBuilder(inactivityWindow time.Duration) *TTPBuilder {
	return &TTPBuilder{
		sessions:         make(map[string]*sessionState),
		inactivityWindow: inactivityWindow,
	}
}

// Update incorporates an event into the appropriate TTP session.
// Returns the session (may be new or updated), and whether it is new.
func (b *TTPBuilder) Update(event *database.Event) (*database.TTPSession, bool) {
	fp := campaignFingerprint(event)

	b.mu.Lock()
	defer b.mu.Unlock()

	state, exists := b.sessions[fp]
	if !exists {
		now := event.Timestamp
		if now.IsZero() {
			now = time.Now().UTC()
		}
		sess := &database.TTPSession{
			SessionID:           fp,
			CampaignFingerprint: fp,
			FirstSeen:           now,
			LastSeen:            now,
			Confidence:          0.5,
		}
		state = &sessionState{
			session:   sess,
			usernames: make(map[string]bool),
			tools:     make(map[string]bool),
			stems:     make(map[string]bool),
			honeypots: make(map[string]bool),
			ips:       make(map[string]bool),
			lastSeen:  now,
		}
		b.sessions[fp] = state
	}

	updateState(state, event)
	rebuildSession(state)

	return state.session, !exists
}

// GetActiveSessions returns all currently active sessions.
func (b *TTPBuilder) GetActiveSessions() []*database.TTPSession {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make([]*database.TTPSession, 0, len(b.sessions))
	for _, s := range b.sessions {
		result = append(result, s.session)
	}
	return result
}

// FlushExpired returns sessions that have been inactive longer than
// inactivityWindow and removes them from the in-memory map.
// Caller is responsible for persisting them.
func (b *TTPBuilder) FlushExpired() []*database.TTPSession {
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := time.Now().UTC().Add(-b.inactivityWindow)
	var expired []*database.TTPSession
	for fp, s := range b.sessions {
		if s.lastSeen.Before(cutoff) {
			expired = append(expired, s.session)
			delete(b.sessions, fp)
		}
	}
	return expired
}

// updateState merges a new event into the session accumulator.
func updateState(s *sessionState, event *database.Event) {
	ts := event.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	if ts.After(s.lastSeen) {
		s.lastSeen = ts
	}
	if ts.After(s.session.LastSeen) {
		s.session.LastSeen = ts
	}
	s.session.EventCount++

	if event.SourceIP != "" {
		s.ips[event.SourceIP] = true
	}
	if event.Honeypot != "" {
		s.honeypots[event.Honeypot] = true
	}
	if event.Username != "" {
		s.usernames[event.Username] = true
	}
	if event.TechniqueID != "" {
		addUnique(&s.session.Techniques, event.TechniqueID)
	}
	if event.KillChainStage != "" {
		addUnique(&s.session.KillChainStages, event.KillChainStage)
	}

	// Tool signatures: domains from URLs in command + user agents
	if event.Command != "" {
		for _, u := range reURL.FindAllString(event.Command, -1) {
			if matches := reDomain.FindStringSubmatch(u); len(matches) > 1 {
				s.tools[strings.ToLower(matches[1])] = true
			}
		}
	}
	if event.Metadata != nil {
		if ua, ok := event.Metadata["user_agent"]; ok && ua != "" {
			s.tools[ua] = true
		}
	}

	// Command stems
	if event.Command != "" {
		parts := strings.Fields(event.Command)
		if len(parts) > 0 {
			s.stems[parts[0]] = true
		}
	}

	// Shared infrastructure detection
	s.session.SharedInfrastructure = isSharedInfrastructure(event.SourceIP)
}

// rebuildSession recomputes derived slice fields from accumulator state.
func rebuildSession(s *sessionState) {
	s.session.SourceIPs = sortedKeys(s.ips)

	// Confidence grows with event count, capped at 0.95.
	conf := 0.5 + float64(s.session.EventCount)*0.01
	if conf > 0.95 {
		conf = 0.95
	}
	s.session.Confidence = conf
}

// campaignFingerprint generates a stable fingerprint for grouping sessions.
// It is based on tool signatures + command stems. Falls back to source IP
// for pure brute-forcers that have neither.
func campaignFingerprint(event *database.Event) string {
	var tools []string
	var stems []string

	if event.Command != "" {
		for _, u := range reURL.FindAllString(event.Command, -1) {
			if matches := reDomain.FindStringSubmatch(u); len(matches) > 1 {
				tools = append(tools, strings.ToLower(matches[1]))
			}
		}
		parts := strings.Fields(event.Command)
		if len(parts) > 0 {
			stems = append(stems, parts[0])
		}
	}
	if event.Metadata != nil {
		if ua, ok := event.Metadata["user_agent"]; ok && ua != "" {
			tools = append(tools, ua)
		}
	}

	if len(tools) == 0 && len(stems) == 0 {
		// Fall back to source IP
		return fnvStr("ip:" + event.SourceIP)
	}

	sort.Strings(tools)
	sort.Strings(stems)
	raw := strings.Join(tools, "|") + "+" + strings.Join(stems, "|")
	return fnvStr(raw)
}

// fnvStr returns the hex-encoded FNV-1a 32-bit hash of s.
func fnvStr(s string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return fmt.Sprintf("%08x", h.Sum32())
}

// knownCloudCIDRs lists rough cloud provider and VPN prefix heuristics.
var knownCloudCIDRs []*net.IPNet

func init() {
	cidrs := []string{
		"3.0.0.0/8",    // AWS us-east-1 (rough)
		"13.0.0.0/8",   // Azure (rough)
		"35.0.0.0/8",   // GCP (rough)
		"34.0.0.0/8",   // GCP (rough)
		"52.0.0.0/8",   // AWS
		"54.0.0.0/8",   // AWS
		"18.0.0.0/8",   // AWS
		"104.196.0.0/14", // GCP
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			knownCloudCIDRs = append(knownCloudCIDRs, network)
		}
	}
}

// isSharedInfrastructure returns true if the IP looks like cloud/VPN.
func isSharedInfrastructure(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range knownCloudCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// addUnique appends v to *slice only if not already present.
func addUnique(slice *[]string, v string) {
	for _, existing := range *slice {
		if existing == v {
			return
		}
	}
	*slice = append(*slice, v)
}

// sortedKeys returns the sorted keys of a map[string]bool.
func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
