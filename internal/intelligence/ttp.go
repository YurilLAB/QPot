package intelligence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/durablejson"
)

// A TTP session is one activity episode of one source: every event from an
// IPv4 address (or an IPv6 /64) until the source has been quiet for the
// inactivity window, whatever it ran and whichever honeypots it reached. What
// a source does never decides which session its events join.
//
// Campaign attribution is separate. Sessions of different sources get the same
// CampaignFingerprint only when they share strong evidence:
//
//   - a payload: the SHA-256 of a file the source downloaded or uploaded;
//   - payload infrastructure: a host a URL in its input points at;
//   - a command sequence: its first sequenceCommands distinct shell commands,
//     in order.
//
// Links are transitive (A shares a host with B, B a payload with C: one
// campaign) and are recomputed from the sessions' evidence, so the result does
// not depend on the order events arrive in. A user agent or a credential pair
// never links sources; shared inside an already linked campaign it only raises
// confidence a little. A session with no strong evidence is a campaign of its
// own, named after its source.

// Limits on the state attacker input can grow.
const (
	// maxSessionIPs bounds the source addresses one session lists: the
	// addresses seen inside one IPv6 /64.
	maxSessionIPs = 10000
	// sequenceCommands is how many distinct shell commands make a command
	// sequence. A short run of reconnaissance ("uname -a", "id", "whoami") is
	// typed by unrelated people and tools in the same order every day, so it
	// must not link them; five identical commands in the same order are a
	// script. One common command can therefore never link two sources.
	sequenceCommands = 5
	// maxSessionEvidence bounds the hosts and payload hashes one session
	// keeps; the earliest seen are kept.
	maxSessionEvidence = 32
	// maxSessionWeak bounds the user agents and credential pairs one session
	// keeps for corroboration.
	maxSessionWeak = 8
	// maxEvidenceEntries and maxWeakEntries bound those entries across all
	// sessions. At the limit new entries are not recorded until sessions
	// expire: the sources are still tracked, they are just not linked.
	maxEvidenceEntries = 200000
	maxWeakEntries     = 100000
	// maxActiveSessions bounds the open sessions kept after a flush. Above it
	// the sessions quiet the longest are closed early, as if they had expired.
	maxActiveSessions = 100000
)

// Confidence values; see campaignConfidence.
const (
	confidenceUnknownSource = 0.1
	confidenceSharedSource  = 0.3
	confidenceSingleSource  = 0.5
	weightSharedPayload     = 0.8
	weightSharedHost        = 0.7
	weightSharedSequence    = 0.5
	weightCorroboration     = 0.2
	maxConfidence           = 0.95
)

// evidenceKinds is the set of strong evidence kinds a session shares with at
// least one other source.
type evidenceKinds uint8

const (
	sharedPayload evidenceKinds = 1 << iota
	sharedHost
	sharedSequence
)

// campaignConfidence says how strong the evidence is that a session's events
// belong to one campaign. It never depends on how many events there are.
//
//   - unknownSource: the events had no usable source address and share only a
//     honeypot, so nothing ties them together: 0.1.
//   - One source, tied together only by coming from the same address: 0.5,
//     or 0.3 when the address is shared infrastructure (cloud, NAT, VPN),
//     where one address is not one actor.
//   - Each kind of strong evidence the session shares with another source is
//     independent support (noisy-OR): the remaining doubt is multiplied by
//     0.2 for a payload, 0.3 for a download host, 0.5 for a command sequence.
//   - corroborated: a user agent or credential pair shared with another
//     source of the same campaign multiplies the doubt by 0.8. It counts only
//     on top of strong evidence.
//
// The result is capped at 0.95: none of this is proof.
func campaignConfidence(unknownSource, sharedInfrastructure bool, shared evidenceKinds, corroborated bool) float64 {
	if unknownSource {
		return confidenceUnknownSource
	}
	doubt := 1 - confidenceSingleSource
	if sharedInfrastructure {
		doubt = 1 - confidenceSharedSource
	}
	if shared&sharedPayload != 0 {
		doubt *= 1 - weightSharedPayload
	}
	if shared&sharedHost != 0 {
		doubt *= 1 - weightSharedHost
	}
	if shared&sharedSequence != 0 {
		doubt *= 1 - weightSharedSequence
	}
	if shared != 0 && corroborated {
		doubt *= 1 - weightCorroboration
	}
	// Two decimals: the weights are not known any more precisely, and it
	// keeps 1-(1-0.3) from being stored as 0.30000000000000004.
	return min(math.Round((1-doubt)*100)/100, maxConfidence)
}

// Hash domains: one per use, so a value hashed for one purpose can never equal
// a value hashed for another.
const (
	domainSession          = "qpot/ttp/session"
	domainCampaignSource   = "qpot/ttp/campaign/source"
	domainCampaignEvidence = "qpot/ttp/campaign/evidence"
	domainHost             = "qpot/ttp/evidence/host"
	domainPayload          = "qpot/ttp/evidence/payload"
	domainCommand          = "qpot/ttp/evidence/command"
	domainSequence         = "qpot/ttp/evidence/sequence"
	domainUserAgent        = "qpot/ttp/weak/user-agent"
	domainCredential       = "qpot/ttp/weak/credential"
)

// Evidence keys are a kind prefix and a hash128, so attacker-chosen text of
// any length costs a fixed 34 bytes.
const (
	kindPayload  = "p:"
	kindHost     = "h:"
	kindSequence = "s:"
)

// emptySHA256 is the SHA-256 of no bytes: an empty download identifies no
// payload, and every failed fetch would share it.
const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// unknownSourcePrefix and legacyPrefix name the sessions that are not keyed
// by a source address. Neither can be the text of an address or a prefix.
const (
	unknownSourcePrefix = "unknown:"
	legacyPrefix        = "legacy:"
	// sharedSourcePrefix names the session of one honeypot connection whose
	// source address is not the visitor's (see SharedSource).
	sharedSourcePrefix = "shared:"
)

// SharedSourceKey is the metadata key the collector sets on an event whose
// source address is inside one of the instance's own Docker networks: the
// address of Docker's port proxy or bridge, which every visitor Docker
// forwarded that way arrives from (a connection from the host itself, a
// Docker without its packet-filter rules, rootless Docker, Docker Desktop).
// Such an address says nothing about who connected.
const SharedSourceKey = database.SharedSourceKey

// maxSharedSessionID bounds the honeypot's own session ID in a session key.
const maxSharedSessionID = 64

// SharedSource reports whether the event's source address is a shared one.
func SharedSource(event *database.Event) bool {
	return event != nil && event.Metadata[SharedSourceKey] != ""
}

// hash128 returns the first 128 bits of the SHA-256 of the parts under a
// domain, as 32 hex characters. The domain and each part are written as
// "<length>:<bytes>", so ("ab", "c") and ("a", "bc") differ.
func hash128(domain string, parts ...string) string {
	h := sha256.New()
	var n [20]byte
	write := func(p string) {
		_, _ = h.Write(append(strconv.AppendInt(n[:0], int64(len(p)), 10), ':'))
		_, _ = h.Write([]byte(p))
	}
	write(domain)
	for _, p := range parts {
		write(p)
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// sessionSource returns the key of the session an event belongs to. An IPv4
// address is its own source; an IPv6 address counts as its /64, the smallest
// prefix a single host is routinely given (the convention the proxy's limiter
// and cells use); IPv4-mapped IPv6 is the IPv4 address. An event with no
// usable address (empty, unparseable, or the collector's 0.0.0.0 / ::
// placeholder) goes to one "unknown source" session per honeypot, and known is
// false: that session is a bucket, not an actor.
//
// A shared source address (SharedSource) is not a source at all: every
// visitor would land in one session, and one campaign. Such an event is keyed
// by the honeypot's own session ID, which separates the connections, or goes
// to the unknown bucket when the honeypot gives none.
func sessionSource(event *database.Event) (key string, known bool) {
	if SharedSource(event) {
		if id := event.Metadata["session"]; id != "" {
			if len(id) > maxSharedSessionID {
				id = id[:maxSharedSessionID]
			}
			return sharedSourcePrefix + event.Honeypot + "/" + id, true
		}
		return unknownSourcePrefix + event.Honeypot, false
	}
	if a, err := netip.ParseAddr(event.SourceIP); err == nil {
		a = a.Unmap().WithZone("")
		switch {
		case a.IsUnspecified():
		case a.Is4():
			return a.String(), true
		default:
			if p, err := a.Prefix(64); err == nil {
				return p.String(), true
			}
		}
	}
	return unknownSourcePrefix + event.Honeypot, false
}

// sighting is an evidence key and the time of the earliest event showing it.
type sighting struct {
	Key string    `json:"key"`
	At  time.Time `json:"at"`
}

// earlier orders sightings by time, then key.
func earlier(a, b sighting) bool {
	if !a.At.Equal(b.At) {
		return a.At.Before(b.At)
	}
	return a.Key < b.Key
}

// addEarliest records a sighting of key in list, which holds at most limit
// sightings in earlier order: the limit earliest of all the keys it was given,
// whatever order they came in. A list that may not grow (the builder is at its
// total limit) only replaces. It returns the list and the change in its length.
func addEarliest(list []sighting, key string, at time.Time, limit int, grow bool) ([]sighting, int) {
	n := len(list)
	for i := range list {
		if list[i].Key == key {
			if !at.Before(list[i].At) {
				return list, 0
			}
			list = append(list[:i], list[i+1:]...) // re-inserted below, earlier
			break
		}
	}
	entry := sighting{Key: key, At: at}
	pos := sort.Search(len(list), func(i int) bool { return !earlier(list[i], entry) })
	if len(list) >= limit || (len(list) == n && !grow) {
		if pos >= len(list) {
			return list, 0
		}
		list = list[:len(list)-1]
	}
	list = append(list, sighting{})
	copy(list[pos+1:], list[pos:])
	list[pos] = entry
	return list, len(list) - n
}

// addSmallest records key in the sorted list, which holds the limit smallest
// keys it was given. It returns the list and the change in its length.
func addSmallest(list []string, key string, limit int, grow bool) ([]string, int) {
	pos := sort.SearchStrings(list, key)
	if pos < len(list) && list[pos] == key {
		return list, 0
	}
	n := len(list)
	if n >= limit || !grow {
		if pos >= n {
			return list, 0
		}
		list = list[:n-1]
	}
	list = append(list, "")
	copy(list[pos+1:], list[pos:])
	list[pos] = key
	return list, len(list) - n
}

// sessionState is one open session and the evidence it has shown.
type sessionState struct {
	session *database.TTPSession
	// source is the session's key in TTPBuilder.sessions.
	source string
	// unknown marks a honeypot's "unknown source" bucket. It holds events of
	// any number of actors, so it carries no evidence and links to nothing.
	unknown bool
	// legacy marks a session restored from a format-0 checkpoint. Those were
	// keyed by behaviour, not by source, so no new event can join one: it
	// keeps its stored ID, fingerprint and confidence until it expires.
	legacy   bool
	evidence []sighting // download hosts and payload hashes
	commands []sighting // the earliest distinct shell commands
	weak     []string   // user agents and credential pairs, hashed
	lastSeen time.Time
	// sourceCampaign caches the fingerprint the session has without evidence.
	sourceCampaign string
}

// strong returns the session's strong evidence: its hosts and payloads, and
// its command sequence once it has sequenceCommands distinct commands. The
// sequence is dated by its last command. The result may alias s.evidence.
func (s *sessionState) strong() []sighting {
	if len(s.commands) < sequenceCommands {
		return s.evidence
	}
	keys := make([]string, len(s.commands))
	for i, c := range s.commands {
		keys[i] = c.Key
	}
	out := append(make([]sighting, 0, len(s.evidence)+1), s.evidence...)
	return append(out, sighting{Key: kindSequence + hash128(domainSequence, keys...), At: s.commands[len(s.commands)-1].At})
}

// retainedEvidence is the evidence of a source's expired sessions. It is kept
// while the campaign it belongs to still has an open session, so the campaign
// keeps its fingerprint and its sessions their confidence when the first
// members expire.
type retainedEvidence struct {
	Strong   []sighting `json:"strong"`
	Weak     []string   `json:"weak,omitempty"`
	LastSeen time.Time  `json:"last_seen"`
}

// checkpointFormat is the version of builderCheckpoint. Format 0 is the
// unversioned map[fingerprint]session the builder wrote before.
const checkpointFormat = 1

// builderCheckpoint is the builder's complete state as stored in the worker's
// durable checkpoint. Fields are exported only for JSON encoding.
type builderCheckpoint struct {
	Format   int                          `json:"format"`
	Sessions map[string]sessionCheckpoint `json:"sessions"`
	Retained map[string]*retainedEvidence `json:"retained,omitempty"`
}

// sessionCheckpoint preserves a session's complete accumulator, not just its
// public projection. The map key it is stored under is its source key.
type sessionCheckpoint struct {
	Session  *database.TTPSession `json:"session"`
	Unknown  bool                 `json:"unknown,omitempty"`
	Legacy   bool                 `json:"legacy,omitempty"`
	Evidence []sighting           `json:"evidence,omitempty"`
	Commands []sighting           `json:"commands,omitempty"`
	Weak     []string             `json:"weak,omitempty"`
	LastSeen time.Time            `json:"last_seen"`
}

// legacySessionCheckpoint reads what a format-0 checkpoint is still needed
// for. Its other fields (usernames, tools, stems, honeypots, ips) were
// accumulated but never read.
type legacySessionCheckpoint struct {
	Session  *database.TTPSession `json:"session"`
	LastSeen time.Time            `json:"last_seen"`
}

func (b *TTPBuilder) checkpoint() ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.resolveLocked()
	state := builderCheckpoint{
		Format:   checkpointFormat,
		Sessions: make(map[string]sessionCheckpoint, len(b.sessions)),
		Retained: b.retained,
	}
	for key, s := range b.sessions {
		state.Sessions[key] = sessionCheckpoint{s.session, s.unknown, s.legacy, s.evidence, s.commands, s.weak, s.lastSeen}
	}
	return durablejson.Marshal(state)
}

// restoreCheckpoint replaces the builder's state with a checkpoint's. A
// format-0 checkpoint (written before sessions were keyed by source) restores
// too: its sessions are carried as they are until they expire.
func (b *TTPBuilder) restoreCheckpoint(data []byte) error {
	sessions := make(map[string]*sessionState)
	retained := make(map[string]*retainedEvidence)
	if len(data) > 0 {
		var probe struct {
			Format *int `json:"format"`
		}
		if err := durablejson.Unmarshal(data, &probe); err != nil {
			return fmt.Errorf("decode intelligence session checkpoint: %w", err)
		}
		switch {
		case probe.Format == nil:
			var old map[string]legacySessionCheckpoint
			if err := durablejson.Unmarshal(data, &old); err != nil {
				return fmt.Errorf("decode intelligence session checkpoint: %w", err)
			}
			for fp, c := range old {
				if c.Session == nil || c.Session.SessionID == "" || c.Session.CampaignFingerprint != fp {
					return fmt.Errorf("invalid intelligence session checkpoint for %q", fp)
				}
				key := legacyPrefix + fp
				sessions[key] = &sessionState{session: c.Session, source: key, legacy: true, lastSeen: c.LastSeen}
			}
		case *probe.Format == checkpointFormat:
			var state builderCheckpoint
			if err := durablejson.Unmarshal(data, &state); err != nil {
				return fmt.Errorf("decode intelligence session checkpoint: %w", err)
			}
			for key, c := range state.Sessions {
				if key == "" || c.Session == nil || c.Session.SessionID == "" {
					return fmt.Errorf("invalid intelligence session checkpoint for %q", key)
				}
				s := &sessionState{session: c.Session, source: key, unknown: c.Unknown, legacy: c.Legacy, lastSeen: c.LastSeen}
				if !s.unknown && !s.legacy {
					// Re-adding restores the lists' order and limits whatever
					// the stored JSON holds.
					s.evidence = restoreSightings(c.Evidence, maxSessionEvidence)
					s.commands = restoreSightings(c.Commands, sequenceCommands)
					s.weak = restoreWeak(c.Weak)
					if !slices.IsSorted(s.session.SourceIPs) {
						slices.Sort(s.session.SourceIPs)
						s.session.SourceIPs = slices.Compact(s.session.SourceIPs)
					}
				}
				sessions[key] = s
			}
			for key, g := range state.Retained {
				if g == nil {
					continue
				}
				kept := &retainedEvidence{Strong: restoreSightings(g.Strong, maxSessionEvidence+1), Weak: restoreWeak(g.Weak), LastSeen: g.LastSeen}
				if len(kept.Strong) > 0 {
					retained[key] = kept
				}
			}
		default:
			return fmt.Errorf("unsupported intelligence session checkpoint format %d", *probe.Format)
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sessions, b.retained = sessions, retained
	b.strongEntries, b.weakEntries, b.retainedStrong, b.retainedWeak = 0, 0, 0, 0
	for _, s := range sessions {
		b.strongEntries += len(s.evidence) + len(s.commands)
		b.weakEntries += len(s.weak)
	}
	for _, g := range retained {
		b.retainedStrong += len(g.Strong)
		b.retainedWeak += len(g.Weak)
	}
	b.strongEntries += b.retainedStrong
	b.weakEntries += b.retainedWeak
	b.resolved = false
	return nil
}

func restoreSightings(stored []sighting, limit int) []sighting {
	var list []sighting
	for _, k := range stored {
		if k.Key != "" {
			list, _ = addEarliest(list, k.Key, k.At, limit, true)
		}
	}
	return list
}

func restoreWeak(stored []string) []string {
	var list []string
	for _, k := range stored {
		if k != "" {
			list, _ = addSmallest(list, k, maxSessionWeak, true)
		}
	}
	return list
}

// TTPBuilder groups events into per-source TTP sessions and attributes the
// sessions to campaigns; see the description at the top of this file.
type TTPBuilder struct {
	mu sync.Mutex
	// sessions holds the open sessions by source key (see sessionSource), or
	// by legacyPrefix and the old fingerprint for a session from a format-0
	// checkpoint.
	sessions map[string]*sessionState
	// retained holds the evidence of expired sessions, by source key.
	retained         map[string]*retainedEvidence
	inactivityWindow time.Duration

	// strongEntries and weakEntries count the evidence entries held by
	// sessions and retained evidence together; retainedStrong and
	// retainedWeak count the retained part.
	strongEntries, weakEntries   int
	retainedStrong, retainedWeak int
	// The limits, as fields so tests can lower them.
	maxEvidence, maxWeak, maxSessions int

	// resolved is false while an update, a flush or a restore has not been
	// followed by resolveLocked: the sessions' campaign fingerprints and
	// confidence are then out of date.
	resolved bool
}

// NewTTPBuilder creates a TTPBuilder with the given inactivity window.
func NewTTPBuilder(inactivityWindow time.Duration) *TTPBuilder {
	return &TTPBuilder{
		sessions:         make(map[string]*sessionState),
		retained:         make(map[string]*retainedEvidence),
		inactivityWindow: inactivityWindow,
		maxEvidence:      maxEvidenceEntries,
		maxWeak:          maxWeakEntries,
		maxSessions:      maxActiveSessions,
	}
}

// Update adds an event to its source's session, opening one when the source
// has none. It returns the session's ID and whether the session is new. The
// session's campaign fingerprint and confidence, and those of every session
// the event links it to, are brought up to date by the next
// GetActiveSessions, which is what the caller persists.
func (b *TTPBuilder) Update(event *database.Event) (sessionID string, isNew bool) {
	ts := event.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	source, known := sessionSource(event)

	b.mu.Lock()
	defer b.mu.Unlock()

	s := b.sessions[source]
	if s == nil {
		// The session ID names this activity episode, not the source or the
		// campaign: once a session expires and is flushed, the same source
		// returning later starts a new session, which must not overwrite the
		// stored one (all backends upsert by ID). It never changes afterwards,
		// whatever the session is later linked to.
		s = &sessionState{
			session: &database.TTPSession{
				SessionID: fmt.Sprintf("%s-%d", hash128(domainSession, source), ts.UnixNano()),
				FirstSeen: ts,
				LastSeen:  ts,
			},
			source:   source,
			unknown:  !known,
			lastSeen: ts,
		}
		b.sessions[source] = s
		isNew = true
	}
	b.resolved = false

	if ts.Before(s.session.FirstSeen) {
		s.session.FirstSeen = ts
	}
	if ts.After(s.session.LastSeen) {
		s.session.LastSeen = ts
	}
	if ts.After(s.lastSeen) {
		s.lastSeen = ts
	}
	s.session.EventCount++
	if event.TechniqueID != "" {
		addUnique(&s.session.Techniques, event.TechniqueID)
	}
	if event.KillChainStage != "" {
		addUnique(&s.session.KillChainStages, event.KillChainStage)
	}
	if known {
		if SharedSource(event) {
			// Docker's address is no one's: it is not listed as the
			// session's source, and the session says its source is shared.
			s.session.SharedInfrastructure = true
		} else {
			// The list stays sorted and holds the maxSessionIPs smallest
			// addresses, so a repeat sighting costs a binary search and the
			// result does not depend on arrival order.
			s.session.SourceIPs, _ = addSmallest(s.session.SourceIPs, event.SourceIP, maxSessionIPs, true)
			// Any shared address makes the session shared, whichever event
			// shows it first.
			if isSharedInfrastructure(event.SourceIP) {
				s.session.SharedInfrastructure = true
			}
		}
		b.observe(s, event, ts)
	}
	return s.session.SessionID, isNew
}

// observe records the evidence an event shows.
func (b *TTPBuilder) observe(s *sessionState, event *database.Event, ts time.Time) {
	strong := func(list *[]sighting, key string, limit int) {
		var grown int
		*list, grown = addEarliest(*list, key, ts, limit, b.strongEntries < b.maxEvidence)
		b.strongEntries += grown
	}
	weak := func(key string) {
		var grown int
		s.weak, grown = addSmallest(s.weak, key, maxSessionWeak, b.weakEntries < b.maxWeak)
		b.weakEntries += grown
	}
	host := func(_, h string) {
		// A private or loopback host is each victim's own, not shared
		// infrastructure; hostIOC drops those and anything that is no host.
		if typ, v := hostIOC(h); typ != "" {
			strong(&s.evidence, kindHost+hash128(domainHost, v), maxSessionEvidence)
		}
	}

	// The command field of an NSM sensor is its own text, not attacker input.
	if event.Command != "" && !sensorText(event) {
		eachLocation(refang(event.Command), host)
		if isCommandEvent(event.EventType) {
			// Whitespace is all that is normalised: the same script sends the
			// same text, and anything looser would link different ones.
			if cmd := strings.Join(strings.Fields(event.Command), " "); cmd != "" {
				strong(&s.commands, hash128(domainCommand, cmd), sequenceCommands)
			}
		}
	}
	if text := payloadLocationText(event); text != "" {
		eachLocation(text, host)
	}
	if h := payloadSHA256(event); h != "" && h != emptySHA256 {
		strong(&s.evidence, kindPayload+hash128(domainPayload, h), maxSessionEvidence)
	}

	if ua := event.Metadata["user_agent"]; ua != "" {
		weak(hash128(domainUserAgent, ua))
	}
	if event.Username != "" && event.Password != "" {
		weak(hash128(domainCredential, event.Username, event.Password))
	}
}

// GetActiveSessions returns a snapshot of every open session, with campaign
// fingerprints and confidence up to date. A session whose fingerprint or
// confidence changed because another source linked to it is in the snapshot
// like any other, so a caller that persists the snapshot persists the change.
func (b *TTPBuilder) GetActiveSessions() []*database.TTPSession {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.resolveLocked()

	// Return independent DEEP copies, not the live *TTPSession pointers. The
	// worker goroutine mutates those objects (and their slices) under the
	// lock; handing out the live pointers would let a caller read them after
	// the lock is released and race the worker.
	result := make([]*database.TTPSession, 0, len(b.sessions))
	for _, s := range b.sessions {
		cp := *s.session
		cp.SourceIPs = append([]string(nil), s.session.SourceIPs...)
		cp.KillChainStages = append([]string(nil), s.session.KillChainStages...)
		cp.Techniques = append([]string(nil), s.session.Techniques...)
		cp.IOCIDs = append([]string(nil), s.session.IOCIDs...)
		result = append(result, &cp)
	}
	return result
}

// FlushExpired removes and returns the sessions that have been inactive
// longer than inactivityWindow and, when more than the session limit remain,
// the ones quiet the longest. Call it only once the open sessions have been
// persisted (the worker persists them with every batch): a removed session's
// evidence stays linked to its campaign, but the session itself is gone.
func (b *TTPBuilder) FlushExpired() []*database.TTPSession {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.resolveLocked() // a session leaves with its final attribution

	cutoff := time.Now().UTC().Add(-b.inactivityWindow)
	var expired, open []string
	for key, s := range b.sessions {
		if s.lastSeen.Before(cutoff) {
			expired = append(expired, key)
		} else {
			open = append(open, key)
		}
	}
	if over := len(open) - b.maxSessions; over > 0 {
		sort.Slice(open, func(i, j int) bool {
			a, c := b.sessions[open[i]].lastSeen, b.sessions[open[j]].lastSeen
			if !a.Equal(c) {
				return a.Before(c)
			}
			return open[i] < open[j]
		})
		expired = append(expired, open[:over]...)
	}
	if len(expired) == 0 {
		return nil
	}
	result := make([]*database.TTPSession, 0, len(expired))
	for _, key := range expired {
		result = append(result, b.sessions[key].session)
		b.retire(key)
	}
	// Drop the retained evidence of campaigns that have no open session left,
	// then keep what remains within half the evidence limit, oldest out
	// first, so open sessions always have room for theirs.
	b.resolved = false
	b.resolveLocked()
	if b.retainedStrong > b.maxEvidence/2 {
		oldest := make([]string, 0, len(b.retained))
		for key := range b.retained {
			oldest = append(oldest, key)
		}
		sort.Slice(oldest, func(i, j int) bool {
			a, c := b.retained[oldest[i]].LastSeen, b.retained[oldest[j]].LastSeen
			if !a.Equal(c) {
				return a.Before(c)
			}
			return oldest[i] < oldest[j]
		})
		for _, key := range oldest {
			if b.retainedStrong <= b.maxEvidence/2 {
				break
			}
			b.dropRetained(key)
		}
		b.resolved = false
	}
	return result
}

// retire removes a session and keeps its evidence as retained evidence of its
// source.
func (b *TTPBuilder) retire(key string) {
	s := b.sessions[key]
	delete(b.sessions, key)
	b.strongEntries -= len(s.evidence) + len(s.commands)
	b.weakEntries -= len(s.weak)
	strong := s.strong()
	if len(strong) == 0 {
		return
	}
	g := b.retained[key]
	if g == nil {
		g = &retainedEvidence{}
		b.retained[key] = g
	}
	if s.lastSeen.After(g.LastSeen) {
		g.LastSeen = s.lastSeen
	}
	had := len(g.Strong)
	for _, k := range strong {
		g.Strong, _ = addEarliest(g.Strong, k.Key, k.At, maxSessionEvidence+1, true)
	}
	b.strongEntries += len(g.Strong) - had
	b.retainedStrong += len(g.Strong) - had
	// Retained corroboration may use half the weak limit; past it the
	// evidence is retained without.
	if b.retainedWeak+len(s.weak) <= b.maxWeak/2 {
		had = len(g.Weak)
		for _, k := range s.weak {
			g.Weak, _ = addSmallest(g.Weak, k, maxSessionWeak, true)
		}
		b.weakEntries += len(g.Weak) - had
		b.retainedWeak += len(g.Weak) - had
	}
}

func (b *TTPBuilder) dropRetained(key string) {
	g := b.retained[key]
	delete(b.retained, key)
	b.strongEntries -= len(g.Strong)
	b.retainedStrong -= len(g.Strong)
	b.weakEntries -= len(g.Weak)
	b.retainedWeak -= len(g.Weak)
}

// resolveLocked brings every session's campaign fingerprint and confidence
// up to date. It recomputes them from the evidence the open sessions and the
// retained evidence hold now, so the result is a function of that state alone
// and not of the order it was built in.
//
// The evidence keys form a union-find: the keys of one source are joined, so
// two sources are in the same set exactly when a chain of shared keys connects
// them. A campaign is named after the key seen earliest in its set (ties: the
// smaller key), which later evidence does not displace.
func (b *TTPBuilder) resolveLocked() {
	if b.resolved {
		return
	}
	b.resolved = true

	parent := make(map[string]string)   // union-find over strong evidence keys
	first := make(map[string]time.Time) // each key's earliest sighting
	holders := make(map[string]int)     // the number of sources showing each key
	find := func(k string) string {
		for parent[k] != k {
			parent[k] = parent[parent[k]]
			k = parent[k]
		}
		return k
	}

	// One view per source: its open session and its retained evidence
	// together, since both are the same source's.
	type sourceView struct {
		session *sessionState // nil when the source has only retained evidence
		strong  []sighting
		weak    []string
	}
	views := make([]sourceView, 0, len(b.sessions)+len(b.retained))
	hold := func(v sourceView) {
		for i, k := range v.strong {
			if at, seen := first[k.Key]; !seen {
				parent[k.Key] = k.Key
				first[k.Key] = k.At
			} else if k.At.Before(at) {
				first[k.Key] = k.At
			}
			holders[k.Key]++
			if i > 0 {
				if a, c := find(v.strong[0].Key), find(k.Key); a != c {
					parent[c] = a
				}
			}
		}
		views = append(views, v)
	}
	for key, s := range b.sessions {
		v := sourceView{session: s}
		if !s.legacy && !s.unknown {
			v.strong, v.weak = s.strong(), s.weak
			if g := b.retained[key]; g != nil {
				v.strong, v.weak = mergeSightings(v.strong, g.Strong), mergeWeak(v.weak, g.Weak)
			}
		}
		hold(v)
	}
	for key, g := range b.retained {
		if b.sessions[key] == nil {
			hold(sourceView{strong: g.Strong, weak: g.Weak})
		}
	}

	// A campaign is live while one of its sources has an open session.
	// Retained evidence of any other campaign has nothing left to link.
	live := make(map[string]bool)
	for _, v := range views {
		if v.session != nil && len(v.strong) > 0 {
			live[find(v.strong[0].Key)] = true
		}
	}
	for key, g := range b.retained {
		if len(g.Strong) == 0 || !live[find(g.Strong[0].Key)] {
			b.dropRetained(key)
		}
	}

	anchor := make(map[string]sighting) // each live campaign's earliest key
	for k, at := range first {
		root := find(k)
		if !live[root] {
			continue
		}
		if a, ok := anchor[root]; !ok || earlier(sighting{k, at}, a) {
			anchor[root] = sighting{k, at}
		}
	}

	// A user agent or credential pair corroborates only inside a campaign.
	type corroboration struct{ campaign, key string }
	weakHolders := make(map[corroboration]int)
	for _, v := range views {
		if len(v.strong) > 0 && len(v.weak) > 0 {
			root := find(v.strong[0].Key)
			if live[root] {
				for _, w := range v.weak {
					weakHolders[corroboration{root, w}]++
				}
			}
		}
	}

	fingerprints := make(map[string]string, len(anchor))
	for _, v := range views {
		s := v.session
		if s == nil || s.legacy {
			continue
		}
		var shared evidenceKinds
		corroborated := false
		if len(v.strong) == 0 {
			if s.sourceCampaign == "" {
				s.sourceCampaign = hash128(domainCampaignSource, s.source)
			}
			s.session.CampaignFingerprint = s.sourceCampaign
		} else {
			root := find(v.strong[0].Key)
			fp := fingerprints[root]
			if fp == "" {
				fp = hash128(domainCampaignEvidence, anchor[root].Key)
				fingerprints[root] = fp
			}
			s.session.CampaignFingerprint = fp
			for _, k := range v.strong {
				if holders[k.Key] > 1 {
					switch {
					case strings.HasPrefix(k.Key, kindPayload):
						shared |= sharedPayload
					case strings.HasPrefix(k.Key, kindHost):
						shared |= sharedHost
					case strings.HasPrefix(k.Key, kindSequence):
						shared |= sharedSequence
					}
				}
			}
			if shared != 0 {
				for _, w := range v.weak {
					if weakHolders[corroboration{root, w}] > 1 {
						corroborated = true
						break
					}
				}
			}
		}
		s.session.Confidence = campaignConfidence(s.unknown, s.session.SharedInfrastructure, shared, corroborated)
	}
}

// mergeSightings returns the union of two lists, each key at its earliest.
func mergeSightings(a, b []sighting) []sighting {
	out := append(make([]sighting, 0, len(a)+len(b)), a...)
next:
	for _, k := range b {
		for i := range out {
			if out[i].Key == k.Key {
				if k.At.Before(out[i].At) {
					out[i].At = k.At
				}
				continue next
			}
		}
		out = append(out, k)
	}
	return out
}

// mergeWeak returns the union of two lists of weak keys.
func mergeWeak(a, b []string) []string {
	out := append(make([]string, 0, len(a)+len(b)), a...)
	for _, k := range b {
		if !slices.Contains(a, k) {
			out = append(out, k)
		}
	}
	return out
}

// knownCloudCIDRs lists rough cloud provider and VPN prefix heuristics.
var knownCloudCIDRs []*net.IPNet

func init() {
	cidrs := []string{
		"3.0.0.0/8",      // AWS us-east-1 (rough)
		"13.0.0.0/8",     // Azure (rough)
		"35.0.0.0/8",     // GCP (rough)
		"34.0.0.0/8",     // GCP (rough)
		"52.0.0.0/8",     // AWS
		"54.0.0.0/8",     // AWS
		"18.0.0.0/8",     // AWS
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
