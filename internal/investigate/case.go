// Package investigate assembles what QPot recorded about one session or one
// campaign into a case an operator can follow: the activity in time order
// (connection, credentials, commands with their captured output, transferred
// files, canaries), the evidence that links sessions into a campaign, the
// related sessions, and whatever is missing or was cut.
//
// Nothing in a case is inferred beyond the stored records. Every step, file,
// link and gap names the records it rests on by reference (Record.Ref), and
// the case carries those records, so each conclusion can be checked against
// them; an exported bundle holds the same records with a manifest of hashes.
//
// A case is built from reads the database interface already offers, so it is
// the same on every backend. All work is bounded: a case reads at most
// Options.MaxEvents events for a session and says so when a session has more.
package investigate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/intelligence"
)

// Limits. A case is something a person reads: past these sizes it says what
// it left out instead of growing.
const (
	// DefaultMaxEvents is how many events of one session a case reads.
	DefaultMaxEvents = 5000
	// HardMaxEvents is the most Options.MaxEvents may ask for.
	HardMaxEvents = 50000
	// SessionScan is how many stored sessions, newest first, a case looks
	// through for the session or campaign asked for.
	SessionScan = 5000
	// MaxCampaignSessions is how many sessions of a campaign get a timeline.
	MaxCampaignSessions = 25
	// MaxRefs is how many records one step, link or gap names.
	MaxRefs = 20
	// MaxOutput is how many bytes of one command's captured stream a case
	// carries, and maxOutputTotal how many for the whole case.
	MaxOutput      = 64 << 10
	maxOutputTotal = 4 << 20
	// maxSourceFilter is the most source addresses a read filters by; a
	// session listing more is read by its time window alone.
	maxSourceFilter = 256
	// maxQueries bounds the database reads of one session.
	maxQueries = 2000
	// maxListed bounds the lists of a summary.
	maxListed = 50
	// maxSummary is how long a step's one-line summary may be.
	maxSummary = 400
)

// Phases of a timeline step, in the order an intrusion passes through them.
const (
	PhaseConnection  = "connection"
	PhaseCredentials = "credentials"
	PhaseCommand     = "command"
	PhaseTransfer    = "transfer"
	PhaseCanary      = "canary"
	PhaseClose       = "close"
	PhaseOther       = "other"
)

// phaseOrder is the order Summary.Reached lists phases in.
var phaseOrder = []string{PhaseConnection, PhaseCredentials, PhaseCommand, PhaseTransfer, PhaseCanary}

// Gap kinds: what a case could not show, or shows incompletely.
const (
	GapEventLimit       = "event-limit"
	GapEventsMissing    = "events-missing"
	GapValueCut         = "value-cut"
	GapLineDiscarded    = "line-discarded"
	GapCaptureCut       = "capture-cut"
	GapCaptureError     = "capture-error"
	GapOutputMissing    = "output-missing"
	GapOutputNotKept    = "output-not-captured"
	GapUnfinished       = "command-unfinished"
	GapUnclassified     = "unclassified"
	GapSharedSource     = "shared-source"
	GapUnknownSource    = "unknown-source"
	GapOldSession       = "old-session"
	GapSourceList       = "source-list"
	GapSessionLimit     = "session-limit"
	GapSessionScan      = "session-scan"
	GapNoSharedEvidence = "no-shared-evidence"
	GapCanaryUnmatched  = "canary-not-matched"
)

// ErrNotFound is returned for a session or campaign that is not among the
// stored sessions a case looks through.
var ErrNotFound = errors.New("not found among the stored sessions")

// Reader is the part of database.Database a case reads.
type Reader interface {
	GetEvents(ctx context.Context, filter database.EventFilter) ([]*database.Event, error)
	GetTTPSessions(ctx context.Context, limit int) ([]*database.TTPSession, error)
}

// OutputReader returns what a command printed, from the capture the honeypot
// kept outside the database. stream is "stdout" or "stderr". found is false
// when the event names no capture or the capture is gone; cut is true when
// only the first MaxOutput bytes were returned.
type OutputReader interface {
	Output(event *database.Event, stream string) (data []byte, cut, found bool, err error)
}

// Options bound and feed a case.
type Options struct {
	// MaxEvents is how many events of one session to read; DefaultMaxEvents
	// when zero, at most HardMaxEvents.
	MaxEvents int
	// Trips are the instance's canary trips; those from a session's source
	// are placed on its timeline.
	Trips []*canary.Trip
	// Output reads captured command output; nil shows none.
	Output OutputReader
	// Now is the case's time; time.Now when nil.
	Now func() time.Time
}

func (o Options) maxEvents() int {
	switch {
	case o.MaxEvents <= 0:
		return DefaultMaxEvents
	case o.MaxEvents > HardMaxEvents:
		return HardMaxEvents
	}
	return o.MaxEvents
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now().UTC()
	}
	return time.Now().UTC()
}

// Record is one stored event a case rests on.
type Record struct {
	// Ref names the record. It is the first 128 bits of a SHA-256 over the
	// fields the collector stored (RecordRef), so anyone holding the record
	// can recompute it, and it does not change when the event is classified.
	Ref string `json:"ref"`
	// SessionID is the session whose timeline the record is on.
	SessionID string          `json:"session_id"`
	Event     *database.Event `json:"event"`
}

// Output is what a command printed, as far as it was captured.
type Output struct {
	Stdout string `json:"stdout,omitempty"`
	Stderr string `json:"stderr,omitempty"`
	// Bytes is how many bytes of both streams the case carries.
	Bytes int `json:"bytes"`
	// Cut says the capture or the case holds only the beginning.
	Cut bool `json:"cut,omitempty"`
	// Binary says bytes that are not text were replaced in Stdout or Stderr;
	// an exported bundle holds the bytes as captured.
	Binary bool `json:"binary,omitempty"`

	stdout, stderr []byte
}

// Step is one entry of a timeline: an event, or a run of alike events.
type Step struct {
	At time.Time `json:"at"`
	// Until is the time of the last event of a folded run.
	Until     *time.Time `json:"until,omitempty"`
	Phase     string     `json:"phase"`
	Honeypot  string     `json:"honeypot,omitempty"`
	EventType string     `json:"event_type,omitempty"`
	// Summary is one line, cut to maxSummary; the records hold the rest.
	Summary string `json:"summary"`
	// Count is how many events the step stands for.
	Count int `json:"count"`

	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// Outcome of a login: "accepted", "refused" or "" when the honeypot's
	// event does not say.
	Outcome string `json:"outcome,omitempty"`
	// Tried lists the first distinct credential pairs of a folded run.
	Tried []string `json:"tried,omitempty"`

	Command  string  `json:"command,omitempty"`
	ExitCode *int    `json:"exit_code,omitempty"`
	Output   *Output `json:"output,omitempty"`

	URL    string `json:"url,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	File   string `json:"file,omitempty"`
	// CausedBy is the record of the command that names this transfer's URL,
	// host or file, when one earlier command of the same connection does.
	CausedBy string `json:"caused_by,omitempty"`
	// Because says what CausedBy rests on.
	Because string `json:"because,omitempty"`

	Technique string `json:"technique,omitempty"`
	// Refs are the records the step stands for, at most MaxRefs; MoreRefs
	// counts the rest. A canary step names its trip as "trip:<id>".
	Refs     []string `json:"refs"`
	MoreRefs int      `json:"more_refs,omitempty"`

	connection string // the honeypot's own session ID, for CausedBy
	single     bool   // a captured command: never folded into another
}

// File is one transferred file and everything that points at it.
type File struct {
	SHA256 string   `json:"sha256,omitempty"`
	URLs   []string `json:"urls,omitempty"`
	Names  []string `json:"names,omitempty"`
	// Empty marks the hash of no bytes: a transfer that fetched nothing.
	Empty     bool      `json:"empty,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	Transfers int       `json:"transfers"`
	// Refs are the transfer records, Commands the commands that caused them.
	Refs     []string `json:"refs"`
	Commands []string `json:"commands,omitempty"`
}

// Evidence is one piece of a session's strong campaign evidence.
type Evidence struct {
	Kind  string    `json:"kind"`
	Value string    `json:"value"`
	At    time.Time `json:"at"`
	Refs  []string  `json:"refs"`
	// Shared is true when another session of the case shows it too.
	Shared bool `json:"shared"`

	key string
}

// Gap is something a case could not show, or shows incompletely.
type Gap struct {
	Kind string `json:"kind"`
	// SessionID is empty for a gap of the whole case.
	SessionID string   `json:"session_id,omitempty"`
	Detail    string   `json:"detail"`
	Count     int      `json:"count,omitempty"`
	Refs      []string `json:"refs,omitempty"`
}

// SessionCase is one session's part of a case.
type SessionCase struct {
	Session   *database.TTPSession `json:"session"`
	Honeypots []string             `json:"honeypots"`
	// Reached lists the phases the session got to, in phase order.
	Reached []string `json:"reached"`
	// EventsRead is how many stored events the timeline was built from.
	EventsRead int        `json:"events_read"`
	Timeline   []Step     `json:"timeline"`
	Files      []File     `json:"files"`
	Evidence   []Evidence `json:"evidence"`
}

// Link is one piece of strong evidence two or more sessions share: the
// reason they are one campaign.
type Link struct {
	Kind     string     `json:"kind"`
	Value    string     `json:"value"`
	Sessions []LinkSide `json:"sessions"`
}

// LinkSide is one session's showing of a link.
type LinkSide struct {
	SessionID string    `json:"session_id"`
	At        time.Time `json:"at"`
	Refs      []string  `json:"refs"`
}

// Related is a session connected to the case's subject.
type Related struct {
	SessionID string `json:"session_id"`
	// Relation is "same campaign", "same source, earlier" or "same source,
	// later".
	Relation   string    `json:"relation"`
	Campaign   string    `json:"campaign_fingerprint"`
	Sources    []string  `json:"source_ips"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	EventCount int64     `json:"event_count"`
}

// Trip is a canary trip on a case, without the canary's secret value.
type Trip struct {
	ID       string    `json:"id"`
	CanaryID string    `json:"canary_id"`
	Kind     string    `json:"kind"`
	Name     string    `json:"name"`
	Memo     string    `json:"memo,omitempty"`
	Channel  string    `json:"channel"`
	Time     time.Time `json:"time"`
	SourceIP string    `json:"source_ip,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	Repeats  int       `json:"repeats,omitempty"`
	// SessionID is the session whose time the trip falls in, or "" for a
	// trip by the same source at another time.
	SessionID string `json:"session_id,omitempty"`
}

// Summary is the head of a case.
type Summary struct {
	Campaign    string    `json:"campaign_fingerprint"`
	Sessions    int       `json:"sessions"`
	Sources     []string  `json:"source_ips"`
	MoreSources int       `json:"more_source_ips,omitempty"`
	Honeypots   []string  `json:"honeypots"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	// Events is what the sessions counted; EventsRead what the case read.
	Events     int64    `json:"events"`
	EventsRead int      `json:"events_read"`
	Reached    []string `json:"reached"`
	Techniques []string `json:"techniques"`
	KillChain  []string `json:"kill_chain_stages"`
	Confidence float64  `json:"confidence"`
	Shared     bool     `json:"shared_infrastructure"`
	Files      int      `json:"files"`
	Trips      int      `json:"canary_trips"`
}

// Case is everything recorded about one session or one campaign.
type Case struct {
	// Kind is "session" or "campaign"; ID the session ID or the campaign
	// fingerprint.
	Kind      string         `json:"kind"`
	ID        string         `json:"id"`
	Instance  string         `json:"instance,omitempty"`
	Generated time.Time      `json:"generated"`
	Summary   Summary        `json:"summary"`
	Sessions  []*SessionCase `json:"sessions"`
	Links     []Link         `json:"links"`
	Related   []Related      `json:"related"`
	Trips     []Trip         `json:"canary_trips"`
	Gaps      []Gap          `json:"gaps"`
	Records   []Record       `json:"records"`
}

// RecordRef names a stored event by its content: the first 128 bits of the
// SHA-256 of the fields the collector stored, each written as
// "<length>:<bytes>" in a fixed order, with the metadata sorted by key. The
// classification the worker adds later is left out, so the name is the same
// before and after it.
//
// Text is hashed as JSON carries it: a byte that is not UTF-8 counts as
// U+FFFD. A record read back from an exported bundle therefore has the
// reference it was exported under. The payload is bytes, and hashed as such.
func RecordRef(e *database.Event) string {
	if e == nil {
		return ""
	}
	h := sha256.New()
	var n [20]byte
	raw := func(p string) {
		_, _ = h.Write(append(strconv.AppendInt(n[:0], int64(len(p)), 10), ':'))
		_, _ = h.Write([]byte(p))
	}
	write := func(p string) { raw(jsonText(p)) }
	write("qpot/record/1")
	write(strconv.FormatInt(e.Timestamp.UnixNano(), 10))
	write(e.Honeypot)
	write(e.SourceIP)
	write(strconv.Itoa(e.SourcePort))
	write(strconv.Itoa(e.DestPort))
	write(e.Protocol)
	write(e.EventType)
	write(e.Username)
	write(e.Password)
	write(e.Command)
	raw(string(e.Payload))
	keys := make([]string, 0, len(e.Metadata))
	for k := range e.Metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	write(strconv.Itoa(len(keys)))
	for _, k := range keys {
		write(k)
		write(e.Metadata[k])
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// jsonText returns s as encoding/json writes and reads it back: every byte
// that is not part of a UTF-8 sequence becomes U+FFFD.
func jsonText(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && n == 1 {
			b.WriteRune(utf8.RuneError)
		} else {
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}

// SessionCaseFor builds the case of one stored session.
func SessionCaseFor(ctx context.Context, db Reader, sessionID string, opts Options) (*Case, error) {
	sessions, err := db.GetTTPSessions(ctx, SessionScan)
	if err != nil {
		return nil, fmt.Errorf("investigate: read sessions: %w", err)
	}
	var subject *database.TTPSession
	for _, s := range sessions {
		if s != nil && s.SessionID == sessionID {
			subject = s
			break
		}
	}
	if subject == nil {
		return nil, fmt.Errorf("session %w", ErrNotFound)
	}
	b := newBuilder(opts)
	c := b.start("session", sessionID)
	sc, err := b.session(ctx, db, subject, opts.maxEvents())
	if err != nil {
		return nil, err
	}
	c.Sessions = []*SessionCase{sc}
	c.Related = related(subject, sessions)
	b.scanGap(sessions)
	b.finish(c, []*database.TTPSession{subject})
	return c, nil
}

// CampaignCaseFor builds the case of the stored sessions that carry one
// campaign fingerprint.
func CampaignCaseFor(ctx context.Context, db Reader, fingerprint string, opts Options) (*Case, error) {
	sessions, err := db.GetTTPSessions(ctx, SessionScan)
	if err != nil {
		return nil, fmt.Errorf("investigate: read sessions: %w", err)
	}
	var members []*database.TTPSession
	for _, s := range sessions {
		if s != nil && s.CampaignFingerprint == fingerprint && fingerprint != "" {
			members = append(members, s)
		}
	}
	if len(members) == 0 {
		return nil, fmt.Errorf("campaign %w", ErrNotFound)
	}
	sort.SliceStable(members, func(i, j int) bool {
		if !members[i].FirstSeen.Equal(members[j].FirstSeen) {
			return members[i].FirstSeen.Before(members[j].FirstSeen)
		}
		return members[i].SessionID < members[j].SessionID
	})
	b := newBuilder(opts)
	c := b.start("campaign", fingerprint)
	built := members
	if len(built) > MaxCampaignSessions {
		built = built[:MaxCampaignSessions]
		b.gap(Gap{Kind: GapSessionLimit, Count: len(members) - len(built),
			Detail: fmt.Sprintf("The campaign has %d sessions. The %d earliest have a timeline here; open the others one at a time.", len(members), len(built))})
		for _, s := range members[MaxCampaignSessions:] {
			c.Related = append(c.Related, relatedOf(s, "same campaign"))
		}
	}
	// The campaign's events are shared out, so that a case of many sessions
	// is no larger than a case of one.
	each := opts.maxEvents() / len(built)
	if each < 1 {
		each = 1
	}
	for _, s := range built {
		sc, err := b.session(ctx, db, s, each)
		if err != nil {
			return nil, err
		}
		c.Sessions = append(c.Sessions, sc)
	}
	b.scanGap(sessions)
	b.finish(c, members)
	return c, nil
}

// builder holds what is shared across the sessions of one case.
type builder struct {
	opts    Options
	gaps    []Gap
	records []Record
	seen    map[string]bool // record refs already in records
	trips   []Trip
	output  int // bytes of output carried so far
}

func newBuilder(opts Options) *builder { return &builder{opts: opts, seen: map[string]bool{}} }

func (b *builder) start(kind, id string) *Case {
	return &Case{Kind: kind, ID: id, Generated: b.opts.now()}
}

func (b *builder) gap(g Gap) {
	if len(g.Refs) > MaxRefs {
		g.Refs = g.Refs[:MaxRefs]
	}
	b.gaps = append(b.gaps, g)
}

// scanGap says when the stored sessions are more than a case looks through.
func (b *builder) scanGap(sessions []*database.TTPSession) {
	if len(sessions) >= SessionScan {
		b.gap(Gap{Kind: GapSessionScan, Count: SessionScan,
			Detail: fmt.Sprintf("Only the %d most recent sessions were looked through for related sessions; older ones are not listed.", SessionScan)})
	}
}

// record adds an event to the case's records and returns its reference.
func (b *builder) record(sessionID string, e *database.Event) string {
	ref := RecordRef(e)
	if !b.seen[ref] {
		b.seen[ref] = true
		b.records = append(b.records, Record{Ref: ref, SessionID: sessionID, Event: e})
	}
	return ref
}

// finish fills the parts of a case that span its sessions.
func (b *builder) finish(c *Case, members []*database.TTPSession) {
	c.Links = links(c.Sessions)
	if c.Kind == "campaign" && len(c.Sessions) > 1 {
		linked := map[string]bool{}
		for _, l := range c.Links {
			for _, side := range l.Sessions {
				linked[side.SessionID] = true
			}
		}
		for _, sc := range c.Sessions {
			if !linked[sc.Session.SessionID] {
				b.gap(Gap{Kind: GapNoSharedEvidence, SessionID: sc.Session.SessionID,
					Detail: "This session carries the campaign's fingerprint, but the events read for it show no evidence another session here shares. " +
						"The link was made from evidence outside what was read: events past the limit or no longer stored, an earlier session of the same source, or a session without a timeline here."})
			}
		}
	}

	s := &c.Summary
	s.Sessions = len(members)
	sources, honeypots, techniques, stages := newSet(), newSet(), newSet(), newSet()
	reached := map[string]bool{}
	for i, m := range members {
		if i == 0 || m.FirstSeen.Before(s.FirstSeen) {
			s.FirstSeen = m.FirstSeen
		}
		if m.LastSeen.After(s.LastSeen) {
			s.LastSeen = m.LastSeen
		}
		s.Events += m.EventCount
		s.Shared = s.Shared || m.SharedInfrastructure
		if m.Confidence > s.Confidence {
			s.Confidence = m.Confidence
		}
		if s.Campaign == "" {
			s.Campaign = m.CampaignFingerprint
		}
		sources.add(m.SourceIPs...)
		techniques.add(m.Techniques...)
		stages.add(m.KillChainStages...)
	}
	for _, sc := range c.Sessions {
		honeypots.add(sc.Honeypots...)
		s.EventsRead += sc.EventsRead
		s.Files += len(sc.Files)
		for _, p := range sc.Reached {
			reached[p] = true
		}
	}
	s.Sources, s.MoreSources = sources.first(maxListed)
	s.Honeypots, _ = honeypots.first(maxListed)
	s.Techniques, _ = techniques.first(maxListed)
	s.KillChain, _ = stages.first(maxListed)
	s.Reached = []string{}
	for _, p := range phaseOrder {
		if reached[p] {
			s.Reached = append(s.Reached, p)
		}
	}
	s.Trips = len(b.trips)

	sort.SliceStable(b.trips, func(i, j int) bool { return b.trips[i].Time.Before(b.trips[j].Time) })
	c.Trips = b.trips
	c.Gaps = b.gaps
	c.Records = b.records
	// Empty lists, not null: a reader of the JSON need not tell them apart.
	if c.Links == nil {
		c.Links = []Link{}
	}
	if c.Related == nil {
		c.Related = []Related{}
	}
	if c.Trips == nil {
		c.Trips = []Trip{}
	}
	if c.Gaps == nil {
		c.Gaps = []Gap{}
	}
	if c.Records == nil {
		c.Records = []Record{}
	}
}

// links returns the strong evidence two or more of the sessions share, and
// marks it shared on each of them.
func links(sessions []*SessionCase) []Link {
	type showing struct {
		session int
		ev      int
	}
	byKey := map[string][]showing{}
	var order []string
	for si, sc := range sessions {
		for ei, ev := range sc.Evidence {
			if _, ok := byKey[ev.key]; !ok {
				order = append(order, ev.key)
			}
			byKey[ev.key] = append(byKey[ev.key], showing{si, ei})
		}
	}
	var out []Link
	for _, key := range order {
		shown := byKey[key]
		if len(shown) < 2 {
			continue
		}
		first := sessions[shown[0].session].Evidence[shown[0].ev]
		l := Link{Kind: first.Kind, Value: first.Value}
		for _, sh := range shown {
			ev := &sessions[sh.session].Evidence[sh.ev]
			ev.Shared = true
			l.Sessions = append(l.Sessions, LinkSide{SessionID: sessions[sh.session].Session.SessionID, At: ev.At, Refs: ev.Refs})
		}
		out = append(out, l)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return kindRank(out[i].Kind) < kindRank(out[j].Kind)
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// kindRank orders evidence kinds strongest first.
func kindRank(kind string) int {
	switch kind {
	case intelligence.EvidencePayload:
		return 0
	case intelligence.EvidenceHost:
		return 1
	}
	return 2
}

func relatedOf(s *database.TTPSession, relation string) Related {
	sources := s.SourceIPs
	if len(sources) > maxListed {
		sources = sources[:maxListed]
	}
	if sources == nil {
		sources = []string{}
	}
	return Related{SessionID: s.SessionID, Relation: relation, Campaign: s.CampaignFingerprint, Sources: sources,
		FirstSeen: s.FirstSeen, LastSeen: s.LastSeen, EventCount: s.EventCount}
}

// related lists the stored sessions connected to subject: those of its
// campaign, and those of the same source at another time.
func related(subject *database.TTPSession, sessions []*database.TTPSession) []Related {
	source, _, known := intelligence.SplitSessionID(subject.SessionID)
	var out []Related
	for _, s := range sessions {
		if s == nil || s.SessionID == subject.SessionID {
			continue
		}
		other, _, ok := intelligence.SplitSessionID(s.SessionID)
		switch {
		case known && ok && other == source && s.LastSeen.Before(subject.FirstSeen):
			out = append(out, relatedOf(s, "same source, earlier"))
		case known && ok && other == source:
			out = append(out, relatedOf(s, "same source, later"))
		case subject.CampaignFingerprint != "" && s.CampaignFingerprint == subject.CampaignFingerprint:
			out = append(out, relatedOf(s, "same campaign"))
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].FirstSeen.Equal(out[j].FirstSeen) {
			return out[i].FirstSeen.Before(out[j].FirstSeen)
		}
		return out[i].SessionID < out[j].SessionID
	})
	if len(out) > 4*maxListed {
		out = out[:4*maxListed]
	}
	return out
}

// set is an insertion-ordered set of non-empty strings.
type set struct {
	seen map[string]bool
	list []string
}

func newSet() *set { return &set{seen: map[string]bool{}} }

func (s *set) add(values ...string) {
	for _, v := range values {
		if v != "" && !s.seen[v] {
			s.seen[v] = true
			s.list = append(s.list, v)
		}
	}
}

// first returns at most n values, sorted, and how many more there are.
func (s *set) first(n int) ([]string, int) {
	out := append([]string{}, s.list...)
	sort.Strings(out)
	if len(out) > n {
		return out[:n], len(out) - n
	}
	return out, 0
}

// cut returns s shortened to at most n bytes at a rune boundary, with a mark
// when it was shortened.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	end := n
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end] + "…"
}

// urlHost returns the host of a URL, or "".
func urlHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
