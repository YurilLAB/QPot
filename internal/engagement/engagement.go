// Package engagement measures how far visitors go inside a honeypot: how many
// sessions log in, run commands and fetch payloads, how long and how deep the
// sessions are, how varied the commands are, how often a session ends right
// after a fingerprint probe, how many sources come back, and how much usable
// intelligence the sessions leave.
//
// It works on a stream of events, so the same numbers can be computed for a
// QPot instance (ReadDatabase) and for the JSON log of any Cowrie deployment
// (ReadCowrieLog) and then compared (Compare). doc/effectiveness.md defines
// every metric.
//
// The result does not depend on the order of the events, and memory stays
// bounded on large or hostile input: every set of distinct values has a
// limit, and the report says when a limit was reached.
package engagement

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"io"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"
)

// SessionGap is the quiet time that ends a session formed by source address:
// two events from one source to one honeypot belong to the same session when
// they are at most this far apart.
const SessionGap = 30 * time.Minute

// ReturnAfter is how much later a source must start another session, after
// one of its interactive sessions ended, to count as returning.
const ReturnAfter = time.Hour

// ShortSession is the largest number of commands a session may have to count
// as having left after a probe.
const ShortSession = 3

// TopStemCount is how many command stems a report lists.
const TopStemCount = 10

const (
	maxNameBytes    = 64
	maxSessionBytes = 128
	// maxReported bounds a session length a honeypot reports about itself.
	maxReported = 366 * 24 * time.Hour
)

// Event is one honeypot event, reduced to what the metrics need.
type Event struct {
	// Time is when the event happened. An event without a time is not used.
	Time time.Time
	// Honeypot names the honeypot that logged it.
	Honeypot string
	// SourceIP is the visitor's address.
	SourceIP string
	// SessionID is the honeypot's own session identifier, when it has one.
	SessionID string
	// Type is the honeypot's event id, such as cowrie.login.success.
	Type string
	// Username and Password are the credentials of a login event.
	Username string
	Password string
	// Command is the input line of a command event.
	Command string
	// URL is where a payload was fetched from.
	URL string
	// SHA256 is the hash of a fetched or uploaded payload.
	SHA256 string
	// TechniqueID is the ATT&CK technique the event was classified as.
	TechniqueID string
	// ReportedDuration is the session length the honeypot states itself
	// (Cowrie's cowrie.session.closed "duration"). Zero when it states none.
	ReportedDuration time.Duration
}

// Options are the memory limits of one computation. A zero field takes its
// default.
type Options struct {
	// DistinctLimit bounds each set of distinct values (commands, payload
	// hashes, URLs, hosts, credential pairs, techniques), per scope.
	// Default 50000.
	DistinctLimit int
	// StemLimit bounds the distinct command stems counted, per scope.
	// Default 10000.
	StemLimit int
	// SessionCommandLimit bounds the distinct commands remembered per
	// session. Default 64.
	SessionCommandLimit int
	// SessionLimit bounds the session keys held: (honeypot, session id)
	// pairs plus (honeypot, source) pairs. Default 2000000.
	SessionLimit int
}

func (o Options) withDefaults() Options {
	if o.DistinctLimit <= 0 {
		o.DistinctLimit = 50000
	}
	if o.StemLimit <= 0 {
		o.StemLimit = 10000
	}
	if o.SessionCommandLimit <= 0 {
		o.SessionCommandLimit = 64
	}
	if o.SessionLimit <= 0 {
		o.SessionLimit = 2000000
	}
	return o
}

// Source feeds events to emit until it has no more or emit returns false.
type Source func(emit func(Event) bool) error

// Compute reads every event of src and returns the report.
func Compute(label string, src Source, opt Options) (*Report, error) {
	a := NewAggregator(opt)
	if err := src(func(e Event) bool {
		a.Add(e)
		return true
	}); err != nil {
		return nil, err
	}
	return a.Report(label), nil
}

// Event classes, by the honeypot's own event id. Cowrie and ADBHoney name
// logins <honeypot>.login.success / .failed, QPot derives the same names for
// Heralding, and the refrigeration emulator uses .auth.success / .failed.
// Commands are <honeypot>.command.input (Cowrie, ADBHoney),
// ssh-proxy.command.start (QPot's SSH backend; .finish repeats the command)
// and <honeypot>.command. Cowrie's cowrie.command.failed repeats an input
// line and is not counted.
func isLoginSuccess(t string) bool {
	return strings.HasSuffix(t, ".login.success") || strings.HasSuffix(t, ".auth.success")
}

func isLoginFailed(t string) bool {
	return strings.HasSuffix(t, ".login.failed") || strings.HasSuffix(t, ".auth.failed")
}

func isCommand(t string) bool {
	return strings.HasSuffix(t, ".command.input") || strings.HasSuffix(t, ".command.start") || strings.HasSuffix(t, ".command")
}

// isPayload: the honeypot stored a file the visitor fetched or uploaded.
func isPayload(t string) bool {
	return strings.HasSuffix(t, ".file_download") || strings.HasSuffix(t, ".file_upload")
}

// isPayloadFailed: a fetch that named a URL and stored nothing.
func isPayloadFailed(t string) bool {
	return strings.HasSuffix(t, ".file_download.failed")
}

// groupKey identifies a (honeypot, session id) or (honeypot, source) pair by
// a 128-bit hash, so a key costs the same whatever the honeypot logged.
type groupKey struct{ a, b uint64 }

func lessGroupKey(x, y groupKey) bool {
	if x.a != y.a {
		return x.a < y.a
	}
	return x.b < y.b
}

// session is everything kept about one session. Two sessions merge into the
// same result in either order.
type session struct {
	seen        bool
	first, last int64 // microseconds since the Unix epoch
	reported    int64 // longest honeypot-reported length, microseconds
	src         uint32
	commands    uint32
	attempted   bool
	loggedIn    bool
	payload     bool
	cmdsOver    bool
	lastProbe   probeKind
	lastCmd     int64
	cmds        []uint64 // distinct command hashes, ascending
}

// group holds the sessions of one key: one for a session id, one per run of
// activity for a source.
type group struct {
	used     bool
	bySource bool
	honeypot uint32
	events   int64
	one      session
	segs     []session // ascending by first; more than SessionGap apart
}

// observation is what one event adds to a session.
type observation struct {
	t         int64
	src       uint32
	reported  int64
	attempted bool
	loggedIn  bool
	payload   bool
	command   bool
	cmdHash   uint64
	probe     probeKind
}

// scopeSets are the distinct values seen in one scope: one honeypot, or all.
type scopeSets struct {
	commands   *capped[uint64, struct{}]
	stems      *capped[string, int64]
	stemTotal  int64
	hashes     *capped[uint64, struct{}]
	urls       *capped[uint64, struct{}]
	hosts      *capped[uint64, struct{}]
	creds      *capped[uint64, struct{}]
	techniques *capped[uint64, struct{}]
}

func newScopeSets(o Options) *scopeSets {
	set := func() *capped[uint64, struct{}] {
		return newCapped[uint64, struct{}](o.DistinctLimit, lessUint64)
	}
	return &scopeSets{
		commands: set(), hashes: set(), urls: set(), hosts: set(), creds: set(), techniques: set(),
		stems: newCapped[string, int64](o.StemLimit, lessString),
	}
}

// Aggregator turns events into a Report. Add events in any order, then call
// Report once.
type Aggregator struct {
	opt    Options
	in     Input
	hasher hash.Hash
	sum    [sha256.Size]byte

	honeypots map[string]uint32
	hpNames   []string
	hpSets    []*scopeSets
	overall   *scopeSets

	sources  map[string]uint32 // source address -> index+1 into srcNames
	srcNames []string

	groups *capped[groupKey, group]

	haveTime    bool
	first, last int64
}

// NewAggregator returns an empty Aggregator.
func NewAggregator(opt Options) *Aggregator {
	opt = opt.withDefaults()
	return &Aggregator{
		opt:       opt,
		hasher:    sha256.New(),
		honeypots: make(map[string]uint32),
		overall:   newScopeSets(opt),
		sources:   make(map[string]uint32),
		groups:    newCapped[groupKey, group](opt.SessionLimit, lessGroupKey),
	}
}

// digest hashes the parts, each followed by a zero byte.
func (a *Aggregator) digest(parts ...string) groupKey {
	a.hasher.Reset()
	for _, p := range parts {
		_, _ = io.WriteString(a.hasher, p)
		_, _ = a.hasher.Write([]byte{0})
	}
	s := a.hasher.Sum(a.sum[:0])
	return groupKey{binary.BigEndian.Uint64(s[:8]), binary.BigEndian.Uint64(s[8:16])}
}

func (a *Aggregator) hash64(parts ...string) uint64 { return a.digest(parts...).a }

// cleanName makes a honeypot name safe to print and bounded.
func cleanName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	if len(s) > maxNameBytes {
		s = s[:maxNameBytes]
	}
	b := []byte(s)
	for i, c := range b {
		if c < 0x21 || c > 0x7e {
			b[i] = '?'
		}
	}
	return string(b)
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (a *Aggregator) honeypot(name string) uint32 {
	if i, ok := a.honeypots[name]; ok {
		return i
	}
	i := uint32(len(a.hpNames))
	a.honeypots[name] = i
	a.hpNames = append(a.hpNames, name)
	a.hpSets = append(a.hpSets, newScopeSets(a.opt))
	return i
}

func (a *Aggregator) source(addr string) uint32 {
	if addr == "" {
		return 0
	}
	if i, ok := a.sources[addr]; ok {
		return i
	}
	a.srcNames = append(a.srcNames, addr)
	i := uint32(len(a.srcNames))
	a.sources[addr] = i
	return i
}

// Add counts one event.
func (a *Aggregator) Add(e Event) {
	a.in.Events++
	if e.Time.IsZero() {
		a.in.WithoutTime++
		return
	}
	sid := clip(strings.TrimSpace(e.SessionID), maxSessionBytes)
	src := clip(strings.TrimSpace(e.SourceIP), maxNameBytes)
	if sid == "" && src == "" {
		a.in.WithoutSessionKey++
		return
	}
	a.in.Used++
	t := e.Time.UnixMicro()
	if !a.haveTime || t < a.first {
		a.first = t
	}
	if !a.haveTime || t > a.last {
		a.last = t
	}
	a.haveTime = true

	hpName := cleanName(e.Honeypot)
	hp := a.honeypot(hpName)
	typ := strings.ToLower(strings.TrimSpace(e.Type))
	scopes := [2]*scopeSets{a.overall, a.hpSets[hp]}

	ob := observation{t: t}
	switch {
	case isLoginSuccess(typ):
		ob.attempted, ob.loggedIn = true, true
		if e.Username != "" || e.Password != "" {
			h := a.hash64(e.Username, e.Password)
			for _, s := range scopes {
				s.creds.slot(h)
			}
		}
	case isLoginFailed(typ):
		ob.attempted = true
	case isCommand(typ):
		if cmd := NormalizeCommand(e.Command); cmd != "" {
			ob.command = true
			ob.cmdHash = a.hash64(cmd)
			ob.probe = classifyProbe(cmd)
			stem := Stem(cmd)
			for _, s := range scopes {
				s.commands.slot(ob.cmdHash)
				s.stemTotal++
				if n := s.stems.slot(stem); n != nil {
					*n++
				}
			}
		}
	case isPayload(typ), isPayloadFailed(typ):
		if isPayload(typ) {
			ob.payload = true
			if sum := strings.ToLower(strings.TrimSpace(e.SHA256)); isSHA256(sum) {
				h := a.hash64(sum)
				for _, s := range scopes {
					s.hashes.slot(h)
				}
			}
		}
		if u := strings.TrimSpace(e.URL); u != "" {
			h := a.hash64(u)
			host := urlHost(u)
			for _, s := range scopes {
				s.urls.slot(h)
				if host != "" {
					s.hosts.slot(a.hash64(host))
				}
			}
		}
	}
	if tech := strings.ToUpper(strings.TrimSpace(e.TechniqueID)); tech != "" {
		h := a.hash64(tech)
		for _, s := range scopes {
			s.techniques.slot(h)
		}
	}
	if e.ReportedDuration > 0 && sid != "" {
		ob.reported = min(e.ReportedDuration, maxReported).Microseconds()
	}

	var key groupKey
	if sid != "" {
		key = a.digest("id", hpName, sid)
	} else {
		key = a.digest("source", hpName, src)
	}
	g := a.groups.slot(key)
	if g == nil {
		return
	}
	g.events++
	ob.src = a.source(src)
	if !g.used {
		g.used = true
		g.honeypot = hp
		g.bySource = sid == ""
	}
	if !g.bySource {
		a.observe(&g.one, ob)
		return
	}
	a.observeBySource(g, ob)
}

// observeBySource puts the event into the run of activity it belongs to,
// joining two runs when it falls within SessionGap of both.
func (a *Aggregator) observeBySource(g *group, ob observation) {
	gap := SessionGap.Microseconds()
	i := sort.Search(len(g.segs), func(i int) bool { return g.segs[i].first > ob.t })
	joinPrev := i > 0 && ob.t-g.segs[i-1].last <= gap
	joinNext := i < len(g.segs) && g.segs[i].first-ob.t <= gap
	switch {
	case joinPrev && joinNext:
		a.merge(&g.segs[i-1], &g.segs[i])
		g.segs = append(g.segs[:i], g.segs[i+1:]...)
		a.observe(&g.segs[i-1], ob)
	case joinPrev:
		a.observe(&g.segs[i-1], ob)
	case joinNext:
		a.observe(&g.segs[i], ob)
	default:
		g.segs = append(g.segs, session{})
		copy(g.segs[i+1:], g.segs[i:])
		g.segs[i] = session{}
		a.observe(&g.segs[i], ob)
	}
}

// observe adds one event to a session.
func (a *Aggregator) observe(s *session, ob observation) {
	if !s.seen {
		s.seen = true
		s.first, s.last = ob.t, ob.t
	} else {
		s.first = min(s.first, ob.t)
		s.last = max(s.last, ob.t)
	}
	s.src = a.minSource(s.src, ob.src)
	s.reported = max(s.reported, ob.reported)
	s.attempted = s.attempted || ob.attempted
	s.loggedIn = s.loggedIn || ob.loggedIn
	s.payload = s.payload || ob.payload
	if !ob.command {
		return
	}
	switch {
	case s.commands == 0 || ob.t > s.lastCmd:
		s.lastCmd, s.lastProbe = ob.t, ob.probe
	case ob.t == s.lastCmd:
		s.lastProbe = min(s.lastProbe, ob.probe)
	}
	if s.commands < math.MaxUint32 {
		s.commands++
	}
	a.addCommand(s, ob.cmdHash)
}

// merge adds session o to session s.
func (a *Aggregator) merge(s, o *session) {
	s.first = min(s.first, o.first)
	s.last = max(s.last, o.last)
	s.src = a.minSource(s.src, o.src)
	s.reported = max(s.reported, o.reported)
	s.attempted = s.attempted || o.attempted
	s.loggedIn = s.loggedIn || o.loggedIn
	s.payload = s.payload || o.payload
	if o.commands > 0 {
		switch {
		case s.commands == 0 || o.lastCmd > s.lastCmd:
			s.lastCmd, s.lastProbe = o.lastCmd, o.lastProbe
		case o.lastCmd == s.lastCmd:
			s.lastProbe = min(s.lastProbe, o.lastProbe)
		}
	}
	if total := uint64(s.commands) + uint64(o.commands); total > math.MaxUint32 {
		s.commands = math.MaxUint32
	} else {
		s.commands = uint32(total)
	}
	s.cmdsOver = s.cmdsOver || o.cmdsOver
	for _, h := range o.cmds {
		a.addCommand(s, h)
	}
}

// addCommand remembers a distinct command of the session, keeping the
// smallest hashes when there are more than the limit.
func (a *Aggregator) addCommand(s *session, h uint64) {
	i := sort.Search(len(s.cmds), func(i int) bool { return s.cmds[i] >= h })
	if i < len(s.cmds) && s.cmds[i] == h {
		return
	}
	if len(s.cmds) >= a.opt.SessionCommandLimit {
		s.cmdsOver = true
		if i == len(s.cmds) {
			return
		}
		s.cmds = s.cmds[:len(s.cmds)-1]
	}
	s.cmds = append(s.cmds, 0)
	copy(s.cmds[i+1:], s.cmds[i:])
	s.cmds[i] = h
}

// minSource keeps the smaller address of two, so a session with events from
// more than one address names the same one in any order.
func (a *Aggregator) minSource(x, y uint32) uint32 {
	switch {
	case x == 0:
		return y
	case y == 0:
		return x
	case a.srcNames[y-1] < a.srcNames[x-1]:
		return y
	}
	return x
}

func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// urlHost is the lower-case host of a URL, without its port. Empty when the
// text has none.
func urlHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
