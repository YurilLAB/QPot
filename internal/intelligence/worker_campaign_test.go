package intelligence

import (
	"context"
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
