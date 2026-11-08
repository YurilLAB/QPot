package canary

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestNewMintsDistinctTokens(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		c, err := New(KindWeb, "t", "")
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if !strings.HasPrefix(c.ID, "cnry_") {
			t.Fatalf("bad id %q", c.ID)
		}
		if seen[c.Token] {
			t.Fatalf("duplicate token %q", c.Token)
		}
		seen[c.Token] = true
	}
}

func TestNewAWSShape(t *testing.T) {
	c, err := New(KindAWS, "ci-runner", "planted in jenkins")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !strings.HasPrefix(c.AccessKeyID, "AKIA") || len(c.AccessKeyID) != 20 {
		t.Fatalf("access key id %q not AKIA+16", c.AccessKeyID)
	}
	if len(c.SecretAccessKey) != 40 {
		t.Fatalf("secret length = %d, want 40", len(c.SecretAccessKey))
	}
	vals := c.watchValues()
	if len(vals) != 2 {
		t.Fatalf("watch values = %d, want 2", len(vals))
	}
}

func TestNewRejectsUnknownKind(t *testing.T) {
	if _, err := New(Kind("bogus"), "x", ""); err == nil {
		t.Fatal("expected error for unknown kind")
	}
}

func TestURL(t *testing.T) {
	c, _ := New(KindWeb, "x", "")
	if got := c.URL("https://a.example.com/"); got != "https://a.example.com/c/"+c.Token {
		t.Fatalf("URL = %q", got)
	}
	if got := c.URL(""); got != "/c/"+c.Token {
		t.Fatalf("empty-base URL = %q", got)
	}
}

func TestRenderFile(t *testing.T) {
	c, _ := New(KindFile, "Q4 Salaries", "share")
	name, body, err := c.RenderFile("https://a.example.com")
	if err != nil {
		t.Fatalf("RenderFile: %v", err)
	}
	if !strings.HasSuffix(name, ".html") {
		t.Fatalf("filename %q", name)
	}
	if !strings.Contains(string(body), c.Token) {
		t.Fatal("rendered file does not embed the beacon token")
	}
	// A web canary must refuse to render a file.
	w, _ := New(KindWeb, "x", "")
	if _, _, err := w.RenderFile("https://a"); err == nil {
		t.Fatal("expected error rendering file for web canary")
	}
}

func TestToEvent(t *testing.T) {
	c, _ := New(KindAWS, "db-creds", "planted in /etc/secrets")
	tr := &Trip{
		ID: "trip_x", CanaryID: c.ID, Kind: KindAWS, Name: c.Name,
		Memo: c.Memo, Channel: "honeypot", SourceIP: "203.0.113.5",
		Detail: "matched in cowrie session",
	}
	ev := tr.ToEvent()
	if ev.Honeypot != "canary" {
		t.Fatalf("honeypot = %q", ev.Honeypot)
	}
	if !ev.Classified || ev.Confidence != 1.0 {
		t.Fatalf("canary event must be classified with confidence 1.0")
	}
	if ev.TechniqueID != "T1078.004" {
		t.Fatalf("aws technique = %q", ev.TechniqueID)
	}
	if ev.Metadata["severity"] != "critical" {
		t.Fatalf("severity = %q", ev.Metadata["severity"])
	}
	if ev.Metadata["canary_memo"] != c.Memo {
		t.Fatalf("memo not propagated")
	}
}

// Canary trips sit in the same ATT&CK tables as classified events, whose
// tactics are ATT&CK short names ("credential-access"): a title-case name
// stood out as a different tactic in the dashboard.
func TestCanaryTacticsUseATTCKShortNames(t *testing.T) {
	short := regexp.MustCompile(`^[a-z]+(?:-[a-z]+)*$`)
	for _, k := range []Kind{KindWeb, KindFile, KindAWS, KindCredential, KindSSHKey} {
		ev := (&Trip{ID: "trip_x", Kind: k, SourceIP: "203.0.113.5"}).ToEvent()
		if !short.MatchString(ev.TacticName) || ev.TacticID == "" {
			t.Errorf("%s: tactic %q %q, want an ATT&CK short name", k, ev.TacticID, ev.TacticName)
		}
	}
}

func TestStoreCreateListDeletePersist(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir, 0)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	c, err := s.Create(KindWeb, "bookmark", "fake admin link")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if list := s.List(); len(list) != 1 || list[0].ID != c.ID {
		t.Fatalf("List = %+v", list)
	}

	// Reopen from disk: the canary must survive.
	s2, err := NewStore(dir, 0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, ok := s2.Get(c.ID); !ok {
		t.Fatal("canary did not persist across reopen")
	}

	ok, err := s2.Delete(c.ID)
	if err != nil || !ok {
		t.Fatalf("Delete: ok=%v err=%v", ok, err)
	}
	if _, ok := s2.Get(c.ID); ok {
		t.Fatal("canary still present after delete")
	}
	if _, err := NewStore(dir, 0); err != nil {
		t.Fatalf("reopen after delete: %v", err)
	}
}

func TestTripByToken(t *testing.T) {
	s, _ := NewStore(t.TempDir(), 0)
	c, _ := s.Create(KindWeb, "x", "")

	tr, ok, err := s.TripByToken(c.Token, "198.51.100.9", "curl/8", "GET /c/", Origin{})
	if err != nil || !ok || tr == nil {
		t.Fatalf("TripByToken: ok=%v err=%v", ok, err)
	}
	if tr.Channel != "http" {
		t.Fatalf("channel = %q", tr.Channel)
	}
	// Unknown token: no trip, no error (caller serves identical decoy).
	if _, ok, err := s.TripByToken("nope", "1.2.3.4", "", "", Origin{}); ok || err != nil {
		t.Fatalf("unknown token tripped: ok=%v err=%v", ok, err)
	}
	// Counter incremented and a trip is retained.
	got, _ := s.Get(c.ID)
	if got.Trips != 1 {
		t.Fatalf("trip count = %d", got.Trips)
	}
	if trips := s.Trips(10); len(trips) != 1 {
		t.Fatalf("trips len = %d", len(trips))
	}

	// Disabled canary must not trip.
	if _, err := s.SetEnabled(c.ID, false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if _, ok, _ := s.TripByToken(c.Token, "1.1.1.1", "", "", Origin{}); ok {
		t.Fatal("disabled canary tripped")
	}
}

func TestMatchCredential(t *testing.T) {
	s, _ := NewStore(t.TempDir(), 0)
	c, _ := s.Create(KindAWS, "ci", "jenkins")

	session := "attacker ran: aws s3 ls --access-key " + c.AccessKeyID + " ; cat /tmp/x"
	tr, ok, err := s.Match(session, "203.0.113.7", "cowrie")
	if err != nil || !ok || tr == nil {
		t.Fatalf("Match: ok=%v err=%v", ok, err)
	}
	if tr.Channel != "honeypot" {
		t.Fatalf("channel = %q", tr.Channel)
	}
	// No match for unrelated text.
	if _, ok, _ := s.Match("nothing interesting here", "1.2.3.4", "cowrie"); ok {
		t.Fatal("unexpected match")
	}
	if !s.HasWatchValues() {
		t.Fatal("HasWatchValues should be true with an AWS canary")
	}
}

func TestTripHistoryCap(t *testing.T) {
	s, _ := NewStore(t.TempDir(), 5)
	c, _ := s.Create(KindWeb, "x", "")
	for i := 0; i < 20; i++ {
		if _, _, err := s.TripByToken(c.Token, fmt.Sprintf("10.0.0.%d", i), "", "", Origin{}); err != nil {
			t.Fatalf("trip %d: %v", i, err)
		}
	}
	if trips := s.Trips(0); len(trips) != 5 {
		t.Fatalf("trip history not capped: len = %d", len(trips))
	}
	// Lifetime counter keeps counting even though history is capped.
	got, _ := s.Get(c.ID)
	if got.Trips != 20 {
		t.Fatalf("lifetime trips = %d, want 20", got.Trips)
	}
}

func TestCorruptStoreReported(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "canaries.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(dir, 0); err == nil {
		t.Fatal("expected error opening corrupt store")
	}
}

// Replaying one token from one source must alert once, not on every request.
func TestRepeatTripsAreFolded(t *testing.T) {
	s, _ := NewStore(t.TempDir(), 100)
	c, _ := s.Create(KindWeb, "x", "")
	alerts := 0
	for i := 0; i < 500; i++ {
		if _, ok, err := s.TripByToken(c.Token, "203.0.113.9", "curl", "", Origin{}); err != nil {
			t.Fatal(err)
		} else if ok {
			alerts++
		}
	}
	if alerts != 1 {
		t.Fatalf("500 replays from one source raised %d alerts, want 1", alerts)
	}
	trips := s.Trips(0)
	if len(trips) != 1 || trips[0].Repeats != 499 {
		t.Fatalf("trips=%d repeats=%d, want 1 trip with 499 repeats", len(trips), trips[0].Repeats)
	}
	if got, _ := s.Get(c.ID); got.Trips != 500 {
		t.Fatalf("lifetime trips = %d, want 500", got.Trips)
	}
	// A different source is a new trip; so is the same source after the window.
	if _, ok, _ := s.TripByToken(c.Token, "198.51.100.7", "", "", Origin{}); !ok {
		t.Fatal("hit from a new source was folded")
	}
	old := TripDedupeWindow
	TripDedupeWindow = 0
	defer func() { TripDedupeWindow = old }()
	if _, ok, _ := s.TripByToken(c.Token, "203.0.113.9", "", "", Origin{}); !ok {
		t.Fatal("hit after the dedupe window was folded")
	}
}

// Trips handed to callers must not alias the stored ones: a repeat hit bumps
// the stored trip's Repeats under the lock while an API handler encodes its
// result without it (found with -race).
func TestTripsAreCopies(t *testing.T) {
	s, err := NewStore(t.TempDir(), 100)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Create(KindWeb, "w", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.TripByToken(c.Token, "203.0.113.9", "ua", "", Origin{}); !ok || err != nil {
		t.Fatalf("first trip: %v %v", ok, err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			_, _, _ = s.TripByToken(c.Token, "203.0.113.9", "ua", "", Origin{}) // repeats
		}
	}()
	for i := 0; i < 200; i++ {
		if _, err := json.Marshal(s.Trips(10)); err != nil {
			t.Fatal(err)
		}
	}
	<-done
	got := s.Trips(1)
	got[0].Repeats = -1
	if s.Trips(1)[0].Repeats == -1 {
		t.Fatal("Trips returned the stored trip, not a copy")
	}
}
