package canary

import (
	"os"
	"path/filepath"
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

	tr, ok, err := s.TripByToken(c.Token, "198.51.100.9", "curl/8", "GET /c/")
	if err != nil || !ok || tr == nil {
		t.Fatalf("TripByToken: ok=%v err=%v", ok, err)
	}
	if tr.Channel != "http" {
		t.Fatalf("channel = %q", tr.Channel)
	}
	// Unknown token: no trip, no error (caller serves identical decoy).
	if _, ok, err := s.TripByToken("nope", "1.2.3.4", "", ""); ok || err != nil {
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
	if _, ok, _ := s.TripByToken(c.Token, "1.1.1.1", "", ""); ok {
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
		if _, _, err := s.TripByToken(c.Token, "1.1.1.1", "", ""); err != nil {
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
