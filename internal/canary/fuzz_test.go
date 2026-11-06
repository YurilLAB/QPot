package canary

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzStoreLoad: canaries.json is read at every start. Whatever it holds, the
// store must either refuse it or come up usable: listing, the beacon and the
// session matcher must not panic on what it loaded.
func FuzzStoreLoad(f *testing.F) {
	for _, s := range []string{
		`{"version":1,"canaries":[],"trips":[]}`,
		`{"version":1,"canaries":[null,{"id":"cnry_1","token":"t","kind":"aws","enabled":true,"access_key_id":"AKIAX"}],"trips":[null]}`,
		`{"trips":[{"canary_id":"cnry_1","time":"2026-01-01T00:00:00Z"},null]}`,
		`{"canaries":[{"id":"cnry_2","token":"","kind":"web","enabled":true}]}`,
		`null`, `[]`, `{}`, `{"trips":{}}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "canaries.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := NewStore(dir, 5)
		if err != nil {
			return
		}
		_ = s.List()
		_ = s.Trips(0)
		_ = s.HasWatchValues()
		_, _, _ = s.TripByToken("t", "203.0.113.1", "ua", "GET /c/t")
		_, _, _ = s.Match("AKIAX AKIA", "203.0.113.1", "matched")
		if len(s.Trips(0)) > 5 {
			t.Fatalf("trip history exceeds the cap: %d", len(s.Trips(0)))
		}
	})
}

// FuzzMatch: a session trips a credential canary exactly when it contains one
// of the planted values.
func FuzzMatch(f *testing.F) {
	f.Add("aws s3 ls --access-key AKIA")
	f.Add("")
	f.Add(strings.Repeat("A", 100))
	dir := f.TempDir()
	s, err := NewStore(dir, 0)
	if err != nil {
		f.Fatal(err)
	}
	c, err := s.Create(KindAWS, "ci", "jenkins")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, text string) {
		want := strings.Contains(text, c.AccessKeyID) || strings.Contains(text, c.SecretAccessKey)
		_, ok, _ := s.Match(text, "198.51.100."+string(rune('0'+len(text)%10)), "fuzz")
		if ok && !want {
			t.Fatalf("Match tripped on text without a planted value: %q", text)
		}
	})
}
