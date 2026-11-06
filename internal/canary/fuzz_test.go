package canary

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
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

// FuzzDeriver: whatever the seed and label, the derived values keep their
// shapes (charset, length, watchable), the key file parses back to its key,
// and the same input derives the same values.
func FuzzDeriver(f *testing.F) {
	f.Add("ds_0123", "label", 16)
	f.Add("", "", 0)
	f.Add(strings.Repeat("\x00", 64), "\xff", 300)
	f.Fuzz(func(t *testing.T, seed, label string, n int) {
		n = (n%256 + 256) % 256
		d := NewDeriver(seed)
		chars := d.Chars(label, n, charsAlnum)
		if len(chars) != n || strings.Trim(chars, charsAlnum) != "" {
			t.Fatalf("Chars(%d) = %q", n, chars)
		}
		if again := NewDeriver(seed).Chars(label, n, charsAlnum); again != chars {
			t.Fatal("not stable")
		}
		if v := d.Intn(label, n+1); v < 0 || v > n {
			t.Fatalf("Intn(%d) = %d", n+1, v)
		}
		pw := d.HumanPassword(label)
		if len(pw) <= MinWatchLen || strings.ContainsAny(pw, "'\"\\ $`") {
			t.Fatalf("human password %q", pw)
		}
		key := d.Ed25519Key(label)
		parsed, err := ssh.ParseRawPrivateKey(MarshalEd25519PrivateKey(key, label, uint32(n)))
		if err != nil {
			t.Fatalf("key file does not parse: %v", err)
		}
		if got, ok := parsed.(*ed25519.PrivateKey); !ok || !got.Equal(key) {
			t.Fatal("key file holds another key")
		}
	})
}
