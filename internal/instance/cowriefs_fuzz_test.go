package instance

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// FuzzCowrieFsPatch feeds arbitrary persona usernames/passwords/seeds through the
// home-user derivation and the fake-fs patch-script generator, asserting no panic
// and - critically - that whatever hostile content a username or generated
// history carries, the embedded user blob is ALWAYS valid base64+JSON that
// round-trips intact (so it can never break the generated Python's syntax). This
// is the injection-safety invariant of the deploy-time pickle patch.
func FuzzCowrieFsPatch(f *testing.F) {
	f.Add("jmartin", "Summer1!", "seedA")
	f.Add("a\");import os#", "p", "")
	f.Add("b\nrm -rf /", "\xff\x00", "x")
	f.Add("", "", "")
	f.Fuzz(func(t *testing.T, user, pass, seed string) {
		tmpl := credentialTemplate{Name: "fuzz", Users: []credUser{
			{Username: user, Passwords: []string{pass}},
			{Username: "deploy", Passwords: []string{"d"}},
		}}
		users := cowrieHomeUsers(tmpl, seed) // must not panic
		// The full embedded-file set (home content + system files) is what the
		// deploy-time patch embeds; hostile usernames flow into file paths here.
		files := append(cowrieHomeFiles(tmpl, seed),
			embeddedSystemFiles(tmpl, profileForSeed(seed), "host", seed)...)
		script := cowrieFsPatchScript(files, personaHomeNames(tmpl, seed)) // must not panic

		// The FIRST base64 blob is the FILES payload; it must decode + JSON-parse
		// back to the same files (no path/content can corrupt or escape the
		// embedding and break the generated Python).
		marker := `b64decode("`
		i := strings.Index(script, marker)
		if i < 0 {
			t.Fatal("patch script missing base64 files blob")
		}
		rest := script[i+len(marker):]
		j := strings.IndexByte(rest, '"')
		if j < 0 {
			t.Fatal("unterminated base64 blob")
		}
		raw, err := base64.StdEncoding.DecodeString(rest[:j])
		if err != nil {
			t.Fatalf("embedded blob not valid base64: %v", err)
		}
		var got []embeddedFile
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("embedded blob not valid JSON: %v", err)
		}
		if len(got) != len(files) {
			t.Fatalf("round-trip file count mismatch: got %d want %d", len(got), len(files))
		}
		for k := range files {
			if got[k].Path != files[k].Path || got[k].Content != files[k].Content || got[k].UID != files[k].UID {
				t.Errorf("file %d not preserved through embedding: %+v vs %+v", k, got[k], files[k])
			}
		}
		// Home users must never include root or service accounts and must have a
		// uid space starting at 1000 shared with etcPasswd.
		for _, hu := range users {
			if hu.Name == "" || hu.Name == "root" {
				t.Errorf("home user must not be empty/root: %q", hu.Name)
			}
			if hu.UID < 1000 {
				t.Errorf("home user %q has uid %d (<1000)", hu.Name, hu.UID)
			}
		}
	})
}
