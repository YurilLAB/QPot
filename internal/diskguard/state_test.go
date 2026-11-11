package diskguard

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var stoppedAt = time.Date(2026, 11, 12, 9, 30, 15, 0, time.UTC)

func TestStateAddRemove(t *testing.T) {
	var s State
	if s.Held() || s.Has("cowrie") || len(s.Names()) != 0 {
		t.Fatalf("zero state: %+v", s)
	}
	if !s.Add("dionaea", stoppedAt) || !s.Add("cowrie", stoppedAt.Add(time.Minute)) {
		t.Fatal("Add refused a honeypot name")
	}
	// A second Add keeps the first time.
	if s.Add("cowrie", stoppedAt.Add(time.Hour)) {
		t.Error("Add reported a change for a honeypot already listed")
	}
	if got := s.Names(); !reflect.DeepEqual(got, []string{"cowrie", "dionaea"}) {
		t.Errorf("Names = %v, want them by name", got)
	}
	if !s.Stopped[0].StoppedAt.Equal(stoppedAt.Add(time.Minute)) {
		t.Errorf("cowrie stopped at %v", s.Stopped[0].StoppedAt)
	}
	// Names that are not honeypot names never get in: they end up in a
	// docker command line.
	for _, bad := range []string{"", "-rf", "Cowrie", "a b", "a/b", "../x", "x\n", "--help", strings.Repeat("a", 65), "a;b", "a$b"} {
		if s.Add(bad, stoppedAt) {
			t.Errorf("Add accepted %q", bad)
		}
	}
	c := s.Clone()
	if !s.Remove("cowrie") || s.Remove("cowrie") || s.Has("cowrie") || !s.Has("dionaea") {
		t.Errorf("Remove: %+v", s)
	}
	if !c.Has("cowrie") || len(c.Stopped) != 2 {
		t.Errorf("the clone changed with the original: %+v", c)
	}
	if !s.Remove("dionaea") || s.Held() {
		t.Errorf("after removing both: %+v", s)
	}
}

func TestStateAddIsBounded(t *testing.T) {
	var s State
	for i := 0; i < MaxStopped+50; i++ {
		s.Add(fmt.Sprintf("hp-%d", i), stoppedAt)
	}
	if len(s.Stopped) != MaxStopped {
		t.Fatalf("%d entries, want at most %d", len(s.Stopped), MaxStopped)
	}
	data, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > maxStateBytes {
		t.Fatalf("a full state is %d bytes, more than the %d a read accepts", len(data), maxStateBytes)
	}
	// The longest names there can be still fit.
	var long State
	for i := 0; i < MaxStopped; i++ {
		long.Add(fmt.Sprintf("%s%04d", strings.Repeat("a", 60), i), stoppedAt)
	}
	data, err = long.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if back, err := ParseState(data); err != nil || len(back.Stopped) != MaxStopped {
		t.Fatalf("a full state of long names does not read back: %d entries, %v (%d bytes)", len(back.Stopped), err, len(data))
	}
}

// TestStateRoundTrip: a restarted guard reads back exactly what the last one
// stopped, no more.
func TestStateRoundTrip(t *testing.T) {
	path := Path(t.TempDir())
	if filepath.Base(path) != StateFile {
		t.Fatalf("Path = %s", path)
	}
	// No file: nothing stopped, and no error.
	if s, err := LoadState(path); err != nil || s.Held() {
		t.Fatalf("missing file: %+v, %v", s, err)
	}
	var s State
	s.Add("cowrie", stoppedAt)
	s.Add("ssh-proxy", stoppedAt.Add(2*time.Second))
	if err := SaveState(path, s); err != nil {
		t.Fatal(err)
	}
	back, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, s) {
		t.Fatalf("read back %+v, wrote %+v", back, s)
	}
	// The operator's own stops are not in it.
	if back.Has("dionaea") {
		t.Fatal("a honeypot the guard never stopped is listed")
	}
	// No temporary file is left next to it.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != StateFile {
		t.Fatalf("folder after a save: %v", entries)
	}
	// Saved again with one fewer, then with none: the file goes.
	s.Remove("cowrie")
	if err := SaveState(path, s); err != nil {
		t.Fatal(err)
	}
	if back, err := LoadState(path); err != nil || !reflect.DeepEqual(back.Names(), []string{"ssh-proxy"}) {
		t.Fatalf("after removing one: %+v, %v", back, err)
	}
	s.Remove("ssh-proxy")
	if err := SaveState(path, s); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("an empty state left its file: %v", err)
	}
	// Removing what is not there is fine.
	if err := SaveState(path, State{}); err != nil {
		t.Fatalf("saving an empty state twice: %v", err)
	}
}

// TestCorruptStateStoppedNothing: a file the guard does not fully understand
// lists nothing, so nothing is started because of it.
func TestCorruptStateStoppedNothing(t *testing.T) {
	valid := `{"version":1,"stopped":[{"name":"cowrie","stopped_at":"2026-11-12T09:30:15Z"}]}`
	if s, err := ParseState([]byte(valid)); err != nil || !reflect.DeepEqual(s.Names(), []string{"cowrie"}) {
		t.Fatalf("the valid file: %+v, %v", s, err)
	}
	many := `{"version":1,"stopped":[`
	for i := 0; i <= MaxStopped; i++ {
		if i > 0 {
			many += ","
		}
		many += fmt.Sprintf(`{"name":"h%d","stopped_at":"2026-11-12T09:30:15Z"}`, i)
	}
	many += "]}"
	cases := map[string]string{
		"empty":             "",
		"spaces":            "  \n",
		"cut short":         valid[:len(valid)/2],
		"not json":          "cowrie dionaea",
		"an array":          `["cowrie"]`,
		"null":              "null",
		"no version":        `{"stopped":[{"name":"cowrie","stopped_at":"2026-11-12T09:30:15Z"}]}`,
		"another version":   `{"version":2,"stopped":[{"name":"cowrie","stopped_at":"2026-11-12T09:30:15Z"}]}`,
		"unknown field":     `{"version":1,"stopped":[],"start":["cowrie"]}`,
		"unknown in entry":  `{"version":1,"stopped":[{"name":"cowrie","stopped_at":"2026-11-12T09:30:15Z","x":1}]}`,
		"name is a flag":    `{"version":1,"stopped":[{"name":"--volumes","stopped_at":"2026-11-12T09:30:15Z"}]}`,
		"name with a space": `{"version":1,"stopped":[{"name":"cowrie dionaea","stopped_at":"2026-11-12T09:30:15Z"}]}`,
		"name upper case":   `{"version":1,"stopped":[{"name":"Cowrie","stopped_at":"2026-11-12T09:30:15Z"}]}`,
		"empty name":        `{"version":1,"stopped":[{"name":"","stopped_at":"2026-11-12T09:30:15Z"}]}`,
		"name is a number":  `{"version":1,"stopped":[{"name":7,"stopped_at":"2026-11-12T09:30:15Z"}]}`,
		"bad time":          `{"version":1,"stopped":[{"name":"cowrie","stopped_at":"yesterday"}]}`,
		"year before 0":     `{"version":1,"stopped":[{"name":"cowrie","stopped_at":"0000-01-01T00:00:00+10:00"}]}`,
		"year after 9999":   `{"version":1,"stopped":[{"name":"cowrie","stopped_at":"9999-12-31T23:00:00-10:00"}]}`,
		"listed twice":      `{"version":1,"stopped":[{"name":"cowrie","stopped_at":"2026-11-12T09:30:15Z"},{"name":"cowrie","stopped_at":"2026-11-12T09:30:15Z"}]}`,
		"stopped is a map":  `{"version":1,"stopped":{"cowrie":true}}`,
		"data after":        valid + valid,
		"text after":        valid + " x",
		"too many":          many,
		"too large":         `{"version":1,"stopped":[]}` + strings.Repeat(" ", maxStateBytes),
	}
	dir := t.TempDir()
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := ParseState([]byte(content))
			if err == nil {
				t.Fatalf("ParseState accepted it: %+v", s)
			}
			if s.Held() {
				t.Fatalf("a refused file still lists %v", s.Names())
			}
			// The same through the file.
			path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			s, err = LoadState(path)
			if err == nil || s.Held() {
				t.Fatalf("LoadState: %+v, %v", s, err)
			}
			// The error never repeats what the file holds.
			if strings.Contains(err.Error(), "--volumes") || strings.Contains(err.Error(), "cowrie dionaea") {
				t.Errorf("the error repeats the file's content: %v", err)
			}
		})
	}
	// An empty list is a valid file that lists nothing.
	for _, ok := range []string{`{"version":1,"stopped":[]}`, `{"version":1,"stopped":null}`, `{"version":1}`, " " + valid + "\n"} {
		if _, err := ParseState([]byte(ok)); err != nil {
			t.Errorf("ParseState(%q): %v", ok, err)
		}
	}
	// A folder in the file's place is an error too, and lists nothing.
	asDir := filepath.Join(dir, "as-dir")
	if err := os.Mkdir(asDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if s, err := LoadState(asDir); err == nil || s.Held() {
		t.Fatalf("a folder as the state file: %+v, %v", s, err)
	}
}

// TestSaveReplacesACorruptFile: the next save puts a damaged file right.
func TestSaveReplacesACorruptFile(t *testing.T) {
	path := Path(t.TempDir())
	if err := os.WriteFile(path, []byte("{{{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := LoadState(path); err == nil || s.Held() {
		t.Fatalf("damaged file: %+v, %v", s, err)
	}
	var s State
	s.Add("cowrie", stoppedAt)
	if err := SaveState(path, s); err != nil {
		t.Fatal(err)
	}
	if back, err := LoadState(path); err != nil || !back.Has("cowrie") {
		t.Fatalf("after the save: %+v, %v", back, err)
	}
	if err := os.WriteFile(path, []byte("{{{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveState(path, State{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("saving an empty state left the damaged file: %v", err)
	}
}

// TestSaveFailsWithoutTheFolder: a save that cannot write says so and leaves
// nothing half-written.
func TestSaveFailsWithoutTheFolder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gone", StateFile)
	var s State
	s.Add("cowrie", stoppedAt)
	if err := SaveState(path, s); err == nil {
		t.Fatal("SaveState into a missing folder reported success")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("left behind: %v", entries)
	}
}

// FuzzParseState: whatever the file holds, the parser does not panic, and
// what it accepts is a bounded list of distinct honeypot names that writes
// and reads back the same.
func FuzzParseState(f *testing.F) {
	for _, seed := range []string{
		"",
		"null",
		"{}",
		`{"version":1}`,
		`{"version":1,"stopped":[]}`,
		`{"version":1,"stopped":[{"name":"cowrie","stopped_at":"2026-11-12T09:30:15Z"}]}`,
		`{"version":1,"stopped":[{"name":"ssh-proxy","stopped_at":"2026-11-12T09:30:15+10:00"},{"name":"cowrie","stopped_at":"0001-01-01T00:00:00Z"}]}`,
		`{"version":1,"stopped":[{"name":"--volumes","stopped_at":"2026-11-12T09:30:15Z"}]}`,
		`{"version":1,"stopped":[{"name":"cowrie","stopped_at":"0000-01-01T00:00:00+10:00"}]}`,
		`{"version":1,"stopped":[{"name":"cowrie","stopped_at":"9999-12-31T23:00:00-10:00"}]}`,
		`{"version":2,"stopped":[]}`,
		`{"version":1,"stopped":[{"name":"a"},{"name":"a"}]}`,
		`{"version":1,"stopped":[{"name":"a","stopped_at":null}]}`,
		`{"_qpot_encoding":"base64-strings-v1","data":{}}`,
		`{"version":1,"stopped":[]}{"version":1}`,
		"[1,2,3]",
		"\x00\xff",
		`{"version":1e0,"stopped":[]}`,
		`{"VERSION":1,"Stopped":[{"NAME":"cowrie","Stopped_At":"2026-11-12T09:30:15Z"}]}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := ParseState(data)
		if err != nil {
			if s.Held() {
				t.Fatalf("a refused state lists %v", s.Names())
			}
			return
		}
		if len(data) > maxStateBytes {
			t.Fatalf("accepted %d bytes", len(data))
		}
		if len(s.Stopped) > MaxStopped {
			t.Fatalf("accepted %d entries", len(s.Stopped))
		}
		seen := map[string]bool{}
		for i, e := range s.Stopped {
			if !namePattern.MatchString(e.Name) {
				t.Fatalf("accepted the name %q", e.Name)
			}
			if seen[e.Name] {
				t.Fatalf("accepted %q twice", e.Name)
			}
			seen[e.Name] = true
			if i > 0 && s.Stopped[i-1].Name >= e.Name {
				t.Fatalf("not in order: %v", s.Names())
			}
		}
		out, err := s.Marshal()
		if err != nil {
			// A time outside what JSON can carry cannot have been read.
			t.Fatalf("an accepted state does not encode: %v", err)
		}
		back, err := ParseState(out)
		if err != nil {
			t.Fatalf("an accepted state does not read back: %v\n%s", err, out)
		}
		if !reflect.DeepEqual(back.Names(), s.Names()) {
			t.Fatalf("names changed on the way: %v, then %v", s.Names(), back.Names())
		}
		for i := range back.Stopped {
			if !back.Stopped[i].StoppedAt.Equal(s.Stopped[i].StoppedAt) {
				t.Fatalf("time of %s changed: %v, then %v", s.Stopped[i].Name, s.Stopped[i].StoppedAt, back.Stopped[i].StoppedAt)
			}
		}
		again, err := back.Marshal()
		if err != nil || !bytes.Equal(again, out) {
			t.Fatalf("the second encoding differs: %v\n%s\n%s", err, out, again)
		}
	})
}
