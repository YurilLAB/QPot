package vectorstate

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestFingerprintsMatchTheCollector: the checksum and the checkpoints file
// are the collector's own. The values come from Vector 0.61 (the pinned
// collector image) reading these exact lines.
func TestFingerprintsMatchTheCollector(t *testing.T) {
	if got := crc64ECMA182([]byte("123456789")); got != 0x6c40df5f0b497347 {
		t.Fatalf("CRC-64/ECMA-182 check value: %#x", got)
	}
	for line, want := range map[string]uint64{
		`{"other":1}` + "\n":              12616341708018161462,
		`{"n":1,"x":"first line"}` + "\n": 8010487477755392035,
	} {
		got, ok := Fingerprint(strings.NewReader(line + `{"n":2}` + "\n"))
		if !ok || got != want {
			t.Errorf("Fingerprint(%q) = %d %v, want %d", line, got, ok, want)
		}
	}
	// No whole first line yet, or one longer than the collector reads.
	for _, s := range []string{"", `{"partial":`, strings.Repeat("x", MaxLine+1) + "\n"} {
		if _, ok := Fingerprint(strings.NewReader(s)); ok {
			t.Errorf("fingerprint of %d bytes without a whole first line", len(s))
		}
	}

	data := t.TempDir()
	dir := filepath.Join(data, Dir, "cowrie_logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(s string) {
		if err := os.WriteFile(filepath.Join(dir, "checkpoints.json"), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// As Vector 0.61 wrote it.
	write(`{"version":"1","checkpoints":[{"fingerprint":{"first_lines_checksum":8010487477755392035},"position":49,"modified":"2026-11-08T22:45:46.219653150Z"},{"fingerprint":{"first_lines_checksum":12616341708018161462},"position":12,"modified":"2026-11-08T22:45:40.059927532Z"}]}`)
	d := Load(data, HoneypotSource("cowrie"))
	if d[8010487477755392035] != 49 || d[12616341708018161462] != 12 || len(d) != 2 {
		t.Errorf("checkpoints read as %v", d)
	}
	if Load(data, HoneypotSource("dionaea")) != nil {
		t.Error("a source without checkpoints has some")
	}
	write(`{"version":"1","checkpoints":[{"fingerprint":{"first_lines_checksum":7},"position":5},{"fingerprint":{"first_line_checksum":7},"position":9},{"fingerprint":{"dev_inode":[1,2]},"position":3}]}`)
	if d := Load(data, "cowrie_logs"); d[7] != -1 || len(d) != 1 {
		t.Errorf("a shared fingerprint, an inode fingerprint: %v", d)
	}
	for _, bad := range []string{`{"version":"2","checkpoints":[]}`, `not json`, ``} {
		write(bad)
		if Load(data, "cowrie_logs") != nil {
			t.Errorf("checkpoints read from %q", bad)
		}
	}
}

func writeFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestSeed: the logs a source reads count as delivered as far as they go;
// what it does not read, a log without a whole first line, a symlink, and
// logs the collector cannot tell apart (a shared first line) are left out. A
// source with state is never seeded again.
func TestSeed(t *testing.T) {
	data := t.TempDir()
	logs := filepath.Join(data, "honeypots", "cowrie", "logs")
	writeFile(t, filepath.Join(logs, "cowrie.json"), "{\"a\":1}\n{\"a\":2}\n")
	writeFile(t, filepath.Join(logs, "sub", "x.log"), "line one\n")
	writeFile(t, filepath.Join(logs, "copy.json"), "{\"a\":1}\nother\n") // same first line as cowrie.json
	writeFile(t, filepath.Join(logs, "tty", "s.log"), "recording\n")     // not read
	writeFile(t, filepath.Join(logs, "cowrie.json.1"), "rotated\n")      // not read
	writeFile(t, filepath.Join(logs, "partial.json"), "{\"no newline\"") // no fingerprint yet
	outside := filepath.Join(data, "secret.json")
	writeFile(t, outside, "secret\n")
	if runtime.GOOS != "windows" {
		if err := os.Symlink(outside, filepath.Join(logs, "link.json")); err != nil {
			t.Fatal(err)
		}
	}
	src := Source{Name: HoneypotSource("cowrie"), Dir: "honeypots/cowrie/logs", Read: func(rel string) bool {
		return !strings.HasPrefix(rel, "tty/") && (strings.HasSuffix(rel, ".json") || strings.HasSuffix(rel, ".log"))
	}}
	n, err := Seed(data, src, time.Now(), nil)
	if err != nil || n != 1 {
		t.Fatalf("Seed = %d %v, want 1 log", n, err)
	}
	d := Load(data, src.Name)
	fp := func(s string) uint64 { v, _ := Fingerprint(strings.NewReader(s)); return v }
	if d[fp("line one\n")] != 9 || len(d) != 1 {
		t.Errorf("seeded %v", d)
	}
	if _, ok := d[fp("{\"a\":1}\n")]; ok {
		t.Error("seeded logs sharing a first line")
	}
	// Control: once the copy differs, cowrie.json is seeded too.
	if err := os.Remove(filepath.Join(data, Dir, src.Name, "checkpoints.json")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(logs, "copy.json"), "{\"b\":1}\n")
	if n, err := Seed(data, src, time.Now(), nil); err != nil || n != 3 || Load(data, src.Name)[fp("{\"a\":1}\n")] != 16 {
		t.Fatalf("control: Seed = %d %v, %v", n, err, Load(data, src.Name))
	}
	if _, ok := d[fp("secret\n")]; ok {
		t.Error("seeded through a symlink")
	}
	before, _ := os.ReadFile(filepath.Join(data, Dir, src.Name, "checkpoints.json"))
	writeFile(t, filepath.Join(logs, "new.json"), "{\"new\":1}\n")
	if n, err := Seed(data, src, time.Now(), nil); err != nil || n != 0 {
		t.Fatalf("second Seed = %d %v", n, err)
	}
	after, _ := os.ReadFile(filepath.Join(data, Dir, src.Name, "checkpoints.json"))
	if string(before) != string(after) {
		t.Error("a source with state was seeded again")
	}
	// A source with no logs yet gets empty state.
	if n, err := Seed(data, Source{Name: "p0f_log", Dir: "p0f/log", Read: func(string) bool { return true }}, time.Now(), nil); err != nil || n != 0 {
		t.Fatalf("empty source: %d %v", n, err)
	}
	if d := Load(data, "p0f_log"); d == nil || len(d) != 0 {
		t.Errorf("empty source state: %v", d)
	}
}

// A log that belongs to a container's user cannot be opened by an ordinary
// user running QPot. Seeding used to skip it without a word, so the collector
// read it from its start and every event in it was stored a second time
// (found by the upgrade rehearsal from 1.0.1). Now the privileged reader is
// asked for the whole source, and without one nothing is written.
func TestSeedReadsWhatThisUserMayNot(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a file this process may not read")
	}
	data := t.TempDir()
	logs := filepath.Join(data, "honeypots", "cowrie", "logs")
	const mine, theirs = "{\"mine\":1}\n{\"mine\":2}\n", "{\"theirs\":1}\n{\"theirs\":2}\n{\"theirs\":3}\n"
	writeFile(t, filepath.Join(logs, "readable.json"), mine)
	writeFile(t, filepath.Join(logs, "cowrie.json"), theirs)
	if err := os.Chmod(filepath.Join(logs, "cowrie.json"), 0); err != nil {
		t.Fatal(err)
	}
	src := Source{Name: HoneypotSource("cowrie"), Dir: "honeypots/cowrie/logs", Read: func(rel string) bool { return strings.HasSuffix(rel, ".json") }}
	fp := func(line string) uint64 { v, _ := Fingerprint(strings.NewReader(line)); return v }

	if n, err := Seed(data, src, time.Now(), nil); err == nil {
		t.Fatalf("Seed without a privileged reader = %d, want an error: a skipped log is sent again in full", n)
	}
	if Load(data, src.Name) != nil {
		t.Fatal("state was written although a log could not be read")
	}

	var asked []string
	reader := func(dir string, read func(string) bool) ([]LogFile, error) {
		asked = append(asked, dir)
		if !read("cowrie.json") || read("cowrie.txt") {
			t.Error("the reader was not given the source's own filter")
		}
		return []LogFile{
			{Rel: "readable.json", Size: int64(len(mine)), FirstLine: []byte("{\"mine\":1}\n")},
			{Rel: "cowrie.json", Size: int64(len(theirs)), FirstLine: []byte("{\"theirs\":1}\n")},
			{Rel: "started.json", Size: 5, FirstLine: nil},                            // no whole line yet
			{Rel: "odd.json", Size: 3, FirstLine: []byte("{\"longer than it\":1}\n")}, // shrank since it was listed
		}, nil
	}
	n, err := Seed(data, src, time.Now(), reader)
	if err != nil || n != 2 {
		t.Fatalf("Seed = %d %v, want both logs", n, err)
	}
	if len(asked) != 1 || asked[0] != logs {
		t.Errorf("the reader was asked for %v, want the source's folder once", asked)
	}
	d := Load(data, src.Name)
	if d[fp(theirs)] != int64(len(theirs)) || d[fp(mine)] != int64(len(mine)) || len(d) != 2 {
		t.Errorf("seeded %v", d)
	}

	// A reader that fails leaves no state behind, so the next start tries again.
	other := Source{Name: "other_logs", Dir: "honeypots/cowrie/logs", Read: src.Read}
	failing := func(string, func(string) bool) ([]LogFile, error) { return nil, errors.New("no docker") }
	if _, err := Seed(data, other, time.Now(), failing); err == nil || Load(data, other.Name) != nil {
		t.Errorf("a failed reader: err %v, state %v", err, Load(data, other.Name))
	}
}
