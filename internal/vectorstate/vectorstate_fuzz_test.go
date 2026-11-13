package vectorstate

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoad: the collector's checkpoints file is written by a container, and
// disk cleanup empties a log only as far as that file says the log was
// delivered. Whatever the file holds, reading it never fails the caller, and
// never yields a position cleanup could take for "delivered" that the file
// did not state: no negative position but the -1 that marks a fingerprint two
// checkpoints share, which confirms nothing.
func FuzzLoad(f *testing.F) {
	f.Add([]byte(`{"version":"1","checkpoints":[{"fingerprint":{"first_lines_checksum":406960853713952337},"position":99887,"modified":"2026-11-13T12:22:44Z"}]}`))
	f.Add([]byte(`{"version":"1","checkpoints":[{"fingerprint":{"first_lines_checksum":1},"position":5},{"fingerprint":{"first_line_checksum":1},"position":9}]}`))
	f.Add([]byte(`{"version":"1","checkpoints":[{"fingerprint":{"first_lines_checksum":7},"position":-3}]}`))
	f.Add([]byte(`{"version":"2","checkpoints":[{"fingerprint":{"first_lines_checksum":7},"position":3}]}`))
	f.Add([]byte(`{"version":"1","checkpoints":[{"fingerprint":{"dev_inode":[1,2]},"position":3}]}`))
	f.Add([]byte(`[`))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := checkpointsPath(dir, "cowrie_logs")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		for fp, pos := range Load(dir, "cowrie_logs") {
			if pos < -1 {
				t.Fatalf("fingerprint %d is delivered up to %d", fp, pos)
			}
		}
	})
}

// FuzzFingerprint: a log has a fingerprint only once it has a whole first
// line within the collector's longest line, and then it is the checksum of
// that line alone: what follows the first newline never changes it.
func FuzzFingerprint(f *testing.F) {
	f.Add([]byte("{\"eventid\":\"cowrie.session.connect\"}\n"), []byte("more\n"))
	f.Add([]byte("no newline"), []byte(""))
	f.Add([]byte("\n"), []byte("\n"))
	f.Add(bytes.Repeat([]byte("x"), MaxLine), []byte("\nrest"))
	f.Fuzz(func(t *testing.T, first, rest []byte) {
		fp, ok := Fingerprint(bytes.NewReader(first))
		newline := bytes.IndexByte(first, '\n')
		if want := newline >= 0 && newline < MaxLine+1; ok != want {
			t.Fatalf("a log of %d bytes with its first newline at %d: fingerprint %v, want %v", len(first), newline, ok, want)
		}
		if !ok {
			return
		}
		if again, ok2 := Fingerprint(bytes.NewReader(append(append([]byte{}, first...), rest...))); !ok2 || again != fp {
			t.Fatalf("what follows the first line changed the fingerprint: %d to %d (%v)", fp, again, ok2)
		}
		if line, ok3 := Fingerprint(bytes.NewReader(first[:newline+1])); !ok3 || line != fp || fp != crc64ECMA182(first[:newline+1]) {
			t.Fatalf("the fingerprint is not the checksum of the first line: %d, %d", fp, line)
		}
	})
}
