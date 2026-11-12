package sshcapture

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// FuzzWriterReplay drives the writer with arbitrary capture streams, as guest
// root can write them, from containers at arbitrary points of their limits.
// Whatever the stream: the writer does not fail or panic; a follower cut off
// anywhere, followed by a whole replay, leaves every session with at most one
// start and one finish line (never a finish without its start); a second
// whole replay changes nothing; every record line is valid JSON; and the
// counters that bound what the host keeps stay inside their limits. The same
// holds when another writer (a reset's drain) replays part of the stream
// between two batches of a follower that then goes on.
func FuzzWriterReplay(f *testing.F) {
	f.Add([]byte{0, 0, 1, 1, 0, 9, 4, 0, 0, 5, 0, 0}, uint16(0), uint32(0), uint8(3))
	f.Add([]byte{0, 0, 1, 0, 1, 2, 1, 1, 200, 4, 1, 3, 5, 1, 0, 5, 0, 0}, uint16(softUserFiles), uint32(0), uint8(7))
	f.Add([]byte{0, 2, 3, 2, 2, 50, 3, 2, 50, 6, 2, 0, 4, 2, 1, 0, 2, 4, 5, 2, 0}, uint16(softUserFiles-3), uint32(softUserBytes>>10), uint8(11))
	f.Add([]byte{7, 0, 0, 1, 0, 255, 0, 0, 0, 0, 0, 0, 5, 0, 0}, uint16(maxUserFiles), uint32(maxUserBytes>>10), uint8(2))
	f.Fuzz(func(t *testing.T, program []byte, usedFiles uint16, usedKiB uint32, cut uint8) {
		if len(program) > 600 {
			program = program[:600]
		}
		e := newEmitter(testConn)
		for i := 0; i+2 < len(program); i += 3 {
			ch, arg := int(program[i+1]%6), int(program[i+2])
			switch program[i] % 8 {
			case 0:
				e.open(ch, map[int]int{0: 0, 1: 1000, 2: 33}[arg%3], arg&4 != 0, 41000+ch, strings.Repeat("c", arg%40))
			case 1:
				e.rec(ch, KindOutput, int64(arg), []byte(strings.Repeat("o", arg*8)))
			case 2:
				e.rec(ch, KindInput, int64(arg), []byte(strings.Repeat("i", arg)))
			case 3:
				e.rec(ch, KindError, int64(arg), []byte(strings.Repeat("e", arg)))
			case 4:
				e.rec(ch, KindExit, int64(arg), []byte(fmt.Sprintf("exit=%d", arg)))
			case 5:
				e.rec(ch, KindClosed, int64(arg), nil)
			case 6:
				e.rec(ch, KindTruncated, int64(arg), nil)
			case 7:
				e.lines = append(e.lines, []byte(strings.Repeat("not a record ", arg%4)))
			}
		}
		dir := t.TempDir()
		// The same starting point for every replay, as every replay of one
		// container reads the same stream from its first line.
		writer := func() *Writer {
			t.Helper()
			w, err := NewWriter(dir, testContainer, testCreated, nil)
			if err != nil {
				t.Fatal(err)
			}
			files := min(int(usedFiles), maxUserFiles)
			bytes := min(int64(usedKiB)<<10, int64(maxUserBytes))
			w.usage[0] = &usage{files: files, bytes: bytes}
			w.total = usage{files: files, bytes: bytes}
			return w
		}
		replay := func(lines [][]byte) *Writer {
			w := writer()
			for _, l := range lines {
				if err := w.Apply(l); err != nil {
					t.Fatalf("Apply: %v", err)
				}
			}
			if err := w.Finish(); err != nil {
				t.Fatalf("Finish: %v", err)
			}
			return w
		}
		at := 0
		if len(e.lines) > 0 {
			at = int(cut) % (len(e.lines) + 1)
		}
		replay(e.lines[:at]) // a follower whose stream ended early
		w := replay(e.lines)
		files := snapshot(t, dir)
		invariants(t, w, files)

		replay(e.lines)
		again := snapshot(t, dir)
		if len(again) != len(files) {
			t.Fatalf("a second whole replay changed the folder: %d files, then %d", len(files), len(again))
		}
		for name, body := range files {
			if again[name] != body {
				t.Fatalf("a second whole replay changed %s", name)
			}
		}

		// In a folder of its own: a follower part-way through the stream
		// lets go of the folder, a drain replays the stream from its first
		// line and is cut off somewhere, and the follower goes on with what
		// it knew.
		dir = t.TempDir()
		follower := writer()
		for _, l := range e.lines[:at] {
			if err := follower.Apply(l); err != nil {
				t.Fatalf("Apply: %v", err)
			}
		}
		if err := follower.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		replay(e.lines[:(at*7+int(cut))%(len(e.lines)+1)])
		for _, l := range e.lines[at:] {
			if err := follower.Apply(l); err != nil {
				t.Fatalf("Apply: %v", err)
			}
		}
		if err := follower.Finish(); err != nil {
			t.Fatalf("Finish: %v", err)
		}
		invariants(t, follower, snapshot(t, dir))
	})
}

// invariants are what holds of a capture folder and the writer that last
// wrote it, whatever the stream and however its replays were cut.
func invariants(t *testing.T, w *Writer, files map[string]string) {
	t.Helper()
	{
		if w.total.files > maxContainerFiles || w.total.bytes > maxContainerBytes+64<<10 || w.overflowBytes > maxOverflowBytes+64<<10 {
			t.Fatalf("past the container's limits: %+v, overflow %d", w.total, w.overflowBytes)
		}
		for uid, u := range w.usage {
			if u.files > maxUserFiles+1 || u.bytes > maxUserBytes+64<<10 {
				t.Fatalf("account %d past its limits: %+v", uid, u)
			}
		}
		starts, finishes := map[string]int{}, map[string]int{}
		for name, body := range files {
			if !strings.HasPrefix(name, "uid-") || strings.Count(name, "/") != 1 {
				t.Fatalf("a file outside an account's folder: %q", name)
			}
			if !strings.HasSuffix(name, ".json") {
				continue
			}
			if body != "" && !strings.HasSuffix(body, "\n") {
				t.Fatalf("%s does not end in a whole line", name)
			}
			for _, line := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
				var ev SessionEvent
				if err := json.Unmarshal([]byte(line), &ev); err != nil || ev.Session == "" {
					t.Fatalf("%s holds a line that is not a record: %q (%v)", name, line, err)
				}
				switch ev.Phase {
				case "start":
					starts[ev.Session]++
				case "finish":
					finishes[ev.Session]++
				default:
					t.Fatalf("%s: phase %q", name, ev.Phase)
				}
			}
		}
		for s, n := range starts {
			if n != 1 || finishes[s] > 1 {
				t.Fatalf("session %s has %d start and %d finish lines", s, n, finishes[s])
			}
		}
		for s := range finishes {
			if starts[s] != 1 {
				t.Fatalf("session %s has a finish line without its start", s)
			}
		}
	}
}
