package sshcapture

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

const testContainer = "4f1c0de5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3"

// emitter writes capture lines the way the backend's sshd does.
type emitter struct {
	conn  string
	seq   map[int]uint64
	lines [][]byte
}

func newEmitter(conn string) *emitter { return &emitter{conn: conn, seq: map[int]uint64{}} }

func (e *emitter) rec(ch int, kind Kind, ms int64, payload []byte) {
	l := fmt.Sprintf("%s %d %d %c %d %s", e.conn, ch, e.seq[ch], kind, ms, base64.StdEncoding.EncodeToString(payload))
	e.seq[ch]++
	e.lines = append(e.lines, []byte(l))
}

func (e *emitter) open(ch, uid int, pty bool, rport int, command string) {
	e.seq[ch] = 0
	for off := 0; off < len(command); off += maxPayload {
		e.rec(ch, KindCommand, 0, []byte(command[off:min(len(command), off+maxPayload)]))
	}
	p := map[bool]int{false: 0, true: 1}
	cmd := 0
	if command != "" {
		cmd = 1
	}
	e.rec(ch, KindOpen, 0, []byte(fmt.Sprintf("time=1731136000123 uid=%d pty=%d sub=0 cmd=%d rport=%d lport=22 rip=172.20.0.10 host=web01 user=%s", uid, p[pty], cmd, rport, map[int]string{0: "root"}[uid]+"u")))
}

func apply(t *testing.T, dir string, lines [][]byte, attribute Attributor) {
	t.Helper()
	w, err := NewWriter(dir, testContainer, testCreated, attribute)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		if err := w.Apply(l); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Finish(); err != nil {
		t.Fatal(err)
	}
}

// snapshot reads every file below dir.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		rel, _ := filepath.Rel(dir, p)
		files[filepath.ToSlash(rel)] = string(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func records(t *testing.T, files map[string]string) map[string][]SessionEvent {
	t.Helper()
	out := map[string][]SessionEvent{}
	for name, body := range files {
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
			var ev SessionEvent
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			out[name] = append(out[name], ev)
		}
	}
	return out
}

func session(e *emitter) {
	e.open(0, 0, false, 41000, "uname -a")
	e.rec(0, KindInput, 1, []byte("stdin-bytes"))
	e.rec(0, KindOutput, 2, []byte("Linux web01\n"))
	e.rec(0, KindError, 3, []byte("warning\n"))
	e.rec(0, KindExit, 4, []byte("exit=3"))
	e.rec(0, KindOutput, 5, []byte("late\n")) // drained after the exit
	e.rec(0, KindClosed, 6, nil)
}

// A session the broker can pin only on the visitor carries its address and
// lease, but no connection.
func TestWriterNamesTheVisitorWhenNoConnectionIsKnown(t *testing.T) {
	e := newEmitter(testConn)
	session(e)
	dir := t.TempDir()
	gen := uint64(9)
	apply(t, dir, e.lines, func(Open, time.Time) (Attribution, bool) {
		return Attribution{SrcIP: "203.0.113.9", Generation: &gen, Visitor: true}, true
	})
	recs := records(t, snapshot(t, dir))
	if len(recs) != 1 {
		t.Fatalf("want one command record, got %d", len(recs))
	}
	for _, evs := range recs {
		for _, ev := range evs {
			if ev.Attribution != "broker-visitor" || ev.SrcIP != "203.0.113.9" || ev.SrcPort != 0 || ev.SessionID != "" || ev.Generation == nil || *ev.Generation != 9 {
				t.Fatalf("visitor attribution: %+v", ev)
			}
		}
	}
}

func TestWriterWritesTheCollectorRecord(t *testing.T) {
	e := newEmitter(testConn)
	session(e)
	dir := t.TempDir()
	gen := uint64(7)
	apply(t, dir, e.lines, func(o Open, since time.Time) (Attribution, bool) {
		if !since.Equal(testCreated) {
			t.Fatalf("attributor got creation %v", since)
		}
		if o.PeerIP != "172.20.0.10" || o.PeerPort != 41000 {
			t.Fatalf("attributor got %+v", o)
		}
		return Attribution{SrcIP: "203.0.113.9", SrcPort: 55555, SessionID: strings.Repeat("ab", 16), Generation: &gen}, true
	})
	files := snapshot(t, dir)
	recs := records(t, files)
	if len(recs) != 1 {
		t.Fatalf("want one command record, got %v", files)
	}
	for name, evs := range recs {
		if !strings.HasPrefix(name, "uid-0/20241109T070640Z-") || len(evs) != 2 {
			t.Fatalf("record %s has %d lines", name, len(evs))
		}
		start, finish := evs[0], evs[1]
		if start.EventType != "ssh_backend_command_start" || start.Phase != "start" || finish.EventType != "ssh_backend_command" || finish.Phase != "finish" {
			t.Fatalf("phases: %+v / %+v", start, finish)
		}
		if start.Input != "uname -a" || start.SrcIP != "203.0.113.9" || start.SrcPort != 55555 || start.PeerIP != "172.20.0.10" || start.PeerPort != 41000 ||
			start.Attribution != "broker-cell" || start.Generation == nil || *start.Generation != 7 || start.Hostname != "web01" || start.Username != "rootu" {
			t.Fatalf("start record: %+v", start)
		}
		if finish.ExitCode == nil || *finish.ExitCode != 3 || finish.DurationMS != 6 || finish.Stdout != "Linux web01\nlate\n" || finish.Stderr != "warning\n" || finish.CaptureError != "" {
			t.Fatalf("finish record: %+v", finish)
		}
		base := strings.TrimSuffix(name, ".json")
		if files[base+".in"] != "stdin-bytes" || files[base+".out"] != "Linux web01\nlate\n" || files[base+".err"] != "warning\n" {
			t.Fatalf("streams: %q %q %q", files[base+".in"], files[base+".out"], files[base+".err"])
		}
		if start.StdoutFile != filepath.Base(base)+".out" || start.TimingFile != "" {
			t.Fatalf("file names: %+v", start)
		}
	}
}

func TestWriterReplayIsIdempotent(t *testing.T) {
	e := newEmitter(testConn)
	session(e)
	other := newEmitter(strings.Repeat("f", 32))
	other.open(3, 1000, true, 42000, "")
	other.rec(3, KindInput, 10, []byte("ls\r"))
	other.rec(3, KindOutput, 1250, []byte("ls\r\nfile\r\n"))
	other.rec(3, KindExit, 1300, []byte("signal=9"))
	other.rec(3, KindClosed, 1300, nil)
	// Interleave the two connections as concurrent writers to one pipe would.
	var lines [][]byte
	for i := 0; i < max(len(e.lines), len(other.lines)); i++ {
		if i < len(e.lines) {
			lines = append(lines, e.lines[i])
		}
		if i < len(other.lines) {
			lines = append(lines, other.lines[i])
		}
	}
	once, twice, crashed := t.TempDir(), t.TempDir(), t.TempDir()
	apply(t, once, lines, nil)
	apply(t, twice, lines, nil)
	apply(t, twice, lines, nil)
	// A follower that stopped half way, then a full replay.
	apply(t, crashed, lines[:len(lines)/2], nil)
	apply(t, crashed, lines, nil)
	want := snapshot(t, once)
	if len(want) != 9 {
		t.Fatalf("want two commands (5 + 4 files), got %d: %v", len(want), keys(want))
	}
	for name, dir := range map[string]string{"replayed": twice, "crash then replay": crashed} {
		if got := snapshot(t, dir); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%s files differ:\n%v\n%v", name, keys(got), keys(want))
		}
	}
	for name, evs := range records(t, want) {
		if len(evs) != 2 {
			t.Fatalf("%s has %d lines", name, len(evs))
		}
		if strings.HasPrefix(name, "uid-1000/") {
			base := strings.TrimSuffix(name, ".json")
			if evs[1].ExitCode == nil || *evs[1].ExitCode != 137 || !evs[0].PTY || evs[1].Input != "ls\r" ||
				want[base+".timing"] != "I 0.010000 3\nO 1.240000 10\n" || evs[0].Attribution != "peer-only" || evs[0].SrcIP != "172.20.0.10" {
				t.Fatalf("pty session: %+v timing %q", evs[1], want[base+".timing"])
			}
		}
	}
}

func TestWriterKeepsReusedChannelsApart(t *testing.T) {
	e := newEmitter(testConn)
	for i := 0; i < 2; i++ {
		e.open(0, 0, false, 41000, fmt.Sprintf("echo %d", i))
		e.rec(0, KindOutput, 1, []byte(fmt.Sprintf("%d\n", i)))
		e.rec(0, KindExit, 1, []byte("exit=0"))
		e.rec(0, KindClosed, 2, nil)
	}
	dir := t.TempDir()
	apply(t, dir, e.lines, nil)
	recs := records(t, snapshot(t, dir))
	if len(recs) != 2 {
		t.Fatalf("a reused channel merged sessions: %v", recs)
	}
	seen := map[string]bool{}
	for _, evs := range recs {
		seen[evs[1].Input+"|"+evs[1].Stdout] = true
	}
	if !seen["echo 0|0\n"] || !seen["echo 1|1\n"] {
		t.Fatalf("sessions: %v", seen)
	}
}

func TestWriterAbruptTeardown(t *testing.T) {
	e := newEmitter(testConn)
	e.open(0, 0, false, 41000, "sleep 100")
	e.rec(0, KindOutput, 1, []byte("partial"))
	e.open(1, 0, false, 41000, "true")
	e.rec(1, KindExit, 2, []byte("exit=0")) // exited; the close never arrived
	dir := t.TempDir()
	apply(t, dir, e.lines, nil)
	for name, evs := range records(t, snapshot(t, dir)) {
		switch evs[0].Input {
		case "sleep 100":
			if len(evs) != 1 {
				t.Fatalf("%s: an unfinished command gained a finish: %+v", name, evs)
			}
		case "true":
			if len(evs) != 2 || evs[1].ExitCode == nil || *evs[1].ExitCode != 0 {
				t.Fatalf("%s: a captured exit was not finished: %+v", name, evs)
			}
		default:
			t.Fatalf("unexpected record %s", name)
		}
	}
}

func TestWriterLimitsAndTruncation(t *testing.T) {
	long := strings.Repeat("x", maxCommand+maxPayload)
	e := newEmitter(testConn)
	e.open(0, 0, false, 41000, long)
	e.rec(0, KindTruncated, 1, nil)
	e.rec(0, KindExit, 2, []byte("exit=0"))
	e.rec(0, KindClosed, 2, nil)
	dir := t.TempDir()
	apply(t, dir, e.lines, nil)
	for _, evs := range records(t, snapshot(t, dir)) {
		if len(evs[0].Input) != maxCommand || !evs[0].CommandTruncated || !evs[1].Truncated {
			t.Fatalf("long command / truncation not recorded: %d %v %v", len(evs[0].Input), evs[0].CommandTruncated, evs[1].Truncated)
		}
	}

	// Inside the reserve of the per-account file limit, commands keep their
	// record but no streams.
	e = newEmitter(testConn)
	n := softUserFiles/filesPerEntry + 3
	for i := 0; i < n; i++ {
		e.open(i, 0, false, 41000, "true")
		e.rec(i, KindOutput, 1, []byte("o"))
		e.rec(i, KindExit, 1, []byte("exit=0"))
		e.rec(i, KindClosed, 1, nil)
	}
	dir = t.TempDir()
	apply(t, dir, e.lines, nil)
	limited := 0
	for _, evs := range records(t, snapshot(t, dir)) {
		if strings.Contains(evs[1].CaptureError, "account capture limit") {
			limited++
			if !evs[1].Truncated || evs[1].Stdout != "" {
				t.Fatalf("limited command: %+v", evs[1])
			}
		}
	}
	if limited != 3 {
		t.Fatalf("want exactly three limited commands, got %d", limited)
	}
}

// A visitor who stays in one cell and keeps running commands used to pass the
// per-account file limit after 409 of them, and every later command then ran
// without leaving any record (found by the HiFi capture soak: the 413th
// command of a 21-minute session). The writer now says the capture is full
// while there is still room, so the follower can stop the cell, and every
// command up to the hard limit keeps at least its record.
func TestWriterSaysFullBeforeAnyCommandGoesUnrecorded(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir, testContainer, testCreated, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := newEmitter(testConn)
	fullAt, applied := 0, 0
	run := func(i int) {
		t.Helper()
		e.open(i, 0, false, 41000, fmt.Sprintf("echo %d", i))
		e.rec(i, KindOutput, 1, []byte("o"))
		e.rec(i, KindExit, 1, []byte("exit=0"))
		e.rec(i, KindClosed, 1, nil)
		for _, l := range e.lines[applied:] {
			if err := w.Apply(l); err != nil {
				t.Fatal(err)
			}
		}
		applied = len(e.lines)
	}
	const afterFull = 200 // what a visitor might still run before the cell stops
	n := 0
	for ; fullAt == 0 || n < fullAt+afterFull; n++ {
		run(n)
		if fullAt == 0 && w.Full() != "" {
			fullAt = n + 1
		}
		if n > 2*maxUserFiles {
			t.Fatal("the writer never said its capture was full")
		}
	}
	if err := w.Finish(); err != nil {
		t.Fatal(err)
	}
	if want := softUserFiles/filesPerEntry + 1; fullAt != want {
		t.Errorf("full after %d commands, want %d (the first one inside the reserve)", fullAt, want)
	}
	if w.Full() != "files kept for one account" {
		t.Errorf("full because of %q", w.Full())
	}
	have := map[string]int{}
	for _, evs := range records(t, snapshot(t, dir)) {
		have[evs[0].Input] = len(evs)
	}
	for i := 0; i < n; i++ {
		if have[fmt.Sprintf("echo %d", i)] != 2 {
			t.Fatalf("command %d of %d (full after %d) has %d record lines, want its start and its finish", i+1, n, fullAt, have[fmt.Sprintf("echo %d", i)])
		}
	}
}

// Every way a container's capture can run out is announced by Full while
// there is still room, so nothing is refused before the cell can be stopped.
func TestWriterSaysFullForEveryLimit(t *testing.T) {
	big := []byte(strings.Repeat("A", maxPayload))
	fresh := func() *Writer {
		t.Helper()
		w, err := NewWriter(t.TempDir(), testContainer, testCreated, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = w.Finish() }) // before the folder is removed
		return w
	}
	feed := func(w *Writer, e *emitter) {
		t.Helper()
		for _, l := range e.lines {
			if err := w.Apply(l); err != nil {
				t.Fatal(err)
			}
		}
		e.lines = nil
	}
	cases := []struct {
		name, want string
		prepare    func(w *Writer)
		step       func(e *emitter, i int)
		most       int // steps the hard limit allows
	}{
		{name: "bytes of one account", want: "bytes kept for one account",
			prepare: func(w *Writer) { w.usage[7] = &usage{bytes: softUserBytes - 3*maxPayload} },
			step: func(e *emitter, i int) {
				e.open(i, 7, false, 41000, "x")
				e.rec(i, KindOutput, 1, big)
				e.rec(i, KindExit, 1, []byte("exit=0"))
				e.rec(i, KindClosed, 1, nil)
			}, most: 8},
		{name: "files of the container", want: "files kept for the cell",
			prepare: func(w *Writer) { w.total.files = softContainerFiles - 2*filesPerEntry },
			step: func(e *emitter, i int) {
				e.open(i, 7, false, 41000, "x")
				e.rec(i, KindExit, 1, []byte("exit=0"))
				e.rec(i, KindClosed, 1, nil)
			}, most: 8},
		{name: "bytes of the container", want: "bytes kept for the cell",
			prepare: func(w *Writer) { w.total.bytes = softContainerBytes - 3*maxPayload },
			step: func(e *emitter, i int) {
				e.open(i, 7, false, 41000, "x")
				e.rec(i, KindOutput, 1, big)
				e.rec(i, KindExit, 1, []byte("exit=0"))
				e.rec(i, KindClosed, 1, nil)
			}, most: 8},
		{name: "accounts", want: "accounts with sessions",
			step: func(e *emitter, i int) {
				e.open(i, 2000+i, false, 41000, "x")
				e.rec(i, KindExit, 1, []byte("exit=0"))
				e.rec(i, KindClosed, 1, nil)
			}, most: maxAccounts},
		{name: "sessions left open", want: "sessions open at once",
			step: func(e *emitter, i int) { e.open(i, 7, false, 41000, "x") }, most: maxOpen},
		{name: "commands without a session", want: "sessions open at once",
			step: func(e *emitter, i int) { e.rec(i, KindCommand, 0, []byte("c")) }, most: maxOpen},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := fresh()
			if c.prepare != nil {
				c.prepare(w)
			}
			e := newEmitter(testConn)
			steps := 0
			for w.Full() == "" {
				if steps >= c.most {
					t.Fatalf("not full after %d steps, when the hard limit refuses the next", steps)
				}
				c.step(e, steps)
				feed(w, e)
				steps++
			}
			if w.Full() != c.want {
				t.Errorf("full because of %q, want %q", w.Full(), c.want)
			}
			if steps > c.most-c.most/reserveShare+1 {
				t.Errorf("full only after %d of %d steps: no reserve is left", steps, c.most)
			}
		})
	}
}

func TestWriterIgnoresForeignLines(t *testing.T) {
	e := newEmitter(testConn)
	e.rec(0, KindOutput, 1, []byte("orphan data")) // no open: rotated out
	dir := t.TempDir()
	apply(t, dir, append(e.lines, []byte("not a record"), []byte("")), nil)
	if files := snapshot(t, dir); len(files) != 0 {
		t.Fatalf("foreign lines wrote %v", keys(files))
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// A live follower that lags behind a reset's drain must not duplicate or cut
// anything: both replay the same container, in turns under the cells lock,
// so every split of the work between them gives the files of one replay.
func TestWritersReplayingInTurnsConverge(t *testing.T) {
	e := newEmitter(testConn)
	session(e)
	e.open(2, 1000, true, 41001, "")
	for i := 0; i < 6; i++ {
		e.rec(2, KindInput, int64(10+i), []byte(fmt.Sprintf("key %d\n", i)))
		e.rec(2, KindOutput, int64(11+i), []byte(fmt.Sprintf("echo %d\r\n", i)))
	}
	e.rec(2, KindExit, 30, []byte("exit=0"))
	e.rec(2, KindClosed, 31, nil)
	want := t.TempDir()
	apply(t, want, e.lines, nil)
	reference := snapshot(t, want)
	for lag := 0; lag <= len(e.lines); lag++ {
		dir := t.TempDir()
		follower, err := NewWriter(dir, testContainer, testCreated, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range e.lines[:lag] {
			if err := follower.Apply(l); err != nil {
				t.Fatal(err)
			}
		}
		if err := follower.Flush(); err != nil {
			t.Fatal(err)
		}
		apply(t, dir, e.lines, nil) // the drain: everything, then finished
		for _, l := range e.lines[lag:] {
			if err := follower.Apply(l); err != nil {
				t.Fatal(err)
			}
		}
		if err := follower.Finish(); err != nil {
			t.Fatal(err)
		}
		if got := snapshot(t, dir); fmt.Sprint(got) != fmt.Sprint(reference) {
			t.Fatalf("follower %d lines behind the drain left different files:\n%v\nwant\n%v", len(e.lines)-lag, got, reference)
		}
		// A follower that starts after the drain and stops partway (the
		// control plane killed) must not cut what the drain completed.
		late, err := NewWriter(dir, testContainer, testCreated, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range e.lines[:lag] {
			if err := late.Apply(l); err != nil {
				t.Fatal(err)
			}
		}
		if err := late.Flush(); err != nil {
			t.Fatal(err)
		}
		if got := snapshot(t, dir); fmt.Sprint(got) != fmt.Sprint(reference) {
			t.Fatalf("a follower stopped after %d lines cut the drained files:\n%v\nwant\n%v", lag, got, reference)
		}
	}
}

// testCreated is the test container's creation time.
var testCreated = time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)

// Guest root can write records into sshd's stream: account numbers, session
// numbers and unclosed sessions are all its to choose. What the host keeps
// stays within the container's limits whatever it writes.
func TestWriterBoundsWhatAForgedStreamCanMakeTheHostKeep(t *testing.T) {
	e := newEmitter(testConn)
	big := []byte(strings.Repeat("A", maxPayload))
	for uid := 0; uid < maxAccounts+20; uid++ {
		e.open(uid, uid+1000, false, 41000, "x")
		e.rec(uid, KindOutput, 1, big)
		e.rec(uid, KindExit, 1, []byte("exit=0"))
		e.rec(uid, KindClosed, 1, nil)
	}
	dir := t.TempDir()
	w, err := NewWriter(dir, testContainer, testCreated, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range e.lines {
		if err := w.Apply(l); err != nil {
			t.Fatal(err)
		}
	}
	// Pending commands and open sessions that never close stay bounded.
	flood := newEmitter(strings.Repeat("f", 32))
	for ch := 0; ch < 3*maxOpen; ch++ {
		flood.rec(ch, KindCommand, 0, []byte("c"))
	}
	for ch := 0; ch < 3*maxOpen; ch++ {
		flood.open(100000+ch, 1000+ch%maxAccounts, false, 41000, "")
	}
	for _, l := range flood.lines {
		if err := w.Apply(l); err != nil {
			t.Fatal(err)
		}
	}
	if len(w.pending) > maxOpen || len(w.active) > maxOpen || len(w.usage) > maxAccounts || len(w.ordinals) > maxSessions {
		t.Fatalf("unbounded state: %d pending, %d active, %d accounts, %d sessions", len(w.pending), len(w.active), len(w.usage), len(w.ordinals))
	}
	if err := w.Finish(); err != nil {
		t.Fatal(err)
	}
	accounts, _ := filepath.Glob(filepath.Join(dir, "uid-*"))
	if len(accounts) != maxAccounts {
		t.Fatalf("%d account folders, want the cap %d", len(accounts), maxAccounts)
	}
	if w.total.files > maxContainerFiles || w.total.bytes > maxContainerBytes {
		t.Fatalf("over the container limits: %+v", w.total)
	}
	// The container-wide byte and file limits hold across accounts too.
	one := func(total usage) (*Writer, string) {
		t.Helper()
		dir := t.TempDir()
		w, err := NewWriter(dir, testContainer, testCreated, nil)
		if err != nil {
			t.Fatal(err)
		}
		w.total = total
		e := newEmitter(testConn)
		e.open(0, 5, false, 41000, "x")
		e.rec(0, KindOutput, 1, big)
		e.rec(0, KindExit, 1, []byte("exit=0"))
		e.rec(0, KindClosed, 1, nil)
		for _, l := range e.lines {
			if err := w.Apply(l); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Finish(); err != nil {
			t.Fatal(err)
		}
		return w, dir
	}
	// Room for one more session's files, but only a little more data: the
	// record line counts too, and the output is cut at the limit.
	w2, dir2 := one(usage{bytes: maxContainerBytes - 1500, files: softContainerFiles - filesPerEntry - 1})
	outputs, _ := filepath.Glob(filepath.Join(dir2, "uid-5", "*.out"))
	if w2.total.files != softContainerFiles-1 || len(outputs) != 1 {
		t.Fatalf("container byte limit not applied: %+v %v", w2.total, outputs)
	}
	if data, _ := os.ReadFile(outputs[0]); len(data) == 0 || len(data) >= len(big) {
		t.Fatalf("kept %d of %d bytes at the container limit", len(data), len(big))
	}
	// A timing line per output byte counts too: a PTY stream of single bytes
	// cannot make the host keep many times the limit.
	dir4 := t.TempDir()
	w4, err := NewWriter(dir4, testContainer, testCreated, nil)
	if err != nil {
		t.Fatal(err)
	}
	w4.total = usage{bytes: maxContainerBytes - 4000}
	e4 := newEmitter(testConn)
	e4.open(0, 5, true, 41000, "")
	for i := 0; i < 1000; i++ {
		e4.rec(0, KindOutput, int64(i), []byte("x"))
	}
	e4.rec(0, KindExit, 1000, []byte("exit=0"))
	e4.rec(0, KindClosed, 1000, nil)
	for _, l := range e4.lines {
		if err := w4.Apply(l); err != nil {
			t.Fatal(err)
		}
	}
	if err := w4.Finish(); err != nil {
		t.Fatal(err)
	}
	kept := 0
	for _, suffix := range []string{"*.out", "*.timing", "*.json"} {
		files, _ := filepath.Glob(filepath.Join(dir4, "uid-5", suffix))
		for _, f := range files {
			info, _ := os.Stat(f)
			kept += int(info.Size())
		}
	}
	if kept > 4000+8<<10 { // the limit, plus the finish line of the open session
		t.Fatalf("a single-byte PTY stream kept %d bytes against a 4000-byte allowance", kept)
	}
	// No room outside the reserve for a session's files: its record alone,
	// one file.
	w3, dir3 := one(usage{files: softContainerFiles - filesPerEntry + 1})
	if outputs, _ := filepath.Glob(filepath.Join(dir3, "uid-5", "*.out")); w3.total.files != softContainerFiles-filesPerEntry+2 || w3.total.bytes > 4096 || len(outputs) != 0 {
		t.Fatalf("container file limit not applied: %+v %v", w3.total, outputs)
	}
	// Record lines count too: sessions with long commands and no data stop
	// opening once the container is at its limit.
	dir5 := t.TempDir()
	w5, err := NewWriter(dir5, testContainer, testCreated, nil)
	if err != nil {
		t.Fatal(err)
	}
	w5.total = usage{bytes: maxContainerBytes - 100<<10}
	e5 := newEmitter(testConn)
	command := strings.Repeat("c", maxCommand)
	for ch := 0; ch < 50; ch++ {
		e5.open(ch, 5, false, 41000, command)
		e5.rec(ch, KindExit, 1, []byte("exit=0"))
		e5.rec(ch, KindClosed, 1, nil)
	}
	for _, l := range e5.lines {
		if err := w5.Apply(l); err != nil {
			t.Fatal(err)
		}
	}
	if err := w5.Finish(); err != nil {
		t.Fatal(err)
	}
	if records, _ := filepath.Glob(filepath.Join(dir5, "uid-5", "*.json")); len(records) == 0 || len(records) > 4 {
		t.Fatalf("%d records kept against a 100 KiB allowance of 32 KiB records", len(records))
	}
}
