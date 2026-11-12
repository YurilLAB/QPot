package sshcapture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDocker serves one container. Its error stream carries log lines, the
// capture records in two parts (the second released by the test) and a
// final log fragment; its output stream carries noise that must be ignored.
type fakeDocker struct {
	mu       sync.Mutex
	id       string
	running  bool
	capture  [][]byte
	log      string // before the capture
	tail     string // after it
	noise    string // on the output stream
	release  chan struct{}
	streamed chan struct{}
}

func (d *fakeDocker) inspect(context.Context, string) (Container, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return Container{ID: d.id, Created: testCreated, Running: d.running}, nil
}

func (d *fakeDocker) stream(ctx context.Context, id string, follow bool) (io.ReadCloser, io.ReadCloser, func() error, error) {
	outR, outW := io.Pipe()
	errR, errW := io.Pipe()
	half := len(d.capture) / 2
	go func() {
		_, _ = errW.Write([]byte(d.log))
		for _, l := range d.capture[:half] {
			_, _ = errW.Write(append(append([]byte(nil), l...), '\n'))
		}
		if follow && d.release != nil {
			if d.streamed != nil {
				close(d.streamed)
			}
			select {
			case <-d.release:
			case <-ctx.Done():
			}
		}
		for _, l := range d.capture[half:] {
			_, _ = errW.Write(append(append([]byte(nil), l...), '\n'))
		}
		_, _ = errW.Write([]byte(d.tail))
		_ = errW.Close()
	}()
	go func() {
		_, _ = outW.Write([]byte(d.noise))
		_ = outW.Close()
	}()
	return outR, errR, func() error { return nil }, nil
}

func mutexLock(mu *sync.Mutex) Lock {
	return func(context.Context) (func(), error) { mu.Lock(); return mu.Unlock, nil }
}

func testTarget(dir string) Target {
	return Target{Service: "ssh-backend-1", Container: "qpot_ssh-backend-1", Dir: func() (string, error) { return dir, nil }}
}

func TestDrainWritesCompleteRecordsAndAuthLog(t *testing.T) {
	e := newEmitter(testConn)
	session(e)
	// A record-shaped line that arrives as a log line (with sshd's carriage
	// return) or on the output stream is not capture.
	forged := newEmitter(strings.Repeat("f", 32))
	forged.open(7, 0, false, 41007, "forged")
	forged.rec(7, KindExit, 1, []byte("exit=0"))
	forged.rec(7, KindClosed, 1, nil)
	var asLog, onStdout strings.Builder
	for _, l := range forged.lines {
		asLog.Write(l)
		asLog.WriteString("\r\n")
		onStdout.Write(l)
		onStdout.WriteString("\n")
	}
	d := &fakeDocker{id: testContainer, capture: e.lines,
		log:   "Accepted password for root from 172.20.0.10 port 41000 ssh2\r\n" + asLog.String(),
		tail:  "no newline at end",
		noise: onStdout.String()}
	var mu sync.Mutex
	c := &Converter{Stream: d.stream, Inspect: d.inspect, Lock: mutexLock(&mu), Poll: time.Millisecond}
	dir := t.TempDir()
	if err := c.Drain(context.Background(), testTarget(dir)); err != nil {
		t.Fatal(err)
	}
	files := snapshot(t, dir)
	if files[AuthLog] != "Accepted password for root from 172.20.0.10 port 41000 ssh2\r\n"+asLog.String()+"no newline at end\n" {
		t.Fatalf("auth log: %q", files[AuthLog])
	}
	want := t.TempDir()
	apply(t, want, e.lines, nil)
	got := snapshot(t, dir)
	delete(got, AuthLog)
	if fmt.Sprint(got) != fmt.Sprint(snapshot(t, want)) {
		t.Fatalf("drain differs from a direct replay: %v", keys(got))
	}
}

func TestFollowStopsWritingAfterAResetArchivesTheFolder(t *testing.T) {
	e := newEmitter(testConn)
	session(e)
	e2 := newEmitter(strings.Repeat("e", 32))
	e2.open(1, 0, false, 41001, "id")
	e2.rec(1, KindExit, 1, []byte("exit=0"))
	e2.rec(1, KindClosed, 1, nil)
	d := &fakeDocker{id: testContainer, running: true, capture: append(e.lines, e2.lines...), release: make(chan struct{}), streamed: make(chan struct{})}
	var mu sync.Mutex
	c := &Converter{Stream: d.stream, Inspect: d.inspect, Lock: mutexLock(&mu), Poll: time.Millisecond, Logger: discardLogger()}
	parent := t.TempDir()
	dir := filepath.Join(parent, "current")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan struct{})
	go func() { c.Follow(ctx, testTarget(dir)); close(finished) }()
	<-d.streamed
	// Wait until the first half is on disk.
	deadline := time.Now().Add(10 * time.Second)
	for len(snapshot(t, dir)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the follower wrote nothing")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// A reset: under the lock, archive the folder and create a fresh one.
	mu.Lock()
	if err := os.Rename(dir, filepath.Join(parent, "archive-g1-x")); err != nil {
		mu.Unlock()
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o777); err != nil {
		mu.Unlock()
		t.Fatal(err)
	}
	d.mu.Lock()
	d.running = false
	d.mu.Unlock()
	mu.Unlock()
	close(d.release)
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-finished
	if files := snapshot(t, dir); len(files) != 0 {
		t.Fatalf("the old container's capture leaked into the new folder: %v", keys(files))
	}
	if files := snapshot(t, filepath.Join(parent, "archive-g1-x")); len(files) == 0 {
		t.Fatal("the archived folder lost the first half")
	}
}

func TestFollowReplaysToTheSameFiles(t *testing.T) {
	e := newEmitter(testConn)
	session(e)
	d := &fakeDocker{id: testContainer, running: false, capture: e.lines, log: "Server listening on 0.0.0.0 port 22.\r\n"}
	var mu sync.Mutex
	c := &Converter{Stream: d.stream, Inspect: d.inspect, Lock: mutexLock(&mu), Poll: time.Millisecond, Logger: discardLogger()}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	c.Follow(ctx, testTarget(dir)) // a stopped container is replayed once
	want := t.TempDir()
	apply(t, want, e.lines, nil)
	got := snapshot(t, dir)
	delete(got, AuthLog)
	if fmt.Sprint(got) != fmt.Sprint(snapshot(t, want)) {
		t.Fatalf("follow differs from a direct replay: %v", keys(got))
	}
}

func TestReadLinesTellsRecordsFromLogLines(t *testing.T) {
	e := newEmitter(testConn)
	e.open(1, 0, false, 41000, "id")
	record := string(e.lines[0])
	long := strings.Repeat("A", maxLogLine+10)
	input := "first\r\n" + record + "\n" + long + "\n" + record + "\r\n" + "second\n" + record
	out := make(chan streamLine, 10)
	var wg sync.WaitGroup
	wg.Add(1)
	go readLines(io.NopCloser(strings.NewReader(input)), out, &wg)
	wg.Wait()
	close(out)
	var got []string
	for l := range out {
		got = append(got, fmt.Sprintf("%v:%q", l.record, l.data))
	}
	want := []string{
		fmt.Sprintf("false:%q", "first\r\n"),
		fmt.Sprintf("true:%q", record),
		fmt.Sprintf("false:%q", record+"\r\n"), // a log line, whatever it says
		fmt.Sprintf("false:%q", "second\n"),
		fmt.Sprintf("false:%q", record+"\n"), // cut off at the end: not one whole write
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("lines:\n%v\nwant\n%v", got, want)
	}
}

func TestBrokerIndex(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "sessions.json")
	gen := func(n uint64) string { return fmt.Sprintf("%d", n) }
	line := func(ts, backend string, port int, src string, g uint64) string {
		return fmt.Sprintf(`{"timestamp":%q,"event_type":"ssh_proxy_connect","honeypot":"ssh-proxy","src_ip":%q,"src_port":5000,"backend":%q,"session_id":"%032d","generation":%s,"backend_port":%d}`+"\n",
			ts, src, backend, g, gen(g), port)
	}
	body := line("2026-11-09T10:00:00Z", "ssh-backend-1", 40000, "203.0.113.1", 1) +
		`{"timestamp":"2026-11-09T10:00:01Z","event_type":"ssh_proxy_session","src_ip":"203.0.113.1","backend":"ssh-backend-1","backend_port":40000}` + "\n" +
		"garbage\n" +
		line("2026-11-09T11:00:00Z", "ssh-backend-1", 40000, "203.0.113.2", 2) // the port came round again
	if err := os.WriteFile(log, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	x := NewBrokerIndex(log)
	at := func(ts string) int64 { v, _ := time.Parse(time.RFC3339, ts); return v.UnixMilli() }
	app := x.Attributor("ssh-backend-1", true)
	since := at("2026-11-09T09:59:00Z")
	for _, c := range []struct {
		ts, want string
		port     int
		ok       bool
	}{
		{"2026-11-09T10:00:05Z", "203.0.113.1", 40000, true},
		{"2026-11-09T11:30:00Z", "203.0.113.2", 40000, true},
		{"2026-11-09T10:00:05Z", "", 40001, false},
		{"2026-11-09T09:00:00Z", "", 40000, false}, // before any connect
	} {
		a, ok := app(Open{TimeMillis: at(c.ts), PeerPort: c.port}, time.UnixMilli(since))
		if ok != c.ok || a.SrcIP != c.want {
			t.Fatalf("%s port %d: %+v %v", c.ts, c.port, a, ok)
		}
	}
	backup := x.Attributor("ssh-backend-1", false)
	// One connection had reached the cell: the backup session is its.
	if a, ok := backup(Open{TimeMillis: at("2026-11-09T10:30:00Z"), PeerPort: 5555}, time.UnixMilli(since)); !ok || a.Visitor || a.SrcIP != "203.0.113.1" ||
		a.SessionID != fmt.Sprintf("%032d", 1) || a.Generation == nil || *a.Generation != 1 {
		t.Fatalf("backup attribution: %+v %v", a, ok)
	}
	// Two had: either may have made it, so it names only the visitor.
	if a, ok := backup(Open{TimeMillis: at("2026-11-09T11:30:00Z"), PeerPort: 5555}, time.UnixMilli(since)); !ok || !a.Visitor || a.SrcIP != "203.0.113.2" ||
		a.SessionID != "" || a.SrcPort != 0 || a.Generation == nil || *a.Generation != 2 {
		t.Fatalf("backup attribution with two connections: %+v %v", a, ok)
	}
	if _, ok := x.Attributor("ssh-backend-2", true)(Open{TimeMillis: at("2026-11-09T12:00:00Z"), PeerPort: 40000}, time.UnixMilli(since)); ok {
		t.Fatal("another cell's connection was used")
	}
	// Appended later: found on the miss-triggered refresh.
	f, err := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(line("2026-11-09T12:00:00Z", "ssh-backend-2", 41000, "198.51.100.7", 4))
	_ = f.Close()
	if a, ok := x.Attributor("ssh-backend-2", true)(Open{TimeMillis: at("2026-11-09T12:00:01Z"), PeerPort: 41000}, time.UnixMilli(since)); !ok || a.SrcIP != "198.51.100.7" {
		t.Fatalf("appended connect: %+v %v", a, ok)
	}
	// A backup session reads every connection before it, not just those
	// already read: the one appended since makes it the visitor's.
	backup2 := x.Attributor("ssh-backend-2", false)
	if a, ok := backup2(Open{TimeMillis: at("2026-11-09T12:00:05Z")}, time.UnixMilli(since)); !ok || a.Visitor || a.SrcIP != "198.51.100.7" {
		t.Fatalf("backup with one connection: %+v %v", a, ok)
	}
	if f, err = os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0); err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(line("2026-11-09T12:10:00Z", "ssh-backend-2", 41001, "198.51.100.8", 4))
	_ = f.Close()
	if a, ok := backup2(Open{TimeMillis: at("2026-11-09T12:20:00Z")}, time.UnixMilli(since)); !ok || !a.Visitor || a.SrcIP != "198.51.100.8" || a.SessionID != "" {
		t.Fatalf("backup after a second connection: %+v %v", a, ok)
	}
	// A container created after a connection never takes it: a record forged
	// with an old time and a guessed port names no earlier visitor.
	later := time.UnixMilli(at("2026-11-09T10:30:00Z"))
	if a, ok := app(Open{TimeMillis: at("2026-11-09T10:00:05Z"), PeerPort: 40000}, later); ok {
		t.Fatalf("a connection from before the container was used: %+v", a)
	}
	if a, ok := app(Open{TimeMillis: at("2026-11-09T11:30:00Z"), PeerPort: 40000}, later); !ok || a.SrcIP != "203.0.113.2" {
		t.Fatalf("the container's own connection: %+v %v", a, ok)
	}
}

func TestParseInspect(t *testing.T) {
	ct, err := parseInspect("c", "0123456789abcdef 2026-11-09T09:14:00.123456789Z true\n")
	if err != nil || ct.ID != "0123456789abcdef" || !ct.Running || ct.Created.UnixNano() != time.Date(2026, 11, 9, 9, 14, 0, 123456789, time.UTC).UnixNano() {
		t.Fatalf("%+v %v", ct, err)
	}
	for _, bad := range []string{"", "short 2026-11-09T09:14:00Z true", "0123456789abcdef not-a-time true", "0123456789abcdef 2026-11-09T09:14:00Z"} {
		if _, err := parseInspect("c", bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// sshd's own log is kept up to maxAuthLog per container, then ends with one
// note; the capture records are converted whatever the log's size, and the
// follower keeps exactly what the drain keeps.
func TestAuthLogIsBounded(t *testing.T) {
	e := newEmitter(testConn)
	session(e)
	line := "Failed password for root from 172.20.0.10 port 41000 ssh2" + strings.Repeat(".", 40) + "\r\n"
	d := &fakeDocker{id: testContainer, capture: e.lines, log: strings.Repeat(line, maxAuthLog/len(line)+1000)}
	var mu sync.Mutex
	c := &Converter{Stream: d.stream, Inspect: d.inspect, Lock: mutexLock(&mu), Poll: time.Millisecond, Logger: discardLogger()}
	drained := t.TempDir()
	if err := c.Drain(context.Background(), testTarget(drained)); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(drained, AuthLog))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > maxAuthLog+len(authLogFull) || !strings.HasSuffix(string(got), authLogFull) || !strings.HasPrefix(string(got), line) {
		t.Fatalf("sshd log kept %d bytes against a %d-byte limit", len(got), maxAuthLog)
	}
	want := t.TempDir()
	apply(t, want, e.lines, nil)
	records := snapshot(t, drained)
	delete(records, AuthLog)
	if fmt.Sprint(records) != fmt.Sprint(snapshot(t, want)) {
		t.Fatal("a full sshd log cost the capture records")
	}
	followed := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c.Follow(ctx, testTarget(followed))
	if again, err := os.ReadFile(filepath.Join(followed, AuthLog)); err != nil || string(again) != string(got) {
		t.Fatalf("the follower kept a different sshd log: %d bytes, %v", len(again), err)
	}
}

// The follower stops a container whose capture comes within the reserve of a
// limit, once, while the container still runs; a replay of a container that
// has already stopped stops nothing.
func TestFollowRetiresACellCloseToItsCaptureLimit(t *testing.T) {
	capture := func(n int) [][]byte {
		e := newEmitter(testConn)
		for i := 0; i < n; i++ {
			e.open(i, 0, false, 41000, fmt.Sprintf("echo %d", i))
			e.rec(i, KindExit, 1, []byte("exit=0"))
			e.rec(i, KindClosed, 1, nil)
		}
		return e.lines
	}
	n := softUserFiles/filesPerEntry + 40
	run := func(t *testing.T, lines [][]byte, running bool, fail int) (retired []string, d *fakeDocker, dir string) {
		t.Helper()
		d = &fakeDocker{id: testContainer, running: running, capture: lines}
		var mu, calls sync.Mutex
		c := &Converter{Stream: d.stream, Inspect: d.inspect, Lock: mutexLock(&mu), Poll: time.Millisecond, Logger: discardLogger()}
		c.Retire = func(_ context.Context, id string) error {
			calls.Lock()
			defer calls.Unlock()
			retired = append(retired, id)
			if len(retired) <= fail {
				return errors.New("docker is busy")
			}
			d.mu.Lock()
			d.running = false
			d.mu.Unlock()
			return nil
		}
		dir = t.TempDir()
		if err := c.follow(context.Background(), testTarget(dir), Container{ID: testContainer, Created: testCreated, Running: running}); err != nil {
			t.Fatal(err)
		}
		calls.Lock()
		defer calls.Unlock()
		return append([]string(nil), retired...), d, dir
	}
	t.Run("running", func(t *testing.T) {
		retired, _, dir := run(t, capture(n), true, 0)
		if len(retired) != 1 || retired[0] != testContainer {
			t.Fatalf("stopped %v, want the container once", retired)
		}
		// What ran before the stop landed is all recorded.
		if got := len(sessions(t, snapshot(t, dir))); got != n {
			t.Fatalf("%d of %d commands have a record", got, n)
		}
	})
	t.Run("a failed stop is tried again", func(t *testing.T) {
		// Enough lines after the capture is full for several more batches.
		if retired, _, _ := run(t, capture(n+400), true, 2); len(retired) != 3 {
			t.Fatalf("stop tried %d times, want twice failing and once succeeding", len(retired))
		}
	})
	t.Run("already stopped", func(t *testing.T) {
		if retired, _, _ := run(t, capture(n), false, 0); len(retired) != 0 {
			t.Fatalf("a stopped container's replay stopped %v", retired)
		}
	})
}
