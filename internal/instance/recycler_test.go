package instance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestReadNewLinesHandlesPartialAndTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	write := func(s string, appendMode bool) {
		flag := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
		if appendMode {
			flag = os.O_CREATE | os.O_WRONLY | os.O_APPEND
		}
		f, err := os.OpenFile(path, flag, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		f.WriteString(s)
		f.Close()
	}
	write("a\nb", false)
	off, part, lines := readNewLines(path, 0, nil)
	if len(lines) != 1 || string(lines[0]) != "a" || string(part) != "b" {
		t.Fatalf("got lines=%q partial=%q", lines, part)
	}
	write("c\nd\n", true)
	off, part, lines = readNewLines(path, off, part)
	if len(lines) != 2 || string(lines[0]) != "bc" || string(lines[1]) != "d" || len(part) != 0 {
		t.Fatalf("got lines=%q partial=%q", lines, part)
	}
	write("e\n", false) // truncated/rotated
	_, _, lines = readNewLines(path, off, part)
	if len(lines) != 1 || string(lines[0]) != "e" {
		t.Fatalf("after truncation got %q", lines)
	}
}

func TestRecycleTarget(t *testing.T) {
	cases := map[string]string{
		`{"event_type":"ssh_proxy_cell_reset","backend":"ssh-backend-1"}`: "ssh-backend-1",
		// A cell outlives its source's connections and failed dials.
		`{"event_type":"ssh_proxy_session","backend":"ssh-backend-1"}`:       "",
		`{"event_type":"ssh_proxy_backend_error","backend":"ssh-backend-2"}`: "",
		`{"event_type":"ssh_proxy_rejected","backend":"ssh-backend-1"}`:      "",
		`not json`: "",
	}
	for in, want := range cases {
		if got := recycleTarget([]byte(in)); got != want {
			t.Errorf("recycleTarget(%s) = %q, want %q", in, got, want)
		}
	}
}

// The recycler recreates every backend at start, then each backend the broker
// asks to reset - and never anything outside the configured pool.
func TestBackendRecyclerRecreatesOnCellResets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	if err := os.WriteFile(path, []byte(`{"event_type":"ssh_proxy_session","backend":"ssh-backend-1"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	got := map[string]int{}
	r := &BackendRecycler{
		LogPath:  path,
		Services: map[string]bool{"ssh-backend-1": true, "ssh-backend-2": true},
		Poll:     20 * time.Millisecond,
		Recreate: func(ctx context.Context, s string) error {
			mu.Lock()
			got[s]++
			mu.Unlock()
			return nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)
	count := func(s string) int { mu.Lock(); defer mu.Unlock(); return got[s] }
	waitFor := func(cond func() bool) {
		deadline := time.Now().Add(3 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				mu.Lock()
				t.Fatalf("timed out; recreations so far: %v", got)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitFor(func() bool { return count("ssh-backend-1") == 1 && count("ssh-backend-2") == 1 })

	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"event_type":"ssh_proxy_cell_reset","backend":"ssh-backend-2"}` + "\n")
	f.WriteString(`{"event_type":"ssh_proxy_cell_reset","backend":"evil; rm -rf /"}` + "\n")
	f.WriteString(`{"event_type":"ssh_proxy_session","backend":"ssh-backend-1"}` + "\n")
	f.WriteString(`{"event_type":"ssh_proxy_backend_error","backend":"ssh-backend-1"}` + "\n")
	f.WriteString(`{"event_type":"ssh_proxy_rejected","backend":"ssh-backend-1"}` + "\n")
	f.Close()
	waitFor(func() bool { return count("ssh-backend-2") == 2 })
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if got["ssh-backend-1"] != 1 || len(got) != 2 {
		t.Fatalf("unexpected recreations: %v", got)
	}
}

func TestBumpGeneration(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "generations")
	for want := 1; want <= 3; want++ {
		if err := bumpGeneration(dir, "ssh-backend-1"); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(dir, "ssh-backend-1"))
		if err != nil || strings.TrimSpace(string(b)) != strconv.Itoa(want) {
			t.Fatalf("after bump %d: %q, %v", want, b, err)
		}
	}
	st, _ := os.Stat(filepath.Join(dir, "ssh-backend-1"))
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o644 {
		t.Errorf("mode %v, want 0644 (broker runs as another user)", st.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

type recyclerLogBuffer struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (b *recyclerLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(p)
}
func (b *recyclerLogBuffer) records() []map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(b.data.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var record map[string]any
		if json.Unmarshal(line, &record) == nil {
			out = append(out, record)
		}
	}
	return out
}

func TestRecyclerMetadataReadFailureReportsOnceAndRecoversWithoutLostAuthority(t *testing.T) {
	file := filepath.Join(t.TempDir(), "sessions.json")
	event := []byte(`{"event_type":"ssh_proxy_cell_reset","backend":"ssh-backend-1","generation":0}`)
	content := append(append([]byte(nil), event...), '\n')
	if err := os.WriteFile(file, content, 0o600); err != nil {
		t.Fatal(err)
	}
	generations := filepath.Join(t.TempDir(), "generations")
	var phase, reads, resets atomic.Int32
	var invalidCursor atomic.Bool
	r := &BackendRecycler{InstanceName: "metadata-reader", LogPath: file, GenerationDir: generations, Services: map[string]bool{"ssh-backend-1": true}, Poll: 5 * time.Millisecond, RequireGeneration: true, Recreate: func(context.Context, string) error { resets.Add(1); return nil }}
	var log recyclerLogBuffer
	logger := slog.New(slog.NewJSONHandler(&log, nil))
	reader := func(path string, offset int64, partial []byte) (int64, []byte, [][]byte, error) {
		reads.Add(1)
		switch phase.Load() {
		case 0:
			return offset, partial, nil, os.ErrNotExist
		case 1:
			if offset != 0 || len(partial) != 0 {
				invalidCursor.Store(true)
			}
			// Even a transport returning partial data with an error must not
			// grant reset authority or advance the caller's saved cursor.
			return offset + 123, []byte("tainted"), [][]byte{event}, os.ErrPermission
		default:
			return readNewLinesDetailed(path, offset, partial)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); r.run(ctx, reader, logger) }()
	wait := func(check func() bool) {
		t.Helper()
		until := time.Now().Add(3 * time.Second)
		for !check() {
			if time.Now().After(until) {
				t.Fatal("metadata retry/recovery timed out")
			}
			time.Sleep(time.Millisecond)
		}
	}
	wait(func() bool { return reads.Load() >= 4 })
	if len(log.records()) != 0 || resets.Load() != 0 {
		t.Fatal("expected absent startup log was not quiet")
	}
	phase.Store(1)
	start := reads.Load()
	wait(func() bool { return reads.Load() >= start+7 })
	warnings := 0
	for _, record := range log.records() {
		if record["level"] == "WARN" && strings.Contains(record["msg"].(string), "QP-INST-014") {
			warnings++
		}
	}
	if warnings != 1 || resets.Load() != 0 || invalidCursor.Load() {
		t.Fatalf("unreadable metadata spammed or reset authority: warnings=%d resets=%d invalidcursor=%v", warnings, resets.Load(), invalidCursor.Load())
	}
	if _, err := os.Lstat(filepath.Join(generations, "ssh-backend-1")); !os.IsNotExist(err) {
		t.Fatal("unreadable metadata advanced generation")
	}
	phase.Store(2)
	wait(func() bool { return resets.Load() == 1 && r.generation("ssh-backend-1") == 1 })
	// Leave enough successful polls to prove recovery is reported just once
	// and the preserved bytes are consumed once after read access returns.
	start = reads.Load()
	wait(func() bool { return reads.Load() >= start+5 })
	cancel()
	<-done
	warnings, recoveries := 0, 0
	for _, record := range log.records() {
		msg, _ := record["msg"].(string)
		if record["level"] == "WARN" && strings.Contains(msg, "QP-INST-014") {
			warnings++
		}
		if record["level"] == "INFO" && record["code"] == "QP-INST-014" {
			recoveries++
		}
	}
	if warnings != 1 || recoveries != 1 || resets.Load() != 1 || invalidCursor.Load() {
		t.Fatalf("read recovery lost/spammed authority: warnings=%d recoveries=%d resets=%d", warnings, recoveries, resets.Load())
	}
	if data, err := os.ReadFile(file); err != nil || !bytes.Equal(data, content) {
		t.Fatal("permission recovery changed broker metadata")
	}
}

func TestReadNewLinesDetailedPreservesCursorOnErrors(t *testing.T) {
	root := t.TempDir()
	partial := []byte("unfinished")
	for _, path := range []string{filepath.Join(root, "missing"), root} {
		next, held, lines, err := readNewLinesDetailed(path, 17, partial)
		if err == nil || next != 17 || !bytes.Equal(held, partial) || len(lines) > 0 {
			t.Fatalf("failed read consumed metadata cursor: %d %q %q %v", next, held, lines, err)
		}
	}
	if _, _, _, err := readNewLinesDetailed(filepath.Join(root, "missing"), 17, partial); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("startup absence lost its error identity")
	}
	file := filepath.Join(root, "ordinary.json")
	if err := os.WriteFile(file, []byte("safe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(file, link); err == nil {
		if _, _, _, err := readNewLinesDetailed(link, 0, nil); err == nil {
			t.Fatal("recycler followed a substituted metadata symlink")
		}
	}
}

func TestBrokerMetadataRotationUsesOpenedIdentityAndRetainsItOnError(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sessions.json")
	if err := os.WriteFile(path, []byte("first\npartial"), 0o600); err != nil {
		t.Fatal(err)
	}
	var previous os.FileInfo
	offset, partial, lines, err := readBrokerLog(path, 0, nil, &previous)
	if err != nil || len(lines) != 1 || string(lines[0]) != "first" || string(partial) != "partial" || previous == nil {
		t.Fatalf("first metadata read: %q %q %v", lines, partial, err)
	}
	before := previous
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	next, held, _, err := readBrokerLog(path, offset, partial, &previous)
	if !errors.Is(err, os.ErrNotExist) || next != offset || !bytes.Equal(held, partial) || previous != before {
		t.Fatal("missing rotated metadata changed cursor/identity")
	}
	// Deliberately make the new file longer than the prior offset so a size
	// comparison alone cannot notice rotation or preserve its first request.
	if err := os.WriteFile(path, []byte("replacement-first-request\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, held, lines, err = readBrokerLog(path, offset, partial, &previous)
	if err != nil || len(held) != 0 || len(lines) != 1 || string(lines[0]) != "replacement-first-request" || os.SameFile(previous, before) {
		t.Fatalf("rotated metadata skipped or joined old bytes: %q %q %v", lines, held, err)
	}
}
