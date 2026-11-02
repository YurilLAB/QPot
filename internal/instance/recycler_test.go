package instance

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
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
		`{"event_type":"ssh_proxy_session","backend":"ssh-backend-1"}`:       "ssh-backend-1",
		`{"event_type":"ssh_proxy_backend_error","backend":"ssh-backend-2"}`: "ssh-backend-2",
		`{"event_type":"ssh_proxy_rejected","backend":"ssh-backend-1"}`:      "",
		`not json`: "",
	}
	for in, want := range cases {
		if got := recycleTarget([]byte(in)); got != want {
			t.Errorf("recycleTarget(%s) = %q, want %q", in, got, want)
		}
	}
}

// The recycler recreates every backend at start, then each backend whose
// session ends - and never anything outside the configured pool.
func TestBackendRecyclerRecreatesAfterSessions(t *testing.T) {
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
	f.WriteString(`{"event_type":"ssh_proxy_session","backend":"ssh-backend-2"}` + "\n")
	f.WriteString(`{"event_type":"ssh_proxy_session","backend":"evil; rm -rf /"}` + "\n")
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
