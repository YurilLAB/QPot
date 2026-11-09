package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/proxy"
)

func TestHostReadableSessionLogBooleanIsStrictBeforeEffects(t *testing.T) {
	for _, value := range []string{"true", "1", "TRUE", "false", "0"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("QPOT_SSHPROXY_HOST_READABLE_LOG", value)
			enabled, err := hostReadableSessionLogFromEnv()
			want := value == "true" || value == "1" || value == "TRUE"
			if err != nil || enabled != want {
				t.Fatalf("boolean %q: enabled=%v err=%v", value, enabled, err)
			}
		})
	}
	t.Run("unset", func(t *testing.T) {
		t.Setenv("QPOT_SSHPROXY_HOST_READABLE_LOG", "false")
		if err := os.Unsetenv("QPOT_SSHPROXY_HOST_READABLE_LOG"); err != nil {
			t.Fatal(err)
		}
		if enabled, err := hostReadableSessionLogFromEnv(); err != nil || enabled {
			t.Fatalf("unset must preserve the private default: %v %v", enabled, err)
		}
	})
	for _, value := range []string{"", "yes", "on", "2", " true ", "true\n"} {
		t.Run("invalid "+value, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "not-created")
			t.Setenv("QPOT_SSHPROXY_HOST_READABLE_LOG", value)
			t.Setenv("QPOT_SSHPROXY_LOG", filepath.Join(root, "sessions.json"))
			t.Setenv("QPOT_SSHPROXY_BACKENDS", "b=127.0.0.1:1")
			t.Setenv("QPOT_SSHPROXY_LISTEN", "invalid-listen")
			if err := run(); err == nil || !strings.Contains(err.Error(), "QPOT_SSHPROXY_HOST_READABLE_LOG") {
				t.Fatalf("invalid boolean reached logger/listener: %v", err)
			}
			if _, err := os.Lstat(root); !os.IsNotExist(err) {
				t.Fatalf("invalid boolean created a log directory: %v", err)
			}
		})
	}
}

func TestSessionLogDefaultPreservesExistingModeBytesAndInode(t *testing.T) {
	name := filepath.Join(t.TempDir(), "sessions.json")
	if err := os.WriteFile(name, []byte("before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	beforeFile, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	before, err := beforeFile.Stat()
	if err := errors.Join(err, beforeFile.Close()); err != nil {
		t.Fatal(err)
	}
	file, err := openSessionLog(name, false)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteString("after\n")
	if err := errors.Join(writeErr, file.Close()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(name)
	if err != nil || !os.SameFile(before, after) || before.Mode().Perm() != after.Mode().Perm() {
		t.Fatalf("default logger changed existing permissions/identity: %v", err)
	}
	if data, err := os.ReadFile(name); err != nil || string(data) != "before\nafter\n" {
		t.Fatalf("default logger truncated evidence: %q %v", data, err)
	}
}

func TestSessionLogDefaultKeepsTrustedSymlinkPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	name := filepath.Join(dir, "sessions.json")
	if err := os.WriteFile(target, []byte("before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, name); err != nil {
		t.Skip(err)
	}
	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	file, err := openSessionLog(name, false)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteString("after\n")
	if err := errors.Join(writeErr, file.Close()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(target)
	if err != nil || !os.SameFile(before, after) || after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("default custom symlink target mode/identity changed: %v", err)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "before\nafter\n" {
		t.Fatalf("default custom path stopped appending: %q %v", data, err)
	}
}

type startupSink struct{ events []proxy.Event }

func (s *startupSink) Emit(e proxy.Event) { s.events = append(s.events, e) }

func TestStartupPoolCapturesBeforeRequestAndRejectsFirstLease(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "old"), []byte("3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	backends := []proxy.Backend{{ID: "old", Addr: "127.0.0.1:22"}, {ID: "new", Addr: "127.0.0.1:22"}}
	gate := proxy.NewGenerationGate(dir)
	pool := startupPool(backends, nil, gate)
	if _, err := pool.Lease(); !errors.Is(err, proxy.ErrNoBackend) {
		t.Fatalf("startup leased a backend before trusted reset: %v", err)
	}
	// A host recreation may finish between baseline capture and log emission.
	// The emitted request must retain its older baseline so the host ignores it.
	if err := os.WriteFile(filepath.Join(dir, "old"), []byte("4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sink := &startupSink{}
	requestStartupResets(sink, "ssh-proxy", backends, gate)
	if len(sink.events) != len(backends) {
		t.Fatalf("startup reset events=%d want %d", len(sink.events), len(backends))
	}
	for i, event := range sink.events {
		want := uint64(0)
		if i == 0 {
			want = 3
		}
		if event.EventType != proxy.EventCellReset || event.Reason != proxy.ReasonStartupReset ||
			event.Backend != backends[i].ID || event.Generation == nil || *event.Generation != want {
			t.Fatalf("startup event %+v want backend=%s generation=%d", event, backends[i].ID, want)
		}
		data, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		var decoded proxy.Event
		if err := json.Unmarshal(data, &decoded); err != nil || decoded.Generation == nil || *decoded.Generation != want {
			t.Fatalf("startup generation lost in JSON: %s %v", data, err)
		}
	}
}

func TestStartupWithoutGenerationGateKeepsLegacyPool(t *testing.T) {
	backends := []proxy.Backend{{ID: "b", Addr: "127.0.0.1:22"}}
	pool := startupPool(backends, nil, nil)
	if _, err := pool.Lease(); err != nil {
		t.Fatalf("legacy ungated pool became unavailable: %v", err)
	}
	sink := &startupSink{}
	requestStartupResets(sink, "ssh-proxy", backends, nil)
	if len(sink.events) != 0 {
		t.Fatal("ungated startup emitted a generation reset request")
	}
}

func TestFailedListenerDoesNotRequestBackendRecreation(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "sessions.json")
	t.Setenv("QPOT_SSHPROXY_LISTEN", held.Addr().String())
	t.Setenv("QPOT_SSHPROXY_BACKENDS", "b=127.0.0.1:22")
	t.Setenv("QPOT_SSHPROXY_LOG", logPath)
	t.Setenv("QPOT_SSHPROXY_GENERATIONS", dir)
	t.Setenv("QPOT_SSHPROXY_RECYCLE", "on")
	if err := run(); err == nil {
		t.Fatal("broker started while its listener was occupied")
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("failed startup requested a reset: %s", data)
	}
}

// A zero hold is a real choice (a cell per connection), unlike a zero idle
// timeout; anything unreadable keeps the default.
func TestEnvHoldAcceptsZero(t *testing.T) {
	for value, want := range map[string]time.Duration{"": 30 * time.Minute, "0": 0, "0m": 0, "45m": 45 * time.Minute, "-1m": 30 * time.Minute, "soon": 30 * time.Minute} {
		t.Setenv("QPOT_SSHPROXY_CELL_HOLD", value)
		if got := envHold("QPOT_SSHPROXY_CELL_HOLD", 30*time.Minute); got != want {
			t.Errorf("%q read as %s, want %s", value, got, want)
		}
	}
}
