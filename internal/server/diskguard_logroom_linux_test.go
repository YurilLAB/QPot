//go:build linux

package server

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/diskguard"
)

// TestDiskGuardKeepsLogRoom: every tick with room on the disk gives each
// enabled honeypot's logs their room beyond the end; a disabled honeypot's
// and a disk below the floor get none (the room would come out of what the
// collector and the database need then).
func TestDiskGuardKeepsLogRoom(t *testing.T) {
	g := newGuardTest(t, "guard-logroom", allRunning(), nil)
	logOf := func(name, file string) string {
		dir := filepath.Join(g.cfg.DataPath, "honeypots", name, "logs")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, file)
		if err := os.WriteFile(p, []byte("{\"n\":1}\n"), 0o666); err != nil {
			t.Fatal(err)
		}
		return p
	}
	room := func(p string) int64 {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		return info.Sys().(*syscall.Stat_t).Blocks*512 - (info.Size()+4095)&^4095
	}
	cowrie, endlessh, conpot := logOf("cowrie", "cowrie.json"), logOf("endlessh", "endlessh.log"), logOf("conpot", "conpot.json")

	// Below the floor: no room is taken.
	g.setFree(100)
	g.tick()
	if r := room(cowrie); r >= diskguard.LogRoom/2 {
		t.Fatalf("room taken below the floor: %d", r)
	}
	g.setFree(50000)
	g.tick() // the honeypots start again at the resume mark
	g.tick()
	for _, p := range []string{cowrie, endlessh} {
		if r := room(p); r < diskguard.LogRoom-4096 {
			t.Errorf("%s: %d bytes of room, want %d", p, r, diskguard.LogRoom)
		}
		if data, _ := os.ReadFile(p); string(data) != "{\"n\":1}\n" {
			t.Errorf("%s: content changed: %q", p, data)
		}
	}
	if r := room(conpot); r >= diskguard.LogRoom/2 {
		t.Errorf("a disabled honeypot's log got %d bytes of room", r)
	}
}

// TestDiskGuardMakesAHoneypotsOwnLogsWritable: a log QPot may not write is
// handed to the helper once, off the tick, and gets its room on a tick after
// that; while it stays unwritable it is handed over again only every
// logRoomHelpEvery.
func TestDiskGuardMakesAHoneypotsOwnLogsWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may write every file")
	}
	g := newGuardTest(t, "guard-logroom-help", allRunning(), nil)
	dir := filepath.Join(g.cfg.DataPath, "honeypots", "cowrie", "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "cowrie.json")
	if err := os.WriteFile(log, []byte("{\"n\":1}\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var calls [][]string
	fix := false
	done := make(chan struct{}, 8)
	g.s.api.diskGuard.writable = func(_ context.Context, folder string, names []string) error {
		mu.Lock()
		calls = append(calls, append([]string{folder}, names...))
		chmod := fix
		mu.Unlock()
		if chmod {
			for _, name := range names {
				if err := os.Chmod(filepath.Join(folder, name), 0o666); err != nil {
					t.Error(err)
				}
			}
		}
		done <- struct{}{}
		return nil
	}
	settled := func() {
		t.Helper()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("the helper was not run")
		}
		for deadline := time.Now().Add(10 * time.Second); g.s.api.diskGuard.helping.Load(); {
			if time.Now().After(deadline) {
				t.Fatal("the helper's run did not end")
			}
			time.Sleep(time.Millisecond)
		}
	}
	room := func() int64 {
		info, err := os.Stat(log)
		if err != nil {
			t.Fatal(err)
		}
		return info.Sys().(*syscall.Stat_t).Blocks*512 - (info.Size()+4095)&^4095
	}
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(calls)
	}
	// A helper that changes nothing: asked once, then not again until
	// logRoomHelpEvery has passed.
	g.tick()
	settled()
	if want := [][]string{{dir, "cowrie.json"}}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("handed to the helper: %v, want %v", calls, want)
	}
	for i := 0; i < 10; i++ {
		g.tick()
	}
	if count() != 1 || room() >= diskguard.LogRoom/2 {
		t.Fatalf("an unwritable log within %s: %d helper runs, %d bytes of room; want 1 and none", logRoomHelpEvery, count(), room())
	}
	// Then one that does: the log gets its room on the next tick.
	mu.Lock()
	fix = true
	mu.Unlock()
	g.now = g.now.Add(logRoomHelpEvery)
	g.tick()
	settled()
	if count() != 2 {
		t.Fatalf("after %s: %d helper runs, want 2", logRoomHelpEvery, count())
	}
	g.tick()
	if r := room(); r < diskguard.LogRoom-4096 {
		t.Fatalf("the log made writable has %d bytes of room, want %d", r, diskguard.LogRoom)
	}
	for i := 0; i < 3; i++ {
		g.tick()
	}
	if count() != 2 {
		t.Fatalf("a log with its room was handed to the helper again: %d runs", count())
	}
}

// TestFirstFew: a list of names a container made is cut to a few in a log
// line, with how many were left out.
func TestFirstFew(t *testing.T) {
	var many []string
	for i := 0; i < 1000; i++ {
		many = append(many, "x")
	}
	got := firstFew(many)
	if len(got) != 9 || got[8] != "and 992 more" {
		t.Fatalf("firstFew of 1000 = %d entries ending %q", len(got), got[len(got)-1])
	}
	if got := firstFew(many[:8]); len(got) != 8 {
		t.Fatalf("firstFew of 8 = %d entries", len(got))
	}
}
