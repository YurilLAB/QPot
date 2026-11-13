//go:build linux

package server

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

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
