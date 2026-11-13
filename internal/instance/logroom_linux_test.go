//go:build linux

package instance

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/diskguard"
)

func mkfifo(path string) error { return syscall.Mkfifo(path, 0o666) }

// fileAllocated is how many bytes a file's blocks hold.
func fileAllocated(info os.FileInfo) int64 {
	return info.Sys().(*syscall.Stat_t).Blocks * 512
}

// TestKeepLogRoom: the guard keeps room beyond the end of each log in a
// honeypot's folder without changing its size or content, tops it up when a
// honeypot has written into it, leaves alone what is not a regular log, and
// never follows a link or waits on a FIFO the container left there.
func TestKeepLogRoom(t *testing.T) {
	dir := t.TempDir()
	if err := ensureHoneypotLogs(dir, []string{"a.json", "b.log"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.json", "b.log"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0o666 || info.Size() != 0 {
			t.Fatalf("%s: %v %v", name, info, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte("{\"n\":1}\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	// Created again at the next start: what is there stays.
	if err := ensureHoneypotLogs(dir, []string{"a.json"}); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "a.json")); string(data) != "{\"n\":1}\n" {
		t.Fatalf("a second start changed the log: %q", data)
	}
	outside := filepath.Join(t.TempDir(), "outside.log")
	if err := os.WriteFile(outside, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link.log")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mkfifo(filepath.Join(dir, "pipe.log")); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var res diskguard.LogRoomResult
	var err error
	go func() { res, err = diskguard.KeepLogRoom(dir, diskguard.LogRoomOptions{}); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("KeepLogRoom waited on a FIFO")
	}
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(res.Kept)
	if !slices.Equal(res.Kept, []string{"a.json", "b.log"}) || len(res.Denied) != 0 || len(res.Failed) != 0 {
		t.Fatalf("result %+v", res)
	}
	allocated := func(name string) (size, room int64) {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return info.Size(), fileAllocated(info) - (info.Size()+4095)&^4095
	}
	if size, room := allocated("a.json"); size != 8 || room < diskguard.LogRoom-4096 {
		t.Fatalf("a.json: size %d, room %d", size, room)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "a.json")); string(data) != "{\"n\":1}\n" {
		t.Fatalf("the log's content changed: %q", data)
	}
	if info, _ := os.Stat(outside); fileAllocated(info) > 8192 {
		t.Fatal("room was given to a file outside the folder through a link")
	}
	// A honeypot writes into the room; the next tick gives back what it used.
	f, err := os.OpenFile(filepath.Join(dir, "b.log"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(bytes.Repeat([]byte("x"), 512<<10)); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, room := allocated("b.log"); room > diskguard.LogRoom*3/4 {
		t.Fatalf("b.log still has %d of room after half of it was written", room)
	}
	if _, err := diskguard.KeepLogRoom(dir, diskguard.LogRoomOptions{}); err != nil {
		t.Fatal(err)
	}
	if size, room := allocated("b.log"); size != 512<<10 || room < diskguard.LogRoom-4096 {
		t.Fatalf("b.log after the top-up: size %d, room %d", size, room)
	}
	// A log the container's user made, which QPot may not write: no room,
	// and said so. (Root may write anything.)
	if os.Geteuid() != 0 {
		if err := os.WriteFile(filepath.Join(dir, "theirs.log"), []byte("x\n"), 0o444); err != nil {
			t.Fatal(err)
		}
		res, err := diskguard.KeepLogRoom(dir, diskguard.LogRoomOptions{})
		if err != nil || !slices.Contains(res.Denied, "theirs.log") {
			t.Fatalf("an unwritable log: %+v, %v", res, err)
		}
	}
	if res, err := diskguard.KeepLogRoom(filepath.Join(dir, "missing"), diskguard.LogRoomOptions{}); err != nil || len(res.Kept) != 0 {
		t.Fatalf("a missing folder: %+v, %v", res, err)
	}
}

// TestKeepLogRoomIsBounded: a honeypot that fills its logs folder with empty
// logs gets room for at most diskguard.LogRoomFiles of them, its own logs
// first, however many ticks pass; a log that has room already counts against
// the limit whatever its name; and no room is taken once the disk says it
// cannot spare it.
func TestKeepLogRoomIsBounded(t *testing.T) {
	dir := t.TempDir()
	if err := ensureHoneypotLogs(dir, HoneypotLogNames("conpot")); err != nil {
		t.Fatal(err)
	}
	// What a compromised Conpot could leave: a thousand empty logs whose
	// names sort before its own.
	for i := range 1000 {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("a%04d.json", i)), nil, 0o666); err != nil {
			t.Fatal(err)
		}
	}
	total := func() (sum int64, withRoom int) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				t.Fatal(err)
			}
			if r := fileAllocated(info) - (info.Size()+4095)&^4095; r > 0 {
				sum += r
				withRoom++
			}
		}
		return sum, withRoom
	}
	opt := diskguard.LogRoomOptions{Preferred: HoneypotLogNames("conpot"), MaxFiles: diskguard.LogRoomFiles}
	for tick := range 5 {
		res, err := diskguard.KeepLogRoom(dir, opt)
		if err != nil {
			t.Fatal(err)
		}
		sum, n := total()
		if n > diskguard.LogRoomFiles || sum > int64(diskguard.LogRoomFiles)*(diskguard.LogRoom+4096) || res.Held != n {
			t.Fatalf("tick %d: %d logs hold %d bytes of room (result says %d), want at most %d logs", tick, n, sum, res.Held, diskguard.LogRoomFiles)
		}
		for _, own := range HoneypotLogNames("conpot") {
			if !slices.Contains(res.Kept, own) {
				t.Fatalf("tick %d: Conpot's own %s has no room: kept %v", tick, own, res.Kept)
			}
		}
		if len(res.Over) != 1002-diskguard.LogRoomFiles {
			t.Fatalf("tick %d: %d logs reported over the limit", tick, len(res.Over))
		}
	}
	// A log that already has room counts, whatever its name: one the
	// container renamed after it got room does not make room for another.
	if err := os.Rename(filepath.Join(dir, "a0000.json"), filepath.Join(dir, "zz-renamed.log")); err != nil {
		t.Fatal(err)
	}
	if _, err := diskguard.KeepLogRoom(dir, opt); err != nil {
		t.Fatal(err)
	}
	if _, n := total(); n > diskguard.LogRoomFiles {
		t.Fatalf("after a rename %d logs have room", n)
	}
	// The disk can spare room for one more log, then none.
	other := t.TempDir()
	for i := range 4 {
		if err := os.WriteFile(filepath.Join(other, fmt.Sprintf("l%d.log", i)), nil, 0o666); err != nil {
			t.Fatal(err)
		}
	}
	asked := 0
	res, err := diskguard.KeepLogRoom(other, diskguard.LogRoomOptions{Allow: func() bool { asked++; return asked <= 1 }})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Kept) != 1 || len(res.Failed) != 3 || res.Held != 1 || asked != 4 {
		t.Fatalf("with room for one: %+v, asked %d times", res, asked)
	}
}
