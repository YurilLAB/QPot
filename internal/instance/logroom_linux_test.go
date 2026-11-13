//go:build linux

package instance

import (
	"bytes"
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
	go func() { res, err = diskguard.KeepLogRoom(dir); close(done) }()
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
	if _, err := diskguard.KeepLogRoom(dir); err != nil {
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
		res, err := diskguard.KeepLogRoom(dir)
		if err != nil || !slices.Contains(res.Denied, "theirs.log") {
			t.Fatalf("an unwritable log: %+v, %v", res, err)
		}
	}
	if res, err := diskguard.KeepLogRoom(filepath.Join(dir, "missing")); err != nil || len(res.Kept) != 0 {
		t.Fatalf("a missing folder: %+v, %v", res, err)
	}
}
