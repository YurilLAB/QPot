//go:build linux

package diskguard

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func roomBeyond(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return beyondEnd(info)
}

func writeLog(t *testing.T, dir, name string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("{\"n\":1}\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestKeepLogRoomLeavesACrowdedFolder: a logs folder with more entries than
// LogRoomEntries is one its container filled. Nothing in it gets room, not
// even the honeypot's own log, and the call stops reading it there; with the
// folder back at the limit the log gets its room.
func TestKeepLogRoomLeavesACrowdedFolder(t *testing.T) {
	dir := t.TempDir()
	own := writeLog(t, dir, "own.log", 0o666)
	// own.log and this many more are one over the limit.
	for i := 0; i < LogRoomEntries; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%05d.txt", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := KeepLogRoom(dir, LogRoomOptions{Preferred: []string{"own.log"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Crowded || len(res.Kept) != 0 || res.Held != 0 || roomBeyond(t, own) != 0 {
		t.Fatalf("a folder of %d entries: crowded %v, kept %v, held %d, room %d; want it left alone",
			LogRoomEntries+1, res.Crowded, res.Kept, res.Held, roomBeyond(t, own))
	}
	if err := os.Remove(filepath.Join(dir, "f00000.txt")); err != nil {
		t.Fatal(err)
	}
	res, err = KeepLogRoom(dir, LogRoomOptions{Preferred: []string{"own.log"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Crowded || !slices.Equal(res.Kept, []string{"own.log"}) || roomBeyond(t, own) < LogRoom-4096 {
		t.Fatalf("a folder of %d entries: crowded %v, kept %v, room %d; want own.log with its room",
			LogRoomEntries, res.Crowded, res.Kept, roomBeyond(t, own))
	}
}

// TestKeepLogRoomOpensFewLogs: a folder of logs QPot may not write costs
// MaxFiles opens a call, not one for each log, and the honeypot's own log is
// tried first wherever its name sorts.
func TestKeepLogRoomOpensFewLogs(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may write every file")
	}
	dir := t.TempDir()
	for i := 0; i < 50; i++ {
		writeLog(t, dir, fmt.Sprintf("a%02d.log", i), 0o444)
	}
	res, err := KeepLogRoom(dir, LogRoomOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Denied) != LogRoomFiles || len(res.Kept) != 0 || len(res.Failed) != 0 || res.Held != 0 {
		t.Fatalf("50 logs QPot may not write: denied %v, kept %v, failed %v, held %d; want %d denied and nothing else",
			res.Denied, res.Kept, res.Failed, res.Held, LogRoomFiles)
	}
	own := writeLog(t, dir, "zz-own.log", 0o666)
	res, err = KeepLogRoom(dir, LogRoomOptions{Preferred: []string{"zz-own.log"}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Kept, []string{"zz-own.log"}) || len(res.Denied) != LogRoomFiles-1 || roomBeyond(t, own) < LogRoom-4096 {
		t.Fatalf("the honeypot's own log among 50 others: kept %v, denied %v, room %d", res.Kept, res.Denied, roomBeyond(t, own))
	}
}

// TestKeepLogRoomWhenTheDiskCannotSpare: with the disk at its floor a log
// that has its room keeps it and is not reported, and a log without room
// gets none.
func TestKeepLogRoomWhenTheDiskCannotSpare(t *testing.T) {
	dir := t.TempDir()
	a := writeLog(t, dir, "a.log", 0o666)
	if _, err := KeepLogRoom(dir, LogRoomOptions{}); err != nil {
		t.Fatal(err)
	}
	if roomBeyond(t, a) < LogRoom-4096 {
		t.Fatalf("a.log has %d bytes of room, want %d", roomBeyond(t, a), LogRoom)
	}
	b := writeLog(t, dir, "b.log", 0o666)
	asked := 0
	res, err := KeepLogRoom(dir, LogRoomOptions{Allow: func() bool { asked++; return false }})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Kept, []string{"a.log"}) || res.Failed["b.log"] == nil || len(res.Failed) != 1 || roomBeyond(t, b) != 0 || asked != 2 {
		t.Fatalf("at the floor: kept %v, failed %v, b.log room %d, asked %d times; want a.log kept, b.log failed without room, 2",
			res.Kept, res.Failed, roomBeyond(t, b), asked)
	}
	// A log that has written its room nearly full is failed too: what is
	// left is not the room it should have.
	if err := os.Truncate(a, LogRoom); err != nil {
		t.Fatal(err)
	}
	res, err = KeepLogRoom(dir, LogRoomOptions{Allow: func() bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Kept) != 0 || res.Failed["a.log"] == nil {
		t.Fatalf("a log with its room used up, at the floor: kept %v, failed %v", res.Kept, res.Failed)
	}
}

// TestKeepLogRoomAsksForItsRoomEveryCall: room is asked for on every call,
// so a file whose room is whole is still one the filesystem was told to keep
// room for; its size, content and room do not change.
func TestKeepLogRoomAsksForItsRoomEveryCall(t *testing.T) {
	dir := t.TempDir()
	a := writeLog(t, dir, "a.log", 0o666)
	for i := 0; i < 3; i++ {
		res, err := KeepLogRoom(dir, LogRoomOptions{})
		if err != nil || !slices.Equal(res.Kept, []string{"a.log"}) || res.Held != 1 {
			t.Fatalf("call %d: kept %v, held %d, %v", i+1, res.Kept, res.Held, err)
		}
	}
	if data, err := os.ReadFile(a); err != nil || string(data) != "{\"n\":1}\n" {
		t.Fatalf("content changed: %q, %v", data, err)
	}
	if r := roomBeyond(t, a); r < LogRoom-4096 || r > LogRoom+4096 {
		t.Fatalf("room after three calls: %d, want %d", r, LogRoom)
	}
}
