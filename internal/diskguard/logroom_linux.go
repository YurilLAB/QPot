//go:build linux

package diskguard

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"syscall"

	"golang.org/x/sys/unix"
)

// KeepLogRoom gives logs directly in dir (the *.log and *.json files a
// honeypot writes there) at least logRoomTopUp, and at most LogRoom, bytes of
// allocated space beyond their end: opt.Preferred first, then the others in
// name order, and never more than opt.MaxFiles of them at a time, counting
// every log that has room already. Before each allocation it asks opt.Allow
// whether the disk can spare it. It writes no byte and never changes a file's
// size.
//
// dir is a folder the honeypot's container can write to, so nothing in it
// is trusted: a log is opened inside dir only, never through a link, only
// as the regular file that was listed, and without waiting on a FIFO.
func KeepLogRoom(dir string, opt LogRoomOptions) (LogRoomResult, error) {
	res := LogRoomResult{Failed: map[string]error{}}
	limit := opt.MaxFiles
	if limit <= 0 {
		limit = LogRoomFiles
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return res, nil
		}
		return res, err
	}
	defer root.Close()
	f, err := root.Open(".")
	if err != nil {
		return res, err
	}
	entries, err := f.ReadDir(-1)
	_ = f.Close()
	if err != nil {
		return res, err
	}
	// The logs, and which of them have room now (each counts against the
	// limit, whatever its name).
	room := map[string]int64{}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if !isLogName(name) || !e.Type().IsRegular() {
			continue
		}
		info, err := root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		names = append(names, name)
		if r := beyondEnd(info); r > 0 {
			room[name] = r
		}
	}
	slices.Sort(names)
	order := make([]string, 0, len(names))
	for _, name := range opt.Preferred {
		if slices.Contains(names, name) && !slices.Contains(order, name) {
			order = append(order, name)
		}
	}
	for _, name := range names {
		if !slices.Contains(order, name) {
			order = append(order, name)
		}
	}
	for _, name := range order {
		have, held := room[name]
		if held && have >= logRoomTopUp {
			res.Kept = append(res.Kept, name)
			continue
		}
		if !held && len(room) >= limit {
			res.Over = append(res.Over, name)
			continue
		}
		if opt.Allow != nil && !opt.Allow() {
			res.Failed[name] = fmt.Errorf("the disk has no room to spare")
			continue
		}
		switch err := keepFileRoom(root, name); {
		case err == nil:
			res.Kept = append(res.Kept, name)
			room[name] = LogRoom
		case errors.Is(err, fs.ErrPermission):
			res.Denied = append(res.Denied, name)
		default:
			res.Failed[name] = err
		}
	}
	res.Held = len(room)
	return res, nil
}

// beyondEnd is how many bytes a file's blocks hold beyond its last one.
func beyondEnd(info os.FileInfo) int64 {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	// The blocks hold the file's own bytes up to its last block; what they
	// hold beyond that is the room.
	return max(st.Blocks*512-(info.Size()+4095)&^4095, 0)
}

// keepFileRoom makes the room of one log in root whole.
func keepFileRoom(root *os.Root, name string) error {
	listed, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !listed.Mode().IsRegular() {
		return fmt.Errorf("not a regular file")
	}
	// O_NONBLOCK: a FIFO put in the listed file's place fails at once
	// instead of waiting for a reader.
	f, err := root.OpenFile(name, os.O_WRONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || !os.SameFile(info, listed) {
		return fmt.Errorf("replaced while it was opened")
	}
	if beyondEnd(info) >= logRoomTopUp {
		return nil
	}
	for {
		err = unix.Fallocate(int(f.Fd()), unix.FALLOC_FL_KEEP_SIZE, info.Size(), LogRoom)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("allocate room: %w", err)
	}
	return nil
}
