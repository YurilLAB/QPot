//go:build linux

package diskguard

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"syscall"

	"golang.org/x/sys/unix"
)

// KeepLogRoom gives logs directly in dir (the *.log and *.json files a
// honeypot writes there) LogRoom bytes of allocated space beyond their end:
// opt.Preferred first, then the others in name order, and never more than
// opt.MaxFiles of them at a time, counting every log that has room already.
// Before each allocation it asks opt.Allow whether the disk can spare it. It
// writes no byte and never changes a file's size.
//
// dir is a folder the honeypot's container can write to, so nothing in it
// is trusted: a log is opened inside dir only, never through a link, only
// as the regular file that was listed, and without waiting on a FIFO. What
// one call costs is bounded too: it lists at most LogRoomEntries entries
// (a folder with more gets nothing) and opens at most opt.MaxFiles logs.
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
	var entries []fs.DirEntry
	for {
		more, err := f.ReadDir(512)
		entries = append(entries, more...)
		if len(entries) > LogRoomEntries {
			_ = f.Close()
			res.Crowded = true
			return res, nil
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = f.Close()
			return res, err
		}
	}
	_ = f.Close()
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
	// A log is opened only to be given room, and at most limit logs are
	// opened in one call, whatever comes of it: a folder of logs QPot may
	// not write costs a few opens, not one for each.
	opened := 0
	for _, name := range order {
		have, held := room[name]
		if !held && len(room) >= limit {
			res.Over = append(res.Over, name)
			continue
		}
		if opened >= limit {
			if held {
				res.Kept = append(res.Kept, name)
			}
			continue
		}
		if opt.Allow != nil && !opt.Allow() {
			// Room that is nearly whole needs nothing from the disk.
			if held && have >= logRoomTopUp {
				res.Kept = append(res.Kept, name)
			} else {
				res.Failed[name] = fmt.Errorf("the disk has no room to spare")
			}
			continue
		}
		opened++
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
	// The blocks hold the file's own bytes up to the end of its last block
	// (of the filesystem's block size, which is not 4 kB everywhere); what
	// they hold beyond that is the room.
	block := int64(st.Blksize)
	if block <= 0 {
		block = 4096
	}
	return max(st.Blocks*512-(info.Size()+block-1)/block*block, 0)
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
	// Asked for on every call, also where the blocks beyond the end look
	// whole: blocks a filesystem put there on its own (XFS, ahead of a
	// growing file) are taken back when the disk fills; blocks asked for
	// are kept. Where they are there already this changes nothing.
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
