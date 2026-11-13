//go:build linux

package diskguard

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// KeepLogRoom gives every log directly in dir (the *.log and *.json files a
// honeypot writes there) at least logRoomTopUp, and at most LogRoom, bytes
// of allocated space beyond its end. It writes no byte and never changes a
// file's size.
//
// dir is a folder the honeypot's container can write to, so nothing in it
// is trusted: a log is opened inside dir only, never through a link, only
// as the regular file that was listed, and without waiting on a FIFO.
func KeepLogRoom(dir string) (LogRoomResult, error) {
	res := LogRoomResult{Failed: map[string]error{}}
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
	for _, e := range entries {
		name := e.Name()
		if !isLogName(name) || !e.Type().IsRegular() {
			continue
		}
		switch err := keepFileRoom(root, name); {
		case err == nil:
			res.Kept = append(res.Kept, name)
		case errors.Is(err, fs.ErrPermission):
			res.Denied = append(res.Denied, name)
		default:
			res.Failed[name] = err
		}
	}
	return res, nil
}

// keepFileRoom keeps the room of one log in root.
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
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("no allocation information")
	}
	size := info.Size()
	// The blocks hold the file's own bytes up to its last block; what
	// they hold beyond that is the room.
	end := (size + 4095) &^ 4095
	if st.Blocks*512-end >= logRoomTopUp {
		return nil
	}
	for {
		err = unix.Fallocate(int(f.Fd()), unix.FALLOC_FL_KEEP_SIZE, size, LogRoom)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("allocate room: %w", err)
	}
	return nil
}
