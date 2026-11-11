//go:build windows

package hostsetup

import (
	"errors"
	"math"
	"os"

	"golang.org/x/sys/windows"
)

// interruptProcess cannot deliver Ctrl-C to another process on Windows; the
// caller then kills it.
func interruptProcess(*os.Process) error { return errors.New("interrupt not supported") }

// freeBytes is not measured on Windows (Docker Desktop keeps images in its
// own virtual disk).
func freeBytes(string) int64 { return 0 }

// dataFreeBytes returns the space the current user may still use on the
// volume that holds the folder path, and whether it could be read: a full
// volume is 0 and true. An instance's data folder is an ordinary Windows
// folder that Docker Desktop shares with the containers, so its volume is
// the one the honeypots' logs fill.
func dataFreeBytes(path string) (int64, bool) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, false
	}
	var avail, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &total, &free); err != nil {
		return 0, false
	}
	if avail > math.MaxInt64 {
		return math.MaxInt64, true
	}
	return int64(avail), true
}

// oNoFollow has no Windows equivalent; O_EXCL still refuses an existing name.
const oNoFollow = 0

// notPrivate: the temporary folder Windows gives a user is in their own
// profile, and its access list already shuts other users out.
func notPrivate(os.FileInfo) string { return "" }

// unsafeParent: see notPrivate.
func unsafeParent(string) string { return "" }
