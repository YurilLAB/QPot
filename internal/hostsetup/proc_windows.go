//go:build windows

package hostsetup

import (
	"errors"
	"os"
)

// interruptProcess cannot deliver Ctrl-C to another process on Windows; the
// caller then kills it.
func interruptProcess(*os.Process) error { return errors.New("interrupt not supported") }

// freeBytes is not measured on Windows (Docker Desktop keeps images in its
// own virtual disk).
func freeBytes(string) int64 { return 0 }

// oNoFollow has no Windows equivalent; O_EXCL still refuses an existing name.
const oNoFollow = 0

// notPrivate: the temporary folder Windows gives a user is in their own
// profile, and its access list already shuts other users out.
func notPrivate(os.FileInfo) string { return "" }

// unsafeParent: see notPrivate.
func unsafeParent(string) string { return "" }
