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
