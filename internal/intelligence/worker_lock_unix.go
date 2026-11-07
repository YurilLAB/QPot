//go:build !windows

package intelligence

import (
	"golang.org/x/sys/unix"
	"os"
)

func lockWorkerFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}
