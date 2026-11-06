//go:build !windows

package hostsetup

import (
	"os"
	"syscall"
)

// interruptProcess asks p to stop the way Ctrl-C does, so a package manager
// can finish its current write and leave its database consistent.
func interruptProcess(p *os.Process) error { return p.Signal(os.Interrupt) }

// freeBytes returns the space available to unprivileged users at path.
func freeBytes(path string) int64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0
	}
	return int64(st.Bavail) * int64(st.Bsize) // #nosec G115 -- sizes fit int64
}
