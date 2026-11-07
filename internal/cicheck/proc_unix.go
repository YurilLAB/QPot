//go:build !windows

package cicheck

import (
	"os/exec"
	"syscall"
	"time"
)

// killGroup runs the command in its own process group and, when its
// context ends, kills the whole group: a step's background programs must
// not outlive it.
func killGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 10 * time.Second
}
