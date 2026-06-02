//go:build !windows

package server

import (
	"os/exec"
	"syscall"
)

// configureHookProcessGroup puts a response hook (and every process it forks)
// into its own process group and kills the whole group when the command's
// context fires.
//
// Without this, exec's context cancellation kills only the direct shell. A hook
// that forks - which is the common case, e.g. "iptables -A ...; logger ..." or
// anything that backgrounds a child - leaves descendants running past the
// timeout, and because they inherit the stdout/stderr pipe, Wait blocks reading
// that pipe until they exit. The per-action timeout would then be silently
// ineffective. Signalling the negative pid (the process group) tears the whole
// subtree down at the deadline.
func configureHookProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
}
