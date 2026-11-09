//go:build linux || darwin

package sshbackend

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
)

const privateKeyReadFlags = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// Inherited stdin is usually a blocking descriptor. A duplicate marked
// nonblocking before os.NewFile joins Go's poller, allowing Close to cancel a
// pending read when the command exits while its SSH channel remains open.
func cancellableFileInput(file *os.File) (io.Reader, func(), error) {
	raw, err := file.SyscallConn()
	if err != nil {
		return nil, nil, err
	}
	var duplicate int
	var flags uintptr
	var setupErr error
	err = raw.Control(func(fd uintptr) {
		var errno syscall.Errno
		flags, _, errno = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0)
		if errno != 0 {
			setupErr = errno
			return
		}
		syscall.ForkLock.RLock()
		duplicate, setupErr = syscall.Dup(int(fd))
		if setupErr == nil {
			syscall.CloseOnExec(duplicate)
		}
		syscall.ForkLock.RUnlock()
		if setupErr == nil {
			setupErr = syscall.SetNonblock(duplicate, true)
			if setupErr != nil {
				_ = syscall.Close(duplicate)
			}
		}
	})
	if err = errors.Join(err, setupErr); err != nil {
		return nil, nil, err
	}
	reader := os.NewFile(uintptr(duplicate), "session stdin")
	return reader, func() {
		_ = reader.Close()
		if flags&syscall.O_NONBLOCK == 0 {
			_ = raw.Control(func(fd uintptr) { _ = syscall.SetNonblock(int(fd), false) })
		}
	}, nil
}

func inputPipeClosed(err error) bool { return errors.Is(err, syscall.EPIPE) }

func execDaemon(path string, args, env []string) error { return syscall.Exec(path, args, env) }
func lockFile(file *os.File) error                     { return syscall.Flock(int(file.Fd()), syscall.LOCK_EX) }
func processSignals() []os.Signal {
	return []os.Signal{syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGWINCH}
}
func setProcessGroup(cmd *exec.Cmd, pty bool) {
	if !pty {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
}
func forwardSignal(cmd *exec.Cmd, signal os.Signal, pty bool) {
	if sig, ok := signal.(syscall.Signal); ok && !pty {
		_ = syscall.Kill(-cmd.Process.Pid, sig)
	} else {
		_ = cmd.Process.Signal(signal)
	}
}
func fileUID(info os.FileInfo) int {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(stat.Uid)
	}
	return -1
}

func processExitCode(state *os.ProcessState) int {
	if code := state.ExitCode(); code >= 0 {
		return code
	}
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return 128
}
