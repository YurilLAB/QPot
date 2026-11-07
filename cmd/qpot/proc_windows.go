//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

func detachProcess(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}

func processAlive(pid int) bool {
	p, err := os.FindProcess(pid) // opens a handle; fails if the process is gone
	if err != nil {
		return false
	}
	_ = p.Release()
	return true
}

// isServeProcess cannot cheaply read another process's command line on
// Windows; the pid file is private to the instance directory, so trust it.
func isServeProcess(pid int, instanceName string) bool { return true }

// processStartTime returns when pid started.
func processStartTime(pid int) (time.Time, bool) {
	h, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid)) // #nosec G115 -- a pid fits uint32
	if err != nil {
		return time.Time{}, false
	}
	defer syscall.CloseHandle(h)
	var created, exited, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, created.Nanoseconds()), true
}

func terminateProcess(pid int) {
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Kill()
	}
}
