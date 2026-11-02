//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
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

func terminateProcess(pid int) {
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Kill()
	}
}
