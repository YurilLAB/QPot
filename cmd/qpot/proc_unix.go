//go:build !windows

package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// detachProcess starts c in its own session so it survives the terminal.
func detachProcess(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }

func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

// isServeProcess checks /proc/<pid>/cmdline (where available) that pid really
// is `qpot serve -i <instance>`; without /proc it trusts the pid file.
func isServeProcess(pid int, instanceName string) bool {
	data, err := os.ReadFile("/proc/" + itoa(pid) + "/cmdline")
	if err != nil {
		return !fileExists("/proc/self/cmdline")
	}
	args := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
	hasServe, hasInst := false, false
	for i, a := range args {
		if a == "serve" {
			hasServe = true
		}
		if (a == "-i" || a == "--instance") && i+1 < len(args) && args[i+1] == instanceName {
			hasInst = true
		}
	}
	return hasServe && hasInst
}

func terminateProcess(pid int) {
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Signal(syscall.SIGTERM)
	}
}

func itoa(n int) string {
	return strconv.Itoa(n)
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
