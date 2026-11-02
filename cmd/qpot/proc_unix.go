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

// totalMemoryBytes returns physical memory from /proc/meminfo (Linux), or 0.
func totalMemoryBytes() int64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "MemTotal:" {
			kb, _ := strconv.ParseInt(f[1], 10, 64)
			return kb * 1024
		}
	}
	return 0
}

// freeDiskBytes returns the free space available to unprivileged users at path.
func freeDiskBytes(path string) int64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0
	}
	return int64(st.Bavail) * int64(st.Bsize) // #nosec G115 -- sizes fit int64
}
