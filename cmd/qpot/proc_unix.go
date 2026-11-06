//go:build !windows

package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
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

// processStartTime returns when pid started, from /proc (Linux); false where
// that is not available.
func processStartTime(pid int) (time.Time, bool) {
	stat, err := os.ReadFile("/proc/" + itoa(pid) + "/stat")
	if err != nil {
		return time.Time{}, false
	}
	// The command name (field 2) may contain spaces and parentheses; the
	// fields after its closing parenthesis start at field 3, so the start
	// time (field 22, in clock ticks since boot) is the 20th of them.
	i := strings.LastIndexByte(string(stat), ')')
	if i < 0 {
		return time.Time{}, false
	}
	f := strings.Fields(string(stat[i+1:]))
	if len(f) < 20 {
		return time.Time{}, false
	}
	ticks, err := strconv.ParseInt(f[19], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	boot, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, false
	}
	for _, line := range strings.Split(string(boot), "\n") {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			secs, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return time.Time{}, false
			}
			// USER_HZ is 100 on every Linux architecture's user ABI.
			return time.Unix(secs, 0).Add(time.Duration(ticks) * 10 * time.Millisecond), true
		}
	}
	return time.Time{}, false
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
