//go:build linux || darwin

package sshbackend

import (
	"os"
	"syscall"
)

func execDaemon(path string, args, env []string) error { return syscall.Exec(path, args, env) }

func fileUID(info os.FileInfo) int {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(stat.Uid)
	}
	return -1
}
