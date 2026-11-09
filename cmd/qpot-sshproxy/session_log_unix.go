//go:build unix

package main

import (
	"os"
	"syscall"
)

const (
	sessionLogOpenFlags      = syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	sessionLogLinksSupported = true
)

func sessionLogSingleLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}
