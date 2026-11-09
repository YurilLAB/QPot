//go:build !unix

package main

import "os"

const (
	sessionLogOpenFlags      = 0
	sessionLogLinksSupported = false
)

func sessionLogSingleLink(os.FileInfo) bool { return false }
