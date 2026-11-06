package main

import (
	"os"

	"golang.org/x/term"
)

// isTerminal reports whether f is an interactive terminal.
func isTerminal(f *os.File) bool { return term.IsTerminal(int(f.Fd())) } // #nosec G115 -- a file descriptor fits int

// geteuid is the effective user ID (-1 on Windows).
func geteuid() int { return os.Geteuid() }
