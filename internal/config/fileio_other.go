//go:build !windows

package config

import "os"

// rename(2) replaces a file atomically whoever has it open.
func renameFile(from, to string) error { return os.Rename(from, to) }

func openConfig(path string) (*os.File, error) { return os.Open(path) }
