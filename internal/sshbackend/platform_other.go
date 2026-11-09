//go:build !linux && !darwin

package sshbackend

import (
	"errors"
	"os"
)

func execDaemon(string, []string, []string) error { return errors.New("SSH backend requires Linux") }
func fileUID(os.FileInfo) int                     { return os.Getuid() }
