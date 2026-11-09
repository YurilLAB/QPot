//go:build windows

package config

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// Windows refuses to replace a file while anything has it open, and to open
// one while it is being replaced: a Save racing a reader (the web UI's, the
// CLI's, or a virus scanner's) failed with "Access is denied" or "being used
// by another process". Both hold the file for a moment, so replacing and
// opening are retried for a while, as the Go command does
// (cmd/go/internal/robustio).
const shareRetry = 2 * time.Second

func transient(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}

// retry runs op until it succeeds, fails otherwise than transiently, or
// shareRetry has passed.
func retry(op func() error) error {
	deadline := time.Now().Add(shareRetry)
	delay := time.Millisecond
	for {
		err := op()
		if err == nil || !transient(err) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(delay)
		delay = min(2*delay, 64*time.Millisecond)
	}
}

func renameFile(from, to string) error {
	return retry(func() error { return os.Rename(from, to) })
}

func openConfig(path string) (*os.File, error) {
	var f *os.File
	err := retry(func() error {
		var err error
		f, err = os.Open(path)
		return err
	})
	return f, err
}
