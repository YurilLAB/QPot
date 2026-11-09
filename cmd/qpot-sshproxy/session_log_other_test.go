//go:build !unix

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHostReadableSessionLogUnsupportedPlatformHasNoEffects(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-created")
	file, err := openSessionLog(filepath.Join(dir, "sessions.json"), true)
	if file != nil {
		file.Close()
	}
	if err == nil {
		t.Fatal("host readability accepted unverified link-count semantics")
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("unsupported opt-in changed the filesystem: %v", err)
	}
}
