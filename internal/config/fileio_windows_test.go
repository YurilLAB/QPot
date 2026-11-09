//go:build windows

package config

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func writeTestFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSaveWaitsForABriefHolder: a file someone has open for a moment delays
// a save instead of failing it (control: a plain rename fails at once); one
// held for good fails the save after shareRetry, not never, and unchanged.
func TestSaveWaitsForABriefHolder(t *testing.T) {
	p := writeTestFile(t, "old")
	h, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, p); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("control: replacing an open file: %v, want access denied", err)
	}
	go func() {
		time.Sleep(200 * time.Millisecond)
		h.Close()
	}()
	start := time.Now()
	if err := writeConfigFile(p, []byte("new")); err != nil {
		t.Fatalf("save behind a brief holder: %v", err)
	}
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Errorf("the save did not wait for the holder (%v)", d)
	}
	if got, _ := os.ReadFile(p); string(got) != "new" {
		t.Errorf("saved %q", got)
	}

	q := writeTestFile(t, "old")
	g, err := os.Open(q)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	start = time.Now()
	err = writeConfigFile(q, []byte("new"))
	d := time.Since(start)
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) || d < shareRetry || d > shareRetry+time.Second {
		t.Errorf("save behind a holder that stays: %v after %v", err, d)
	}
	if got, _ := io.ReadAll(g); string(got) != "old" {
		t.Errorf("the failed save changed the file: %q", got)
	}
}

// TestReadWaitsForABriefHolder: a file opened without sharing for a moment
// (as during a replace) delays a read instead of failing it; control: a
// plain read fails at once.
func TestReadWaitsForABriefHolder(t *testing.T) {
	p := writeTestFile(t, "content")
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(p); !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		windows.CloseHandle(h)
		t.Fatalf("control: reading a file held without sharing: %v, want a sharing violation", err)
	}
	go func() {
		time.Sleep(200 * time.Millisecond)
		windows.CloseHandle(h)
	}()
	start := time.Now()
	got, err := ReadFile(p, 0)
	if err != nil || string(got) != "content" {
		t.Fatalf("read behind a brief holder: %q %v", got, err)
	}
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Errorf("the read did not wait for the holder (%v)", d)
	}
}

// TestReadFileLimitAndMissing: the size limit, and a missing file reported at
// once as not existing (Load falls back to the defaults on it).
func TestReadFileLimitAndMissing(t *testing.T) {
	p := writeTestFile(t, "12345")
	if _, err := ReadFile(p, 4); err == nil {
		t.Error("a file over the limit was read")
	}
	if got, err := ReadFile(p, 5); err != nil || string(got) != "12345" {
		t.Errorf("at the limit: %q %v", got, err)
	}
	start := time.Now()
	if _, err := ReadFile(filepath.Join(t.TempDir(), "none.yaml"), 0); !os.IsNotExist(err) {
		t.Errorf("missing file: %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("a missing file was retried (%v)", d)
	}
}
