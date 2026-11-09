//go:build unix

package instance

import (
	"bytes"
	"path/filepath"
	"syscall"
	"testing"
)

func TestBrokerMetadataReaderRefusesFIFOWithoutConsumingCursor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	partial := []byte("held")
	offset, remaining, lines, err := readNewLinesDetailed(path, 9, partial)
	if err == nil || offset != 9 || !bytes.Equal(remaining, partial) || len(lines) != 0 {
		t.Fatal("FIFO metadata was opened or consumed")
	}
}
