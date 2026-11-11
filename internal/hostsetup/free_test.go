package hostsetup

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDataFreeBytes: the free space of a real folder is known and matches
// the disk, a folder that does not exist yet is measured at its nearest
// existing parent, and it works on every supported system (FreeBytes reads
// 0 on Windows).
func TestDataFreeBytes(t *testing.T) {
	dir := t.TempDir()
	free, known := DataFreeBytes(dir)
	if !known {
		t.Fatalf("the free space of %s could not be read", dir)
	}
	if free < 0 {
		t.Fatalf("free space %d", free)
	}
	t.Logf("%d bytes free at %s", free, dir)
	// The same disk through a path that does not exist yet.
	missing := filepath.Join(dir, "honeypots", "cowrie", "logs")
	free2, known2 := DataFreeBytes(missing)
	if !known2 {
		t.Fatalf("the free space above %s could not be read", missing)
	}
	// Other programs write to the disk between the two readings; a
	// difference of more than 1 GiB means another disk was measured.
	if diff := free - free2; diff > 1<<30 || diff < -(1<<30) {
		t.Errorf("free space of the folder %d and of a missing folder in it %d differ", free, free2)
	}
	// Writing to the disk does not make more room on it: a 1 MiB file may
	// leave at most the first reading plus what others freed meanwhile.
	if err := os.WriteFile(filepath.Join(dir, "fill"), make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if free3, known3 := DataFreeBytes(dir); !known3 || free3 > free+(1<<30) {
		t.Errorf("after writing 1 MiB: %d (known %v), before: %d", free3, known3, free)
	}
	// Where FreeBytes measures (not on Windows), the two agree.
	if old := FreeBytes(dir); old > 0 {
		now, _ := DataFreeBytes(dir)
		if diff := old - now; diff > 1<<30 || diff < -(1<<30) {
			t.Errorf("FreeBytes %d and DataFreeBytes %d differ", old, now)
		}
	}
}
