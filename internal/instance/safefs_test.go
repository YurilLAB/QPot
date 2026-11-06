package instance

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

// TestCowrieTTYSymlinkNotFollowed: cowrie writes to its logs mount, so it can
// leave a symlink at log/tty. Initialize made that path with MkdirAll and
// chmod 0777, which follow it: the directory it points at, outside the
// instance, became world-writable. The link is now replaced by a real
// directory and the target keeps its mode.
func TestCowrieTTYSymlinkNotFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	cfg := config.Default("tty-symlink")
	cfg.DataPath = t.TempDir()
	enableOnly(cfg, "cowrie")
	outside := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	logs := filepath.Join(cfg.DataPath, "honeypots", "cowrie", "logs")
	if err := os.MkdirAll(logs, 0o750); err != nil {
		t.Fatal(err)
	}
	tty := filepath.Join(logs, "tty")
	if err := os.Symlink(outside, tty); err != nil {
		t.Fatal(err)
	}

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if fi, err := os.Stat(outside); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("the directory the link pointed at: %v, mode %v (want 0700)", err, fi.Mode().Perm())
	}
	fi, err := os.Lstat(tty)
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm() != 0o777 {
		t.Fatalf("log/tty after Initialize: %v %v", err, fi.Mode())
	}
}
