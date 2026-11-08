//go:build !windows

package instance

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

// The folders dionaea, galah and miniprint write to exist before start, are
// writable by the container's user, and the folders above a nested one can be
// passed through: dionaea (uid 2000) reaches roots/ftp through roots/.
func TestInitializePreparesWritableHoneypotFolders(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default("folders-test")
	cfg.DataPath = dir
	cfg.ConfigPath = filepath.Join(dir, "config.yaml")
	for _, name := range []string{"dionaea", "galah", "miniprint"} {
		hp := cfg.Honeypots[name]
		hp.Enabled = true
		cfg.Honeypots[name] = hp
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	hp := filepath.Join(dir, "honeypots")
	writable := []string{
		"dionaea/data", "dionaea/data/binaries", "dionaea/data/roots/ftp", "dionaea/data/roots/tftp",
		"dionaea/data/roots/www", "dionaea/data/roots/upnp", "dionaea/data/rtp",
		"galah/cert", "miniprint/uploads", "miniprint/data",
	}
	for _, rel := range writable {
		info, err := os.Stat(filepath.Join(hp, rel))
		if err != nil || !info.IsDir() {
			t.Errorf("%s missing: %v", rel, err)
			continue
		}
		if info.Mode().Perm()&0o007 != 0o007 {
			t.Errorf("%s is %o: the container's user cannot write it", rel, info.Mode().Perm())
		}
	}
	info, err := os.Stat(filepath.Join(hp, "dionaea/data/roots"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o005 != 0o005 {
		t.Errorf("dionaea/data/roots is %o: the container's user cannot reach roots/ftp", info.Mode().Perm())
	}
}

// dionaea writes to its data folder, so what it left there is never followed
// when QPot makes the folders inside it: symlinks pointing out of the
// instance are replaced by folders, and what they pointed at stays untouched.
func TestInitializeReplacesSymlinksInDionaeaData(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(dir, "honeypots", "dionaea", "data")
	if err := os.MkdirAll(data, 0o777); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"roots", "binaries"} {
		if err := os.Symlink(outside, filepath.Join(data, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(data, "rtp"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default("dionaea-symlinks")
	cfg.DataPath = dir
	cfg.ConfigPath = filepath.Join(dir, "config.yaml")
	hp := cfg.Honeypots["dionaea"]
	hp.Enabled = true
	cfg.Honeypots["dionaea"] = hp
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"roots", "roots/ftp", "binaries", "rtp"} {
		fi, err := os.Lstat(filepath.Join(data, rel))
		if err != nil || !fi.IsDir() {
			t.Errorf("data/%s is not a real folder: %v %v", rel, fi, err)
		}
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 || fi.Mode().Perm() != 0o700 {
		t.Errorf("the folder outside the instance changed: %d entries, mode %o", len(entries), fi.Mode().Perm())
	}
}
