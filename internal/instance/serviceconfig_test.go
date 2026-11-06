package instance

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

// TestInitializeWritesServiceConfigs verifies the previously-missing wiring:
// after Initialize, the files the compose mounts (docker-compose.yml,
// vector.yaml, and per-honeypot TPOT configs) actually exist on disk. Without
// vector.yaml the log-collection pipeline can't start.
func TestInitializeWritesServiceConfigs(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default("svccfg-test")
	cfg.DataPath = dir
	cfg.ConfigPath = filepath.Join(dir, "config.yaml")

	// Enable the honeypots whose data dirs and config files setup prepares.
	for _, name := range []string{"cowrie", "conpot", "heralding", "adbhoney"} {
		hp := cfg.Honeypots[name]
		hp.Enabled = true
		cfg.Honeypots[name] = hp
	}

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	mustExist := []string{
		filepath.Join(dir, "docker-compose.yml"),
		filepath.Join(dir, "vector.yaml"),
	}

	for _, p := range mustExist {
		info, err := os.Stat(p)
		if err != nil {
			t.Errorf("expected file %s to exist after Initialize: %v", p, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("file %s is empty", p)
		}
	}

	// Cowrie renders its own config from its persona, so QPot writes none;
	// it only needs the ttylog dir its log mount would otherwise hide.
	cowrie := filepath.Join(dir, "honeypots", "cowrie")
	if info, err := os.Stat(filepath.Join(cowrie, "logs", "tty")); err != nil || !info.IsDir() {
		t.Errorf("cowrie logs/tty dir missing: %v", err)
	}
	for _, stale := range []string{"etc/cowrie.cfg", "etc/userdb.txt", "honeyfs", "qpot_patch_fs.py"} {
		if _, err := os.Stat(filepath.Join(cowrie, stale)); err == nil {
			t.Errorf("Initialize still writes cowrie %s", stale)
		}
	}

	// Conpot and heralding keep the identity they draw in a state dir; the
	// bind mount needs it to exist (docker would create it root-owned).
	for _, name := range []string{"conpot", "heralding"} {
		if info, err := os.Stat(filepath.Join(dir, "honeypots", name, "state")); err != nil || !info.IsDir() {
			t.Errorf("%s state dir missing: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "honeypots", "conpot", "conpot.cfg")); err == nil {
		t.Error("Initialize still writes the unmounted conpot.cfg")
	}
	// Heralding's config is mounted as a file, so it must be written before
	// start, with QPot's content.
	got, err := os.ReadFile(filepath.Join(dir, "honeypots", "heralding", "heralding.yml"))
	if err != nil || string(got) != string(heraldingConfig) {
		t.Errorf("heralding.yml not written with QPot's config (err %v, %d bytes)", err, len(got))
	}
	got, err = os.ReadFile(filepath.Join(dir, "honeypots", "adbhoney", "adbhoney.cfg"))
	if err != nil || string(got) != string(adbhoneyConfig(cfg)) {
		t.Errorf("adbhoney.cfg not written with the instance's config (err %v, %d bytes)", err, len(got))
	}
	if info, err := os.Stat(filepath.Join(dir, "honeypots", "adbhoney", "dl")); err != nil || !info.IsDir() {
		t.Errorf("adbhoney dl dir missing: %v", err)
	}
}
