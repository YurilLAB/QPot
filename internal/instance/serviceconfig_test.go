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

	// Ensure cowrie is enabled so we exercise the TPOT config path.
	if hp, ok := cfg.Honeypots["cowrie"]; ok {
		hp.Enabled = true
		cfg.Honeypots["cowrie"] = hp
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
	if _, ok := cfg.Honeypots["cowrie"]; ok && cfg.Honeypots["cowrie"].Enabled {
		mustExist = append(mustExist, filepath.Join(dir, "honeypots", "cowrie", "cowrie.cfg"))
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
}
