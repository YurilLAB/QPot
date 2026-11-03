package instance

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
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
		// cowrie.cfg lands in the etc/ subdir (the cowrie deployment profile's
		// ConfigSubdir) so it's inside the directory the container mounts.
		mustExist = append(mustExist, filepath.Join(dir, "honeypots", "cowrie", "etc", "cowrie.cfg"))
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

func TestServiceConfigsCannotFollowHoneypotSymlinkOutsideInstance(t *testing.T) {
	dir := t.TempDir()
	m := serviceConfigManager(t, filepath.Join(dir, "instance"))
	if err := m.generateServiceConfigs(); err != nil {
		t.Fatal(err)
	}
	// The writable etc bind mount lets a compromised honeypot replace an
	// existing generated config with a symlink. Regeneration must not follow
	// that link with the host control plane's filesystem privileges.
	sentinel := filepath.Join(dir, "host-file")
	const original = "host data must remain intact\n"
	if err := os.WriteFile(sentinel, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(m.config.DataPath, "honeypots", "cowrie", "etc", "cowrie.cfg")
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sentinel, configPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := m.generateServiceConfigs(); err == nil {
		t.Error("regeneration accepted a config symlink outside the honeypot root")
	}
	got, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatal("host file outside the instance was overwritten through a honeypot symlink")
	}
}

func serviceConfigManager(t *testing.T, dataPath string) *Manager {
	t.Helper()
	cfg := config.Default("symlink-boundary")
	cfg.DataPath = dataPath
	cfg.ConfigPath = filepath.Join(dataPath, "config.yaml")
	cfg.Security.SandboxMode = "none"
	for name, hp := range cfg.Honeypots {
		hp.Enabled = name == "cowrie"
		cfg.Honeypots[name] = hp
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestServiceConfigsRejectExternalDirectorySymlinks(t *testing.T) {
	for _, rel := range []string{"etc", filepath.Join("logs", "tty"), filepath.Join("honeyfs", "etc")} {
		t.Run(rel, func(t *testing.T) {
			dir := t.TempDir()
			m := serviceConfigManager(t, filepath.Join(dir, "instance"))
			if err := m.generateServiceConfigs(); err != nil {
				t.Fatal(err)
			}
			external := filepath.Join(dir, "host-directory")
			if err := os.Mkdir(external, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(m.config.DataPath, "honeypots", "cowrie", rel)
			if err := os.RemoveAll(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(external, path); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			if err := m.generateServiceConfigs(); err == nil {
				t.Error("regeneration accepted an external directory symlink")
			}
			entries, err := os.ReadDir(external)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Errorf("wrote %d files outside the honeypot root", len(entries))
			}
			st, err := os.Stat(external)
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" && st.Mode().Perm() != 0o700 {
				t.Errorf("external directory permissions changed to %o", st.Mode().Perm())
			}
		})
	}
}

// Relative links entirely within a honeypot remain useful and safe, including
// links in parent directory components and in the final generated filename.
func TestServiceConfigsAllowInternalSymlinks(t *testing.T) {
	m := serviceConfigManager(t, t.TempDir())
	if err := m.generateServiceConfigs(); err != nil {
		t.Fatal(err)
	}
	hpDir := filepath.Join(m.config.DataPath, "honeypots", "cowrie")
	etc := filepath.Join(hpDir, "etc")
	want, err := os.ReadFile(filepath.Join(etc, "cowrie.cfg"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(etc, filepath.Join(hpDir, "config-store")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("config-store", etc); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	configPath := filepath.Join(etc, "cowrie.cfg")
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("cowrie-generated.cfg", configPath); err != nil {
		t.Fatal(err)
	}
	if err := m.generateServiceConfigs(); err != nil {
		t.Fatalf("safe internal links rejected: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(hpDir, "config-store", "cowrie-generated.cfg"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("generated config through internal links differs from regular generation")
	}
}

func FuzzServiceConfigSymlinkBoundary(f *testing.F) {
	f.Add(uint8(0), false, []byte("host file"))
	f.Add(uint8(0), true, []byte("host file"))
	f.Add(uint8(4), true, []byte{0, 0xff, 1})
	f.Fuzz(func(t *testing.T, chainLength uint8, relative bool, original []byte) {
		if len(original) > 4096 {
			t.Skip()
		}
		dir := t.TempDir()
		m := serviceConfigManager(t, filepath.Join(dir, "instance"))
		etc := filepath.Join(m.config.DataPath, "honeypots", "cowrie", "etc")
		if err := os.MkdirAll(etc, 0o750); err != nil {
			t.Fatal(err)
		}
		sentinel := filepath.Join(dir, "host-file")
		if err := os.WriteFile(sentinel, original, 0o600); err != nil {
			t.Fatal(err)
		}
		target := sentinel
		if relative {
			var err error
			target, err = filepath.Rel(etc, sentinel)
			if err != nil {
				t.Fatal(err)
			}
		}
		// Every possible target stays within this test's temporary directory;
		// the mutation engine never supplies a real host path to write.
		for i := 0; i < int(chainLength%8); i++ {
			name := "link" + strconv.Itoa(i)
			if err := os.Symlink(target, filepath.Join(etc, name)); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			target = name
		}
		if err := os.Symlink(target, filepath.Join(etc, "cowrie.cfg")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if err := m.generateServiceConfigs(); err == nil {
			t.Error("regeneration accepted a symlink chain escaping the honeypot root")
		}
		got, err := os.ReadFile(sentinel)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, original) {
			t.Fatal("regeneration modified a host file outside the honeypot root")
		}
	})
}
