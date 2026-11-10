package instance

import (
	"bytes"
	"encoding/xml"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"gopkg.in/yaml.v3"
)

func TestManagedClickHouseKeeperConfiguration(t *testing.T) {
	cfg := config.Default("keeper-config")
	cfg.DataPath = t.TempDir()
	cfg.Security.SandboxMode = "none"
	enableOnly(cfg) // Coordination is ready even before intelligence is enabled.
	if err := prepareClickHouseKeeper(cfg); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.DataPath, "clickhouse-keeper.xml")
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, clickHouseKeeperConfig) {
		t.Fatalf("generated Keeper configuration differs: %v", err)
	}
	var settings struct {
		Prefix string `xml:"keeper_map_path_prefix"`
		Server struct {
			Port      int    `xml:"tcp_port"`
			ID        int    `xml:"server_id"`
			Log       string `xml:"log_storage_path"`
			Snapshots string `xml:"snapshot_storage_path"`
		} `xml:"keeper_server"`
		Client struct {
			Node struct {
				Host string `xml:"host"`
				Port int    `xml:"port"`
			} `xml:"node"`
		} `xml:"zookeeper"`
	}
	if err := xml.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	if settings.Prefix == "" || settings.Server.ID != 1 || settings.Server.Port != settings.Client.Node.Port || settings.Client.Node.Host != "127.0.0.1" || !strings.HasPrefix(settings.Server.Log, "/var/lib/clickhouse/") || !strings.HasPrefix(settings.Server.Snapshots, "/var/lib/clickhouse/") {
		t.Fatal("Keeper must use persistent database storage and a local client connection")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o644 {
			t.Fatalf("database user cannot read its non-secret configuration: %v", err)
		}
	}
	out := renderComposeCfg(t, cfg)
	var document struct {
		Services map[string]struct {
			Volumes []string `yaml:"volumes"`
			Ports   []string `yaml:"ports"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(out), &document); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, volume := range document.Services["database"].Volumes {
		if volume == path+":/etc/clickhouse-server/config.d/qpot-keeper.xml:ro" {
			found = true
		}
	}
	if !found {
		t.Fatal("the real ClickHouse config.d must receive the single read-only configuration file")
	}
	for _, service := range document.Services {
		for _, port := range service.Ports {
			if strings.Contains(port, "9181") || strings.Contains(port, "9234") {
				t.Fatal("coordination ports must not be published")
			}
		}
	}
}

func TestManagedClickHouseKeeperDoesNotFollowReplacedConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation depends on Windows host policy")
	}
	cfg := config.Default("keeper-link")
	cfg.DataPath = t.TempDir()
	outside := filepath.Join(t.TempDir(), "keep")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.DataPath, "clickhouse-keeper.xml")
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if err := prepareClickHouseKeeper(cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "keep" {
		t.Fatal("configuration generation followed a link outside the instance")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatal("generated configuration is not an ordinary file")
	}
}
