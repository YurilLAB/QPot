package instance

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/qpot/qpot/internal/config"
)

//go:embed clickhouse_keeper.xml
var clickHouseKeeperConfig []byte

// clickHouseLimitsConfig sizes the server for its container: no internal
// diagnostic tables (they were most of an idle instance's CPU and disk
// writes, and grow without limit), caches and merge pools for a 1 GiB
// memory limit without swap.
//
//go:embed clickhouse_limits.xml
var clickHouseLimitsConfig []byte

func clickHouseLimitsPath(cfg *config.Config) string {
	return filepath.Join(cfg.DataPath, "clickhouse-limits.xml")
}

func clickHouseKeeperPath(cfg *config.Config) string {
	return filepath.Join(cfg.DataPath, "clickhouse-keeper.xml")
}

// prepareClickHouseKeeper keeps the default managed database usable with
// native fenced leases. External databases must provision their own Keeper.
// The generated file contains no credentials and is readable by the database
// user through one read-only file mount; its host parent remains private.
func prepareClickHouseKeeper(cfg *config.Config) error {
	if cfg.Database.Type != "clickhouse" {
		return nil
	}
	if err := writeClickHouseConfig(cfg, clickHouseLimitsPath(cfg), clickHouseLimitsConfig); err != nil {
		return err
	}
	return writeClickHouseConfig(cfg, clickHouseKeeperPath(cfg), clickHouseKeeperConfig)
}

// writeClickHouseConfig publishes one generated server configuration file:
// no credentials, readable by the database user through a read-only file
// mount, replaced atomically.
func writeClickHouseConfig(cfg *config.Config, path string, content []byte) error {
	file, err := os.CreateTemp(cfg.DataPath, ".clickhouse-config-*.xml")
	if err != nil {
		return fmt.Errorf("prepare ClickHouse configuration: %w", err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	defer file.Close()
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Chmod(0o644); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	// ReplaceFile replaces a symlink itself; it never writes its target and
	// honors Windows readers of a previously generated configuration.
	return config.ReplaceFile(temporary, path)
}
