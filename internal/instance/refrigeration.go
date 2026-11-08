package instance

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/refrigeration"
)

func refrigerationSiteProfile(cfg *config.Config) string {
	if hp, ok := cfg.GetHoneypotConfig("refrigeration"); ok {
		if profile := strings.TrimSpace(hp.CustomConfig["site_profile"]); profile != "" {
			return profile
		}
	}
	return "retail"
}

func refrigerationBuildPath(cfg *config.Config) string {
	return filepath.Join(cfg.DataPath, "honeypots", "refrigeration", "build")
}

// writeRefrigerationBuild emits the exact sources bundled into this QPot
// binary. Only Docker is needed on the host, including for a released binary.
func writeRefrigerationBuild(cfg *config.Config) error {
	files, err := refrigeration.BuildFiles()
	if err != nil {
		return err
	}
	root := refrigerationBuildPath(cfg)
	if err := os.MkdirAll(filepath.Dir(root), 0750); err != nil {
		return fmt.Errorf("create refrigeration build directory: %w", err)
	}
	tmp, err := os.MkdirTemp(filepath.Dir(root), ".build-")
	if err != nil {
		return fmt.Errorf("create refrigeration build staging directory: %w", err)
	}
	defer os.RemoveAll(tmp)
	for name, content := range files {
		target := filepath.Join(tmp, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0750); err != nil {
			return fmt.Errorf("create refrigeration build context: %w", err)
		}
		if err := os.WriteFile(target, content, 0644); err != nil {
			return fmt.Errorf("write refrigeration build source %s: %w", name, err)
		}
	}
	// Retired assets must not survive an upgrade and become part of an image
	// whose tag only describes the current bundled sources.
	if err := os.RemoveAll(root); err != nil {
		return fmt.Errorf("replace refrigeration build context: %w", err)
	}
	if err := os.Rename(tmp, root); err != nil {
		return fmt.Errorf("activate refrigeration build context: %w", err)
	}
	return nil
}
