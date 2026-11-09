package config

import (
	"fmt"
	"math"
	"slices"
	"strings"
)

const (
	// SSHEnvironmentStandalone keeps the ordinary disposable SSH backend pool.
	SSHEnvironmentStandalone = "standalone"
	// SSHEnvironmentOrganization gives each SSH connection its own application,
	// database and backup cell, recycled together before the next connection.
	SSHEnvironmentOrganization = "organization"
	// SSHImageSourcePublished uses QPot's published HiFi images.
	SSHImageSourcePublished = "published"
	// SSHImageSourceLocal uses the fixed development tags built by the operator.
	SSHImageSourceLocal = "local"
)

// Docker uses a 100ms CFS period for the cpus setting; Linux's minimum positive
// quota is 1ms. Compose versions use float32 CPU values, so check both numeric
// conversions and Docker's integer multiplication before division.
func validSSHCPUPercent(percent float64) bool {
	if percent < 1 || math.IsNaN(percent) || math.IsInf(percent, 0) {
		return false
	}
	const maxNanoCPUs = math.MaxInt64 / 100000
	CPUs := percent / 100
	return CPUs*1e9 <= maxNanoCPUs && float64(float32(CPUs)*1e9) <= maxNanoCPUs
}

// SSHEnvironment returns the selected HiFi environment, defaulting to standalone.
// Call ValidateSSHEnvironment before deploying a configuration: an invalid mode
// remains invalid here rather than being silently replaced with the default.
func SSHEnvironment(cfg *Config) string {
	if cfg == nil {
		return SSHEnvironmentStandalone
	}
	hp, _ := cfg.GetHoneypotConfig("ssh-proxy")
	mode := strings.TrimSpace(hp.CustomConfig["environment"])
	if mode == "" {
		return SSHEnvironmentStandalone
	}
	return mode
}

// SSHImageSource returns the selected HiFi image source, defaulting to published.
// Unknown values are retained so validation can reject them before deployment.
func SSHImageSource(cfg *Config) string {
	if cfg == nil {
		return SSHImageSourcePublished
	}
	hp, _ := cfg.GetHoneypotConfig("ssh-proxy")
	source := strings.TrimSpace(hp.CustomConfig["image_source"])
	if source == "" {
		return SSHImageSourcePublished
	}
	return source
}

// ValidateSSHEnvironment checks the HiFi environment and its supported setting
// names, including configurations supplied directly rather than through the UI.
// A valid selection may be saved while ssh-proxy is disabled; this never enables it.
func ValidateSSHEnvironment(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	hp, _ := cfg.GetHoneypotConfig("ssh-proxy")
	if err := ValidateSSHEnvironmentSettings(hp.CustomConfig); err != nil {
		return err
	}
	if hp.Resources.UseCustomLimits {
		CPU := hp.Resources.MaxCPUPercent
		if CPU != 0 && !validSSHCPUPercent(CPU) {
			return fmt.Errorf("honeypots.ssh-proxy.resources.max_cpu_percent: use zero to inherit or at least 1 percent, within Docker's representable CPU quota range")
		}
		for _, limit := range []struct {
			name  string
			value int64
		}{
			{"max_memory_mb", hp.Resources.MaxMemoryMB},
			{"max_storage_gb", hp.Resources.MaxStorageGB},
			{"max_pids", hp.Resources.MaxPids},
		} {
			if limit.value < 0 {
				return fmt.Errorf("honeypots.ssh-proxy.resources.%s: use zero to inherit or a positive limit", limit.name)
			}
		}
		if hp.Resources.MaxMemoryMB > math.MaxInt64>>20 {
			return fmt.Errorf("honeypots.ssh-proxy.resources.max_memory_mb: limit exceeds Docker's signed 64-bit byte range")
		}
		if hp.Resources.MaxMemoryMB != 0 && hp.Resources.MaxMemoryMB < 6 {
			return fmt.Errorf("honeypots.ssh-proxy.resources.max_memory_mb: use zero to inherit or at least 6 MiB, Docker's minimum memory limit")
		}
		if hp.Resources.MaxStorageGB > math.MaxInt64>>30 {
			return fmt.Errorf("honeypots.ssh-proxy.resources.max_storage_gb: limit exceeds the signed 64-bit cleanup byte range")
		}
	}
	if hp.Enabled {
		limits := cfg.GetEffectiveResourceLimits("ssh-proxy")
		if !validSSHCPUPercent(limits.MaxCPUPercent) || limits.MaxMemoryMB < 6 || limits.MaxMemoryMB > math.MaxInt64>>20 || limits.MaxPids <= 0 || limits.MaxStorageGB > math.MaxInt64>>30 {
			return fmt.Errorf("honeypots.ssh-proxy.resources: effective memory must be at least 6 MiB, PIDs must be positive, CPU must be at least 1 percent, and CPU/memory/storage conversions must fit Docker and cleanup byte ranges")
		}
	}
	return nil
}

// ValidateSSHEnvironmentSettings checks the environment and setting names of a
// proposed ssh-proxy custom_config without modifying the caller's map. Backend
// counts retain their existing value validation and legacy runtime handling.
func ValidateSSHEnvironmentSettings(custom map[string]string) error {
	keys := make([]string, 0, len(custom))
	for key := range custom {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		if key != "backends" && key != "environment" && key != "image_source" {
			return fmt.Errorf("honeypots.ssh-proxy.custom_config: unsupported setting %q (use backends, environment or image_source)", key)
		}
	}
	mode := strings.TrimSpace(custom["environment"])
	switch mode {
	case "", SSHEnvironmentStandalone, SSHEnvironmentOrganization:
	default:
		return fmt.Errorf("honeypots.ssh-proxy.custom_config.environment %q: use standalone or organization", custom["environment"])
	}
	switch strings.TrimSpace(custom["image_source"]) {
	case "", SSHImageSourcePublished, SSHImageSourceLocal:
		return nil
	default:
		return fmt.Errorf("honeypots.ssh-proxy.custom_config.image_source %q: use published or local", custom["image_source"])
	}
}
