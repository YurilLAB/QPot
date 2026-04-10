// Package config manages QPot configuration
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// AlertConfig configures webhook alerting when attack thresholds are crossed.
type AlertConfig struct {
	Enabled    bool     `yaml:"enabled"`
	WebhookURL string   `yaml:"webhook_url"`  // Slack/Discord/generic webhook
	Threshold  int      `yaml:"threshold"`     // events per minute to trigger
	Honeypots  []string `yaml:"honeypots"`     // which honeypots to alert on (empty = all)
}

// IntelligenceConfig configures the threat intelligence subsystem.
type IntelligenceConfig struct {
	Enabled          bool          `yaml:"enabled"`
	ATTCKDataPath    string        `yaml:"attck_data_path"`   // where to cache downloaded ATT&CK data
	WorkerInterval   time.Duration `yaml:"worker_interval"`   // default 15min
	WorkerBatchSize  int           `yaml:"worker_batch_size"` // default 500
	InactivityWindow time.Duration `yaml:"inactivity_window"` // TTP session inactivity, default 30min
	FetchATTCK       bool          `yaml:"fetch_attck"`       // try to fetch latest from MITRE, default true
}

// Config represents QPot configuration
type Config struct {
	InstanceName string            `yaml:"instance_name"`
	QPotID       string            `yaml:"qpot_id"`
	DataPath     string            `yaml:"data_path"`
	ConfigPath   string            `yaml:"config_path"`
	Database     DatabaseConfig    `yaml:"database"`
	Security     SecurityConfig    `yaml:"security"`
	Honeypots    map[string]HoneypotConfig `yaml:"honeypots"`
	Ports        PortConfig        `yaml:"ports"`
	WebUI        WebUIConfig       `yaml:"web_ui"`
	Stealth      StealthConfig     `yaml:"stealth"`
	Alerts       AlertConfig       `yaml:"alerts"`
	Intelligence IntelligenceConfig `yaml:"intelligence"`
}

// DatabaseConfig contains database connection settings
type DatabaseConfig struct {
	Type         string                `yaml:"type"`      // clickhouse, timescaledb, elasticsearch
	Host         string                `yaml:"host"`
	Port         int                   `yaml:"port"`
	Username     string                `yaml:"username"`
	Password     string                `yaml:"password"`
	Database     string                `yaml:"database"`  // database name
	SSLMode      string                `yaml:"ssl_mode"`
	
	// Connection pooling
	PoolConfig   *PoolConfig           `yaml:"pool,omitempty"`
	
	// Read replicas for high availability
	ReadReplicas []*ReadReplicaConfig  `yaml:"read_replicas,omitempty"`
	
	// Retention policies
	RetentionPolicies []*RetentionPolicyConfig `yaml:"retention_policies,omitempty"`
	
	// Schema version tracking
	AutoMigrate  bool                  `yaml:"auto_migrate"`
	TargetVersion int                  `yaml:"target_version,omitempty"`
}

// PoolConfig defines connection pool settings
type PoolConfig struct {
	MaxOpenConns        int           `yaml:"max_open_conns"`
	MaxIdleConns        int           `yaml:"max_idle_conns"`
	ConnMaxLifetime     time.Duration `yaml:"conn_max_lifetime"`
	ConnMaxIdleTime     time.Duration `yaml:"conn_max_idle_time"`
	HealthCheckInterval time.Duration `yaml:"health_check_interval"`
	AcquireTimeout      time.Duration `yaml:"acquire_timeout"`
}

// ReadReplicaConfig defines a read replica configuration
type ReadReplicaConfig struct {
	Name     string            `yaml:"name"`
	Host     string            `yaml:"host"`
	Port     int               `yaml:"port"`
	Priority int               `yaml:"priority"`
	Weight   int               `yaml:"weight"`
	Region   string            `yaml:"region,omitempty"`
	Tags     map[string]string `yaml:"tags,omitempty"`
}

// RetentionPolicyConfig defines data retention settings
type RetentionPolicyConfig struct {
	ID              string              `yaml:"id"`
	Name            string              `yaml:"name"`
	Enabled         bool                `yaml:"enabled"`
	Honeypots       []string            `yaml:"honeypots,omitempty"`
	HotRetention    time.Duration       `yaml:"hot_retention"`
	WarmRetention   time.Duration       `yaml:"warm_retention"`
	ColdRetention   time.Duration       `yaml:"cold_retention"`
	ArchiveType     string              `yaml:"archive_type,omitempty"` // s3, gcs, filesystem
	ArchiveConfig   map[string]string   `yaml:"archive_config,omitempty"`
	CompressionType string              `yaml:"compression"`
	Schedule        string              `yaml:"schedule"`
}

// SecurityConfig contains security hardening options
type SecurityConfig struct {
	SandboxMode        string            `yaml:"sandbox_mode"`        // none, gvisor, kata, firejail
	EnableAppArmor     bool              `yaml:"enable_apparmor"`
	EnableSeccomp      bool              `yaml:"enable_seccomp"`
	ReadOnlyFilesystem bool              `yaml:"read_only_filesystem"`
	DropCapabilities   bool              `yaml:"drop_capabilities"`
	NoNewPrivileges    bool              `yaml:"no_new_privileges"`
	ResourceLimits     ResourceLimits    `yaml:"resource_limits"`
	NetworkIsolation   NetworkIsolation  `yaml:"network_isolation"`
	RuntimeSecurity    RuntimeSecurity   `yaml:"runtime_security"`
}

// RuntimeSecurity contains additional runtime security settings
type RuntimeSecurity struct {
	EnableSeccompProfile   bool     `yaml:"enable_seccomp_profile"`
	SeccompProfile         string   `yaml:"seccomp_profile"`          // custom, default, docker-default
	EnableLandlock         bool     `yaml:"enable_landlock"`          // Linux 5.13+
	EnableCgroupV2         bool     `yaml:"enable_cgroupv2"`          // Use cgroup v2 limits
	DisableSUIDBinaries    bool     `yaml:"disable_suid_binaries"`
	HideProcessInfo        bool     `yaml:"hide_process_info"`        // Hide other processes
	IsolateHostname        bool     `yaml:"isolate_hostname"`         // Unique hostname per container
}

// ResourceLimits contains container resource constraints
type ResourceLimits struct {
	MaxCPUPercent    float64 `yaml:"max_cpu_percent"`
	MaxMemoryMB      int64   `yaml:"max_memory_mb"`
	MaxStorageGB     int64   `yaml:"max_storage_gb"`
	MaxPids          int64   `yaml:"max_pids"`
	RestartAttempts  int     `yaml:"restart_attempts"`
}

// NetworkIsolation contains network security settings
type NetworkIsolation struct {
	SeparateNetworks     bool     `yaml:"separate_networks"`
	BlockOutbound        bool     `yaml:"block_outbound"`
	AllowedPorts         []int    `yaml:"allowed_ports"`
	RateLimitConnections int      `yaml:"rate_limit_connections"`
	EnableNAT            bool     `yaml:"enable_nat"`
	RandomizeMAC         bool     `yaml:"randomize_mac"`
}

// HoneypotConfig contains individual honeypot settings
type HoneypotConfig struct {
	Enabled       bool              `yaml:"enabled"`
	Port          int               `yaml:"port"`
	RiskLevel     string            `yaml:"risk_level"`  // low, medium, high, critical
	Sandbox       bool              `yaml:"sandbox"`
	Resources     HoneypotResources `yaml:"resources"`   // Per-honeypot resource limits
	Environment   map[string]string `yaml:"environment"`
	Stealth       HoneypotStealth   `yaml:"stealth"`
	CustomConfig  map[string]string `yaml:"custom_config"`  // TPOT config overrides
}

// HoneypotResources contains per-honeypot resource limits
type HoneypotResources struct {
	UseCustomLimits bool    `yaml:"use_custom_limits"`
	MaxCPUPercent   float64 `yaml:"max_cpu_percent"`
	MaxMemoryMB     int64   `yaml:"max_memory_mb"`
	MaxStorageGB    int64   `yaml:"max_storage_gb"`
	MaxPids         int64   `yaml:"max_pids"`
	MaxFileDescriptors int64 `yaml:"max_file_descriptors"`
}

// HoneypotStealth contains per-honeypot stealth settings
type HoneypotStealth struct {
	Enabled              bool   `yaml:"enabled"`
	FakeHostname         string `yaml:"fake_hostname"`
	FakeOS               string `yaml:"fake_os"`
	FakeKernel           string `yaml:"fake_kernel"`
	RandomizeSSHVersion  bool   `yaml:"randomize_ssh_version"`
	AddArtificialDelay   bool   `yaml:"add_artificial_delay"`
	DelayRangeMs         int    `yaml:"delay_range_ms"`
	FakeServices         []string `yaml:"fake_services"`
	BannerString         string   `yaml:"banner_string"`
}

// StealthConfig contains global stealth settings
type StealthConfig struct {
	Enabled                 bool     `yaml:"enabled"`
	HideDockerArtifacts     bool     `yaml:"hide_docker_artifacts"`
	FakeSystemd             bool     `yaml:"fake_systemd"`
	RandomizeResponseTime   bool     `yaml:"randomize_response_time"`
	MinResponseDelay        int      `yaml:"min_response_delay_ms"`
	MaxResponseDelay        int      `yaml:"max_response_delay_ms"`
	AddRealisticErrors      bool     `yaml:"add_realistic_errors"`
	ErrorRatePercent        int      `yaml:"error_rate_percent"`
	MasqueradeHostname      string   `yaml:"masquerade_hostname"`
	MasqueradeOS            string   `yaml:"masquerade_os"`
	BlockCommonProbes       bool     `yaml:"block_common_probes"`
	BlockedProbes           []string `yaml:"blocked_probes"`
}

// PortConfig contains port allocation settings
type PortConfig struct {
	BasePort       int  `yaml:"base_port"`
	AutoAllocate   bool `yaml:"auto_allocate"`
	WebUIPort      int  `yaml:"web_ui_port"`
	DatabasePort   int  `yaml:"database_port"`
}

// WebUIConfig contains web interface settings
type WebUIConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Port      int    `yaml:"port"`
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
	BindAddr  string `yaml:"bind_addr"`
	QPotIDAuth bool  `yaml:"qpot_id_auth"`  // Require QPot ID to access
}

var (
	configMu sync.RWMutex
	configs  = make(map[string]*Config)
)

// Default returns a default configuration for a new instance
func Default(instanceName string) *Config {
	homeDir, _ := os.UserHomeDir()
	dataPath := filepath.Join(homeDir, ".qpot", "instances", instanceName)
	configPath := filepath.Join(dataPath, "config.yaml")

	return &Config{
		InstanceName: instanceName,
		DataPath:     dataPath,
		ConfigPath:   configPath,
		Database: DatabaseConfig{
			Type:        "clickhouse",
			Host:        "localhost",
			Port:        9000,
			Username:    "qpot",
			Password:    "",
			Database:    "qpot",
			SSLMode:     "disable",
			AutoMigrate: true,
			PoolConfig: &PoolConfig{
				MaxOpenConns:        25,
				MaxIdleConns:        10,
				ConnMaxLifetime:     time.Hour,
				ConnMaxIdleTime:     30 * time.Minute,
				HealthCheckInterval: 5 * time.Minute,
				AcquireTimeout:      30 * time.Second,
			},
			RetentionPolicies: []*RetentionPolicyConfig{
				{
					ID:              "default",
					Name:            "Default 90-Day Retention",
					Enabled:         true,
					HotRetention:    90 * 24 * time.Hour,
					WarmRetention:   180 * 24 * time.Hour,
					ColdRetention:   365 * 24 * time.Hour,
					CompressionType: "gzip",
					Schedule:        "0 2 * * *",
				},
			},
		},
		Security: SecurityConfig{
			SandboxMode:        "gvisor",
			EnableAppArmor:     true,
			EnableSeccomp:      true,
			ReadOnlyFilesystem: true,
			DropCapabilities:   true,
			NoNewPrivileges:    true,
			ResourceLimits: ResourceLimits{
				MaxCPUPercent:   50.0,
				MaxMemoryMB:     512,
				MaxStorageGB:    10,
				MaxPids:         100,
				RestartAttempts: 3,
			},
			NetworkIsolation: NetworkIsolation{
				SeparateNetworks:     true,
				BlockOutbound:        false,
				AllowedPorts:         []int{},
				RateLimitConnections: 100,
				EnableNAT:            true,
				RandomizeMAC:         true,
			},
			RuntimeSecurity: RuntimeSecurity{
				EnableSeccompProfile: true,
				SeccompProfile:       "custom",
				EnableLandlock:       true,
				EnableCgroupV2:       true,
				DisableSUIDBinaries:  true,
				HideProcessInfo:      true,
				IsolateHostname:      true,
			},
		},
		Honeypots: map[string]HoneypotConfig{
			"cowrie": {
				Enabled:   true,
				Port:      2222,
				RiskLevel: "low",
				Sandbox:   true,
				Resources: HoneypotResources{
					UseCustomLimits: false,
					MaxCPUPercent:   30.0,
					MaxMemoryMB:     256,
					MaxPids:         50,
				},
				Stealth: HoneypotStealth{
					Enabled:             true,
					FakeHostname:        "webserver",
					FakeOS:              "Ubuntu 22.04.3 LTS",
					FakeKernel:          "5.15.0-91-generic",
					RandomizeSSHVersion: true,
					AddArtificialDelay:  true,
					DelayRangeMs:        50,
				},
			},
			"dionaea": {
				Enabled:   false,
				Port:      21,
				RiskLevel: "medium",
				Sandbox:   true,
				Resources: HoneypotResources{
					UseCustomLimits: true,
					MaxCPUPercent:   40.0,
					MaxMemoryMB:     384,
					MaxPids:         75,
				},
				Stealth: HoneypotStealth{
					Enabled:     true,
					FakeOS:      "Windows Server 2019",
					BannerString: "Microsoft FTP Service",
				},
			},
			"conpot": {
				Enabled:   false,
				Port:      102,
				RiskLevel: "low",
				Sandbox:   true,
				Resources: HoneypotResources{
					UseCustomLimits: false,
					MaxCPUPercent:   20.0,
					MaxMemoryMB:     128,
					MaxPids:         25,
				},
			},
			"endlessh": {
				Enabled:   true,
				Port:      2223,
				RiskLevel: "low",
				Sandbox:   false,
				Resources: HoneypotResources{
					UseCustomLimits: false,
					MaxCPUPercent:   5.0,
					MaxMemoryMB:     32,
					MaxPids:         10,
				},
			},
			"adbhoney": {
				Enabled:   false,
				Port:      5555,
				RiskLevel: "low",
				Sandbox:   true,
				Resources: HoneypotResources{
					UseCustomLimits: false,
					MaxCPUPercent:   15.0,
					MaxMemoryMB:     64,
					MaxPids:         20,
				},
			},
		},
		Ports: PortConfig{
			BasePort:     10000,
			AutoAllocate: true,
			WebUIPort:    8080,
			DatabasePort: 9000,
		},
		WebUI: WebUIConfig{
			Enabled:    true,
			Port:       8080,
			Username:   "admin",
			Password:   "",
			BindAddr:   "127.0.0.1",
			QPotIDAuth: true,
		},
		Stealth: StealthConfig{
			Enabled:               true,
			HideDockerArtifacts:   true,
			FakeSystemd:           true,
			RandomizeResponseTime: true,
			MinResponseDelay:      10,
			MaxResponseDelay:      200,
			AddRealisticErrors:    true,
			ErrorRatePercent:      2,
			MasqueradeHostname:    "prod-server",
			MasqueradeOS:          "Linux",
			BlockCommonProbes:    true,
			BlockedProbes: []string{
				"nmap",
				"masscan",
				"zgrab",
				"censys",
				"shodan",
			},
		},
		Alerts: AlertConfig{
			Enabled:   false,
			Threshold: 10, // 10 events per minute before alerting
			Honeypots: []string{}, // empty = alert on all honeypots
		},
		Intelligence: IntelligenceConfig{
			Enabled:          true,
			ATTCKDataPath:    filepath.Join(dataPath, "intelligence"),
			WorkerInterval:   15 * time.Minute,
			WorkerBatchSize:  500,
			InactivityWindow: 30 * time.Minute,
			FetchATTCK:       true,
		},
	}
}

// Load loads configuration for an instance
func Load(instanceName string) (*Config, error) {
	configMu.RLock()
	if cfg, ok := configs[instanceName]; ok {
		configMu.RUnlock()
		return cfg, nil
	}
	configMu.RUnlock()

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	configPath := filepath.Join(homeDir, ".qpot", "instances", instanceName, "config.yaml")
	
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return default config
			return Default(instanceName), nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Ensure paths are set
	if cfg.DataPath == "" {
		cfg.DataPath = filepath.Join(homeDir, ".qpot", "instances", instanceName)
	}
	if cfg.ConfigPath == "" {
		cfg.ConfigPath = configPath
	}

	configMu.Lock()
	configs[instanceName] = &cfg
	configMu.Unlock()

	return &cfg, nil
}

// Save saves configuration to disk
func Save(cfg *Config) error {
	// Ensure both the data directory and the config file's directory exist.
	if err := os.MkdirAll(cfg.DataPath, 0750); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}
	if configDir := filepath.Dir(cfg.ConfigPath); configDir != cfg.DataPath {
		if err := os.MkdirAll(configDir, 0750); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(cfg.ConfigPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	configMu.Lock()
	configs[cfg.InstanceName] = cfg
	configMu.Unlock()

	return nil
}

// EnableHoneypot enables a honeypot
func (c *Config) EnableHoneypot(name string) {
	if hp, ok := c.Honeypots[name]; ok {
		hp.Enabled = true
		c.Honeypots[name] = hp
	}
}

// DisableHoneypot disables a honeypot
func (c *Config) DisableHoneypot(name string) {
	if hp, ok := c.Honeypots[name]; ok {
		hp.Enabled = false
		c.Honeypots[name] = hp
	}
}

// GetEnabledHoneypots returns list of enabled honeypots
func (c *Config) GetEnabledHoneypots() []string {
	var enabled []string
	for name, hp := range c.Honeypots {
		if hp.Enabled {
			enabled = append(enabled, name)
		}
	}
	return enabled
}

// AllocatePort allocates a unique port for an instance.
// It uses FNV-1a hashing over the instance name for good distribution,
// and clamps the result to a sensible range (BasePort + 0..999 * 2).
func (c *Config) AllocatePort(basePort int) int {
	if !c.Ports.AutoAllocate {
		return basePort
	}

	// FNV-1a 32-bit hash for better distribution than summing ASCII values.
	const (
		fnvOffset32 uint32 = 2166136261
		fnvPrime32  uint32 = 16777619
	)
	h := fnvOffset32
	for _, ch := range c.InstanceName {
		h ^= uint32(ch)
		h *= fnvPrime32
	}
	// Map to [0, 500) and multiply by 2 to keep even spacing between instances.
	offset := int(h%500) * 2

	return c.Ports.BasePort + offset + basePort
}

// GetDockerComposePath returns path to docker-compose file
func (c *Config) GetDockerComposePath() string {
	return filepath.Join(c.DataPath, "docker-compose.yml")
}

// GetDatabasePath returns path to database data directory
func (c *Config) GetDatabasePath() string {
	return filepath.Join(c.DataPath, "db")
}

// GetHoneypotLogPath returns path to honeypot logs
func (c *Config) GetHoneypotLogPath(honeypot string) string {
	return filepath.Join(c.DataPath, "logs", honeypot)
}

// GetEffectiveResourceLimits returns effective resource limits for a honeypot
// Uses per-honeypot limits if configured, otherwise falls back to global limits
func (c *Config) GetEffectiveResourceLimits(honeypot string) ResourceLimits {
	hp, ok := c.Honeypots[honeypot]
	if !ok {
		return c.Security.ResourceLimits
	}

	if !hp.Resources.UseCustomLimits {
		return c.Security.ResourceLimits
	}

	return ResourceLimits{
		MaxCPUPercent:   hp.Resources.MaxCPUPercent,
		MaxMemoryMB:     hp.Resources.MaxMemoryMB,
		MaxStorageGB:    hp.Resources.MaxStorageGB,
		MaxPids:         hp.Resources.MaxPids,
		RestartAttempts: c.Security.ResourceLimits.RestartAttempts,
	}
}

// GetTPOTConfig generates TPOT-compatible configuration for a honeypot
func (c *Config) GetTPOTConfig(honeypot string) map[string]string {
	config := make(map[string]string)
	
	if hp, ok := c.Honeypots[honeypot]; ok {
		// Add TPOT-specific configs from custom config
		for k, v := range hp.CustomConfig {
			config[k] = v
		}
		
		// Add stealth configs
		if hp.Stealth.Enabled {
			config["STEALTH_ENABLED"] = "true"
			if hp.Stealth.FakeHostname != "" {
				config["FAKE_HOSTNAME"] = hp.Stealth.FakeHostname
			}
			if hp.Stealth.FakeOS != "" {
				config["FAKE_OS"] = hp.Stealth.FakeOS
			}
			if hp.Stealth.FakeKernel != "" {
				config["FAKE_KERNEL"] = hp.Stealth.FakeKernel
			}
		}
	}
	
	return config
}
