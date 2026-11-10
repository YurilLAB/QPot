// Package config manages QPot configuration
package config

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// AlertConfig configures webhook alerting when attack thresholds are crossed.
type AlertConfig struct {
	Enabled    bool     `yaml:"enabled"`
	WebhookURL string   `yaml:"webhook_url"` // Slack/Discord/generic webhook
	Threshold  int      `yaml:"threshold"`   // events per minute to trigger
	Honeypots  []string `yaml:"honeypots"`   // which honeypots to alert on (empty = all)
	// Cooldown debounces alerting: once an alert fires (webhook and/or response
	// hooks), further triggers are suppressed until the cooldown elapses. This
	// prevents alert fatigue and stops a sustained attack from re-running a
	// firewall/SOAR hook every minute. Zero means no cooldown (alert each
	// minute the threshold is exceeded). Default 5m.
	Cooldown time.Duration `yaml:"cooldown"`
}

// ResponseConfig configures local commands to execute when an alert
// threshold trips. Each entry runs through `sh -c` on Linux/macOS and
// `cmd /C` on Windows, with the following environment variables set so
// the command can act on the trigger:
//
//	QPOT_ID            - the QPot instance ID
//	QPOT_INSTANCE      - the human-readable instance name
//	QPOT_TOTAL_EVENTS  - events seen in the trigger window (last minute)
//	QPOT_UNIQUE_IPS    - distinct source IPs in the trigger window
//	QPOT_THRESHOLD     - the configured events-per-minute threshold that tripped
//	QPOT_TIMESTAMP     - RFC3339/UTC time of the trigger (matches the webhook)
//	QPOT_TOP_SOURCE_IP - the most active attacker IP, when known
//	QPOT_TOP_HONEYPOT  - the most-hit honeypot, when known
//
// Trigger-derived values (top source IP, top honeypot) are passed as
// environment variables, never interpolated into the command line, so an
// attacker-influenced value cannot inject shell syntax.
//
// This replaces the previous fictional "lockdown integration" with a
// real, generic mechanism — point it at any firewall, lockdown script,
// SOAR runbook, or custom shell pipeline.
type ResponseConfig struct {
	Enabled          bool             `yaml:"enabled"`
	OnAttackDetected []ResponseAction `yaml:"on_attack_detected"`
}

// ResponseAction is one command that fires on an attack-detected event.
type ResponseAction struct {
	Name    string        `yaml:"name"`    // free-form label for logs
	Command string        `yaml:"command"` // shell command line
	Timeout time.Duration `yaml:"timeout"` // per-command timeout (default 10s, hard cap 5min)
}

// IntelligenceConfig configures the threat intelligence subsystem.
type IntelligenceConfig struct {
	Enabled          bool          `yaml:"enabled"`
	ATTCKDataPath    string        `yaml:"attck_data_path"`   // where to cache downloaded ATT&CK data
	WorkerInterval   time.Duration `yaml:"worker_interval"`   // default 5min, at least 1min
	WorkerBatchSize  int           `yaml:"worker_batch_size"` // default 500
	InactivityWindow time.Duration `yaml:"inactivity_window"` // TTP session inactivity, default 30min
	FetchATTCK       bool          `yaml:"fetch_attck"`       // try to fetch latest from MITRE, default true
}

// The intelligence worker's cadence. Each run that finds new events tags
// them in the database (a ClickHouse mutation per batch), so the cadence
// trades how soon attack categories show against write load.
const (
	DefaultWorkerInterval = 5 * time.Minute
	// MinWorkerInterval is the shortest cadence a config may set.
	MinWorkerInterval = time.Minute
	// legacyWorkerInterval was the default before DefaultWorkerInterval.
	// Save writes the whole config, so every config saved then holds it:
	// it is read as that old default and moved to the new one.
	legacyWorkerInterval = 15 * time.Minute
)

// Config represents QPot configuration
type Config struct {
	InstanceName string                    `yaml:"instance_name"`
	QPotID       string                    `yaml:"qpot_id"`
	DataPath     string                    `yaml:"data_path"`
	ConfigPath   string                    `yaml:"config_path"`
	Database     DatabaseConfig            `yaml:"database"`
	Security     SecurityConfig            `yaml:"security"`
	Honeypots    map[string]HoneypotConfig `yaml:"honeypots"`
	Ports        PortConfig                `yaml:"ports"`
	WebUI        WebUIConfig               `yaml:"web_ui"`
	Stealth      StealthConfig             `yaml:"stealth"`
	Alerts       AlertConfig               `yaml:"alerts"`
	Intelligence IntelligenceConfig        `yaml:"intelligence"`
	Response     ResponseConfig            `yaml:"response"`
	Collector    CollectorConfig           `yaml:"collector"`
	AttackMap    AttackMapConfig           `yaml:"attack_map"`
	Canary       CanaryConfig              `yaml:"canary"`
	Cleanup      CleanupConfig             `yaml:"cleanup"`

	// hpMu guards concurrent access to the Honeypots map. The web server mutates
	// it (EnableHoneypot/DisableHoneypot on the POST /api/honeypots path) from one
	// goroutine while other request goroutines read it (GET handlers, Status,
	// Save's marshal) — without this, Go's runtime aborts with "concurrent map
	// read and map write" and the whole process dies. Always accessed via the
	// accessor methods below; unexported so YAML ignores it.
	hpMu sync.RWMutex
}

// GetHoneypotConfig returns the config for one honeypot under a read lock, so it
// is safe to call concurrently with EnableHoneypot/DisableHoneypot.
func (c *Config) GetHoneypotConfig(name string) (HoneypotConfig, bool) {
	c.hpMu.RLock()
	defer c.hpMu.RUnlock()
	hp, ok := c.Honeypots[name]
	return hp, ok
}

// SnapshotHoneypots returns a shallow copy of the Honeypots map taken under a
// read lock, so callers can range over it without racing a concurrent
// enable/disable. HoneypotConfig values are copied; the per-honeypot maps/slices
// inside them are shared (read-only by convention).
func (c *Config) SnapshotHoneypots() map[string]HoneypotConfig {
	c.hpMu.RLock()
	defer c.hpMu.RUnlock()
	out := make(map[string]HoneypotConfig, len(c.Honeypots))
	for k, v := range c.Honeypots {
		out[k] = v
	}
	return out
}

// AttackMapConfig places this sensor on the attack map: attacks are drawn
// from the attacker's country to here. Country is an ISO-3166-1 alpha-2 code
// (set by `qpot setup` from the host's time zone); Latitude/Longitude, when
// both non-zero, override the country's centroid.
type AttackMapConfig struct {
	Country   string  `yaml:"country,omitempty"`
	Latitude  float64 `yaml:"latitude,omitempty"`
	Longitude float64 `yaml:"longitude,omitempty"`
}

// CollectorConfig configures the Vector log collector.
type CollectorConfig struct {
	// GeoIPDBPath is the path, inside the collector container, to a MaxMind
	// GeoLite2 .mmdb file. When empty, GeoIP enrichment is disabled and the
	// Vector pipeline omits the enrichment table entirely — otherwise Vector
	// refuses to start because the enrichment-table file does not exist.
	GeoIPDBPath string `yaml:"geoip_db_path"`

	// IngestSuricata controls whether the Vector pipeline also ingests
	// Suricata's EVE JSON (/data/suricata/log/eve.json) — T-Pot's network IDS.
	// When true (the default), Suricata alert events flow into the same events
	// store as honeypot logs, so they appear in the dashboards / attack map /
	// Kibana. Harmless when Suricata is not deployed: the file source simply
	// matches nothing. Set false to ignore Suricata even if present.
	IngestSuricata bool `yaml:"ingest_suricata"`

	// IngestP0f ingests p0f's passive OS-fingerprint log
	// (/data/p0f/log/p0f.json) as events tagged honeypot="p0f", with the
	// detected OS in the command/metadata so dashboards can show attacker OS
	// distribution. Default true; harmless when p0f is not deployed.
	IngestP0f bool `yaml:"ingest_p0f"`

	// IngestFatt ingests fatt's network-fingerprint log
	// (/data/fatt/log/fatt.log) as events tagged honeypot="fatt", with the
	// JA3/HASSH fingerprints in metadata. Default true; harmless when fatt is
	// not deployed.
	IngestFatt bool `yaml:"ingest_fatt"`
}

// CleanupConfig bounds what the instance keeps on disk outside its database:
// the honeypots' logs and captured files (downloads, session recordings,
// uploads) and the collector's backup copy of every event. Each honeypot's
// folder is also held under its storage limit (security.resource_limits
// .max_storage_gb, or the honeypot's own). See internal/cleanup.
type CleanupConfig struct {
	// Enabled turns automatic cleanup on (hourly, and soon after start).
	// Unset means on: configs written before cleanup existed get it too.
	Enabled *bool `yaml:"enabled,omitempty"`
	// MaxAgeDays: captured files, rotated logs and backup days older than
	// this are deleted. Default 30.
	MaxAgeDays int `yaml:"max_age_days"`
	// MaxLogMB: a honeypot log the collector reads is emptied once it is
	// larger than this, while the collector runs (its events are already in
	// the database and the backup). Default 256.
	MaxLogMB int64 `yaml:"max_log_mb"`
	// MaxBackupMB bounds the collector's backup folder; its oldest days go
	// first. Default 2048.
	MaxBackupMB int64 `yaml:"max_backup_mb"`
}

// Cleanup defaults and the bounds the web UI and config accept.
const (
	DefaultCleanupMaxAgeDays  = 30
	DefaultCleanupMaxLogMB    = 256
	DefaultCleanupMaxBackupMB = 2048
	MaxCleanupAgeDays         = 3650
	MaxCleanupMB              = 1 << 24 // 16 TiB in MB
)

// On reports whether automatic cleanup runs.
func (c CleanupConfig) On() bool { return c.Enabled == nil || *c.Enabled }

// clamp fills unset or out-of-range values with the defaults.
func (c *CleanupConfig) clamp() {
	if c.MaxAgeDays <= 0 || c.MaxAgeDays > MaxCleanupAgeDays {
		c.MaxAgeDays = DefaultCleanupMaxAgeDays
	}
	if c.MaxLogMB <= 0 || c.MaxLogMB > MaxCleanupMB {
		c.MaxLogMB = DefaultCleanupMaxLogMB
	}
	if c.MaxBackupMB <= 0 || c.MaxBackupMB > MaxCleanupMB {
		c.MaxBackupMB = DefaultCleanupMaxBackupMB
	}
}

// CanaryConfig controls the canary (honeytoken) subsystem: decoy artifacts
// planted in the operator's environment that alert on monitored beacon requests
// or watched values in captured event fields. File reads and direct AWS use are
// not monitored; an observed trip does not by itself establish malicious intent.
type CanaryConfig struct {
	// Enabled turns the subsystem on. When true the web server serves the
	// public beacon endpoint (/c/<token>) and the management API; the
	// intelligence worker also watches captured sessions for planted
	// credential values. Default true.
	Enabled bool `yaml:"enabled"`

	// BaseURL is the public origin under which beacon URLs are minted, e.g.
	// "https://assets.example.com". It must point at wherever this QPot web
	// server is reachable so a planted token actually phones home. When empty,
	// URLs are rendered path-only (/c/<token>) and the operator is warned.
	BaseURL string `yaml:"base_url"`

	// Decoy selects the response served from /c/<token> so the beacon does not
	// look like an alerting endpoint:
	//   "notfound" (default) — a plain 404, indistinguishable from a dead link
	//   "pixel"              — a 1x1 transparent GIF (for <img>/document beacons)
	// Any other value falls back to "notfound".
	Decoy string `yaml:"decoy"`

	// MaxTrips bounds the retained trip history in canaries.json. Default 500.
	MaxTrips int `yaml:"max_trips"`
}

// DatabaseConfig contains database connection settings
type DatabaseConfig struct {
	Type     string `yaml:"type"` // clickhouse, timescaledb, elasticsearch
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Database string `yaml:"database"` // database name
	SSLMode  string `yaml:"ssl_mode"`

	// Connection pooling
	PoolConfig *PoolConfig `yaml:"pool,omitempty"`

	// Read replicas for high availability
	ReadReplicas []*ReadReplicaConfig `yaml:"read_replicas,omitempty"`

	// Retention policies
	RetentionPolicies []*RetentionPolicyConfig `yaml:"retention_policies,omitempty"`

	// Schema version tracking
	AutoMigrate   bool `yaml:"auto_migrate"`
	TargetVersion int  `yaml:"target_version,omitempty"`
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
	ID              string            `yaml:"id"`
	Name            string            `yaml:"name"`
	Enabled         bool              `yaml:"enabled"`
	Honeypots       []string          `yaml:"honeypots,omitempty"`
	HotRetention    time.Duration     `yaml:"hot_retention"`
	WarmRetention   time.Duration     `yaml:"warm_retention"`
	ColdRetention   time.Duration     `yaml:"cold_retention"`
	ArchiveType     string            `yaml:"archive_type,omitempty"` // s3, gcs, filesystem
	ArchiveConfig   map[string]string `yaml:"archive_config,omitempty"`
	CompressionType string            `yaml:"compression"`
	Schedule        string            `yaml:"schedule"`
}

// SecurityConfig contains security hardening options
type SecurityConfig struct {
	SandboxMode        string           `yaml:"sandbox_mode"`     // none, gvisor, kata
	SandboxFallback    string           `yaml:"sandbox_fallback"` // deny (default), docker (non-executing emulators only)
	EnableAppArmor     bool             `yaml:"enable_apparmor"`
	EnableSeccomp      bool             `yaml:"enable_seccomp"`
	ReadOnlyFilesystem bool             `yaml:"read_only_filesystem"`
	DropCapabilities   bool             `yaml:"drop_capabilities"`
	NoNewPrivileges    bool             `yaml:"no_new_privileges"`
	ResourceLimits     ResourceLimits   `yaml:"resource_limits"`
	NetworkIsolation   NetworkIsolation `yaml:"network_isolation"`
	RuntimeSecurity    RuntimeSecurity  `yaml:"runtime_security"`
}

// RuntimeSecurity contains additional runtime security settings
type RuntimeSecurity struct {
	EnableSeccompProfile bool   `yaml:"enable_seccomp_profile"`
	SeccompProfile       string `yaml:"seccomp_profile"` // custom, default, docker-default
	EnableLandlock       bool   `yaml:"enable_landlock"` // Linux 5.13+
	EnableCgroupV2       bool   `yaml:"enable_cgroupv2"` // Use cgroup v2 limits
	DisableSUIDBinaries  bool   `yaml:"disable_suid_binaries"`
	HideProcessInfo      bool   `yaml:"hide_process_info"` // Hide other processes
	IsolateHostname      bool   `yaml:"isolate_hostname"`  // Unique hostname per container
}

// ResourceLimits contains container resource constraints
type ResourceLimits struct {
	MaxCPUPercent   float64 `yaml:"max_cpu_percent"`
	MaxMemoryMB     int64   `yaml:"max_memory_mb"`
	MaxStorageGB    int64   `yaml:"max_storage_gb"` // each honeypot folder's limit (storage cleanup)
	MaxPids         int64   `yaml:"max_pids"`
	RestartAttempts int     `yaml:"restart_attempts"`
}

// NetworkIsolation contains network security settings
type NetworkIsolation struct {
	SeparateNetworks bool `yaml:"separate_networks"`
	// BlockOutbound stops honeypots from opening any outbound connection
	// (DNS to the host's resolvers excepted). Honeypots that fetch what an
	// attacker asks for (cowrie's wget/curl) then capture nothing.
	BlockOutbound bool `yaml:"block_outbound"`
	// AllowPrivateEgress turns the egress guard off. By default honeypots
	// cannot open connections to private, loopback, link-local (cloud
	// metadata), CGNAT or multicast addresses, or to the docker host itself;
	// public destinations stay reachable (see internal/netguard).
	AllowPrivateEgress bool `yaml:"allow_private_egress"`
	RandomizeMAC       bool `yaml:"randomize_mac"`
}

// HoneypotConfig contains individual honeypot settings
type HoneypotConfig struct {
	Enabled      bool              `yaml:"enabled"`
	Port         int               `yaml:"port"`
	RiskLevel    string            `yaml:"risk_level"` // low, medium, high, critical
	Sandbox      bool              `yaml:"sandbox"`
	Resources    HoneypotResources `yaml:"resources"` // Per-honeypot resource limits
	Environment  map[string]string `yaml:"environment"`
	Stealth      HoneypotStealth   `yaml:"stealth"`
	CustomConfig map[string]string `yaml:"custom_config"` // TPOT config overrides
	// DeviceProfile records the automatic device selection independently of a
	// user pin, so catalog updates and removing a pin keep the same device.
	DeviceProfile ResolvedDeviceProfile `yaml:"device_profile,omitempty"`
}

// HoneypotResources contains per-honeypot resource limits
type HoneypotResources struct {
	UseCustomLimits    bool    `yaml:"use_custom_limits"`
	MaxCPUPercent      float64 `yaml:"max_cpu_percent"`
	MaxMemoryMB        int64   `yaml:"max_memory_mb"`
	MaxStorageGB       int64   `yaml:"max_storage_gb"` // 0: the global limit (storage cleanup)
	MaxPids            int64   `yaml:"max_pids"`
	MaxFileDescriptors int64   `yaml:"max_file_descriptors"`
}

// HoneypotStealth contains per-honeypot stealth settings
type HoneypotStealth struct {
	Enabled             bool     `yaml:"enabled"`
	FakeHostname        string   `yaml:"fake_hostname"`
	FakeOS              string   `yaml:"fake_os"`
	FakeKernel          string   `yaml:"fake_kernel"`
	RandomizeSSHVersion bool     `yaml:"randomize_ssh_version"`
	AddArtificialDelay  bool     `yaml:"add_artificial_delay"`
	DelayRangeMs        int      `yaml:"delay_range_ms"`
	FakeServices        []string `yaml:"fake_services"`
	BannerString        string   `yaml:"banner_string"`
	// CredentialTemplate names a realistic login persona (see credential
	// templates) for honeypots that authenticate users (Cowrie). Empty means
	// QPot auto-selects one per instance from the QPot ID, so each deployment
	// looks like a distinct real system.
	CredentialTemplate string `yaml:"credential_template"`
}

// StealthConfig contains global stealth settings
type StealthConfig struct {
	Enabled               bool     `yaml:"enabled"`
	HideDockerArtifacts   bool     `yaml:"hide_docker_artifacts"`
	FakeSystemd           bool     `yaml:"fake_systemd"`
	RandomizeResponseTime bool     `yaml:"randomize_response_time"`
	MinResponseDelay      int      `yaml:"min_response_delay_ms"`
	MaxResponseDelay      int      `yaml:"max_response_delay_ms"`
	AddRealisticErrors    bool     `yaml:"add_realistic_errors"`
	ErrorRatePercent      int      `yaml:"error_rate_percent"`
	MasqueradeHostname    string   `yaml:"masquerade_hostname"`
	MasqueradeOS          string   `yaml:"masquerade_os"`
	BlockCommonProbes     bool     `yaml:"block_common_probes"`
	BlockedProbes         []string `yaml:"blocked_probes"`
}

// PortConfig contains port allocation settings
type PortConfig struct {
	BasePort     int  `yaml:"base_port"`
	AutoAllocate bool `yaml:"auto_allocate"`
	WebUIPort    int  `yaml:"web_ui_port"`
	DatabasePort int  `yaml:"database_port"`
}

// WebUIConfig contains web interface settings
type WebUIConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Port       int    `yaml:"port"`
	Username   string `yaml:"username"`
	Password   string `yaml:"password"`
	BindAddr   string `yaml:"bind_addr"`
	QPotIDAuth bool   `yaml:"qpot_id_auth"` // Require QPot ID to access
}

var (
	configMu sync.RWMutex
	configs  = make(map[string]*Config)
)

// userHomeOrFallback returns the user's home directory. When that lookup
// fails, it falls back to UserConfigDir (XDG-aware on Linux,
// %AppData% on Windows, ~/Library on macOS) and finally to the current
// working directory. We never want to return "" because that produces
// relative paths in DataPath, which then refuse to bind-mount in Docker.
func userHomeOrFallback() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return home
	}
	if cfgDir, err := os.UserConfigDir(); err == nil && cfgDir != "" {
		return cfgDir
	}
	if cwd, err := os.Getwd(); err == nil && cwd != "" {
		return cwd
	}
	return "."
}

// Default returns a default configuration for a new instance.
// If os.UserHomeDir fails (e.g. on stripped-down containers where neither
// $HOME nor /etc/passwd is set) we fall back to the OS-specific user
// config directory, and ultimately to the current working directory, so
// the returned Config always has an absolute, usable DataPath rather
// than relative paths under "/.qpot/...".
func Default(instanceName string) *Config {
	homeDir := userHomeOrFallback()
	dataPath := filepath.Join(homeDir, ".qpot", "instances", instanceName)
	configPath := filepath.Join(dataPath, "config.yaml")

	return &Config{
		InstanceName: instanceName,
		DataPath:     dataPath,
		ConfigPath:   configPath,
		Database: DatabaseConfig{
			Type:     "clickhouse",
			Host:     "localhost",
			Port:     9000,
			Username: "qpot",
			// Random per instance (persisted in config.yaml on create). An empty
			// password let anything that could reach the database log in.
			// rand.Text is base32 ([A-Z2-7]), safe unquoted in YAML and DSNs.
			Password:    rand.Text(),
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
			SandboxFallback:    "deny",
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
				SeparateNetworks: true,
				RandomizeMAC:     true,
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
					Enabled: true,
					// Identity (hostname / OS / kernel / SSH version) is left
					// unset on purpose: QPot derives it per-instance from the
					// QPot ID so each deployment is unique. Hardcoding a shared
					// default here would recreate the exact static-fingerprint
					// problem that lets scanners spot stock T-Pot at a glance.
					// Set these explicitly only to pin a specific identity.
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
					Enabled:      true,
					FakeOS:       "Windows Server 2019",
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
			// All other supported honeypots, disabled by default. Enable with
			// `qpot honeypot enable <name>`. The port shown is the honeypot's
			// primary service; its full port set comes from the deploy profile.
			"heralding":      {Enabled: false, Port: 22, RiskLevel: "high", Sandbox: true},
			"mailoney":       {Enabled: false, Port: 25, RiskLevel: "medium", Sandbox: true},
			"ddospot":        {Enabled: false, Port: 53, RiskLevel: "low", Sandbox: true},
			"ciscoasa":       {Enabled: false, Port: 8443, RiskLevel: "medium", Sandbox: true},
			"citrixhoneypot": {Enabled: false, Port: 443, RiskLevel: "high", Sandbox: true},
			"elasticpot":     {Enabled: false, Port: 9200, RiskLevel: "medium", Sandbox: true},
			"ipphoney":       {Enabled: false, Port: 631, RiskLevel: "low", Sandbox: true},
			"medpot":         {Enabled: false, Port: 2575, RiskLevel: "low", Sandbox: true},
			"dicompot":       {Enabled: false, Port: 11112, RiskLevel: "low", Sandbox: true},
			"honeyaml":       {Enabled: false, Port: 8080, RiskLevel: "low", Sandbox: true},
			"tanner":         {Enabled: false, Port: 80, RiskLevel: "medium", Sandbox: true},
			"redishoneypot":  {Enabled: false, Port: 6379, RiskLevel: "low", Sandbox: true},
			"refrigeration":  defaultRefrigerationConfig(),
			// Newer / 2024-2026 honeypots. beelzebub and galah are LLM-backed and
			// need an Ollama/API provider configured to be fully convincing.
			"beelzebub":  {Enabled: false, Port: 22, RiskLevel: "high", Sandbox: true},
			"galah":      {Enabled: false, Port: 8080, RiskLevel: "medium", Sandbox: true},
			"go-pot":     {Enabled: false, Port: 8080, RiskLevel: "low", Sandbox: true},
			"h0neytr4p":  {Enabled: false, Port: 80, RiskLevel: "medium", Sandbox: true},
			"hellpot":    {Enabled: false, Port: 8080, RiskLevel: "low", Sandbox: true},
			"log4pot":    {Enabled: false, Port: 8080, RiskLevel: "high", Sandbox: true},
			"miniprint":  {Enabled: false, Port: 9100, RiskLevel: "low", Sandbox: true},
			"sentrypeer": {Enabled: false, Port: 5060, RiskLevel: "medium", Sandbox: true},
			"wordpot":    {Enabled: false, Port: 80, RiskLevel: "medium", Sandbox: true},
			// High-interaction SSH proxy (HiFi). Disabled by default and marked
			// CRITICAL: enabling it stands up REAL OpenSSH backends (genuine code
			// execution) behind a transparent L4 broker, which is what fully
			// closes the protocol-fingerprinting gap. Only run it with the
			// isolation runtime (gVisor/Kata) and the egress lock the compose
			// renderer applies. custom_config["backends"] sets the backend count
			// (default 2). See doc/ssh-hifi-proxy.md.
			"ssh-proxy": {
				Enabled:   false,
				Port:      22,
				RiskLevel: "critical",
				Sandbox:   true,
				Resources: HoneypotResources{
					UseCustomLimits: true,
					MaxCPUPercent:   50.0,
					MaxMemoryMB:     512,
					MaxPids:         256,
				},
				Stealth: HoneypotStealth{Enabled: true},
				CustomConfig: map[string]string{
					"backends": "2",
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
			BlockCommonProbes:     true,
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
			Threshold: 10,              // 10 events per minute before alerting
			Honeypots: []string{},      // empty = alert on all honeypots
			Cooldown:  5 * time.Minute, // debounce: at most one alert per 5 min
		},
		Intelligence: IntelligenceConfig{
			Enabled:          true,
			ATTCKDataPath:    filepath.Join(dataPath, "intelligence"),
			WorkerInterval:   DefaultWorkerInterval,
			WorkerBatchSize:  500,
			InactivityWindow: 30 * time.Minute,
			FetchATTCK:       true,
		},
		Collector: CollectorConfig{
			// Ingest T-Pot's NSM sensors (Suricata IDS, p0f OS fingerprints,
			// fatt network fingerprints) by default so their data shows up in
			// QPot when those sensors are deployed (no-op otherwise).
			IngestSuricata: true,
			IngestP0f:      true,
			IngestFatt:     true,
		},
		Canary: CanaryConfig{
			Enabled:  true,
			Decoy:    "notfound",
			MaxTrips: 500,
		},
		Cleanup: CleanupConfig{
			MaxAgeDays:  DefaultCleanupMaxAgeDays,
			MaxLogMB:    DefaultCleanupMaxLogMB,
			MaxBackupMB: DefaultCleanupMaxBackupMB,
		},
	}
}

// ValidateInstanceName rejects names that are not a single safe path component.
// The instance name is interpolated into a filesystem path
// (~/.qpot/instances/<name>/...), so a name containing a path separator or ".."
// would escape the instances directory (e.g. "../../etc"). This is the defense
// boundary for every command that resolves an instance by name.
func ValidateInstanceName(name string) error {
	if name == "" {
		return fmt.Errorf("instance name must not be empty")
	}
	if name == "." || name == ".." || name != filepath.Base(name) ||
		strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return fmt.Errorf("invalid instance name %q: must be a single path component without separators or '..'", name)
	}
	return nil
}

// Load loads configuration for an instance
func Load(instanceName string) (*Config, error) {
	if err := ValidateInstanceName(instanceName); err != nil {
		return nil, err
	}

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

	data, err := ReadFile(configPath, 0)
	if err != nil {
		if os.IsNotExist(err) {
			// Return default config
			return Default(instanceName), nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg, err := Parse(data, configPath)
	if err != nil {
		return nil, err
	}

	// qpot.id is authoritative, as it is in loadInstance. A legacy YAML file
	// may omit the ID or retain an older credential after rotation. Parse only
	// validates profiles; any missing selection is resolved on the next Save,
	// after this runtime identity is known.
	idPath := filepath.Join(filepath.Dir(configPath), "qpot.id")
	idData, idErr := os.ReadFile(idPath)
	switch {
	case idErr == nil:
		id := strings.TrimSpace(string(idData))
		if !qpotIDPattern.MatchString(id) {
			return nil, fmt.Errorf("invalid QPot ID file %s; restore this instance's saved identity", idPath)
		}
		cfg.QPotID = id
	case !os.IsNotExist(idErr):
		return nil, fmt.Errorf("failed to read QPot ID file: %w", idErr)
	}

	configMu.Lock()
	configs[instanceName] = cfg
	configMu.Unlock()

	return cfg, nil
}

// Parse reads the contents of an instance's config file as Load does,
// configPath being where they were read from (its folder is the data path
// when the file names none), but leaves Load's cache of loaded configs alone:
// a process that keeps running while the CLI changes the file (qpot serve)
// reads what the file says now with it.
func Parse(data []byte, configPath string) (*Config, error) {
	instanceName := filepath.Base(filepath.Dir(configPath))
	// yaml.Unmarshal leaves what the file omits as it finds it, so the QPot ID
	// check starts on: a file without qpot_id_auth (hand-written, or trimmed
	// to the settings that matter) otherwise served the API with no
	// credential, and with no bind_addr on every interface. A file that sets
	// them is honoured; an empty bind address means loopback.
	cfg := Config{WebUI: WebUIConfig{QPotIDAuth: true}}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	// New services remain disabled on upgrade, but must be available to enable
	// from the same catalog and settings API as services in a fresh instance.
	if cfg.Honeypots == nil {
		cfg.Honeypots = map[string]HoneypotConfig{}
	}
	if _, exists := cfg.Honeypots["refrigeration"]; !exists {
		cfg.Honeypots["refrigeration"] = defaultRefrigerationConfig()
	}
	if strings.TrimSpace(cfg.WebUI.BindAddr) == "" {
		cfg.WebUI.BindAddr = "127.0.0.1"
	}

	if err := cfg.checkIdentifiers(); err != nil {
		return nil, fmt.Errorf("invalid config file %s: %w", configPath, err)
	}

	// Ensure paths are set
	if cfg.DataPath == "" {
		cfg.DataPath = filepath.Dir(configPath)
	}
	if cfg.ConfigPath == "" {
		cfg.ConfigPath = configPath
	}

	// yaml.Unmarshal does not merge defaults, so a hand-written config that
	// enables intelligence but omits the worker tunables would leave them at
	// the zero value. A zero WorkerInterval panics time.NewTicker, and a zero
	// WorkerBatchSize makes the classifier a silent no-op. Clamp them here.
	switch iv := cfg.Intelligence.WorkerInterval; {
	case iv <= 0, iv == legacyWorkerInterval:
		cfg.Intelligence.WorkerInterval = DefaultWorkerInterval
	case iv < MinWorkerInterval:
		cfg.Intelligence.WorkerInterval = MinWorkerInterval
	}
	if cfg.Intelligence.WorkerBatchSize <= 0 {
		cfg.Intelligence.WorkerBatchSize = 500
	}
	if cfg.Intelligence.InactivityWindow <= 0 {
		cfg.Intelligence.InactivityWindow = 30 * time.Minute
	}
	cfg.Cleanup.clamp()

	// Clamp the global resource limits the same way. yaml.Unmarshal leaves any
	// omitted field at its zero value, so a hand-written or older config that
	// drops (or partially fills) the `security:` section would otherwise render
	// `memory: 0M` / `cpus: '0'` into the compose - which Docker REJECTS
	// ("Minimum memory limit allowed is 6MB"), so every honeypot fails to start.
	// Restore the secure-by-default limits for any unset field so the sandbox
	// guarantees hold and the stack still comes up. (MaxPids is rendered only
	// when non-zero, so 0 = unlimited is acceptable, but we still apply the
	// default to keep the PID cap a sandbox has by default.)
	rl := &cfg.Security.ResourceLimits
	if rl.MaxCPUPercent <= 0 {
		rl.MaxCPUPercent = 50.0
	}
	if rl.MaxMemoryMB <= 0 {
		rl.MaxMemoryMB = 512
	}
	if rl.MaxStorageGB <= 0 {
		rl.MaxStorageGB = 10
	}
	if rl.MaxPids <= 0 {
		rl.MaxPids = 100
	}
	if rl.RestartAttempts <= 0 {
		rl.RestartAttempts = 3
	}

	// A config that omits the security section also leaves SandboxMode empty.
	// Restore the secure declared policy. Availability is checked at deployment;
	// an absent requested runtime must never silently select ordinary Docker.
	if cfg.Security.SandboxMode == "" {
		cfg.Security.SandboxMode = "gvisor"
	}
	if cfg.Security.SandboxFallback == "" {
		cfg.Security.SandboxFallback = "deny"
	}
	// Resolve omitted legacy global limits before checking the finite caps of
	// an enabled HiFi cell. Explicit invalid custom overrides remain errors.
	if err := ValidateSSHEnvironment(&cfg); err != nil {
		return nil, fmt.Errorf("invalid config file %s: %w", configPath, err)
	}

	if err := cfg.resolveDeviceProfiles(false); err != nil {
		return nil, fmt.Errorf("invalid config file %s: %w", configPath, err)
	}

	// Surface obvious misconfigurations at load time. We log instead of
	// returning an error so a broken sub-section (e.g. a bad alert webhook
	// URL) doesn't prevent QPot from starting and serving honeypots —
	// it's a defence-in-depth principle: the honeypot platform itself
	// must keep running even when integrations are misconfigured.
	for _, msg := range cfg.Validate() {
		slog.Warn("Config validation", "instance", instanceName, "warning", msg)
	}
	return &cfg, nil
}

var (
	qpotIDPattern = regexp.MustCompile(`^qp_[a-z2-7]{24}$`)
	// instanceNamePattern is the instance name the CLI accepts (qpot setup,
	// qpot instance create): a single path component, a docker name.
	instanceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$`)
	// honeypotNamePattern covers every honeypot QPot has: a compose service
	// name, a network name and a directory under honeypots/.
	honeypotNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

// knownDatabaseTypes are the backends database.New opens ("" leaves the
// instance without a database service).
var knownDatabaseTypes = map[string]bool{"": true, "clickhouse": true, "timescaledb": true, "elasticsearch": true}

// knownRiskLevels are the risk levels the UI shows ("" is unset).
var knownRiskLevels = map[string]bool{"": true, "low": true, "medium": true, "high": true, "critical": true}

// checkIdentifiers refuses the values that are written into
// docker-compose.yml, file paths and the web UI as they are: the instance
// name, the database type and the honeypot names (container and service
// names, bind-mount paths, a comment), the data path (bind mounts) and the
// risk levels (the dashboard). A newline in one of them added a service of
// its choosing to the compose file. Risk levels are matched without regard
// to case and stored in lower case.
func (c *Config) checkIdentifiers() error {
	if c.InstanceName != "" && !instanceNamePattern.MatchString(c.InstanceName) {
		return fmt.Errorf("instance_name %q: use 1-32 letters, digits, hyphens or underscores", c.InstanceName)
	}
	if !knownDatabaseTypes[c.Database.Type] {
		return fmt.Errorf("database.type %q: use clickhouse, timescaledb or elasticsearch", c.Database.Type)
	}
	for _, p := range []struct{ key, value string }{
		{"data_path", c.DataPath}, {"config_path", c.ConfigPath},
		{"collector.geoip_db_path", c.Collector.GeoIPDBPath},
	} {
		if strings.ContainsFunc(p.value, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return fmt.Errorf("%s %q contains a control character", p.key, p.value)
		}
	}
	for name, hp := range c.Honeypots {
		if !honeypotNamePattern.MatchString(name) {
			return fmt.Errorf("honeypot name %q: use lower-case letters, digits and hyphens", name)
		}
		risk := strings.ToLower(strings.TrimSpace(hp.RiskLevel))
		if !knownRiskLevels[risk] {
			return fmt.Errorf("honeypots.%s.risk_level %q: use low, medium, high or critical", name, hp.RiskLevel)
		}
		if risk != hp.RiskLevel {
			hp.RiskLevel = risk
			c.Honeypots[name] = hp
		}
	}
	return nil
}

// Validate returns a slice of human-readable warnings for any
// misconfigurations it can spot statically. Empty slice means the
// config looks sane. The intent is to fail loud, not to fail closed:
// callers should log the warnings rather than refuse to start.
func (c *Config) Validate() []string {
	var warnings []string

	// Response hooks: enabled but with no actions configured is almost
	// certainly a typo or a half-finished migration.
	if c.Response.Enabled && len(c.Response.OnAttackDetected) == 0 {
		warnings = append(warnings, "response.enabled=true but response.on_attack_detected is empty; nothing will fire")
	}
	for i, action := range c.Response.OnAttackDetected {
		if strings.TrimSpace(action.Command) == "" {
			warnings = append(warnings, fmt.Sprintf("response.on_attack_detected[%d] has empty command", i))
		}
	}

	// Cluster TLS: enabling encryption without cert/key is the trap that
	// previously caused silent fallback to plain HTTP.
	// (Cluster config lives in a separate package, so we only catch the
	// hint we have here — see internal/cluster for the runtime check.)

	// Alerts: enabled webhook with no URL is a no-op.
	if c.Alerts.Enabled && strings.TrimSpace(c.Alerts.WebhookURL) == "" &&
		!c.Response.Enabled {
		warnings = append(warnings, "alerts.enabled=true but no webhook_url and no response hooks; no alerting will happen")
	}

	return warnings
}

// Save saves configuration to disk. Device-profile migration is adopted only
// after the complete file has been written and atomically activated.
func Save(cfg *Config) error {
	// Serialize saves and honeypot setters through activation. Otherwise a
	// slower save could replace a newer one, or adopting its resolved profile
	// could overwrite a concurrent honeypot change. Other config fields are
	// immutable after startup.
	cfg.hpMu.Lock()
	defer cfg.hpMu.Unlock()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	// Decode into a fresh config rather than copying the live RWMutex. Unlike
	// Parse, this snapshot applies no load-time defaults or other migrations.
	var pending Config
	if err := yaml.Unmarshal(data, &pending); err != nil {
		return fmt.Errorf("failed to copy config for save: %w", err)
	}
	if err := ValidateSSHEnvironment(&pending); err != nil {
		return fmt.Errorf("invalid SSH environment: %w", err)
	}
	if err := pending.resolveDeviceProfiles(true); err != nil {
		return fmt.Errorf("invalid device profile: %w", err)
	}
	data, err = yaml.Marshal(&pending)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	// Ensure both the data directory and the config file's directory exist.
	if err := os.MkdirAll(cfg.DataPath, 0750); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}
	if configDir := filepath.Dir(cfg.ConfigPath); configDir != cfg.DataPath {
		if err := os.MkdirAll(configDir, 0750); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}
	}

	if err := writeConfigFile(cfg.ConfigPath, data); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	if hp, ok := pending.Honeypots["conpot"]; ok {
		current := cfg.Honeypots["conpot"]
		current.DeviceProfile = hp.DeviceProfile
		cfg.Honeypots["conpot"] = current
	}

	configMu.Lock()
	configs[cfg.InstanceName] = cfg
	configMu.Unlock()

	return nil
}

// writeConfigFile keeps the previous file intact on staging or activation
// failure. The same-directory temporary file is private from creation onward.
func writeConfigFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".qpot-config-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return renameFile(tmp.Name(), path)
}

// EnableHoneypot enables a honeypot
//
// A config written before the honeypot existed has no entry for it (Load does
// not merge defaults), so the default entry is added; otherwise enabling it
// reported success but changed nothing. Unknown names are left untouched.
func (c *Config) EnableHoneypot(name string) {
	c.hpMu.Lock()
	defer c.hpMu.Unlock()
	hp, ok := c.Honeypots[name]
	if !ok {
		def, known := Default(c.InstanceName).Honeypots[name]
		if !known {
			return
		}
		hp = def
		if c.Honeypots == nil {
			c.Honeypots = make(map[string]HoneypotConfig)
		}
	}
	hp.Enabled = true
	c.Honeypots[name] = hp
}

// DisableHoneypot disables a honeypot
func (c *Config) DisableHoneypot(name string) {
	c.hpMu.Lock()
	defer c.hpMu.Unlock()
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

// AllocatePortFor allocates a host port for a specific honeypot's container
// port. Unlike AllocatePort (keyed only on the container port), this folds the
// honeypot name into the hash so two honeypots that both listen on the same
// container port (e.g. cowrie and heralding both on 22) still get distinct host
// ports and do not collide. Deterministic per (instance, honeypot, port).
// HostPortSpread is the width of the host-port window QPot auto-allocates
// published honeypot ports within, starting at the (>=10000) base. It is capped
// so the window stays BELOW the Linux ephemeral range (default
// net.ipv4.ip_local_port_range = 32768..60999): with base 10000 the top port is
// 31999. Publishing inside the ephemeral range races the kernel's dynamic
// allocator - another container's outbound connection (or docker-proxy) can grab
// the same number first, and `docker compose up` then fails with "address
// already in use" intermittently (observed with the full 26-honeypot set, where
// heralding got 39734). Keeping the window below the ephemeral floor removes that
// race. buildHostPortMap (compose.go) uses the same window for its dedup probe.
const HostPortSpread = 22000

func (c *Config) AllocatePortFor(honeypot string, basePort int) int {
	if !c.Ports.AutoAllocate {
		return basePort
	}
	const (
		fnvOffset32 uint32 = 2166136261
		fnvPrime32  uint32 = 16777619
	)
	h := fnvOffset32
	for _, ch := range c.InstanceName + ":" + honeypot {
		h ^= uint32(ch)
		h *= fnvPrime32
	}
	for _, ch := range []byte{byte(basePort), byte(basePort >> 8)} {
		h ^= uint32(ch)
		h *= fnvPrime32
	}
	base := c.Ports.BasePort
	if base < 1024 {
		base = 10000
	}
	// Spread host ports across [base, base+HostPortSpread) so an instance's ~50
	// ports rarely collide.
	return base + int(h%HostPortSpread)
}

// DatabaseContainerPort is the database container's native protocol port:
// 5432 for TimescaleDB, 9000 for ClickHouse.
func (c *Config) DatabaseContainerPort() int {
	if c.Database.Type == "timescaledb" {
		return 5432
	}
	return 9000
}

// DefaultDatabaseHostPort is the 127.0.0.1 port derived for the instance's
// database container from its name. The compose generator moves it off ports
// other instances publish, so the port in use is DatabaseHostPort.
func (c *Config) DefaultDatabaseHostPort() int {
	return c.AllocatePort(c.DatabaseContainerPort())
}

// DatabaseHostPort is the 127.0.0.1 port the instance's database container is
// published on: the one its compose file publishes, else the default. Only the
// compose file knows it once the default was taken by another instance.
func (c *Config) DatabaseHostPort() int {
	if p := c.composeDatabaseHostPort(); p > 0 {
		return p
	}
	return c.DefaultDatabaseHostPort()
}

// composeDatabaseHostPort returns the host port the instance's compose file
// publishes the database service's container port on, 0 if there is none.
func (c *Config) composeDatabaseHostPort() int {
	if c.DataPath == "" {
		return 0
	}
	data, err := os.ReadFile(c.GetDockerComposePath())
	if err != nil {
		return 0
	}
	var doc struct {
		Services map[string]struct {
			Ports []string `yaml:"ports"`
		} `yaml:"services"`
	}
	if yaml.Unmarshal(data, &doc) != nil {
		return 0
	}
	suffix := ":" + strconv.Itoa(c.DatabaseContainerPort())
	for _, spec := range doc.Services["database"].Ports {
		rest, ok := strings.CutSuffix(spec, suffix)
		if !ok {
			continue
		}
		if i := strings.LastIndexByte(rest, ':'); i >= 0 {
			rest = rest[i+1:]
		}
		if p, err := strconv.Atoi(rest); err == nil && p > 0 && p <= 65535 {
			return p
		}
	}
	return 0
}

// DatabaseClient returns the settings the host-side qpot process uses to reach
// the instance's database. For the compose-managed database (loopback host on
// the image's default port) that is the per-instance published port, not the
// container port; any other host/port is used as configured.
func (c *Config) DatabaseClient() *DatabaseConfig {
	d := c.Database
	loopback := d.Host == "localhost" || d.Host == "127.0.0.1" || d.Host == "::1"
	if loopback && (d.Port == 9000 || d.Port == 5432) && (d.Type == "clickhouse" || d.Type == "timescaledb") {
		d.Port = c.DatabaseHostPort()
	}
	return &d
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

// GetEffectiveResourceLimits returns effective resource limits for a honeypot.
// Nonzero per-honeypot limits override the global values when custom limits are
// enabled. Unset fields and restart attempts retain the global values.
func (c *Config) GetEffectiveResourceLimits(honeypot string) ResourceLimits {
	limits := c.Security.ResourceLimits
	hp, ok := c.GetHoneypotConfig(honeypot)
	if !ok {
		return limits
	}

	if !hp.Resources.UseCustomLimits {
		return limits
	}

	if hp.Resources.MaxCPUPercent != 0 {
		limits.MaxCPUPercent = hp.Resources.MaxCPUPercent
	}
	if hp.Resources.MaxMemoryMB != 0 {
		limits.MaxMemoryMB = hp.Resources.MaxMemoryMB
	}
	if hp.Resources.MaxStorageGB != 0 {
		limits.MaxStorageGB = hp.Resources.MaxStorageGB
	}
	if hp.Resources.MaxPids != 0 {
		limits.MaxPids = hp.Resources.MaxPids
	}
	return limits
}
