// Package instance manages QPot instances
package instance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/security"
)

// composePSEntry is one container row from `docker compose ps --format json`.
// Field tags are matched case-insensitively, so they cover docker compose v2's
// capitalised keys ("Service", "State", "Health").
type composePSEntry struct {
	Service  string `json:"service"`
	Name     string `json:"name"`
	State    string `json:"state"`
	Health   string `json:"health"`
	ExitCode int    `json:"exitcode"`
}

// parseComposePS parses `docker compose ps --format json` output into a map
// keyed by compose service name (which equals the honeypot name). It accepts
// both the JSON-array form and the newline-delimited (JSONL) form that
// different docker compose versions emit.
func parseComposePS(output []byte) map[string]composePSEntry {
	out := make(map[string]composePSEntry)
	trimmed := bytes.TrimSpace(output)
	if len(trimmed) == 0 {
		return out
	}

	if trimmed[0] == '[' {
		var arr []composePSEntry
		if err := json.Unmarshal(trimmed, &arr); err == nil {
			for _, e := range arr {
				if e.Service != "" {
					out[e.Service] = e
				}
			}
		}
		return out
	}

	// JSONL / whitespace-separated objects.
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	for {
		var e composePSEntry
		if err := dec.Decode(&e); err != nil {
			if err == io.EOF {
				break
			}
			// Malformed trailing data — return whatever parsed so far.
			break
		}
		if e.Service != "" {
			out[e.Service] = e
		}
	}
	return out
}

// Manager handles QPot instance lifecycle
type Manager struct {
	config   *config.Config
	sandbox  *security.Sandbox
	database database.Database
	dbOnce   sync.Once
	dbErr    error
}

// InstanceInfo represents information about an instance
type InstanceInfo struct {
	Name     string `json:"name"`
	QPotID   string `json:"qpot_id"`
	Running  bool   `json:"running"`
	Ports    string `json:"ports"`
	DataPath string `json:"data_path"`
}

// Status represents instance status
type Status struct {
	Overall   string           `json:"overall"`
	Honeypots []HoneypotStatus `json:"honeypots"`
	Database  string           `json:"database"`
	Uptime    time.Duration    `json:"uptime"`
}

// HoneypotStatus represents a honeypot's status
type HoneypotStatus struct {
	Name    string `json:"name"`
	Running bool   `json:"running"`
	Status  string `json:"status"`
	Port    int    `json:"port"`
	Risk    string `json:"risk"`
}

// NewManager creates a new instance manager.
// The database connection is not established at construction time; it is
// lazily initialized on first use via db(). This means commands such as
// "qpot status" or "qpot logs" succeed even when the database container is
// not running.
func NewManager(cfg *config.Config) (*Manager, error) {
	sandbox, err := security.NewSandbox(&cfg.Security)
	if err != nil {
		return nil, fmt.Errorf("failed to create sandbox: %w", err)
	}

	return &Manager{
		config:  cfg,
		sandbox: sandbox,
	}, nil
}

// db returns the database connection, creating and connecting it on first call.
// Callers that need the database (e.g. Start) should call this and handle
// the error explicitly.
func (m *Manager) db() (database.Database, error) {
	m.dbOnce.Do(func() {
		db, err := database.New(&m.config.Database)
		if err != nil {
			m.dbErr = err
			return
		}
		connectCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := db.Connect(connectCtx); err != nil {
			m.dbErr = fmt.Errorf("connect: %w", err)
			return
		}
		m.database = db
	})
	return m.database, m.dbErr
}

// Initialize sets up a new instance
func (m *Manager) Initialize(ctx context.Context) error {
	slog.Info("Initializing QPot instance", "name", m.config.InstanceName)

	// Create data directories
	dirs := []string{
		m.config.DataPath,
		filepath.Join(m.config.DataPath, "logs"),
		filepath.Join(m.config.DataPath, "db"),
		filepath.Join(m.config.DataPath, "certs"),
		filepath.Join(m.config.DataPath, "honeypots"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Create honeypot-specific directories
	for name, hp := range m.config.Honeypots {
		if hp.Enabled {
			hpDir := filepath.Join(m.config.DataPath, "honeypots", name)
			if err := os.MkdirAll(hpDir, 0750); err != nil {
				return fmt.Errorf("failed to create honeypot directory: %w", err)
			}
			if err := os.MkdirAll(filepath.Join(hpDir, "logs"), 0750); err != nil {
				return fmt.Errorf("failed to create honeypot logs directory: %w", err)
			}
		}
	}

	// Validate host security
	if err := m.sandbox.ValidateHost(); err != nil {
		slog.Warn("Host validation warnings", "error", err)
	}

	// Save configuration
	if err := config.Save(m.config); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	// Generate docker-compose.yml
	if err := m.generateDockerCompose(); err != nil {
		return fmt.Errorf("failed to generate docker-compose: %w", err)
	}

	// Generate the auxiliary config files the compose file mounts into the
	// collector and honeypot containers (Vector pipeline + per-honeypot TPOT
	// configs). Without these the bind mounts point at non-existent files and
	// the log-collection pipeline never starts.
	if err := m.generateServiceConfigs(); err != nil {
		return fmt.Errorf("failed to generate service configs: %w", err)
	}

	slog.Info("Instance initialized successfully", "name", m.config.InstanceName)
	return nil
}

// Start starts the QPot instance
func (m *Manager) Start(ctx context.Context, detach bool) error {
	slog.Info("Starting QPot instance", "name", m.config.InstanceName)

	// Check if already running
	if m.IsRunning(ctx) {
		return fmt.Errorf("instance is already running")
	}

	// Regenerate the compose file and service configs from the current
	// configuration before starting. The compose file is otherwise only written
	// at instance-create time, so honeypots enabled/disabled afterwards (via
	// `qpot honeypot enable/disable`) would never be reflected when `qpot up`
	// runs. Re-running Initialize is idempotent (mkdir -p, save config, render
	// templates) and keeps the running stack in sync with config.yaml.
	if err := m.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to prepare instance for start: %w", err)
	}

	// Eagerly initialize the database connection when starting.
	if _, err := m.db(); err != nil {
		slog.Warn("Database connection could not be established at start", "error", err)
	}

	// Pull images first
	if err := m.pullImages(ctx); err != nil {
		slog.Warn("Failed to pull some images", "error", err)
	}

	// Start services
	composeFile := m.config.GetDockerComposePath()
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composeFile, "up")
	if detach {
		cmd.Args = append(cmd.Args, "-d")
	}
	cmd.Dir = m.config.DataPath
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start docker compose: %w", err)
	}

	if detach {
		// Reap the process in the background to avoid zombies.
		go func() { _ = cmd.Wait() }()
		// Watch the honeypots settle and log which started / which failed (and
		// why). Non-fatal: a single honeypot failing must not abort the instance.
		m.verifyStartup(ctx, 90*time.Second)
		return nil
	}

	// When not detached, wait for the process in a goroutine so we can also
	// poll for health. The process ends when docker compose exits.
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()

	// Wait for the honeypots to settle and report per-honeypot startup status.
	// Failures are logged (with the reason) rather than aborting: the collector,
	// database, web UI and the honeypots that did come up keep running.
	m.verifyStartup(ctx, 2*time.Minute)

	// Block until the compose process exits or context is cancelled.
	select {
	case <-ctx.Done():
	case <-waitDone:
	}

	slog.Info("QPot instance started successfully")
	return nil
}

// Stop stops the QPot instance
func (m *Manager) Stop(ctx context.Context) error {
	slog.Info("Stopping QPot instance", "name", m.config.InstanceName)

	composeFile := m.config.GetDockerComposePath()
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composeFile, "down", "--remove-orphans")
	cmd.Dir = m.config.DataPath

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop docker compose: %w\nOutput: %s", err, output)
	}

	slog.Info("QPot instance stopped")
	return nil
}

// IsRunning checks if the instance is running
func (m *Manager) IsRunning(ctx context.Context) bool {
	composeFile := m.config.GetDockerComposePath()
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composeFile, "ps", "-q")
	cmd.Dir = m.config.DataPath

	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return len(strings.TrimSpace(string(output))) > 0
}

// Status returns the current status of the instance
func (m *Manager) Status(ctx context.Context) (*Status, error) {
	status := &Status{
		Overall:   "stopped",
		Honeypots: []HoneypotStatus{},
		Database:  m.config.Database.Type,
	}

	if !m.IsRunning(ctx) {
		return status, nil
	}

	status.Overall = "running"

	// Get container statuses
	composeFile := m.config.GetDockerComposePath()
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composeFile, "ps", "--format", "json")
	cmd.Dir = m.config.DataPath

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get container status: %w", err)
	}

	// Parse container status by matching the exact compose service name and
	// its reported state. A previous substring match on the raw JSON blob
	// produced false positives (one honeypot's name appearing inside another
	// container's name/image/label) and reported stopped-but-present
	// containers as healthy.
	entries := parseComposePS(output)
	// Snapshot under the config lock: Status is served by the web server
	// concurrently with POST /api/honeypots, which mutates the map.
	for name, hp := range m.config.SnapshotHoneypots() {
		hs := HoneypotStatus{
			Name: name,
			Port: hp.Port,
			Risk: hp.RiskLevel,
		}

		if !hp.Enabled {
			hs.Status = "disabled"
			status.Honeypots = append(status.Honeypots, hs)
			continue
		}

		entry, present := entries[name]
		switch {
		case present && strings.EqualFold(entry.State, "running"):
			hs.Running = true
			switch strings.ToLower(entry.Health) {
			case "unhealthy":
				hs.Status = "unhealthy"
			case "starting":
				hs.Status = "starting"
			default: // "healthy" or no healthcheck configured
				hs.Status = "healthy"
			}
		default:
			hs.Status = "stopped"
		}

		status.Honeypots = append(status.Honeypots, hs)
	}

	return status, nil
}

// StartHoneypot starts a specific honeypot
// isConfiguredHoneypot guards docker compose invocations against argument
// injection: only names defined in the instance config may be passed as a
// service argument to docker.
func (m *Manager) isConfiguredHoneypot(name string) bool {
	if name == "" {
		return false
	}
	_, ok := m.config.GetHoneypotConfig(name)
	return ok
}

func (m *Manager) StartHoneypot(ctx context.Context, name string) error {
	if !m.isConfiguredHoneypot(name) {
		return fmt.Errorf("unknown honeypot: %q", name)
	}
	slog.Info("Starting honeypot", "name", name, "instance", m.config.InstanceName)

	composeFile := m.config.GetDockerComposePath()
	// Enabling ssh-proxy must bring up its real-OpenSSH backend companions too,
	// or the broker has nothing to forward to. The service names are generated
	// by us (fixed "ssh-backend-N" pattern), never user input, so appending them
	// to the argv is injection-safe.
	args := append([]string{"compose", "-f", composeFile, "up", "-d", name}, m.companionServices(name)...)
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = m.config.DataPath

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start honeypot: %w\nOutput: %s", err, output)
	}

	return nil
}

// companionServices returns the additional compose service names that must be
// started/stopped together with a honeypot. Only ssh-proxy has companions (its
// HiFi backends); every other honeypot returns nil. The names are derived
// deterministically (sshproxy.go), so they are safe to pass to docker.
func (m *Manager) companionServices(name string) []string {
	if name == sshProxyHoneypot && sshProxyEnabled(m.config) {
		return sshBackendServiceNames(m.config)
	}
	return nil
}

// StopHoneypot stops a specific honeypot
func (m *Manager) StopHoneypot(ctx context.Context, name string) error {
	if !m.isConfiguredHoneypot(name) {
		return fmt.Errorf("unknown honeypot: %q", name)
	}
	slog.Info("Stopping honeypot", "name", name, "instance", m.config.InstanceName)

	composeFile := m.config.GetDockerComposePath()
	// Stop the HiFi backends alongside the broker (see companionServices).
	args := append([]string{"compose", "-f", composeFile, "stop", name}, m.companionServices(name)...)
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = m.config.DataPath

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop honeypot: %w\nOutput: %s", err, output)
	}

	return nil
}

// GetLogs returns logs for a honeypot or all honeypots
func (m *Manager) GetLogs(ctx context.Context, honeypot string, follow bool, tail int) (<-chan string, error) {
	// Empty means "all honeypots"; any specific name must be configured so it
	// can't be injected as a flag into `docker compose logs`.
	if honeypot != "" && !m.isConfiguredHoneypot(honeypot) {
		return nil, fmt.Errorf("unknown honeypot: %q", honeypot)
	}

	logs := make(chan string, 100)

	composeFile := m.config.GetDockerComposePath()
	args := []string{"compose", "-f", composeFile, "logs"}

	if follow {
		args = append(args, "-f")
	}
	if tail > 0 {
		args = append(args, fmt.Sprintf("--tail=%d", tail))
	}
	if honeypot != "" {
		args = append(args, honeypot)
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = m.config.DataPath

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start logs command: %w", err)
	}

	go func() {
		// Always reap the child and close its pipe, even on the early ctx.Done
		// return below. Without this Wait(), killing the process leaves a zombie
		// and leaks the stdout pipe FD on every /api/logs request that caps out or
		// whose client disconnects (its context is cancelled when the handler
		// returns) - exhausting FDs/PIDs under dashboard polling. Wait() runs
		// before close(logs) (defers are LIFO).
		defer close(logs)
		defer func() { _ = cmd.Wait() }()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				_ = cmd.Process.Kill()
				return
			case logs <- scanner.Text():
			}
		}
	}()

	return logs, nil
}

// pullImages pulls Docker images for the instance
func (m *Manager) pullImages(ctx context.Context) error {
	composeFile := m.config.GetDockerComposePath()
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composeFile, "pull")
	cmd.Dir = m.config.DataPath
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// generateDockerCompose generates the docker-compose.yml file
func (m *Manager) generateDockerCompose() error {
	generator := &ComposeGenerator{
		Config:  m.config,
		Sandbox: m.sandbox,
	}

	compose, err := generator.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate compose: %w", err)
	}

	composePath := m.config.GetDockerComposePath()
	if err := os.WriteFile(composePath, []byte(compose), 0640); err != nil {
		return fmt.Errorf("failed to write docker-compose.yml: %w", err)
	}

	return nil
}

// generateServiceConfigs writes the auxiliary config files that the generated
// docker-compose.yml mounts into containers: the Vector collector pipeline
// (vector.toml) and any per-honeypot TPOT config (e.g. cowrie.cfg, conpot.cfg).
// These generators existed but were never invoked, so the mounts previously
// resolved to missing files and the log pipeline could not run.
func (m *Manager) generateServiceConfigs() error {
	generator := &ComposeGenerator{
		Config:  m.config,
		Sandbox: m.sandbox,
	}

	// Vector collector pipeline config.
	vectorCfg, err := generator.GenerateVectorConfig()
	if err != nil {
		return fmt.Errorf("failed to generate vector config: %w", err)
	}
	// Written as YAML (the config content is YAML); the filename extension
	// matters because Vector selects its parser from it — a .toml name made
	// Vector parse this YAML as TOML and fail to start, collecting nothing.
	vectorPath := filepath.Join(m.config.DataPath, "vector.yaml")
	if err := os.WriteFile(vectorPath, []byte(vectorCfg), 0640); err != nil {
		return fmt.Errorf("failed to write vector.yaml: %w", err)
	}

	// Per-honeypot TPOT configs. Honeypots without a specific config simply
	// return an empty set and write nothing.
	for name, hp := range m.config.Honeypots {
		if !hp.Enabled {
			continue
		}
		cfgs, err := generator.GenerateTPOTConfig(name)
		if err != nil {
			return fmt.Errorf("failed to generate config for honeypot %q: %w", name, err)
		}
		// Config files must land inside the subdir the container mounts (e.g.
		// cowrie reads cowrie.cfg/userdb.txt from etc/, which is bind-mounted),
		// so honor the deployment profile's ConfigSubdir.
		prof := deployProfileFor(name)
		hpDir := filepath.Join(m.config.DataPath, "honeypots", name)
		cfgDir := hpDir
		if prof.ConfigSubdir != "" {
			cfgDir = filepath.Join(hpDir, prof.ConfigSubdir)
		}
		// Ensure all profile volume subdirs (and the config dir) exist so the
		// bind mounts resolve to real directories. They must be writable by the
		// honeypot's in-container non-root user (e.g. uid 2000), which is not
		// the host user that creates them, so use 0777. These dirs hold attacker
		// logs / decoy SSH host keys / downloads — not QPot secrets.
		for _, v := range prof.Volumes {
			// File mounts (e.g. a generated cowrie.cfg) only need their parent
			// directory; the file itself is written by the config loop below.
			dir := filepath.Join(hpDir, v.HostSubdir)
			if v.File {
				dir = filepath.Dir(dir)
			}
			if err := os.MkdirAll(dir, 0750); err != nil {
				return fmt.Errorf("failed to create %s dir for honeypot %q: %w", v.HostSubdir, name, err)
			}
			if err := os.Chmod(dir, 0777); err != nil {
				return fmt.Errorf("failed to chmod %s dir for honeypot %q: %w", v.HostSubdir, name, err)
			}
		}
		if err := os.MkdirAll(cfgDir, 0750); err != nil {
			return fmt.Errorf("failed to create config dir for honeypot %q: %w", name, err)
		}
		for filename, content := range cfgs {
			dest := filepath.Join(cfgDir, filename)
			// World-readable (0644): these are decoy configs (cowrie.cfg,
			// userdb.txt) with no real secrets, and the honeypot runs as a
			// non-root user that must be able to read them — otherwise the
			// honeypot silently falls back to its baked-in defaults.
			if err := os.WriteFile(dest, []byte(content), 0644); err != nil {
				return fmt.Errorf("failed to write %s for honeypot %q: %w", filename, name, err)
			}
		}

		// Cowrie gets a per-instance honeyfs layer so post-login recon is
		// consistent with the login persona / distro identity (see honeyfs.go).
		if name == "cowrie" {
			// Cowrie writes a per-session ttylog to log/tty/ (ttylog_path in
			// cowrie.cfg) but does NOT create that directory itself, and our
			// logs bind mount shadows whatever the image shipped. Without it
			// cowrie crashes the shell channel on every login (the recon shell
			// dies the instant an attacker connects) - a broken honeypot that
			// the port-only healthcheck never catches. Pre-create it, writable
			// by cowrie's in-container uid 2000.
			ttyDir := filepath.Join(hpDir, "logs", "tty")
			if err := os.MkdirAll(ttyDir, 0750); err != nil {
				return fmt.Errorf("failed to create cowrie log/tty dir: %w", err)
			}
			if err := os.Chmod(ttyDir, 0777); err != nil {
				return fmt.Errorf("failed to chmod cowrie log/tty dir: %w", err)
			}
			for rel, content := range generator.generateCowrieHoneyfs() {
				dest := filepath.Join(hpDir, "honeyfs", rel)
				if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
					return fmt.Errorf("failed to create honeyfs dir for cowrie: %w", err)
				}
				if err := os.WriteFile(dest, []byte(content), 0644); err != nil {
					return fmt.Errorf("failed to write honeyfs/%s for cowrie: %w", rel, err)
				}
			}
		}

		// HiFi ssh-proxy: pre-create each real-OpenSSH backend's persisted
		// host-key dir and log dir, so the bind mounts resolve to real
		// directories owned by us (rather than docker creating them as root). The
		// backend sshd writes host keys to /etc/ssh and recordings to
		// /var/log/ssh-backend; both must be writable by the in-container user.
		if name == sshProxyHoneypot {
			mkBackendDir := func(rel string) error {
				dir := filepath.Join(m.config.DataPath, "honeypots", sshBackendDataDir, rel)
				if err := os.MkdirAll(dir, 0750); err != nil {
					return fmt.Errorf("failed to create ssh-backend dir %q: %w", rel, err)
				}
				// 0777 so the in-container sshd uid (not the host user that creates
				// these) can write host keys / recordings.
				if err := os.Chmod(dir, 0777); err != nil {
					return fmt.Errorf("failed to chmod ssh-backend dir %q: %w", rel, err)
				}
				return nil
			}
			// One SHARED host-key dir for the whole pool (so all backends present
			// the same fingerprint), plus a per-backend log dir.
			if err := mkBackendDir("shared-hostkeys"); err != nil {
				return err
			}
			for _, svc := range sshBackendServiceNames(m.config) {
				if err := mkBackendDir(filepath.Join(svc, "logs")); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// List returns all QPot instances
func List() ([]InstanceInfo, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	instancesDir := filepath.Join(homeDir, ".qpot", "instances")
	entries, err := os.ReadDir(instancesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []InstanceInfo{}, nil
		}
		return nil, fmt.Errorf("failed to read instances directory: %w", err)
	}

	var instances []InstanceInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		dataPath := filepath.Join(instancesDir, name)

		// Try to load config
		cfg, err := config.Load(name)
		if err != nil {
			continue
		}

		// Check if running
		mgr, _ := NewManager(cfg)
		running := false
		if mgr != nil {
			running = mgr.IsRunning(context.Background())
		}

		// Load QPot ID
		qpotID, _ := LoadID(name)
		idStr := ""
		if qpotID != nil {
			idStr = qpotID.ID
		}

		instances = append(instances, InstanceInfo{
			Name:     name,
			QPotID:   idStr,
			Running:  running,
			Ports:    fmt.Sprintf("%d-%d", cfg.Ports.BasePort, cfg.Ports.BasePort+1000),
			DataPath: dataPath,
		})
	}

	return instances, nil
}

// Remove removes an instance
func Remove(ctx context.Context, name string) error {
	slog.Info("Removing QPot instance", "name", name)

	cfg, err := config.Load(name)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	mgr, err := NewManager(cfg)
	if err != nil {
		return fmt.Errorf("failed to create manager: %w", err)
	}

	// Stop if running
	if mgr.IsRunning(ctx) {
		if err := mgr.Stop(ctx); err != nil {
			return fmt.Errorf("failed to stop instance: %w", err)
		}
	}

	// Remove data directory
	if err := os.RemoveAll(cfg.DataPath); err != nil {
		return fmt.Errorf("failed to remove data directory: %w", err)
	}

	slog.Info("Instance removed", "name", name)
	return nil
}
