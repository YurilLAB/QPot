// Package instance manages QPot instances
package instance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/security"
	"github.com/qpot/qpot/internal/vectorstate"
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
		db, err := database.New(m.config.DatabaseClient())
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
	sandbox, _ := security.NewSandbox(&m.config.Security)
	if _, err := sandbox.Selection(); err != nil {
		return err
	}
	if err := os.MkdirAll(m.config.DataPath, 0o750); err != nil {
		return err
	}
	cellLock, err := lockSSHCells(ctx, m.config.DataPath)
	if err != nil {
		return fmt.Errorf("lock SSH cell layout: %w", err)
	}
	defer cellLock.Close()
	return m.initializeLocked(ctx)
}

func (m *Manager) initializeLocked(ctx context.Context, selections ...security.RuntimeSelection) error {
	declared, _ := security.NewSandbox(&m.config.Security)
	if _, err := declared.Selection(); err != nil {
		return err
	}
	for _, selection := range selections {
		if err := declared.ValidateSelection(selection, requiresStrongSandbox(m.config)); err != nil {
			return err
		}
	}
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

	// Validate the candidate before touching any live cell. Auxiliary files
	// must also be ready before obsolete services are retired or the new
	// Compose layout becomes visible to the recycler.
	if _, err := m.renderDockerCompose(selections...); err != nil {
		return fmt.Errorf("failed to generate docker-compose: %w", err)
	}
	if err := prepareSSHRuntimeLayout(ctx, m.config); err != nil {
		return err
	}
	// Empty-ID legacy library callers reserve randomness only after validation;
	// all callers now render the same pinned location used by the live guest.
	compose, err := m.renderDockerCompose(selections...)
	if err != nil {
		return fmt.Errorf("failed to generate pinned docker-compose: %w", err)
	}

	// Generate the auxiliary config files the compose file mounts into the
	// collector and honeypot containers (Vector pipeline + per-honeypot TPOT
	// configs). Without these the bind mounts point at non-existent files and
	// the log-collection pipeline never starts.
	if err := m.generateServiceConfigs(); err != nil {
		return fmt.Errorf("failed to generate service configs: %w", err)
	}
	if err := m.publishDockerCompose(ctx, compose); err != nil {
		return fmt.Errorf("failed to publish docker-compose: %w", err)
	}

	slog.Info("Instance initialized successfully", "name", m.config.InstanceName)
	return nil
}

// Start starts the QPot instance
func (m *Manager) Start(ctx context.Context, detach bool) error {
	slog.Info("Starting QPot instance", "name", m.config.InstanceName)
	if sshProxyEnabled(m.config) {
		if err := config.ValidateSSHEnvironment(m.config); err != nil {
			return err
		}
		if err := validateSSHRuntimeImages(m.config, HiFiImageRevision); err != nil {
			return err
		}
	}
	if _, err := resolveSandbox(ctx, m.config); err != nil {
		return err
	}
	if m.AllRunning(ctx) {
		return fmt.Errorf("instance is already running")
	}
	if err := os.MkdirAll(m.config.DataPath, 0o750); err != nil {
		return err
	}
	cellLock, err := lockSSHCells(ctx, m.config.DataPath)
	if err != nil {
		return fmt.Errorf("lock instance deployment: %w", err)
	}
	defer cellLock.Close()
	selection, err := resolveSandbox(ctx, m.config)
	if err != nil {
		return err
	}
	if sshProxyEnabled(m.config) {
		if err := validateSSHRuntimeResources(ctx); err != nil {
			return err
		}
	}
	if err := checkContainment(ctx, m.config); err != nil {
		return err
	}
	if err := m.initializeLocked(ctx, selection); err != nil {
		return fmt.Errorf("failed to prepare instance for start: %w", err)
	}
	if _, err := m.db(); err != nil {
		slog.Warn("Database connection could not be established at start", "error", err)
	}
	if err := m.pullImages(ctx); err != nil {
		slog.Warn("Failed to pull some images", "error", err)
	}
	for _, name := range m.config.GetEnabledHoneypots() {
		if err := m.prepareOwnership(ctx, name); err != nil {
			slog.Warn("Could not hand data dirs to the honeypot's user; it may fail to write its logs", "honeypot", name, "error", err)
		}
	}
	if err := m.prepareSSHDeployment(ctx); err != nil {
		return fmt.Errorf("prepare fresh SSH cell recordings: %w", err)
	}
	// Once per instance: earlier versions wrote the QPot ID into the log
	// backups. A failure does not keep the honeypots down; qpot doctor
	// reports the backups until a later start gets it done.
	if err := m.scrubLogBackups(ctx); err != nil {
		slog.Warn("Log backups still carry the QPot ID; it will be retried at the next start", "error", err)
	}
	// Creation must finish under the same lock as layout publication. Starting
	// a foreground compose process and immediately unlocking would still let a
	// recycler race its asynchronous container creation.
	composeFile := m.config.GetDockerComposePath()
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composeFile, "up", "-d")
	cmd.Dir = m.config.DataPath
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker compose up failed (see the output above): %w", err)
	}
	if err := m.verifyStartedSandbox(ctx, sandboxServices(m.config, m), selection); err != nil {
		return err
	}
	_ = cellLock.Close()
	// Health settling can require the recycler to finish a broker startup
	// request, so it must not hold the deployment lock.
	m.verifyStartup(ctx, 90*time.Second)
	if detach {
		return nil
	}
	// The public CLI always uses detached creation then runs the control plane.
	// An internal foreground caller gets logs without a second mutating up.
	follow := exec.CommandContext(ctx, "docker", "compose", "-f", composeFile, "logs", "--follow", "--no-color")
	follow.Dir = m.config.DataPath
	follow.Stdout, follow.Stderr = os.Stdout, os.Stderr
	err = follow.Run()
	if ctx.Err() != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return m.Stop(stopCtx)
	}
	return err
}

// Stop stops the QPot instance
func (m *Manager) Stop(ctx context.Context) error {
	slog.Info("Stopping QPot instance", "name", m.config.InstanceName)
	cellLock, err := lockSSHCells(ctx, m.config.DataPath)
	if err != nil {
		return fmt.Errorf("lock instance stop: %w", err)
	}
	defer cellLock.Close()
	return m.stopLocked(ctx, true)
}

// stopLocked holds the same lifecycle exclusion as startup and runtime-store
// deletion. A false/unknown status probe never authorizes deleting a live bind.
// With convert, the SSH cells are stopped and their sessions converted
// first: removing a backend container loses its capture, so if conversion
// fails nothing is removed. Without it (the store is deleted next) the
// cells are removed with everything else.
func (m *Manager) stopLocked(ctx context.Context, convert bool) error {
	composeFile := m.config.GetDockerComposePath()
	if layout, err := readSSHLayout(composeFile, m.config.InstanceName); convert && err == nil && len(layout.Groups) > 0 {
		var services []string
		for _, members := range layout.Groups {
			services = append(services, members...)
		}
		sort.Strings(services)
		if err := stopSSHServices(ctx, composeFile, services); err != nil {
			return fmt.Errorf("nothing was removed: %w", err)
		}
		brokerLog, err := sshBrokerSessionLog(m.config)
		if err != nil {
			return fmt.Errorf("nothing was removed: find the SSH broker's log: %w", err)
		}
		if err := drainSSHCaptures(ctx, m.config.DataPath, m.config.InstanceName, brokerLog, services); err != nil {
			return fmt.Errorf("nothing was removed: %w; stop again once the cause is fixed, or remove those containers with docker to discard the sessions", err)
		}
	}
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composeFile, "down", "--remove-orphans")
	cmd.Dir = m.config.DataPath

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop docker compose: %w\nOutput: %s", err, output)
	}

	slog.Info("QPot instance stopped")
	return nil
}

// expectedServices are the compose services the instance runs once it is up,
// as configured: the database (ClickHouse or TimescaleDB), the collector, the
// egress guard when it is on, and every enabled honeypot with its companions.
func (m *Manager) expectedServices() []string {
	var out []string
	if t := m.config.Database.Type; t == "clickhouse" || t == "timescaledb" {
		out = append(out, "database")
	}
	out = append(out, "collector")
	if eg, err := egressGuardFor(m.config); err == nil && eg.Enabled {
		out = append(out, "netguard")
	}
	for name, hp := range m.config.SnapshotHoneypots() {
		if hp.Enabled {
			out = append(out, name)
			out = append(out, m.companionServices(name)...)
		}
	}
	sort.Strings(out)
	return out
}

// StoppedServices returns the services the instance should run (see
// expectedServices) that have no running container: exited, created, or
// never created. It fails when docker cannot be asked.
func (m *Manager) StoppedServices(ctx context.Context) ([]string, error) {
	states, err := m.ServiceStates(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, svc := range m.expectedServices() {
		if !strings.EqualFold(states[svc].State, "running") {
			out = append(out, svc)
		}
	}
	return out, nil
}

// AllRunning reports whether every service the instance should run is
// running. IsRunning is true as soon as any one container runs: after an
// unclean stop docker brings back only the containers its restart policy
// covers, and the database or the honeypots can stay down next to them.
func (m *Manager) AllRunning(ctx context.Context) bool {
	stopped, err := m.StoppedServices(ctx)
	return err == nil && len(stopped) == 0
}

// IsRunning reports whether any of the instance's containers is running (see
// AllRunning for whether all of them are).
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

	// Every configured honeypot is listed, also while the instance is down:
	// callers count the enabled ones from this list (the dashboard said
	// "0 running of 0 enabled" while ten honeypots were on).
	entries := map[string]composePSEntry{}
	if m.IsRunning(ctx) {
		status.Overall = "running"
		composeFile := m.config.GetDockerComposePath()
		cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composeFile, "ps", "--format", "json")
		cmd.Dir = m.config.DataPath
		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to get container status: %w", err)
		}
		// Parse container status by matching the exact compose service name
		// and its reported state. A previous substring match on the raw JSON
		// blob produced false positives (one honeypot's name appearing inside
		// another container's name/image/label) and reported
		// stopped-but-present containers as healthy.
		entries = parseComposePS(output)
	}
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
	return m.startHoneypot(ctx, name, false)
}

// RecreateHoneypot runs a honeypot with changed settings: as StartHoneypot,
// but its container (and its companions') is always recreated. Some settings
// live only in files the honeypot reads when it starts, such as Cowrie's bait
// plan: they leave the compose service as it was, and `compose up -d` alone
// kept the old container serving the old files. Only the named services are
// forced: compose still starts a stopped dependency and waits for it, so a
// public honeypot never runs without its egress guard, and leaves running
// ones (database, egress guard) as they are.
func (m *Manager) RecreateHoneypot(ctx context.Context, name string) error {
	return m.startHoneypot(ctx, name, true)
}

func (m *Manager) startHoneypot(ctx context.Context, name string, recreate bool) error {
	if !m.isConfiguredHoneypot(name) {
		return fmt.Errorf("unknown honeypot: %q", name)
	}
	if name == sshProxyHoneypot {
		if err := config.ValidateSSHEnvironment(m.config); err != nil {
			return err
		}
		if err := validateSSHRuntimeImages(m.config, HiFiImageRevision); err != nil {
			return err
		}
	}
	if _, err := resolveSandbox(ctx, m.config, name); err != nil {
		return err
	}
	slog.Info("Starting honeypot", "name", name, "instance", m.config.InstanceName)
	if err := os.MkdirAll(m.config.DataPath, 0o750); err != nil {
		return err
	}
	cellLock, err := lockSSHCells(ctx, m.config.DataPath)
	if err != nil {
		return fmt.Errorf("lock honeypot deployment: %w", err)
	}
	defer cellLock.Close()
	selection, err := resolveSandbox(ctx, m.config, name)
	if err != nil {
		return err
	}
	if name == sshProxyHoneypot {
		if err := config.ValidateSSHEnvironment(m.config); err != nil {
			return err
		}
		if err := validateSSHRuntimeResources(ctx); err != nil {
			return err
		}
	}
	if err := checkContainment(ctx, m.config, name); err != nil {
		return err
	}

	// Regenerate the compose file and collector config first: a honeypot
	// enabled on a running instance is not in the existing compose file
	// (`compose up -d <name>` failed with "no such service") and the
	// collector would not tail its logs.
	if err := m.initializeLocked(ctx, selection); err != nil {
		return fmt.Errorf("failed to regenerate the instance config: %w", err)
	}
	if err := m.prepareOwnership(ctx, name); err != nil {
		slog.Warn("Could not hand data dirs to the honeypot's user", "honeypot", name, "error", err)
	}
	if name == sshProxyHoneypot {
		if err := m.prepareSSHDeployment(ctx); err != nil {
			return fmt.Errorf("prepare fresh SSH cell recordings: %w", err)
		}
	}

	composeFile := m.config.GetDockerComposePath()
	// Enabling ssh-proxy must bring up its real-OpenSSH backend companions too,
	// or the broker has nothing to forward to. The service names are generated
	// by us (fixed "ssh-backend-N" pattern), never user input, so appending them
	// to the argv is injection-safe.
	args := []string{"compose", "-f", composeFile, "up", "-d"}
	if recreate {
		// Not --no-deps: that would skip the wait on the egress guard.
		args = append(args, "--force-recreate")
	}
	args = append(append(args, name), m.companionServices(name)...)
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = m.config.DataPath

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start honeypot: %w\nOutput: %s", err, output)
	}
	if err := m.verifyStartedSandbox(ctx, append([]string{name}, m.companionServices(name)...), selection); err != nil {
		return err
	}
	_ = cellLock.Close()

	// Pick up the regenerated collector config (it now reads this honeypot's
	// logs); Vector reads its config only at start.
	restart := exec.CommandContext(ctx, "docker", "compose", "-f", composeFile, "restart", "collector")
	restart.Dir = m.config.DataPath
	if out, err := restart.CombinedOutput(); err != nil {
		return fmt.Errorf("honeypot started, but the collector did not restart (its logs are not collected yet): %w\nOutput: %s", err, out)
	}
	return nil
}

// companionServices returns the additional compose service names that must be
// started/stopped together with a honeypot. Only ssh-proxy has companions (its
// HiFi backends); every other honeypot returns nil. The names are derived
// deterministically (sshproxy.go), so they are safe to pass to docker.
func (m *Manager) companionServices(name string) []string {
	// Not gated on the enabled flag: `honeypot disable` saves the config
	// before stopping, and the companions must be stopped with it.
	switch name {
	case sshProxyHoneypot:
		return allSSHCellServiceNames(m.config)
	case "tanner":
		return tannerCompanionServices()
	}
	return nil
}

// StopHoneypot stops a specific honeypot
func (m *Manager) StopHoneypot(ctx context.Context, name string) error {
	if !m.isConfiguredHoneypot(name) {
		return fmt.Errorf("unknown honeypot: %q", name)
	}
	slog.Info("Stopping honeypot", "name", name, "instance", m.config.InstanceName)
	cellLock, err := lockSSHCells(ctx, m.config.DataPath)
	if err != nil {
		return fmt.Errorf("lock honeypot stop: %w", err)
	}
	defer cellLock.Close()

	composeFile := m.config.GetDockerComposePath()
	// Stop the HiFi backends alongside the broker (see companionServices).
	companions := m.companionServices(name)
	if name == sshProxyHoneypot {
		layout, err := readSSHLayout(composeFile, m.config.InstanceName)
		if err != nil {
			return fmt.Errorf("read deployed SSH cells before stopping: %w", err)
		}
		if len(layout.Groups) > 0 {
			companions = nil
			for _, members := range layout.Groups {
				companions = append(companions, members...)
			}
			sort.Strings(companions)
		}
	}
	args := append([]string{"compose", "-f", composeFile, "stop", name}, companions...)
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
		// A line of any length is read (a honeypot logs what attackers send):
		// stopping at the first long one left docker blocked writing to a pipe
		// nobody read, and Wait() above waiting for it. Reading stops early
		// only by killing docker first.
		reader := bufio.NewReaderSize(stdout, 64<<10)
		for {
			line, err := readLogLine(reader, maxLogLine)
			if err == nil || line != "" {
				select {
				case <-ctx.Done():
					_ = cmd.Process.Kill()
					return
				case logs <- line:
				}
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					_ = cmd.Process.Kill()
				}
				return
			}
		}
	}()

	return logs, nil
}

// maxLogLine is the most of one log line GetLogs passes on; the rest of a
// longer line is read and dropped.
const maxLogLine = 64 << 10

// readLogLine reads one line of any length without its line ending, keeping
// its first max bytes and marking it when more were dropped.
func readLogLine(r *bufio.Reader, max int) (string, error) {
	var line []byte
	dropped := false
	for {
		chunk, more, err := r.ReadLine()
		keep := min(len(chunk), max-len(line))
		line = append(line, chunk[:keep]...)
		dropped = dropped || keep < len(chunk)
		if err != nil || !more {
			if dropped {
				line = append(line, " [line truncated]"...)
			}
			return string(line), err
		}
	}
}

// pullImages pulls Docker images for the instance
func (m *Manager) pullImages(ctx context.Context) error {
	composeFile := m.config.GetDockerComposePath()
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composeFile, "pull", "--ignore-buildable")
	cmd.Dir = m.config.DataPath
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// generateDockerCompose generates the docker-compose.yml file
func (m *Manager) generateDockerCompose() error {
	compose, err := m.renderDockerCompose()
	if err != nil {
		return err
	}
	return m.publishDockerCompose(context.Background(), compose)
}

func (m *Manager) renderDockerCompose(selections ...security.RuntimeSelection) (string, error) {
	ports, subnets := siblingReservations(m.config.DataPath)
	generator := &ComposeGenerator{
		Config:          m.config,
		Sandbox:         m.sandbox,
		ReservedPorts:   ports,
		ReservedSubnets: subnets,
		KeepPorts:       ownHostPorts(m.config.GetDockerComposePath()),
	}
	if len(selections) > 0 {
		generator.executionSelection = &selections[0]
	}
	generator.ReservedNets, generator.KeepSubnets = hostDockerSubnets(context.Background(), composeProjectName(m.config), generator.currentNetworkNames())

	compose, err := generator.Generate()
	if err != nil {
		return "", fmt.Errorf("failed to generate compose: %w", err)
	}
	return compose, nil
}

func (m *Manager) publishDockerCompose(ctx context.Context, compose string) error {
	composePath := m.config.GetDockerComposePath()
	oldCompose, err := os.ReadFile(composePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read previous docker-compose: %w", err)
	}
	// Stage and sync first. A generation/disk error must leave the previous
	// layout and services intact, rather than removing the working graph.
	f, err := os.CreateTemp(m.config.DataPath, ".compose-candidate-*.yaml")
	if err != nil {
		return err
	}
	staged := f.Name()
	defer os.Remove(staged)
	if _, err := f.WriteString(compose); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := retireSSHCells(ctx, m.config, oldCompose); err != nil {
		return err
	}
	if err := os.Rename(staged, composePath); err != nil {
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
	if err := prepareClickHouseKeeper(m.config); err != nil {
		return err
	}
	generator := &ComposeGenerator{
		Config:  m.config,
		Sandbox: m.sandbox,
	}

	// The collector keeps its checkpoints in the instance folder, and reads a
	// log it has none for from its start. When it has kept none yet (a new
	// instance, or one an older QPot ran, which kept none), what the logs
	// hold now counts as delivered, so it is not sent again.
	if err := vectorstate.MigrateLegacy(m.config.DataPath); err != nil {
		return err
	}
	_, statErr := os.Lstat(filepath.Join(m.config.DataPath, vectorstate.Dir))
	firstState := errors.Is(statErr, fs.ErrNotExist)

	// The collector's folders must exist before it starts: Docker would create
	// a missing one owned by root.
	mounts, err := collectorMounts(m.config)
	if err != nil {
		return err
	}
	for _, cm := range mounts {
		if !cm.Dir {
			continue
		}
		if cm.Container == "/var/lib/vector" {
			if err := ensureContainerDir(cm.Host, 0o750); err != nil {
				return fmt.Errorf("failed to prepare private collector checkpoints: %w", err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.FromSlash(cm.Host), 0750); err != nil {
			return fmt.Errorf("failed to create collector folder %s: %w", cm.Host, err)
		}
	}
	// A mount inside another mount needs its mount point to exist already
	// (see nestedMountPoints). Created below the outer folder without
	// following a link out of it.
	for _, np := range nestedMountPoints(mounts) {
		if err := ensureContainerDirIn(filepath.FromSlash(np.OuterHost), np.Rel, 0o750); err != nil {
			return fmt.Errorf("failed to create the collector's mount point %s in %s: %w", np.Rel, np.OuterHost, err)
		}
	}
	if firstState {
		sources, err := CollectorSources(m.config)
		if err != nil {
			return err
		}
		for _, src := range sources {
			// Native recordings must replay from the beginning unless an
			// authoritative retained checkpoint already acknowledges them.
			// Adopting a distinct source never proves old evidence delivered.
			if src.Name == SSHBackendLogSource {
				continue
			}
			n, err := vectorstate.Seed(m.config.DataPath, src, time.Now(), collectorLogReader)
			if err != nil {
				return fmt.Errorf("the logs this instance already holds could not be marked as collected, and without that the collector would send them all again: %w", err)
			}
			if n > 0 {
				slog.Info("Collector starts after what the logs already hold", "source", src.Name, "logs", n)
			}
		}
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
	if err := writeSecretFile(vectorPath, []byte(vectorCfg)); err != nil {
		return fmt.Errorf("failed to write vector.yaml: %w", err)
	}

	// Per-honeypot data dirs, and the config files a profile mounts (most
	// images render their own: cowrie from its persona, conpot from its
	// template).
	for name, hp := range m.config.Honeypots {
		if !hp.Enabled {
			continue
		}
		prof := deployProfile(m.config, name)
		if prof.LocalBuild {
			if err := writeRefrigerationBuild(m.config); err != nil {
				return err
			}
		}
		hpDir := filepath.Join(m.config.DataPath, "honeypots", name)
		// Ensure all profile volume subdirs (and the config dir) exist so the
		// bind mounts resolve to real directories. They must be writable by the
		// honeypot's in-container non-root user (e.g. uid 2000), which is not
		// the host user that creates them, so use 0777. These dirs hold attacker
		// logs / decoy SSH host keys / downloads — not QPot secrets.
		for _, v := range prof.Volumes {
			// File mounts (e.g. heralding.yml) need their parent directory and
			// the file, written before start: docker would otherwise create a
			// directory at the missing path.
			dir := filepath.Join(hpDir, v.HostSubdir)
			if v.File {
				dir = filepath.Dir(dir)
			}
			if err := os.MkdirAll(dir, 0750); err != nil {
				return fmt.Errorf("failed to create %s dir for honeypot %q: %w", v.HostSubdir, name, err)
			}
			if v.File {
				if len(v.Content) == 0 {
					return fmt.Errorf("honeypot %q: no content for %s", name, v.HostSubdir)
				}
				// World-readable: the image's non-root user reads it. It is the
				// honeypot's own config, no QPot secret.
				dest := filepath.Join(hpDir, v.HostSubdir)
				if err := os.WriteFile(dest, v.Content, 0644); err != nil {
					return fmt.Errorf("failed to write %s for honeypot %q: %w", v.HostSubdir, name, err)
				}
				if err := os.Chmod(dest, 0644); err != nil {
					return fmt.Errorf("failed to chmod %s for honeypot %q: %w", v.HostSubdir, name, err)
				}
			}
			mode := os.FileMode(0777)
			if v.ReadOnly {
				mode = 0755 // host-written; only read inside the container
			}
			if slices.Contains(prof.OwnedSubdirs, v.HostSubdir) {
				continue // handed to the image's user by prepareOwnership
			}
			if err := os.Chmod(dir, mode); err != nil {
				return fmt.Errorf("failed to chmod %s dir for honeypot %q: %w", v.HostSubdir, name, err)
			}
		}
		if err := os.MkdirAll(hpDir, 0750); err != nil {
			return fmt.Errorf("failed to create data dir for honeypot %q: %w", name, err)
		}
		// Folders the image needs inside a writable volume (dionaea's
		// roots/ftp), writable by the container's user. The container can
		// leave anything there; see ensureContainerDirIn.
		for _, d := range prof.ContainerDirs {
			vol, rel, ok := strings.Cut(d, "/")
			if !ok {
				return fmt.Errorf("honeypot %q: folder %q is not inside a volume", name, d)
			}
			if err := ensureContainerDirIn(filepath.Join(hpDir, vol), rel, 0777); err != nil {
				return fmt.Errorf("failed to prepare %s for honeypot %q: %w", d, name, err)
			}
		}

		if err := ensureHoneypotLogs(filepath.Join(hpDir, "logs"), prof.Logs); err != nil {
			return fmt.Errorf("honeypot %q: %w", name, err)
		}

		if name == "cowrie" {
			// Cowrie writes a per-session ttylog to log/tty/ but does NOT create
			// that directory itself, and our logs bind mount shadows whatever the
			// image shipped. Without it cowrie crashes the shell channel on every
			// login (the recon shell dies the instant an attacker connects) - a
			// broken honeypot that the port-only healthcheck never catches.
			// Pre-create it, writable by cowrie's in-container uid 2000. It lies
			// inside the logs mount, which cowrie writes to, so whatever cowrie
			// left at log/tty is never followed (see ensureContainerDir).
			ttyDir := filepath.Join(hpDir, "logs", "tty")
			if err := ensureContainerDir(ttyDir, 0777); err != nil {
				return fmt.Errorf("failed to prepare cowrie log/tty dir: %w", err)
			}
		}

		// HiFi ssh-proxy: prepare the pool's host keys (handed to each backend
		// at start), the broker's log folder and each cell's evidence folder,
		// which the control plane fills from the backends' session capture.
		if name == sshProxyHoneypot {
			if err := prepareSSHOrganization(m.config); err != nil {
				return err
			}
			brokerLogs, err := sshBrokerLogDir(m.config)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(brokerLogs, 0o750); err != nil {
				return err
			}
			if err := ensureContainerDir(brokerLogs, 0o777); err != nil {
				return err
			}
			// One SHARED host-key dir for the whole pool (so all backends present
			// the same fingerprint), plus a per-backend log dir. The keys are
			// generated here, on the host, and copied into each backend at start.
			keyDir, err := sshStoreSharedKeys(m.config)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(keyDir, 0o755); err != nil {
				return fmt.Errorf("failed to create ssh-backend host-key dir: %w", err)
			}
			if err := ensureSSHHostKeys(keyDir); err != nil {
				return fmt.Errorf("failed to create ssh-backend host keys: %w", err)
			}
			for _, svc := range allSSHCellServiceNames(m.config) {
				if err := prepareSSHLogDir(m.config.DataPath, svc); err != nil {
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

	// Don't let Remove "succeed" on a name that doesn't exist: config.Load below
	// auto-creates a default config (and dir), so without this guard
	// `remove <typo>` would create-then-delete an empty instance and report
	// success, masking the typo.
	dir := config.Default(name).DataPath
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return fmt.Errorf("instance %q does not exist", name)
	}
	if err != nil {
		return fmt.Errorf("inspect instance directory: %w", err)
	}
	// A restored/hand-edited default-path symlink may load another instance's
	// location metadata. Refuse before stopping or deleting any owned store.
	if !info.IsDir() {
		return sshStorageError(errors.New("the default instance directory is not an ordinary directory; inspect the link without following it before removing this instance"))
	}

	cfg, err := config.Load(name)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	mgr, err := NewManager(cfg)
	if err != nil {
		return fmt.Errorf("failed to create manager: %w", err)
	}

	cellLock, err := lockSSHCells(ctx, cfg.DataPath)
	if err != nil {
		return err
	}
	defer cellLock.Close()
	store, err := sshStoreAt(cfg.DataPath)
	if err != nil {
		return err
	}
	ownedData := samePath(cfg.DataPath, dir)
	// A persisted external store must have an authoritative successful stop,
	// even when Docker's status query would report no running containers.
	if ownedData && !store.legacy {
		// The store and every recording in it are deleted next.
		if err := mgr.stopLocked(ctx, false); err != nil {
			return sshStorageError(err)
		}
		if err := removeSSHStore(ctx, cfg.DataPath); err != nil {
			return err
		}
	} else if mgr.IsRunning(ctx) {
		if err := mgr.stopLocked(ctx, true); err != nil {
			return fmt.Errorf("failed to stop instance: %w", err)
		}
	}

	// Remove the instance's own directory, not the data_path its config.yaml
	// names: that comes from a file a hand edit or a restored backup can point
	// anywhere (another user's instance, a home folder), and deleting it took
	// a directory that was never the instance's while leaving the instance
	// behind. A data_path elsewhere is left in place.
	if !samePath(cfg.DataPath, dir) {
		slog.Warn("The instance's data_path is outside its directory; left in place",
			"data_path", cfg.DataPath, "instance_dir", dir)
	}
	// Windows cannot delete a file a handle holds open, and the lock file is
	// in dir. Delete everything else while still holding the lock, then
	// release it and remove what is left.
	keep := []string{sshCellsLockName, sshFoldersLockName}
	if err := removeAllBut(dir, keep...); err != nil {
		// The database's, the collector's and some honeypots' files belong
		// to their containers' users, root among them: on Linux the user who
		// runs qpot cannot delete them. A root helper container can. (Found
		// when a lab instance could not be removed: "permission denied" on
		// the collector's backup of the first day.)
		if !errors.Is(err, fs.ErrPermission) {
			return fmt.Errorf("failed to remove data directory: %w", err)
		}
		if herr := removeHelper(ctx, dir, keep); herr != nil {
			return fmt.Errorf("failed to remove data directory: %w (files of the containers' users are left; the helper container that removes them failed: %v). Remove %s as root", err, herr, dir)
		}
		if err := removeAllBut(dir, keep...); err != nil {
			return fmt.Errorf("failed to remove data directory: %w", err)
		}
	}
	_ = cellLock.Close()
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("failed to remove data directory: %w", err)
	}

	slog.Info("Instance removed", "name", name)
	return nil
}

// removeHelperScript deletes everything directly in /i except the names it
// is given as arguments (QPot's own lock files, held open by the caller).
// rm never follows a link out of the mounted folder.
const removeHelperScript = `skip=""
for k in "$@"; do skip="$skip ! -name $k"; done
find /i -mindepth 1 -maxdepth 1 $skip -exec rm -rf -- {} +`

// removeHelper deletes the contents of an instance's own directory as root
// in a throwaway container, with only that directory mounted; a variable so
// tests can stand in. It uses the collector's image, which an instance that
// ever ran has, and never pulls one.
var removeHelper = func(ctx context.Context, dir string, keep []string) error {
	if !filepath.IsAbs(dir) || strings.ContainsAny(dir, ",\n\x00") {
		return fmt.Errorf("folder %q cannot be mounted", dir)
	}
	for _, k := range keep {
		if k == "" || strings.ContainsAny(k, " \t\n/'\"$`\\*?[") {
			return fmt.Errorf("unexpected name to keep: %q", k)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", CollectorImage).CombinedOutput(); err != nil {
		return fmt.Errorf("the collector image is not on this host: %s", firstLineOf(out))
	}
	args := append([]string{"run", "--rm", "--network", "none", "--read-only", "--pull", "never",
		"--cap-drop", "ALL", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER",
		"--security-opt", "no-new-privileges", "--pids-limit", "32", "--memory", "128m",
		"--user", "0:0", "--mount", "type=bind,source=" + dir + ",target=/i",
		"--entrypoint", "sh", CollectorImage, "-c", removeHelperScript, "sh"}, keep...)
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput() // #nosec G204 -- fixed program and image; dir and keep are checked above
	if err != nil {
		return fmt.Errorf("%w: %s", err, firstLineOf(out))
	}
	return nil
}

// removeAllBut removes every entry of dir except those named keep. Like
// os.RemoveAll, it removes a symlink itself, never what it points at.
func removeAllBut(dir string, keep ...string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if slices.Contains(keep, e.Name()) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// samePath reports whether a and b name the same directory once cleaned and
// made absolute.
func samePath(a, b string) bool {
	aa, err1 := filepath.Abs(a)
	bb, err2 := filepath.Abs(b)
	return err1 == nil && err2 == nil && aa == bb
}

// ServiceState is one compose service's container state, e.g. State "running"
// and Health "healthy" ("" when the service has no healthcheck).
type ServiceState struct {
	State  string
	Health string
}

// ServiceStates reports the state of every service in the instance's compose
// project (honeypots, database, collector, HiFi backends), keyed by service.
func (m *Manager) ServiceStates(ctx context.Context) (map[string]ServiceState, error) {
	composeFile := m.config.GetDockerComposePath()
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composeFile, "ps", "--all", "--format", "json")
	cmd.Dir = m.config.DataPath
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker compose ps: %w", err)
	}
	states := map[string]ServiceState{}
	for svc, e := range parseComposePS(out) {
		states[svc] = ServiceState{State: e.State, Health: e.Health}
	}
	return states, nil
}

// PublishedHostPorts returns the host ports this instance will publish for its
// enabled honeypots (as the compose generator assigns them, avoiding other
// instances' ports), so setup can check they are free before starting.
func PublishedHostPorts(cfg *config.Config) map[string]int {
	ports, subnets := siblingReservations(cfg.DataPath)
	g := &ComposeGenerator{Config: cfg, ReservedPorts: ports, ReservedSubnets: subnets,
		KeepPorts: ownHostPorts(cfg.GetDockerComposePath())}
	return g.buildHostPortMap()
}

// composeProjectName is the compose project docker derives for the instance:
// the compose file's directory name, lowercased.
func composeProjectName(cfg *config.Config) string {
	return strings.ToLower(filepath.Base(cfg.DataPath))
}

// writeSecretFile writes a generated file that carries secrets (the database
// password; the compose file also carries the QPot ID) owner-only, like
// config.yaml and qpot.id. os.WriteFile keeps an existing file's mode, so the
// mode is set explicitly to tighten files written by older versions (0640).
func writeSecretFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// ownershipHelperImage is used to chown host directories for images that run
// as a non-root user (see prepareOwnership). It is the collector image, which
// every instance pulls anyway.
const ownershipHelperImage = CollectorImage

// prepareOwnership hands a honeypot's OwnedSubdirs to the image's user, like
// T-Pot's tpotinit does for its data dirs. A non-root host user cannot chown
// to another uid, so when that fails it runs chown in a throwaway container
// with only CAP_CHOWN, no network and only that directory mounted.
func (m *Manager) prepareOwnership(ctx context.Context, name string) error {
	d := deployProfileFor(name)
	if d.RunAsUID == "" || len(d.OwnedSubdirs) == 0 {
		return nil
	}
	var uid, gid int
	if _, err := fmt.Sscanf(d.RunAsUID, "%d:%d", &uid, &gid); err != nil {
		return fmt.Errorf("bad RunAsUID %q", d.RunAsUID)
	}
	for _, sub := range d.OwnedSubdirs {
		dir := filepath.Join(m.config.DataPath, "honeypots", name, sub)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
		if err := os.Chown(dir, uid, gid); err == nil {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		out, err := exec.CommandContext(cctx, "docker", "run", "--rm", "--network", "none",
			"--cap-drop", "ALL", "--cap-add", "CHOWN", "--security-opt", "no-new-privileges",
			"--user", "0:0", "--entrypoint", "chown", "-v", dir+":/target",
			ownershipHelperImage, d.RunAsUID, "/target").CombinedOutput()
		cancel()
		if err != nil {
			return fmt.Errorf("chown %s: %w: %s", dir, err, out)
		}
	}
	return nil
}

// HostProbePorts returns the published host TCP ports to probe for a honeypot
// that has no in-container healthcheck (NoShell), else nil.
func HostProbePorts(cfg *config.Config, name string) []int {
	if !deployProfileFor(name).NoShell {
		return nil
	}
	tcp, _ := deployPorts(cfg, name)
	all := PublishedHostPorts(cfg)
	var out []int
	for _, p := range tcp {
		if hp, ok := all[portKey(name, p)]; ok {
			out = append(out, hp)
		}
	}
	return out
}

// LLMConfigKeys returns the custom_config keys an LLM-backed honeypot accepts.
func LLMConfigKeys(name string) []string {
	var keys []string
	for k := range deployProfileFor(name).LLMEnv {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// SettingKeys returns every custom_config key `qpot honeypot set` accepts for
// a honeypot: its LLM settings and its other settings (cowrie's persona,
// ssh-proxy's backend count, ...).
func SettingKeys(name string) []string {
	keys := append(LLMConfigKeys(name), deployProfileFor(name).Settings...)
	slices.Sort(keys)
	return keys
}

// ReloadCollector regenerates the instance's configs and, when the stack is
// running, restarts the collector so it uses them (Vector reads its config
// only at start).
func (m *Manager) ReloadCollector(ctx context.Context) error {
	if err := m.Initialize(ctx); err != nil {
		return err
	}
	if !m.IsRunning(ctx) {
		return nil
	}
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", m.config.GetDockerComposePath(), "restart", "collector")
	cmd.Dir = m.config.DataPath
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("restart collector: %w: %s", err, out)
	}
	return nil
}
