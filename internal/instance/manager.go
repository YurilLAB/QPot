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

	// Refuse only when everything is up already: when only some containers
	// run (docker restarted those whose policy says so after an unclean
	// stop), `compose up -d` below starts the others and leaves those alone.
	if m.AllRunning(ctx) {
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
	for _, name := range m.config.GetEnabledHoneypots() {
		if err := m.prepareOwnership(ctx, name); err != nil {
			slog.Warn("Could not hand data dirs to the honeypot's user; it may fail to write its logs", "honeypot", name, "error", err)
		}
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

	if detach {
		// `compose up -d` returns once the containers are created and started.
		// Its exit status matters: a port already allocated, a missing image or
		// an invalid compose file used to be ignored and reported as success.
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("docker compose up failed (see the output above): %w", err)
		}
		// Watch the honeypots settle and log which started / which failed (and
		// why). Non-fatal: a single honeypot failing must not abort the instance.
		m.verifyStartup(ctx, 90*time.Second)
		return nil
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start docker compose: %w", err)
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
	slog.Info("Starting honeypot", "name", name, "instance", m.config.InstanceName)

	// Regenerate the compose file and collector config first: a honeypot
	// enabled on a running instance is not in the existing compose file
	// (`compose up -d <name>` failed with "no such service") and the
	// collector would not tail its logs.
	if err := m.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to regenerate the instance config: %w", err)
	}
	if err := m.prepareOwnership(ctx, name); err != nil {
		slog.Warn("Could not hand data dirs to the honeypot's user", "honeypot", name, "error", err)
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
		return sshBackendServiceNames(m.config)
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
	ports, subnets := siblingReservations(m.config.DataPath)
	generator := &ComposeGenerator{
		Config:          m.config,
		Sandbox:         m.sandbox,
		ReservedPorts:   ports,
		ReservedSubnets: subnets,
		ReservedNets:    hostDockerSubnets(context.Background(), composeProjectName(m.config)),
		KeepPorts:       ownHostPorts(m.config.GetDockerComposePath()),
	}

	compose, err := generator.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate compose: %w", err)
	}

	composePath := m.config.GetDockerComposePath()
	if err := writeSecretFile(composePath, []byte(compose)); err != nil {
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

	// The collector's folders must exist before it starts: Docker would create
	// a missing one owned by root.
	for _, cm := range collectorMounts(m.config) {
		if !cm.Dir {
			continue
		}
		if err := os.MkdirAll(filepath.FromSlash(cm.Host), 0750); err != nil {
			return fmt.Errorf("failed to create collector folder %s: %w", cm.Host, err)
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
			// the same fingerprint), plus a per-backend log dir. The keys are
			// generated here and the dir is mounted read-only into the backends.
			keyDir := filepath.Join(m.config.DataPath, "honeypots", sshBackendDataDir, "shared-hostkeys")
			if err := os.MkdirAll(keyDir, 0o755); err != nil {
				return fmt.Errorf("failed to create ssh-backend host-key dir: %w", err)
			}
			if err := ensureSSHHostKeys(keyDir); err != nil {
				return fmt.Errorf("failed to create ssh-backend host keys: %w", err)
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

	// Don't let Remove "succeed" on a name that doesn't exist: config.Load below
	// auto-creates a default config (and dir), so without this guard
	// `remove <typo>` would create-then-delete an empty instance and report
	// success, masking the typo.
	dir := config.Default(name).DataPath
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("instance %q does not exist", name)
	}

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

	// Remove the instance's own directory, not the data_path its config.yaml
	// names: that comes from a file a hand edit or a restored backup can point
	// anywhere (another user's instance, a home folder), and deleting it took
	// a directory that was never the instance's while leaving the instance
	// behind. A data_path elsewhere is left in place.
	if !samePath(cfg.DataPath, dir) {
		slog.Warn("The instance's data_path is outside its directory; left in place",
			"data_path", cfg.DataPath, "instance_dir", dir)
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("failed to remove data directory: %w", err)
	}

	slog.Info("Instance removed", "name", name)
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
