// Package instance manages QPot instances
package instance

import (
	"bufio"
	"context"
	"fmt"
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
	Overall   string            `json:"overall"`
	Honeypots []HoneypotStatus  `json:"honeypots"`
	Database  string            `json:"database"`
	Uptime    time.Duration     `json:"uptime"`
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

// db returns the database connection, creating it on first call.
// Callers that need the database (e.g. Start) should call this and handle
// the error explicitly.
func (m *Manager) db() (database.Database, error) {
	m.dbOnce.Do(func() {
		m.database, m.dbErr = database.New(&m.config.Database)
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
		return nil
	}

	// When not detached, wait for the process in a goroutine so we can also
	// poll for health. The process ends when docker compose exits.
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()

	// Wait for startup
	if err := m.waitForHealthy(ctx); err != nil {
		return fmt.Errorf("services failed to become healthy: %w", err)
	}

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

	// Parse container status (simplified)
	for name, hp := range m.config.Honeypots {
		hs := HoneypotStatus{
			Name: name,
			Port: hp.Port,
			Risk: hp.RiskLevel,
		}

		if hp.Enabled {
			// Check if container is running
			if strings.Contains(string(output), name) {
				hs.Running = true
				hs.Status = "healthy"
			} else {
				hs.Status = "stopped"
			}
		} else {
			hs.Status = "disabled"
		}

		status.Honeypots = append(status.Honeypots, hs)
	}

	return status, nil
}

// StartHoneypot starts a specific honeypot
func (m *Manager) StartHoneypot(ctx context.Context, name string) error {
	slog.Info("Starting honeypot", "name", name, "instance", m.config.InstanceName)

	composeFile := m.config.GetDockerComposePath()
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composeFile, "up", "-d", name)
	cmd.Dir = m.config.DataPath

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start honeypot: %w\nOutput: %s", err, output)
	}

	return nil
}

// StopHoneypot stops a specific honeypot
func (m *Manager) StopHoneypot(ctx context.Context, name string) error {
	slog.Info("Stopping honeypot", "name", name, "instance", m.config.InstanceName)

	composeFile := m.config.GetDockerComposePath()
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composeFile, "stop", name)
	cmd.Dir = m.config.DataPath

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop honeypot: %w\nOutput: %s", err, output)
	}

	return nil
}

// GetLogs returns logs for a honeypot or all honeypots
func (m *Manager) GetLogs(ctx context.Context, honeypot string, follow bool, tail int) (<-chan string, error) {
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
		defer close(logs)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				cmd.Process.Kill()
				return
			case logs <- scanner.Text():
			}
		}
		cmd.Wait()
	}()

	return logs, nil
}

// waitForHealthy waits for services to become healthy
func (m *Manager) waitForHealthy(ctx context.Context) error {
	timeout := time.After(2 * time.Minute)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for services")
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if m.isHealthy(ctx) {
				return nil
			}
		}
	}
}

// isHealthy checks if all services are healthy.
// Returns false when no containers are running, when any container is
// unhealthy/exited, or when containers are still starting up.
func (m *Manager) isHealthy(ctx context.Context) bool {
	composeFile := m.config.GetDockerComposePath()
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composeFile, "ps", "-a", "--format", "table {{.Name}}\t{{.Status}}")
	cmd.Dir = m.config.DataPath

	output, err := cmd.Output()
	if err != nil {
		return false
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	// The first line is the header; if there are no service rows the stack is
	// not running and we must not report healthy.
	serviceRows := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Skip the header row produced by the "table" format.
		if strings.HasPrefix(trimmed, "NAME") {
			continue
		}
		serviceRows++
		// Any of these states means we are not yet fully healthy.
		if strings.Contains(line, "unhealthy") ||
			strings.Contains(line, "Exit") ||
			strings.Contains(line, "starting") ||
			strings.Contains(line, "health: starting") {
			return false
		}
	}

	return serviceRows > 0
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
