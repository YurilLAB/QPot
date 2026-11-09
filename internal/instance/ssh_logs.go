package instance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"github.com/qpot/qpot/internal/config"
)

func sshBackendLogDir(cfg *config.Config, service string) (string, error) {
	store, err := planSSHStore(cfg)
	return store.current(service), err
}

func sshBackendLogDirAt(dataPath, service string) (string, error) {
	store, err := sshStoreAt(dataPath)
	return store.current(service), err
}

func sshBrokerLogDir(cfg *config.Config) (string, error) {
	store, err := planSSHStore(cfg)
	return filepath.Join(store.area(), "logs", "broker"), err
}

// SSHCellLogServices lists every finite service ID whose retained recordings
// belong to the logical ssh-proxy honeypot, including currently retired slots.
func SSHCellLogServices() []string {
	var services []string
	for slot := 1; slot <= maxSSHBackends; slot++ {
		app := fmt.Sprintf("ssh-backend-%d", slot)
		services = append(services, app, app+"-db", app+"-backup")
	}
	return services
}

func prepareSSHLogDir(dataPath, service string) error {
	if sshCellApp(service) == "" {
		return fmt.Errorf("invalid SSH cell log service %q", service)
	}
	store, err := sshStoreAt(dataPath)
	if err != nil {
		return err
	}
	current := store.current(service)
	rel, err := filepath.Rel(store.area(), filepath.Dir(current))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(store.area(), 0o750); err != nil {
		return err
	}
	if err := ensureContainerDirIn(store.area(), rel, 0o750); err != nil {
		return err
	}
	return ensureContainerDir(current, 0o777)
}

// archiveSSHCellLogs runs only after every member has stopped and while holding
// the lifecycle lock. A new guest sees a fresh directory, never the previous
// visitor's recordings. Renaming preserves captured bytes and symlink entries
// without opening any attacker-controlled file inside the recording tree.
func archiveSSHCellLogs(dataPath string, members []string, generation uint64) error {
	store, err := sshStoreAt(dataPath)
	if err != nil {
		return err
	}
	for _, service := range members {
		if sshCellApp(service) == "" {
			return fmt.Errorf("invalid SSH cell archive service %q", service)
		}
		current := store.current(service)
		parent := filepath.Dir(current)
		rel, err := filepath.Rel(store.area(), parent)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(store.area(), 0o750); err != nil {
			return err
		}
		if err := ensureContainerDirIn(store.area(), rel, 0o750); err != nil {
			return fmt.Errorf("prepare private SSH archive directory: %w", err)
		}
		// Before this layout, recordings lived beside the backend host keys.
		// Move them into the same retained host-only archive tree once stopped.
		legacy := filepath.Join(dataPath, "honeypots", sshBackendDataDir, service, "logs")
		for _, source := range []string{current, legacy} {
			info, err := os.Lstat(source)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return fmt.Errorf("inspect SSH recordings before reset: %w", err)
			}
			if !info.IsDir() {
				return fmt.Errorf("SSH recordings path must be a real directory: %s", source)
			}
			directory, err := os.Open(source)
			if err != nil {
				return fmt.Errorf("inspect stopped SSH recordings: %w", err)
			}
			// Only test emptiness. A guest can create arbitrarily many entries;
			// reading the whole directory into host memory is unnecessary.
			entries, readErr := directory.Readdirnames(1)
			closeErr := directory.Close()
			if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil {
				return fmt.Errorf("inspect stopped SSH recordings: %w", errors.Join(readErr, closeErr))
			}
			if len(entries) == 0 {
				if err := os.Remove(source); err != nil {
					return fmt.Errorf("remove empty stopped SSH recordings: %w", err)
				}
				continue
			}
			archive, err := os.MkdirTemp(parent, fmt.Sprintf("archive-g%d-", generation))
			if err != nil {
				return fmt.Errorf("reserve private SSH recording archive: %w", err)
			}
			if err := os.Rename(source, filepath.Join(archive, "logs")); err != nil {
				_ = os.Remove(archive)
				return fmt.Errorf("archive stopped SSH recordings: %w", err)
			}
		}
		if err := ensureContainerDir(current, 0o777); err != nil {
			return fmt.Errorf("create fresh SSH recording directory: %w", err)
		}
	}
	return nil
}

func stopSSHServices(ctx context.Context, composeFile string, services []string) error {
	if len(services) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	args := append([]string{"compose", "-f", composeFile, "stop", "--timeout", "10"}, services...)
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = filepath.Dir(composeFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("stop SSH cell before discarding visitor state: %w: %s", err, output)
	}
	return nil
}

// prepareSSHDeployment is the operator counterpart of a normal lease reset.
// Stopping the broker prevents an existing pool from leasing during deployment;
// its next process starts quarantined and requests a trusted whole-cell reset.
func (m *Manager) prepareSSHDeployment(ctx context.Context) error {
	if !sshProxyEnabled(m.config) {
		return nil
	}
	layout, err := readSSHLayout(m.config.GetDockerComposePath(), m.config.InstanceName)
	if err != nil {
		return err
	}
	services := []string{sshProxyHoneypot}
	apps := make([]string, 0, len(layout.Groups))
	for app, members := range layout.Groups {
		apps = append(apps, app)
		services = append(services, members...)
	}
	sort.Strings(apps)
	if err := stopSSHServices(ctx, m.config.GetDockerComposePath(), services); err != nil {
		return err
	}
	recycler, err := NewBackendRecycler(m.config)
	if err != nil {
		return err
	}
	if err := drainSSHCaptures(ctx, m.config.DataPath, m.config.InstanceName, recycler.LogPath, services); err != nil {
		return fmt.Errorf("the SSH cells are stopped but kept: %w", err)
	}
	for _, app := range apps {
		if err := archiveSSHCellLogs(m.config.DataPath, layout.Groups[app], recycler.generation(app)); err != nil {
			return err
		}
	}
	// A normal compose up may restart an existing stopped container. Remove
	// only these stopped HiFi containers so even that path gets fresh writable
	// layers and binds the newly created current recording directories.
	removeCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	args := append([]string{"compose", "-f", m.config.GetDockerComposePath(), "rm", "--force"}, services...)
	cmd := exec.CommandContext(removeCtx, "docker", args...)
	cmd.Dir = m.config.DataPath
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("remove stopped SSH cells before fresh deployment: %w: %s", err, output)
	}
	return nil
}
