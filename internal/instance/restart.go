package instance

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/qpot/qpot/internal/config"
)

// RestartHoneypot restarts a honeypot's container, and its companions
// (ssh-proxy's real-OpenSSH backends, tanner's services), as
// `docker compose restart` does: the same containers with the same settings.
// Only a configured honeypot's name ever reaches docker's argv.
func (m *Manager) RestartHoneypot(ctx context.Context, name string) error {
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
	selection, err := resolveSandbox(ctx, m.config, name)
	if err != nil {
		return err
	}
	if name == sshProxyHoneypot || selection.Runtime != "" {
		cellLock, err := lockSSHCells(ctx, m.config.DataPath)
		if err != nil {
			return fmt.Errorf("lock honeypot restart: %w", err)
		}
		defer cellLock.Close()
		selection, err = resolveSandbox(ctx, m.config, name)
		if err != nil {
			return err
		}
	}
	if name == sshProxyHoneypot {
		layout, err := readSSHLayout(m.config.GetDockerComposePath(), m.config.InstanceName)
		if err != nil {
			return err
		}
		if err := validateSSHLayoutImages(layout, HiFiImageRevision); err != nil {
			return err
		}
		if err := sshStoreReady(m.config.DataPath); err != nil {
			return err
		}
		// Recheck after taking the lifecycle lock so a concurrent deployment
		// cannot replace the already inspected document before restart.
		layout, err = readSSHLayout(m.config.GetDockerComposePath(), m.config.InstanceName)
		if err != nil {
			return err
		}
		if err := validateSSHLayoutImages(layout, HiFiImageRevision); err != nil {
			return err
		}
		if err := validateSSHRuntimeResources(ctx); err != nil {
			return err
		}
	}
	if err := checkContainment(ctx, m.config, name); err != nil {
		return err
	}
	services := append([]string{name}, m.companionServices(name)...)
	if err := validateSandboxCompose(m.config, m.config.GetDockerComposePath(), services, selection); err != nil {
		return err
	}
	if err := verifySandboxContainers(ctx, m.config, services, selection); err != nil {
		return err
	}
	args := append([]string{"compose", "-f", m.config.GetDockerComposePath(), "restart"}, services...)
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = m.config.DataPath
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to restart honeypot: %w\nOutput: %s", err, out)
	}
	return m.verifyStartedSandbox(ctx, services, selection)
}
