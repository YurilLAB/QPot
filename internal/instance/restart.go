package instance

import (
	"context"
	"fmt"
	"os/exec"
)

// RestartHoneypot restarts a honeypot's container, and its companions
// (ssh-proxy's real-OpenSSH backends, tanner's services), as
// `docker compose restart` does: the same containers with the same settings.
// Only a configured honeypot's name ever reaches docker's argv.
func (m *Manager) RestartHoneypot(ctx context.Context, name string) error {
	if !m.isConfiguredHoneypot(name) {
		return fmt.Errorf("unknown honeypot: %q", name)
	}
	args := append([]string{"compose", "-f", m.config.GetDockerComposePath(), "restart", name}, m.companionServices(name)...)
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = m.config.DataPath
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to restart honeypot: %w\nOutput: %s", err, out)
	}
	return nil
}
