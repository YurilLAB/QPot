package instance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/hostsetup"
	"github.com/qpot/qpot/internal/security"
	"gopkg.in/yaml.v3"
)

// SandboxStatus reports the configured policy and runtimes actually observed
// on this instance's containers. An installed binary is not runtime evidence.
type SandboxStatus struct {
	Requested      string            `json:"requested"`
	FallbackPolicy string            `json:"fallback_policy"`
	Runtime        string            `json:"runtime"`
	Fallback       bool              `json:"fallback"`
	Verified       bool              `json:"verified"`
	Services       map[string]string `json:"services"`
	Code           string            `json:"code,omitempty"`
}

// Only these reviewed protocol emulators may use an explicitly approved
// fallback. Unknown sensors and real execution services (including Tanner's
// PHP companion and HiFi SSH) retain the requested stronger runtime.
func requiresStrongSandbox(cfg *config.Config, targets ...string) bool {
	names := append(cfg.GetEnabledHoneypots(), targets...)
	for _, name := range names {
		switch name {
		case "cowrie", "conpot", "refrigeration":
		default:
			return true
		}
	}
	return false
}

func resolveSandbox(ctx context.Context, cfg *config.Config, targets ...string) (security.RuntimeSelection, error) {
	sb, err := security.NewSandbox(&cfg.Security)
	if err != nil {
		return security.RuntimeSelection{}, err
	}
	if len(cfg.GetEnabledHoneypots()) == 0 && len(targets) == 0 {
		return sb.Selection() // A control-only deployment has no guest runtime.
	}
	return sb.ResolveForStart(ctx, requiresStrongSandbox(cfg, targets...))
}

func sandboxServices(cfg *config.Config, manager *Manager) []string {
	seen := map[string]bool{}
	for _, name := range cfg.GetEnabledHoneypots() {
		seen[name] = true
		for _, companion := range manager.companionServices(name) {
			seen[companion] = true
		}
	}
	services := make([]string, 0, len(seen))
	for name := range seen {
		services = append(services, name)
	}
	sort.Strings(services)
	return services
}

func validateSandboxCompose(cfg *config.Config, path string, services []string, selection security.RuntimeSelection) error {
	sb, _ := security.NewSandbox(&cfg.Security)
	if err := sb.ValidateSelection(selection, requiresStrongSandbox(cfg)); err != nil {
		return err
	}
	if selection.Runtime == "" {
		return nil // Standard Docker was explicitly selected or approved.
	}
	f, err := os.Open(path)
	if err != nil {
		return hostsetup.E("QP-DOCKER-012").Wrap(err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	if err != nil || len(data) > 4<<20 {
		return hostsetup.E("QP-DOCKER-012").WithWhy("The stored deployment could not be read within its size bound.").Wrap(err)
	}
	var document struct {
		Services map[string]struct {
			Runtime string            `yaml:"runtime"`
			Labels  map[string]string `yaml:"labels"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		return hostsetup.E("QP-DOCKER-012").Wrap(err)
	}
	for _, name := range services {
		service, ok := document.Services[name]
		if !ok || service.Labels["qpot.instance"] != cfg.InstanceName || service.Labels["qpot.honeypot"] == "" || service.Runtime != selection.Runtime {
			return hostsetup.E("QP-DOCKER-012").WithWhy("Stored service %q does not declare the required runtime %q.", name, selection.Runtime)
		}
	}
	return nil
}

type sandboxContainer struct {
	ID       string `json:"id"`
	Runtime  string `json:"runtime"`
	Service  string `json:"service"`
	Instance string `json:"instance"`
	Honeypot string `json:"honeypot"`
	Running  bool   `json:"running"`
}

// Inspect only identity/runtime metadata; Docker's full container report can
// contain credentials and must not enter health responses or error messages.
const sandboxInspectFormat = `{"id":{{json .Id}},"runtime":{{json .HostConfig.Runtime}},"service":{{json (index .Config.Labels "com.docker.compose.service")}},"instance":{{json (index .Config.Labels "qpot.instance")}},"honeypot":{{json (index .Config.Labels "qpot.honeypot")}},"running":{{json .State.Running}}}`

type sandboxOutput struct{ buffer bytes.Buffer }

func (b *sandboxOutput) Bytes() []byte { return b.buffer.Bytes() }

func (b *sandboxOutput) Write(p []byte) (int, error) {
	if len(p) > (4<<20)-b.buffer.Len() {
		return 0, fmt.Errorf("docker isolation report exceeds its size bound")
	}
	return b.buffer.Write(p)
}

func sandboxDocker(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "docker", args...)
	var output sandboxOutput
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func inspectSandboxContainers(ctx context.Context, cfg *config.Config) ([]sandboxContainer, error) {
	output, err := sandboxDocker(ctx, "ps", "--all", "--quiet", "--no-trunc", "--filter", "label=qpot.instance="+cfg.InstanceName, "--filter", "label=qpot.honeypot")
	if err != nil {
		return nil, hostsetup.E("QP-DOCKER-012").Wrap(err)
	}
	ids := strings.Fields(string(output))
	if len(ids) == 0 {
		return nil, nil
	}
	if len(ids) > 512 {
		return nil, hostsetup.E("QP-DOCKER-012").WithWhy("Too many containers in the isolation report.")
	}
	uniqueIDs := map[string]bool{}
	for _, id := range ids {
		if len(id) != 64 || strings.Trim(id, "0123456789abcdef") != "" {
			return nil, hostsetup.E("QP-DOCKER-012").WithWhy("Docker returned an invalid container identity.")
		}
		if uniqueIDs[id] {
			return nil, hostsetup.E("QP-DOCKER-012").WithWhy("Docker returned duplicate container identities.")
		}
		uniqueIDs[id] = true
	}
	output, err = sandboxDocker(ctx, append([]string{"inspect", "--format", sandboxInspectFormat}, ids...)...)
	if err != nil {
		return nil, hostsetup.E("QP-DOCKER-012").Wrap(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	wanted := map[string]bool{}
	for _, id := range ids {
		wanted[id] = true
	}
	seen := map[string]bool{}
	var containers []sandboxContainer
	for {
		var container sandboxContainer
		err := decoder.Decode(&container)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, hostsetup.E("QP-DOCKER-012").Wrap(err)
		}
		if !wanted[container.ID] || seen[container.ID] || container.Instance != cfg.InstanceName || container.Honeypot == "" || container.Service == "" || container.Runtime == "" {
			return nil, hostsetup.E("QP-DOCKER-012").WithWhy("Docker returned incomplete or foreign isolation metadata.")
		}
		seen[container.ID] = true
		containers = append(containers, container)
	}
	if len(seen) != len(wanted) {
		return nil, hostsetup.E("QP-DOCKER-012").WithWhy("Docker omitted containers from its isolation report.")
	}
	return containers, nil
}

func verifySandboxContainers(ctx context.Context, cfg *config.Config, services []string, selection security.RuntimeSelection) error {
	if selection.Runtime == "" {
		return nil
	}
	containers, err := inspectSandboxContainers(ctx, cfg)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, container := range containers {
		for _, name := range services {
			if container.Service == name {
				if seen[name] || container.Runtime != selection.Runtime {
					return hostsetup.E("QP-DOCKER-012").WithWhy("Container for %q does not use the required runtime %q.", name, selection.Runtime)
				}
				seen[name] = true
			}
		}
	}
	for _, name := range services {
		if !seen[name] {
			return hostsetup.E("QP-DOCKER-012").WithWhy("No verified container exists for %q.", name)
		}
	}
	return nil
}

// A daemon/runtime mismatch must not leave the newly started guests exposed.
// Only generated service IDs from this instance reach the stop command.
func (m *Manager) verifyStartedSandbox(ctx context.Context, services []string, selection security.RuntimeSelection) error {
	if err := verifySandboxContainers(ctx, m.config, services, selection); err != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		args := append([]string{"compose", "-f", m.config.GetDockerComposePath(), "stop", "--timeout", "5"}, services...)
		command := exec.CommandContext(stopCtx, "docker", args...)
		command.Dir = m.config.DataPath
		stopErr := command.Run()
		if stopErr != nil {
			return hostsetup.E("QP-DOCKER-012").WithWhy("Runtime verification failed and the affected guests could not be stopped; stop the owned deployment immediately.").Wrap(errors.Join(err, stopErr))
		}
		return err
	}
	return nil
}

// SandboxStatus is read-only and remains available after isolation failures.
func (m *Manager) SandboxStatus(ctx context.Context) (status SandboxStatus, err error) {
	status.Services = map[string]string{}
	status.Requested = m.config.Security.SandboxMode
	if status.Requested == "" {
		status.Requested = "gvisor"
	}
	status.FallbackPolicy = m.config.Security.SandboxFallback
	if status.FallbackPolicy == "" {
		status.FallbackPolicy = "deny"
	}
	defer func() {
		var coded *hostsetup.Error
		if errors.As(err, &coded) && coded != nil {
			status.Code = coded.Code
		}
	}()
	containers, err := inspectSandboxContainers(ctx, m.config)
	if err != nil {
		return status, err
	}
	var targets []string
	for _, container := range containers {
		if !container.Running {
			continue
		}
		if _, duplicate := status.Services[container.Service]; duplicate {
			return status, hostsetup.E("QP-DOCKER-012").WithWhy("Multiple running containers use one service identity.")
		}
		status.Services[container.Service] = container.Runtime
		targets = append(targets, container.Honeypot)
		if status.Runtime == "" {
			status.Runtime = container.Runtime
		} else if status.Runtime != container.Runtime {
			status.Runtime = "mixed"
		}
	}
	selection, err := resolveSandbox(ctx, m.config, targets...)
	if err != nil {
		return status, err
	}
	status.Fallback = selection.Fallback
	if status.Fallback && status.Runtime != "mixed" {
		declared, _ := security.NewSandbox(&m.config.Security)
		if status.Runtime == declared.ContainerRuntime() {
			status.Fallback = false // Already-running guests still use the stronger runtime.
		}
	}
	for _, actual := range status.Services {
		if selection.Runtime != "" && actual != selection.Runtime {
			return status, hostsetup.E("QP-DOCKER-012").WithWhy("A running honeypot does not use the requested runtime.")
		}
	}
	status.Verified = len(status.Services) > 0
	return status, nil
}
