// Package security provides security sandboxing for honeypots
package security

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/hostsetup"
)

var (
	warnMu  sync.Mutex
	warned  = map[string]bool{}
	warnOut io.Writer // nil: standard output
)

// SetWarningOutput sends explicit sandbox fallback warnings to w (nil: standard
// output) and returns the previous setting.
func SetWarningOutput(w io.Writer) io.Writer {
	warnMu.Lock()
	defer warnMu.Unlock()
	prev := warnOut
	warnOut = w
	return prev
}

// warnOnce prints a fallback warning once per process, so a command that
// builds several managers prints it once.
func warnOnce(msg string) {
	warnMu.Lock()
	defer warnMu.Unlock()
	if warned[msg] {
		return
	}
	warned[msg] = true
	w := warnOut
	if w == nil {
		w = os.Stdout
	}
	fmt.Fprint(w, msg)
}

// SandboxType represents the type of sandbox to use
type SandboxType string

const (
	SandboxNone   SandboxType = "none"
	SandboxGVisor SandboxType = "gvisor"
	SandboxKata   SandboxType = "kata"
)

// RuntimeSelection describes both the operator's requested isolation and the
// runtime selected for an operation. An empty Runtime explicitly means Docker's
// default runtime; it must never be inferred from a failed availability probe.
type RuntimeSelection struct {
	Requested SandboxType `json:"requested"`
	Effective SandboxType `json:"effective"`
	Runtime   string      `json:"runtime"`
	Fallback  bool        `json:"fallback"`
}

// Sandbox retains a snapshot of the declared isolation policy. Live runtime
// availability is checked by ResolveForStart, not by construction or rendering.
type Sandbox struct {
	mode     SandboxType
	fallback string
}

// ContainerRuntime returns the declared runtime, independent of availability.
// Call Selection before rendering and ResolveForStart before deployment; an
// unsupported policy must not reach execution just because this returns "".
func (sb *Sandbox) ContainerRuntime() string {
	switch sb.requestedMode() {
	case SandboxGVisor:
		return "runsc"
	case SandboxKata:
		return "kata-runtime"
	default:
		return ""
	}
}

// NewSandbox captures the configured policy without probing Docker. Keeping
// construction available lets operators inspect and stop a deployment even
// when its requested runtime was removed or its saved policy is invalid.
func NewSandbox(cfg *config.SecurityConfig) (*Sandbox, error) {
	sb := &Sandbox{}
	if cfg != nil {
		sb.mode = SandboxType(cfg.SandboxMode)
		sb.fallback = cfg.SandboxFallback
	}
	return sb, nil
}

func (sb *Sandbox) requestedMode() SandboxType {
	if sb == nil || sb.mode == "" {
		return SandboxGVisor
	}
	return sb.mode
}

func (sb *Sandbox) fallbackPolicy() string {
	if sb == nil || sb.fallback == "" {
		return "deny"
	}
	return sb.fallback
}

// Selection validates the declared policy without querying a live daemon.
// Firejail is not supported: finding an executable never applied it to Docker.
func (sb *Sandbox) Selection() (RuntimeSelection, error) {
	mode, fallback := sb.requestedMode(), sb.fallbackPolicy()
	if mode != SandboxNone && mode != SandboxGVisor && mode != SandboxKata {
		return RuntimeSelection{}, hostsetup.E("QP-DOCKER-010").WithWhy("Unsupported sandbox mode %q.", mode)
	}
	if fallback != "deny" && fallback != "docker" {
		return RuntimeSelection{}, hostsetup.E("QP-DOCKER-010").WithWhy("Unsupported sandbox fallback policy %q.", fallback)
	}
	return RuntimeSelection{Requested: mode, Effective: mode, Runtime: sb.ContainerRuntime()}, nil
}

// ResolveForStart checks the execution daemon afresh. A registered runtime on a
// remote Docker host does not need a matching executable on the QPot client.
// Only an explicit fallback policy may select ordinary Docker, and requested
// stronger isolation never falls back for high-interaction deployments.
func (sb *Sandbox) ResolveForStart(ctx context.Context, highInteraction bool) (RuntimeSelection, error) {
	selection, err := sb.Selection()
	if err != nil {
		return RuntimeSelection{}, err
	}
	if ctx == nil {
		return RuntimeSelection{}, hostsetup.E("QP-DOCKER-011").WithWhy("Runtime validation requires an operation context.")
	}
	if err := ctx.Err(); err != nil {
		return RuntimeSelection{}, hostsetup.E("QP-DOCKER-011").Wrap(err)
	}
	if selection.Effective == SandboxNone {
		return selection, nil
	}
	runtimes, err := dockerRuntimes(ctx)
	if err != nil {
		return RuntimeSelection{}, hostsetup.E("QP-DOCKER-011").Wrap(err)
	}
	if len(runtimes) == 0 {
		return RuntimeSelection{}, hostsetup.E("QP-DOCKER-011").WithWhy("Docker did not provide a runtime registry.")
	}
	if _, registered := runtimes[selection.Runtime]; registered {
		return selection, nil
	}
	if highInteraction || sb.fallbackPolicy() != "docker" {
		return RuntimeSelection{}, hostsetup.E("QP-DOCKER-011").WithWhy("The requested Docker runtime %q is not registered.", selection.Runtime)
	}
	selection.Effective, selection.Runtime, selection.Fallback = SandboxNone, "", true
	warnOnce(fmt.Sprintf("Warning: %s is unavailable; explicit sandbox_fallback=docker selects standard Docker isolation\n", selection.Requested))
	return selection, nil
}

// ValidateSelection verifies that a resolved selection belongs to this policy.
// It does not replace the live availability check in ResolveForStart.
func (sb *Sandbox) ValidateSelection(selection RuntimeSelection, highInteraction bool) error {
	declared, err := sb.Selection()
	if err != nil {
		return err
	}
	if selection == declared {
		return nil
	}
	if !highInteraction && sb.fallbackPolicy() == "docker" && declared.Requested != SandboxNone && selection == (RuntimeSelection{Requested: declared.Requested, Effective: SandboxNone, Fallback: true}) {
		return nil
	}
	return hostsetup.E("QP-DOCKER-012").WithWhy("The selected runtime does not match the configured sandbox policy.")
}

// dockerRuntimes returns the OCI runtimes the Docker daemon has registered.
// A variable so tests can stub the daemon.
var dockerRuntimes = func(parent context.Context) (map[string]json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{json .Runtimes}}").Output()
	if err != nil {
		return nil, err
	}
	var rt map[string]json.RawMessage
	if err := json.Unmarshal(out, &rt); err != nil {
		return nil, err
	}
	return rt, nil
}

func (sb *Sandbox) ValidateHost() error {
	checks := []struct {
		name string
		fn   func() error
	}{
		{"Docker", sb.checkDocker},
		{"User namespaces", sb.checkUserNamespaces},
		{"AppArmor", sb.checkAppArmor},
		{"Seccomp", sb.checkSeccomp},
		{"Cgroup v2", sb.checkCgroupV2},
	}

	var errors []string
	for _, check := range checks {
		if err := check.fn(); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", check.name, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("host validation failed:\n  - %s",
			strings.Join(errors, "\n  - "))
	}

	return nil
}

func (sb *Sandbox) checkDocker() error {
	_, err := exec.LookPath("docker")
	if err != nil {
		return fmt.Errorf("docker not found in PATH")
	}
	return nil
}

func (sb *Sandbox) checkUserNamespaces() error {
	if runtime.GOOS == "linux" {
		// Check if user namespaces are enabled
		data, err := os.ReadFile("/proc/sys/user/max_user_namespaces")
		if err != nil {
			return fmt.Errorf("user namespaces may not be enabled")
		}
		if strings.TrimSpace(string(data)) == "0" {
			return fmt.Errorf("user namespaces are disabled")
		}
	}
	return nil
}

func (sb *Sandbox) checkAppArmor() error {
	if runtime.GOOS == "linux" {
		_, err := exec.LookPath("aa-status")
		if err != nil {
			return fmt.Errorf("AppArmor not available")
		}
	}
	return nil
}

func (sb *Sandbox) checkSeccomp() error {
	// Check if seccomp is supported by kernel
	if runtime.GOOS == "linux" {
		_, err := os.Stat("/proc/self/seccomp")
		if err != nil {
			// Try alternative check
			_, err = os.Stat("/sys/kernel/seccomp")
			if err != nil {
				return fmt.Errorf("seccomp may not be supported")
			}
		}
	}
	return nil
}

func (sb *Sandbox) checkCgroupV2() error {
	if runtime.GOOS == "linux" {
		_, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
		if err != nil {
			return fmt.Errorf("cgroup v2 not available (using v1)")
		}
	}
	return nil
}
