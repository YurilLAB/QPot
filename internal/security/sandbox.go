// Package security provides security sandboxing for honeypots
package security

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/qpot/qpot/internal/config"
)

// SandboxType represents the type of sandbox to use
type SandboxType string

const (
	SandboxNone     SandboxType = "none"
	SandboxGVisor   SandboxType = "gvisor"
	SandboxKata     SandboxType = "kata"
	SandboxFirejail SandboxType = "firejail"
)

// Sandbox manages container isolation for honeypots
type Sandbox struct {
	config      *config.SecurityConfig
	sandboxType SandboxType
	available   bool
}

// ContainerRuntime returns the Docker runtime that should be set on honeypot
// containers for the active sandbox, or "" to use the default runtime.
//
// It returns a non-empty runtime only when the requested runtime-based sandbox
// is actually AVAILABLE on the host (NewSandbox falls back to SandboxNone when
// it is not). This makes it safe to render unconditionally into compose: if the
// operator asked for gVisor but runsc isn't installed, we emit no runtime line
// rather than producing a compose file that docker refuses to start.
func (sb *Sandbox) ContainerRuntime() string {
	if !sb.available {
		return ""
	}
	switch sb.sandboxType {
	case SandboxGVisor:
		return "runsc"
	case SandboxKata:
		return "kata-runtime"
	default:
		return ""
	}
}

// NewSandbox creates a new sandbox manager
func NewSandbox(cfg *config.SecurityConfig) (*Sandbox, error) {
	sb := &Sandbox{
		config:      cfg,
		sandboxType: SandboxType(cfg.SandboxMode),
	}

	// Check if requested sandbox is available
	switch sb.sandboxType {
	case SandboxGVisor:
		sb.available = sb.checkGVisor()
	case SandboxKata:
		sb.available = sb.checkKata()
	case SandboxFirejail:
		sb.available = sb.checkFirejail()
	case SandboxNone:
		sb.available = true
	default:
		// An unknown/empty sandbox mode (a typo, or an old/partial config) must
		// NOT take the whole platform down: degrade to plain containers and warn,
		// consistent with QPot's "keep the honeypots running even when
		// misconfigured" principle. (config.Load already maps an empty mode to the
		// secure default; this is belt-and-braces for any other unrecognized value.)
		fmt.Printf("Warning: unknown sandbox mode %q; falling back to standard containers\n", sb.sandboxType)
		sb.sandboxType = SandboxNone
		sb.available = true
	}

	// Fall back to none if requested sandbox unavailable
	if !sb.available && sb.sandboxType != SandboxNone {
		fmt.Printf("Warning: %s sandbox not available, falling back to standard containers\n", sb.sandboxType)
		sb.sandboxType = SandboxNone
		sb.available = true
	}

	return sb, nil
}

// checkGVisor checks if gVisor (runsc) is installed
func (sb *Sandbox) checkGVisor() bool {
	_, err := exec.LookPath("runsc")
	return err == nil
}

// checkKata checks if Kata Containers is installed
func (sb *Sandbox) checkKata() bool {
	_, err := exec.LookPath("kata-runtime")
	return err == nil
}

// checkFirejail checks if Firejail is installed
func (sb *Sandbox) checkFirejail() bool {
	_, err := exec.LookPath("firejail")
	return err == nil
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
