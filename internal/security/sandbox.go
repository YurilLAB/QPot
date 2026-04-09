// Package security provides security sandboxing for honeypots
package security

import (
	cryptorand "crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/qpot/qpot/internal/config"
)

// SandboxType represents the type of sandbox to use
type SandboxType string

const (
	SandboxNone    SandboxType = "none"
	SandboxGVisor  SandboxType = "gvisor"
	SandboxKata    SandboxType = "kata"
	SandboxFirejail SandboxType = "firejail"
)

// Sandbox manages container isolation for honeypots
type Sandbox struct {
	config      *config.SecurityConfig
	sandboxType SandboxType
	available   bool
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
		return nil, fmt.Errorf("unknown sandbox type: %s", sb.sandboxType)
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

// GetDockerSecurityOptions returns Docker security options for honeypots
func (sb *Sandbox) GetDockerSecurityOptions(honeypot string, hpConfig config.HoneypotConfig) []string {
	// Get effective resource limits
	var limits config.ResourceLimits
	if hpConfig.Resources.UseCustomLimits {
		limits = config.ResourceLimits{
			MaxCPUPercent:   hpConfig.Resources.MaxCPUPercent,
			MaxMemoryMB:     hpConfig.Resources.MaxMemoryMB,
			MaxStorageGB:    hpConfig.Resources.MaxStorageGB,
			MaxPids:         hpConfig.Resources.MaxPids,
			RestartAttempts: sb.config.ResourceLimits.RestartAttempts,
		}
	} else {
		limits = sb.config.ResourceLimits
	}

	var opts []string

	// Resource limits
	if limits.MaxMemoryMB > 0 {
		opts = append(opts, fmt.Sprintf("--memory=%dm", limits.MaxMemoryMB))
		// Also set swap limit to prevent swap abuse
		opts = append(opts, fmt.Sprintf("--memory-swap=%dm", limits.MaxMemoryMB))
	}
	if limits.MaxCPUPercent > 0 {
		cpus := limits.MaxCPUPercent / 100.0
		opts = append(opts, fmt.Sprintf("--cpus=%.2f", cpus))
		// CPU period and quota for finer control
		opts = append(opts, "--cpu-period=100000")
		opts = append(opts, fmt.Sprintf("--cpu-quota=%d", int(cpus*100000)))
	}
	if limits.MaxPids > 0 {
		opts = append(opts, fmt.Sprintf("--pids-limit=%d", limits.MaxPids))
	}
	if hpConfig.Resources.MaxFileDescriptors > 0 {
		opts = append(opts, fmt.Sprintf("--ulimit nofile=%d:%d", 
			hpConfig.Resources.MaxFileDescriptors, 
			hpConfig.Resources.MaxFileDescriptors))
	}

	// Memory protections
	opts = append(opts, "--memory-swappiness=0")        // Disable swap
	opts = append(opts, "--oom-kill-disable=false")     // Allow OOM kill
	opts = append(opts, "--shm-size=64m")               // Limit shared memory

	// Security options
	if sb.config.NoNewPrivileges {
		opts = append(opts, "--security-opt=no-new-privileges:true")
	}
	if sb.config.DropCapabilities {
		opts = append(opts, "--cap-drop=ALL")
		// Only add minimal capabilities needed
		if hpConfig.Port < 1024 {
			opts = append(opts, "--cap-add=NET_BIND_SERVICE")
		}
		opts = append(opts, "--cap-add=SETUID")
		opts = append(opts, "--cap-add=SETGID")
	}
	if sb.config.ReadOnlyFilesystem {
		opts = append(opts, "--read-only")
	}
	
	// Seccomp profile
	if sb.config.RuntimeSecurity.EnableSeccompProfile {
		profile := sb.getSeccompProfile(honeypot)
		if profile != "" {
			opts = append(opts, fmt.Sprintf("--security-opt=seccomp=%s", profile))
		}
	}
	
	// AppArmor
	if sb.config.EnableAppArmor {
		profile := sb.getAppArmorProfile(honeypot)
		opts = append(opts, fmt.Sprintf("--security-opt=apparmor=%s", profile))
	}

	// SELinux
	if runtime.GOOS == "linux" {
		opts = append(opts, "--security-opt=label=type:container_runtime_t")
	}

	// User namespace (rootless)
	opts = append(opts, "--user=1000:1000")

	// Group additions for required permissions
	opts = append(opts, "--group-add=999")  // docker group equivalent

	// Network isolation
	if sb.config.NetworkIsolation.SeparateNetworks {
		// Each honeypot gets its own network
		opts = append(opts, fmt.Sprintf("--network=%s_net", honeypot))
	}
	if sb.config.NetworkIsolation.RandomizeMAC {
		opts = append(opts, fmt.Sprintf("--mac-address=%s", sb.generateRandomMAC()))
	}

	// Hostname isolation
	if sb.config.RuntimeSecurity.IsolateHostname {
		if hpConfig.Stealth.FakeHostname != "" {
			opts = append(opts, fmt.Sprintf("--hostname=%s", hpConfig.Stealth.FakeHostname))
		} else {
			opts = append(opts, fmt.Sprintf("--hostname=%s-host", honeypot))
		}
	}

	// Process hiding - use PID namespace
	opts = append(opts, "--pid=container")

	// IPC namespace
	opts = append(opts, "--ipc=private")

	// UTS namespace for hostname isolation
	opts = append(opts, "--uts=private")

	// Device restrictions
	opts = append(opts, "--device-read-bps=/dev/null:1mb")
	opts = append(opts, "--device-write-bps=/dev/null:1mb")

	// Sandbox runtime
	switch sb.sandboxType {
	case SandboxGVisor:
		opts = append(opts, "--runtime=runsc")
		// gVisor-specific options
		opts = append(opts, "--security-opt=seccomp=unconfined")  // gVisor handles this
	case SandboxKata:
		opts = append(opts, "--runtime=kata-runtime")
	}

	// Restart policy
	if limits.RestartAttempts >= 0 {
		opts = append(opts, fmt.Sprintf("--restart=on-failure:%d", limits.RestartAttempts))
	}

	return opts
}

// GetComposeSecurityExtensions returns Docker Compose security extensions
func (sb *Sandbox) GetComposeSecurityExtensions(honeypot string, hpConfig config.HoneypotConfig) map[string]interface{} {
	ext := make(map[string]interface{})

	// Get effective resource limits
	var limits config.ResourceLimits
	if hpConfig.Resources.UseCustomLimits {
		limits = config.ResourceLimits{
			MaxCPUPercent:   hpConfig.Resources.MaxCPUPercent,
			MaxMemoryMB:     hpConfig.Resources.MaxMemoryMB,
			MaxStorageGB:    hpConfig.Resources.MaxStorageGB,
			MaxPids:         hpConfig.Resources.MaxPids,
			RestartAttempts: sb.config.ResourceLimits.RestartAttempts,
		}
	} else {
		limits = sb.config.ResourceLimits
	}

	// Resource limits
	ext["deploy"] = map[string]interface{}{
		"resources": map[string]interface{}{
			"limits": map[string]interface{}{
				"cpus":   fmt.Sprintf("%.2f", limits.MaxCPUPercent/100.0),
				"memory": fmt.Sprintf("%dm", limits.MaxMemoryMB),
				"pids":   limits.MaxPids,
			},
			"reservations": map[string]interface{}{
				"cpus":   "0.1",
				"memory": "64M",
			},
		},
		"restart_policy": map[string]interface{}{
			"condition":    "on-failure",
			"max_attempts": limits.RestartAttempts,
			"window":       "120s",
		},
	}

	// Security options
	if sb.config.NoNewPrivileges {
		ext["security_opt"] = []string{"no-new-privileges:true"}
	}

	if sb.config.DropCapabilities {
		ext["cap_drop"] = []string{"ALL"}
		caps := []string{"SETUID", "SETGID"}
		if hpConfig.Port < 1024 {
			caps = append(caps, "NET_BIND_SERVICE")
		}
		ext["cap_add"] = caps
	}

	if sb.config.ReadOnlyFilesystem {
		ext["read_only"] = true
		tmpfs := []string{
			"/tmp:noexec,nosuid,size=100m",
			"/var/tmp:noexec,nosuid,size=100m",
			"/run:noexec,nosuid,size=10m",
		}
		if sb.config.SandboxMode == "gvisor" {
			// gVisor needs more tmpfs mounts
			tmpfs = append(tmpfs, "/proc:size=1m")
		}
		ext["tmpfs"] = tmpfs
	}

	// User
	ext["user"] = "1000:1000"

	// Hostname
	if sb.config.RuntimeSecurity.IsolateHostname {
		if hpConfig.Stealth.FakeHostname != "" {
			ext["hostname"] = hpConfig.Stealth.FakeHostname
		} else {
			ext["hostname"] = fmt.Sprintf("%s-host", honeypot)
		}
	}

	// PID namespace
	ext["pid"] = "private"

	// UTS namespace
	ext["uts"] = "private"

	// IPC namespace
	ext["ipc"] = "private"

	return ext
}

// getSeccompProfile returns path to custom seccomp profile
func (sb *Sandbox) getSeccompProfile(honeypot string) string {
	if sb.config.RuntimeSecurity.SeccompProfile == "default" {
		return "default.json"
	}
	
	// Generate custom profile for this honeypot
	profilePath := filepath.Join(os.TempDir(), fmt.Sprintf("qpot-seccomp-%s.json", honeypot))
	profile := sb.generateSeccompProfile(honeypot)
	os.WriteFile(profilePath, []byte(profile), 0644)
	return profilePath
}

// getAppArmorProfile returns AppArmor profile name
func (sb *Sandbox) getAppArmorProfile(honeypot string) string {
	// Return honeypot-specific profile if it exists
	profilePath := fmt.Sprintf("/etc/apparmor.d/qpot-%s", honeypot)
	if _, err := os.Stat(profilePath); err == nil {
		return fmt.Sprintf("qpot-%s", honeypot)
	}
	return "docker-default"
}

// generateSeccompProfile generates a custom seccomp profile for a honeypot
func (sb *Sandbox) generateSeccompProfile(honeypot string) string {
	// Base restrictive seccomp profile
	profile := `{
	"defaultAction": "SCMP_ACT_ERRNO",
	"architectures": [
		"SCMP_ARCH_X86_64",
		"SCMP_ARCH_X86",
		"SCMP_ARCH_AARCH64"
	],
	"syscalls": [
		{
			"names": [
				"accept",
				"accept4",
				"bind",
				"brk",
				"clone",
				"close",
				"connect",
				"epoll_create",
				"epoll_create1",
				"epoll_ctl",
				"epoll_pwait",
				"epoll_wait",
				"exit",
				"exit_group",
				"fcntl",
				"fstat",
				"fstatfs",
				"futex",
				"getdents64",
				"getpeername",
				"getrandom",
				"getsockname",
				"getsockopt",
				"ioctl",
				"listen",
				"lseek",
				"mmap",
				"mprotect",
				"munmap",
				"nanosleep",
				"openat",
				"poll",
				"read",
				"recvfrom",
				"recvmsg",
				"rt_sigaction",
				"rt_sigprocmask",
				"rt_sigreturn",
				"select",
				"sendmsg",
				"sendto",
				"setitimer",
				"setsockopt",
				"shutdown",
				"sigaltstack",
				"socket",
				"socketpair",
				"sysinfo",
				"time",
				"wait4",
				"waitid",
				"write",
				"writev",
				"umask",
				"uname",
				"getcwd",
				"chdir",
				"getpid",
				"getppid",
				"getuid",
				"getgid",
				"geteuid",
				"getegid",
				"setuid",
				"setgid",
				"setreuid",
				"setregid",
				"getgroups",
				"setgroups",
				"prctl",
				"arch_prctl",
				"sched_getaffinity",
				"sched_setaffinity",
				"sched_yield",
				"clock_gettime",
				"clock_getres",
				"gettimeofday",
				"stat",
				"lstat",
				"access",
				"pread64",
				"pwrite64",
				"dup",
				"dup2",
				"dup3",
				"pipe",
				"pipe2",
				"eventfd",
				"eventfd2",
				"signalfd",
				"signalfd4",
				"timerfd_create",
				"timerfd_settime",
				"timerfd_gettime",
				"inotify_init",
				"inotify_init1",
				"inotify_add_watch",
				"inotify_rm_watch",
				"mkdir",
				"mkdirat",
				"rmdir",
				"unlink",
				"unlinkat",
				"rename",
				"renameat",
				"chmod",
				"fchmod",
				"fchmodat",
				"chown",
				"fchown",
				"lchown",
				"fchownat",
				"link",
				"linkat",
				"symlink",
				"symlinkat",
				"readlink",
				"readlinkat",
				"truncate",
				"ftruncate",
				"fsync",
				"fdatasync",
				"sync",
				"syncfs"
			],
			"action": "SCMP_ACT_ALLOW"
		}
	]
}`

	return profile
}

// generateRandomMAC generates a cryptographically random MAC address.
// The first byte sets the locally-administered and unicast bits.
func (sb *Sandbox) generateRandomMAC() string {
	mac := make([]byte, 6)
	if _, err := cryptorand.Read(mac); err != nil {
		// Fallback: use a fixed locally-administered prefix only (still unique per call would
		// require entropy, so log and return a safe static value).
		return "02:00:00:00:00:01"
	}
	// Set locally administered bit (bit 1) and clear multicast bit (bit 0).
	mac[0] = (mac[0] | 0x02) & 0xfe
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// ValidateHost checks if the host system is secure enough
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

// GetSandboxInfo returns information about the sandbox
func (sb *Sandbox) GetSandboxInfo() map[string]interface{} {
	return map[string]interface{}{
		"type":       sb.sandboxType,
		"available":  sb.available,
		"config":     sb.config,
	}
}

// GetStealthEnvironment returns environment variables for stealth
func (sb *Sandbox) GetStealthEnvironment(hpConfig config.HoneypotConfig) map[string]string {
	env := make(map[string]string)
	
	if !hpConfig.Stealth.Enabled {
		return env
	}
	
	// Add stealth environment variables
	if hpConfig.Stealth.FakeHostname != "" {
		env["FAKE_HOSTNAME"] = hpConfig.Stealth.FakeHostname
	}
	if hpConfig.Stealth.FakeOS != "" {
		env["FAKE_OS"] = hpConfig.Stealth.FakeOS
	}
	if hpConfig.Stealth.FakeKernel != "" {
		env["FAKE_KERNEL"] = hpConfig.Stealth.FakeKernel
	}
	if hpConfig.Stealth.BannerString != "" {
		env["BANNER_STRING"] = hpConfig.Stealth.BannerString
	}
	
	env["STEALTH_MODE"] = "enabled"
	
	return env
}
