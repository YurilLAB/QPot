package security

import (
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

// hasSeccompArg reports whether any option sets a seccomp profile, and the
// value it was set to.
func seccompArg(opts []string) (value string, present bool) {
	for _, o := range opts {
		if strings.HasPrefix(o, "--security-opt=seccomp=") {
			return strings.TrimPrefix(o, "--security-opt=seccomp="), true
		}
	}
	return "", false
}

// TestDockerSecurityOptionsHardening verifies the isolation guarantees QPot
// promises are actually emitted for an attacker-facing honeypot: capabilities
// dropped, no-new-privileges, swap disabled, and resource limits applied. A
// privileged-port honeypot (cowrie on 22) must get NET_BIND_SERVICE back but
// nothing more.
func TestDockerSecurityOptionsHardening(t *testing.T) {
	cfg := config.Default("sec-test")
	sb, err := NewSandbox(&cfg.Security)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}
	opts := sb.GetDockerSecurityOptions("cowrie", cfg.Honeypots["cowrie"])
	joined := strings.Join(opts, " ")

	for _, want := range []string{
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges:true",
		"--memory-swappiness=0",
		"--pids-limit=",
		"--memory=",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("docker security options missing %q\ngot: %s", want, joined)
		}
	}
	// A privileged-port honeypot (Port < 1024) must get NET_BIND_SERVICE back.
	hp := cfg.Honeypots["cowrie"]
	hp.Port = 80
	if pj := strings.Join(sb.GetDockerSecurityOptions("cowrie", hp), " "); !strings.Contains(pj, "--cap-add=NET_BIND_SERVICE") {
		t.Errorf("privileged-port honeypot missing NET_BIND_SERVICE\ngot: %s", pj)
	}
	// Must never grant broad capabilities.
	for _, bad := range []string{"--cap-add=ALL", "--privileged", "--cap-add=SYS_ADMIN"} {
		if strings.Contains(joined, bad) {
			t.Errorf("docker security options must not contain %q", bad)
		}
	}

	// With capability dropping disabled, cap-drop must not be emitted.
	cfg2 := config.Default("sec-test2")
	cfg2.Security.DropCapabilities = false
	cfg2.Security.NoNewPrivileges = false
	sb2, _ := NewSandbox(&cfg2.Security)
	j2 := strings.Join(sb2.GetDockerSecurityOptions("cowrie", cfg2.Honeypots["cowrie"]), " ")
	if strings.Contains(j2, "--cap-drop=ALL") {
		t.Error("cap-drop emitted even though DropCapabilities is false")
	}
	if strings.Contains(j2, "no-new-privileges") {
		t.Error("no-new-privileges emitted even though NoNewPrivileges is false")
	}
}

// TestSeccompDefaultOmitsFlag verifies that the "default" seccomp setting does
// NOT emit a seccomp=default.json flag. Docker has no such file; the built-in
// default profile is applied automatically when the flag is absent. Emitting
// seccomp=default.json makes docker fail to open the file and refuse to start
// the container.
func TestSeccompDefaultOmitsFlag(t *testing.T) {
	cfg := &config.SecurityConfig{SandboxMode: "none"}
	cfg.RuntimeSecurity.EnableSeccompProfile = true
	cfg.RuntimeSecurity.SeccompProfile = "default"

	sb, err := NewSandbox(cfg)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}

	opts := sb.GetDockerSecurityOptions("cowrie", config.HoneypotConfig{Port: 2222})
	if v, present := seccompArg(opts); present {
		t.Errorf("expected no seccomp flag for default profile, got seccomp=%q", v)
	}
	// Specifically guard against the regression.
	for _, o := range opts {
		if strings.Contains(o, "default.json") {
			t.Errorf("emitted bogus seccomp file reference: %q", o)
		}
	}
}

// TestSeccompCustomWritesProfile verifies the custom path still produces a
// real, readable profile file reference.
func TestSeccompCustomWritesProfile(t *testing.T) {
	cfg := &config.SecurityConfig{SandboxMode: "none"}
	cfg.RuntimeSecurity.EnableSeccompProfile = true
	cfg.RuntimeSecurity.SeccompProfile = "custom"

	sb, err := NewSandbox(cfg)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}

	opts := sb.GetDockerSecurityOptions("cowrie", config.HoneypotConfig{Port: 2222})
	v, present := seccompArg(opts)
	if !present {
		t.Fatal("expected a seccomp profile flag for custom profile")
	}
	if !strings.HasSuffix(v, ".json") || strings.Contains(v, "default.json") {
		t.Errorf("unexpected custom seccomp profile path %q", v)
	}
}

func TestContainerRuntime(t *testing.T) {
	cases := []struct {
		mode string
		want string // expected runtime when available
	}{
		{"none", ""},
		{"gvisor", "runsc"},
		{"kata", "kata-runtime"},
	}
	for _, tc := range cases {
		cfg := &config.SecurityConfig{SandboxMode: tc.mode}
		sb, err := NewSandbox(cfg)
		if err != nil {
			t.Fatalf("NewSandbox(%q): %v", tc.mode, err)
		}
		got := sb.ContainerRuntime()
		// In this environment runsc/kata are not installed, so NewSandbox
		// falls back to none and ContainerRuntime returns "". The invariant we
		// assert universally: ContainerRuntime is non-empty ONLY when the
		// sandbox is both a runtime type AND available.
		if got != "" && got != tc.want {
			t.Errorf("mode %q: ContainerRuntime=%q, want %q or \"\"", tc.mode, got, tc.want)
		}
		if got != "" && !sb.available {
			t.Errorf("mode %q: returned runtime %q while sandbox not available", tc.mode, got)
		}
	}
}
