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
