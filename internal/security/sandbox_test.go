package security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

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

// TestNewSandboxUnknownModeDegrades verifies an empty or typo'd sandbox mode
// does NOT error (which would fail `qpot up` entirely) but degrades to plain
// containers - QPot must keep the honeypots running even when misconfigured.
func TestNewSandboxUnknownModeDegrades(t *testing.T) {
	for _, mode := range []string{"", "gvsior", "bogus", "GVISOR"} {
		sb, err := NewSandbox(&config.SecurityConfig{SandboxMode: mode})
		if err != nil {
			t.Errorf("NewSandbox(%q) returned error %v; want graceful fallback", mode, err)
			continue
		}
		if sb == nil || !sb.available {
			t.Errorf("NewSandbox(%q): expected an available (fallback) sandbox", mode)
		}
		if rt := sb.ContainerRuntime(); rt != "" {
			t.Errorf("NewSandbox(%q): fallback must use the default runtime (\"\"), got %q", mode, rt)
		}
	}
}

// A runtime binary on PATH is not enough: Docker must have it registered, or
// the generated compose names a runtime docker refuses.
func TestRuntimeUsableRequiresDockerRegistration(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "runsc"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	old := dockerRuntimes
	defer func() { dockerRuntimes = old }()

	dockerRuntimes = func() (map[string]json.RawMessage, error) {
		return map[string]json.RawMessage{"runc": nil}, nil
	}
	if runtimeUsable("runsc", "runsc") {
		t.Fatal("runsc reported usable although docker does not know it")
	}
	dockerRuntimes = func() (map[string]json.RawMessage, error) {
		return map[string]json.RawMessage{"runc": nil, "runsc": nil}, nil
	}
	if !runtimeUsable("runsc", "runsc") {
		t.Fatal("registered runsc reported unusable")
	}
	dockerRuntimes = func() (map[string]json.RawMessage, error) { return nil, os.ErrNotExist }
	if runtimeUsable("runsc", "runsc") {
		t.Fatal("runsc reported usable with no reachable docker daemon")
	}
}
