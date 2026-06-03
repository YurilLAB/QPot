package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadClampsResourceLimits is the regression guard for the bug where a
// config that omits (or partially fills) the security section loaded with
// zero-valued resource limits, rendering "memory: 0M" / "cpus: '0'" into the
// compose - which Docker rejects, so every honeypot failed to start. Load must
// restore the secure-by-default limits for any unset field.
func TestLoadClampsResourceLimits(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	inst := "clamptest"
	dir := filepath.Join(home, ".qpot", "instances", inst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A minimal, hand-written config with NO security: section at all.
	minimal := "instance_name: " + inst + "\n" +
		"honeypots:\n" +
		"  cowrie:\n" +
		"    enabled: true\n" +
		"    port: 22\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(minimal), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(inst)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rl := cfg.Security.ResourceLimits
	if rl.MaxMemoryMB <= 0 {
		t.Errorf("MaxMemoryMB = %d, want clamped to a positive default (Docker rejects memory: 0M)", rl.MaxMemoryMB)
	}
	if rl.MaxCPUPercent <= 0 {
		t.Errorf("MaxCPUPercent = %v, want clamped to a positive default", rl.MaxCPUPercent)
	}
	if rl.MaxPids <= 0 {
		t.Errorf("MaxPids = %d, want clamped to a positive default", rl.MaxPids)
	}
	if rl.RestartAttempts <= 0 {
		t.Errorf("RestartAttempts = %d, want clamped to a positive default", rl.RestartAttempts)
	}
	// The honeypot the user did declare must survive.
	if hp, ok := cfg.Honeypots["cowrie"]; !ok || !hp.Enabled {
		t.Error("the declared cowrie honeypot was lost on load")
	}
}
