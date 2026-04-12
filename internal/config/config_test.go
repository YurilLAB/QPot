package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfigValid(t *testing.T) {
	cfg := Default("test")
	if cfg == nil {
		t.Fatal("Default returned nil")
	}
	if cfg.InstanceName != "test" {
		t.Errorf("InstanceName = %q, want test", cfg.InstanceName)
	}
	if cfg.Database.Type == "" {
		t.Error("default database type should not be empty")
	}
	if cfg.Database.Host == "" {
		t.Error("default database host should not be empty")
	}
	if cfg.Database.Port <= 0 {
		t.Errorf("default database port %d should be positive", cfg.Database.Port)
	}
	if cfg.WebUI.Port <= 0 {
		t.Errorf("default web UI port %d should be positive", cfg.WebUI.Port)
	}
	if cfg.Intelligence.WorkerBatchSize <= 0 {
		t.Error("default intelligence worker batch size should be positive")
	}
	if cfg.Intelligence.WorkerInterval <= 0 {
		t.Error("default intelligence worker interval should be positive")
	}
}

func TestDefaultConfigHoneypots(t *testing.T) {
	cfg := Default("test")
	if len(cfg.Honeypots) == 0 {
		t.Fatal("default config should have at least one honeypot defined")
	}
	// cowrie and endlessh should be enabled by default.
	for _, name := range []string{"cowrie", "endlessh"} {
		hp, ok := cfg.Honeypots[name]
		if !ok {
			t.Errorf("default config missing honeypot %q", name)
			continue
		}
		if !hp.Enabled {
			t.Errorf("honeypot %q should be enabled by default", name)
		}
	}
}

func TestAllocatePortDeterministic(t *testing.T) {
	cfg := Default("myinstance")
	p1 := cfg.AllocatePort(22)
	p2 := cfg.AllocatePort(22)
	if p1 != p2 {
		t.Errorf("AllocatePort is not deterministic: %d vs %d", p1, p2)
	}
}

func TestAllocatePortDifferentForDifferentInstances(t *testing.T) {
	cfg1 := Default("instance1")
	cfg2 := Default("instance2")
	p1 := cfg1.AllocatePort(22)
	p2 := cfg2.AllocatePort(22)
	if p1 == p2 {
		t.Error("different instances should get different allocated ports")
	}
}

func TestAllocatePortInValidRange(t *testing.T) {
	for _, name := range []string{"a", "abc", "very-long-instance-name-here", "test123"} {
		cfg := Default(name)
		for _, base := range []int{22, 80, 443, 9000, 8080} {
			p := cfg.AllocatePort(base)
			if p <= 1024 {
				t.Errorf("instance %q: allocated port %d should be > 1024", name, p)
			}
			if p > 65535 {
				t.Errorf("instance %q: allocated port %d exceeds 65535", name, p)
			}
		}
	}
}

func TestGetEnabledHoneypots(t *testing.T) {
	cfg := Default("test")
	enabled := cfg.GetEnabledHoneypots()
	if len(enabled) == 0 {
		t.Fatal("expected at least one enabled honeypot")
	}
	// Verify each returned name is actually enabled.
	for _, name := range enabled {
		hp, ok := cfg.Honeypots[name]
		if !ok {
			t.Errorf("GetEnabledHoneypots returned unknown honeypot %q", name)
			continue
		}
		if !hp.Enabled {
			t.Errorf("GetEnabledHoneypots returned disabled honeypot %q", name)
		}
	}
}

func TestEnableDisableHoneypot(t *testing.T) {
	cfg := Default("test")
	cfg.DisableHoneypot("cowrie")
	if hp := cfg.Honeypots["cowrie"]; hp.Enabled {
		t.Error("cowrie should be disabled after DisableHoneypot")
	}

	cfg.EnableHoneypot("cowrie")
	if hp := cfg.Honeypots["cowrie"]; !hp.Enabled {
		t.Error("cowrie should be enabled after EnableHoneypot")
	}
}

func TestGetEffectiveResourceLimitsGlobal(t *testing.T) {
	cfg := Default("test")
	// cowrie uses UseCustomLimits=false, so it should get global limits.
	limits := cfg.GetEffectiveResourceLimits("cowrie")
	global := cfg.Security.ResourceLimits
	if limits.MaxCPUPercent != global.MaxCPUPercent {
		t.Errorf("expected global CPU limit %f, got %f", global.MaxCPUPercent, limits.MaxCPUPercent)
	}
}

func TestGetEffectiveResourceLimitsPerHoneypot(t *testing.T) {
	cfg := Default("test")
	// dionaea uses UseCustomLimits=true.
	hp := cfg.Honeypots["dionaea"]
	hp.Resources.UseCustomLimits = true
	hp.Resources.MaxMemoryMB = 999
	cfg.Honeypots["dionaea"] = hp

	limits := cfg.GetEffectiveResourceLimits("dionaea")
	if limits.MaxMemoryMB != 999 {
		t.Errorf("expected per-honeypot memory limit 999, got %d", limits.MaxMemoryMB)
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	cfg := Default("savetest")
	cfg.DataPath = dir
	cfg.ConfigPath = filepath.Join(dir, "config.yaml")
	cfg.InstanceName = "savetest"

	if err := Save(cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	if _, err := os.Stat(cfg.ConfigPath); err != nil {
		t.Fatalf("config file not written: %v", err)
	}

	// Clear cache so Load reads from disk.
	configMu.Lock()
	delete(configs, "savetest")
	configMu.Unlock()

	loaded, err := Load("savetest")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.Database.Type != cfg.Database.Type {
		t.Errorf("database type mismatch after save/load: got %q, want %q",
			loaded.Database.Type, cfg.Database.Type)
	}
	if loaded.InstanceName != cfg.InstanceName {
		t.Errorf("instance name mismatch: got %q, want %q",
			loaded.InstanceName, cfg.InstanceName)
	}
}

func TestLoadFallsBackToDefault(t *testing.T) {
	// Load a non-existent instance — should return default config without error.
	// Use a clearly non-existent name.
	cfg, err := Load("definitely-does-not-exist-xyzzy")
	if err != nil {
		t.Fatalf("Load of unknown instance should return default, got error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load returned nil config")
	}
}

func TestGetTPOTConfig(t *testing.T) {
	cfg := Default("test")
	hp := cfg.Honeypots["cowrie"]
	hp.Stealth.Enabled = true
	hp.Stealth.FakeHostname = "webserver01"
	hp.Stealth.FakeOS = "Ubuntu 22.04"
	cfg.Honeypots["cowrie"] = hp

	tpotCfg := cfg.GetTPOTConfig("cowrie")
	if tpotCfg["STEALTH_ENABLED"] != "true" {
		t.Error("STEALTH_ENABLED should be true when stealth is enabled")
	}
	if tpotCfg["FAKE_HOSTNAME"] != "webserver01" {
		t.Errorf("FAKE_HOSTNAME = %q, want webserver01", tpotCfg["FAKE_HOSTNAME"])
	}
	if tpotCfg["FAKE_OS"] != "Ubuntu 22.04" {
		t.Errorf("FAKE_OS = %q, want Ubuntu 22.04", tpotCfg["FAKE_OS"])
	}
}
