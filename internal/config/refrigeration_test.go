package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRefrigerationUpgradeRemainsOptIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg, err := Parse([]byte("instance_name: legacy\nhoneypots:\n  cowrie:\n    enabled: true\n    port: 22\n"), path)
	if err != nil {
		t.Fatal(err)
	}
	hp, ok := cfg.GetHoneypotConfig("refrigeration")
	if !ok || hp.Enabled || hp.Port != 8080 || hp.RiskLevel != "low" || !hp.Resources.UseCustomLimits {
		t.Fatalf("new service must be available but disabled on upgrade: %+v", hp)
	}
	if cowrie, _ := cfg.GetHoneypotConfig("cowrie"); !cowrie.Enabled {
		t.Fatal("upgrade changed an existing service")
	}
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Parse(data, path)
	if err != nil {
		t.Fatal(err)
	}
	if hp, _ := again.GetHoneypotConfig("refrigeration"); hp.Enabled {
		t.Fatal("save/reload enabled refrigeration")
	}
}

func TestRefrigerationProfileValidationAndRoundTrip(t *testing.T) {
	for _, profile := range []string{"", "retail", "plasma", " plasma ", "   ", "unknown", "Retail", " unknown "} {
		t.Run(profile, func(t *testing.T) {
			cfg := Default("refrigeration-config")
			cfg.DataPath = t.TempDir()
			cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
			cfg.SetHoneypotCustomConfig("refrigeration", map[string]string{"site_profile": profile})
			err := Save(cfg)
			normalized := strings.TrimSpace(profile)
			valid := normalized == "" || normalized == "retail" || normalized == "plasma"
			if !valid {
				if err == nil || !strings.Contains(err.Error(), "site_profile") {
					t.Fatalf("invalid profile must fail clearly: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(cfg.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := Parse(data, cfg.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			if hp, _ := loaded.GetHoneypotConfig("refrigeration"); hp.CustomConfig["site_profile"] != profile {
				t.Fatalf("profile lost on roundtrip: %+v", hp)
			}
		})
	}
	_, err := Parse([]byte("honeypots:\n  refrigeration:\n    custom_config:\n      site_profile: bad\n"), filepath.Join(t.TempDir(), "config.yaml"))
	if err == nil || !strings.Contains(err.Error(), "site_profile") {
		t.Fatalf("hand-edited invalid profile accepted: %v", err)
	}
}
