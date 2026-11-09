package config

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSSHResourceCapsRejectInvalidOverridesAtomically(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*HoneypotResources)
	}{
		{"negative CPU", func(r *HoneypotResources) { r.MaxCPUPercent = -1 }},
		{"NaN CPU", func(r *HoneypotResources) { r.MaxCPUPercent = math.NaN() }},
		{"positive infinity CPU", func(r *HoneypotResources) { r.MaxCPUPercent = math.Inf(1) }},
		{"negative infinity CPU", func(r *HoneypotResources) { r.MaxCPUPercent = math.Inf(-1) }},
		{"underflow CPU", func(r *HoneypotResources) { r.MaxCPUPercent = math.SmallestNonzeroFloat64 }},
		{"sub-nanoCPU", func(r *HoneypotResources) { r.MaxCPUPercent = 1e-10 }},
		{"sub-CFS CPU quota", func(r *HoneypotResources) { r.MaxCPUPercent = 0.5 }},
		{"CPU quota overflow", func(r *HoneypotResources) { r.MaxCPUPercent = math.MaxFloat64 }},
		{"negative memory", func(r *HoneypotResources) { r.MaxMemoryMB = -1 }},
		{"below Docker memory floor", func(r *HoneypotResources) { r.MaxMemoryMB = 1 }},
		{"just below Docker memory floor", func(r *HoneypotResources) { r.MaxMemoryMB = 5 }},
		{"memory byte overflow", func(r *HoneypotResources) { r.MaxMemoryMB = math.MaxInt64 }},
		{"negative storage", func(r *HoneypotResources) { r.MaxStorageGB = -1 }},
		{"storage byte overflow", func(r *HoneypotResources) { r.MaxStorageGB = math.MaxInt64 }},
		{"unlimited PIDs", func(r *HoneypotResources) { r.MaxPids = -1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default("ssh-cap-validation")
			cfg.DataPath = t.TempDir()
			cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
			if err := Save(cfg); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(cfg.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			hp := cfg.Honeypots["ssh-proxy"]
			hp.Resources.UseCustomLimits = true
			tc.set(&hp.Resources)
			cfg.Honeypots["ssh-proxy"] = hp
			if err := Save(cfg); err == nil || !strings.Contains(err.Error(), "ssh-proxy.resources") {
				t.Fatalf("unsafe override reached saved config: %v", err)
			}
			after, err := os.ReadFile(cfg.ConfigPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("refused override replaced the saved config: %v", err)
			}
			data, err := yaml.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Parse(data, cfg.ConfigPath); err == nil || !strings.Contains(err.Error(), "ssh-proxy.resources") {
				t.Fatalf("unsafe handwritten override reached loaded config: %v", err)
			}
			// Other sensors retain their existing resource-policy behavior.
			delete(cfg.Honeypots, "ssh-proxy")
			cfg.Honeypots["cowrie"] = hp
			if err := ValidateSSHEnvironment(cfg); err != nil {
				t.Fatalf("HiFi validation changed another sensor's policy: %v", err)
			}
		})
	}
}

func TestSSHMemoryFloorUsesEffectiveLimits(t *testing.T) {
	for _, memory := range []int64{1, 5, 6} {
		cfg := Default("ssh-memory-floor")
		hp := cfg.Honeypots["ssh-proxy"]
		hp.Enabled = true
		hp.Resources = HoneypotResources{UseCustomLimits: true}
		cfg.Honeypots["ssh-proxy"] = hp
		cfg.Security.ResourceLimits.MaxMemoryMB = memory
		if err := ValidateSSHEnvironment(cfg); (err == nil) != (memory == 6) {
			t.Fatalf("effective inherited memory %d: %v", memory, err)
		}
		hp.Resources.MaxMemoryMB = 6
		cfg.Honeypots["ssh-proxy"] = hp
		if err := ValidateSSHEnvironment(cfg); err != nil {
			t.Fatalf("explicit Engine-valid memory floor rejected: %v", err)
		}
	}
}

func TestSSHResourceCapsResolveLegacyDefaultsAndZeroInheritance(t *testing.T) {
	data := []byte("honeypots:\n  ssh-proxy:\n    enabled: true\n    resources:\n      use_custom_limits: true\n      max_pids: 17\n")
	cfg, err := Parse(data, filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatalf("legacy omitted global limits must be resolved first: %v", err)
	}
	limits := cfg.GetEffectiveResourceLimits("ssh-proxy")
	if limits.MaxCPUPercent != 50 || limits.MaxMemoryMB != 512 || limits.MaxPids != 17 {
		t.Fatalf("incorrect inherited legacy limits: %+v", limits)
	}
	if err := Save(cfg); err != nil {
		t.Fatalf("zero custom fields must remain valid inheritance: %v", err)
	}
}

func TestSSHEnvironmentConfigRoundTrip(t *testing.T) {
	if got := SSHEnvironment(nil); got != SSHEnvironmentStandalone {
		t.Fatalf("nil config default: %q", got)
	}
	if got := SSHImageSource(nil); got != SSHImageSourcePublished {
		t.Fatalf("nil config image default: %q", got)
	}
	for _, raw := range []string{"", "standalone", "organization", "  organization\t", " \n "} {
		t.Run(raw, func(t *testing.T) {
			cfg := Default("ssh-environment")
			cfg.DataPath = t.TempDir()
			cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
			cfg.SetHoneypotCustomConfig("ssh-proxy", map[string]string{"environment": raw, "backends": "3", "image_source": " local "})
			if err := Save(cfg); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(cfg.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := Parse(data, cfg.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			want := strings.TrimSpace(raw)
			if want == "" {
				want = SSHEnvironmentStandalone
			}
			if got := SSHEnvironment(parsed); got != want {
				t.Fatalf("effective mode: %q, want %q", got, want)
			}
			hp, _ := parsed.GetHoneypotConfig("ssh-proxy")
			if hp.Enabled || hp.CustomConfig["environment"] != raw || hp.CustomConfig["backends"] != "3" || hp.CustomConfig["image_source"] != " local " || SSHImageSource(parsed) != SSHImageSourceLocal {
				t.Fatalf("saving a scene must preserve raw settings and keep HiFi off: %+v", hp)
			}
		})
	}
	legacy, err := Parse([]byte("instance_name: legacy\nhoneypots:\n  ssh-proxy:\n    enabled: true\n    custom_config:\n      backends: '2'\n"), filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if got := SSHEnvironment(legacy); got != SSHEnvironmentStandalone {
		t.Fatalf("upgrade opted a legacy instance into a connected scene: %q", got)
	}
	if got := SSHImageSource(legacy); got != SSHImageSourcePublished {
		t.Fatalf("upgrade selected local unpublished images: %q", got)
	}
	missing := Default("ssh-missing")
	delete(missing.Honeypots, "ssh-proxy")
	if got := SSHEnvironment(missing); got != SSHEnvironmentStandalone || ValidateSSHEnvironment(missing) != nil {
		t.Fatalf("missing HiFi must stay standalone: %q", got)
	}
}

func TestSSHImageSourceConfigRoundTrip(t *testing.T) {
	for _, raw := range []string{"", "published", "local", "  local\t", " \n "} {
		t.Run(raw, func(t *testing.T) {
			cfg := Default("ssh-image-source")
			cfg.DataPath = t.TempDir()
			cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
			cfg.SetHoneypotCustomConfig("ssh-proxy", map[string]string{"image_source": raw})
			if err := Save(cfg); err != nil {
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
			want := strings.TrimSpace(raw)
			if want == "" {
				want = SSHImageSourcePublished
			}
			hp, _ := loaded.GetHoneypotConfig("ssh-proxy")
			if SSHImageSource(loaded) != want || hp.CustomConfig["image_source"] != raw || hp.Enabled {
				t.Fatalf("image choice did not preserve its meaning/raw YAML/opt-in: %+v", hp)
			}
		})
	}
}

func TestSSHEnvironmentInvalidConfigNeverReplacesSavedFile(t *testing.T) {
	for _, custom := range []map[string]string{
		{"environment": "Organization"},
		{"environment": "unknown"},
		{"environment": "organization\nstandalone"},
		{"environment": "organization\x00"},
		{"environment": "organization", "environmnt": "organization"},
		{"environment": "organization", "forward_to": "10.0.0.1:22"},
		{"environment": "organization", "image_source": "registry"},
		{"image_source": "https://untrusted.invalid/image"},
		{"image_source": "Local"},
		{"image_source": "local\x00"},
		{"environment": "organization", "forward\nto": "10.0.0.1:22"},
	} {
		t.Run(custom["environment"]+custom["environmnt"]+custom["forward_to"]+custom["image_source"], func(t *testing.T) {
			cfg := Default("ssh-invalid")
			cfg.DataPath = t.TempDir()
			cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
			if err := Save(cfg); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(cfg.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			cfg.SetHoneypotCustomConfig("ssh-proxy", custom)
			if err := Save(cfg); err == nil || !strings.Contains(err.Error(), "ssh-proxy.custom_config") {
				t.Fatalf("unsupported scene setting accepted: %v", err)
			} else if strings.ContainsAny(err.Error(), "\r\n\x00") {
				t.Fatalf("raw control character reached configuration error: %q", err.Error())
			}
			after, err := os.ReadFile(cfg.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("invalid scene replaced the saved config")
			}
			data, err := yaml.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Parse(data, cfg.ConfigPath); err == nil || !strings.Contains(err.Error(), "ssh-proxy.custom_config") {
				t.Fatalf("hand-written unsupported scene setting accepted: %v", err)
			}
		})
	}
}
