package instance

import (
	"bytes"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

func TestSSHEnvironmentSettingsAndDescriptions(t *testing.T) {
	cfg := settingsTestConfig(t, "ssh-environment")
	for _, value := range []string{"", "standalone", "organization"} {
		custom, err := ValidateSettings(cfg, "ssh-proxy", ParseSettingArgs([]string{"environment=" + value}))
		if err != nil || custom["environment"] != value {
			t.Fatalf("valid scene setting %q refused: %v %v", value, custom, err)
		}
	}
	for _, value := range []string{"", "published", "local"} {
		custom, err := ValidateSettings(cfg, "ssh-proxy", ParseSettingArgs([]string{"image_source=" + value}))
		if err != nil || custom["image_source"] != value {
			t.Fatalf("valid image source %q refused: %v %v", value, custom, err)
		}
	}
	for _, args := range [][]string{{"environment=Organization"}, {"environment=organization\n"}, {"environment= organization"}, {"environment=unknown"}, {"environment=organization", "forward_to=10.0.0.1:22"}} {
		if _, err := ValidateSettings(cfg, "ssh-proxy", ParseSettingArgs(args)); !errors.Is(err, ErrInvalidSetting) {
			t.Fatalf("invalid scene mutation accepted: %v: %v", args, err)
		}
	}
	for _, arg := range []string{"image_source=Local", "image_source=local ", "image_source=registry", "image_source=https://untrusted.invalid/image"} {
		if _, err := ValidateSettings(cfg, "ssh-proxy", ParseSettingArgs([]string{arg})); !errors.Is(err, ErrInvalidSetting) {
			t.Fatalf("invalid image source accepted: %s: %v", arg, err)
		}
	}
	if _, err := ValidateSettings(cfg, "cowrie", ParseSettingArgs([]string{"environment=organization"})); !errors.Is(err, ErrInvalidSetting) {
		t.Fatalf("scene setting leaked into another honeypot: %v", err)
	}

	for _, raw := range []string{"", "organization", "  organization\t"} {
		cfg.SetHoneypotCustomConfig("ssh-proxy", map[string]string{"environment": raw, "backends": " 003 ", "image_source": " local "})
		parsed, err := cfg.Clone()
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, setting := range DescribeSettings(parsed, "ssh-proxy") {
			switch setting.Key {
			case "environment":
				found = true
				if setting.Type != "choice" || setting.Value != strings.TrimSpace(raw) || !slices.Equal(setting.Allowed, []string{"standalone", "organization"}) {
					t.Fatalf("scene dropdown cannot represent current config: %+v", setting)
				}
				selected := setting.Value
				if selected == "" {
					selected = setting.Effective
				}
				if selected != config.SSHEnvironment(parsed) || !strings.Contains(setting.Help, "visitor") || !strings.Contains(setting.Help, "cell_hold_minutes") || !strings.Contains(setting.Help, "three") {
					t.Fatalf("description differs from runtime/lifetime/resource cost: %+v", setting)
				}
			case "backends":
				if setting.Value != "3" {
					t.Fatalf("pool-size number control loses a valid padded value: %+v", setting)
				}
			case "image_source":
				if setting.Type != "choice" || setting.Value != "local" || !slices.Equal(setting.Allowed, []string{"published", "local"}) || !strings.Contains(setting.Help, "not pulled") {
					t.Fatalf("image selector lost its source/pull behavior: %+v", setting)
				}
			}
		}
		if !found {
			t.Fatal("HiFi has no environment selector")
		}
		hp, _ := parsed.GetHoneypotConfig("ssh-proxy")
		if hp.CustomConfig["environment"] != raw || hp.CustomConfig["backends"] != " 003 " || hp.CustomConfig["image_source"] != " local " {
			t.Fatal("describing settings rewrote manual YAML")
		}
	}
}

func TestSSHEnvironmentApplyUsesSharedMutationPath(t *testing.T) {
	cfg := settingsTestConfig(t, "ssh-apply")
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{running: true}
	result, err := ApplySettings(t.Context(), cfg, "ssh-proxy", ParseSettingArgs([]string{"environment=organization", "image_source=local"}), runner)
	if err != nil || !result.Saved || result.Enabled || result.Recreated || len(runner.recreated) != 0 {
		t.Fatalf("saving a scene while HiFi is off enabled or started it: %+v %v", result, err)
	}
	cfg.EnableHoneypot("ssh-proxy")
	result, err = ApplySettings(t.Context(), cfg, "ssh-proxy", ParseSettingArgs([]string{"environment=standalone", "image_source=published"}), runner)
	if err != nil || !result.Recreated || !slices.Equal(runner.recreated, []string{"ssh-proxy"}) {
		t.Fatalf("running scene change did not use the shared recreate path: %+v %v", result, err)
	}
	before, err := os.ReadFile(cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err = ApplySettings(t.Context(), cfg, "ssh-proxy", ParseSettingArgs([]string{"environment=organization", "backends=0"}), runner)
	if result != nil || !errors.Is(err, ErrInvalidSetting) || len(runner.recreated) != 1 {
		t.Fatalf("partially applied invalid scene change: %+v %v", result, err)
	}
	after, err := os.ReadFile(cfg.ConfigPath)
	if err != nil || !bytes.Equal(before, after) || config.SSHEnvironment(cfg) != config.SSHEnvironmentStandalone {
		t.Fatalf("invalid setting changed saved or in-memory state: %v", err)
	}
}
