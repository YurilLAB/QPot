package instance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

// fakeRunner records what a settings change asks of the containers.
type fakeRunner struct {
	running   bool
	startErr  error
	stopErr   error
	started   []string
	stopped   []string
	restarted []string
}

func (f *fakeRunner) IsRunning(context.Context) bool { return f.running }
func (f *fakeRunner) StartHoneypot(_ context.Context, name string) error {
	f.started = append(f.started, name)
	return f.startErr
}
func (f *fakeRunner) StopHoneypot(_ context.Context, name string) error {
	f.stopped = append(f.stopped, name)
	return f.stopErr
}
func (f *fakeRunner) RestartHoneypot(_ context.Context, name string) error {
	f.restarted = append(f.restarted, name)
	return f.startErr
}

func settingsTestConfig(t *testing.T, name string) *config.Config {
	t.Helper()
	cfg := config.Default(name)
	dir := t.TempDir()
	cfg.DataPath = dir
	cfg.ConfigPath = filepath.Join(dir, "config.yaml")
	cfg.QPotID = "qp_settingssettingssetting"
	return cfg
}

func TestValidateSettingsRefuses(t *testing.T) {
	cfg := settingsTestConfig(t, "set-refuse")
	cases := []struct {
		hp      string
		changes []SettingChange
		kind    error
		msg     string
	}{
		{"nosuch", ParseSettingArgs([]string{"a=b"}), ErrUnknownHoneypot, `unknown honeypot "nosuch" (see: qpot honeypot list)`},
		{"<img src=x onerror=alert(1)>", ParseSettingArgs([]string{"persona=rhel-9"}), ErrUnknownHoneypot, "unknown honeypot"},
		{"endlessh", ParseSettingArgs([]string{"a=b"}), ErrNoSettings, "endlessh has no settings to set"},
		{"cowrie", ParseSettingArgs([]string{"persona"}), ErrInvalidSetting, `invalid setting "persona" for cowrie (allowed: bait, persona, persona_rotation)`},
		{"cowrie", ParseSettingArgs([]string{"Persona=rhel-9"}), ErrInvalidSetting, "invalid setting"},
		{"cowrie", ParseSettingArgs([]string{"persona=rhel-9\nx"}), ErrInvalidSetting, "persona: value must be a single line"},
		{"cowrie", ParseSettingArgs([]string{"persona=<script>alert(1)</script>"}), ErrInvalidSetting, "persona must be one of"},
		{"cowrie", ParseSettingArgs([]string{"bait=maybe"}), ErrInvalidSetting, "bait must be one of: on, off"},
		{"cowrie", ParseSettingArgs([]string{"persona_rotation=366"}), ErrInvalidSetting, "persona_rotation must be a number of days"},
		{"cowrie", ParseSettingArgs([]string{"persona_rotation= 30"}), ErrInvalidSetting, "persona_rotation"},
		{"conpot", ParseSettingArgs([]string{"template=default"}), ErrInvalidSetting, "template must be one of"},
		{"ssh-proxy", ParseSettingArgs([]string{"backends=17"}), ErrInvalidSetting, "backends must be a whole number from 1 to 16"},
		{"ssh-proxy", ParseSettingArgs([]string{"backends=2.5"}), ErrInvalidSetting, "whole number"},
		{"ssh-proxy", ParseSettingArgs([]string{"backends=abc"}), ErrInvalidSetting, "whole number"},
		{"beelzebub", ParseSettingArgs([]string{"llm_provider=anthropic"}), ErrInvalidSetting, "llm_provider must be one of: ollama, openai"},
		{"galah", ParseSettingArgs([]string{"llm_model=<b>x</b>"}), ErrInvalidSetting, "llm_model may use only"},
		{"galah", ParseSettingArgs([]string{`llm_model=a"b`}), ErrInvalidSetting, "llm_model may use only"},
		{"galah", ParseSettingArgs([]string{"llm_model=a b"}), ErrInvalidSetting, "llm_model may use only"},
		{"galah", ParseSettingArgs([]string{"llm_provider=x\x00y"}), ErrInvalidSetting, "llm_provider may use only"},
		{"galah", ParseSettingArgs([]string{"llm_server_url=javascript:alert(1)"}), ErrInvalidSetting, "must be an http:// or https:// URL"},
		{"galah", ParseSettingArgs([]string{"llm_server_url=http://u:p@10.0.0.5:11434"}), ErrInvalidSetting, "without a user name"},
		{"galah", ParseSettingArgs([]string{`llm_server_url=http://10.0.0.5/"><script>`}), ErrInvalidSetting, "URL"},
		{"galah", ParseSettingArgs([]string{"llm_server_url=http://10.0.0.5/\x1b[2J"}), ErrInvalidSetting, "URL"},
		{"galah", ParseSettingArgs([]string{"llm_temperature=3"}), ErrInvalidSetting, "llm_temperature must be a number from 0 to 2"},
		{"galah", ParseSettingArgs([]string{"llm_temperature=NaN"}), ErrInvalidSetting, "llm_temperature"},
		{"galah", ParseSettingArgs([]string{"llm_temperature=0x1p-1"}), ErrInvalidSetting, "llm_temperature"},
		{"galah", ParseSettingArgs([]string{"llm_temperature=1e0"}), ErrInvalidSetting, "llm_temperature"},
		{"galah", ParseSettingArgs([]string{"llm_temperature=-0"}), ErrInvalidSetting, "llm_temperature"},
		{"galah", ParseSettingArgs([]string{"llm_api_key=sk live"}), ErrInvalidSetting, "llm_api_key may use only"},
		{"galah", ParseSettingArgs([]string{"llm_model=" + strings.Repeat("m", MaxSettingValue+1)}), ErrInvalidSetting, "longer than"},
		// The first bad change is the error; a good one before it is not saved.
		{"cowrie", ParseSettingArgs([]string{"persona=rhel-9", "bait=nope"}), ErrInvalidSetting, "bait"},
	}
	for _, c := range cases {
		_, err := ValidateSettings(cfg, c.hp, c.changes)
		if !errors.Is(err, c.kind) || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%s %+v: got %v, want %v containing %q", c.hp, c.changes, err, c.kind, c.msg)
		}
	}
	if hp, _ := cfg.GetHoneypotConfig("cowrie"); len(hp.CustomConfig) != 0 {
		t.Fatalf("validation changed the config: %v", hp.CustomConfig)
	}
}

func TestValidateSettingsAccepts(t *testing.T) {
	cfg := settingsTestConfig(t, "set-accept")
	ok := map[string][]string{
		"cowrie":    {"persona=rhel-9", "persona_rotation=0", "persona_rotation=365", "persona_rotation=007", "bait=off", "bait=on", "persona="},
		"conpot":    {"template=plc_modbus"},
		"ssh-proxy": {"backends=1", "backends=16"},
		"beelzebub": {"llm_provider=ollama", "llm_model=llama3.1:8b", "llm_host=http://10.0.0.5:11434/api/chat"},
		"galah": {"llm_provider=googleai", "llm_server_url=https://ollama.example:11434", "llm_model=hf.co/org/Model-GGUF:Q4_K_M",
			"llm_temperature=0.7", "llm_api_key=sk-AbC_123.xyz~+/=", "llm_cloud_location=us-central1", "llm_cloud_project=my-proj-1", "llm_api_key="},
	}
	for hp, args := range ok {
		for _, a := range args {
			if _, err := ValidateSettings(cfg, hp, ParseSettingArgs([]string{a})); err != nil {
				t.Errorf("%s %s refused: %v", hp, a, err)
			}
		}
	}
	custom, err := ValidateSettings(cfg, "cowrie", ParseSettingArgs([]string{"persona=rhel-9", "persona=centos-7", "bait=off"}))
	if err != nil || custom["persona"] != "centos-7" || custom["bait"] != "off" {
		t.Fatalf("last value wins: %v %v", custom, err)
	}
}

// Every free-form setting has a value check: a setting added to a deploy
// profile without one is refused outright rather than accepted unchecked.
func TestEverySettingIsChecked(t *testing.T) {
	cfg := settingsTestConfig(t, "set-every")
	for name := range cfg.SnapshotHoneypots() {
		d := deployProfileFor(name)
		for _, key := range SettingKeys(name) {
			if len(d.Values[key]) > 0 {
				continue
			}
			if _, ok := settingSpecs[key]; !ok {
				t.Errorf("%s setting %s has neither a Values list nor a settingSpec", name, key)
			}
		}
	}
}

func TestApplySettings(t *testing.T) {
	ctx := context.Background()

	t.Run("disabled honeypot: saved, nothing started", func(t *testing.T) {
		cfg := settingsTestConfig(t, "apply-off")
		r := &fakeRunner{running: true}
		res, err := ApplySettings(ctx, cfg, "conpot", ParseSettingArgs([]string{"template=iccp"}), r)
		if err != nil || !res.Saved || res.Enabled || res.Recreated || len(r.started) != 0 {
			t.Fatalf("res %+v err %v started %v", res, err, r.started)
		}
		data, _ := os.ReadFile(cfg.ConfigPath)
		if !strings.Contains(string(data), "template: iccp") {
			t.Fatalf("config file lacks the setting:\n%s", data)
		}
	})

	t.Run("running instance: recreated", func(t *testing.T) {
		cfg := settingsTestConfig(t, "apply-run")
		cfg.EnableHoneypot("cowrie")
		r := &fakeRunner{running: true}
		res, err := ApplySettings(ctx, cfg, "cowrie", ParseSettingArgs([]string{"bait=off"}), r)
		if err != nil || !res.Recreated || !res.InstanceRunning || len(r.started) != 1 || r.started[0] != "cowrie" {
			t.Fatalf("res %+v err %v started %v", res, err, r.started)
		}
	})

	t.Run("stopped instance: saved, not started", func(t *testing.T) {
		cfg := settingsTestConfig(t, "apply-stop")
		cfg.EnableHoneypot("cowrie")
		r := &fakeRunner{}
		res, err := ApplySettings(ctx, cfg, "cowrie", ParseSettingArgs([]string{"bait=off"}), r)
		if err != nil || res.Recreated || res.InstanceRunning || len(r.started) != 0 {
			t.Fatalf("res %+v err %v started %v", res, err, r.started)
		}
	})

	t.Run("LLM honeypot still missing a provider: not started", func(t *testing.T) {
		cfg := settingsTestConfig(t, "apply-llm")
		cfg.EnableHoneypot("galah")
		r := &fakeRunner{running: true}
		res, err := ApplySettings(ctx, cfg, "galah", ParseSettingArgs([]string{"llm_provider=ollama"}), r)
		if err != nil || len(res.Missing) != 1 || res.Missing[0] != "llm_model" || len(r.started) != 0 {
			t.Fatalf("res %+v err %v started %v", res, err, r.started)
		}
	})

	t.Run("recreate fails: saved, error says so", func(t *testing.T) {
		cfg := settingsTestConfig(t, "apply-fail")
		cfg.EnableHoneypot("cowrie")
		r := &fakeRunner{running: true, startErr: errors.New("compose exploded")}
		res, err := ApplySettings(ctx, cfg, "cowrie", ParseSettingArgs([]string{"bait=off"}), r)
		if !errors.Is(err, ErrRecreateFailed) || res == nil || !res.Saved ||
			err.Error() != "settings saved, but cowrie did not restart: compose exploded" {
			t.Fatalf("res %+v err %v", res, err)
		}
	})

	t.Run("bad change: nothing saved", func(t *testing.T) {
		cfg := settingsTestConfig(t, "apply-bad")
		res, err := ApplySettings(ctx, cfg, "cowrie", ParseSettingArgs([]string{"bait=off", "persona=nope"}), &fakeRunner{})
		if res != nil || !errors.Is(err, ErrInvalidSetting) {
			t.Fatalf("res %+v err %v", res, err)
		}
		if _, statErr := os.Stat(cfg.ConfigPath); !os.IsNotExist(statErr) {
			t.Fatalf("a refused change wrote the config file (%v)", statErr)
		}
	})

	t.Run("save fails: config in memory unchanged", func(t *testing.T) {
		cfg := settingsTestConfig(t, "apply-nosave")
		// A directory where the file should be: the write fails.
		if err := os.MkdirAll(cfg.ConfigPath, 0o750); err != nil {
			t.Fatal(err)
		}
		res, err := ApplySettings(ctx, cfg, "cowrie", ParseSettingArgs([]string{"bait=off"}), &fakeRunner{})
		if res != nil || !errors.Is(err, ErrSaveFailed) || !strings.HasPrefix(err.Error(), "failed to save config: ") {
			t.Fatalf("res %+v err %v", res, err)
		}
		if hp, _ := cfg.GetHoneypotConfig("cowrie"); hp.CustomConfig["bait"] != "" {
			t.Fatalf("unsaved change kept in memory: %v", hp.CustomConfig)
		}
	})
}

func TestDescribeSettings(t *testing.T) {
	cfg := settingsTestConfig(t, "describe")
	if _, err := ValidateSettings(cfg, "galah", nil); err != nil {
		t.Fatal(err)
	}
	cfg.SetHoneypotCustomConfig("galah", map[string]string{"llm_api_key": "sk-supersecret", "llm_model": "m1"})
	byKey := map[string]SettingInfo{}
	for _, si := range DescribeSettings(cfg, "galah") {
		byKey[si.Key] = si
	}
	if k := byKey["llm_api_key"]; !k.Secret || k.Value != "" || !k.Set || k.Type != "secret" {
		t.Fatalf("api key shown: %+v", k)
	}
	if m := byKey["llm_model"]; m.Value != "m1" || !m.Required || m.Type != "name" {
		t.Fatalf("llm_model: %+v", m)
	}

	byKey = map[string]SettingInfo{}
	for _, si := range DescribeSettings(cfg, "cowrie") {
		byKey[si.Key] = si
	}
	p := byKey["persona"]
	if p.Type != "choice" || p.Set || p.Effective == "" || len(p.Allowed) != len(CowriePersonaIDs()) {
		t.Fatalf("persona: %+v", p)
	}
	if r := byKey["persona_rotation"]; r.Type != "number" || r.Effective != "365" || r.Min == nil || *r.Max != 365 {
		t.Fatalf("persona_rotation: %+v", r)
	}
	if b := byKey["bait"]; b.Effective != "on" {
		t.Fatalf("bait: %+v", b)
	}
	if DescribeSettings(cfg, "nosuch") != nil {
		t.Fatal("unknown honeypot described")
	}
}
