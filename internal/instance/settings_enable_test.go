package instance

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

func savedHoneypot(t *testing.T, cfg *config.Config, name string) config.HoneypotConfig {
	t.Helper()
	data, err := os.ReadFile(cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	onDisk, err := config.Parse(data, cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	hp, _ := onDisk.GetHoneypotConfig(name)
	return hp
}

// SetHoneypotEnabled is `qpot honeypot enable|disable`: saved first, then
// started or stopped only when the instance runs.
func TestSetHoneypotEnabled(t *testing.T) {
	ctx := context.Background()
	cfg := settingsTestConfig(t, "toggle")
	cfg.DisableHoneypot("dionaea")
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}

	r := &fakeRunner{}
	res, err := SetHoneypotEnabled(ctx, cfg, "dionaea", true, r)
	if err != nil || res == nil || !res.Enabled || res.InstanceRunning || res.Applied || len(r.started) != 0 {
		t.Fatalf("on, stopped instance: %+v %v %+v", res, err, r)
	}
	if !savedHoneypot(t, cfg, "dionaea").Enabled {
		t.Fatal("not saved")
	}

	r.running = true
	res, err = SetHoneypotEnabled(ctx, cfg, "dionaea", false, r)
	if err != nil || res.Enabled || !res.InstanceRunning || !res.Applied || !slices.Equal(r.stopped, []string{"dionaea"}) {
		t.Fatalf("off, running: %+v %v %+v", res, err, r)
	}
	if savedHoneypot(t, cfg, "dionaea").Enabled {
		t.Fatal("still on in the file")
	}
	res, err = SetHoneypotEnabled(ctx, cfg, "dionaea", true, r)
	if err != nil || !res.Applied || !slices.Equal(r.started, []string{"dionaea"}) {
		t.Fatalf("on, running: %+v %v %+v", res, err, r)
	}

	// Docker failing: saved all the same, and the error says so.
	r.startErr = errors.New("compose up failed")
	cfg.DisableHoneypot("cowrie")
	res, err = SetHoneypotEnabled(ctx, cfg, "cowrie", true, r)
	var se *SettingsError
	if res == nil || !res.Enabled || res.Applied || !errors.Is(err, ErrStartStopFailed) || !errors.As(err, &se) ||
		!strings.HasPrefix(err.Error(), "failed to start honeypot: ") || !savedHoneypot(t, cfg, "cowrie").Enabled {
		t.Fatalf("start fails: %+v %v", res, err)
	}
	r.stopErr = errors.New("compose stop failed")
	if res, err = SetHoneypotEnabled(ctx, cfg, "cowrie", false, r); res == nil || !errors.Is(err, ErrStartStopFailed) ||
		!strings.HasPrefix(err.Error(), "failed to stop honeypot: ") {
		t.Fatalf("stop fails: %+v %v", res, err)
	}
}

// Refusals save nothing and keep the CLI's messages.
func TestSetHoneypotEnabledRefuses(t *testing.T) {
	ctx := context.Background()
	cfg := settingsTestConfig(t, "toggle-no")
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(cfg.ConfigPath)
	r := &fakeRunner{running: true}

	res, err := SetHoneypotEnabled(ctx, cfg, "cowrei", true, r)
	if res != nil || !errors.Is(err, ErrUnknownHoneypot) || !strings.HasPrefix(err.Error(), "unsupported honeypot: cowrei (supported: ") {
		t.Fatalf("unknown on: %+v %v", res, err)
	}
	res, err = SetHoneypotEnabled(ctx, cfg, "cowrei", false, r)
	if res != nil || !errors.Is(err, ErrUnknownHoneypot) || err.Error() != `unknown honeypot "cowrei" (see: qpot honeypot list)` {
		t.Fatalf("unknown off: %+v %v", res, err)
	}

	res, err = SetHoneypotEnabled(ctx, cfg, "galah", true, r)
	var se *SettingsError
	if res != nil || !errors.Is(err, ErrNeedsSettings) || !errors.As(err, &se) || !slices.Equal(se.Missing, []string{"llm_provider", "llm_model"}) {
		t.Fatalf("galah without a provider: %+v %v", res, err)
	}
	want := "galah needs an LLM provider; set llm_provider, llm_model first, e.g.:\n  qpot honeypot set galah -i toggle-no " + LLMSettingsExample("galah")
	if err.Error() != want {
		t.Fatalf("message:\n%s\nwant:\n%s", err, want)
	}
	if slices.Contains(cfg.GetEnabledHoneypots(), "galah") {
		t.Fatal("galah turned on in memory")
	}
	after, _ := os.ReadFile(cfg.ConfigPath)
	if string(before) != string(after) || len(r.started)+len(r.stopped) != 0 {
		t.Fatalf("a refusal changed something: %+v", r)
	}

	// A config that cannot be saved: refused, and the honeypot is as before
	// in memory too.
	cfg.ConfigPath = cfg.DataPath // a directory: Save fails
	cfg.DisableHoneypot("dionaea")
	if res, err := SetHoneypotEnabled(ctx, cfg, "dionaea", true, r); res != nil || !errors.Is(err, ErrSaveFailed) {
		t.Fatalf("unsaved: %+v %v", res, err)
	}
	if slices.Contains(cfg.GetEnabledHoneypots(), "dionaea") {
		t.Fatal("dionaea is on in memory though the file was not saved")
	}
}
