package instance

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/qpot/qpot/internal/config"
)

// This file is `qpot honeypot enable` and `qpot honeypot disable`. The CLI
// and the web API (POST /api/honeypots) both call SetHoneypotEnabled, so a
// honeypot is turned on or off the same way wherever the request comes from.

// Kinds of SetHoneypotEnabled failure besides ErrUnknownHoneypot and
// ErrSaveFailed, for errors.Is.
var (
	// ErrNeedsSettings: an LLM-backed honeypot cannot be turned on before
	// its provider settings are set (SettingsError.Missing names them).
	ErrNeedsSettings = errors.New("honeypot needs settings first")
	// ErrStartStopFailed: the config was saved, but the honeypot's
	// container did not start or stop.
	ErrStartStopFailed = errors.New("honeypot not started or stopped")
)

// ToggleResult is what SetHoneypotEnabled did.
type ToggleResult struct {
	Honeypot string
	// Enabled is what the config file now says.
	Enabled bool
	// InstanceRunning: the instance's containers were up.
	InstanceRunning bool
	// Applied: the honeypot was started (on) or stopped (off).
	Applied bool
}

// LLMSettingsExample is a `qpot honeypot set` example for an LLM-backed
// honeypot's provider settings.
func LLMSettingsExample(name string) string {
	switch name {
	case "beelzebub":
		return "llm_provider=ollama llm_model=llama3.1 llm_host=http://OLLAMA_HOST:11434/api/chat"
	case "galah":
		return "llm_provider=ollama llm_server_url=http://OLLAMA_HOST:11434 llm_model=llama3.1"
	}
	return "key=value"
}

// SetHoneypotEnabled is `qpot honeypot enable` (on) and `disable`:
// SaveHoneypotEnabled, then ApplyHoneypotEnabled. The result is non-nil once
// the config was saved, also when starting or stopping failed (the error then
// is ErrStartStopFailed).
func SetHoneypotEnabled(ctx context.Context, cfg *config.Config, name string, on bool, runner HoneypotRunner) (*ToggleResult, error) {
	res, err := SaveHoneypotEnabled(cfg, name, on)
	if err != nil {
		return nil, err
	}
	return res, ApplyHoneypotEnabled(ctx, cfg, res, runner)
}

// SaveHoneypotEnabled turns a honeypot on or off in cfg and saves cfg's
// config file. Nothing is saved for an unknown honeypot, or for an
// LLM-backed one turned on without its provider settings.
func SaveHoneypotEnabled(cfg *config.Config, name string, on bool) (*ToggleResult, error) {
	if on {
		// A typo would otherwise be saved as an enabled honeypot with no
		// image, and fail late in `qpot up`.
		if err := (&ComposeGenerator{Config: cfg}).ValidateHoneypot(name); err != nil {
			return nil, &SettingsError{Kind: ErrUnknownHoneypot, Msg: err.Error(), Err: err}
		}
		// LLM-backed honeypots exit at start without a provider; enabling
		// one unconfigured only produced a crash-looping container.
		hp, _ := cfg.GetHoneypotConfig(name)
		if missing := MissingLLMConfig(name, hp.CustomConfig); len(missing) > 0 {
			return nil, &SettingsError{Kind: ErrNeedsSettings, Missing: missing,
				Msg: fmt.Sprintf("%s needs an LLM provider; set %s first, e.g.:\n  qpot honeypot set %s -i %s %s",
					name, strings.Join(missing, ", "), name, cfg.InstanceName, LLMSettingsExample(name))}
		}
	} else if _, ok := cfg.SnapshotHoneypots()[name]; !ok {
		// A typo used to report "Disabled" and save the config unchanged.
		return nil, &SettingsError{Kind: ErrUnknownHoneypot, Msg: fmt.Sprintf("unknown honeypot %q (see: qpot honeypot list)", name)}
	}

	old, had := cfg.GetHoneypotConfig(name)
	if on {
		cfg.EnableHoneypot(name)
	} else {
		cfg.DisableHoneypot(name)
	}
	if err := config.Save(cfg); err != nil {
		// Keep the config in memory what the file still says.
		if had && old.Enabled != on {
			if old.Enabled {
				cfg.EnableHoneypot(name)
			} else {
				cfg.DisableHoneypot(name)
			}
		}
		return nil, &SettingsError{Kind: ErrSaveFailed, Msg: "failed to save config: " + err.Error(), Err: err}
	}
	hp, _ := cfg.GetHoneypotConfig(name)
	return &ToggleResult{Honeypot: name, Enabled: hp.Enabled}, nil
}

// ApplyHoneypotEnabled starts or stops the honeypot of a saved change (res)
// when the instance is running; a stopped instance gets the change at its
// next start. runner reaches the containers; nil uses a Manager for cfg. It
// records what it did in res.
func ApplyHoneypotEnabled(ctx context.Context, cfg *config.Config, res *ToggleResult, runner HoneypotRunner) error {
	if runner == nil {
		mgr, err := NewManager(cfg)
		if err != nil {
			// The CLI never needed a manager to save; the change applies
			// at the next start.
			return nil
		}
		runner = mgr
	}
	if !runner.IsRunning(ctx) {
		return nil
	}
	res.InstanceRunning = true
	verb, act := "start", runner.StartHoneypot
	if !res.Enabled {
		verb, act = "stop", runner.StopHoneypot
	}
	if err := act(ctx, res.Honeypot); err != nil {
		return &SettingsError{Kind: ErrStartStopFailed, Msg: fmt.Sprintf("failed to %s honeypot: %v", verb, err), Err: err}
	}
	res.Applied = true
	return nil
}
