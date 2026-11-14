package instance

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/qpot/qpot/internal/config"
)

// This file is `qpot honeypot set`: the validation of a honeypot's settings
// (custom_config), saving them, and recreating the honeypot. The CLI and the
// web API (PUT /api/honeypots/settings) both call ApplySettings, so a setting
// is accepted or refused the same way wherever it comes from.

// MaxSettingValue is the longest setting value accepted, in bytes.
const MaxSettingValue = 2048

// Kinds of settings failure, for errors.Is. The error text is the message
// for the operator.
var (
	ErrUnknownHoneypot = errors.New("unknown honeypot")
	ErrNoSettings      = errors.New("honeypot has no settings")
	ErrInvalidSetting  = errors.New("invalid setting")
	ErrSaveFailed      = errors.New("config not saved")
	ErrRecreateFailed  = errors.New("honeypot not recreated")
)

// SettingsError is a settings failure: Kind says which (one of the Err
// values above), Msg is the message, Err the cause when there is one.
type SettingsError struct {
	Kind error
	Msg  string
	Err  error
	// Missing names the settings a honeypot needs first (ErrNeedsSettings).
	Missing []string
}

func (e *SettingsError) Error() string { return e.Msg }

// Is matches the error's Kind.
func (e *SettingsError) Is(target error) bool { return target == e.Kind }

// Unwrap returns the cause.
func (e *SettingsError) Unwrap() error { return e.Err }

// SettingChange is one key=value of `qpot honeypot set`; an empty Value
// removes the setting. Arg is how the operator wrote it (named in errors);
// NoValue marks an argument without "=".
type SettingChange struct {
	Key     string
	Value   string
	Arg     string
	NoValue bool
}

// ParseSettingArgs turns the CLI's key=value arguments into changes. Bad
// ones are reported by ApplySettings, in order, as the CLI always did.
func ParseSettingArgs(args []string) []SettingChange {
	out := make([]SettingChange, 0, len(args))
	for _, kv := range args {
		k, v, found := strings.Cut(kv, "=")
		out = append(out, SettingChange{Key: k, Value: v, Arg: kv, NoValue: !found})
	}
	return out
}

// HoneypotRunner is what a settings change, an enable/disable or a restart
// needs from the instance's containers (*Manager has it).
type HoneypotRunner interface {
	IsRunning(ctx context.Context) bool
	StartHoneypot(ctx context.Context, name string) error
	// RecreateHoneypot starts the honeypot in a new container, so settings it
	// reads only at start (files, not the compose service) take effect.
	RecreateHoneypot(ctx context.Context, name string) error
	StopHoneypot(ctx context.Context, name string) error
	RestartHoneypot(ctx context.Context, name string) error
}

// SettingsResult is what ApplySettings did.
type SettingsResult struct {
	Honeypot string
	// Custom is the honeypot's custom_config after the change.
	Custom map[string]string
	// Saved: the config file was written.
	Saved bool
	// Enabled: the honeypot is enabled in the config.
	Enabled bool
	// Missing are LLM settings the honeypot still needs before it can run
	// (it was then not recreated).
	Missing []string
	// InstanceRunning: the instance's containers were up.
	InstanceRunning bool
	// Recreated: the honeypot was recreated with the new settings.
	Recreated bool
}

// ValidateSettings checks changes to a honeypot's settings against what
// `qpot honeypot set` accepts and returns the honeypot's custom_config with
// them applied (cfg is not changed). Changes are checked in order; the first
// bad one is the error.
func ValidateSettings(cfg *config.Config, name string, changes []SettingChange) (map[string]string, error) {
	hp, ok := cfg.GetHoneypotConfig(name)
	if !ok {
		return nil, &SettingsError{Kind: ErrUnknownHoneypot, Msg: fmt.Sprintf("unknown honeypot %q (see: qpot honeypot list)", name)}
	}
	allowed := SettingKeys(name)
	if len(allowed) == 0 {
		return nil, &SettingsError{Kind: ErrNoSettings, Msg: fmt.Sprintf("%s has no settings to set", name)}
	}
	custom := maps.Clone(hp.CustomConfig)
	if custom == nil {
		custom = map[string]string{}
	}
	for _, c := range changes {
		if c.NoValue || !slices.Contains(allowed, c.Key) {
			arg := c.Arg
			if arg == "" {
				arg = c.Key
			}
			return nil, &SettingsError{Kind: ErrInvalidSetting,
				Msg: fmt.Sprintf("invalid setting %q for %s (allowed: %s)", arg, name, strings.Join(allowed, ", "))}
		}
		if err := checkSettingValue(name, c.Key, c.Value); err != nil {
			return nil, &SettingsError{Kind: ErrInvalidSetting, Msg: err.Error()}
		}
		if c.Value == "" {
			delete(custom, c.Key)
		} else {
			custom[c.Key] = c.Value
		}
	}
	if name == "ssh-proxy" {
		if err := config.ValidateSSHEnvironmentSettings(custom); err != nil {
			return nil, &SettingsError{Kind: ErrInvalidSetting, Msg: err.Error()}
		}
	}
	return custom, nil
}

// ApplySettings is `qpot honeypot set`: it validates the changes (nothing is
// saved when one is bad), saves cfg's config file with them and, when the
// honeypot is enabled, has its LLM settings and the instance is running,
// recreates the honeypot so it runs with them. runner reaches the containers;
// nil uses a Manager for cfg.
//
// The result is non-nil once the config was saved, also when the recreate
// failed (the error then is ErrRecreateFailed).
func ApplySettings(ctx context.Context, cfg *config.Config, name string, changes []SettingChange, runner HoneypotRunner) (*SettingsResult, error) {
	custom, err := ValidateSettings(cfg, name, changes)
	if err != nil {
		return nil, err
	}
	old, _ := cfg.GetHoneypotConfig(name)
	cfg.SetHoneypotCustomConfig(name, custom)
	if err := config.Save(cfg); err != nil {
		// Keep the config in memory what the file still says.
		cfg.SetHoneypotCustomConfig(name, old.CustomConfig)
		return nil, &SettingsError{Kind: ErrSaveFailed, Msg: "failed to save config: " + err.Error(), Err: err}
	}
	hp, _ := cfg.GetHoneypotConfig(name)
	res := &SettingsResult{Honeypot: name, Custom: maps.Clone(custom), Saved: true, Enabled: hp.Enabled}
	if !hp.Enabled {
		return res, nil
	}
	if missing := MissingLLMConfig(name, custom); len(missing) > 0 {
		res.Missing = missing
		return res, nil
	}
	if runner == nil {
		mgr, err := NewManager(cfg)
		if err != nil {
			return res, err
		}
		runner = mgr
	}
	if !runner.IsRunning(ctx) {
		return res, nil
	}
	res.InstanceRunning = true
	if err := runner.RecreateHoneypot(ctx, name); err != nil {
		return res, &SettingsError{Kind: ErrRecreateFailed, Msg: fmt.Sprintf("settings saved, but %s did not restart: %v", name, err), Err: err}
	}
	res.Recreated = true
	return res, nil
}

// settingSpec describes a setting whose values are not a fixed list.
type settingSpec struct {
	kind     string // "number", "url", "name", "secret"
	min, max float64
	integer  bool
	help     string
}

// settingSpecs are the free-form settings and how their values are checked.
// Keys with a Values list in the deploy profile (and cowrie's
// persona_rotation) are checked by CheckSetting.
var settingSpecs = map[string]settingSpec{
	"persona_rotation":   {kind: "number", min: 0, max: cowriePersonaMaxRotation, integer: true, help: "Days Cowrie keeps the identity it drew (host name, uptime, addresses) across restarts. Empty: 365."},
	"backends":           {kind: "number", min: 1, max: maxSSHBackends, integer: true, help: "How many real-OpenSSH backends run behind the HiFi broker. Empty: 2."},
	"cell_hold_minutes":  {kind: "number", min: 0, max: config.SSHCellHoldMax, integer: true, help: "Minutes a visitor's address keeps its HiFi cell after its last connection closes, so its next connections find what it left. 0 resets the cell after every connection. Empty: 30."},
	"llm_model":          {kind: "name", help: "The model the honeypot asks, e.g. llama3.1 or gpt-4o-mini."},
	"llm_host":           {kind: "url", help: "URL of the Ollama or OpenAI-compatible chat endpoint, e.g. http://10.0.0.5:11434/api/chat."},
	"llm_server_url":     {kind: "url", help: "URL of the Ollama server, e.g. http://10.0.0.5:11434."},
	"llm_temperature":    {kind: "number", min: 0, max: 2, help: "Sampling temperature, 0 to 2. Empty: the image's default."},
	"llm_api_key":        {kind: "secret", help: "API key for a hosted model. Stored in the instance config; never shown again."},
	"llm_cloud_location": {kind: "name", help: "Cloud region of a hosted model (Vertex AI), e.g. us-central1."},
	"llm_cloud_project":  {kind: "name", help: "Cloud project of a hosted model (Vertex AI)."},
	"llm_provider":       {kind: "name", help: "Which LLM provider answers, e.g. ollama or openai."},
}

// settingHelp explains the settings that have a fixed list of values.
var settingHelp = map[string]string{
	"persona":      "The system Cowrie presents. Empty: one server persona picked for this instance.",
	"bait":         "Plant working files with synthetic credential canaries on server personas. Empty: on.",
	"bait_profile": "Files for an ops server or a Linux industrial support host. Industrial archives reference bait_target; they do not make Cowrie a PLC or start an engineering runtime. Server personas only. Empty: ops.",
	"bait_target":  "Asset referenced by industrial support files: the selected Conpot device or the refrigeration controller. This does not enable the referenced service. Used with bait_profile=industrial. Empty: conpot.",
	"deception":    "qpot: QPot's Cowrie. stock: the image's own Cowrie, with none of QPot's changes and no bait. Use stock only for the control side of a comparison. Empty: qpot.",
	"template":     "The industrial device Conpot emulates; only its ports are published. Empty: the saved automatic device, kept across restarts and upgrades.",
	"site_profile": "Refrigeration site: retail food cabinets or plasma cold storage. Each site keeps its own temperatures, settings and history across restarts and profile switches. Empty: retail.",
	"environment":  "HiFi SSH environment. Standalone is one real Debian 12 server per visitor. Organization adds a PostgreSQL database and an SSH backup host, using three decoy containers per slot. State lasts for a visitor's connections and cell_hold_minutes after them, then resets before reuse. These real shells have writable container filesystems. Official releases select matching published images; development checkouts should build both current images and choose image_source=local. Empty: standalone.",
	"image_source": "Published uses QPot's registry images. Local uses qpot-local/ssh-proxy:development and qpot-local/ssh-backend:development, built from your checkout; build both before starting. Local tags are not pulled from a registry. This also selects the HiFi egress-guard helper image, so use only images you trust. Empty: published.",
}

var (
	// settingNameRe: model, provider, region and project names, e.g.
	// "hf.co/org/Model-GGUF:Q4_K_M".
	settingNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$`)
	// settingNumberRe: plain decimal numbers (no sign, exponent, hex, Inf
	// or NaN, which ParseFloat would take).
	settingNumberRe = regexp.MustCompile(`^[0-9]{1,6}(\.[0-9]{1,6})?$`)
	// settingSecretRe: API keys (base64, hex, "sk-..." and the like).
	settingSecretRe = regexp.MustCompile(`^[A-Za-z0-9._~+/=:-]{1,512}$`)
)

// checkSettingValue reports whether value is accepted for the honeypot's
// setting key. An empty value (removing the setting) always is. Free-form
// values are held to the characters their kind needs, so no setting can
// carry markup, quotes, spaces or control characters.
func checkSettingValue(name, key, value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("%s: value must be a single line", key)
	}
	if value == "" {
		return nil
	}
	if len(value) > MaxSettingValue {
		return fmt.Errorf("%s: value is longer than %d characters", key, MaxSettingValue)
	}
	if err := CheckSetting(name, key, value); err != nil {
		return err
	}
	if len(deployProfileFor(name).Values[key]) > 0 {
		return nil // one of the listed values
	}
	spec, ok := settingSpecs[key]
	if !ok {
		return fmt.Errorf("%s: %s has no value check", name, key)
	}
	switch spec.kind {
	case "number":
		f, err := strconv.ParseFloat(value, 64)
		if !settingNumberRe.MatchString(value) || err != nil || !(f >= spec.min && f <= spec.max) ||
			(spec.integer && strings.Trim(value, "0123456789") != "") {
			what := "a number"
			if spec.integer {
				what = "a whole number"
			}
			return fmt.Errorf("%s: %s must be %s from %g to %g", name, key, what, spec.min, spec.max)
		}
	case "url":
		u, err := url.Parse(value)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
			strings.ContainsAny(value, " \t<>\"'`\\{}|^") || hasControl(value) {
			return fmt.Errorf("%s: %s must be an http:// or https:// URL without a user name or spaces", name, key)
		}
	case "name":
		if !settingNameRe.MatchString(value) {
			return fmt.Errorf("%s: %s may use only letters, digits and . _ : / @ + - (at most 200)", name, key)
		}
	case "secret":
		if !settingSecretRe.MatchString(value) {
			return fmt.Errorf("%s: %s may use only letters, digits and . _ ~ + / = : - (at most 512)", name, key)
		}
	}
	return nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// SettingInfo describes one setting of a honeypot for the web UI.
type SettingInfo struct {
	Key string `json:"key"`
	// Value is the configured value; always "" for a secret.
	Value string `json:"value"`
	// Set: the setting has a configured value.
	Set bool `json:"set"`
	// Effective is the value the honeypot runs with when it differs from
	// Value (a default, or one picked for this instance).
	Effective string `json:"effective,omitempty"`
	// Type is "choice", "number", "url", "name" or "secret".
	Type    string   `json:"type"`
	Allowed []string `json:"allowed,omitempty"`
	// Options enrich device choices without changing their accepted IDs.
	Options []ConpotDeviceProfile `json:"options,omitempty"`
	// Sites is, for each device choice, what this instance's device would
	// say of itself (ConpotSiteFacts); a device that reports no names has
	// no entry.
	Sites map[string][]SiteFact `json:"sites,omitempty"`
	// Default is the saved automatic device, also provided while pinned.
	Default  string   `json:"default,omitempty"`
	Min      *float64 `json:"min,omitempty"`
	Max      *float64 `json:"max,omitempty"`
	Secret   bool     `json:"secret"`
	Required bool     `json:"required"`
	Help     string   `json:"help"`
}

// IsSecretSetting reports whether a setting's value is a credential, never
// shown back once set.
func IsSecretSetting(key string) bool {
	return settingSpecs[key].kind == "secret"
}

// DescribeSettings returns every setting `qpot honeypot set` accepts for a
// honeypot, with its configured and effective values (secrets blanked).
// Empty for an unknown honeypot or one without settings.
func DescribeSettings(cfg *config.Config, name string) []SettingInfo {
	hp, ok := cfg.GetHoneypotConfig(name)
	if !ok {
		return nil
	}
	d := deployProfileFor(name)
	var out []SettingInfo
	for _, key := range SettingKeys(name) {
		v := hp.CustomConfig[key]
		switch name + "/" + key {
		case "conpot/template", "refrigeration/site_profile", "cowrie/bait", "cowrie/persona", "cowrie/bait_profile", "cowrie/bait_target", "cowrie/deception", "ssh-proxy/environment", "ssh-proxy/image_source":
			// Direct YAML accepts the same surrounding whitespace that runtime
			// selection trims. A dropdown needs the canonical ID; an unmatched
			// raw value would become empty and clear a valid choice on save.
			v = strings.TrimSpace(v)
		case "cowrie/persona_rotation":
			// Number inputs also discard padded values. Show the decimal value
			// the launcher accepts, without changing the underlying YAML or
			// presenting an invalid manual value as the default.
			if days, ok := parsePersonaRotation(v); ok {
				v = strconv.Itoa(days)
			} else if strings.TrimSpace(v) == "" {
				v = ""
			}
		case "ssh-proxy/backends":
			// Preserve a valid hand-written pool size when a different field is
			// saved from the form: number inputs discard surrounding whitespace.
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 1 && n <= maxSSHBackends {
				v = strconv.Itoa(n)
			} else if strings.TrimSpace(v) == "" {
				v = ""
			}
		}
		si := SettingInfo{Key: key, Value: v, Set: v != "", Required: slices.Contains(d.LLMRequired, key)}
		if allowed := d.Values[key]; len(allowed) > 0 {
			si.Type, si.Allowed, si.Help = "choice", slices.Clone(allowed), settingHelp[key]
			if si.Help == "" {
				si.Help = settingSpecs[key].help
			}
		} else {
			spec := settingSpecs[key]
			si.Type, si.Help = spec.kind, spec.help
			if spec.kind == "number" {
				lo, hi := spec.min, spec.max
				si.Min, si.Max = &lo, &hi
			}
		}
		if name == "conpot" && key == "template" {
			si.Options = ConpotProfiles()
			si.Default = config.ConpotAutomaticProfileID(cfg)
			si.Sites = map[string][]SiteFact{}
			for _, p := range si.Options {
				if facts := ConpotSiteFacts(cfg, p.ID); len(facts) > 0 {
					si.Sites[p.ID] = facts
				}
			}
		}
		if IsSecretSetting(key) {
			si.Secret, si.Value = true, ""
		}
		if eff := effectiveSetting(cfg, name, key); eff != v {
			si.Effective = eff
		}
		out = append(out, si)
	}
	return out
}

// effectiveSetting is the value a honeypot runs with for a setting that has
// a default or a per-instance pick; "" when it has none.
func effectiveSetting(cfg *config.Config, name, key string) string {
	switch name + "/" + key {
	case "cowrie/persona":
		return cowriePersona(cfg)
	case "cowrie/persona_rotation":
		return strconv.Itoa(cowriePersonaRotation(cfg))
	case "cowrie/bait":
		if baitOn(cfg) {
			return "on"
		}
		return "off"
	case "cowrie/bait_profile":
		return cowrieBaitProfile(cfg)
	case "cowrie/bait_target":
		return cowrieBaitTarget(cfg)
	case "cowrie/deception":
		if cowrieStock(cfg) {
			return "stock"
		}
		return "qpot"
	case "conpot/template":
		return conpotTemplate(cfg).ID
	case "refrigeration/site_profile":
		return refrigerationSiteProfile(cfg)
	case "ssh-proxy/backends":
		return strconv.Itoa(sshBackendCount(cfg))
	case "ssh-proxy/cell_hold_minutes":
		return strconv.Itoa(config.SSHCellHoldMinutes(cfg))
	case "ssh-proxy/environment":
		return config.SSHEnvironment(cfg)
	case "ssh-proxy/image_source":
		return config.SSHImageSource(cfg)
	}
	return ""
}
