package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/instance"
)

// Honeypot settings: GET and PUT /api/honeypots/settings, the web UI's
// `qpot honeypot set`.

// maxSettingsBody bounds a PUT /api/honeypots/settings body.
const maxSettingsBody = 16 << 10

// maxSettingsPerRequest bounds the settings one request changes (no
// honeypot has more than eight).
const maxSettingsPerRequest = 32

// honeypotChangeTimeout bounds the Docker work one change waits for.
const honeypotChangeTimeout = 5 * time.Minute

// honeypotSettingsView is one honeypot's settings for the UI.
type honeypotSettingsView struct {
	Name     string                 `json:"name"`
	Enabled  bool                   `json:"enabled"`
	Settings []instance.SettingInfo `json:"settings"`
	Missing  []string               `json:"missing"`
}

func settingsView(cfg *config.Config, name string) honeypotSettingsView {
	hp, _ := cfg.GetHoneypotConfig(name)
	missing := instance.MissingLLMConfig(name, hp.CustomConfig)
	if missing == nil {
		missing = []string{}
	}
	return honeypotSettingsView{Name: name, Enabled: hp.Enabled, Settings: instance.DescribeSettings(cfg, name), Missing: missing}
}

// handleHoneypotSettings serves GET (one honeypot's settings with ?name=, or
// every honeypot that has settings) and PUT (change them).
func (s *Server) handleHoneypotSettings(w http.ResponseWriter, r *http.Request) {
	if !s.allowMethods(w, r, http.MethodGet, http.MethodPut) {
		return
	}
	if r.Method == http.MethodPut {
		s.putHoneypotSettings(w, r)
		return
	}
	cfg, err := s.readConfig()
	if err != nil {
		slog.Error("honeypot settings: config file not read", "error", err)
		s.sendAPIError(w, http.StatusInternalServerError, "QP-INST-002", "The instance settings could not be read.")
		return
	}
	if name := r.URL.Query().Get("name"); name != "" {
		if !s.isKnownHoneypot(name) {
			s.sendAPIError(w, http.StatusBadRequest, "QP-INPUT-003", "Unknown honeypot.")
			return
		}
		if _, ok := cfg.GetHoneypotConfig(name); !ok {
			cfg = s.config
		}
		writeJSON(w, http.StatusOK, settingsView(cfg, name))
		return
	}
	names := make([]string, 0, 8)
	for name := range cfg.SnapshotHoneypots() {
		if len(instance.SettingKeys(name)) > 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	out := make([]honeypotSettingsView, 0, len(names))
	for _, name := range names {
		out = append(out, settingsView(cfg, name))
	}
	writeJSON(w, http.StatusOK, map[string]any{"honeypots": out})
}

// settingsChangeResponse is the answer to a settings change.
type settingsChangeResponse struct {
	Name            string                 `json:"name"`
	Saved           bool                   `json:"saved"`
	Enabled         bool                   `json:"enabled"`
	InstanceRunning bool                   `json:"instance_running"`
	Recreated       bool                   `json:"recreated"`
	Missing         []string               `json:"missing"`
	Settings        []instance.SettingInfo `json:"settings"`
	Message         string                 `json:"message"`
}

// putHoneypotSettings changes a honeypot's settings exactly as
// `qpot honeypot set` does (instance.ApplySettings).
func (s *Server) putHoneypotSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string            `json:"name"`
		Settings map[string]string `json:"settings"`
	}
	if err := decodeJSONBody(w, r, maxSettingsBody, &req); err != nil {
		s.sendAPIError(w, http.StatusBadRequest, "", err.Error())
		return
	}
	if !s.isKnownHoneypot(req.Name) {
		s.sendAPIError(w, http.StatusBadRequest, "QP-INPUT-003", "Unknown honeypot.")
		return
	}
	if len(req.Settings) == 0 {
		s.sendAPIError(w, http.StatusBadRequest, "QP-INPUT-012", "No settings given: send {\"name\": ..., \"settings\": {\"key\": \"value\"}}.")
		return
	}
	if len(req.Settings) > maxSettingsPerRequest {
		s.sendAPIError(w, http.StatusBadRequest, "QP-INPUT-012", fmt.Sprintf("Too many settings in one request (at most %d).", maxSettingsPerRequest))
		return
	}
	keys := make([]string, 0, len(req.Settings))
	for k := range req.Settings {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	changes := make([]instance.SettingChange, 0, len(keys))
	for _, k := range keys {
		changes = append(changes, instance.SettingChange{Key: k, Value: req.Settings[k], Arg: echoableKey(k)})
	}

	if !s.api.change.TryLock() {
		s.sendAPIError(w, http.StatusConflict, "", "Another honeypot change is still running. Try again when it has finished.")
		return
	}
	defer s.api.change.Unlock()

	cfg, err := s.loadConfigForChange()
	if err != nil {
		slog.Error("honeypot settings: config file not read", "error", err)
		s.sendAPIError(w, http.StatusInternalServerError, "QP-INST-002", "The instance settings could not be read.")
		return
	}
	// Validate first, so a bad request never needs Docker.
	if _, err := instance.ValidateSettings(cfg, req.Name, changes); err != nil {
		s.settingsError(w, req.Name, err)
		return
	}
	runner, err := s.honeypotRunner(cfg)
	if err != nil {
		s.sendInternalError(w, "honeypot settings: no container manager", err)
		return
	}
	extendWriteDeadline(w, honeypotChangeTimeout+30*time.Second)
	// A client that hangs up must not stop Docker half-way.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), honeypotChangeTimeout)
	defer cancel()
	res, err := instance.ApplySettings(ctx, cfg, req.Name, changes, runner)
	if res != nil && res.Saved {
		s.adoptHoneypots(cfg)
	}
	if err != nil {
		if res != nil && res.Saved {
			slog.Error("honeypot settings saved, but the honeypot was not recreated", "honeypot", req.Name, "error", err)
			code := ""
			if errors.Is(err, instance.ErrRecreateFailed) {
				code = "QP-INST-008"
			}
			writeJSON(w, http.StatusBadGateway, apiError{
				Error: fmt.Sprintf("Settings saved, but %s did not restart with them. Its log (GET /api/logs?honeypot=%s) shows why.", req.Name, req.Name),
				Code:  code, Saved: true})
			return
		}
		s.settingsError(w, req.Name, err)
		return
	}
	resp := settingsChangeResponse{
		Name: req.Name, Saved: true, Enabled: res.Enabled, InstanceRunning: res.InstanceRunning,
		Recreated: res.Recreated, Missing: res.Missing, Settings: instance.DescribeSettings(cfg, req.Name),
	}
	if resp.Missing == nil {
		resp.Missing = []string{}
	}
	switch {
	case !res.Enabled:
		resp.Message = fmt.Sprintf("Updated %s settings. %s is turned off; they apply when it is turned on.", req.Name, req.Name)
	case len(res.Missing) > 0:
		resp.Message = fmt.Sprintf("Updated %s settings. %s still needs: %s.", req.Name, req.Name, strings.Join(res.Missing, ", "))
	case !res.InstanceRunning:
		resp.Message = fmt.Sprintf("Updated %s settings. The instance is not running; they apply when it starts.", req.Name)
	default:
		resp.Message = fmt.Sprintf("Updated %s settings and recreated %s with them.", req.Name, req.Name)
	}
	writeJSON(w, http.StatusOK, resp)
}

// echoableKey is how an error names a setting key the request sent: the key
// when it looks like one, else a placeholder, so an error never carries
// markup the request put there.
func echoableKey(k string) string {
	if settingKeyRe.MatchString(k) {
		return k
	}
	return "(not a setting name)"
}

var settingKeyRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// settingsError answers a refused settings change.
func (s *Server) settingsError(w http.ResponseWriter, name string, err error) {
	switch {
	case errors.Is(err, instance.ErrUnknownHoneypot):
		s.sendAPIError(w, http.StatusBadRequest, "QP-INPUT-003", "Unknown honeypot.")
	case errors.Is(err, instance.ErrNoSettings):
		s.sendAPIError(w, http.StatusBadRequest, "QP-INPUT-012", fmt.Sprintf("%s has no settings to change.", name))
	case errors.Is(err, instance.ErrInvalidSetting):
		s.sendAPIError(w, http.StatusBadRequest, "QP-INPUT-012", err.Error())
	case errors.Is(err, instance.ErrSaveFailed):
		slog.Error("honeypot settings: save failed", "error", err)
		s.sendAPIError(w, http.StatusInternalServerError, "QP-INST-002", "The instance settings could not be saved (check the free space and permissions of the instance folder).")
	default:
		s.sendInternalError(w, "honeypot settings failed", err)
	}
}
