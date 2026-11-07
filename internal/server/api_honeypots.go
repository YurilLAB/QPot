package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/qpot/qpot/internal/instance"
)

// POST /api/honeypots: turn a honeypot on or off, exactly as `qpot honeypot
// enable|disable` does (instance.SetHoneypotEnabled). The change is made to
// the config file as it is now: the server's own copy, read when it
// started, is never saved over it.

// maxToggleBody bounds the body of POST /api/honeypots.
const maxToggleBody = 4096

// honeypotToggleResponse is the answer of POST /api/honeypots.
type honeypotToggleResponse struct {
	Status          string `json:"status"` // "ok", as the original endpoint answered
	Name            string `json:"name"`
	Enabled         bool   `json:"enabled"`
	Saved           bool   `json:"saved"`
	InstanceRunning bool   `json:"instance_running"`
	Applied         bool   `json:"applied"`
	Message         string `json:"message"`
}

func (s *Server) handleHoneypotToggle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		Enabled *bool  `json:"enabled"`
	}
	if err := decodeJSONBody(w, r, maxToggleBody, &req); err != nil {
		s.sendAPIError(w, http.StatusBadRequest, "", err.Error())
		return
	}
	if req.Enabled == nil {
		s.sendAPIError(w, http.StatusBadRequest, "", "Say whether to turn the honeypot on or off: {\"name\": ..., \"enabled\": true}.")
		return
	}
	// Checked against the configured honeypots before the name reaches a
	// docker command line.
	if !s.isKnownHoneypot(req.Name) {
		s.sendAPIError(w, http.StatusBadRequest, "QP-INPUT-003", "Unknown honeypot.")
		return
	}
	on := *req.Enabled

	if !s.api.change.TryLock() {
		s.sendAPIError(w, http.StatusConflict, "", "Another honeypot change is still running. Try again when it has finished.")
		return
	}
	defer s.api.change.Unlock()

	cfg, err := s.loadConfigForChange()
	if err != nil {
		slog.Error("honeypot toggle: config file not read", "error", err)
		s.sendAPIError(w, http.StatusInternalServerError, "QP-INST-002", "The instance settings could not be read.")
		return
	}
	runner, err := s.honeypotRunner(cfg)
	if err != nil {
		s.sendInternalError(w, "honeypot toggle: no container manager", err)
		return
	}
	extendWriteDeadline(w, honeypotChangeTimeout+30*time.Second)
	// A client that hangs up must not stop Docker half-way.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), honeypotChangeTimeout)
	defer cancel()
	res, err := instance.SetHoneypotEnabled(ctx, cfg, req.Name, on, runner)
	if res != nil {
		s.adoptHoneypots(cfg)
	}
	if err != nil {
		var se *instance.SettingsError
		switch {
		case res != nil:
			slog.Error("honeypot toggle saved, but the container did not follow", "honeypot", req.Name, "on", on, "error", err)
			verb := "start"
			if !on {
				verb = "stop"
			}
			writeJSON(w, http.StatusBadGateway, apiError{
				Error: fmt.Sprintf("Saved, but %s did not %s. Its log (GET /api/logs?honeypot=%s) shows why.", req.Name, verb, req.Name),
				Code:  "QP-INST-008", Saved: true})
		case errors.Is(err, instance.ErrNeedsSettings) && errors.As(err, &se):
			writeJSON(w, http.StatusBadRequest, apiError{
				Error: fmt.Sprintf("%s needs an LLM provider before it can be turned on. Set it first (PUT /api/honeypots/settings).", req.Name),
				Code:  "QP-INPUT-012", Needs: se.Missing})
		case errors.Is(err, instance.ErrUnknownHoneypot):
			s.sendAPIError(w, http.StatusBadRequest, "QP-INPUT-003", "Unknown honeypot.")
		case errors.Is(err, instance.ErrSaveFailed):
			slog.Error("honeypot toggle: config not saved", "error", err)
			s.sendAPIError(w, http.StatusInternalServerError, "QP-INST-002", "The instance settings could not be saved.")
		default:
			s.sendInternalError(w, "honeypot toggle", err)
		}
		return
	}

	resp := honeypotToggleResponse{Status: "ok", Name: req.Name, Enabled: res.Enabled, Saved: true,
		InstanceRunning: res.InstanceRunning, Applied: res.Applied}
	state, verb := "on", "started"
	if !on {
		state, verb = "off", "stopped"
	}
	if res.Applied {
		resp.Message = fmt.Sprintf("Turned %s %s and %s it.", req.Name, state, verb)
	} else {
		resp.Message = fmt.Sprintf("Turned %s %s. The instance is not running; it applies when it starts.", req.Name, state)
	}
	writeJSON(w, http.StatusOK, resp)
}
