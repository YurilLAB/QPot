package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/qpot/qpot/internal/instance"
)

// POST /api/honeypots/restart: restart one honeypot's container (and its
// companions), the web UI's `qpot docker restart <instance>_<honeypot>`.

// honeypotRestartTimeout bounds the Docker work of one restart.
const honeypotRestartTimeout = 2 * time.Minute

// liveRunner reaches the running instance's containers: the server's own
// manager (or the test runner).
func (s *Server) liveRunner() instance.HoneypotRunner {
	if s.api.runner != nil {
		return s.api.runner(s.config)
	}
	if s.manager == nil {
		return nil
	}
	return s.manager
}

func (s *Server) handleHoneypotRestart(w http.ResponseWriter, r *http.Request) {
	if !s.allowMethods(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeJSONBody(w, r, 4096, &req); err != nil {
		s.sendAPIError(w, http.StatusBadRequest, "", err.Error())
		return
	}
	if !s.isKnownHoneypot(req.Name) {
		s.sendAPIError(w, http.StatusBadRequest, "QP-INPUT-003", "Unknown honeypot.")
		return
	}
	cfg, err := s.readConfig()
	if err != nil {
		slog.Error("honeypot restart: config file not read", "error", err)
		s.sendAPIError(w, http.StatusInternalServerError, "QP-INST-002", "The instance settings could not be read.")
		return
	}
	if hp, ok := cfg.GetHoneypotConfig(req.Name); !ok || !hp.Enabled {
		s.sendAPIError(w, http.StatusConflict, "", fmt.Sprintf("%s is turned off, so there is nothing to restart. Turn it on first.", req.Name))
		return
	}
	runner := s.liveRunner()
	if runner == nil {
		s.sendAPIError(w, http.StatusServiceUnavailable, "", "This server cannot reach the instance's containers.")
		return
	}
	if !s.api.change.TryLock() {
		s.sendAPIError(w, http.StatusConflict, "", "Another honeypot change is still running. Try again when it has finished.")
		return
	}
	defer s.api.change.Unlock()

	extendWriteDeadline(w, honeypotRestartTimeout+30*time.Second)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), honeypotRestartTimeout)
	defer cancel()
	if !runner.IsRunning(ctx) {
		s.sendAPIError(w, http.StatusConflict, "QP-INST-007",
			fmt.Sprintf("The instance is not running. Start it on the host with: qpot up -d -i %s", s.config.InstanceName))
		return
	}
	if err := runner.RestartHoneypot(ctx, req.Name); err != nil {
		slog.Error("honeypot restart failed", "honeypot", req.Name, "error", err)
		s.sendAPIError(w, http.StatusBadGateway, "QP-INST-008",
			fmt.Sprintf("%s did not restart. Its log (GET /api/logs?honeypot=%s) shows why.", req.Name, req.Name))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": req.Name, "restarted": true, "message": "Restarted " + req.Name + "."})
}
