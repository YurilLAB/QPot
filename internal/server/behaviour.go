package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/qpot/qpot/internal/behaviour"
	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/intelligence"
)

// Behaviour alerts (doc/alerts.md): what visitors do, not how many events
// there are. The loop reads what the intelligence worker stored, asks
// internal/behaviour what is new, keeps the answers and sends them on.

const (
	// behaviourInterval is how often the stored sessions are looked at.
	behaviourInterval = time.Minute
	// behaviourSessions and behaviourPayloads bound one look.
	behaviourSessions = 5000
	behaviourPayloads = 5000
	// maxBehaviourBody bounds a settings change.
	maxBehaviourBody = 4 << 10
)

// behaviourState is the server's copy of the alert state, loaded from the
// instance's data folder on first use.
type behaviourState struct {
	mu     sync.Mutex
	state  *behaviour.State
	failed error // why the state file could not be used
}

// load returns the state, reading it once. The caller holds b.mu.
func (b *behaviourState) load(dataPath string) (*behaviour.State, error) {
	if b.state == nil && b.failed == nil {
		b.state, b.failed = behaviour.Load(dataPath)
	}
	return b.state, b.failed
}

// behaviourLoop evaluates the behaviour rules every minute while the
// control plane runs.
func (s *Server) behaviourLoop(ctx context.Context) {
	t := time.NewTicker(behaviourInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.behaviourPass(ctx, time.Now())
		}
	}
}

// behaviourPass looks once and delivers what is new. It returns the alerts
// raised.
func (s *Server) behaviourPass(ctx context.Context, now time.Time) []behaviour.Alert {
	cfg, err := s.readConfig()
	if err != nil {
		cfg = s.config
	}
	if cfg.Alerts.Behaviour.Disabled || !cfg.Intelligence.Enabled {
		return nil
	}
	db := s.db()
	if db == nil {
		return nil
	}
	qctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	sessions, err := db.GetTTPSessions(qctx, behaviourSessions)
	if err != nil {
		slog.Warn("Behaviour alerts: sessions not read", "error", err)
		return nil
	}
	payloads, err := db.GetIOCs(qctx, database.IOCFilter{Types: []string{intelligence.IOCTypeHash}, Limit: behaviourPayloads})
	if err != nil {
		slog.Warn("Behaviour alerts: payload hashes not read", "error", err)
		return nil
	}
	in := behaviour.Input{Now: now, Sessions: sessions, Payloads: payloads, Off: cfg.Alerts.Behaviour.Off}
	if s.canaries != nil {
		in.Trips, in.Canaries = s.canaries.Trips(0), s.canaries.List()
	} else {
		in.Trips, in.Canaries = []*canary.Trip{}, []*canary.Canary{}
	}

	b := &s.behaviour
	b.mu.Lock()
	state, err := b.load(cfg.DataPath)
	if err != nil {
		b.mu.Unlock()
		slog.Error("Behaviour alerts are off: their state file cannot be used. Move it away to start again from a new baseline.", "file", behaviour.StatePath(cfg.DataPath), "error", err)
		return nil
	}
	raised := behaviour.Evaluate(state, in)
	err = behaviour.Save(cfg.DataPath, state)
	b.mu.Unlock()
	if err != nil {
		// Not saved: after a restart these would alert again, which is the
		// safe way round.
		slog.Warn("Behaviour alerts: state not saved", "error", err)
	}
	for _, a := range raised {
		slog.Warn("Behaviour alert", "rule", a.Rule, "severity", a.Severity, "title", a.Title, "session", a.SessionID, "campaign", a.Campaign)
		if cfg.Alerts.WebhookURL != "" {
			s.fireBehaviourWebhook(ctx, cfg, a)
		}
		if cfg.Response.Enabled && len(cfg.Response.OnBehaviour) > 0 {
			s.runHooks(ctx, cfg.Response.OnBehaviour, s.behaviourEnv(cfg, a))
		}
	}
	return raised
}

// behaviourEnv is what a behaviour hook receives.
func (s *Server) behaviourEnv(cfg *config.Config, a behaviour.Alert) []string {
	env := []string{
		"QPOT_ID=" + cfg.QPotID,
		"QPOT_SENSOR_ID=" + cfg.SensorID(),
		"QPOT_INSTANCE=" + cfg.InstanceName,
		"QPOT_TIMESTAMP=" + a.Time.UTC().Format(time.RFC3339),
		"QPOT_ALERT_RULE=" + a.Rule,
		"QPOT_ALERT_SEVERITY=" + a.Severity,
		"QPOT_ALERT_TITLE=" + a.Title,
		"QPOT_ALERT_SESSION=" + a.SessionID,
		"QPOT_ALERT_CAMPAIGN=" + a.Campaign,
	}
	if len(a.Sources) > 0 {
		env = append(env, "QPOT_ALERT_SOURCE_IP="+a.Sources[0])
	}
	return env
}

// fireBehaviourWebhook posts one behaviour alert to the webhook.
func (s *Server) fireBehaviourWebhook(ctx context.Context, cfg *config.Config, a behaviour.Alert) {
	// No QPot ID, as in the volume alert: the payload goes to a third party.
	payload := map[string]any{
		"instance":  cfg.InstanceName,
		"timestamp": a.Time.UTC().Format(time.RFC3339),
		"kind":      "behaviour",
		"rule":      a.Rule,
		"severity":  a.Severity,
		"message":   fmt.Sprintf("QPot %s alert on instance %s: %s", a.Severity, cfg.InstanceName, a.Title),
		"detail":    a.Detail,
	}
	if a.SessionID != "" {
		payload["session_id"] = a.SessionID
	}
	if a.Campaign != "" {
		payload["campaign_fingerprint"] = a.Campaign
	}
	if len(a.Sources) > 0 {
		payload["source_ips"] = a.Sources
	}
	if len(a.Evidence) > 0 {
		payload["evidence"] = a.Evidence
	}
	body, err := json.Marshal(payload)
	if err != nil {
		slog.Error("Behaviour alert webhook: payload not encoded", "error", err)
		return
	}
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, cfg.Alerts.WebhookURL, bytes.NewReader(body))
	if err != nil {
		slog.Error("Behaviour alert webhook: request not created", "error", withoutURL(err))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		slog.Error("Behaviour alert webhook: request failed", "host", req.URL.Host, "error", withoutURL(err))
		return
	}
	resp.Body.Close()
	slog.Info("Behaviour alert webhook fired", "status", resp.StatusCode, "host", req.URL.Host, "rule", a.Rule)
}

// behaviourRule is one rule in the API's answer.
type behaviourRule struct {
	behaviour.Rule
	Enabled bool `json:"enabled"`
}

// behaviourView is the answer of GET and PUT /api/alerts.
type behaviourView struct {
	// Enabled is false when the rules are turned off as a whole; Running is
	// false when they cannot run (the intelligence worker is off).
	Enabled bool `json:"enabled"`
	Running bool `json:"running"`
	// Webhook and Hooks say where an alert goes besides this list.
	Webhook bool            `json:"webhook"`
	Hooks   int             `json:"hooks"`
	Since   *time.Time      `json:"since,omitempty"`
	Rules   []behaviourRule `json:"rules"`
	// Alerts are the most recent alerts, newest first.
	Alerts []behaviour.Alert `json:"alerts"`
	// Problem says why the alert state cannot be used, if it cannot.
	Problem string `json:"problem,omitempty"`
}

func (s *Server) behaviourView(cfg *config.Config, limit int) behaviourView {
	c := cfg.Alerts.Behaviour
	v := behaviourView{Enabled: !c.Disabled, Running: !c.Disabled && cfg.Intelligence.Enabled, Webhook: cfg.Alerts.WebhookURL != "",
		Rules: make([]behaviourRule, 0, len(behaviour.Rules)), Alerts: []behaviour.Alert{}}
	if cfg.Response.Enabled {
		v.Hooks = len(cfg.Response.OnBehaviour)
	}
	off := map[string]bool{}
	for _, r := range c.Off {
		off[r] = true
	}
	for _, r := range behaviour.Rules {
		v.Rules = append(v.Rules, behaviourRule{Rule: r, Enabled: !c.Disabled && !off[r.Name]})
	}
	b := &s.behaviour
	b.mu.Lock()
	defer b.mu.Unlock()
	state, err := b.load(cfg.DataPath)
	if err != nil {
		v.Problem = "The alert state file cannot be used. Move it away to start again from a new baseline."
		return v
	}
	if !state.Started.IsZero() {
		started := state.Started
		v.Since = &started
	}
	for i := len(state.Alerts) - 1; i >= 0 && len(v.Alerts) < limit; i-- {
		v.Alerts = append(v.Alerts, state.Alerts[i])
	}
	return v
}

// GET /api/alerts?limit=N: the behaviour rules and the most recent alerts.
// PUT /api/alerts: {"enabled": bool} turns all rules on or off,
// {"rule": name, "enabled": bool} one of them.
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if !s.allowMethods(w, r, http.MethodGet, http.MethodPut) {
		return
	}
	if r.Method == http.MethodPut {
		s.putAlerts(w, r)
		return
	}
	limit, err := parseIntParam(r.URL.Query(), "limit", 100, 1, behaviour.MaxAlerts)
	if err != nil {
		s.sendAPIError(w, http.StatusBadRequest, "", "Bad request: "+err.Error()+".")
		return
	}
	cfg, err := s.readConfig()
	if err != nil {
		slog.Error("alerts: config file not read", "error", err)
		s.sendAPIError(w, http.StatusInternalServerError, "QP-INST-002", "The instance settings could not be read.")
		return
	}
	writeJSON(w, http.StatusOK, s.behaviourView(cfg, limit))
}

func (s *Server) putAlerts(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Rule    string `json:"rule"`
		Enabled *bool  `json:"enabled"`
	}
	if err := decodeJSONBody(w, r, maxBehaviourBody, &req); err != nil {
		s.sendAPIError(w, http.StatusBadRequest, "QP-WEB-004", err.Error())
		return
	}
	if req.Enabled == nil {
		s.sendAPIError(w, http.StatusBadRequest, "QP-INPUT-012", `Say what to change: {"enabled": true or false}, with "rule" to change one rule.`)
		return
	}
	if req.Rule != "" && !behaviour.IsRule(req.Rule) {
		s.sendAPIError(w, http.StatusBadRequest, "QP-INPUT-012", "There is no such rule. GET /api/alerts lists the rules.")
		return
	}
	if !s.api.change.TryLock() {
		s.sendAPIError(w, http.StatusConflict, "QP-INST-009", "Another change to this instance is still running. Try again when it has finished.")
		return
	}
	defer s.api.change.Unlock()
	cfg, err := s.loadConfigForChange()
	if err != nil {
		slog.Error("alerts: config file not read", "error", err)
		s.sendAPIError(w, http.StatusInternalServerError, "QP-INST-002", "The instance settings could not be read.")
		return
	}
	c := &cfg.Alerts.Behaviour
	if req.Rule == "" {
		c.Disabled = !*req.Enabled
	} else {
		// The list holds known rules only, each once, in the rules' order.
		off := map[string]bool{}
		for _, name := range c.Off {
			off[name] = true
		}
		off[req.Rule] = !*req.Enabled
		c.Off = nil
		for _, rule := range behaviour.Rules {
			if off[rule.Name] {
				c.Off = append(c.Off, rule.Name)
			}
		}
		if *req.Enabled {
			c.Disabled = false // turning a rule on means wanting its alerts
		}
	}
	if err := config.Save(cfg); err != nil {
		slog.Error("alerts: settings not saved", "error", err)
		s.sendAPIError(w, http.StatusInternalServerError, "QP-INST-002", "The alert settings could not be saved.")
		return
	}
	slog.Info("Behaviour alert settings changed", "disabled", c.Disabled, "off", len(c.Off))
	writeJSON(w, http.StatusOK, s.behaviourView(cfg, 100))
}
