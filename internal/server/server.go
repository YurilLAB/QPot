// Package server provides the QPot web API and UI
package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/instance"
	"github.com/qpot/qpot/internal/intelligence"
	"github.com/qpot/qpot/internal/yuril"
)

//go:embed static/*
var staticFS embed.FS

// Server represents the web server
type Server struct {
	config      *config.Config
	manager     *instance.Manager
	database    database.Database
	mux         *http.ServeMux
	classifier  *intelligence.Classifier
	worker      *intelligence.Worker
	ttpBuilder  *intelligence.TTPBuilder
	attckLoader *intelligence.ATTCKLoader
	// forwarder is the configured Yuril outbound forwarder, kept here so
	// the /api/yuril/health endpoint and `qpot yuril status` can expose
	// its activity counters. nil when Yuril forwarding is disabled.
	forwarder *yuril.Forwarder
}

// New creates a new web server.
// The database connection is attempted but a failure is non-fatal; API
// endpoints that require the database will return appropriate errors when
// it is unavailable.
func New(cfg *config.Config) (*Server, error) {
	mgr, err := instance.NewManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create manager: %w", err)
	}

	// Attempt DB connection; log a warning but do not abort server creation.
	var db database.Database
	if rawDB, err := database.New(&cfg.Database); err != nil {
		slog.Warn("Database not available at server start, some API endpoints will be unavailable", "error", err)
	} else {
		connectCtx, connectCancel := context.WithTimeout(context.Background(), 15*time.Second)
		if err := rawDB.Connect(connectCtx); err != nil {
			connectCancel()
			slog.Warn("Database connection failed, some API endpoints will be unavailable", "error", err)
		} else {
			connectCancel()
			db = rawDB
		}
	}

	s := &Server{
		config:   cfg,
		manager:  mgr,
		database: db,
		mux:      http.NewServeMux(),
	}

	// Wire up the intelligence subsystem when enabled.
	if cfg.Intelligence.Enabled {
		loader := intelligence.NewATTCKLoader(cfg.Intelligence.ATTCKDataPath)
		loader.Load(context.Background())
		ttpBuilder := intelligence.NewTTPBuilder(cfg.Intelligence.InactivityWindow)
		classifier := intelligence.NewClassifier(loader, ttpBuilder)
		s.attckLoader = loader
		s.ttpBuilder = ttpBuilder
		s.classifier = classifier
		if db != nil {
			w := intelligence.NewWorker(classifier, db, cfg.Intelligence.WorkerInterval, cfg.Intelligence.WorkerBatchSize)
			// Attach the Yuril forwarder when configured. Failures here are
			// logged but not fatal — QPot must stay up even if Yuril is
			// unreachable.
			if fwd, err := yuril.New(cfg.Yuril); err != nil {
				slog.Warn("Yuril forwarder disabled due to config error", "error", err)
			} else if fwd != nil {
				w = w.WithForwarder(fwd)
				s.forwarder = fwd
				slog.Info("Yuril forwarder enabled", "endpoint", cfg.Yuril.Endpoint)
			}
			s.worker = w
		}
	}

	s.setupRoutes()
	return s, nil
}

// setupRoutes configures HTTP routes
func (s *Server) setupRoutes() {
	// Static files
	s.mux.HandleFunc("/", s.handleStatic)

	// API routes with QPot ID auth
	s.mux.HandleFunc("/api/status", s.withQPotAuth(s.handleStatus))
	s.mux.HandleFunc("/api/honeypots", s.withQPotAuth(s.handleHoneypots))
	s.mux.HandleFunc("/api/events", s.withQPotAuth(s.handleEvents))
	s.mux.HandleFunc("/api/stats", s.withQPotAuth(s.handleStats))
	s.mux.HandleFunc("/api/logs", s.withQPotAuth(s.handleLogs))
	s.mux.HandleFunc("/api/ioc", s.withQPotAuth(s.handleIOC))

	// Intelligence API routes
	s.mux.HandleFunc("/api/techniques", s.withQPotAuth(s.handleTechniques))
	s.mux.HandleFunc("/api/iocs", s.withQPotAuth(s.handleIOCs))
	s.mux.HandleFunc("/api/ttps", s.withQPotAuth(s.handleTTPs))
	s.mux.HandleFunc("/api/intelligence", s.withQPotAuth(s.handleIntelligenceSummary))

	// Yuril Security Suite integration routes — bidirectional intel sharing
	// with YurilAntivirus / YurilTracking. All endpoints require the QPot
	// ID so an attacker who somehow reaches the API cannot poison the IOC
	// store or scrape attacker data.
	s.mux.HandleFunc("/api/yuril/intel", s.withQPotAuth(s.handleYurilIntel))
	s.mux.HandleFunc("/api/yuril/query", s.withQPotAuth(s.handleYurilQuery))
	s.mux.HandleFunc("/api/yuril/health", s.withQPotAuth(s.handleYurilHealth))
}

// withQPotAuth middleware checks QPot ID authentication
func (s *Server) withQPotAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If QPot ID auth is disabled, allow all
		if !s.config.WebUI.QPotIDAuth {
			next(w, r)
			return
		}

		// Check QPot ID from header
		qpotID := r.Header.Get("X-QPot-ID")
		if qpotID == "" {
			// Also check query parameter for easier testing
			qpotID = r.URL.Query().Get("qpot_id")
		}

		if qpotID == "" {
			s.sendError(w, http.StatusUnauthorized, "QPot ID required")
			return
		}

		// Validate QPot ID format
		if !strings.HasPrefix(qpotID, "qp_") || len(qpotID) != 27 {
			s.sendError(w, http.StatusUnauthorized, "Invalid QPot ID format")
			return
		}

		// Check if QPot ID matches this instance (constant-time to prevent timing oracle).
		if subtle.ConstantTimeCompare([]byte(qpotID), []byte(s.config.QPotID)) != 1 {
			s.sendError(w, http.StatusForbidden, "QPot ID does not match this instance")
			return
		}

		next(w, r)
	}
}

// handleStatic serves static files
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		r.URL.Path = "/static/index.html"
	}
	
	// Inject QPot ID into the HTML
	if r.URL.Path == "/static/index.html" {
		data, err := staticFS.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		
		html := string(data)
		// Inject the QPot ID as a script variable (JSON-encoded to prevent XSS).
		idJSON, _ := json.Marshal(s.config.QPotID)
		injection := fmt.Sprintf(`<script>window.QPOT_ID = %s;</script>`, idJSON)
		html = strings.Replace(html, "<head>", "<head>\n"+injection, 1)
		
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
		return
	}
	
	// Serve other static files normally
	http.FileServer(http.FS(staticFS)).ServeHTTP(w, r)
}

// Start starts the web server and background alert polling.
func (s *Server) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.config.WebUI.BindAddr, s.config.WebUI.Port)

	srv := &http.Server{
		Addr:         addr,
		Handler:      s.authMiddleware(s.mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	slog.Info("Starting web server", "addr", addr, "qpot_id", s.config.QPotID)

	// Start alert polling goroutine when alerts are enabled.
	if s.config.Alerts.Enabled && s.config.Alerts.WebhookURL != "" {
		go s.alertLoop(ctx)
	}

	// Start intelligence worker goroutine when enabled.
	if s.worker != nil {
		go s.worker.Run(ctx)
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	return srv.ListenAndServe()
}

// alertLoop polls event stats every minute and fires a webhook when the
// configured events-per-minute threshold is exceeded.
func (s *Server) alertLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.database == nil {
				continue
			}
			since := time.Now().Add(-time.Minute)
			stats, err := s.database.GetStats(ctx, since)
			if err != nil {
				slog.Warn("Alert loop: failed to get stats", "error", err)
				continue
			}

			triggered := false
			if len(s.config.Alerts.Honeypots) == 0 {
				// Alert on total events across all honeypots.
				if int(stats.TotalEvents) >= s.config.Alerts.Threshold {
					triggered = true
				}
			} else {
				// Alert only when a configured honeypot exceeds the threshold.
				for _, hc := range stats.TopHoneypots {
					for _, alertHP := range s.config.Alerts.Honeypots {
						if hc.Honeypot == alertHP && int(hc.Count) >= s.config.Alerts.Threshold {
							triggered = true
						}
					}
				}
			}

			if triggered {
				s.fireWebhook(ctx, stats)
				if s.config.Response.Enabled && len(s.config.Response.OnAttackDetected) > 0 {
					s.runResponseHooks(ctx, stats)
				}
			}
		}
	}
}

// runResponseHooks executes every configured response action when an
// alert threshold trips. Each command runs in a per-action timeout so a
// hung script can't block the alert loop, and stdout/stderr are captured
// to the structured log instead of inheriting the parent FDs.
func (s *Server) runResponseHooks(ctx context.Context, stats *database.Stats) {
	envExtra := s.responseEnv(ctx, stats)

	const defaultTimeout = 10 * time.Second
	const hardCap = 5 * time.Minute

	for i, action := range s.config.Response.OnAttackDetected {
		cmdLine := strings.TrimSpace(action.Command)
		if cmdLine == "" {
			slog.Warn("Response hook: empty command, skipping",
				"index", i, "name", action.Name)
			continue
		}
		timeout := action.Timeout
		if timeout <= 0 {
			timeout = defaultTimeout
		}
		if timeout > hardCap {
			timeout = hardCap
		}

		cmdCtx, cancel := context.WithTimeout(ctx, timeout)
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.CommandContext(cmdCtx, "cmd", "/C", cmdLine)
		} else {
			// Use sh, not bash — sh is universally available on Linux,
			// macOS, and BSDs, including minimal Arch installs.
			cmd = exec.CommandContext(cmdCtx, "sh", "-c", cmdLine)
		}
		cmd.Env = append(os.Environ(), envExtra...)

		out, err := cmd.CombinedOutput()
		cancel()
		// Trim trailing whitespace so multiline output doesn't double-line in logs.
		outStr := strings.TrimRight(string(out), "\n\r\t ")

		switch {
		case err == nil:
			slog.Info("Response hook ran",
				"name", action.Name, "command", cmdLine, "output", outStr)
		case errors.Is(cmdCtx.Err(), context.DeadlineExceeded):
			slog.Warn("Response hook timed out",
				"name", action.Name, "command", cmdLine, "timeout", timeout, "output", outStr)
		default:
			slog.Warn("Response hook failed",
				"name", action.Name, "command", cmdLine, "error", err, "output", outStr)
		}
	}
}

// responseEnv collects the environment variables that response-hook
// commands receive. The list is intentionally small and stable — every
// extra var is a contract that operators' scripts may grow to depend on.
func (s *Server) responseEnv(ctx context.Context, stats *database.Stats) []string {
	env := []string{
		"QPOT_ID=" + s.config.QPotID,
		"QPOT_INSTANCE=" + s.config.InstanceName,
		fmt.Sprintf("QPOT_TOTAL_EVENTS=%d", stats.TotalEvents),
	}
	if len(stats.TopHoneypots) > 0 {
		env = append(env, "QPOT_TOP_HONEYPOT="+stats.TopHoneypots[0].Honeypot)
	}
	// Top attacker IP isn't on Stats; pull it from GetTopAttackers with a
	// short timeout so a sluggish DB doesn't delay every hook.
	if s.database != nil {
		lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		since := time.Now().Add(-time.Minute)
		attackers, err := s.database.GetTopAttackers(lookupCtx, 1, since)
		if err == nil && len(attackers) > 0 {
			env = append(env, "QPOT_TOP_SOURCE_IP="+attackers[0].SourceIP)
		}
	}
	return env
}

// fireWebhook sends a JSON POST to the configured webhook URL.
func (s *Server) fireWebhook(ctx context.Context, stats *database.Stats) {
	payload := map[string]interface{}{
		"qpot_id":      s.config.QPotID,
		"instance":     s.config.InstanceName,
		"total_events": stats.TotalEvents,
		"unique_ips":   stats.UniqueIPs,
		"message":      fmt.Sprintf("QPot alert: %d events in the last minute on instance %s", stats.TotalEvents, s.config.InstanceName),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		slog.Error("Alert webhook: failed to marshal payload", "error", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.Alerts.WebhookURL, bytes.NewReader(body))
	if err != nil {
		slog.Error("Alert webhook: failed to create request", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	webhookClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := webhookClient.Do(req)
	if err != nil {
		slog.Error("Alert webhook: request failed", "error", err)
		return
	}
	resp.Body.Close()
	slog.Info("Alert webhook fired", "status", resp.StatusCode, "url", s.config.Alerts.WebhookURL)
}

// authMiddleware adds basic authentication
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for static files (they handle their own auth)
		if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}

		// If QPot ID auth is enabled, skip basic auth
		if s.config.WebUI.QPotIDAuth {
			next.ServeHTTP(w, r)
			return
		}

		// Fall back to basic auth if QPot ID auth disabled
		if s.config.WebUI.Username == "" || s.config.WebUI.Password == "" {
			next.ServeHTTP(w, r)
			return
		}

		user, pass, ok := r.BasicAuth()
		if !ok || user != s.config.WebUI.Username || pass != s.config.WebUI.Password {
			w.Header().Set("WWW-Authenticate", `Basic realm="QPot"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// handleStatus returns instance status
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	status, err := s.manager.Status(ctx)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Add QPot ID to status
	response := map[string]interface{}{
		"qpot_id":    s.config.QPotID,
		"instance":   s.config.InstanceName,
		"overall":    status.Overall,
		"honeypots":  status.Honeypots,
		"database":   s.config.Database.Type,
	}

	s.sendJSON(w, response)
}

// handleHoneypots manages honeypots
func (s *Server) handleHoneypots(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	switch r.Method {
	case http.MethodGet:
		// List honeypots
		var list []map[string]interface{}
		for name, hp := range s.config.Honeypots {
			// Check if running
			running := false
			if s.manager != nil {
				status, _ := s.manager.Status(ctx)
				if status != nil {
					for _, h := range status.Honeypots {
						if h.Name == name {
							running = h.Running
							break
						}
					}
				}
			}

			list = append(list, map[string]interface{}{
				"name":    name,
				"enabled": hp.Enabled,
				"running": running,
				"port":    hp.Port,
				"risk":    hp.RiskLevel,
			})
		}
		s.sendJSON(w, list)

	case http.MethodPost:
		// Enable/disable honeypot
		var req struct {
			Name    string `json:"name"`
			Enabled bool   `json:"enabled"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.sendError(w, http.StatusBadRequest, "Invalid request")
			return
		}

		if req.Enabled {
			s.config.EnableHoneypot(req.Name)
			if err := s.manager.StartHoneypot(ctx, req.Name); err != nil {
				s.sendError(w, http.StatusInternalServerError, err.Error())
				return
			}
		} else {
			s.config.DisableHoneypot(req.Name)
			if err := s.manager.StopHoneypot(ctx, req.Name); err != nil {
				s.sendError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}

		if err := config.Save(s.config); err != nil {
			s.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}

		s.sendJSON(w, map[string]string{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleEvents returns events
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if s.database == nil {
		s.sendError(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	ctx := r.Context()

	filter := database.EventFilter{
		Limit: 100,
	}

	// Parse query params
	if honeypots := r.URL.Query()["honeypot"]; len(honeypots) > 0 {
		filter.Honeypots = honeypots
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		if n, err := strconv.Atoi(limit); err == nil && n > 0 {
			if n > 1000 {
				n = 1000
			}
			filter.Limit = n
		}
	}

	events, err := s.database.GetEvents(ctx, filter)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Add QPot ID to each event for tracking
	response := map[string]interface{}{
		"qpot_id": s.config.QPotID,
		"events":  events,
	}

	s.sendJSON(w, response)
}

// handleStats returns statistics
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var stats *database.Stats
	if s.database != nil {
		since := time.Now().Add(-24 * time.Hour)
		var err error
		stats, err = s.database.GetStats(ctx, since)
		if err != nil {
			stats = &database.Stats{}
		}
	} else {
		stats = &database.Stats{}
	}

	// Add QPot ID to stats
	response := map[string]interface{}{
		"qpot_id":       s.config.QPotID,
		"total_events":  stats.TotalEvents,
		"unique_ips":    stats.UniqueIPs,
		"top_countries": stats.TopCountries,
		"top_honeypots": stats.TopHoneypots,
	}

	s.sendJSON(w, response)
}

// handleLogs returns logs
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	honeypot := r.URL.Query().Get("honeypot")
	tail := 100
	if t := r.URL.Query().Get("tail"); t != "" {
		if n, err := strconv.Atoi(t); err == nil && n > 0 {
			if n > 5000 {
				n = 5000
			}
			tail = n
		}
	}

	logs, err := s.manager.GetLogs(ctx, honeypot, false, tail)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var lines []string
	for line := range logs {
		lines = append(lines, line)
	}

	s.sendJSON(w, lines)
}

// handleIOC returns a list of unique source IPs seen in the last 24 hours,
// sorted by attack count. Useful for firewall blocklist generation.
func (s *Server) handleIOC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.database == nil {
		s.sendError(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	ctx := r.Context()
	since := time.Now().Add(-24 * time.Hour)

	attackers, err := s.database.GetTopAttackers(ctx, 1000, since)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	type IOCEntry struct {
		SourceIP    string   `json:"source_ip"`
		Country     string   `json:"country,omitempty"`
		AttackCount int64    `json:"attack_count"`
		Honeypots   []string `json:"honeypots,omitempty"`
		FirstSeen   string   `json:"first_seen"`
		LastSeen    string   `json:"last_seen"`
	}

	entries := make([]IOCEntry, 0, len(attackers))
	for _, a := range attackers {
		entries = append(entries, IOCEntry{
			SourceIP:    a.SourceIP,
			Country:     a.Country,
			AttackCount: a.AttackCount,
			Honeypots:   a.Honeypots,
			FirstSeen:   a.FirstSeen.UTC().Format(time.RFC3339),
			LastSeen:    a.LastSeen.UTC().Format(time.RFC3339),
		})
	}

	response := map[string]interface{}{
		"qpot_id":    s.config.QPotID,
		"generated":  time.Now().UTC().Format(time.RFC3339),
		"count":      len(entries),
		"ioc_list":   entries,
	}
	s.sendJSON(w, response)
}

// handleTechniques returns unique ATT&CK techniques observed in classified events.
func (s *Server) handleTechniques(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.database == nil {
		s.sendError(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	ctx := r.Context()
	// Fetch recent events and aggregate technique counts client-side.
	filter := database.EventFilter{Limit: 10000}
	events, err := s.database.GetEvents(ctx, filter)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	type techEntry struct {
		TechniqueID   string `json:"technique_id"`
		TechniqueName string `json:"technique_name"`
		TacticName    string `json:"tactic_name"`
		Count         int    `json:"count"`
	}

	counts := make(map[string]*techEntry)
	for _, ev := range events {
		if ev.TechniqueID == "" {
			continue
		}
		entry, ok := counts[ev.TechniqueID]
		if !ok {
			entry = &techEntry{
				TechniqueID:   ev.TechniqueID,
				TechniqueName: ev.TechniqueName,
				TacticName:    ev.TacticName,
			}
			counts[ev.TechniqueID] = entry
		}
		entry.Count++
	}

	result := make([]*techEntry, 0, len(counts))
	for _, e := range counts {
		result = append(result, e)
	}
	// Sort by count descending.
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j].Count > result[i].Count {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	s.sendJSON(w, result)
}

// handleIOCs returns filtered IOC records.
func (s *Server) handleIOCs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.database == nil {
		s.sendError(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	ctx := r.Context()
	filter := database.IOCFilter{Limit: 100}

	if t := r.URL.Query().Get("type"); t != "" {
		filter.Types = []string{t}
	}
	if hp := r.URL.Query().Get("honeypot"); hp != "" {
		filter.Honeypots = []string{hp}
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &filter.Limit)
	}

	iocs, err := s.database.GetIOCs(ctx, filter)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.sendJSON(w, iocs)
}

// handleTTPs returns TTP session records.
func (s *Server) handleTTPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.database == nil {
		s.sendError(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	ctx := r.Context()
	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			if n > 500 {
				n = 500
			}
			limit = n
		}
	}

	sessions, err := s.database.GetTTPSessions(ctx, limit)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.sendJSON(w, sessions)
}

// handleIntelligenceSummary returns a high-level intelligence overview.
func (s *Server) handleIntelligenceSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	activeSessions := 0
	if s.ttpBuilder != nil {
		activeSessions = len(s.ttpBuilder.GetActiveSessions())
	}

	attckLoaded := false
	if s.attckLoader != nil {
		attckLoaded = s.attckLoader.Loaded()
	}

	var techniquesObserved int
	var iocsTotal int

	if s.database != nil {
		ctx := r.Context()
		// Sample up to 5000 recent events to count distinct observed techniques.
		// This is an approximation that avoids loading the full event table.
		events, err := s.database.GetEvents(ctx, database.EventFilter{Limit: 5000})
		if err == nil {
			seen := make(map[string]bool)
			for _, ev := range events {
				if ev.TechniqueID != "" {
					seen[ev.TechniqueID] = true
				}
			}
			techniquesObserved = len(seen)
		}

		// Approximate IOC count using a larger sample.
		iocs, err := s.database.GetIOCs(ctx, database.IOCFilter{Limit: 10000})
		if err == nil {
			iocsTotal = len(iocs)
		}
	}

	summary := map[string]interface{}{
		"techniques_observed": techniquesObserved,
		"iocs_total":          iocsTotal,
		"active_sessions":     activeSessions,
		"worker_enabled":      s.worker != nil,
		"attck_loaded":        attckLoaded,
	}

	s.sendJSON(w, summary)
}

// sendJSON sends a JSON response
func (s *Server) sendJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// sendError sends an error response
func (s *Server) sendError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   message,
		"qpot_id": s.config.QPotID,
	})
}

// handleYurilHealth is a probe endpoint for the Yuril side to confirm
// the integration is configured correctly: the QPot ID matches, the
// database is reachable, the intelligence subsystem is up, and (when
// applicable) the outbound forwarder is healthy. This is the endpoint
// `qpot yuril test` hits and the one YurilTracking should use as a
// liveness check before forwarding intel.
func (s *Server) handleYurilHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Negotiate API version: if the caller sent X-QPot-API-Version and it
	// doesn't match ours, reply 400 so they fail loudly rather than send
	// payloads we won't understand. An empty header means "I don't care".
	if v := r.Header.Get("X-QPot-API-Version"); v != "" && v != yuril.APIVersion {
		s.sendError(w, http.StatusBadRequest,
			fmt.Sprintf("API version mismatch: client=%s server=%s", v, yuril.APIVersion))
		return
	}

	dbOK := false
	if s.database != nil {
		// A short-timeout sanity query: if the DB is up but slow, don't
		// hold the probe open forever.
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		_, err := s.database.GetStats(ctx, time.Now().Add(-time.Minute))
		dbOK = err == nil
	}

	resp := map[string]interface{}{
		"status":      "ok",
		"qpot_id":     s.config.QPotID,
		"instance":    s.config.InstanceName,
		"api_version": yuril.APIVersion,
		"database":    map[string]interface{}{"reachable": dbOK, "type": s.config.Database.Type},
		"intel": map[string]interface{}{
			"enabled":     s.config.Intelligence.Enabled,
			"worker_up":   s.worker != nil,
			"attck_loaded": s.attckLoader != nil && s.attckLoader.Loaded(),
		},
	}
	if s.forwarder != nil {
		resp["forwarder"] = s.forwarder.Stats()
	} else {
		resp["forwarder"] = map[string]interface{}{"enabled": false}
	}

	w.Header().Set("X-QPot-API-Version", yuril.APIVersion)
	s.sendJSON(w, resp)
}

// yurilIntelRequest is the inbound payload for /api/yuril/intel. The
// shape mirrors the outbound forwarder's IntelBatch so YurilAntivirus
// can forward intel back to QPot using the same wire format it receives.
type yurilIntelRequest struct {
	BatchID string `json:"batch_id,omitempty"`
	Source  string `json:"source,omitempty"`
	Items   []struct {
		Type     string            `json:"type"`
		Value    string            `json:"value"`
		Severity string            `json:"severity,omitempty"`
		Context  map[string]string `json:"context,omitempty"`
	} `json:"items"`
}

// handleYurilIntel accepts IOC pushes from the Yuril Security Suite and
// upserts them into QPot's IOC table. This makes the deception layer
// reactive: an antivirus detection on an endpoint immediately becomes a
// honeypot blocklist entry.
func (s *Server) handleYurilIntel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.database == nil {
		s.sendError(w, http.StatusServiceUnavailable, "database not available")
		return
	}
	if v := r.Header.Get("X-QPot-API-Version"); v != "" && v != yuril.APIVersion {
		s.sendError(w, http.StatusBadRequest,
			fmt.Sprintf("API version mismatch: client=%s server=%s", v, yuril.APIVersion))
		return
	}
	w.Header().Set("X-QPot-API-Version", yuril.APIVersion)

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB cap
	var req yurilIntelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.Items) == 0 {
		s.sendError(w, http.StatusBadRequest, "items array is required and non-empty")
		return
	}

	now := time.Now().UTC()
	source := strings.TrimSpace(req.Source)
	if source == "" {
		source = "yuril"
	}

	accepted := 0
	skipped := 0
	for i, item := range req.Items {
		t := strings.ToLower(strings.TrimSpace(item.Type))
		v := strings.TrimSpace(item.Value)
		if v == "" {
			skipped++
			continue
		}
		// Only accept the IOC types our schema models. Anything else is
		// dropped with a logged warning rather than coerced.
		switch t {
		case "ip", "domain", "url", "hash":
			// ok
		default:
			slog.Debug("yuril intel: skipping unsupported IOC type",
				"index", i, "type", item.Type)
			skipped++
			continue
		}

		// Tag every inbound item with its origin so operators can audit which
		// indicators came from QPot's own honeypots vs. pushed by Yuril.
		meta := map[string]string{
			"origin":      "yuril_inbound",
			"yuril_source": source,
		}
		if item.Severity != "" {
			meta["severity"] = item.Severity
		}
		for k, val := range item.Context {
			// Don't let inbound metadata clobber our origin tag.
			if k == "origin" {
				continue
			}
			meta[k] = val
		}

		ioc := &database.IOC{
			Type:      t,
			Value:     v,
			Honeypot:  "_yuril",
			FirstSeen: now,
			LastSeen:  now,
			Count:     1,
			Metadata:  meta,
		}
		if err := s.database.InsertIOC(r.Context(), ioc); err != nil {
			slog.Warn("yuril intel: InsertIOC failed", "type", t, "value", v, "error", err)
			skipped++
			continue
		}
		accepted++
	}

	s.sendJSON(w, map[string]interface{}{
		"qpot_id":  s.config.QPotID,
		"accepted": accepted,
		"skipped":  skipped,
		"received": len(req.Items),
	})
}

// handleYurilQuery returns everything QPot knows about a given indicator
// — recent events, related IOCs, observed techniques. YurilAntivirus
// hits this when an endpoint sees a connection to a suspicious peer and
// wants to know whether the same peer has been hitting our honeypots.
//
// Query params (at least one required):
//
//	ip=<source-ip>
//	hash=<md5|sha1|sha256>
//	domain=<domain>
func (s *Server) handleYurilQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.database == nil {
		s.sendError(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	q := r.URL.Query()
	ip := strings.TrimSpace(q.Get("ip"))
	hash := strings.TrimSpace(q.Get("hash"))
	domain := strings.TrimSpace(q.Get("domain"))
	if ip == "" && hash == "" && domain == "" {
		s.sendError(w, http.StatusBadRequest, "at least one of ip, hash, domain is required")
		return
	}

	ctx := r.Context()
	since := time.Now().Add(-7 * 24 * time.Hour) // last 7 days

	response := map[string]interface{}{
		"qpot_id":   s.config.QPotID,
		"queried":   map[string]string{"ip": ip, "hash": hash, "domain": domain},
		"queried_at": time.Now().UTC().Format(time.RFC3339),
	}

	// IP lookup: count attacker activity over the last 7 days.
	if ip != "" {
		attackers, err := s.database.GetTopAttackers(ctx, 1000, since)
		if err != nil {
			slog.Warn("yuril query: GetTopAttackers failed", "error", err)
		} else {
			for _, a := range attackers {
				if a.SourceIP == ip {
					response["ip_activity"] = map[string]interface{}{
						"attack_count": a.AttackCount,
						"country":      a.Country,
						"honeypots":    a.Honeypots,
						"first_seen":   a.FirstSeen.UTC().Format(time.RFC3339),
						"last_seen":    a.LastSeen.UTC().Format(time.RFC3339),
					}
					break
				}
			}
		}
	}

	// IOC lookup across all types — a single query then in-memory filter
	// avoids three round trips.
	iocs, err := s.database.GetIOCs(ctx, database.IOCFilter{Limit: 5000})
	if err != nil {
		slog.Warn("yuril query: GetIOCs failed", "error", err)
	} else {
		var matches []*database.IOC
		for _, ioc := range iocs {
			switch {
			case ip != "" && (ioc.SourceIP == ip || (ioc.Type == "ip" && ioc.Value == ip)):
				matches = append(matches, ioc)
			case hash != "" && ioc.Type == "hash" && strings.EqualFold(ioc.Value, hash):
				matches = append(matches, ioc)
			case domain != "" && ioc.Type == "domain" && strings.EqualFold(ioc.Value, domain):
				matches = append(matches, ioc)
			}
		}
		response["matching_iocs"] = matches
		response["matching_iocs_count"] = len(matches)
	}

	s.sendJSON(w, response)
}
