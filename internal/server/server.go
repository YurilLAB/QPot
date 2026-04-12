// Package server provides the QPot web API and UI
package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/instance"
	"github.com/qpot/qpot/internal/intelligence"
)

//go:embed static/*
var staticFS embed.FS

// Server represents the web server
type Server struct {
	config     *config.Config
	manager    *instance.Manager
	database   database.Database
	mux        *http.ServeMux
	classifier *intelligence.Classifier
	worker     *intelligence.Worker
	ttpBuilder *intelligence.TTPBuilder
	attckLoader *intelligence.ATTCKLoader
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
			s.worker = intelligence.NewWorker(classifier, db, cfg.Intelligence.WorkerInterval, cfg.Intelligence.WorkerBatchSize)
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
			}
		}
	}
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
