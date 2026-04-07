// Package server provides the QPot web API and UI
package server

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/instance"
)

//go:embed static/*
var staticFS embed.FS

// Server represents the web server
type Server struct {
	config   *config.Config
	manager  *instance.Manager
	database database.Database
	mux      *http.ServeMux
}

// New creates a new web server
func New(cfg *config.Config) (*Server, error) {
	mgr, err := instance.NewManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create manager: %w", err)
	}

	db, err := database.New(&cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("failed to create database: %w", err)
	}

	s := &Server{
		config:   cfg,
		manager:  mgr,
		database: db,
		mux:      http.NewServeMux(),
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

		// Check if QPot ID matches this instance
		if qpotID != s.config.QPotID {
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
		// Inject the QPot ID as a script variable
		injection := fmt.Sprintf(`<script>window.QPOT_ID = "%s";</script>`, s.config.QPotID)
		html = strings.Replace(html, "<head>", "<head>\n"+injection, 1)
		
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
		return
	}
	
	// Serve other static files normally
	http.FileServer(http.FS(staticFS)).ServeHTTP(w, r)
}

// Start starts the web server
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

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	return srv.ListenAndServe()
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
	ctx := r.Context()

	filter := database.EventFilter{
		Limit: 100,
	}

	// Parse query params
	if honeypots := r.URL.Query()["honeypot"]; len(honeypots) > 0 {
		filter.Honeypots = honeypots
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		fmt.Sscanf(limit, "%d", &filter.Limit)
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

	since := time.Now().Add(-24 * time.Hour)
	stats, err := s.database.GetStats(ctx, since)
	if err != nil {
		// Return empty stats if database not ready
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
	fmt.Sscanf(r.URL.Query().Get("tail"), "%d", &tail)

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

// sendJSON sends a JSON response
func (s *Server) sendJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// sendError sends an error response
func (s *Server) sendError(w http.ResponseWriter, code int, message string) {
	w.WriteHeader(code)
	s.sendJSON(w, map[string]string{
		"error":    message,
		"qpot_id":  s.config.QPotID,
	})
}
