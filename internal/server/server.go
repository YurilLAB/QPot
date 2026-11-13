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
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/cluster"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/hostsetup"
	"github.com/qpot/qpot/internal/instance"
	"github.com/qpot/qpot/internal/intelligence"
	"github.com/qpot/qpot/internal/overview"
)

//go:embed static
var staticFS embed.FS

// Server represents the web server
type Server struct {
	config  *config.Config
	manager *instance.Manager
	// Start serves the web UI at once and fills these in behind it: database
	// once it is reached (connectDatabase), classifier, ttpBuilder and
	// attckLoader once the ATT&CK data is loaded (prepareIntelligence), and
	// worker once both are there. Read them through db(), intelWorker(),
	// intelClassifier() and intelState().
	dbMu        sync.RWMutex
	database    database.Database
	mux         *http.ServeMux
	classifier  *intelligence.Classifier
	worker      *intelligence.Worker
	ttpBuilder  *intelligence.TTPBuilder
	attckLoader *intelligence.ATTCKLoader
	// cluster exposes the honeypot "group" (paired QPot nodes) to the
	// Pairing/Networking dashboard tab. nil when this node is standalone.
	cluster *cluster.Manager

	// canaries is the canary (honeytoken) registry. nil when the subsystem is
	// disabled, in which case the beacon and management routes are not served.
	canaries *canary.Store
	// canaryOutbox holds canary trips the database has not taken yet (see
	// canary_outbox.go). nil without the canary subsystem.
	canaryOutbox *canaryOutbox
	// planted is followPlanted's state: the planted canaries follow the
	// instance's config file while the server runs.
	planted plantedFollower

	// behaviour is the state of the behaviour alerts (behaviour.go).
	behaviour behaviourState

	// casesBuilding counts the investigation cases being put together, under
	// caseMu: at most caseSlots at once (api_investigate.go).
	caseMu        sync.Mutex
	casesBuilding int

	// lastAlert is when the alert loop last fired (webhook/response hooks),
	// used to debounce alerting within Alerts.Cooldown. Touched only by the
	// single alertLoop goroutine.
	lastAlert time.Time

	// startedAt is when this control plane started serving: the node's uptime
	// in its cluster. nodeStats is the last node stats sent to the cluster,
	// kept when a database query fails. Both touched only by Start and the
	// node stats goroutine.
	startedAt time.Time
	nodeStats cluster.NodeStats

	// api is the state of the web UI's api_*.go endpoints.
	api apiState
}

// dbStartupWait is how long after the server starts it tries the database
// every startupRetry before backing off (reconnectBackoff). `qpot up` starts
// the database container moments before the web server, and a fresh
// ClickHouse refuses connections and then reports "Database qpot does not
// exist" while its entrypoint initialises; a single attempt lost that race,
// the schema was never created and the collector dropped every event.
var dbStartupWait = 90 * time.Second

// startupRetry is how often the server tries the database during
// dbStartupWait.
var startupRetry = 2 * time.Second

// errNoDatabaseClient: the config names no database QPot can open.
var errNoDatabaseClient = errors.New("no database client for this config")

// openDatabase makes one attempt to connect to the instance database and
// ensure its schema. Ensuring the schema is idempotent (CREATE ... IF NOT
// EXISTS) and makes `qpot up` work on a fresh database without a separate
// `qpot db migrate` step; otherwise the events table is never created and the
// collector drops everything. A cancelled ctx stops the attempt. Tests replace
// it.
var openDatabase = func(ctx context.Context, cfg *config.Config) (database.Database, error) {
	rawDB, err := database.New(cfg.DatabaseClient())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNoDatabaseClient, err)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := rawDB.Connect(ctx); err != nil {
		return nil, err
	}
	if err := rawDB.InitializeSchema(ctx); err != nil {
		_ = rawDB.Close()
		return nil, fmt.Errorf("initialize schema: %w", err)
	}
	return rawDB, nil
}

// db is the instance database, or nil until it has been reached.
func (s *Server) db() database.Database {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()
	return s.database
}

// intelWorker is the intelligence worker, or nil while it has no database.
func (s *Server) intelWorker() *intelligence.Worker {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()
	return s.worker
}

// intelClassifier is the event classifier, or nil while intelligence is off
// or its ATT&CK data is still loading.
func (s *Server) intelClassifier() *intelligence.Classifier {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()
	return s.classifier
}

// intelState is the classifier's session builder and ATT&CK data, nil like
// intelClassifier.
func (s *Server) intelState() (*intelligence.TTPBuilder, *intelligence.ATTCKLoader) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()
	return s.ttpBuilder, s.attckLoader
}

// prepareIntelligence loads the ATT&CK data (MITRE's latest when it can be
// fetched, else the cached or embedded copy) and builds the classifier from
// it. Start runs it behind the web UI: the download takes up to 30 seconds.
func (s *Server) prepareIntelligence(ctx context.Context) {
	cfg := s.config.Intelligence
	loader := intelligence.NewATTCKLoader(cfg.ATTCKDataPath)
	loader.Load(ctx)
	ttpBuilder := intelligence.NewTTPBuilder(cfg.InactivityWindow)
	classifier := intelligence.NewClassifier(loader, ttpBuilder)
	s.dbMu.Lock()
	s.attckLoader, s.ttpBuilder, s.classifier = loader, ttpBuilder, classifier
	s.dbMu.Unlock()
}

// newWorker builds the intelligence worker over db, when intelligence is on.
// Callers hold dbMu.
func (s *Server) newWorker(db database.Database) *intelligence.Worker {
	if s.classifier == nil || db == nil {
		return nil
	}
	cfg := s.config.Intelligence
	w := intelligence.NewWorker(s.classifier, db, cfg.WorkerInterval, cfg.WorkerBatchSize)
	// Let the worker scan captured sessions for planted canary credential
	// values as it classifies them.
	if s.canaries != nil {
		w = w.WithCanaryMatcher(&canaryMatcher{s: s})
	}
	return w
}

// workerRestartDelay bounds the wait before a stopped intelligence worker is
// replaced: short at first, so a database restart costs seconds, then longer
// while whatever stops it lasts (another node owns the work, the database is
// still away). The longest wait is what recovery can take after the database
// is back: at a minute, the failure soak measured 45 to 63 seconds from a
// database's return to intelligence running again. A try costs a handful of
// small queries.
var workerRestartDelay = [2]time.Duration{5 * time.Second, 15 * time.Second}

// superviseWorker runs the intelligence worker until ctx ends.
//
// Worker.Run returns by itself when the worker may not do the work: it could
// not take the database lease (another node holds it, or the database is
// away), or it lost the lease it had (the database was out of reach for
// longer than a lease lasts). Such a Worker is finished. It is never
// resumed, because what it holds in memory may be behind what a successor
// wrote; a new one is started instead, which must take a new lease - refused
// while another owner's is alive - and begins from the durable checkpoint.
//
// Before this, the first lost lease ended intelligence until someone
// restarted the control plane, and restarting the database for 30 seconds
// was enough to lose it.
func (s *Server) superviseWorker(ctx context.Context, w *intelligence.Worker) {
	delay := workerRestartDelay[0]
	for {
		began := time.Now()
		w.Run(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(began) > 2*workerRestartDelay[1] {
			delay = workerRestartDelay[0] // it worked for a while: a new problem
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(2*delay, workerRestartDelay[1])
		s.dbMu.Lock()
		next := s.newWorker(s.database)
		if next != nil {
			next.CarryReplaysRemoved(w.ReplaysRemoved())
			s.worker = next
		}
		s.dbMu.Unlock()
		if next == nil {
			return
		}
		// Why it stopped is in the stopped worker's own "paused" line.
		slog.Info("Starting a new intelligence worker: the previous one stopped")
		w = next
	}
}

// reconnectBackoff bounds the wait between attempts to reach a database that
// was still not there dbStartupWait after the server started.
var reconnectBackoff = [2]time.Duration{5 * time.Second, time.Minute}

// connectDatabase reaches the instance database behind the web UI, then
// calls reached. It tries at once, every startupRetry while the database may
// still be starting, then less and less often: a host that boots slowly or a
// database restarted along with QPot is reached whenever it answers; before,
// the server gave up for the rest of the run. Until then the data endpoints
// answer 503 and the canary outbox and the intelligence worker wait. A config
// naming no database QPot can open does not change while QPot runs, so that
// ends the trying.
func (s *Server) connectDatabase(ctx context.Context, reached func()) {
	begin := time.Now()
	var delay time.Duration
	backingOff := false
	for attempt := 0; ; attempt++ {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		db, err := openDatabase(ctx, s.config)
		if errors.Is(err, errNoDatabaseClient) {
			slog.Warn("No database for this config; some API endpoints are unavailable", "error", err)
			return
		}
		if err == nil {
			if ctx.Err() != nil {
				_ = db.Close()
				return
			}
			s.dbMu.Lock()
			s.database = db
			s.dbMu.Unlock()
			slog.Info("Database connected; starting what needs it", "attempts", attempt+1)
			reached()
			return
		}
		switch {
		case time.Since(begin) < dbStartupWait:
			if attempt == 0 {
				slog.Info("Waiting for the database to finish starting; the web UI is up meanwhile", "error", err)
			}
			delay = startupRetry
		case !backingOff:
			slog.Warn("Database not reached yet; still trying, some API endpoints are unavailable until then", "error", err)
			backingOff, delay = true, reconnectBackoff[0]
		default:
			delay = min(2*delay, reconnectBackoff[1])
		}
	}
}

// New creates a new web server. It does nothing slow: Start reaches the
// database and loads the ATT&CK data behind the web UI, and the API endpoints
// that need them answer 503 until then.
func New(cfg *config.Config) (*Server, error) {
	mgr, err := instance.NewManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create manager: %w", err)
	}

	s := &Server{
		config:  cfg,
		manager: mgr,
		mux:     http.NewServeMux(),
	}

	// Load the cluster ("group") membership if this node is paired. A missing
	// cluster.json just means standalone — the Pairing tab will say so.
	if dir, err := cluster.DefaultDataPath(); err == nil {
		cm := cluster.NewManager(dir)
		if c, err := cm.LoadCluster(); err == nil && c != nil {
			s.cluster = cm
		}
	}

	// Load the canary (honeytoken) registry when the subsystem is enabled.
	// A load failure (e.g. a corrupt canaries.json) is logged but non-fatal —
	// QPot must still come up; the operator can investigate the store file.
	if cfg.Canary.Enabled {
		if cs, err := canary.NewStore(cfg.DataPath, cfg.Canary.MaxTrips); err != nil {
			slog.Warn("Canary store failed to load; canary subsystem disabled this run", "error", err)
		} else {
			s.canaries = cs
			// The canaries planted in this instance's honeypots (the bait files
			// of its Cowrie persona), derived from the instance. Activation is
			// transactional: a failed write keeps the previous registry, and
			// followPlanted retries the desired plan before subsequent reads.
			if err := cs.SyncPlanted(instance.PlantedCanaries(cfg)); err != nil {
				slog.Warn("Canary watches not updated; previous registry retained, newly planned values may be unwatched until storage recovers", "error", err)
			}
			if s.canaryOutbox, err = newCanaryOutbox(cfg.DataPath); err != nil {
				slog.Error("Canary outbox unavailable; a trip the database refuses is only logged", "error", err)
			}
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
	s.mux.HandleFunc("/api/categories", s.withQPotAuth(s.handleCategories))
	s.mux.HandleFunc("/api/iocs", s.withQPotAuth(s.handleIOCs))
	s.mux.HandleFunc("/api/iocs/export", s.withQPotAuth(s.handleIOCExport))
	s.mux.HandleFunc("/api/ttps", s.withQPotAuth(s.handleTTPs))
	s.mux.HandleFunc("/api/intelligence", s.withQPotAuth(s.handleIntelligenceSummary))

	// Canary (honeytoken) subsystem. Only mounted when enabled.
	if s.canaries != nil {
		// PUBLIC beacon endpoint — deliberately UNauthenticated: a canary URL
		// must be reachable by whoever triggers it. It records a trip and
		// returns an innocuous decoy (404 / pixel) that reveals nothing.
		s.mux.HandleFunc("/c/", s.handleCanaryBeacon)
		// Authenticated management API.
		s.mux.HandleFunc("/api/canaries", s.withQPotAuth(s.handleCanaries))
		s.mux.HandleFunc("/api/canaries/trips", s.withQPotAuth(s.handleCanaryTrips))
		s.mux.HandleFunc("/api/canaries/artifact", s.withQPotAuth(s.handleCanaryArtifact))
	}

	// Pairing / Networking: the honeypot "group" (paired QPot nodes).
	s.mux.HandleFunc("/api/cluster", s.withQPotAuth(s.handleCluster))

	// Local overview: host resources, per-honeypot 24h activity and recent
	// events. Replaces the former ypanel phone-home agent; nothing leaves the host.
	s.mux.HandleFunc("/api/overview", s.withQPotAuth(s.handleOverview))
	s.mux.HandleFunc("/api/cleanup", s.withQPotAuth(s.handleCleanup))
	s.mux.HandleFunc("/api/cleanup/run", s.withQPotAuth(s.handleCleanupRun))

	// Attack map feed (T-Pot's map frontend at /map/, fed from QPot's events).
	s.mux.HandleFunc("/api/map/stream", s.withQPotAuth(s.handleMapStream))

	// The web UI's endpoints for the rest of QPot's features (api_routes.go).
	s.setupAPIRoutes()
}

// CheckExposure refuses to serve the management API without a login on any
// address but loopback (QP-WEB-005). The CLI calls it before it starts
// containers, and Start calls it again: no path may reach Listen without it.
func CheckExposure(cfg *config.Config) error {
	err := cfg.WebUI.CheckExposure()
	if err == nil {
		return nil
	}
	return hostsetup.E("QP-WEB-005").WithWhy("%s.", strings.ToUpper(err.Error()[:1])+err.Error()[1:]).Wrap(err)
}

// withQPotAuth middleware checks QPot ID authentication
func (s *Server) withQPotAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If QPot ID auth is disabled, allow all
		if !s.config.WebUI.QPotIDAuth {
			next(w, r)
			return
		}

		// The QPot ID is read from the X-QPot-ID header only, never from the
		// URL: a query string ends up in proxy and access logs, shell and
		// browser history, and Referer headers.
		qpotID := r.Header.Get("X-QPot-ID")
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

// handleStatic serves static files.
//
// Security: this handler is reached WITHOUT authentication (authMiddleware
// deliberately skips "/" and "/static/"). It must therefore never embed the
// QPot ID — that value is the API credential checked by withQPotAuth, and the
// dashboard treats it like a password: the operator pastes it into the login
// overlay (stored client-side in localStorage) and the JS sends it as the
// X-QPot-ID header. Injecting it into this page would hand the credential to
// any unauthenticated visitor, defeating the auth model entirely.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	// Only GET/HEAD make sense for static assets.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch p := r.URL.Path; {
	case p == "/" || p == "/index.html":
		serveEmbeddedHTML(w, "static/index.html") // T-Pot-style landing page
	case p == "/dashboard" || p == "/dashboard/":
		serveEmbeddedHTML(w, "static/dashboard.html")
	case p == "/map":
		http.Redirect(w, r, "/map/", http.StatusMovedPermanently)
	case p == "/favicon.ico":
		serveFavicon(w, r)
	case strings.Contains(p, ".."):
		// The FileServer below serves the whole static root, so
		// "/assets/../x" would reach files outside the asset trees; the mux
		// cleans such paths, but do not rely on that.
		http.NotFound(w, r)
	case strings.HasPrefix(p, "/assets/") || strings.HasPrefix(p, "/map/"):
		// The embedded FS is read-only and rooted, and noListFS refuses
		// directory listings.
		sub, err := fs.Sub(staticFS, "static")
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		http.FileServer(http.FS(noListFS{sub})).ServeHTTP(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveFavicon answers /favicon.ico, which a browser asks for on its own
// (for an image or a JSON answer opened in a tab) besides the icon each page
// names.
func serveFavicon(w http.ResponseWriter, r *http.Request) {
	data, err := staticFS.ReadFile("static/assets/img/favicon.ico")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeContent(w, r, "favicon.ico", time.Time{}, bytes.NewReader(data))
}

func serveEmbeddedHTML(w http.ResponseWriter, name string) {
	data, err := staticFS.ReadFile(name)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// noListFS serves files and directories that have an index.html, and
// nothing else, so the static tree cannot be browsed.
type noListFS struct{ fs.FS }

func (n noListFS) Open(name string) (fs.File, error) {
	f, err := n.FS.Open(name)
	if err != nil {
		// http.FileServer turns any error other than not-exist/permission
		// into a 500 (e.g. fs.ErrInvalid for a name that is not valid
		// UTF-8); a bad path is the client's, so report it as not found.
		return nil, fs.ErrNotExist
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if st.IsDir() {
		idx, err := n.FS.Open(path.Join(name, "index.html"))
		if err != nil {
			f.Close()
			return nil, fs.ErrNotExist
		}
		idx.Close()
	}
	return f, nil
}

// Start starts the web server and background alert polling.
func (s *Server) Start(ctx context.Context) error {
	if err := CheckExposure(s.config); err != nil {
		return err
	}
	addr := net.JoinHostPort(strings.Trim(s.config.WebUI.BindAddr, "[]"), strconv.Itoa(s.config.WebUI.Port))

	srv := &http.Server{
		Addr:         addr,
		Handler:      securityHeaders(s.authMiddleware(s.mux)),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// The QPot ID is the API credential: never write it to the log.
	slog.Info("Starting web server", "addr", addr, "instance", s.config.InstanceName)

	// Start alert polling when alerts are enabled and there is somewhere for an
	// alert to go: a webhook URL, response hooks, or both.
	if s.alertingConfigured() {
		go s.alertLoop(ctx)
	}

	// This node's uptime and event counts for its cluster, if it joins one.
	s.startedAt = time.Now()
	go s.nodeStatsLoop(ctx)
	go s.behaviourLoop(ctx)

	// Keep the honeypots' logs, captured files and the collector's backup
	// within their limits (internal/cleanup).
	go s.cleanupLoop(ctx)

	// Stop the honeypots before the disk that holds their logs is full, and
	// start them again when there is room (diskguard.go). A stopped server
	// waits for the guard: it may be writing its reserve file.
	guardDone := make(chan struct{})
	go func() { defer close(guardDone); s.diskGuardLoop(ctx) }()

	// The web UI is served at once. Behind it the database is reached and the
	// ATT&CK data loaded; what needs them starts as soon as they are there.
	// Before, the UI waited for both: up to 90 seconds for a database still
	// starting, up to 30 for MITRE's download.
	var (
		startMu                      sync.Mutex
		stopped                      bool
		outboxStarted, workerStarted bool
		workers                      sync.WaitGroup
	)
	startReady := func() {
		startMu.Lock()
		defer startMu.Unlock()
		if stopped || s.db() == nil {
			return
		}
		// Canary trips the database did not take yet, this run's or an
		// earlier one's (canary_outbox.go).
		if !outboxStarted && s.canaryOutbox != nil {
			outboxStarted = true
			go s.canaryOutboxLoop(ctx)
		}
		if workerStarted || s.intelClassifier() == nil {
			return // intelligence is off, or its ATT&CK data is still loading
		}
		s.dbMu.Lock()
		if s.worker == nil {
			s.worker = s.newWorker(s.database)
		}
		w := s.worker
		s.dbMu.Unlock()
		if w == nil {
			return
		}
		workerStarted = true
		// Canary values used inside a honeypot trip within seconds. The
		// intelligence worker scans every event it classifies as well, so it
		// matches what this misses; without it the honeypot channel is off.
		if s.canaries != nil {
			go s.canaryScanLoop(ctx)
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			s.superviseWorker(ctx, w)
		}()
	}
	// Waited for on the way out like the worker: an attempt to reach the
	// database still running would open it after Start returned.
	behind := func(f func()) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			f()
		}()
	}
	if s.config.Intelligence.Enabled && s.intelClassifier() == nil {
		behind(func() {
			s.prepareIntelligence(ctx)
			startReady()
		})
	}
	if s.db() == nil {
		behind(func() { s.connectDatabase(ctx, startReady) })
	}
	startReady()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	err := srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		// The worker writes what it still holds when it stops (bounded by its
		// own timeout); returning first let the process exit before that.
		startMu.Lock()
		stopped = true
		startMu.Unlock()
		workers.Wait()
		<-guardDone
	}
	return err
}

// alertingConfigured reports whether the alert loop has any work to do: a
// webhook URL to POST to, or response hooks to run. Gating only on a webhook
// URL (as the code originally did) silently disabled response-hooks-only
// setups - "run my firewall script on attack, don't POST anywhere" - even
// though config validation treats that as a valid configuration.
func (s *Server) alertingConfigured() bool {
	if !s.config.Alerts.Enabled {
		return false
	}
	if s.config.Alerts.WebhookURL != "" {
		return true
	}
	return s.config.Response.Enabled && len(s.config.Response.OnAttackDetected) > 0
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
			if s.db() == nil {
				continue
			}
			since := time.Now().Add(-time.Minute)
			stats, err := s.db().GetStats(ctx, since)
			if err != nil {
				slog.Warn("Alert loop: failed to get stats", "error", err)
				continue
			}

			if s.alertThresholdExceeded(stats) && !s.alertCoolingDown(time.Now()) {
				s.lastAlert = time.Now()
				// Only POST when a URL is configured - the loop may be running
				// purely to drive response hooks.
				if s.config.Alerts.WebhookURL != "" {
					s.fireWebhook(ctx, stats)
				}
				if s.config.Response.Enabled && len(s.config.Response.OnAttackDetected) > 0 {
					s.runResponseHooks(ctx, stats)
				}
			}
		}
	}
}

// nodeStatsInterval is how often this node's stats go to its cluster.
const nodeStatsInterval = 30 * time.Second

// nodeStatsLoop keeps this node's stats in its cluster current. The cluster
// can attach after the server starts (SetCluster), so every pass checks.
func (s *Server) nodeStatsLoop(ctx context.Context) {
	t := time.NewTicker(nodeStatsInterval)
	defer t.Stop()
	for {
		s.updateNodeStats(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// updateNodeStats gives the running cluster this node's uptime (this control
// plane's) and its events: the last 24 hours' total, as the dashboard counts
// them, and the distinct sources of the last 5 minutes as active attacks.
// Gossip carries them to the other nodes. Nothing set them before, so every
// node showed "0m" and 0 events. A no-op when this control plane does not run
// the cluster; a failed query keeps the last known counts.
func (s *Server) updateNodeStats(ctx context.Context) {
	cm := s.api.liveCluster.Load()
	if cm == nil {
		return
	}
	now := time.Now()
	if s.db() != nil {
		qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if day, err := s.db().GetStats(qctx, now.Add(-24*time.Hour)); err == nil {
			s.nodeStats.TotalEvents = day.TotalEvents
		} else {
			slog.Debug("Node stats: failed to count events", "error", err)
		}
		if recent, err := s.db().GetStats(qctx, now.Add(-5*time.Minute)); err == nil {
			s.nodeStats.ActiveAttacks = recent.UniqueIPs
		}
		cancel()
	}
	if !s.startedAt.IsZero() {
		s.nodeStats.Uptime = now.Sub(s.startedAt).Truncate(time.Second)
	}
	s.nodeStats.LastSync = now
	cm.UpdateNodeStats(s.nodeStats)
	s.updateClusterIntel(ctx, cm, now)
}

// alertThresholdExceeded reports whether the last-minute stats cross the
// configured events-per-minute threshold, honoring the optional honeypot
// allow-list (empty = alert on total across all honeypots).
func (s *Server) alertThresholdExceeded(stats *database.Stats) bool {
	if len(s.config.Alerts.Honeypots) == 0 {
		return int(stats.TotalEvents) >= s.config.Alerts.Threshold
	}
	for _, hc := range stats.TopHoneypots {
		for _, alertHP := range s.config.Alerts.Honeypots {
			if hc.Honeypot == alertHP && int(hc.Count) >= s.config.Alerts.Threshold {
				return true
			}
		}
	}
	return false
}

// alertCoolingDown reports whether a prior alert fired within Alerts.Cooldown,
// debouncing sustained attacks so the webhook/response hooks don't re-fire every
// minute. A zero cooldown disables debouncing.
func (s *Server) alertCoolingDown(now time.Time) bool {
	if s.config.Alerts.Cooldown <= 0 || s.lastAlert.IsZero() {
		return false
	}
	return now.Sub(s.lastAlert) < s.config.Alerts.Cooldown
}

// capWriter captures up to max bytes of a hook's output for logging and
// silently discards the rest, so a misbehaving hook that floods stdout/stderr
// can't exhaust memory. It always reports a full write so the child never
// blocks on a backed-up pipe.
type capWriter struct {
	buf      bytes.Buffer
	max      int
	overflow bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	if rem := w.max - w.buf.Len(); rem > 0 {
		if len(p) <= rem {
			w.buf.Write(p)
		} else {
			w.buf.Write(p[:rem])
			w.overflow = true
		}
	} else if len(p) > 0 {
		w.overflow = true
	}
	return len(p), nil
}

// runResponseHooks executes every configured response action when an
// alert threshold trips. Each command runs in a per-action timeout so a
// hung script can't block the alert loop, and stdout/stderr are captured
// (bounded) to the structured log instead of inheriting the parent FDs.
func (s *Server) runResponseHooks(ctx context.Context, stats *database.Stats) {
	s.runHooks(ctx, s.config.Response.OnAttackDetected, s.responseEnv(ctx, stats))
}

// runHooks runs each action with envExtra added to the environment, as
// runResponseHooks describes.
func (s *Server) runHooks(ctx context.Context, actions []config.ResponseAction, envExtra []string) {
	const defaultTimeout = 10 * time.Second
	const hardCap = 5 * time.Minute

	for i, action := range actions {
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

		// Kill the hook's whole process group at the deadline, and - as a
		// backstop - never let Wait block more than WaitDelay past the timeout
		// on a descendant that inherited the output pipe. Together these make
		// the per-action timeout actually effective for forking hooks.
		configureHookProcessGroup(cmd)
		cmd.WaitDelay = 2 * time.Second

		const maxHookOutput = 16 << 10 // 16 KiB captured for logs
		cw := &capWriter{max: maxHookOutput}
		cmd.Stdout = cw
		cmd.Stderr = cw
		err := cmd.Run()
		cancel()
		// Trim trailing whitespace so multiline output doesn't double-line in logs.
		outStr := strings.TrimRight(cw.buf.String(), "\n\r\t ")
		if cw.overflow {
			outStr += " …[truncated]"
		}

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
		"QPOT_SENSOR_ID=" + s.config.SensorID(),
		"QPOT_INSTANCE=" + s.config.InstanceName,
		fmt.Sprintf("QPOT_TOTAL_EVENTS=%d", stats.TotalEvents),
		fmt.Sprintf("QPOT_UNIQUE_IPS=%d", stats.UniqueIPs),
		fmt.Sprintf("QPOT_THRESHOLD=%d", s.config.Alerts.Threshold),
		// RFC3339/UTC, matching the webhook payload, so a hook can stamp its
		// action with the same trigger time the SIEM sees.
		"QPOT_TIMESTAMP=" + time.Now().UTC().Format(time.RFC3339),
	}
	if len(stats.TopHoneypots) > 0 {
		env = append(env, "QPOT_TOP_HONEYPOT="+stats.TopHoneypots[0].Honeypot)
	}
	// Top attacker IP isn't on Stats; pull it from GetTopAttackers with a
	// short timeout so a sluggish DB doesn't delay every hook.
	if s.db() != nil {
		lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		since := time.Now().Add(-time.Minute)
		attackers, err := s.db().GetTopAttackers(lookupCtx, 1, since)
		if err == nil && len(attackers) > 0 {
			env = append(env, "QPOT_TOP_SOURCE_IP="+attackers[0].SourceIP)
		}
	}
	return env
}

// fireWebhook sends a JSON POST to the configured webhook URL.
func (s *Server) fireWebhook(ctx context.Context, stats *database.Stats) {
	// No QPot ID: it is the web API's credential, and a webhook hands the
	// payload to a third party (a chat channel). "instance" names the sender.
	payload := map[string]interface{}{
		"instance": s.config.InstanceName,
		// RFC3339/UTC timestamp so SIEM and chat integrations can order and
		// correlate alerts (most webhook consumers require a timestamp field).
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"total_events": stats.TotalEvents,
		"unique_ips":   stats.UniqueIPs,
		"message":      fmt.Sprintf("QPot alert: %d events in the last minute on instance %s", stats.TotalEvents, s.config.InstanceName),
	}
	// Surface the most-hit honeypot so a responder knows what is under attack
	// without a second lookup.
	if len(stats.TopHoneypots) > 0 {
		payload["top_honeypot"] = stats.TopHoneypots[0].Honeypot
	}

	body, err := json.Marshal(payload)
	if err != nil {
		slog.Error("Alert webhook: failed to marshal payload", "error", err)
		return
	}

	// Webhook URLs (Slack, Discord, ...) carry their credential in the path or
	// query, so only the scheme and host are ever logged.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.Alerts.WebhookURL, bytes.NewReader(body))
	if err != nil {
		slog.Error("Alert webhook: failed to create request", "error", withoutURL(err))
		return
	}
	req.Header.Set("Content-Type", "application/json")

	webhookClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := webhookClient.Do(req)
	if err != nil {
		slog.Error("Alert webhook: request failed", "host", req.URL.Host, "error", withoutURL(err))
		return
	}
	resp.Body.Close()
	slog.Info("Alert webhook fired", "status", resp.StatusCode, "host", req.URL.Host)
}

// withoutURL strips the URL that net/http and net/url put in their errors.
func withoutURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

// isPublicPath reports paths served without authentication: the static pages
// and their assets (they hold no data and no credential - every API call they
// make needs the QPot ID) and the public canary beacon (/c/<token>), which
// must be reachable by anyone who triggers a planted token.
func isPublicPath(p string) bool {
	switch p {
	case "/", "/index.html", "/dashboard", "/dashboard/", "/map", "/favicon.ico":
		return true
	}
	return strings.HasPrefix(p, "/assets/") || strings.HasPrefix(p, "/map/") || strings.HasPrefix(p, "/c/")
}

// securityHeaders wraps a handler with standard hardening response headers for
// the web UI: block MIME sniffing, framing (clickjacking), referrer leakage,
// and constrain resource loading via a Content-Security-Policy. The CSP allows
// 'self' plus inline script/style (the dashboard ships inline JS/CSS but no
// external/CDN resources), so it blocks injected external script sources - the
// main XSS exfiltration vector - without breaking the UI.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; "+
				"style-src 'self' 'unsafe-inline'; "+
				// No third-party images: the attack map draws its world locally.
				"img-src 'self' data:; "+
				"connect-src 'self'; base-uri 'self'; form-action 'self'; "+
				"frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// authMiddleware adds basic authentication (when configured) to everything
// but the public paths.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for static files (they handle their own auth) and for the
		// public canary beacon (/c/<token>), which must be reachable by anyone
		// who triggers a planted token — that is the whole point of a canary.
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// A browser attaches cached Basic credentials to a cross-site form
		// POST, and a form can send a JSON body as text/plain. Requiring a
		// JSON body makes such a request impossible to forge: a cross-origin
		// fetch with this type needs a CORS preflight, which is never granted.
		if !jsonBodyAllowed(r) {
			s.sendError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
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
		// Constant-time compare (both fields evaluated) so response timing
		// does not leak how much of the username/password matched.
		userOK := subtle.ConstantTimeCompare([]byte(user), []byte(s.config.WebUI.Username)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(s.config.WebUI.Password)) == 1
		if !ok || !userOK || !passOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="QPot"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// jsonBodyAllowed reports whether r may reach a handler: requests that carry a
// body (POST, PUT, PATCH) must declare it as application/json, the only type
// the API accepts and one an HTML form cannot send.
func jsonBodyAllowed(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return true
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/json"
}

// handleStatus returns instance status
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	status, err := s.manager.Status(ctx)
	if err != nil {
		s.sendInternalError(w, "status failed", err)
		return
	}

	// By name: the manager lists them in map order, and the web UI redraws
	// a list whose order changes.
	honeypots := append([]instance.HoneypotStatus(nil), status.Honeypots...)
	sort.Slice(honeypots, func(i, j int) bool { return honeypots[i].Name < honeypots[j].Name })

	// The QPot ID is the API credential: the caller has it already, and an
	// answer that repeats it puts it on screen. No reply carries it.
	response := map[string]interface{}{
		"instance":  s.config.InstanceName,
		"overall":   status.Overall,
		"honeypots": honeypots,
		"database":  s.config.Database.Type,
		// Whether the disk guard keeps honeypots stopped because the disk
		// is nearly full (diskguard.go).
		"disk_guard": s.diskGuardStatus(),
	}

	s.sendJSON(w, response)
}

// handleHoneypots manages honeypots
func (s *Server) handleHoneypots(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	switch r.Method {
	case http.MethodGet:
		// List honeypots. Snapshot under the config lock so we never range the
		// live map while a concurrent POST enables/disables a honeypot. The
		// instance status (two docker runs) is fetched once, not per honeypot.
		running := map[string]bool{}
		if s.manager != nil {
			if status, _ := s.manager.Status(ctx); status != nil {
				for _, h := range status.Honeypots {
					running[h.Name] = h.Running
				}
			}
		}
		// The config file as it is now: the CLI may have turned honeypots
		// on or off since this server started.
		cfg, err := s.readConfig()
		if err != nil {
			cfg = s.config
		}
		hps := cfg.SnapshotHoneypots()
		names := make([]string, 0, len(hps))
		for name := range hps {
			names = append(names, name)
		}
		sort.Strings(names) // one order every time (the UI redraws on a change)
		// "port" is the honeypot's own setting; attackers reach the host
		// ports the instance publishes for it (none while it is off).
		ports := instance.HostPortMappings(cfg)
		var list []map[string]interface{}
		for _, name := range names {
			hp := hps[name]
			list = append(list, map[string]interface{}{
				"name":       name,
				"enabled":    hp.Enabled,
				"running":    running[name],
				"port":       hp.Port,
				"host_ports": hostPortsOf(ports, name),
				"risk":       hp.RiskLevel,
			})
		}
		s.sendJSON(w, list)

	case http.MethodPost:
		// Turn a honeypot on or off (api_honeypots.go), as the CLI does.
		s.handleHoneypotToggle(w, r)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleStats returns statistics
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var stats *database.Stats
	if s.db() != nil {
		since := time.Now().Add(-24 * time.Hour)
		var err error
		stats, err = s.db().GetStats(ctx, since)
		if err != nil {
			stats = &database.Stats{}
		}
	} else {
		stats = &database.Stats{}
	}

	response := map[string]interface{}{
		"total_events":  stats.TotalEvents,
		"unique_ips":    stats.UniqueIPs,
		"top_countries": stats.TopCountries,
		"top_honeypots": stats.TopHoneypots,
	}

	s.sendJSON(w, response)
}

// handleLogs returns logs
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()

	// An empty honeypot means "all"; a non-empty value must be a known
	// honeypot so it can't be injected as a flag into `docker compose logs`.
	honeypot := r.URL.Query().Get("honeypot")
	if honeypot != "" && !s.isKnownHoneypot(honeypot) {
		s.sendError(w, http.StatusBadRequest, "unknown honeypot")
		return
	}

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
		s.sendInternalError(w, "get logs failed", err)
		return
	}

	// Bound both line count and raw bytes: many individually bounded attacker
	// log lines must not accumulate hundreds of MiB in one dashboard request.
	const maxLogLines = 10000
	const maxLogBytes = 4 << 20
	lines := make([]string, 0, 100)
	logBytes := 0
	truncated := false
	for line := range logs {
		if len(lines) >= maxLogLines || len(line) > maxLogBytes-logBytes {
			truncated = true
			break
		}
		lines = append(lines, line)
		logBytes += len(line)
	}
	if truncated {
		w.Header().Set("X-QPot-Logs-Truncated", "true")
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

	if s.db() == nil {
		s.sendError(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	ctx := r.Context()
	since := time.Now().Add(-24 * time.Hour)

	attackers, err := s.db().GetTopAttackers(ctx, 1000, since)
	if err != nil {
		s.sendInternalError(w, "get top attackers failed", err)
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
		"generated": time.Now().UTC().Format(time.RFC3339),
		"count":     len(entries),
		"ioc_list":  entries,
	}
	s.sendJSON(w, response)
}

// recentSample is how many of the newest events /api/techniques and
// /api/categories count over, and summarySample how many the intelligence
// summary looks at for the number of techniques seen.
const (
	recentSample  = 10000
	summarySample = 5000
)

// handleTechniques returns unique ATT&CK techniques observed in classified events.
func (s *Server) handleTechniques(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.db() == nil {
		s.sendError(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	ctx := r.Context()
	type techEntry struct {
		TechniqueID   string `json:"technique_id"`
		TechniqueName string `json:"technique_name"`
		TacticName    string `json:"tactic_name"`
		Count         int    `json:"count"`
	}
	// A store that counts for itself reads three columns of the sample; the
	// others return the events, payloads and all, to be counted here.
	if summarizer, ok := s.db().(database.RecentSummarizer); ok {
		counted, err := summarizer.RecentTechniques(ctx, recentSample)
		if err != nil {
			s.sendInternalError(w, "count techniques failed", err)
			return
		}
		result := make([]*techEntry, 0, len(counted))
		for _, c := range counted {
			result = append(result, &techEntry{c.TechniqueID, c.TechniqueName, c.TacticName, c.Count})
		}
		s.sendJSON(w, result)
		return
	}
	events, err := s.db().GetEvents(ctx, database.EventFilter{Limit: recentSample})
	if err != nil {
		s.sendInternalError(w, "get events failed", err)
		return
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
	// By count, most first; equal counts by technique ID, so the order does
	// not change from one answer to the next.
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count != result[j].Count {
			return result[i].Count > result[j].Count
		}
		return result[i].TechniqueID < result[j].TechniqueID
	})

	s.sendJSON(w, result)
}

// handleCategories returns every attack category with its label and how many
// recent classified events carry it, in the catalogue's order. The dashboard
// reads its labels from here, so they live in one place.
func (s *Server) handleCategories(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.db() == nil {
		s.sendError(w, http.StatusServiceUnavailable, "database not available")
		return
	}
	// The same recent sample /api/techniques counts.
	counts := map[string]int{}
	if summarizer, ok := s.db().(database.RecentSummarizer); ok {
		counted, err := summarizer.RecentCategories(r.Context(), recentSample)
		if err != nil {
			s.sendInternalError(w, "count categories failed", err)
			return
		}
		counts = counted
	} else {
		events, err := s.db().GetEvents(r.Context(), database.EventFilter{Limit: recentSample})
		if err != nil {
			s.sendInternalError(w, "get events failed", err)
			return
		}
		for _, ev := range events {
			for _, c := range ev.Categories {
				counts[c]++
			}
		}
	}
	type categoryEntry struct {
		intelligence.Category
		Count int `json:"count"`
	}
	cats := intelligence.Categories()
	result := make([]categoryEntry, 0, len(cats))
	for _, c := range cats {
		result = append(result, categoryEntry{Category: c, Count: counts[c.ID]})
	}
	s.sendJSON(w, result)
}

// handleIOCs returns filtered IOC records.
func (s *Server) handleIOCs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.db() == nil {
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
	// Clamp the limit to a sane range. A missing/invalid/<=0 value keeps the
	// default; an unbounded value would let a caller pull the entire IOC table
	// into memory (and limit<=0 omits the SQL LIMIT clause entirely).
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			if n > 1000 {
				n = 1000
			}
			filter.Limit = n
		}
	}

	iocs, err := s.db().GetIOCs(ctx, filter)
	if err != nil {
		s.sendInternalError(w, "get iocs failed", err)
		return
	}

	s.sendJSON(w, iocs)
}

// handleIOCExport exports extracted IOCs in a threat-intel interchange format.
// Currently MISP (the de-facto honeypot/TIP sharing standard); the response is
// a single importable MISP event. Optional ?type= / ?honeypot= filters and a
// ?limit= (default 1000, max 10000) apply. This is the standards-based way to
// feed QPot's findings into a SIEM/TIP without any external dependency.
func (s *Server) handleIOCExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.db() == nil {
		s.sendError(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "" {
		format = "misp"
	}
	if format != "misp" {
		s.sendError(w, http.StatusBadRequest, "unsupported export format (supported: misp)")
		return
	}

	filter := database.IOCFilter{Limit: 1000}
	if t := r.URL.Query().Get("type"); t != "" {
		filter.Types = []string{t}
	}
	if hp := r.URL.Query().Get("honeypot"); hp != "" {
		filter.Honeypots = []string{hp}
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			if n > 10000 {
				n = 10000
			}
			filter.Limit = n
		}
	}

	iocs, err := s.db().GetIOCs(r.Context(), filter)
	if err != nil {
		s.sendInternalError(w, "get iocs failed", err)
		return
	}

	event := intelligence.BuildMISPEvent(iocs, s.config.InstanceName, time.Now())
	w.Header().Set("Content-Disposition", `attachment; filename="qpot-misp-event.json"`)
	s.sendJSON(w, event)
}

// handleTTPs returns TTP session records.
func (s *Server) handleTTPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.db() == nil {
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

	sessions, err := s.db().GetTTPSessions(ctx, limit)
	if err != nil {
		s.sendInternalError(w, "get TTP sessions failed", err)
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

	ttpBuilder, attckLoader := s.intelState()
	// A session is one source's activity; a campaign is the sessions that
	// share strong evidence (a payload, a download host, a command
	// sequence). Sources that share nothing are each their own campaign.
	activeSessions, activeCampaigns := 0, 0
	if ttpBuilder != nil {
		sessions := ttpBuilder.GetActiveSessions()
		activeSessions = len(sessions)
		campaigns := make(map[string]struct{}, len(sessions))
		for _, session := range sessions {
			campaigns[session.CampaignFingerprint] = struct{}{}
		}
		activeCampaigns = len(campaigns)
	}

	attckLoaded := false
	if attckLoader != nil {
		attckLoaded = attckLoader.Loaded()
	}

	var techniquesObserved int
	var iocsTotal int

	if s.db() != nil {
		ctx := r.Context()
		// Distinct techniques among the newest 5000 events: a sample, so
		// that the whole events table is not read.
		if summarizer, ok := s.db().(database.RecentSummarizer); ok {
			if counted, err := summarizer.RecentTechniques(ctx, summarySample); err == nil {
				techniquesObserved = len(counted)
			}
		} else if events, err := s.db().GetEvents(ctx, database.EventFilter{Limit: summarySample}); err == nil {
			seen := make(map[string]bool)
			for _, ev := range events {
				if ev.TechniqueID != "" {
					seen[ev.TechniqueID] = true
				}
			}
			techniquesObserved = len(seen)
		}

		// Every indicator, from a store that can count them; from the
		// others what a read of at most 10000 returns.
		if counter, ok := s.db().(database.IOCCounter); ok {
			if n, err := counter.CountIOCs(ctx); err == nil {
				iocsTotal = int(n)
			}
		} else if iocs, err := s.db().GetIOCs(ctx, database.IOCFilter{Limit: 10000}); err == nil {
			iocsTotal = len(iocs)
		}
	}

	summary := map[string]interface{}{
		"techniques_observed": techniquesObserved,
		"iocs_total":          iocsTotal,
		"active_sessions":     activeSessions,
		"active_campaigns":    activeCampaigns,
		"worker_enabled":      s.intelWorker() != nil,
		"attck_loaded":        attckLoaded,
		"worker_status":       "disabled",
		"worker_healthy":      false,
	}
	if s.intelWorker() != nil {
		state, lastError := s.intelWorker().Status()
		summary["worker_status"] = state
		summary["worker_healthy"] = state == "running"
		// Rows the worker deleted because the collector had read their log
		// line a second time (since the control plane started).
		summary["replays_removed"] = s.intelWorker().ReplaysRemoved()
		var coded *hostsetup.Error
		if errors.As(lastError, &coded) {
			// Only expose catalog guidance, never the wrapped database error,
			// which may contain an event payload, connection string or secret.
			summary["worker_error_code"] = coded.Code
			summary["worker_error_remedy"] = hostsetup.E(coded.Code).Remedy()
		}
	}

	s.sendJSON(w, summary)
}

// handleCluster returns the honeypot "group" (paired QPot nodes) for the
// Pairing/Networking dashboard tab: the group summary plus per-node name,
// online status, uptime, and total requests. When this node is standalone
// (no cluster.json), it reports clustered=false.
// Version is the QPot build version reported by /api/overview; the CLI sets it.
var Version = "dev"

// handleOverview serves the local instance overview (see internal/overview).
func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var cl *overview.Cluster
	if cm, _ := s.clusterView(); cm != nil {
		if st := cm.GetStatus(); st != nil {
			cl = &overview.Cluster{ID: st.ID, Name: st.Name, Nodes: st.NodeCount, Healthy: st.HealthyNodes}
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	// The config file as it is now: the CLI may have turned honeypots on or
	// off since this server started (the honeypot list reads it the same way).
	cfg, err := s.readConfig()
	if err != nil {
		cfg = s.config
	}
	ov := overview.Build(ctx, cfg, s.db(), cl, Version)
	ports := instance.HostPortMappings(cfg)
	out := overviewAnswer{Overview: ov, Honeypots: make([]overviewHoneypot, 0, len(ov.Honeypots))}
	for _, h := range ov.Honeypots {
		out.Honeypots = append(out.Honeypots, overviewHoneypot{Honeypot: h, HostPorts: hostPortsOf(ports, h.Name)})
	}
	s.sendJSON(w, out)
}

// overviewAnswer is the overview with the host ports each honeypot publishes:
// its Honeypots field takes the place of the embedded overview's in the JSON
// (the shallower field wins).
type overviewAnswer struct {
	*overview.Overview
	Honeypots []overviewHoneypot `json:"honeypots"`
}

type overviewHoneypot struct {
	overview.Honeypot
	HostPorts []instance.PortMapping `json:"host_ports"`
}

// hostPortsOf is a honeypot's published host ports, an empty list (not null)
// when it publishes none.
func hostPortsOf(ports map[string][]instance.PortMapping, name string) []instance.PortMapping {
	if p := ports[name]; p != nil {
		return p
	}
	return []instance.PortMapping{}
}

func (s *Server) handleCluster(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cm, live := s.clusterView()
	if cm == nil {
		s.sendJSON(w, map[string]interface{}{"clustered": false, "live": false})
		return
	}

	status := cm.GetStatus()
	nodes := cm.GetNodes()
	// By name (the manager keeps members in a map).
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Name != nodes[j].Name {
			return nodes[i].Name < nodes[j].Name
		}
		return nodes[i].ID < nodes[j].ID
	})

	type nodeView struct {
		Name          string `json:"name"`
		Address       string `json:"address"`
		Online        bool   `json:"online"`
		Status        string `json:"status"`
		UptimeSecs    int64  `json:"uptime_seconds"`
		TotalEvents   int64  `json:"total_events"`
		ActiveAttacks int64  `json:"active_attacks"`
		IsLocal       bool   `json:"is_local"`
	}
	views := make([]nodeView, 0, len(nodes))
	localID := cm.LocalNodeID()
	for _, n := range nodes {
		views = append(views, nodeView{
			Name:          n.Name,
			Address:       fmt.Sprintf("%s:%d", n.Address, n.Port),
			Online:        n.Status == cluster.NodeStatusHealthy,
			Status:        string(n.Status),
			UptimeSecs:    int64(n.Stats.Uptime.Seconds()),
			TotalEvents:   n.Stats.TotalEvents,
			ActiveAttacks: n.Stats.ActiveAttacks,
			IsLocal:       localID != "" && n.ID == localID,
		})
	}

	s.sendJSON(w, map[string]interface{}{
		"clustered": true,
		// live: from the cluster this control plane runs; else as cluster.json
		// held when the server started.
		"live":  live,
		"group": status,
		"nodes": views,
		// The most active sources of the last hour the nodes share (see
		// updateClusterIntel), those seen by the most nodes first.
		"shared_attackers": cm.SharedAttackers(sharedAttackersShown),
	})
}

// sendJSON sends a JSON response
func (s *Server) sendJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// isKnownHoneypot reports whether name matches a honeypot defined in the
// instance config. Used as an allow-list before any honeypot name reaches a
// docker compose argv.
func (s *Server) isKnownHoneypot(name string) bool {
	if name == "" {
		return false
	}
	_, ok := s.config.GetHoneypotConfig(name)
	return ok
}

// sendError sends an error response.
//
// Security: this must NOT include the QPot ID. sendError is invoked by the
// auth middleware on 401/403 failures, i.e. for UNAUTHENTICATED clients, so
// embedding s.config.QPotID here would hand the API credential to anyone who
// hits a protected endpoint without (or with a wrong) credential — a complete
// auth bypass.
func (s *Server) sendError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}

// sendInternalError logs the real error server-side and returns a generic
// message to the client, so internal details (DB schema, docker output, file
// paths) are never echoed to API callers.
func (s *Server) sendInternalError(w http.ResponseWriter, context string, err error) {
	slog.Error(context, "error", err)
	s.sendError(w, http.StatusInternalServerError, "internal error")
}
