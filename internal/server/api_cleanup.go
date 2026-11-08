package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/qpot/qpot/internal/cleanup"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/instance"
)

// Storage cleanup (internal/cleanup): the hourly run, GET and PUT
// /api/cleanup (the settings and the last run) and POST /api/cleanup/run.

const (
	// cleanupFirstRun: the first run waits for the collector to be up.
	cleanupFirstRun = 2 * time.Minute
	cleanupEvery    = time.Hour
	// cleanupTimeout bounds one run.
	cleanupTimeout = 10 * time.Minute
	// maxCleanupBody bounds a PUT /api/cleanup body.
	maxCleanupBody = 4 << 10
)

// cleanupState is the cleanup runs' state.
type cleanupState struct {
	// run lets one run go at a time; a manual run waits for a scheduled one.
	run chan struct{}
	mu  sync.Mutex
	// last is the last run that changed something or could have (not a
	// preview); next is when the next scheduled run starts.
	last *cleanup.Report
	next time.Time
	// helper and collector replace the Docker helper and the collector's
	// state (tests).
	helper    cleanup.Helper
	collector func(context.Context) bool
}

func (c *cleanupState) lock(ctx context.Context) bool {
	c.mu.Lock()
	if c.run == nil {
		c.run = make(chan struct{}, 1)
	}
	run := c.run
	c.mu.Unlock()
	select {
	case run <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (c *cleanupState) unlock() { <-c.run }

// cleanupLoop runs cleanup soon after start, then hourly, while it is on.
func (s *Server) cleanupLoop(ctx context.Context) {
	t := time.NewTimer(cleanupFirstRun)
	defer t.Stop()
	s.setNextCleanup(time.Now().Add(cleanupFirstRun))
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.runCleanup(ctx, false, false); err != nil {
				slog.Warn("Storage cleanup did not run", "error", err)
			}
			s.setNextCleanup(time.Now().Add(cleanupEvery))
			t.Reset(cleanupEvery)
		}
	}
}

func (s *Server) setNextCleanup(t time.Time) {
	c := &s.api.cleanup
	c.mu.Lock()
	c.next = t
	c.mu.Unlock()
}

// runCleanup runs cleanup with the settings in the config file now. A
// scheduled run (manual false) does nothing while cleanup is off; a dry run
// changes nothing and is not kept as the last run.
func (s *Server) runCleanup(ctx context.Context, manual, dryRun bool) (*cleanup.Report, error) {
	cfg, err := s.readConfig()
	if err != nil {
		return nil, err
	}
	if !manual && !cfg.Cleanup.On() {
		return nil, nil
	}
	c := &s.api.cleanup
	if !c.lock(ctx) {
		return nil, ctx.Err()
	}
	defer c.unlock()
	rctx, cancel := context.WithTimeout(ctx, cleanupTimeout)
	defer cancel()
	rep := cleanup.Run(rctx, cfg, cleanup.LimitsFor(cfg), cleanup.Options{
		DryRun: dryRun, CollectorRunning: s.collectorRunning(rctx), Helper: s.cleanupHelper(),
	})
	if !dryRun {
		c.mu.Lock()
		c.last = rep
		c.mu.Unlock()
		slog.Info("Storage cleanup ran", "removed", rep.Removed, "emptied", rep.Emptied, "freed_bytes", rep.Freed,
			"collector_running", rep.Collector, "errors", len(rep.Errors), "manual", manual)
		for _, e := range rep.Errors {
			slog.Warn("Storage cleanup", "error", e)
		}
	}
	return rep, nil
}

// collectorRunning reports whether the collector container runs: only then
// may a log it reads be emptied.
func (s *Server) collectorRunning(ctx context.Context) bool {
	if f := s.api.cleanup.collector; f != nil {
		return f(ctx)
	}
	st := s.serviceStater()
	if st == nil {
		return false
	}
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	states, err := st.ServiceStates(sctx)
	if err != nil {
		return false
	}
	c, ok := states["collector"]
	return ok && c.State == "running"
}

// cleanupHelper removes and empties what the honeypots' and the collector's
// own users own (Linux), in a container of the collector's image.
func (s *Server) cleanupHelper() cleanup.Helper {
	if h := s.api.cleanup.helper; h != nil {
		return h
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	return &cleanup.DockerHelper{Image: instance.CollectorImage}
}

// cleanupSettings is the cleanup section as the API shows and takes it.
type cleanupSettings struct {
	Enabled     bool  `json:"enabled"`
	MaxAgeDays  int   `json:"max_age_days"`
	MaxLogMB    int64 `json:"max_log_mb"`
	MaxBackupMB int64 `json:"max_backup_mb"`
}

// cleanupView is GET /api/cleanup.
type cleanupView struct {
	Settings cleanupSettings `json:"settings"`
	// HoneypotLimitGB is every honeypot folder's storage limit, except
	// those with their own (HoneypotLimits).
	HoneypotLimitGB int64            `json:"honeypot_limit_gb"`
	HoneypotLimits  map[string]int64 `json:"honeypot_limits_gb"`
	Running         bool             `json:"running"`
	NextRun         *time.Time       `json:"next_run"`
	Last            *cleanup.Report  `json:"last"`
}

func (s *Server) cleanupView(cfg *config.Config) cleanupView {
	c := cfg.Cleanup
	v := cleanupView{
		Settings:        cleanupSettings{Enabled: c.On(), MaxAgeDays: c.MaxAgeDays, MaxLogMB: c.MaxLogMB, MaxBackupMB: c.MaxBackupMB},
		HoneypotLimitGB: cfg.Security.ResourceLimits.MaxStorageGB,
		HoneypotLimits:  map[string]int64{},
	}
	for name, hp := range cfg.SnapshotHoneypots() {
		if hp.Resources.UseCustomLimits && hp.Resources.MaxStorageGB > 0 {
			v.HoneypotLimits[name] = hp.Resources.MaxStorageGB
		}
	}
	st := &s.api.cleanup
	st.mu.Lock()
	defer st.mu.Unlock()
	v.Last = st.last
	if st.run != nil {
		v.Running = len(st.run) > 0
	}
	if c.On() && !st.next.IsZero() {
		next := st.next
		v.NextRun = &next
	}
	return v
}

// handleCleanup serves GET (settings and the last run) and PUT (settings).
func (s *Server) handleCleanup(w http.ResponseWriter, r *http.Request) {
	if !s.allowMethods(w, r, http.MethodGet, http.MethodPut) {
		return
	}
	if r.Method == http.MethodPut {
		s.putCleanup(w, r)
		return
	}
	cfg, err := s.readConfig()
	if err != nil {
		slog.Error("cleanup: config file not read", "error", err)
		s.sendAPIError(w, http.StatusInternalServerError, "QP-INST-002", "The instance settings could not be read.")
		return
	}
	writeJSON(w, http.StatusOK, s.cleanupView(cfg))
}

// putCleanup changes the cleanup settings: every field is optional.
func (s *Server) putCleanup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled     *bool  `json:"enabled"`
		MaxAgeDays  *int   `json:"max_age_days"`
		MaxLogMB    *int64 `json:"max_log_mb"`
		MaxBackupMB *int64 `json:"max_backup_mb"`
	}
	if err := decodeJSONBody(w, r, maxCleanupBody, &req); err != nil {
		s.sendAPIError(w, http.StatusBadRequest, "QP-WEB-004", err.Error())
		return
	}
	if req.Enabled == nil && req.MaxAgeDays == nil && req.MaxLogMB == nil && req.MaxBackupMB == nil {
		s.sendAPIError(w, http.StatusBadRequest, "QP-INPUT-012", `No settings given: send {"enabled", "max_age_days", "max_log_mb", "max_backup_mb"}.`)
		return
	}
	if v := req.MaxAgeDays; v != nil && (*v < 1 || *v > config.MaxCleanupAgeDays) {
		s.sendAPIError(w, http.StatusBadRequest, "QP-INPUT-012", fmt.Sprintf("Keep files for 1 to %d days.", config.MaxCleanupAgeDays))
		return
	}
	for _, v := range []*int64{req.MaxLogMB, req.MaxBackupMB} {
		if v != nil && (*v < 1 || *v > config.MaxCleanupMB) {
			s.sendAPIError(w, http.StatusBadRequest, "QP-INPUT-012", fmt.Sprintf("A size limit is 1 to %d MB.", config.MaxCleanupMB))
			return
		}
	}
	if !s.api.change.TryLock() {
		s.sendAPIError(w, http.StatusConflict, "QP-INST-009", "Another change to this instance is still running. Try again when it has finished.")
		return
	}
	defer s.api.change.Unlock()
	cfg, err := s.loadConfigForChange()
	if err != nil {
		slog.Error("cleanup: config file not read", "error", err)
		s.sendAPIError(w, http.StatusInternalServerError, "QP-INST-002", "The instance settings could not be read.")
		return
	}
	c := &cfg.Cleanup
	if req.Enabled != nil {
		on := *req.Enabled
		c.Enabled = &on
	}
	if req.MaxAgeDays != nil {
		c.MaxAgeDays = *req.MaxAgeDays
	}
	if req.MaxLogMB != nil {
		c.MaxLogMB = *req.MaxLogMB
	}
	if req.MaxBackupMB != nil {
		c.MaxBackupMB = *req.MaxBackupMB
	}
	if err := config.Save(cfg); err != nil {
		slog.Error("cleanup: settings not saved", "error", err)
		s.sendAPIError(w, http.StatusInternalServerError, "QP-INST-002", "The cleanup settings could not be saved.")
		return
	}
	slog.Info("Storage cleanup settings changed", "enabled", c.On(), "max_age_days", c.MaxAgeDays,
		"max_log_mb", c.MaxLogMB, "max_backup_mb", c.MaxBackupMB)
	writeJSON(w, http.StatusOK, s.cleanupView(cfg))
}

// handleCleanupRun runs cleanup now (?dry_run=1: only says what it would do).
func (s *Server) handleCleanupRun(w http.ResponseWriter, r *http.Request) {
	if !s.allowMethods(w, r, http.MethodPost) {
		return
	}
	dry := r.URL.Query().Get("dry_run")
	if dry != "" && dry != "0" && dry != "1" && dry != "true" && dry != "false" {
		s.sendAPIError(w, http.StatusBadRequest, "QP-INPUT-012", "dry_run is 1 or 0.")
		return
	}
	extendWriteDeadline(w, cleanupTimeout+30*time.Second)
	// A client that hangs up must not stop a run half-way.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), cleanupTimeout+time.Minute)
	defer cancel()
	rep, err := s.runCleanup(ctx, true, dry == "1" || dry == "true")
	if err != nil {
		s.sendInternalError(w, "cleanup: run failed", err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}
