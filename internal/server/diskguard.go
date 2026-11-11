package server

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/diskguard"
	"github.com/qpot/qpot/internal/hostsetup"
	"github.com/qpot/qpot/internal/instance"
)

// Disk guard (internal/diskguard): a honeypot whose disk is full still
// accepts connections and cannot write its log, so what it accepted is
// recorded nowhere. Every few seconds the guard reads the free space of the
// disk that holds the honeypots' logs. Below the floor it runs cleanup once
// and, if that was not enough, stops every honeypot that runs (a stopped
// container's port is closed). It writes down which ones it stopped and
// starts exactly those again at the resume mark. The decisions are
// diskguard.Machine's; this file reads the disk and reaches the containers.

const (
	// diskGuardEvery is how often the guard reads the disk.
	diskGuardEvery = 5 * time.Second
	// diskGuardCleanupTimeout bounds the cleanup the guard waits for before
	// it stops the honeypots.
	diskGuardCleanupTimeout = time.Minute
	// diskGuardStatesTimeout bounds one look at the containers' states.
	diskGuardStatesTimeout = 30 * time.Second
	// diskGuardStopTimeout bounds stopping one honeypot.
	diskGuardStopTimeout = 2 * time.Minute
	// diskGuardStartTimeout bounds starting one honeypot.
	diskGuardStartTimeout = honeypotChangeTimeout
	// diskGuardReconcileEvery is how often the guard, between its two
	// marks, looks whether a honeypot it stopped runs again.
	diskGuardReconcileEvery = 30 * time.Second
	// diskGuardRetryFirst and diskGuardRetryMax are the waits between tries
	// to start honeypots that did not start.
	diskGuardRetryFirst = time.Minute
	diskGuardRetryMax   = 10 * time.Minute
	// diskGuardWarnEvery is how often one repeated problem is logged.
	diskGuardWarnEvery = 5 * time.Minute
	// diskGuardCode is the error code that explains a guard stop.
	diskGuardCode = "QP-RES-008"
)

// diskGuardInfra are the compose services that are not honeypots: the guard
// never stops them.
var diskGuardInfra = map[string]bool{"database": true, "collector": true, "netguard": true}

// diskGuardFront maps a compose service that takes attackers' connections
// for a honeypot of another name to that honeypot: snare is tanner's web
// front end.
var diskGuardFront = map[string]string{"snare": "tanner"}

// diskGuardCompanions maps the other services a honeypot runs to it:
// tanner's helpers and the SSH cells of ssh-proxy. They are stopped and
// started with their honeypot (instance.Manager does that).
var diskGuardCompanions = func() map[string]string {
	m := map[string]string{"tanner_api": "tanner", "tanner_phpox": "tanner", "tanner_redis": "tanner"}
	for _, svc := range instance.SSHCellLogServices() {
		m[svc] = "ssh-proxy"
	}
	return m
}()

// diskFreeBytes reads the free space of the disk that holds a folder; tests
// replace it.
var diskFreeBytes = hostsetup.DataFreeBytes

// diskGuardState is the guard's state in a running server.
type diskGuardState struct {
	// run lets one tick go at a time. Everything below it down to mu is
	// only touched by the tick that holds it.
	run     sync.Mutex
	machine diskguard.Machine
	// loaded: the state file has been read. state lists the honeypots the
	// guard stopped; dirty means the file does not say so yet.
	loaded bool
	state  diskguard.State
	dirty  bool
	// reconciled is when the guard last compared state with the containers.
	reconciled time.Time
	// retryAt and retryWait space the tries to start honeypots again.
	retryAt   time.Time
	retryWait time.Duration
	// warned is when each repeated problem was last logged (a fixed, small
	// set of keys).
	warned map[string]time.Time
	// condition is the last tick's, to log a change once.
	condition diskguard.Condition

	// free replaces diskFreeBytes (tests).
	free func(path string) (int64, bool)

	// mu guards view, which GET /api/status reads.
	mu   sync.Mutex
	view *diskGuardView
}

// diskGuardStopped is one honeypot the guard keeps stopped.
type diskGuardStopped struct {
	Name      string    `json:"name"`
	StoppedAt time.Time `json:"stopped_at"`
}

// diskGuardView is the "disk_guard" field of GET /api/status.
type diskGuardView struct {
	// State is "off", "unknown" (the free space cannot be read), "ok",
	// "low" (below the floor: honeypots are kept stopped) or "waiting"
	// (room is back above the floor; the stopped honeypots start at the
	// resume mark).
	State string `json:"state"`
	// FreeBytes is null when the free space cannot be read.
	FreeBytes       *int64 `json:"free_bytes"`
	MinFreeBytes    int64  `json:"min_free_bytes"`
	ResumeFreeBytes int64  `json:"resume_free_bytes"`
	// Stopped lists the honeypots the guard stopped and has not started
	// again.
	Stopped []diskGuardStopped `json:"stopped"`
	// Code is the error code that explains a stop (while low or waiting).
	Code string `json:"code,omitempty"`
	// CheckedAt is when the guard last read the disk.
	CheckedAt time.Time `json:"checked_at"`
}

// diskGuardThresholds are cfg's two marks.
func diskGuardThresholds(cfg *config.Config) diskguard.Thresholds {
	return diskguard.FromMB(cfg.Cleanup.DiskGuard())
}

// diskGuardFolder is the folder whose disk the guard watches: the
// honeypots' logs are under <data>/honeypots/<name>/logs.
func diskGuardFolder(cfg *config.Config) string {
	return filepath.Join(cfg.DataPath, "honeypots")
}

// CheckDiskSpace refuses to start honeypots while the disk that holds the
// instance's data is below the disk guard's floor (QP-RES-008): `qpot up`
// asks it before it starts containers. It allows the start when the guard
// is off or the free space cannot be read.
func CheckDiskSpace(cfg *config.Config) error {
	t := diskGuardThresholds(cfg)
	if !t.On() || cfg.DataPath == "" {
		return nil
	}
	free, known := diskFreeBytes(diskGuardFolder(cfg))
	if !known || free >= t.MinFree {
		return nil
	}
	return hostsetup.E(diskGuardCode).WithWhy(
		"Only %d MB are free on the disk that holds %s, and cleanup.min_free_mb is %d. A honeypot that cannot write its log still accepts connections and records nothing, so the honeypots were not started.",
		free>>20, cfg.DataPath, t.MinFree>>20)
}

// diskGuardLoop runs the guard at once and then every diskGuardEvery.
func (s *Server) diskGuardLoop(ctx context.Context) {
	t := time.NewTicker(diskGuardEvery)
	defer t.Stop()
	for {
		s.diskGuardTick(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// read is one look at the disk that holds cfg's honeypot logs.
func (g *diskGuardState) read(cfg *config.Config) diskguard.Reading {
	if cfg.DataPath == "" {
		return diskguard.Reading{}
	}
	free := g.free
	if free == nil {
		free = diskFreeBytes
	}
	n, known := free(diskGuardFolder(cfg))
	return diskguard.Reading{Free: n, Known: known && n >= 0}
}

// warnNow reports whether a repeated problem is due to be logged again.
func (g *diskGuardState) warnNow(key string, now time.Time) bool {
	if g.warned == nil {
		g.warned = map[string]time.Time{}
	}
	if last, ok := g.warned[key]; ok && now.Sub(last) < diskGuardWarnEvery && !now.Before(last) {
		return false
	}
	g.warned[key] = now
	return true
}

// save writes the state file when it is behind. A write that fails (the
// disk is full) is tried again on the next tick; the guard goes by what it
// has in memory meanwhile.
func (g *diskGuardState) save(path string, now time.Time) {
	if !g.dirty {
		return
	}
	if err := diskguard.SaveState(path, g.state); err != nil {
		if g.warnNow("save", now) {
			slog.Warn("Disk guard: its state file could not be written; if this server stops now, the honeypots it stopped are not started again by themselves",
				"error", err, "stopped", g.state.Names())
		}
		return
	}
	g.dirty = false
}

// diskGuardTick is one round of the guard: read the disk, do what the
// machine says, save the state and keep the view for GET /api/status.
func (s *Server) diskGuardTick(ctx context.Context, now time.Time) {
	g := &s.api.diskGuard
	g.run.Lock()
	defer g.run.Unlock()

	cfg, err := s.readConfig()
	if err != nil {
		if g.warnNow("config", now) {
			slog.Warn("Disk guard: the config file could not be read; using the settings this server started with", "error", err)
		}
		cfg = s.config
	}
	if cfg.DataPath == "" {
		return
	}
	path := diskguard.Path(cfg.DataPath)
	if !g.loaded {
		st, err := diskguard.LoadState(path)
		if err != nil {
			// Nothing in a damaged file is trusted: no honeypot is started
			// because of it. The next save replaces or removes it.
			slog.Warn("Disk guard: its state file is damaged and was ignored; no honeypot is started because of it", "error", err)
			g.dirty = true
		}
		g.state, g.loaded = st, true
		if st.Held() {
			slog.Warn("Disk guard: honeypots it stopped earlier are still stopped", "stopped", st.Names())
		}
	}

	t := diskGuardThresholds(cfg)
	r := g.read(cfg)
	action := g.machine.Next(now, t, r, g.state.Held())
	stoppedFirst := false
	if action == diskguard.Cleanup {
		if stoppedFirst = diskGuardUrgent(t, r); stoppedFirst {
			// Hardly anything is left: a honeypot cannot write its log now,
			// and cleanup may take a minute. Stop first, then look for room.
			// (Found by filling a disk at once: with cleanup first, the
			// honeypot kept accepting connections it could not record.)
			slog.Warn("Disk guard: the disk is full; stopping the honeypots before cleanup",
				"free_mb", r.Free>>20, "min_free_mb", t.MinFree>>20, "code", diskGuardCode)
			s.diskGuardStop(ctx, cfg, path, now, t, r)
		} else {
			slog.Warn("Disk guard: the disk is nearly full; running cleanup before any honeypot is stopped",
				"free_mb", r.Free>>20, "min_free_mb", t.MinFree>>20, "code", diskGuardCode)
		}
		s.diskGuardCleanup(ctx)
		r = g.read(cfg)
		// The machine has just asked for a cleanup, so it does not ask again.
		action = g.machine.Next(now, t, r, g.state.Held())
	}
	switch action {
	case diskguard.Stop:
		// One round of stops per tick: what did not stop is tried again on
		// the next one.
		if !stoppedFirst {
			s.diskGuardStop(ctx, cfg, path, now, t, r)
		}
	case diskguard.Resume:
		s.diskGuardResume(ctx, cfg, now, t, r)
	default:
		if g.state.Held() && r.Known {
			s.diskGuardReconcile(ctx, cfg, now)
		}
	}
	g.save(path, now)

	cond := diskguard.Describe(t, r, g.state.Held())
	if cond != g.condition {
		if g.condition != "" || (cond != diskguard.OK && cond != diskguard.Off) {
			slog.Info("Disk guard", "state", string(cond), "free_mb", r.Free>>20, "free_known", r.Known,
				"min_free_mb", t.MinFree>>20, "resume_free_mb", t.ResumeFree>>20, "stopped", g.state.Names())
		}
		g.condition = cond
	}
	v := newDiskGuardView(t, r, g.state, now)
	g.mu.Lock()
	g.view = &v
	g.mu.Unlock()
}

// diskGuardUrgent reports whether the disk is so nearly full (under a quarter
// of the floor) that the honeypots are stopped before cleanup is tried
// instead of after.
func diskGuardUrgent(t diskguard.Thresholds, r diskguard.Reading) bool {
	return r.Known && t.On() && r.Free < t.MinFree/4
}

// diskGuardCleanup runs the storage cleanup as the hourly run does (it does
// nothing while cleanup is turned off) and waits for it for a bounded time.
func (s *Server) diskGuardCleanup(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, diskGuardCleanupTimeout)
	defer cancel()
	rep, err := s.runCleanup(cctx, false, false)
	switch {
	case err != nil:
		slog.Warn("Disk guard: cleanup did not run", "error", err)
	case rep == nil:
		slog.Warn("Disk guard: cleanup is turned off (cleanup.enabled), so nothing was removed")
	}
}

// diskGuardRunning is what the guard needs to know about the containers.
type diskGuardRunning struct {
	// any: at least one container of the instance runs.
	any bool
	// active are the honeypots with a running container of their own or of
	// a companion; front are those whose attacker-facing container runs.
	active map[string]bool
	front  map[string]bool
	// services are the running compose services.
	services map[string]bool
}

// up reports whether a honeypot runs as far as the guard can tell: its own
// container, and for one with a separate front end that one too.
func (r diskGuardRunning) up(name string) bool {
	if !r.services[name] {
		return false
	}
	for front, owner := range diskGuardFront {
		if owner == name && !r.services[front] {
			return false
		}
	}
	return true
}

// containerActive reports whether a container in this state takes
// connections now or will by itself in a moment.
func containerActive(state string) bool {
	return state == "running" || state == "restarting"
}

// diskGuardContainers asks Docker which of cfg's honeypots run.
func (s *Server) diskGuardContainers(ctx context.Context, cfg *config.Config) (diskGuardRunning, error) {
	out := diskGuardRunning{active: map[string]bool{}, front: map[string]bool{}, services: map[string]bool{}}
	st := s.serviceStater()
	if st == nil {
		return out, errors.New("this server cannot reach the instance's containers")
	}
	sctx, cancel := context.WithTimeout(ctx, diskGuardStatesTimeout)
	defer cancel()
	states, err := st.ServiceStates(sctx)
	if err != nil {
		return out, err
	}
	hps := cfg.SnapshotHoneypots()
	for svc, state := range states {
		if !containerActive(state.State) {
			continue
		}
		out.any = true
		out.services[svc] = true
		if diskGuardInfra[svc] {
			continue
		}
		if _, ok := hps[svc]; ok {
			out.active[svc], out.front[svc] = true, true
			continue
		}
		if owner, ok := diskGuardFront[svc]; ok {
			if _, ok := hps[owner]; ok {
				out.active[owner], out.front[owner] = true, true
			}
			continue
		}
		if owner, ok := diskGuardCompanions[svc]; ok {
			if _, ok := hps[owner]; ok {
				out.active[owner] = true
			}
		}
	}
	return out, nil
}

// sortedNames returns a set's names in order.
func sortedNames(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for name, in := range set {
		if in {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// diskGuardStop stops every honeypot that runs. It is called on every tick
// below the floor, so one that was started again is stopped again.
func (s *Server) diskGuardStop(ctx context.Context, cfg *config.Config, path string, now time.Time, t diskguard.Thresholds, r diskguard.Reading) {
	g := &s.api.diskGuard
	running, err := s.diskGuardContainers(ctx, cfg)
	if err != nil {
		if g.warnNow("states", now) {
			slog.Error("Disk guard: the disk is nearly full, but the containers' states could not be read, so no honeypot was stopped",
				"error", err, "free_mb", r.Free>>20, "code", diskGuardCode)
		}
		return
	}
	names := sortedNames(running.active)
	if len(names) == 0 {
		return
	}
	// Not behind the lock of the honeypot changes (s.api.change): a stop
	// changes no setting, and it must not wait minutes for a change that
	// is still running. The manager's own lock keeps Docker calls apart.
	live, err := s.loadConfigForChange()
	if err != nil {
		live = cfg
	}
	runner, err := s.honeypotRunner(live)
	if err != nil {
		// A config that no manager can be made for must not keep the
		// honeypots running: the server's own manager can stop them too.
		if runner = s.liveRunner(); runner == nil {
			if g.warnNow("runner", now) {
				slog.Error("Disk guard: the disk is nearly full, but the containers cannot be reached, so no honeypot was stopped", "error", err, "code", diskGuardCode)
			}
			return
		}
	}
	// Written down before the stop: a server that is killed half-way still
	// knows what it stopped. Only a honeypot that took connections is
	// listed, so nothing the operator had stopped is started later.
	for _, name := range names {
		if running.front[name] && g.state.Add(name, now) {
			g.dirty = true
		}
	}
	g.save(path, now)
	for _, name := range names {
		sctx, cancel := context.WithTimeout(ctx, diskGuardStopTimeout)
		err := runner.StopHoneypot(sctx, name)
		cancel()
		if err != nil {
			slog.Error("Disk guard: a honeypot did not stop; it is tried again in a few seconds",
				"honeypot", name, "error", err, "code", diskGuardCode)
			continue
		}
		slog.Warn("Disk guard stopped a honeypot: the disk is nearly full and it could not record what it accepts",
			"honeypot", name, "free_mb", r.Free>>20, "min_free_mb", t.MinFree>>20,
			"resume_free_mb", t.ResumeFree>>20, "code", diskGuardCode)
	}
}

// diskGuardResume starts the honeypots the guard stopped, through the
// normal start path (instance.Manager.StartHoneypot and its start gates).
// One that was turned off meanwhile, or runs already, is only taken off the
// list. One that does not start stays on it and is tried again later.
func (s *Server) diskGuardResume(ctx context.Context, cfg *config.Config, now time.Time, t diskguard.Thresholds, r diskguard.Reading) {
	g := &s.api.diskGuard
	if now.Before(g.retryAt) {
		return
	}
	later := func() {
		g.retryWait = min(max(2*g.retryWait, diskGuardRetryFirst), diskGuardRetryMax)
		g.retryAt = now.Add(g.retryWait)
	}
	running, err := s.diskGuardContainers(ctx, cfg)
	if err != nil {
		slog.Warn("Disk guard: there is room again, but the containers' states could not be read; the honeypots are started later",
			"error", err, "stopped", g.state.Names())
		later()
		return
	}
	if !s.api.change.TryLock() {
		return
	}
	defer s.api.change.Unlock()
	if !running.any {
		// The operator stopped the whole instance: `qpot up` starts it,
		// honeypots and all.
		slog.Info("Disk guard: the instance is not running, so it starts no honeypot; the next qpot up starts them", "stopped", g.state.Names())
		g.state, g.dirty = diskguard.State{}, true
		g.retryAt, g.retryWait = time.Time{}, 0
		return
	}
	live, err := s.loadConfigForChange()
	if err != nil {
		slog.Warn("Disk guard: there is room again, but the config file could not be read; the honeypots are started later", "error", err)
		later()
		return
	}
	runner, err := s.honeypotRunner(live)
	if err != nil {
		slog.Warn("Disk guard: there is room again, but the containers cannot be reached; the honeypots are started later", "error", err)
		later()
		return
	}
	failed := false
	for _, name := range g.state.Names() {
		hp, ok := live.GetHoneypotConfig(name)
		switch {
		case !ok || !hp.Enabled:
			slog.Info("Disk guard: a honeypot it stopped was turned off meanwhile and stays stopped", "honeypot", name)
		case running.up(name):
			slog.Info("Disk guard: a honeypot it stopped runs again already", "honeypot", name)
		default:
			sctx, cancel := context.WithTimeout(ctx, diskGuardStartTimeout)
			err := runner.StartHoneypot(sctx, name)
			cancel()
			if err != nil {
				failed = true
				slog.Error("Disk guard: a honeypot it stopped did not start again; it is tried again later",
					"honeypot", name, "error", err)
				continue
			}
			slog.Warn("Disk guard started a honeypot again: there is room on the disk",
				"honeypot", name, "free_mb", r.Free>>20, "resume_free_mb", t.ResumeFree>>20, "guard_on", t.On())
		}
		if g.state.Remove(name) {
			g.dirty = true
		}
	}
	if failed {
		later()
		return
	}
	g.retryAt, g.retryWait = time.Time{}, 0
}

// diskGuardReconcile runs between the two marks, while the guard holds
// honeypots: one that runs again was started by someone else, so the guard
// takes it off its list and will not start it later.
func (s *Server) diskGuardReconcile(ctx context.Context, cfg *config.Config, now time.Time) {
	g := &s.api.diskGuard
	if !g.reconciled.IsZero() && now.Sub(g.reconciled) < diskGuardReconcileEvery && !now.Before(g.reconciled) {
		return
	}
	g.reconciled = now
	running, err := s.diskGuardContainers(ctx, cfg)
	if err != nil {
		return
	}
	for _, name := range g.state.Names() {
		if running.up(name) && g.state.Remove(name) {
			g.dirty = true
			slog.Info("Disk guard: a honeypot it stopped was started again by someone else; it is no longer the guard's to start", "honeypot", name)
		}
	}
}

// newDiskGuardView renders the guard's state for GET /api/status.
func newDiskGuardView(t diskguard.Thresholds, r diskguard.Reading, st diskguard.State, now time.Time) diskGuardView {
	v := diskGuardView{
		State:           string(diskguard.Describe(t, r, st.Held())),
		MinFreeBytes:    t.MinFree,
		ResumeFreeBytes: t.ResumeFree,
		Stopped:         make([]diskGuardStopped, 0, len(st.Stopped)),
		CheckedAt:       now.UTC().Truncate(time.Second),
	}
	if !t.On() {
		v.MinFreeBytes, v.ResumeFreeBytes = 0, 0
	}
	if r.Known {
		free := r.Free
		v.FreeBytes = &free
	}
	for _, e := range st.Stopped {
		v.Stopped = append(v.Stopped, diskGuardStopped{Name: e.Name, StoppedAt: e.StoppedAt})
	}
	if st.Held() || v.State == string(diskguard.Low) {
		v.Code = diskGuardCode
	}
	return v
}

// diskGuardStatus is the guard's state for GET /api/status: the last tick's,
// or, before the first one, a look at the disk and the state file now.
func (s *Server) diskGuardStatus() diskGuardView {
	g := &s.api.diskGuard
	g.mu.Lock()
	last := g.view
	g.mu.Unlock()
	if last != nil {
		v := *last
		v.Stopped = append([]diskGuardStopped{}, last.Stopped...)
		return v
	}
	cfg, err := s.readConfig()
	if err != nil {
		cfg = s.config
	}
	var st diskguard.State
	if cfg.DataPath != "" {
		// A damaged file lists nothing.
		st, _ = diskguard.LoadState(diskguard.Path(cfg.DataPath))
	}
	return newDiskGuardView(diskGuardThresholds(cfg), g.read(cfg), st, time.Now())
}
