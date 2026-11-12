package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/diskguard"
	"github.com/qpot/qpot/internal/hostsetup"
	"github.com/qpot/qpot/internal/instance"
)

const guardMB = int64(1) << 20

// guardRunner stands in for the instance's containers: it keeps a state per
// compose service, and a stop or start changes it as Docker would.
type guardRunner struct {
	mu        sync.Mutex
	states    map[string]instance.ServiceState
	statesErr error
	stopped   []string
	started   []string
	stopErr   map[string]error
	startErr  map[string]error
	// companions are the services stopped and started with a honeypot.
	companions map[string][]string
	// startCfgs are the configs a start was asked with.
	cfgs []*config.Config
	// onStop, when set, is called at every stop.
	onStop func()
}

func newGuardRunner(states map[string]string) *guardRunner {
	r := &guardRunner{states: map[string]instance.ServiceState{}, stopErr: map[string]error{}, startErr: map[string]error{},
		companions: map[string][]string{"tanner": {"snare", "tanner_api", "tanner_phpox", "tanner_redis"},
			"ssh-proxy": {"ssh-backend-1", "ssh-backend-1-db", "ssh-backend-1-backup"}}}
	for svc, st := range states {
		r.states[svc] = instance.ServiceState{State: st}
	}
	return r
}

func (r *guardRunner) ServiceStates(context.Context) (map[string]instance.ServiceState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.statesErr != nil {
		return nil, r.statesErr
	}
	out := make(map[string]instance.ServiceState, len(r.states))
	for k, v := range r.states {
		out[k] = v
	}
	return out, nil
}

func (r *guardRunner) IsRunning(context.Context) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, st := range r.states {
		if st.State == "running" {
			return true
		}
	}
	return false
}

func (r *guardRunner) set(state string, name string) {
	for _, svc := range append([]string{name}, r.companions[name]...) {
		if _, ok := r.states[svc]; ok || svc == name {
			r.states[svc] = instance.ServiceState{State: state}
		}
	}
}

func (r *guardRunner) StopHoneypot(_ context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopped = append(r.stopped, name)
	if r.onStop != nil {
		r.onStop()
	}
	if err := r.stopErr[name]; err != nil {
		return err
	}
	r.set("exited", name)
	return nil
}

func (r *guardRunner) StartHoneypot(_ context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.started = append(r.started, name)
	if err := r.startErr[name]; err != nil {
		return err
	}
	r.set("running", name)
	return nil
}

func (r *guardRunner) RecreateHoneypot(ctx context.Context, name string) error {
	return r.StartHoneypot(ctx, name)
}

func (r *guardRunner) RestartHoneypot(ctx context.Context, name string) error {
	return r.StartHoneypot(ctx, name)
}

// setState is what the operator (or Docker) does behind the guard's back.
func (r *guardRunner) setState(svc, state string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.states[svc] = instance.ServiceState{State: state}
}

func (r *guardRunner) state(svc string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.states[svc].State
}

// take returns and forgets the stops and starts so far.
func (r *guardRunner) take() (stopped, started []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	stopped, started = r.stopped, r.started
	r.stopped, r.started = nil, nil
	return stopped, started
}

// guardTest is a server with a fake disk and fake containers.
type guardTest struct {
	*apiTestServer
	t      *testing.T
	runner *guardRunner
	mu     sync.Mutex
	freeMB int64
	known  bool
	// freeFn, when set, replaces freeMB (a disk that cleanup changes).
	freeFn func() int64
	asked  []string
	now    time.Time
}

// guardEnabled are the honeypots turned on in a guard test's config.
var guardEnabled = map[string]bool{"cowrie": true, "dionaea": true, "endlessh": true}

func newGuardTest(t *testing.T, name string, states map[string]string, prep func(*config.Config)) *guardTest {
	t.Helper()
	a := newAPITestServer(t, name, func(cfg *config.Config) {
		for hp, h := range cfg.Honeypots {
			h.Enabled = guardEnabled[hp]
			cfg.Honeypots[hp] = h
		}
		// No reserve file unless a test asks for one: the default is 64 MB
		// of random bytes per test.
		none := int64(0)
		cfg.Cleanup.ReserveMB = &none
		if prep != nil {
			prep(cfg)
		}
	})
	g := &guardTest{apiTestServer: a, t: t, runner: newGuardRunner(states), freeMB: 50000, known: true,
		now: time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)}
	g.attach(a.s)
	return g
}

// attach gives a server the test's disk and containers.
func (g *guardTest) attach(s *Server) {
	s.api.runner = func(c *config.Config) instance.HoneypotRunner {
		g.runner.mu.Lock()
		g.runner.cfgs = append(g.runner.cfgs, c)
		g.runner.mu.Unlock()
		return g.runner
	}
	s.api.cleanup.collector = func(context.Context) bool { return true }
	s.api.diskGuard.free = func(path string) (int64, bool) {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.asked = append(g.asked, path)
		if g.freeFn != nil {
			return g.freeFn() * guardMB, g.known
		}
		return g.freeMB * guardMB, g.known
	}
}

// restart is a new qpot serve for the same instance: it knows nothing but
// what is on disk.
func (g *guardTest) restart() {
	s := &Server{config: g.cfg, mux: http.NewServeMux()}
	g.attach(s)
	g.s = s
}

func (g *guardTest) setFree(mb int64) {
	g.mu.Lock()
	g.freeMB = mb
	g.mu.Unlock()
}

// tick runs the guard once, five seconds after the last time.
func (g *guardTest) tick() {
	g.t.Helper()
	g.now = g.now.Add(diskGuardEvery)
	g.s.diskGuardTick(context.Background(), g.now)
}

// file returns what the state file lists (nil when there is none).
func (g *guardTest) file() []string {
	g.t.Helper()
	st, err := diskguard.LoadState(diskguard.Path(g.cfg.DataPath))
	if err != nil {
		g.t.Fatalf("state file: %v", err)
	}
	if !st.Held() {
		return nil
	}
	return st.Names()
}

func (g *guardTest) wantCalls(what string, wantStopped, wantStarted []string) {
	g.t.Helper()
	stopped, started := g.runner.take()
	if !reflect.DeepEqual(stopped, wantStopped) {
		g.t.Fatalf("%s: stopped %v, want %v", what, stopped, wantStopped)
	}
	if !reflect.DeepEqual(started, wantStarted) {
		g.t.Fatalf("%s: started %v, want %v", what, started, wantStarted)
	}
}

// allRunning is an instance with its three enabled honeypots, a disabled
// one's container absent and the infrastructure up.
func allRunning() map[string]string {
	return map[string]string{"database": "running", "collector": "running", "netguard": "running",
		"cowrie": "running", "dionaea": "running", "endlessh": "running"}
}

// TestDiskGuardStopsAndResumes is the whole cycle on one server: low disk ->
// cleanup tried -> honeypots stopped (the infrastructure and a honeypot the
// operator had stopped are left alone) -> stopped again when one comes back
// -> nothing between the marks -> exactly the guard's own stops started at
// the resume mark.
func TestDiskGuardStopsAndResumes(t *testing.T) {
	states := allRunning()
	states["endlessh"] = "exited" // the operator stopped it with docker
	g := newGuardTest(t, "guard-cycle", states, nil)
	old := oldCapture(t, g.apiTestServer)

	// Plenty of room: nothing happens, and Docker is not even asked.
	g.tick()
	g.wantCalls("plenty of room", nil, nil)
	if len(g.runner.cfgs) != 0 {
		t.Fatalf("the guard reached for the containers with plenty of room (%d times)", len(g.runner.cfgs))
	}
	if g.file() != nil {
		t.Fatalf("state file with plenty of room: %v", g.file())
	}
	// It watches the folder the honeypots' logs are in.
	if want := filepath.Join(g.cfg.DataPath, "honeypots"); len(g.asked) == 0 || g.asked[0] != want {
		t.Fatalf("free space read of %v, want %s", g.asked, want)
	}
	if v := g.s.diskGuardStatus(); v.State != "ok" || v.Code != "" || len(v.Stopped) != 0 || v.FreeBytes == nil || *v.FreeBytes != 50000*guardMB {
		t.Fatalf("status with plenty of room: %+v", v)
	}

	// Below the floor: cleanup first, then the stop.
	g.setFree(100)
	g.tick()
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("cleanup was not tried before the stop: the 40-day-old capture is still there (%v)", err)
	}
	if last := getCleanup(t, g.apiTestServer).Last; last == nil || last.Removed == 0 {
		t.Fatalf("the cleanup the guard ran is not the instance's last run: %+v", last)
	}
	g.wantCalls("low disk", []string{"cowrie", "dionaea"}, nil)
	for _, svc := range []string{"database", "collector", "netguard"} {
		if g.runner.state(svc) != "running" {
			t.Errorf("%s was stopped", svc)
		}
	}
	if got := g.file(); !reflect.DeepEqual(got, []string{"cowrie", "dionaea"}) {
		t.Fatalf("state file lists %v, want the two the guard stopped", got)
	}
	v := g.s.diskGuardStatus()
	if v.State != "low" || v.Code != "QP-RES-008" || len(v.Stopped) != 2 || v.Stopped[0].Name != "cowrie" ||
		v.MinFreeBytes != 512*guardMB || v.ResumeFreeBytes != 1024*guardMB || *v.FreeBytes != 100*guardMB {
		t.Fatalf("status while low: %+v", v)
	}
	if !v.Stopped[0].StoppedAt.Equal(g.now) {
		t.Errorf("stopped_at %v, want %v", v.Stopped[0].StoppedAt, g.now)
	}

	// Still low, nothing runs: nothing to stop, no second cleanup.
	g.tick()
	g.wantCalls("still low", nil, nil)

	// Someone starts cowrie again while the disk is still low.
	g.runner.setState("cowrie", "running")
	g.tick()
	g.wantCalls("cowrie came back", []string{"cowrie"}, nil)
	// So does a crash-looping one: Docker would bring it back by itself.
	g.runner.setState("dionaea", "restarting")
	g.tick()
	g.wantCalls("dionaea restarting", []string{"dionaea"}, nil)
	// And the operator's own endlessh: it is stopped too, and, having taken
	// connections, it is now the guard's to start again.
	g.runner.setState("endlessh", "running")
	g.tick()
	g.wantCalls("endlessh started while low", []string{"endlessh"}, nil)
	if got := g.file(); !reflect.DeepEqual(got, []string{"cowrie", "dionaea", "endlessh"}) {
		t.Fatalf("state file lists %v", got)
	}
	// The operator stops endlessh for good with the guard holding it: turned
	// off in the config, it is not started at the resume mark.
	cfg, err := g.s.loadConfigForChange()
	if err != nil {
		t.Fatal(err)
	}
	cfg.DisableHoneypot("endlessh")
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}

	// Between the marks: nothing stops, nothing starts.
	for _, mb := range []int64{512, 700, 1023, 600} {
		g.setFree(mb)
		g.tick()
		g.wantCalls("between the marks", nil, nil)
		if v := g.s.diskGuardStatus(); v.State != "waiting" || v.Code != "QP-RES-008" || len(v.Stopped) != 3 {
			t.Fatalf("status at %d MB: %+v", mb, v)
		}
	}

	// The resume mark: the guard's own stops start, through StartHoneypot.
	g.setFree(1024)
	g.tick()
	g.wantCalls("resume mark", nil, []string{"cowrie", "dionaea"})
	if got := g.file(); got != nil {
		t.Fatalf("state file after the resume: %v", got)
	}
	if _, err := os.Stat(diskguard.Path(g.cfg.DataPath)); !os.IsNotExist(err) {
		t.Fatalf("the state file is still there: %v", err)
	}
	if g.runner.state("endlessh") == "running" {
		t.Fatal("a honeypot the operator turned off was started")
	}
	if v := g.s.diskGuardStatus(); v.State != "ok" || v.Code != "" || len(v.Stopped) != 0 {
		t.Fatalf("status after the resume: %+v", v)
	}
	g.tick()
	g.wantCalls("after the resume", nil, nil)
}

// TestDiskGuardLeavesOperatorStopsAlone: a honeypot that was not running
// when the guard stopped the rest is not started at the resume mark.
func TestDiskGuardLeavesOperatorStopsAlone(t *testing.T) {
	states := allRunning()
	states["endlessh"] = "exited"
	g := newGuardTest(t, "guard-operator", states, nil)
	g.setFree(10)
	g.tick()
	g.wantCalls("low disk", []string{"cowrie", "dionaea"}, nil)
	g.setFree(5000)
	g.tick()
	g.wantCalls("room again", nil, []string{"cowrie", "dionaea"})
	if g.runner.state("endlessh") != "exited" {
		t.Fatalf("endlessh, which the operator had stopped, is %s", g.runner.state("endlessh"))
	}
}

// TestDiskGuardRestartResumesOnlyItsOwn: a restarted qpot serve starts
// exactly the honeypots the state file lists, and none because of a damaged
// file.
func TestDiskGuardRestartResumesOnlyItsOwn(t *testing.T) {
	t.Run("state file", func(t *testing.T) {
		states := allRunning()
		states["endlessh"] = "exited"
		g := newGuardTest(t, "guard-restart", states, nil)
		g.setFree(100)
		g.tick()
		g.wantCalls("low disk", []string{"cowrie", "dionaea"}, nil)

		// qpot serve dies and comes back while the disk is still low.
		g.restart()
		g.tick()
		g.wantCalls("restarted, still low", nil, nil)
		if v := g.s.diskGuardStatus(); v.State != "low" || len(v.Stopped) != 2 {
			t.Fatalf("status after the restart: %+v", v)
		}
		// And again, now with room.
		g.restart()
		// Before its first look the status already tells what the file says.
		g.setFree(4000)
		if v := g.s.diskGuardStatus(); v.State != "waiting" || len(v.Stopped) != 2 {
			t.Fatalf("status before the first tick: %+v", v)
		}
		g.tick()
		g.wantCalls("restarted with room", nil, []string{"cowrie", "dionaea"})
		if g.runner.state("endlessh") != "exited" {
			t.Fatal("the restarted guard started a honeypot it had not stopped")
		}
		if got := g.file(); got != nil {
			t.Fatalf("state file after the resume: %v", got)
		}
	})

	t.Run("damaged state file", func(t *testing.T) {
		states := allRunning()
		states["cowrie"], states["dionaea"] = "exited", "exited"
		g := newGuardTest(t, "guard-damaged", states, nil)
		path := diskguard.Path(g.cfg.DataPath)
		if err := os.WriteFile(path, []byte(`{"version":1,"stopped":[{"name":"cowrie","stopped_at":"2026-11-12T09:30:15Z"},{"name":"--volumes"`), 0o600); err != nil {
			t.Fatal(err)
		}
		g.tick()
		g.wantCalls("damaged file, plenty of room", nil, nil)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("the damaged file was left in place: %v", err)
		}
		if v := g.s.diskGuardStatus(); v.State != "ok" || len(v.Stopped) != 0 {
			t.Fatalf("status: %+v", v)
		}
	})

	t.Run("names the config does not have", func(t *testing.T) {
		g := newGuardTest(t, "guard-foreign", allRunning(), nil)
		var st diskguard.State
		st.Add("no-such-honeypot", g.now)
		st.Add("heralding", g.now) // configured, and turned off
		if err := diskguard.SaveState(diskguard.Path(g.cfg.DataPath), st); err != nil {
			t.Fatal(err)
		}
		g.tick()
		g.wantCalls("foreign names", nil, nil)
		if got := g.file(); got != nil {
			t.Fatalf("state file: %v", got)
		}
	})
}

// TestDiskGuardCleanupRecovers: when cleanup frees enough, no honeypot is
// stopped.
func TestDiskGuardCleanupRecovers(t *testing.T) {
	g := newGuardTest(t, "guard-cleanup", allRunning(), nil)
	old := oldCapture(t, g.apiTestServer)
	// The disk is low for as long as the old capture is on it.
	g.freeFn = func() int64 {
		if _, err := os.Stat(old); err == nil {
			return 200
		}
		return 3000
	}
	g.tick()
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("cleanup did not run: %v", err)
	}
	g.wantCalls("cleanup freed enough", nil, nil)
	if got := g.file(); got != nil {
		t.Fatalf("state file: %v", got)
	}
	if v := g.s.diskGuardStatus(); v.State != "ok" {
		t.Fatalf("status: %+v", v)
	}
}

// TestDiskGuardRespectsCleanupOff: with automatic cleanup turned off the
// guard deletes nothing, and still stops the honeypots.
func TestDiskGuardRespectsCleanupOff(t *testing.T) {
	off := false
	g := newGuardTest(t, "guard-nocleanup", allRunning(), func(cfg *config.Config) { cfg.Cleanup.Enabled = &off })
	old := oldCapture(t, g.apiTestServer)
	g.setFree(100)
	g.tick()
	if _, err := os.Stat(old); err != nil {
		t.Fatalf("the guard removed a file with cleanup turned off: %v", err)
	}
	g.wantCalls("low disk, cleanup off", []string{"cowrie", "dionaea", "endlessh"}, nil)
}

// TestDiskGuardOffAndUnknown: a guard that is off, or cannot read the disk,
// does nothing; one turned off while it holds honeypots gives them back.
func TestDiskGuardOffAndUnknown(t *testing.T) {
	t.Run("off", func(t *testing.T) {
		zero := int64(0)
		g := newGuardTest(t, "guard-off", allRunning(), func(cfg *config.Config) { cfg.Cleanup.MinFreeMB = &zero })
		old := oldCapture(t, g.apiTestServer)
		g.setFree(0)
		g.tick()
		g.wantCalls("guard off, full disk", nil, nil)
		if _, err := os.Stat(old); err != nil {
			t.Fatalf("a guard that is off ran cleanup: %v", err)
		}
		if v := g.s.diskGuardStatus(); v.State != "off" || v.MinFreeBytes != 0 || v.ResumeFreeBytes != 0 || v.Code != "" {
			t.Fatalf("status: %+v", v)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		g := newGuardTest(t, "guard-unknown", allRunning(), nil)
		g.known = false
		g.setFree(0)
		g.tick()
		g.wantCalls("unknown free space", nil, nil)
		v := g.s.diskGuardStatus()
		if v.State != "unknown" || v.FreeBytes != nil {
			t.Fatalf("status: %+v", v)
		}
		data, err := json.Marshal(v)
		if err != nil || !strings.Contains(string(data), `"free_bytes":null`) {
			t.Fatalf("JSON: %s %v", data, err)
		}
	})
	t.Run("a full disk is not unknown", func(t *testing.T) {
		g := newGuardTest(t, "guard-full", allRunning(), nil)
		g.setFree(0)
		g.tick()
		g.wantCalls("0 bytes free", []string{"cowrie", "dionaea", "endlessh"}, nil)
	})
	t.Run("turned off while holding", func(t *testing.T) {
		g := newGuardTest(t, "guard-turned-off", allRunning(), nil)
		g.setFree(100)
		g.tick()
		g.wantCalls("low disk", []string{"cowrie", "dionaea", "endlessh"}, nil)
		cfg, err := g.s.loadConfigForChange()
		if err != nil {
			t.Fatal(err)
		}
		zero := int64(0)
		cfg.Cleanup.MinFreeMB = &zero
		if err := config.Save(cfg); err != nil {
			t.Fatal(err)
		}
		g.tick()
		g.wantCalls("guard turned off", nil, []string{"cowrie", "dionaea", "endlessh"})
		if got := g.file(); got != nil {
			t.Fatalf("state file: %v", got)
		}
	})
}

// TestDiskGuardCompanions: a honeypot whose front end is another service
// (tanner's snare) and one with cells (ssh-proxy) are stopped and started
// by their honeypot's name, never by a companion's.
func TestDiskGuardCompanions(t *testing.T) {
	states := map[string]string{"database": "running", "collector": "running", "netguard": "running",
		"tanner": "exited", "snare": "running", "tanner_api": "running", "tanner_phpox": "running", "tanner_redis": "running",
		"ssh-proxy": "running", "ssh-backend-1": "running", "ssh-backend-1-db": "running", "ssh-backend-1-backup": "running",
		"cowrie": "exited"}
	g := newGuardTest(t, "guard-companions", states, func(cfg *config.Config) {
		for _, name := range []string{"tanner", "ssh-proxy"} {
			hp, ok := cfg.Honeypots[name]
			if !ok {
				t.Fatalf("the default config has no %s", name)
			}
			hp.Enabled = true
			cfg.Honeypots[name] = hp
		}
	})
	g.setFree(100)
	g.tick()
	g.wantCalls("low disk", []string{"ssh-proxy", "tanner"}, nil)
	for svc := range states {
		if !diskGuardInfra[svc] && g.runner.state(svc) == "running" {
			t.Errorf("%s still runs", svc)
		}
	}
	if got := g.file(); !reflect.DeepEqual(got, []string{"ssh-proxy", "tanner"}) {
		t.Fatalf("state file lists %v", got)
	}
	// Cells that run without their broker take no connections: they are
	// stopped, and ssh-proxy is not the guard's to start afterwards.
	g2 := newGuardTest(t, "guard-cells-only", map[string]string{"database": "running", "collector": "running",
		"ssh-proxy": "exited", "ssh-backend-1": "running"}, func(cfg *config.Config) {
		hp := cfg.Honeypots["ssh-proxy"]
		hp.Enabled = true
		cfg.Honeypots["ssh-proxy"] = hp
	})
	g2.setFree(100)
	g2.tick()
	g2.wantCalls("cells without a broker", []string{"ssh-proxy"}, nil)
	if got := g2.file(); got != nil {
		t.Fatalf("state file lists %v for a broker that was not running", got)
	}
	g2.setFree(5000)
	g2.tick()
	g2.wantCalls("room again", nil, nil)

	g.setFree(5000)
	g.tick()
	g.wantCalls("room again", nil, []string{"ssh-proxy", "tanner"})
}

// TestDiskGuardBetweenMarksDropsWhatRunsAgain: a honeypot the guard stopped
// and someone else started again between the marks is no longer the
// guard's: if the operator then stops it, the guard does not start it.
func TestDiskGuardBetweenMarksDropsWhatRunsAgain(t *testing.T) {
	g := newGuardTest(t, "guard-reconcile", allRunning(), nil)
	g.setFree(100)
	g.tick()
	g.wantCalls("low disk", []string{"cowrie", "dionaea", "endlessh"}, nil)
	g.setFree(700)
	g.tick()
	// qpot up, or the web UI, starts cowrie between the marks.
	g.runner.setState("cowrie", "running")
	g.now = g.now.Add(diskGuardReconcileEvery)
	g.tick()
	g.wantCalls("between the marks", nil, nil)
	if got := g.file(); !reflect.DeepEqual(got, []string{"dionaea", "endlessh"}) {
		t.Fatalf("state file lists %v", got)
	}
	// The operator stops it again; the resume mark leaves it alone.
	g.runner.setState("cowrie", "exited")
	g.setFree(2000)
	g.tick()
	g.wantCalls("resume mark", nil, []string{"dionaea", "endlessh"})
	if g.runner.state("cowrie") != "exited" {
		t.Fatal("cowrie was started although the operator stopped it")
	}
}

// TestDiskGuardFailures: a stop that fails is tried again on the next tick;
// a start that fails stays on the list and is tried again later, not on
// every tick; with Docker unreachable nothing is forgotten.
func TestDiskGuardFailures(t *testing.T) {
	g := newGuardTest(t, "guard-failures", allRunning(), nil)
	g.setFree(100)
	g.runner.stopErr["dionaea"] = errors.New("docker: daemon busy")
	g.tick()
	g.wantCalls("first stop", []string{"cowrie", "dionaea", "endlessh"}, nil)
	if g.runner.state("dionaea") != "running" {
		t.Fatal("the fake stopped dionaea despite its error")
	}
	g.tick()
	g.wantCalls("second try", []string{"dionaea"}, nil)
	delete(g.runner.stopErr, "dionaea")
	g.tick()
	g.wantCalls("third try", []string{"dionaea"}, nil)

	// Docker does not answer while the disk is low: nothing changes.
	g.runner.statesErr = errors.New("docker compose ps: exit status 1")
	g.tick()
	g.wantCalls("docker down while low", nil, nil)
	if got := g.file(); len(got) != 3 {
		t.Fatalf("state file lists %v", got)
	}
	// Still down at the resume mark: nothing is started or forgotten.
	g.setFree(5000)
	g.tick()
	g.wantCalls("docker down at the resume mark", nil, nil)
	if got := g.file(); len(got) != 3 {
		t.Fatalf("state file lists %v", got)
	}
	g.runner.statesErr = nil
	// Not before the wait is over.
	g.tick()
	g.wantCalls("inside the wait", nil, nil)
	g.now = g.now.Add(diskGuardRetryFirst)
	g.runner.startErr["cowrie"] = errors.New("QP-RES-007: limits not enforced")
	g.tick()
	g.wantCalls("first start", nil, []string{"cowrie", "dionaea", "endlessh"})
	if got := g.file(); !reflect.DeepEqual(got, []string{"cowrie"}) {
		t.Fatalf("state file lists %v, want the one that did not start", got)
	}
	if v := g.s.diskGuardStatus(); v.State != "waiting" || len(v.Stopped) != 1 {
		t.Fatalf("status: %+v", v)
	}
	// The next ticks do not hammer Docker.
	for i := 0; i < 5; i++ {
		g.tick()
	}
	g.wantCalls("inside the second wait", nil, nil)
	delete(g.runner.startErr, "cowrie")
	g.now = g.now.Add(2 * diskGuardRetryFirst)
	g.tick()
	g.wantCalls("second start", nil, []string{"cowrie"})
	if got := g.file(); got != nil {
		t.Fatalf("state file: %v", got)
	}
}

// TestDiskGuardInstanceDown: when nothing of the instance runs at the
// resume mark, the operator stopped it; the guard starts nothing.
func TestDiskGuardInstanceDown(t *testing.T) {
	g := newGuardTest(t, "guard-down", allRunning(), nil)
	g.setFree(100)
	g.tick()
	g.wantCalls("low disk", []string{"cowrie", "dionaea", "endlessh"}, nil)
	for _, svc := range []string{"database", "collector", "netguard"} {
		g.runner.setState(svc, "exited")
	}
	g.setFree(5000)
	g.tick()
	g.wantCalls("instance down", nil, nil)
	if got := g.file(); got != nil {
		t.Fatalf("state file: %v", got)
	}
}

// TestDiskGuardStateFileUnwritable: when the state cannot be written (the
// disk is full), the honeypots are stopped all the same, and the file is
// written once it can be.
func TestDiskGuardStateFileUnwritable(t *testing.T) {
	g := newGuardTest(t, "guard-unwritable", allRunning(), nil)
	// A folder where the file belongs: no write can replace it.
	path := diskguard.Path(g.cfg.DataPath)
	if err := os.MkdirAll(filepath.Join(path, "in-the-way"), 0o700); err != nil {
		t.Fatal(err)
	}
	g.setFree(100)
	g.tick()
	g.wantCalls("low disk, state not writable", []string{"cowrie", "dionaea", "endlessh"}, nil)
	if v := g.s.diskGuardStatus(); v.State != "low" || len(v.Stopped) != 3 {
		t.Fatalf("status: %+v", v)
	}
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	g.tick()
	if got := g.file(); len(got) != 3 {
		t.Fatalf("the state was not written once it could be: %v", got)
	}
}

// TestCheckDiskSpace: qpot up is refused with QP-RES-008 below the floor,
// and only then.
func TestCheckDiskSpace(t *testing.T) {
	orig := diskFreeBytes
	defer func() { diskFreeBytes = orig }()
	var asked string
	set := func(mb int64, known bool) {
		diskFreeBytes = func(path string) (int64, bool) { asked = path; return mb * guardMB, known }
	}
	cfg := config.Default("up-disk")
	cfg.DataPath = t.TempDir()

	set(511, true)
	err := CheckDiskSpace(cfg)
	var coded *hostsetup.Error
	if !errors.As(err, &coded) || coded.Code != "QP-RES-008" {
		t.Fatalf("below the floor: %v, want QP-RES-008", err)
	}
	if hostsetup.ExitStatus(coded.Code) != 18 {
		t.Errorf("exit status %d, want the RES category's 18", hostsetup.ExitStatus(coded.Code))
	}
	if why := coded.Cause(); !strings.Contains(why, "511 MB") || !strings.Contains(why, "512") || !strings.Contains(why, cfg.DataPath) {
		t.Errorf("the cause does not say how much is free and needed: %q", why)
	}
	if !strings.Contains(coded.Remedy(), "qpot cleanup") {
		t.Errorf("the fix does not name qpot cleanup: %q", coded.Remedy())
	}
	if want := filepath.Join(cfg.DataPath, "honeypots"); asked != want {
		t.Errorf("free space read of %s, want %s", asked, want)
	}
	set(0, true)
	if err := CheckDiskSpace(cfg); !errors.As(err, &coded) || coded.Code != "QP-RES-008" {
		t.Fatalf("full disk: %v, want QP-RES-008", err)
	}

	// Allowed: at the floor, between the marks, unknown, guard off.
	for _, c := range []struct {
		name  string
		mb    int64
		known bool
		off   bool
	}{
		{"exactly the floor", 512, true, false},
		{"between the marks", 800, true, false},
		{"plenty", 90000, true, false},
		{"unknown", 0, false, false},
		{"guard off, full disk", 0, true, true},
	} {
		set(c.mb, c.known)
		cc := config.Default("up-disk")
		cc.DataPath = cfg.DataPath
		if c.off {
			zero := int64(0)
			cc.Cleanup.MinFreeMB = &zero
		}
		if err := CheckDiskSpace(cc); err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
		}
	}
	// The operator's own floor counts.
	set(1500, true)
	custom := config.Default("up-disk")
	custom.DataPath = cfg.DataPath
	two := int64(2048)
	custom.Cleanup.MinFreeMB, custom.Cleanup.ResumeFreeMB = &two, 4096
	if err := CheckDiskSpace(custom); !errors.As(err, &coded) || coded.Code != "QP-RES-008" {
		t.Fatalf("below a floor of 2048: %v", err)
	}
}

// TestStatusCarriesDiskGuard: GET /api/status has the disk_guard field in
// its documented shape.
func TestStatusCarriesDiskGuard(t *testing.T) {
	runningDockerOnPath(t)
	g := newGuardTest(t, "guard-status", allRunning(), nil)
	mgr, err := instance.NewManager(g.cfg)
	if err != nil {
		t.Fatal(err)
	}
	g.s.manager = mgr
	read := func() map[string]any {
		t.Helper()
		rec := g.do(http.MethodGet, "/api/status", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/status: %d %s", rec.Code, rec.Body.String())
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"instance", "overall", "honeypots", "database", "disk_guard"} {
			if _, ok := body[k]; !ok {
				t.Fatalf("status has no %q: %s", k, rec.Body.String())
			}
		}
		var dg map[string]any
		if err := json.Unmarshal(body["disk_guard"], &dg); err != nil {
			t.Fatal(err)
		}
		return dg
	}
	keys := func(m map[string]any) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	dg := read()
	if want := []string{"checked_at", "free_bytes", "min_free_bytes", "reserve_bytes", "resume_free_bytes", "state", "stopped"}; !reflect.DeepEqual(keys(dg), want) {
		t.Fatalf("disk_guard keys %v, want %v", keys(dg), want)
	}
	if dg["state"] != "ok" || dg["min_free_bytes"] != float64(512*guardMB) || dg["resume_free_bytes"] != float64(1024*guardMB) {
		t.Fatalf("disk_guard: %v", dg)
	}
	if list, ok := dg["stopped"].([]any); !ok || len(list) != 0 {
		t.Fatalf("stopped is %v, want an empty list", dg["stopped"])
	}

	g.setFree(100)
	g.tick()
	dg = read()
	if want := []string{"checked_at", "code", "free_bytes", "min_free_bytes", "reserve_bytes", "resume_free_bytes", "state", "stopped"}; !reflect.DeepEqual(keys(dg), want) {
		t.Fatalf("disk_guard keys %v, want %v", keys(dg), want)
	}
	if dg["state"] != "low" || dg["code"] != "QP-RES-008" || dg["free_bytes"] != float64(100*guardMB) {
		t.Fatalf("disk_guard: %v", dg)
	}
	list, _ := dg["stopped"].([]any)
	if len(list) != 3 {
		t.Fatalf("stopped: %v", dg["stopped"])
	}
	first, _ := list[0].(map[string]any)
	if !reflect.DeepEqual(keys(first), []string{"name", "stopped_at"}) || first["name"] != "cowrie" {
		t.Fatalf("stopped[0]: %v", first)
	}
	if _, err := time.Parse(time.RFC3339, first["stopped_at"].(string)); err != nil {
		t.Fatalf("stopped_at: %v", err)
	}
}

// TestDiskGuardLoopStops: the loop ticks at once and ends with its context.
func TestDiskGuardLoopStops(t *testing.T) {
	g := newGuardTest(t, "guard-loop", allRunning(), nil)
	g.setFree(100)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.s.diskGuardLoop(ctx); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for g.runner.state("cowrie") == "running" {
		if time.Now().After(deadline) {
			t.Fatal("the loop did not stop the honeypots on its first tick")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the loop did not end with its context")
	}
}

// TestDiskGuardFullDiskStopsBeforeCleanup: on a disk with hardly anything
// left, the honeypots are stopped before cleanup runs, not after it. Cleanup
// may then free enough to stay above the floor, but below the resume mark the
// honeypots stay stopped.
func TestDiskGuardFullDiskStopsBeforeCleanup(t *testing.T) {
	g := newGuardTest(t, "guard-full", allRunning(), nil)
	old := oldCapture(t, g.apiTestServer)
	var stoppedWhileCaptureWasThere bool
	// Nothing is free while the old capture is on the disk; cleanup, which
	// deletes it, brings back 700 MB: above the floor, below the resume mark.
	g.freeFn = func() int64 {
		if _, err := os.Stat(old); err == nil {
			return 0
		}
		return 700
	}
	g.runner.onStop = func() {
		if _, err := os.Stat(old); err == nil {
			stoppedWhileCaptureWasThere = true
		}
	}
	g.tick()
	if !stoppedWhileCaptureWasThere {
		t.Fatal("the honeypots were not stopped before cleanup ran")
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("cleanup did not run after the stop: %v", err)
	}
	g.wantCalls("full disk", []string{"cowrie", "dionaea", "endlessh"}, nil)
	if v := g.s.diskGuardStatus(); v.State != "waiting" || len(v.Stopped) != 3 {
		t.Fatalf("status after cleanup freed some room: %+v", v)
	}
	// Still below the resume mark: nothing is started.
	g.tick()
	g.wantCalls("between the marks", nil, nil)
	g.freeFn = func() int64 { return 3000 }
	g.tick()
	g.wantCalls("room again", nil, []string{"cowrie", "dionaea", "endlessh"})

	// Control: just below the floor, cleanup comes first and no honeypot is
	// stopped when it frees enough (TestDiskGuardCleanupRecovers); here the
	// threshold itself.
	on := diskguard.FromMB(512, 1024)
	for _, c := range []struct {
		freeMB int64
		known  bool
		want   bool
	}{{0, true, true}, {127, true, true}, {128, true, false}, {400, true, false}, {0, false, false}} {
		if got := diskGuardUrgent(on, diskguard.Reading{Free: c.freeMB * guardMB, Known: c.known}); got != c.want {
			t.Errorf("urgent at %d MB (known %v) = %v, want %v", c.freeMB, c.known, got, c.want)
		}
	}
	if diskGuardUrgent(diskguard.FromMB(0, 0), diskguard.Reading{Free: 0, Known: true}) {
		t.Error("a guard that is off is never urgent")
	}
}

// The guard keeps a reserve file while there is room for it and frees it
// first when the disk runs low, before cleanup and before any honeypot is
// stopped: a honeypot that could not write its log can again at once.
func TestDiskGuardReserve(t *testing.T) {
	g := newGuardTest(t, "guard-reserve", allRunning(), func(cfg *config.Config) {
		one := int64(1)
		cfg.Cleanup.ReserveMB = &one
	})
	reserve := diskGuardReservePath(g.cfg)
	size := func() int64 { return diskReserveSize(reserve) }

	// Not enough room above the resume mark for it: none is written.
	g.setFree(1024)
	g.tick()
	if size() != 0 {
		t.Fatalf("a reserve of %d bytes was written with exactly the resume mark free", size())
	}
	g.setFree(50000)
	g.tick()
	if size() != guardMB {
		t.Fatalf("reserve file is %d bytes, want %d", size(), guardMB)
	}
	if v := g.s.diskGuardStatus(); v.ReserveBytes != guardMB || v.State != "ok" {
		t.Fatalf("status with a reserve: %+v", v)
	}
	data, err := os.ReadFile(reserve)
	if err != nil || bytes.Count(data, []byte{0}) > len(data)/8 {
		t.Fatalf("the reserve must hold bytes no filesystem stores as nothing: %v, %d zero bytes of %d", err, bytes.Count(data, []byte{0}), len(data))
	}
	g.wantCalls("plenty of room", nil, nil)

	// The disk runs low and is not full: a honeypot can still write, so the
	// reserve is kept for the moment it cannot, and goes once the honeypots
	// are stopped, for the collector and the database.
	var reserveAtStop int64 = -1
	g.runner.onStop = func() {
		if reserveAtStop < 0 {
			reserveAtStop = size()
		}
	}
	g.setFree(100)
	g.tick()
	g.wantCalls("low", []string{"cowrie", "dionaea", "endlessh"}, nil)
	if reserveAtStop != guardMB || size() != 0 {
		t.Fatalf("the reserve was %d bytes when the first honeypot was stopped and is %d now; want it kept until they are stopped, then freed", reserveAtStop, size())
	}
	if v := g.s.diskGuardStatus(); v.ReserveBytes != 0 {
		t.Fatalf("status while low: %+v", v)
	}
	// Between the marks nothing is started and no reserve is written.
	g.setFree(800)
	g.tick()
	if size() != 0 {
		t.Fatal("a reserve was written while honeypots are stopped")
	}
	// Room again: the honeypots start and the reserve comes back.
	g.setFree(50000)
	g.tick()
	g.wantCalls("room again", nil, []string{"cowrie", "dionaea", "endlessh"})
	g.tick()
	if size() != guardMB {
		t.Fatalf("reserve after recovery is %d bytes, want %d", size(), guardMB)
	}

	// Turned off in the config: the file goes.
	none := int64(0)
	g.cfg.Cleanup.ReserveMB = &none
	if err := config.Save(g.cfg); err != nil {
		t.Fatal(err)
	}
	g.tick()
	if size() != 0 {
		t.Fatal("the reserve file stayed after cleanup.reserve_mb was set to 0")
	}
}

// The reserve is for the lines a honeypot holds when the disk is full. Freed
// while something still fills the disk, the writer takes it too: the guard
// frees it when the disk is full and has stopped filling, and it does so
// while it is busy stopping the honeypots, which is when they write.
func TestDiskGuardReserveWaitsForAFullDisk(t *testing.T) {
	g := newGuardTest(t, "guard-reserve-full", allRunning(), func(cfg *config.Config) {
		one := int64(1)
		cfg.Cleanup.ReserveMB = &one
	})
	reserve := diskGuardReservePath(g.cfg)
	g.tick()
	if diskReserveSize(reserve) != guardMB {
		t.Fatal("no reserve after the first tick")
	}

	// Low, and still filling: every look finds less than the one before,
	// down to nothing, where it stays. The first honeypot takes as long to
	// stop as Cowrie does when it waits for room.
	looks := 0
	g.mu.Lock()
	g.freeFn = func() int64 {
		looks++
		return max(0, 15-int64(looks))
	}
	g.mu.Unlock()
	looksWhenFreed, freedDuringStop := 0, false
	g.runner.onStop = func() {
		if looksWhenFreed != 0 {
			return
		}
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if diskReserveSize(reserve) == 0 {
				g.mu.Lock()
				looksWhenFreed, freedDuringStop = looks, true
				g.mu.Unlock()
				return
			}
		}
		looksWhenFreed = -1
	}
	g.tick()
	g.wantCalls("filling", []string{"cowrie", "dionaea", "endlessh"}, nil)
	if !freedDuringStop {
		t.Fatal("the reserve was not freed while the honeypots were being stopped on a full disk")
	}
	// 15 looks find the disk still filling (14 MB down to 0); the reserve
	// may go at the second look that finds it full, not before.
	if looksWhenFreed < 16 {
		t.Fatalf("the reserve was freed at look %d, while the disk was still being filled", looksWhenFreed)
	}
}

// watchDiskReserve by itself: nothing while there is room, nothing while the
// free space falls or cannot be read, the reserve when the disk stays full.
func TestWatchDiskReserve(t *testing.T) {
	dir := t.TempDir()
	reserve := filepath.Join(dir, diskGuardReserveName)
	write := func() {
		t.Helper()
		if err := keepDiskReserve(reserve, 4096); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	free, known := int64(1<<30), true
	set := func(n int64, k bool) { mu.Lock(); free, known = n, k; mu.Unlock() }
	read := func(string) (int64, bool) { mu.Lock(); defer mu.Unlock(); return free, known }
	wait := 4 * diskGuardSettleEvery

	write()
	stop := watchDiskReserve(context.Background(), read, dir, reserve)
	time.Sleep(wait)
	if diskReserveSize(reserve) == 0 {
		t.Fatal("freed with a gigabyte of room")
	}
	set(diskGuardFullBytes, true) // exactly the mark is not below it
	time.Sleep(wait)
	if diskReserveSize(reserve) == 0 {
		t.Fatal("freed at the mark, not below it")
	}
	set(0, false)
	time.Sleep(wait)
	if diskReserveSize(reserve) == 0 {
		t.Fatal("freed when the free space could not be read")
	}
	set(0, true)
	for deadline := time.Now().Add(5 * time.Second); diskReserveSize(reserve) != 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("not freed on a disk that stays full")
		}
	}
	stop()

	// Ending the watch ends it: a disk that fills afterwards frees nothing.
	write()
	set(1<<30, true)
	stop = watchDiskReserve(context.Background(), read, dir, reserve)
	stop()
	set(0, true)
	time.Sleep(wait)
	if diskReserveSize(reserve) == 0 {
		t.Fatal("freed after the watch was ended")
	}
}

// Between two full ticks the guard only reads the free space. A disk that
// falls below the floor makes the next full tick due at once; the reserve is
// that tick's to free.
func TestDiskGuardWatch(t *testing.T) {
	g := newGuardTest(t, "guard-watch", allRunning(), func(cfg *config.Config) {
		one := int64(1)
		cfg.Cleanup.ReserveMB = &one
	})
	reserve := diskGuardReservePath(g.cfg)
	if !g.s.diskGuardDue(g.now) {
		t.Fatal("no full tick was due before the first one")
	}
	g.tick()
	if diskReserveSize(reserve) != guardMB {
		t.Fatal("no reserve after the first tick")
	}
	soon := g.now.Add(diskGuardWatchEvery)
	if g.s.diskGuardDue(soon) {
		t.Fatal("a full tick is due a second after the last, with plenty of room")
	}
	// Unknown free space is no reason to act.
	g.mu.Lock()
	g.known = false
	g.mu.Unlock()
	g.setFree(0)
	if g.s.diskGuardDue(soon) {
		t.Fatal("an unreadable disk made a tick due")
	}
	g.mu.Lock()
	g.known = true
	g.mu.Unlock()

	// Below the floor, not yet urgent: a tick is due, the reserve is the
	// tick's to free.
	g.setFree(300)
	if !g.s.diskGuardDue(soon) || diskReserveSize(reserve) != guardMB {
		t.Fatalf("300 MB free: due and reserve kept expected; reserve is %d bytes", diskReserveSize(reserve))
	}
	// Hardly anything left: a tick is due, and it frees the reserve.
	g.setFree(0)
	if !g.s.diskGuardDue(soon) {
		t.Fatal("a full disk did not make a tick due")
	}
	g.now = soon.Add(-diskGuardEvery) // tick() adds it back
	g.tick()
	g.wantCalls("full", []string{"cowrie", "dionaea", "endlessh"}, nil)
	if diskReserveSize(reserve) != 0 {
		t.Fatal("the reserve was not freed by the tick that found the disk full")
	}

	// With the honeypots stopped nothing is urgent: the next look waits for
	// the ordinary interval.
	if g.s.diskGuardDue(g.now.Add(diskGuardWatchEvery)) {
		t.Fatal("a tick is due every second while the honeypots are already stopped")
	}
	if !g.s.diskGuardDue(g.now.Add(diskGuardEvery)) {
		t.Fatal("no tick due after the ordinary interval")
	}
}
