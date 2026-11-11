package doctor

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/hostsetup"
	"github.com/qpot/qpot/internal/instance"
)

func listenLocal(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln, ln.Addr().(*net.TCPAddr).Port
}

// TestDockerChecksReportResourceLimits: Docker accepts a limit it cannot apply
// and drops it (swap without a cgroup for dockerd, memory on Raspberry Pi OS),
// so doctor says which ones honeypots can exceed.
func TestDockerChecksReportResourceLimits(t *testing.T) {
	up := hostsetup.DockerState{CLI: true, DaemonUp: true, Server: hostsetup.MinEngine, Compose: true, ComposeVersion: hostsetup.MinCompose}
	find := func(cs []Check) *Check {
		for i := range cs {
			if cs[i].Name == "resource limits" {
				return &cs[i]
			}
		}
		return nil
	}
	none := func() int64 { return 0 }
	nofree := func(string) int64 { return 0 }
	if c := find(DockerChecks(up, none, nofree)); c != nil {
		t.Fatalf("unknown limits reported: %+v", c)
	}
	st := up
	st.Limits = &hostsetup.CgroupLimits{Memory: true, Swap: true, Pids: true, CPU: true}
	if c := find(DockerChecks(st, none, nofree)); c == nil || c.Level != "ok" {
		t.Fatalf("all limits: %+v", c)
	}
	st.Limits = &hostsetup.CgroupLimits{Pids: true, CPU: true}
	c := find(DockerChecks(st, none, nofree))
	if c == nil || c.Level != "warn" || c.Code != "QP-RES-006" || !strings.Contains(c.Detail, "memory, swap limits") {
		t.Fatalf("missing memory and swap: %+v", c)
	}
	if FirstFailCode(DockerChecks(st, none, nofree)) != "" {
		t.Fatal("a limits warning must not stop setup")
	}
	down := st
	down.DaemonUp = false
	if c := find(DockerChecks(down, none, nofree)); c != nil {
		t.Fatalf("limits reported for a daemon that is down: %+v", c)
	}
}

// A web UI held by something else (e.g. another instance) must not pass the
// health check.
func TestWebUICheckRequiresThisInstance(t *testing.T) {
	cfg := config.Default("mine")
	cfg.QPotID = "qp_aaaaaaaaaaaaaaaaaaaaaaaa"
	cfg.WebUI.BindAddr = "127.0.0.1"

	serve := func(h http.HandlerFunc) {
		ln, port := listenLocal(t)
		srv := &http.Server{Handler: h}
		go srv.Serve(ln)
		t.Cleanup(func() { srv.Close() })
		cfg.WebUI.Port = port
	}

	serve(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-QPot-ID") != cfg.QPotID {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"instance":"mine"}`))
	})
	if c := WebUICheck(context.Background(), cfg); c.Level != "ok" {
		t.Fatalf("own web UI: %+v", c)
	}

	// Another instance: rejects our QPot ID.
	serve(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	if c := WebUICheck(context.Background(), cfg); c.Level != "fail" {
		t.Fatalf("foreign web UI passed: %+v", c)
	}
	// Some other HTTP service entirely.
	serve(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>hi</html>")) })
	if c := WebUICheck(context.Background(), cfg); c.Level != "fail" {
		t.Fatalf("unrelated HTTP service passed: %+v", c)
	}
}

func TestGeoIPCheck(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{InstanceName: "t", DataPath: dir}
	if c := GeoIPCheck(cfg); c.Name != "" {
		t.Errorf("no database configured: want no check, got %+v", c)
	}
	cfg.Collector.GeoIPDBPath = "/data/geoip/db.mmdb"
	if c := GeoIPCheck(cfg); c.Level != "fail" {
		t.Errorf("missing file: %+v", c)
	}
	if err := os.MkdirAll(filepath.Join(dir, "geoip"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "geoip", "db.mmdb"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if c := GeoIPCheck(cfg); c.Level != "ok" {
		t.Errorf("present file: %+v", c)
	}
}

type sandboxDoctorObservation struct {
	status instance.SandboxStatus
	err    error
}

func (*sandboxDoctorObservation) ServiceStates(context.Context) (map[string]instance.ServiceState, error) {
	return map[string]instance.ServiceState{}, nil
}
func (o *sandboxDoctorObservation) SandboxStatus(context.Context) (instance.SandboxStatus, error) {
	return o.status, o.err
}

type sandboxDoctorWithoutObservation struct{}

func (sandboxDoctorWithoutObservation) ServiceStates(context.Context) (map[string]instance.ServiceState, error) {
	return map[string]instance.ServiceState{}, nil
}

func TestSandboxCheckRequiresObservedRuntime(t *testing.T) {
	for _, tt := range []struct {
		name                string
		status              instance.SandboxStatus
		err                 error
		level, code, detail string
	}{
		{name: "actual gVisor", status: instance.SandboxStatus{Runtime: "runsc", Verified: true, Services: map[string]string{"cowrie": "runsc"}}, level: "ok", detail: `verified runtime "runsc"`},
		{name: "explicit none with mixed runtimes", status: instance.SandboxStatus{Runtime: "mixed", Verified: true, Services: map[string]string{"cowrie": "runc", "conpot": "runsc"}}, level: "ok", detail: `verified runtimes "runc", "runsc"`},
		{name: "actual standard Docker", status: instance.SandboxStatus{Runtime: "runc", Verified: true, Services: map[string]string{"cowrie": "runc"}}, level: "ok", detail: `verified runtime "runc"`},
		{name: "explicit fallback", status: instance.SandboxStatus{Requested: "gvisor", Runtime: "runc", Fallback: true, Verified: true, Services: map[string]string{"cowrie": "runc"}}, level: "warn", code: "QP-DOCKER-011", detail: "explicit Docker fallback"},
		{name: "capability without observation", status: instance.SandboxStatus{Runtime: "runsc"}, level: "fail", code: "QP-DOCKER-011", detail: "no running honeypot"},
		{name: "missing runtime", status: instance.SandboxStatus{Verified: true, Services: map[string]string{"cowrie": ""}}, level: "fail", code: "QP-DOCKER-011", detail: "no running honeypot"},
		{name: "unobserved service runtime", status: instance.SandboxStatus{Runtime: "runsc", Verified: true, Services: map[string]string{"cowrie": ""}}, level: "fail", code: "QP-DOCKER-011", detail: "no running honeypot"},
		{name: "missing services", status: instance.SandboxStatus{Runtime: "runsc", Verified: true}, level: "fail", code: "QP-DOCKER-011", detail: "no running honeypot"},
		{name: "unavailable", err: hostsetup.E("QP-DOCKER-011").Wrap(errors.New("private diagnostics")), level: "fail", code: "QP-DOCKER-011"},
		{name: "mismatch", status: instance.SandboxStatus{Runtime: "runc", Services: map[string]string{"cowrie": "runc"}}, err: hostsetup.E("QP-DOCKER-012").Wrap(errors.New("private diagnostics")), level: "fail", code: "QP-DOCKER-012", detail: `observed runtime "runc"`},
		{name: "bad policy", err: hostsetup.E("QP-DOCKER-010").Wrap(errors.New("private diagnostics")), level: "fail", code: "QP-DOCKER-010"},
		{name: "uncoded observation failure", err: errors.New("private diagnostics"), level: "fail", code: "QP-DOCKER-011"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := sandboxCheck(t.Context(), config.Default("isolation"), &sandboxDoctorObservation{status: tt.status, err: tt.err})
			if got.Name != "honeypot isolation" || got.Level != tt.level || got.Code != tt.code || !strings.Contains(got.Detail, tt.detail) || strings.Contains(got.Detail, "private diagnostics") {
				t.Fatalf("unexpected isolation check: %+v", got)
			}
		})
	}
	if got := sandboxCheck(t.Context(), config.Default("isolation"), sandboxDoctorWithoutObservation{}); got.Level != "fail" || got.Code != "QP-DOCKER-011" {
		t.Fatalf("missing observer falsely passed: %+v", got)
	}
	cfg := config.Default("no-honeypots")
	cfg.Honeypots = map[string]config.HoneypotConfig{}
	if got := sandboxCheck(t.Context(), cfg, sandboxDoctorWithoutObservation{}); got.Level != "ok" || !strings.Contains(got.Detail, "no enabled honeypots") {
		t.Fatalf("no-honeypot deployment requires unrelated runtime: %+v", got)
	}
}

func TestHealthChecksIncludeSandboxObservation(t *testing.T) {
	cfg := config.Default("health-isolation")
	cfg.Honeypots = map[string]config.HoneypotConfig{"ddospot": {Enabled: true}}
	cfg.WebUI.Enabled = false
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // Keep unrelated database inspection local, bounded and offline.
	checks := HealthChecks(ctx, cfg, &sandboxDoctorObservation{status: instance.SandboxStatus{Runtime: "runsc", Verified: true, Services: map[string]string{"ddospot": "runsc"}}}, nil)
	for _, check := range checks {
		if check.Name == "honeypot isolation" {
			if check.Level != "ok" || !strings.Contains(check.Detail, `"runsc"`) {
				t.Fatalf("incorrect isolation result: %+v", check)
			}
			return
		}
	}
	t.Fatal("health report omitted the actual isolation observation")
}

func TestSandboxCheckInspectsRunningOrphans(t *testing.T) {
	cfg := config.Default("orphaned-isolation")
	cfg.Honeypots = map[string]config.HoneypotConfig{}
	observer := &sandboxDoctorObservation{
		status: instance.SandboxStatus{Requested: "gvisor", Runtime: "runc", Services: map[string]string{"cowrie": "runc"}},
		err:    hostsetup.E("QP-DOCKER-012").Wrap(errors.New("private orphan diagnostics")),
	}
	got := sandboxCheck(t.Context(), cfg, observer)
	if got.Level != "fail" || got.Code != "QP-DOCKER-012" || !strings.Contains(got.Detail, `observed runtime "runc"`) || strings.Contains(got.Detail, "private orphan diagnostics") {
		t.Fatalf("disabled configuration hid a running container runtime mismatch: %+v", got)
	}
	observer.err = nil
	observer.status = instance.SandboxStatus{Requested: "none", Runtime: "runc", Verified: true, Services: map[string]string{"cowrie": "runc"}}
	cfg.Security.SandboxMode = "none"
	if got := sandboxCheck(t.Context(), cfg, observer); got.Level != "ok" || !strings.Contains(got.Detail, `verified runtime "runc"`) {
		t.Fatalf("explicit ordinary-Docker orphan was not observed: %+v", got)
	}
	observer.status.Verified = false
	if got := sandboxCheck(t.Context(), cfg, observer); got.Level != "fail" || got.Code != "QP-DOCKER-011" {
		t.Fatalf("unverified running orphan passed isolation: %+v", got)
	}
	observer.status = instance.SandboxStatus{Services: map[string]string{}}
	if got := sandboxCheck(t.Context(), cfg, observer); got.Level != "ok" || !strings.Contains(got.Detail, "no enabled or running honeypots") {
		t.Fatalf("empty deployment needs unrelated runtime: %+v", got)
	}

}

// TestContainmentChecks: the doctor names a setting that removes containment,
// a web UI without a login, and files that still carry the QPot ID.
func TestContainmentChecks(t *testing.T) {
	newCfg := func(t *testing.T) *config.Config {
		cfg := config.Default("contain")
		cfg.QPotID = "qp_abcdefghijklmnopqrstuvwx"
		cfg.DataPath = t.TempDir()
		for name, hp := range cfg.Honeypots {
			hp.Enabled = name == "cowrie"
			cfg.Honeypots[name] = hp
		}
		return cfg
	}
	level := func(cs []Check, name string) (string, string) {
		for _, c := range cs {
			if c.Name == name {
				return c.Level, c.Code
			}
		}
		return "missing", ""
	}
	marker := func(t *testing.T, cfg *config.Config) {
		if err := os.WriteFile(filepath.Join(cfg.DataPath, ".backup-credential-scrubbed"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("a healthy instance", func(t *testing.T) {
		cfg := newCfg(t)
		marker(t, cfg)
		for _, c := range ContainmentChecks(cfg) {
			if c.Level != "ok" {
				t.Errorf("%s: %s %s (%s)", c.Name, c.Level, c.Detail, c.Code)
			}
		}
		if !instance.BackupsScrubbed(cfg) {
			t.Fatal("the marker name in this test is not the one the scrub writes")
		}
	})
	t.Run("egress guard off with a sensitive honeypot", func(t *testing.T) {
		cfg := newCfg(t)
		hp := cfg.Honeypots["dionaea"]
		hp.Enabled = true
		cfg.Honeypots["dionaea"] = hp
		cfg.Security.NetworkIsolation.AllowPrivateEgress = true
		if l, code := level(ContainmentChecks(cfg), "containment settings"); l != "fail" || code != "QP-INST-015" {
			t.Errorf("containment settings: %s %s", l, code)
		}
	})
	t.Run("web UI without a login", func(t *testing.T) {
		cfg := newCfg(t)
		cfg.WebUI.QPotIDAuth = false
		cfg.WebUI.Password = ""
		if l, _ := level(ContainmentChecks(cfg), "web UI login"); l != "warn" {
			t.Errorf("on loopback: %s, want warn", l)
		}
		cfg.WebUI.BindAddr = "0.0.0.0"
		if l, code := level(ContainmentChecks(cfg), "web UI login"); l != "fail" || code != "QP-WEB-005" {
			t.Errorf("on 0.0.0.0: %s %s, want fail QP-WEB-005", l, code)
		}
	})
	t.Run("files an earlier version wrote", func(t *testing.T) {
		cfg := newCfg(t)
		if l, code := level(ContainmentChecks(cfg), "QPot ID in stored files"); l != "warn" || code != "QP-INST-016" {
			t.Errorf("backups not checked yet: %s %s, want warn QP-INST-016", l, code)
		}
		marker(t, cfg)
		if err := os.WriteFile(filepath.Join(cfg.DataPath, "vector.yaml"), []byte("# QPot ID: "+cfg.QPotID+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cs := ContainmentChecks(cfg)
		if l, code := level(cs, "QPot ID in stored files"); l != "fail" || code != "QP-INST-016" {
			t.Errorf("old vector.yaml: %s %s, want fail QP-INST-016", l, code)
		}
		for _, c := range cs {
			if strings.Contains(c.Detail, cfg.QPotID) {
				t.Errorf("check %q prints the QPot ID", c.Name)
			}
		}
	})
}
