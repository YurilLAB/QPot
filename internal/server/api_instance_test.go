package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/hostsetup"
	"github.com/qpot/qpot/internal/instance"
	"github.com/qpot/qpot/internal/intelligence"
)

// downDB is a database that no longer answers.
type downDB struct{ fakeDB }

func (d *downDB) Ping(context.Context) error {
	return errors.New("dial tcp 127.0.0.1:19000: connection refused")
}

func TestInstanceInfo(t *testing.T) {
	a := newAPITestServer(t, "api-instance", func(c *config.Config) {
		c.EnableHoneypot("cowrie")
		c.Collector.GeoIPDBPath = "/data/geoip/dbip-country-lite.mmdb"
		c.AttackMap.Country = "AU"
		c.Database.Type = "clickhouse"
	})
	assertAuthRequired(t, a.h, http.MethodGet, "/api/instance", "")
	if rec := a.do(http.MethodPost, "/api/instance", `{}`); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rec.Code)
	}

	a.s.database = &fakeDB{}
	a.runner.states = map[string]instance.ServiceState{
		"database": {State: "running", Health: "healthy"}, "cowrie": {State: "running"}, "collector": {State: "exited"},
	}
	geoDir := filepath.Join(a.cfg.DataPath, "geoip")
	if err := os.MkdirAll(geoDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(geoDir, "dbip-country-lite.mmdb"), []byte("mmdb"), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := a.do(http.MethodGet, "/api/instance", "")
	var info instanceInfo
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &info) != nil {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body.String())
	}
	if info.Name != "api-instance" || info.Status != "running" || info.WebUI["auth"] != "qpot-id" {
		t.Fatalf("instance: %+v", info)
	}
	var cowrie *instanceHoneypot
	for i := range info.Honeypots {
		if info.Honeypots[i].Name == "cowrie" {
			cowrie = &info.Honeypots[i]
		}
		if !info.Honeypots[i].Enabled && len(info.Honeypots[i].HostPorts) != 0 {
			t.Errorf("%s is off but lists host ports", info.Honeypots[i].Name)
		}
	}
	if cowrie == nil || !cowrie.Enabled || cowrie.Description == "" || !cowrie.HasSettings || len(cowrie.HostPorts) != 2 ||
		cowrie.HostPorts[0].ContainerPort != 22 || cowrie.HostPorts[1].ContainerPort != 23 || cowrie.HostPorts[0].HostPort == 0 {
		t.Fatalf("cowrie: %+v", cowrie)
	}
	if len(info.Services) != 3 || info.Services[0].Name != "collector" || info.Services[0].State != "exited" {
		t.Fatalf("services: %+v", info.Services)
	}
	if !info.Database.Connected || !info.Database.Healthy || info.Database.SchemaVersion != 1 || info.Database.Type != "clickhouse" {
		t.Fatalf("database: %+v", info.Database)
	}
	if !info.GeoIP.Configured || !info.GeoIP.Present || info.GeoIP.File != "dbip-country-lite.mmdb" || info.GeoIP.Updated == nil ||
		info.GeoIP.SizeBytes != 4 || info.GeoIP.UpdateCommand != "qpot geoip update -i api-instance" {
		t.Fatalf("geoip: %+v", info.GeoIP)
	}
	if info.AttackMap["country"] != "AU" || info.Cluster["clustered"] != false {
		t.Fatalf("map %v cluster %v", info.AttackMap, info.Cluster)
	}

	// Database down, Docker not answering, GeoIP file gone.
	a.s.database = &downDB{}
	a.runner.states, a.runner.statesErr = nil, errors.New("Cannot connect to the Docker daemon at unix:///var/run/docker.sock")
	if err := os.Remove(filepath.Join(geoDir, "dbip-country-lite.mmdb")); err != nil {
		t.Fatal(err)
	}
	rec = a.do(http.MethodGet, "/api/instance", "")
	info = instanceInfo{}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &info) != nil {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body.String())
	}
	if info.Status != "unknown" || info.ServicesError == "" || len(info.Services) != 0 ||
		!info.Database.Connected || info.Database.Healthy || info.Database.Error == "" ||
		info.GeoIP.Present || !info.GeoIP.Configured {
		t.Fatalf("degraded: %+v", info)
	}
	for _, leak := range []string{"docker.sock", "19000", "connection refused"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("internal detail %q in the answer", leak)
		}
	}
}

// A configured URL is shown without anything that can carry a credential.
func TestPublicOrigin(t *testing.T) {
	secret := strings.Repeat("s3", 8)
	for in, want := range map[string]string{
		"https://canary.example.net":                                    "https://canary.example.net",
		"https://canary.example.net/c":                                  "https://canary.example.net/c",
		"http://u:" + secret + "@canary.example.net:8443/c?k=" + secret: "http://canary.example.net:8443/c",
		"https://canary.example.net/#" + secret:                         "https://canary.example.net/",
		"ftp://canary.example.net":                                      "",
		"javascript:alert(1)":                                           "",
		"":                                                              "",
		"%zz":                                                           "",
	} {
		if got := publicOrigin(in); got != want {
			t.Errorf("publicOrigin(%q) = %q, want %q", in, got, want)
		}
	}
}

// instanceSandboxRunner exposes the optional observation interface while
// preserving the same normal service-state path used by the HTTP handler.
type instanceSandboxRunner struct {
	*fakeHPRunner
	status instance.SandboxStatus
	err    error
	calls  atomic.Int64
}

func (f *instanceSandboxRunner) SandboxStatus(context.Context) (instance.SandboxStatus, error) {
	f.calls.Add(1)
	return f.status, f.err
}

func TestInstanceInfoReportsObservedSandboxAndRedactsProbeErrors(t *testing.T) {
	const privateDetail = "synthetic-private-runtime-probe-detail"
	for _, scenario := range []struct {
		name, mode, fallback string
		observed             instance.SandboxStatus
		err                  error
	}{
		{"explicit Docker", "none", "deny", instance.SandboxStatus{Requested: "none", FallbackPolicy: "deny", Runtime: "runc", Verified: true, Services: map[string]string{"cowrie": "runc"}}, nil},
		{"observed Kata", "kata", "deny", instance.SandboxStatus{Requested: "kata", FallbackPolicy: "deny", Runtime: "kata-runtime", Verified: true, Services: map[string]string{"cowrie": "kata-runtime"}}, nil},
		{"explicit emulator fallback", "gvisor", "docker", instance.SandboxStatus{Requested: "gvisor", FallbackPolicy: "docker", Runtime: "runc", Fallback: true, Verified: true, Services: map[string]string{"cowrie": "runc"}}, nil},
		{"mismatched real runtime", "gvisor", "deny", instance.SandboxStatus{Requested: "gvisor", FallbackPolicy: "deny", Runtime: "runc", Verified: false, Code: "QP-DOCKER-012", Services: map[string]string{"cowrie": "runc"}}, hostsetup.E("QP-DOCKER-012").WithWhy(privateDetail).Wrap(errors.New("docker inspect unix:///private/runtime.sock: " + privateDetail))},
		{"no observed guests", "none", "deny", instance.SandboxStatus{Requested: "none", FallbackPolicy: "deny", Services: map[string]string{}}, nil},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			a := newAPITestServer(t, "api-isolation", func(cfg *config.Config) {
				cfg.Security.SandboxMode, cfg.Security.SandboxFallback = scenario.mode, scenario.fallback
				cfg.Intelligence.Enabled = false
			})
			a.s.database = &fakeDB{}
			a.runner.states = map[string]instance.ServiceState{"database": {State: "running", Health: "healthy"}, "cowrie": {State: "running"}}
			observer := &instanceSandboxRunner{fakeHPRunner: a.runner, status: scenario.observed, err: scenario.err}
			a.s.api.runner = func(*config.Config) instance.HoneypotRunner { return observer }
			rec := a.do(http.MethodGet, "/api/instance", "")
			var info instanceInfo
			if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &info) != nil {
				t.Fatalf("instance observation: %d %s", rec.Code, rec.Body.String())
			}
			if observer.calls.Load() != 1 || info.Sandbox.Requested != scenario.mode || info.Sandbox.FallbackPolicy != scenario.fallback || info.Sandbox.Runtime != scenario.observed.Runtime || info.Sandbox.Verified != scenario.observed.Verified || info.Sandbox.Fallback != scenario.observed.Fallback || info.Sandbox.Code != scenario.observed.Code || len(info.Sandbox.Services) != len(scenario.observed.Services) {
				t.Fatalf("reported isolation differs from the owned-container observation: %+v", info.Sandbox)
			}
			for service, runtime := range scenario.observed.Services {
				if info.Sandbox.Services[service] != runtime {
					t.Fatalf("actual runtime for %s was hidden: %+v", service, info.Sandbox)
				}
			}
			if !info.Database.Healthy || info.Status != "running" || strings.Contains(rec.Body.String(), privateDetail) || strings.Contains(rec.Body.String(), "runtime.sock") {
				t.Fatalf("probe failure leaked details or hid the otherwise healthy instance: %s", rec.Body.String())
			}
		})
	}
}

func TestInstanceInfoDoesNotInventIsolationWithoutAnObserver(t *testing.T) {
	a := newAPITestServer(t, "api-no-runtime-observer", func(cfg *config.Config) {
		cfg.Security.SandboxMode = "gvisor"
		cfg.Security.SandboxFallback = "deny"
	})
	a.s.database = &fakeDB{}
	a.runner.states = map[string]instance.ServiceState{"cowrie": {State: "running"}}
	rec := a.do(http.MethodGet, "/api/instance", "")
	var info instanceInfo
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &info) != nil {
		t.Fatalf("instance observation: %d %s", rec.Code, rec.Body.String())
	}
	if info.Sandbox.Requested != "gvisor" || info.Sandbox.FallbackPolicy != "deny" || info.Sandbox.Verified || info.Sandbox.Runtime != "" || len(info.Sandbox.Services) != 0 || info.Sandbox.Code != "QP-DOCKER-011" {
		t.Fatalf("configured isolation was advertised as observed: %+v", info.Sandbox)
	}
}

type instanceUncoordinatedWorkerDB struct {
	fakeDB
	checkpointReads atomic.Int64
	closed          atomic.Int64
}

func (d *instanceUncoordinatedWorkerDB) IntelligenceLockIdentity() string {
	return "instance-api-uncoordinated-database"
}

func (d *instanceUncoordinatedWorkerDB) LoadIntelligenceCheckpoint(ctx context.Context) (*database.IntelligenceCheckpoint, error) {
	d.checkpointReads.Add(1)
	return d.fakeDB.LoadIntelligenceCheckpoint(ctx)
}

func (d *instanceUncoordinatedWorkerDB) Close() error { d.closed.Add(1); return nil }

func TestInstanceInfoWorkerPointerDoesNotClaimOwnershipOrStopTheDatabase(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configDir)
	t.Setenv("APPDATA", configDir)
	a := newAPITestServer(t, "api-worker-ownership", func(cfg *config.Config) { cfg.Intelligence.Enabled = true })
	db := &instanceUncoordinatedWorkerDB{}
	a.s.database = db
	a.runner.states = map[string]instance.ServiceState{"database": {State: "running", Health: "healthy"}, "collector": {State: "running", Health: "healthy"}}
	w := intelligence.NewWorker(nil, db, time.Hour, 100)
	a.s.worker = w
	assertWorker := func(state, code string) {
		t.Helper()
		rec := a.do(http.MethodGet, "/api/instance", "")
		var info instanceInfo
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &info) != nil {
			t.Fatalf("instance worker health: %d %s", rec.Code, rec.Body.String())
		}
		if info.Intelligence["enabled"] != true || info.Intelligence["worker_running"] != false || info.Intelligence["worker_healthy"] != false || info.Intelligence["worker_status"] != state {
			t.Fatalf("non-owning worker was advertised as active: %+v", info.Intelligence)
		}
		if code != "" && (info.Intelligence["worker_error_code"] != code || info.Intelligence["worker_error_remedy"] != hostsetup.E(code).Remedy()) {
			t.Fatalf("missing catalog-only ownership recovery: %+v", info.Intelligence)
		}
		if code == "" && (info.Intelligence["worker_error_code"] != nil || info.Intelligence["worker_error_remedy"] != nil) {
			t.Fatalf("unstarted worker advertised an error it has not encountered: %+v", info.Intelligence)
		}
		if !info.Database.Connected || !info.Database.Healthy || info.Status != "running" {
			t.Fatalf("stopped intelligence worker hid healthy collection/database services: %+v", info)
		}
	}
	assertWorker("not_started", "")
	if err := db.InsertEvent(t.Context(), &database.Event{ID: "before-ownership-refusal"}); err != nil {
		t.Fatal(err)
	}
	w.Run(t.Context()) // lacks IntelligenceLeaser: must stop before any checkpoint read
	assertWorker("stopped", "QP-INTEL-008")
	if err := db.InsertEvent(t.Context(), &database.Event{ID: "after-ownership-refusal"}); err != nil {
		t.Fatal(err)
	}
	if db.checkpointReads.Load() != 0 || db.closed.Load() != 0 || len(db.insertedEvents()) != 2 {
		t.Fatal("worker refusal read intelligence state, closed the shared database or prevented event inserts")
	}
}

type instanceRunningWorkerDB struct {
	fakeDB
	read chan struct{}
	once sync.Once
}

func (d *instanceRunningWorkerDB) GetUnclassifiedEvents(context.Context, int) ([]*database.Event, error) {
	d.once.Do(func() { close(d.read) })
	return nil, nil
}

func TestInstanceInfoReportsAnActuallyRunningWorkerAndDisabledPolicy(t *testing.T) {
	a := newAPITestServer(t, "api-running-worker", func(cfg *config.Config) { cfg.Intelligence.Enabled = true })
	db := &instanceRunningWorkerDB{read: make(chan struct{})}
	a.s.database = db
	classifier := intelligence.NewClassifier(intelligence.NewATTCKLoader(t.TempDir()), nil)
	w := intelligence.NewWorker(classifier, db, time.Hour, 100)
	a.s.worker = w
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); w.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("HTTP worker-health fixture did not stop")
		}
	})
	select {
	case <-db.read:
	case <-time.After(2 * time.Second):
		t.Fatal("fixture worker did not begin processing")
	}
	for _, enabled := range []bool{true, false} {
		a.cfg.Intelligence.Enabled = enabled
		if err := config.Save(a.cfg); err != nil {
			t.Fatal(err)
		}
		rec := a.do(http.MethodGet, "/api/instance", "")
		var info instanceInfo
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &info) != nil {
			t.Fatalf("instance worker health: %d %s", rec.Code, rec.Body.String())
		}
		wantState := "disabled"
		if enabled {
			wantState = "running"
		}
		if info.Intelligence["enabled"] != enabled || info.Intelligence["worker_running"] != enabled || info.Intelligence["worker_healthy"] != enabled || info.Intelligence["worker_status"] != wantState {
			t.Fatalf("worker health did not follow lifecycle/configuration: %+v", info.Intelligence)
		}
	}
}
