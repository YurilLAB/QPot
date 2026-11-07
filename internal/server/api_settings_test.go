package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/instance"
)

// fakeHPRunner stands in for the instance's containers in API tests.
type fakeHPRunner struct {
	mu        sync.Mutex
	running   bool
	startErr  error
	started   []string
	stopped   []string
	restarted []string
	// cfgs are the configs the server asked for a runner for.
	cfgs []*config.Config
}

func (f *fakeHPRunner) IsRunning(context.Context) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}
func (f *fakeHPRunner) StartHoneypot(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = append(f.started, name)
	return f.startErr
}
func (f *fakeHPRunner) StopHoneypot(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = append(f.stopped, name)
	return nil
}
func (f *fakeHPRunner) RestartHoneypot(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.restarted = append(f.restarted, name)
	return f.startErr
}

// apiTestServer is a server for one instance whose config file is on disk,
// with canaries on and a fake container runner.
type apiTestServer struct {
	s      *Server
	h      http.Handler
	runner *fakeHPRunner
	cfg    *config.Config
}

func newAPITestServer(t testing.TB, name string, prep func(*config.Config)) *apiTestServer {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default(name)
	cfg.DataPath = dir
	cfg.ConfigPath = filepath.Join(dir, "config.yaml")
	cfg.QPotID = validTestID
	cfg.WebUI.QPotIDAuth = true
	cfg.Security.SandboxMode = "none"
	cfg.Canary = config.CanaryConfig{Enabled: true, Decoy: "notfound"}
	if prep != nil {
		prep(cfg)
	}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	cs, err := canary.NewStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.SyncPlanted(instance.PlantedCanaries(cfg)); err != nil {
		t.Fatal(err)
	}
	r := &fakeHPRunner{}
	s := &Server{config: cfg, mux: http.NewServeMux(), canaries: cs}
	s.api.runner = func(c *config.Config) instance.HoneypotRunner {
		r.mu.Lock()
		r.cfgs = append(r.cfgs, c)
		r.mu.Unlock()
		return r
	}
	s.setupRoutes()
	return &apiTestServer{s: s, h: securityHeaders(s.authMiddleware(s.mux)), runner: r, cfg: cfg}
}

// do sends a request through the full middleware chain with the QPot ID and,
// for a body, the JSON content type.
func (a *apiTestServer) do(method, path, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.Header.Set("X-QPot-ID", validTestID)
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, req)
	return rec
}

func (a *apiTestServer) configFile(t testing.TB) []byte {
	t.Helper()
	data, err := os.ReadFile(a.cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func decodeAPIError(t *testing.T, rec *httptest.ResponseRecorder) apiError {
	t.Helper()
	var e apiError
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("error body is not JSON: %q", rec.Body.String())
	}
	return e
}

// assertAuthRequired checks a route answers 401 without a QPot ID or with a
// malformed one, and 403 with another instance's.
func assertAuthRequired(t *testing.T, h http.Handler, method, path, body string) {
	t.Helper()
	for _, c := range []struct {
		id   string
		want int
	}{{"", http.StatusUnauthorized}, {"not-an-id", http.StatusUnauthorized}, {"qp_zzzzzzzzzzzzzzzzzzzzzzzz", http.StatusForbidden}} {
		var req *http.Request
		if body != "" {
			req = httptest.NewRequest(method, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
		} else {
			req = httptest.NewRequest(method, path, nil)
		}
		if c.id != "" {
			req.Header.Set("X-QPot-ID", c.id)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s %s with ID %q: %d, want %d", method, path, c.id, rec.Code, c.want)
		}
		if strings.Contains(rec.Body.String(), validTestID) {
			t.Errorf("%s %s: refusal carries the QPot ID", method, path)
		}
	}
}

func TestSettingsAuth(t *testing.T) {
	a := newAPITestServer(t, "api-set-auth", nil)
	before := a.configFile(t)
	assertAuthRequired(t, a.h, http.MethodGet, "/api/honeypots/settings?name=cowrie", "")
	assertAuthRequired(t, a.h, http.MethodPut, "/api/honeypots/settings", `{"name":"cowrie","settings":{"bait":"off"}}`)
	if !bytes.Equal(before, a.configFile(t)) {
		t.Fatal("an unauthenticated PUT changed the config")
	}
}

// A cross-site form can POST/PUT text/plain; the server refuses every body
// type but JSON before a handler runs.
func TestSettingsPutNeedsJSON(t *testing.T) {
	a := newAPITestServer(t, "api-set-csrf", nil)
	before := a.configFile(t)
	for _, ct := range []string{"text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", ""} {
		req := httptest.NewRequest(http.MethodPut, "/api/honeypots/settings", strings.NewReader(`{"name":"cowrie","settings":{"bait":"off"}}`))
		req.Header.Set("X-QPot-ID", validTestID)
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		rec := httptest.NewRecorder()
		a.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("PUT with %q: %d, want 415", ct, rec.Code)
		}
	}
	if !bytes.Equal(before, a.configFile(t)) {
		t.Fatal("a non-JSON PUT changed the config")
	}
	// GET is not a way to change settings.
	if rec := a.do(http.MethodGet, "/api/honeypots/settings?name=cowrie&bait=off", ""); rec.Code != http.StatusOK || !bytes.Equal(before, a.configFile(t)) {
		t.Fatalf("GET: %d, or it changed the config", rec.Code)
	}
	if rec := a.do(http.MethodPost, "/api/honeypots/settings", `{"name":"cowrie","settings":{"bait":"off"}}`); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d, want 405", rec.Code)
	}
}

func TestSettingsGet(t *testing.T) {
	const apiKey = "sk-" + "TESTKEYdoNotShow123"
	a := newAPITestServer(t, "api-set-get", func(c *config.Config) {
		hp := c.Honeypots["galah"]
		hp.CustomConfig = map[string]string{"llm_api_key": apiKey, "llm_provider": "openai"}
		c.Honeypots["galah"] = hp
	})
	rec := a.do(http.MethodGet, "/api/honeypots/settings?name=cowrie", "")
	var one honeypotSettingsView
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &one) != nil {
		t.Fatalf("GET cowrie: %d %s", rec.Code, rec.Body.String())
	}
	keys := []string{}
	for _, si := range one.Settings {
		keys = append(keys, si.Key)
	}
	if one.Name != "cowrie" || strings.Join(keys, ",") != "bait,persona,persona_rotation" {
		t.Fatalf("cowrie settings: %+v", one)
	}

	rec = a.do(http.MethodGet, "/api/honeypots/settings", "")
	var all struct {
		Honeypots []honeypotSettingsView `json:"honeypots"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &all) != nil {
		t.Fatalf("GET all: %d %s", rec.Code, rec.Body.String())
	}
	names := []string{}
	for _, hp := range all.Honeypots {
		names = append(names, hp.Name)
	}
	if got := strings.Join(names, ","); got != "beelzebub,conpot,cowrie,galah,ssh-proxy" {
		t.Fatalf("honeypots with settings: %s", got)
	}
	if strings.Contains(rec.Body.String(), apiKey) {
		t.Fatal("the LLM API key is in the settings listing")
	}
	rec = a.do(http.MethodGet, "/api/honeypots/settings?name=galah", "")
	if strings.Contains(rec.Body.String(), apiKey) || !strings.Contains(rec.Body.String(), `"key":"llm_api_key","value":"","set":true`) {
		t.Fatalf("galah: %s", rec.Body.String())
	}

	for _, bad := range []string{"%3Cscript%3Ealert(1)%3C%2Fscript%3E", "nosuch", "cowrie%00"} {
		rec = a.do(http.MethodGet, "/api/honeypots/settings?name="+bad, "")
		if rec.Code != http.StatusBadRequest || decodeAPIError(t, rec).Code != "QP-INPUT-003" || strings.Contains(rec.Body.String(), "script") {
			t.Errorf("GET name=%s: %d %s", bad, rec.Code, rec.Body.String())
		}
	}
}

// The API saves exactly what `qpot honeypot set` saves: the same config file
// from the same starting file.
func TestSettingsPutMatchesCLI(t *testing.T) {
	a := newAPITestServer(t, "api-set-cli", func(c *config.Config) { c.EnableHoneypot("cowrie") })
	orig := a.configFile(t)

	rec := a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"cowrie","settings":{"persona":"rhel-9","bait":"off","persona_rotation":"30"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
	}
	viaAPI := a.configFile(t)

	// What the CLI does (cmd/qpot honeypot set): load the file, apply the
	// key=value arguments, save.
	if err := os.WriteFile(a.cfg.ConfigPath, orig, 0o600); err != nil {
		t.Fatal(err)
	}
	cliCfg, err := config.Parse(orig, a.cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := instance.ApplySettings(context.Background(), cliCfg, "cowrie",
		instance.ParseSettingArgs([]string{"persona=rhel-9", "bait=off", "persona_rotation=30"}), &fakeHPRunner{}); err != nil {
		t.Fatal(err)
	}
	viaCLI := a.configFile(t)
	if !bytes.Equal(viaAPI, viaCLI) {
		t.Fatalf("API and CLI saved different configs:\nAPI:\n%s\nCLI:\n%s", viaAPI, viaCLI)
	}
	if bytes.Equal(viaAPI, orig) || !bytes.Contains(viaAPI, []byte("persona: rhel-9")) {
		t.Fatalf("the change is not in the file:\n%s", viaAPI)
	}

	// Removing a setting with "" is `persona=`.
	rec = a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"cowrie","settings":{"persona":""}}`)
	if rec.Code != http.StatusOK || bytes.Contains(a.configFile(t), []byte("persona: rhel-9")) {
		t.Fatalf("remove: %d\n%s", rec.Code, a.configFile(t))
	}
}

func TestSettingsPutRecreates(t *testing.T) {
	a := newAPITestServer(t, "api-set-run", func(c *config.Config) { c.EnableHoneypot("cowrie") })

	// Stopped instance: saved, nothing started, and the answer says so.
	rec := a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"cowrie","settings":{"bait":"off"}}`)
	var resp settingsChangeResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil || resp.Recreated || resp.InstanceRunning ||
		!strings.Contains(resp.Message, "not running") || len(a.runner.started) != 0 {
		t.Fatalf("stopped: %d %s started %v", rec.Code, rec.Body.String(), a.runner.started)
	}

	// Running: recreated, through a manager for the config just saved.
	a.runner.running = true
	rec = a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"cowrie","settings":{"bait":"on"}}`)
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil || !resp.Recreated ||
		len(a.runner.started) != 1 || a.runner.started[0] != "cowrie" {
		t.Fatalf("running: %d %s started %v", rec.Code, rec.Body.String(), a.runner.started)
	}
	last := a.runner.cfgs[len(a.runner.cfgs)-1]
	if hp, _ := last.GetHoneypotConfig("cowrie"); hp.CustomConfig["bait"] != "on" || last == a.s.config {
		t.Fatalf("recreated with the wrong config: %v", hp.CustomConfig)
	}

	// The recreate fails: the settings are saved and the answer says both.
	a.runner.startErr = errors.New("compose: no such image")
	rec = a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"cowrie","settings":{"persona":"centos-7"}}`)
	e := decodeAPIError(t, rec)
	if rec.Code != http.StatusBadGateway || !e.Saved || e.Code != "QP-INST-008" || strings.Contains(e.Error, "no such image") ||
		!bytes.Contains(a.configFile(t), []byte("persona: centos-7")) {
		t.Fatalf("recreate failure: %d %s", rec.Code, rec.Body.String())
	}
	if hp, _ := a.s.config.GetHoneypotConfig("cowrie"); hp.CustomConfig["persona"] != "centos-7" {
		t.Fatalf("server config does not show the saved change: %v", hp.CustomConfig)
	}
}

// Names and values that are not on the honeypot's lists, or hostile, are
// refused without changing anything, and the error never echoes them.
func TestSettingsPutRefusesHostileInput(t *testing.T) {
	a := newAPITestServer(t, "api-set-hostile", nil)
	before := a.configFile(t)
	cases := []struct {
		body, code string
		status     int
	}{
		{`{"name":"<script>alert(1)</script>","settings":{"persona":"rhel-9"}}`, "QP-INPUT-003", 400},
		{`{"name":"cowrie\u0000","settings":{"persona":"rhel-9"}}`, "QP-INPUT-003", 400},
		{`{"name":"--project-name=x","settings":{"persona":"rhel-9"}}`, "QP-INPUT-003", 400},
		{`{"name":"cowrie","settings":{"persona":"<img src=x onerror=alert(1)>"}}`, "QP-INPUT-012", 400},
		{`{"name":"cowrie","settings":{"<img src=x onerror=alert(1)>":"on"}}`, "QP-INPUT-012", 400},
		{`{"name":"galah","settings":{"llm_model":"<svg/onload=alert(1)>"}}`, "QP-INPUT-012", 400},
		{`{"name":"galah","settings":{"llm_server_url":"javascript:alert(1)"}}`, "QP-INPUT-012", 400},
		{`{"name":"galah","settings":{"llm_provider":"ollama\nINJECT=1"}}`, "QP-INPUT-012", 400},
		{`{"name":"endlessh","settings":{"x":"y"}}`, "QP-INPUT-012", 400},
		{`{"name":"cowrie","settings":{}}`, "QP-INPUT-012", 400},
		{`{"name":"cowrie","settings":{"bait":"off"},"extra":1}`, "", 400},
		{`{"name":"cowrie","settings":{"bait":"off"}} {"x":1}`, "", 400},
		{`{"name":"cowrie","settings":{"bait":1}}`, "", 400},
		{`[]`, "", 400},
		{`{"name":"cowrie","settings":{"bait":"` + strings.Repeat("x", maxSettingsBody) + `"}}`, "", 400},
	}
	for _, c := range cases {
		rec := a.do(http.MethodPut, "/api/honeypots/settings", c.body)
		short := c.body
		if len(short) > 80 {
			short = short[:80]
		}
		if rec.Code != c.status {
			t.Errorf("%s: %d, want %d (%s)", short, rec.Code, c.status, rec.Body.String())
			continue
		}
		e := decodeAPIError(t, rec)
		if e.Code != c.code || e.Error == "" {
			t.Errorf("%s: %+v, want code %q", short, e, c.code)
		}
		for _, bad := range []string{"<", ">", "script", "onerror", "onload", "javascript", "INJECT"} {
			if strings.Contains(e.Error, bad) {
				t.Errorf("%s: error echoes %q: %q", short, bad, e.Error)
			}
		}
	}
	if !bytes.Equal(before, a.configFile(t)) || len(a.runner.started) != 0 {
		t.Fatal("a refused PUT changed the config or touched the containers")
	}
}

func TestSettingsPutOneChangeAtATime(t *testing.T) {
	a := newAPITestServer(t, "api-set-busy", nil)
	a.s.api.change.Lock()
	rec := a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"cowrie","settings":{"bait":"off"}}`)
	a.s.api.change.Unlock()
	if rec.Code != http.StatusConflict {
		t.Fatalf("PUT during another change: %d, want 409", rec.Code)
	}
	if rec := a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"cowrie","settings":{"bait":"off"}}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT after it: %d", rec.Code)
	}
}

// A change made with the CLI while the server runs is kept: the server
// changes the config file as it is now, not its own copy from its start.
func TestSettingsPutKeepsCLIChanges(t *testing.T) {
	a := newAPITestServer(t, "api-set-keep", nil)
	cli, err := config.Parse(a.configFile(t), a.cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	cli.EnableHoneypot("conpot")
	cli.SetHoneypotCustomConfig("conpot", map[string]string{"template": "iccp"})
	cli.Collector.GeoIPDBPath = "/data/geoip/dbip-country-lite.mmdb"
	if err := config.Save(cli); err != nil {
		t.Fatal(err)
	}
	rec := a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"cowrie","settings":{"bait":"off"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
	}
	after, err := config.Parse(a.configFile(t), a.cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	conpot, _ := after.GetHoneypotConfig("conpot")
	cowrie, _ := after.GetHoneypotConfig("cowrie")
	if !conpot.Enabled || conpot.CustomConfig["template"] != "iccp" || after.Collector.GeoIPDBPath == "" || cowrie.CustomConfig["bait"] != "off" {
		t.Fatalf("the CLI's change was lost: conpot %+v geoip %q cowrie %v", conpot, after.Collector.GeoIPDBPath, cowrie.CustomConfig)
	}
	if hp, _ := a.s.config.GetHoneypotConfig("conpot"); !hp.Enabled {
		t.Fatal("the server's config does not show the file's honeypots after the change")
	}
}

// Turning Cowrie's bait off (or picking a device persona) through the API
// takes its planted canaries out of the store at once; turning it on plants
// them again.
func TestSettingsPutPlantedCanariesFollow(t *testing.T) {
	a := newAPITestServer(t, "api-set-plant", func(c *config.Config) {
		c.EnableHoneypot("cowrie")
		c.SetHoneypotCustomConfig("cowrie", map[string]string{"persona": "debian-bookworm"})
	})
	planted := func() int {
		rec := a.do(http.MethodGet, "/api/canaries", "")
		var body struct {
			Canaries []map[string]any `json:"canaries"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("canaries: %d %s", rec.Code, rec.Body.String())
		}
		n := 0
		for _, c := range body.Canaries {
			if c["planted"] == true {
				n++
			}
		}
		return n
	}
	if planted() == 0 {
		t.Fatal("no planted canaries to start with")
	}
	if rec := a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"cowrie","settings":{"bait":"off"}}`); rec.Code != http.StatusOK {
		t.Fatalf("bait off: %d %s", rec.Code, rec.Body.String())
	}
	if n := planted(); n != 0 {
		t.Fatalf("bait off: %d planted canaries still watched", n)
	}
	if rec := a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"cowrie","settings":{"bait":"on"}}`); rec.Code != http.StatusOK {
		t.Fatalf("bait on: %d", rec.Code)
	}
	if planted() == 0 {
		t.Fatal("bait on: nothing planted again")
	}
	if rec := a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"cowrie","settings":{"persona":"openwrt"}}`); rec.Code != http.StatusOK {
		t.Fatalf("device persona: %d", rec.Code)
	}
	if n := planted(); n != 0 {
		t.Fatalf("device persona: %d planted canaries still watched", n)
	}
}
