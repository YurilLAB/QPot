package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/hostsetup"
	"github.com/qpot/qpot/internal/instance"
	"gopkg.in/yaml.v3"
)

// fakeHPRunner stands in for the instance's containers in API tests.
type fakeHPRunner struct {
	mu        sync.Mutex
	running   bool
	startErr  error
	started   []string
	recreated []string
	stopped   []string
	restarted []string
	// cfgs are the configs the server asked for a runner for.
	cfgs []*config.Config
	// states / statesErr answer ServiceStates.
	states    map[string]instance.ServiceState
	statesErr error
}

func (f *fakeHPRunner) ServiceStates(context.Context) (map[string]instance.ServiceState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.states, f.statesErr
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
func (f *fakeHPRunner) RecreateHoneypot(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recreated = append(f.recreated, name)
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
	s.api.lookup = testLookup
	s.setupRoutes()
	return &apiTestServer{s: s, h: securityHeaders(s.authMiddleware(s.mux)), runner: r, cfg: cfg}
}

// testLookup resolves a few names for endpoint checks without the network.
func testLookup(_ context.Context, host string) ([]netip.Addr, error) {
	addrs := map[string]string{
		"localhost": "127.0.0.1", "ollama.lan": "10.0.0.5", "llm.example.net": "203.0.113.7",
		"meta.evil.test": "169.254.169.254", "v6meta.evil.test": "fd00:ec2::254",
		"mapped.evil.test": "::ffff:169.254.169.254", "mixed.evil.test": "203.0.113.8",
	}
	a, ok := addrs[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	out := []netip.Addr{netip.MustParseAddr(a)}
	if host == "mixed.evil.test" {
		out = append(out, netip.MustParseAddr("169.254.170.2"))
	}
	return out, nil
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

func TestSettingsPutHiFiKeepsInvalidInputAtomic(t *testing.T) {
	a := newAPITestServer(t, "api-hifi-caps", func(c *config.Config) {
		for name := range c.Honeypots {
			c.DisableHoneypot(name)
		}
		c.EnableHoneypot("ssh-proxy")
		hp, _ := c.GetHoneypotConfig("ssh-proxy")
		hp.Resources = config.HoneypotResources{UseCustomLimits: true, MaxPids: 17}
		hp.CustomConfig = map[string]string{"environment": "standalone", "image_source": "local"}
		c.Honeypots["ssh-proxy"] = hp
	})
	a.runner.running = true
	before := a.configFile(t)
	for _, body := range []string{
		`{"name":"ssh-proxy","settings":{"environment":"Organization"}}`,
		`{"name":"ssh-proxy","settings":{"environment":"organization","max_pids":"-1"}}`,
		`{"name":"ssh-proxy","settings":{"environment":"organization","image_source":"Local"}}`,
		`{"name":"ssh-proxy","settings":{"environment":"organization","cell_hold_minutes":"121"}}`,
		`{"name":"ssh-proxy","settings":{"environment":"organization","cell_hold_minutes":"1.5"}}`,
	} {
		rec := a.do(http.MethodPut, "/api/honeypots/settings", body)
		if e := decodeAPIError(t, rec); rec.Code != http.StatusBadRequest || e.Code != "QP-INPUT-012" || e.Saved {
			t.Fatalf("invalid HiFi setting lost its error contract: %d %s", rec.Code, rec.Body.String())
		}
		if !bytes.Equal(before, a.configFile(t)) || len(a.runner.cfgs) != 0 || len(a.runner.recreated) != 0 {
			t.Fatal("invalid HiFi input changed saved state or reached the container runner")
		}
	}
	rec := a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"ssh-proxy","settings":{"environment":"organization"}}`)
	if rec.Code != http.StatusOK || !slices.Equal(a.runner.recreated, []string{"ssh-proxy"}) {
		t.Fatalf("valid mode with inherited CPU/memory failed: %d %s", rec.Code, rec.Body.String())
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
	if one.Name != "cowrie" || strings.Join(keys, ",") != "bait,bait_profile,bait_target,persona,persona_rotation" {
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
	if got := strings.Join(names, ","); got != "beelzebub,conpot,cowrie,galah,refrigeration,ssh-proxy" {
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
		!strings.Contains(resp.Message, "not running") || len(a.runner.started)+len(a.runner.recreated) != 0 {
		t.Fatalf("stopped: %d %s started %v recreated %v", rec.Code, rec.Body.String(), a.runner.started, a.runner.recreated)
	}

	// Running: recreated, through a manager for the config just saved.
	a.runner.running = true
	rec = a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"cowrie","settings":{"bait":"on"}}`)
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil || !resp.Recreated ||
		!slices.Equal(a.runner.recreated, []string{"cowrie"}) || len(a.runner.started) != 0 {
		t.Fatalf("running: %d %s recreated %v started %v", rec.Code, rec.Body.String(), a.runner.recreated, a.runner.started)
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
		{`{"name":"cowrie","settings":{"bait":"off"},"extra":1}`, "QP-WEB-004", 400},
		{`{"name":"cowrie","settings":{"bait":"off"}} {"x":1}`, "QP-WEB-004", 400},
		{`{"name":"cowrie","settings":{"bait":1}}`, "QP-WEB-004", 400},
		{`[]`, "QP-WEB-004", 400},
		{`null`, "QP-WEB-004", 400},
		{`{"name":"cowrie","settings":{"bait":"` + strings.Repeat("x", maxSettingsBody) + `"}}`, "QP-WEB-004", 400},
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
	if !bytes.Equal(before, a.configFile(t)) || len(a.runner.started)+len(a.runner.recreated) != 0 {
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
	if e := decodeAPIError(t, rec); e.Code != "QP-INST-009" {
		t.Fatalf("busy settings change lacks its stable error code: %+v", e)
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
// marks its previous canaries historical at once; turning it on makes them
// current again. Historical credentials remain watched if reused later.
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
			if c["planted"] == true && c["historical"] != true {
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

// Switching the file profile updates the current canaries immediately, while
// preserving older credentials that may already have been stolen. Invalid
// choices cannot leave config and the registry describing different files.
func TestSettingsPutBaitProfile(t *testing.T) {
	a := newAPITestServer(t, "api-set-bait-profile", func(c *config.Config) {
		c.EnableHoneypot("cowrie")
		c.SetHoneypotCustomConfig("cowrie", map[string]string{"persona": "debian-bookworm"})
		c.SetHoneypotCustomConfig("conpot", map[string]string{"template": "plc_modbus"})
	})
	manual, err := a.s.canaries.Create(canary.KindWeb, "user-created canary", "")
	if err != nil {
		t.Fatal(err)
	}
	profile := func() instance.SettingInfo {
		t.Helper()
		rec := a.do(http.MethodGet, "/api/honeypots/settings?name=cowrie", "")
		var view honeypotSettingsView
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &view) != nil {
			t.Fatalf("GET Cowrie: %d %s", rec.Code, rec.Body.String())
		}
		for _, setting := range view.Settings {
			if setting.Key == "bait_profile" {
				return setting
			}
		}
		t.Fatal("bait_profile missing from settings API")
		return instance.SettingInfo{}
	}
	planted := func(wantIndustrial bool) []string {
		t.Helper()
		rec := a.do(http.MethodGet, "/api/canaries", "")
		var body struct {
			Canaries []struct {
				ID         string `json:"id"`
				Name       string `json:"name"`
				Planted    bool   `json:"planted"`
				Historical bool   `json:"historical"`
			} `json:"canaries"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
			t.Fatalf("GET canaries: %d %s", rec.Code, rec.Body.String())
		}
		var ids []string
		foundManual, foundIndustrial := false, false
		for _, c := range body.Canaries {
			foundManual = foundManual || c.ID == manual.ID
			if c.Planted && !c.Historical {
				ids = append(ids, c.ID)
				foundIndustrial = foundIndustrial || c.Name == "cowrie bait: OT archive credential"
			}
		}
		if !foundManual || len(ids) == 0 || foundIndustrial != wantIndustrial {
			t.Fatalf("canary registry: manual=%v planted=%d industrial=%v, want industrial=%v", foundManual, len(ids), foundIndustrial, wantIndustrial)
		}
		slices.Sort(ids)
		return ids
	}
	initial := profile()
	if initial.Value != "" || initial.Set || initial.Effective != "ops" || initial.Type != "choice" ||
		!slices.Equal(initial.Allowed, []string{"ops", "industrial"}) || !strings.Contains(initial.Help, "Linux industrial support host") {
		t.Fatalf("default file profile metadata: %+v", initial)
	}
	ops := planted(false)
	oldCanaries := a.s.canaries.List()
	setProfile := func(value string) {
		t.Helper()
		body, err := json.Marshal(map[string]any{"name": "cowrie", "settings": map[string]string{"bait_profile": value}})
		if err != nil {
			t.Fatal(err)
		}
		rec := a.do(http.MethodPut, "/api/honeypots/settings", string(body))
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT file profile %q: %d %s", value, rec.Code, rec.Body.String())
		}
	}
	setProfile("industrial")
	industrial := planted(true)
	for _, id := range industrial {
		if slices.Contains(ops, id) {
			t.Fatalf("old ops credential %s still shown as current in industrial profile", id)
		}
	}
	for _, c := range oldCanaries {
		if !c.Planted {
			continue
		}
		retained, ok := a.s.canaries.Get(c.ID)
		if !ok || !retained.Planted || !retained.Historical {
			t.Fatalf("previous credential %s was not retained as historical", c.ID)
		}
		if c.Kind == canary.KindCredential && len(c.Values) > 0 {
			trips, err := a.s.canaries.MatchObservation(canary.Observation{
				Text: c.Values[0], SourceIP: "192.0.2.34", EventKey: "old-ops-value-after-successful-profile-change-" + c.ID,
			})
			if err != nil || len(trips) != 1 || trips[0].CanaryID != c.ID {
				t.Fatalf("historical credential %s no longer matched: trips=%d err=%v", c.ID, len(trips), err)
			}
		}
	}
	if got := profile(); got.Value != "industrial" || !got.Set || got.Effective != "" {
		t.Fatalf("saved industrial metadata: %+v", got)
	}
	before := a.configFile(t)
	beforeRunnerCalls := len(a.runner.cfgs)
	rec := a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"cowrie","settings":{"bait_profile":"unsupported","persona":"rhel-9"}}`)
	if rec.Code != http.StatusBadRequest || !bytes.Equal(before, a.configFile(t)) || len(a.runner.cfgs) != beforeRunnerCalls || !slices.Equal(industrial, planted(true)) {
		t.Fatalf("invalid profile changed state or reached runner: %d %s", rec.Code, rec.Body.String())
	}
	setProfile("ops")
	if !slices.Equal(ops, planted(false)) {
		t.Fatal("switching to ops did not restore its original watched credentials")
	}
	for _, id := range industrial {
		if c, ok := a.s.canaries.Get(id); !ok || !c.Historical {
			t.Fatalf("industrial credential %s not retained as historical after returning to ops", id)
		}
	}
	if got := profile(); got.Value != "ops" || !got.Set || got.Effective != "" {
		t.Fatalf("saved ops metadata: %+v", got)
	}
	setProfile("")
	if got := profile(); got.Value != "" || got.Set || got.Effective != "ops" || !slices.Equal(ops, planted(false)) {
		t.Fatalf("clearing the profile did not restore ops default: %+v", got)
	}
	if len(a.runner.started)+len(a.runner.recreated) != 0 {
		t.Fatal("changing a stopped instance unexpectedly started a honeypot")
	}
}

// A failed recreation can leave the previous container's files in use. Saving
// the desired profile must not create a blind spot for those old credentials.
func TestSettingsPutBaitProfileRecreateFailureKeepsOldCanaries(t *testing.T) {
	a := newAPITestServer(t, "api-set-bait-failure", func(c *config.Config) {
		c.EnableHoneypot("cowrie")
		c.SetHoneypotCustomConfig("cowrie", map[string]string{"persona": "debian-bookworm", "bait_profile": "ops"})
	})
	old := a.s.canaries.List()
	a.runner.running = true
	a.runner.startErr = errors.New("container recreation failed")
	rec := a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"cowrie","settings":{"bait_profile":"industrial"}}`)
	if rec.Code != http.StatusBadGateway || !decodeAPIError(t, rec).Saved || !bytes.Contains(a.configFile(t), []byte("bait_profile: industrial")) || !slices.Equal(a.runner.recreated, []string{"cowrie"}) {
		t.Fatalf("failed recreation did not retain desired settings: %d %s", rec.Code, rec.Body.String())
	}
	// Exercise the config follower as the UI's next canary-list request does.
	if rec = a.do(http.MethodGet, "/api/canaries", ""); rec.Code != http.StatusOK {
		t.Fatalf("GET canaries after failed recreation: %d %s", rec.Code, rec.Body.String())
	}
	matched := false
	for _, c := range old {
		if !c.Planted || c.Kind != canary.KindCredential || len(c.Values) == 0 {
			continue
		}
		if retained, ok := a.s.canaries.Get(c.ID); !ok || !retained.Historical {
			t.Fatalf("previous credential %s was not retained as historical after failed recreation", c.ID)
		}
		trips, err := a.s.canaries.MatchObservation(canary.Observation{
			Text: c.Values[0], SourceIP: "192.0.2.33", EventKey: "old-cowrie-credential-after-failed-recreation-" + c.ID,
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(trips) != 1 || trips[0].CanaryID != c.ID {
			t.Fatalf("previous container credential %s was no longer watched after failed recreation", c.ID)
		}
		matched = true
	}
	if !matched {
		t.Fatal("no old credential canary exercised")
	}
	newActive := false
	for _, c := range a.s.canaries.List() {
		newActive = newActive || (c.Name == "cowrie bait: OT archive credential" && !c.Historical)
	}
	if !newActive {
		t.Fatal("desired industrial credential missing after failed recreation")
	}
}

func (a *apiTestServer) setting(t *testing.T, name, key string) instance.SettingInfo {
	t.Helper()
	rec := a.do(http.MethodGet, "/api/honeypots/settings?name="+name, "")
	var view honeypotSettingsView
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &view) != nil {
		t.Fatalf("GET %s settings: %d %s", name, rec.Code, rec.Body.String())
	}
	for _, setting := range view.Settings {
		if setting.Key == key {
			return setting
		}
	}
	t.Fatalf("%s setting %s missing", name, key)
	return instance.SettingInfo{}
}

// A scenario is a desired configuration, not proof that the corresponding
// container is live. Its maintenance credential is stable across scenarios.
func TestSettingsPutRefrigerationSiteProfile(t *testing.T) {
	a := newAPITestServer(t, "api-refrigeration-profile", func(c *config.Config) {
		for name := range c.Honeypots {
			c.DisableHoneypot(name)
		}
	})
	initial := a.setting(t, "refrigeration", "site_profile")
	if initial.Set || initial.Value != "" || initial.Effective != "retail" || initial.Type != "choice" ||
		!slices.Equal(initial.Allowed, []string{"retail", "plasma"}) || !strings.Contains(initial.Help, "history across restarts") {
		t.Fatalf("default refrigeration metadata: %+v", initial)
	}
	before := a.configFile(t)
	assertAuthRequired(t, a.h, http.MethodGet, "/api/honeypots/settings?name=refrigeration", "")
	assertAuthRequired(t, a.h, http.MethodPut, "/api/honeypots/settings", `{"name":"refrigeration","settings":{"site_profile":"plasma"}}`)
	for _, body := range []string{
		`{"name":"refrigeration","settings":{"site_profile":"unsupported"}}`,
		`{"name":"refrigeration","settings":{"site_profile":"plasma","unknown":"x"}}`,
		`{"name":"refrigeration","settings":{"site_profile":"plasma\nINJECT=1"}}`,
	} {
		rec := a.do(http.MethodPut, "/api/honeypots/settings", body)
		if rec.Code != http.StatusBadRequest || !bytes.Equal(before, a.configFile(t)) || len(a.runner.cfgs) != 0 {
			t.Fatalf("invalid scene reached runner or changed config: %d %s", rec.Code, rec.Body.String())
		}
		if e := decodeAPIError(t, rec); e.Code != "QP-INPUT-012" || e.Error == "" || strings.Contains(e.Error, "INJECT") {
			t.Fatalf("invalid scene lacks a stable safe error: %+v", e)
		}
	}
	a.runner.running = true
	rec := a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"refrigeration","settings":{"site_profile":"plasma"}}`)
	var response settingsChangeResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &response) != nil || !response.Saved || response.Enabled || response.Recreated || len(a.runner.recreated) != 0 {
		t.Fatalf("saving a disabled scene started a service: %d %s", rec.Code, rec.Body.String())
	}
	if got := a.setting(t, "refrigeration", "site_profile"); !got.Set || got.Value != "plasma" || got.Effective != "" {
		t.Fatalf("saved plasma scene metadata: %+v", got)
	}
	if hp, _ := fileConfig(t, a).GetHoneypotConfig("refrigeration"); hp.Enabled || hp.CustomConfig["site_profile"] != "plasma" {
		t.Fatalf("saved scene was not retained independently of enablement: %+v", hp)
	}
	if rec = a.do(http.MethodPost, "/api/honeypots", `{"name":"refrigeration","enabled":true}`); rec.Code != http.StatusOK {
		t.Fatalf("enable refrigeration: %d %s", rec.Code, rec.Body.String())
	}
	// A prior read must not throttle away the explicit API change's new watch.
	if rec = a.do(http.MethodGet, "/api/canaries", ""); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	current := a.s.canaries.List()
	if len(current) != 1 || !current[0].Planted || current[0].Historical || !current[0].Enabled || len(current[0].Values) != 1 {
		t.Fatalf("enabling the native export did not register one active credential: %+v", current)
	}
	credential := current[0]
	a.runner.startErr = errors.New("private builder details must not be reflected")
	rec = a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"refrigeration","settings":{"site_profile":"retail"}}`)
	if e := decodeAPIError(t, rec); rec.Code != http.StatusBadGateway || !e.Saved || e.Code != "QP-INST-008" || strings.Contains(e.Error, "private builder") || !slices.Equal(a.runner.recreated, []string{"refrigeration"}) {
		t.Fatalf("failed build/recreate did not distinguish saved from applied: %d %s", rec.Code, rec.Body.String())
	}
	if got := a.setting(t, "refrigeration", "site_profile"); got.Value != "retail" || !got.Set {
		t.Fatalf("desired scene lost after failed build: %+v", got)
	}
	a.do(http.MethodGet, "/api/canaries", "")
	if got, ok := a.s.canaries.Get(credential.ID); !ok || got.Historical || !got.Enabled || !slices.Equal(got.Values, credential.Values) {
		t.Fatal("scene switch replaced or retired the same instance archive credential")
	}
	a.runner.startErr = nil
	if rec = a.do(http.MethodPost, "/api/honeypots", `{"name":"refrigeration","enabled":false}`); rec.Code != http.StatusOK {
		t.Fatalf("disable refrigeration: %d %s", rec.Code, rec.Body.String())
	}
	a.do(http.MethodGet, "/api/canaries", "")
	if got, ok := a.s.canaries.Get(credential.ID); !ok || !got.Historical || !got.Enabled {
		t.Fatal("disabled controller's previously exported credential is no longer watched")
	}
	trips, err := a.s.canaries.MatchObservation(canary.Observation{Text: credential.Values[0], SourceIP: "192.0.2.45", EventKey: "refrigeration-copy-after-disable"})
	if err != nil || len(trips) != 1 || trips[0].CanaryID != credential.ID {
		t.Fatalf("previous export reuse was missed: trips=%d err=%v", len(trips), err)
	}
	rec = a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"refrigeration","settings":{"site_profile":""}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear scene: %d %s", rec.Code, rec.Body.String())
	}
	if got := a.setting(t, "refrigeration", "site_profile"); got.Set || got.Value != "" || got.Effective != "retail" {
		t.Fatalf("clearing scenario did not restore retail default: %+v", got)
	}
	if rec = a.do(http.MethodPost, "/api/honeypots", `{"name":"refrigeration","enabled":true}`); rec.Code != http.StatusOK {
		t.Fatalf("re-enable refrigeration: %d %s", rec.Code, rec.Body.String())
	}
	a.do(http.MethodGet, "/api/canaries", "")
	if got, ok := a.s.canaries.Get(credential.ID); !ok || got.Historical || !got.Enabled || len(a.s.canaries.Trips(0)) != 1 {
		t.Fatal("re-enabling lost the original watch or its trip history")
	}
}

// A failed apply can leave Conpot reference files in the old Cowrie process.
// Both those values and the desired refrigeration archive must remain watched.
func TestSettingsPutRefrigerationBaitTarget(t *testing.T) {
	a := newAPITestServer(t, "api-refrigeration-bait", func(c *config.Config) {
		for name := range c.Honeypots {
			c.DisableHoneypot(name)
		}
		c.EnableHoneypot("cowrie")
		c.SetHoneypotCustomConfig("cowrie", map[string]string{"persona": "debian-bookworm", "bait_profile": "industrial", "bait_target": "conpot"})
	})
	manual, err := a.s.canaries.Create(canary.KindWeb, "operator-created", "")
	if err != nil {
		t.Fatal(err)
	}
	old := a.s.canaries.List()
	if initial := a.setting(t, "cowrie", "bait_target"); initial.Value != "conpot" || !slices.Equal(initial.Allowed, []string{"conpot", "refrigeration"}) {
		t.Fatalf("bait target metadata: %+v", initial)
	}
	a.do(http.MethodGet, "/api/canaries", "")
	a.runner.running = true
	a.runner.startErr = errors.New("old support process still running")
	rec := a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"cowrie","settings":{"bait_target":"refrigeration"}}`)
	if e := decodeAPIError(t, rec); rec.Code != http.StatusBadGateway || !e.Saved || e.Code != "QP-INST-008" {
		t.Fatalf("failed target recreation: %d %s", rec.Code, rec.Body.String())
	}
	a.do(http.MethodGet, "/api/canaries", "")
	var active []*canary.Canary
	for _, c := range a.s.canaries.List() {
		if c.Planted && !c.Historical {
			active = append(active, c)
		}
	}
	if len(active) != 1 || !strings.Contains(active[0].Name, "refrigeration") || !active[0].Enabled {
		t.Fatalf("desired refrigeration support credential missing: %+v", active)
	}
	newCredential := active[0]
	oldCredentialMatched := false
	for _, c := range old {
		if !c.Planted {
			continue
		}
		if retained, ok := a.s.canaries.Get(c.ID); !ok || !retained.Historical || !retained.Enabled {
			t.Fatalf("old support value %s disappeared after failed target apply", c.ID)
		}
		if c.Kind == canary.KindCredential && len(c.Values) > 0 {
			trips, err := a.s.canaries.MatchObservation(canary.Observation{Text: c.Values[0], SourceIP: "192.0.2.46", EventKey: "old-support-after-failed-target"})
			if err != nil || len(trips) != 1 || trips[0].CanaryID != c.ID {
				t.Fatalf("old support credential no longer matches: trips=%d err=%v", len(trips), err)
			}
			oldCredentialMatched = true
		}
	}
	if !oldCredentialMatched {
		t.Fatal("no prior archive password was exercised")
	}
	if m, ok := a.s.canaries.Get(manual.ID); !ok || m.Planted || m.Historical {
		t.Fatal("target transition altered a manual canary")
	}
	if hp, _ := fileConfig(t, a).GetHoneypotConfig("refrigeration"); hp.Enabled {
		t.Fatal("choosing reference files enabled the referenced controller")
	}
	before := a.configFile(t)
	calls := len(a.runner.cfgs)
	rec = a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"cowrie","settings":{"bait_target":"unsupported","bait_profile":"ops"}}`)
	if rec.Code != http.StatusBadRequest || !bytes.Equal(before, a.configFile(t)) || len(a.runner.cfgs) != calls {
		t.Fatalf("invalid target partially applied or reached runner: %d %s", rec.Code, rec.Body.String())
	}
	if e := decodeAPIError(t, rec); e.Code != "QP-INPUT-012" {
		t.Fatalf("invalid target lost its stable setting error: %+v", e)
	}
	a.runner.startErr = nil
	rec = a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"cowrie","settings":{"bait_target":""}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear bait target: %d %s", rec.Code, rec.Body.String())
	}
	if got := a.setting(t, "cowrie", "bait_target"); got.Set || got.Value != "" || got.Effective != "conpot" {
		t.Fatalf("clearing target did not restore Conpot default: %+v", got)
	}
	a.do(http.MethodGet, "/api/canaries", "")
	if c, ok := a.s.canaries.Get(newCredential.ID); !ok || !c.Historical || !c.Enabled {
		t.Fatal("previous refrigeration support credential was removed after clearing target")
	}
	trips, err := a.s.canaries.MatchObservation(canary.Observation{Text: newCredential.Values[0], SourceIP: "192.0.2.47", EventKey: "previous-refrigeration-support"})
	if err != nil || len(trips) != 1 || trips[0].CanaryID != newCredential.ID {
		t.Fatalf("previous refrigeration support credential no longer matches: trips=%d err=%v", len(trips), err)
	}
}

// An existing config written before the service existed acquires a disabled
// entry through the API. Editing its scenario alone must never opt it in.
func TestSettingsRefrigerationLegacyBackfillStaysOff(t *testing.T) {
	a := newAPITestServer(t, "api-refrigeration-legacy", nil)
	var legacy map[string]any
	if err := yaml.Unmarshal(a.configFile(t), &legacy); err != nil {
		t.Fatal(err)
	}
	delete(legacy["honeypots"].(map[string]any), "refrigeration")
	data, err := yaml.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.cfg.ConfigPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	a.runner.running = true
	rec := a.do(http.MethodGet, "/api/honeypots/settings?name=refrigeration", "")
	var view honeypotSettingsView
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &view) != nil || view.Enabled || len(view.Settings) != 1 || view.Settings[0].Effective != "retail" || !bytes.Equal(data, a.configFile(t)) {
		t.Fatalf("legacy GET enabled or rewrote config: %d %s", rec.Code, rec.Body.String())
	}
	rec = a.do(http.MethodPut, "/api/honeypots/settings", `{"name":"refrigeration","settings":{"site_profile":"plasma"}}`)
	if rec.Code != http.StatusOK || len(a.runner.started)+len(a.runner.recreated) != 0 {
		t.Fatalf("legacy scene edit started a controller: %d %s", rec.Code, rec.Body.String())
	}
	if hp, ok := fileConfig(t, a).GetHoneypotConfig("refrigeration"); !ok || hp.Enabled || hp.CustomConfig["site_profile"] != "plasma" {
		t.Fatalf("legacy backfill settings not retained safely: %+v", hp)
	}
}

func TestHiFiPreflightErrorsExplainRecoveryWithoutLeakingDiagnostics(t *testing.T) {
	for _, code := range []string{"QP-RES-005", "QP-RES-007", "QP-INST-011", "QP-INST-012", "QP-INST-013", "QP-INST-014", "QP-INST-015", "QP-DOCKER-010", "QP-DOCKER-011", "QP-DOCKER-012"} {
		for _, operation := range []struct {
			name, method, path, body string
			enabled, saved           bool
		}{
			{"enable", http.MethodPost, "/api/honeypots", `{"name":"ssh-proxy","enabled":true}`, false, true},
			{"settings", http.MethodPut, "/api/honeypots/settings", `{"name":"ssh-proxy","settings":{"backends":"3"}}`, true, true},
			{"restart", http.MethodPost, "/api/honeypots/restart", `{"name":"ssh-proxy"}`, true, false},
		} {
			t.Run(code+"/"+operation.name, func(t *testing.T) {
				a := newAPITestServer(t, "api-hifi-preflight", func(c *config.Config) {
					for name := range c.Honeypots {
						c.DisableHoneypot(name)
					}
					c.SetHoneypotCustomConfig("ssh-proxy", map[string]string{"image_source": "local"})
					if operation.enabled {
						c.EnableHoneypot("ssh-proxy")
					}
				})
				a.runner.running = true
				a.runner.startErr = errors.Join(errors.New("PRIVATE Docker output"),
					hostsetup.E(code).WithWhy("PRIVATE host path").WithFix("PRIVATE custom remedy"))
				before := a.configFile(t)
				rec := a.do(operation.method, operation.path, operation.body)
				response := decodeAPIError(t, rec)
				entry, ok := hostsetup.Lookup(code)
				if !ok || rec.Code != http.StatusBadGateway || response.Code != code || response.Saved != operation.saved ||
					!strings.Contains(response.Error, entry.Fix) || strings.Contains(rec.Body.String(), "PRIVATE") {
					t.Fatalf("preflight response: %d %s", rec.Code, rec.Body.String())
				}
				if len(a.runner.started)+len(a.runner.recreated)+len(a.runner.restarted) != 1 {
					t.Fatal("request did not reach the failing runtime operation exactly once")
				}
				if operation.name == "restart" && !bytes.Equal(before, a.configFile(t)) {
					t.Fatal("failed restart changed saved settings")
				}
				hp, _ := fileConfig(t, a).GetHoneypotConfig("ssh-proxy")
				if operation.name == "settings" && hp.CustomConfig["backends"] != "3" {
					t.Fatal("saved settings were rolled back after a preflight refusal")
				}
				if operation.name == "enable" {
					if !hp.Enabled {
						t.Fatal("saved enable preference was rolled back after a preflight refusal")
					}
				}
			})
		}
	}
}
