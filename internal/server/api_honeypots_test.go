package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/instance"
)

// fakeDockerOnPath puts a docker command that succeeds at everything first
// on PATH, so a Manager's docker calls pass without Docker.
func fakeDockerOnPath(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	name, body := "docker", "#!/bin/sh\nexit 0\n"
	if runtime.GOOS == "windows" {
		name, body = "docker.cmd", "@exit /b 0\r\n"
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o700); err != nil { // #nosec G306 -- test helper; must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// changeConfigFile changes the instance's config file as the CLI does,
// behind the running server's back.
func changeConfigFile(t *testing.T, a *apiTestServer, change func(*config.Config)) {
	t.Helper()
	data, err := os.ReadFile(a.cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(data, a.cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	change(cfg)
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
}

func fileConfig(t *testing.T, a *apiTestServer) *config.Config {
	t.Helper()
	cfg, err := config.Parse(a.configFile(t), a.cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// Turning a honeypot on from the web UI keeps what the CLI changed in the
// config file since the server started: the server once saved its own copy
// from start-up over it.
func TestHoneypotToggleKeepsFileChanges(t *testing.T) {
	fakeDockerOnPath(t)
	a := newAPITestServer(t, "api-toggle-keep", func(c *config.Config) { c.DisableHoneypot("dionaea") })
	mgr, err := instance.NewManager(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.s.manager = mgr

	changeConfigFile(t, a, func(c *config.Config) {
		c.SetHoneypotCustomConfig("cowrie", map[string]string{"persona": "rhel-9"})
		c.Alerts.Threshold = 77
	})
	rec := a.do(http.MethodPost, "/api/honeypots", `{"name":"dionaea","enabled":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST: %d %s", rec.Code, rec.Body.String())
	}
	got := fileConfig(t, a)
	hp, _ := got.GetHoneypotConfig("cowrie")
	if hp.CustomConfig["persona"] != "rhel-9" || got.Alerts.Threshold != 77 {
		t.Fatalf("the CLI's changes were lost: persona %q, threshold %d", hp.CustomConfig["persona"], got.Alerts.Threshold)
	}
	if !slices.Contains(got.GetEnabledHoneypots(), "dionaea") {
		t.Fatal("dionaea is not on in the file")
	}
	// GET shows the file as it is now.
	var list []map[string]any
	rec = a.do(http.MethodGet, "/api/honeypots", "")
	if json.Unmarshal(rec.Body.Bytes(), &list) != nil {
		t.Fatalf("GET: %s", rec.Body.String())
	}
	changeConfigFile(t, a, func(c *config.Config) { c.DisableHoneypot("cowrie") })
	rec = a.do(http.MethodGet, "/api/honeypots", "")
	list = nil
	if json.Unmarshal(rec.Body.Bytes(), &list) != nil {
		t.Fatalf("GET: %s", rec.Body.String())
	}
	for _, h := range list {
		if h["name"] == "cowrie" && h["enabled"] != false {
			t.Fatalf("GET does not show the CLI's change: %v", h)
		}
	}
}

func TestHoneypotToggle(t *testing.T) {
	a := newAPITestServer(t, "api-toggle", func(c *config.Config) { c.DisableHoneypot("dionaea") })
	var resp honeypotToggleResponse

	// Instance stopped: saved, nothing started.
	rec := a.do(http.MethodPost, "/api/honeypots", `{"name":"dionaea","enabled":true}`)
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil ||
		resp.Status != "ok" || !resp.Enabled || !resp.Saved || resp.InstanceRunning || resp.Applied || len(a.runner.started) != 0 {
		t.Fatalf("on, stopped: %d %s %+v", rec.Code, rec.Body.String(), a.runner)
	}
	if !slices.Contains(fileConfig(t, a).GetEnabledHoneypots(), "dionaea") || !slices.Contains(a.s.config.GetEnabledHoneypots(), "dionaea") {
		t.Fatal("not on in the file or the server's config")
	}

	// Running: stopped, then started.
	a.runner.running = true
	rec = a.do(http.MethodPost, "/api/honeypots", `{"name":"dionaea","enabled":false}`)
	resp = honeypotToggleResponse{}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil || resp.Enabled || !resp.Applied ||
		!slices.Equal(a.runner.stopped, []string{"dionaea"}) || !strings.Contains(resp.Message, "stopped") {
		t.Fatalf("off, running: %d %s", rec.Code, rec.Body.String())
	}
	rec = a.do(http.MethodPost, "/api/honeypots", `{"name":"dionaea","enabled":true}`)
	if rec.Code != http.StatusOK || !slices.Equal(a.runner.started, []string{"dionaea"}) {
		t.Fatalf("on, running: %d %s", rec.Code, rec.Body.String())
	}

	// Docker fails: saved, 502 with the log to read.
	a.runner.startErr = errors.New("compose up: no such image")
	changeConfigFile(t, a, func(c *config.Config) { c.DisableHoneypot("heralding") })
	rec = a.do(http.MethodPost, "/api/honeypots", `{"name":"heralding","enabled":true}`)
	if e := decodeAPIError(t, rec); rec.Code != http.StatusBadGateway || !e.Saved || e.Code != "QP-INST-008" ||
		!strings.Contains(e.Error, "/api/logs?honeypot=heralding") || strings.Contains(e.Error, "no such image") {
		t.Fatalf("docker fails: %d %+v", rec.Code, e)
	}
	if !slices.Contains(fileConfig(t, a).GetEnabledHoneypots(), "heralding") {
		t.Fatal("not saved although the answer says so")
	}
	a.runner.startErr = nil
}

func TestHoneypotToggleRefuses(t *testing.T) {
	a := newAPITestServer(t, "api-toggle-no", nil)
	a.runner.running = true
	before := a.configFile(t)
	for _, c := range []struct {
		body string
		code string
	}{
		{`{"name":"nosuch","enabled":true}`, "QP-INPUT-003"},
		{`{"name":"-rm","enabled":false}`, "QP-INPUT-003"},
		{`{"name":"cowrie"}`, ""},
		{`{"name":"cowrie","enabled":"yes"}`, ""},
		{`{"name":"cowrie","enabled":true,"force":true}`, ""},
		{`{"name":"cowrie","enabled":true} {}`, ""},
		{`{"name":"` + strings.Repeat("a", 5000) + `","enabled":true}`, ""},
		{`not json`, ""},
	} {
		rec := a.do(http.MethodPost, "/api/honeypots", c.body)
		if e := decodeAPIError(t, rec); rec.Code != http.StatusBadRequest || e.Code != c.code {
			t.Errorf("%.40s: %d %+v", c.body, rec.Code, e)
		}
	}

	// An LLM honeypot without its provider: 400 naming the settings.
	rec := a.do(http.MethodPost, "/api/honeypots", `{"name":"galah","enabled":true}`)
	if e := decodeAPIError(t, rec); rec.Code != http.StatusBadRequest || e.Code != "QP-INPUT-012" ||
		!slices.Equal(e.Needs, []string{"llm_provider", "llm_model"}) {
		t.Fatalf("galah: %d %+v", rec.Code, e)
	}

	// Another change running: 409.
	a.s.api.change.Lock()
	rec = a.do(http.MethodPost, "/api/honeypots", `{"name":"cowrie","enabled":false}`)
	a.s.api.change.Unlock()
	if rec.Code != http.StatusConflict {
		t.Fatalf("busy: %d", rec.Code)
	}

	if string(before) != string(a.configFile(t)) || len(a.runner.started)+len(a.runner.stopped) != 0 {
		t.Fatalf("a refused request changed something: %+v", a.runner)
	}
}
