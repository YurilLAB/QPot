package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/instance"
)

// fakeDocker puts a `docker` on PATH that logs each invocation to a file and
// reports cowrie as the only running service. It returns the log path.
func fakeDocker(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake docker is a shell script")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls.log")
	script := `#!/bin/sh
echo "$*" >> "` + logPath + `"
case "$*" in
  *"ps -q"*) echo deadbeef ;;
  *"ps --format json"*) echo '{"Service":"cowrie","State":"running","Health":""}' ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil { // #nosec G306 -- test helper must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

// TestHoneypotListQueriesDockerOnce: GET /api/honeypots asked Docker for the
// whole instance status once per configured honeypot (27 by default, two
// docker runs each), so every dashboard refresh started ~54 docker processes
// and a busy host could run past the server's 15 s write timeout.
func TestHoneypotListQueriesDockerOnce(t *testing.T) {
	logPath := fakeDocker(t)

	cfg := config.Default("hp-list")
	cfg.DataPath = t.TempDir()
	cfg.QPotID = validTestID
	cfg.WebUI.QPotIDAuth = true
	cfg.Security.SandboxMode = "none"
	cfg.EnableHoneypot("cowrie")
	mgr, err := instance.NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{config: cfg, manager: mgr, mux: http.NewServeMux()}
	s.setupRoutes()

	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, authReq(http.MethodGet, "/api/honeypots", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var list []struct {
		Name    string `json:"name"`
		Running bool   `json:"running"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != len(cfg.SnapshotHoneypots()) || len(list) < 2 {
		t.Fatalf("listed %d honeypots, want %d", len(list), len(cfg.SnapshotHoneypots()))
	}
	for _, hp := range list {
		if want := hp.Name == "cowrie"; hp.Running != want {
			t.Errorf("%s running = %v, want %v", hp.Name, hp.Running, want)
		}
	}

	data, _ := os.ReadFile(logPath)
	calls := strings.Count(string(data), "\n")
	if calls > 2 {
		t.Fatalf("GET /api/honeypots ran docker %d times for %d honeypots, want at most 2", calls, len(list))
	}
}

// TestHoneypotPortsAreTheHostPorts: the dashboard, the overview and the
// security list showed each honeypot's config port (cowrie's 2222), which no
// attacker reaches: the host publishes cowrie's 22 and 23 on ports the
// instance allocates. /api/honeypots and /api/overview give those host ports.
func TestHoneypotPortsAreTheHostPorts(t *testing.T) {
	cfg := config.Default("hp-ports")
	cfg.DataPath = t.TempDir()
	cfg.QPotID = validTestID
	cfg.WebUI.QPotIDAuth = true
	cfg.EnableHoneypot("cowrie")
	cfg.DisableHoneypot("dionaea")
	s := &Server{config: cfg, database: &fakeDB{}, mux: http.NewServeMux()}
	s.setupRoutes()
	want := instance.HostPortMappings(cfg)["cowrie"]
	if len(want) < 2 {
		t.Fatalf("cowrie publishes %v, want its ssh and telnet ports", want)
	}
	type hp struct {
		Name      string                 `json:"name"`
		HostPorts []instance.PortMapping `json:"host_ports"`
	}
	check := func(what string, list []hp) {
		t.Helper()
		seen := 0
		for _, h := range list {
			switch h.Name {
			case "cowrie":
				seen++
				if len(h.HostPorts) != len(want) {
					t.Fatalf("%s: cowrie host_ports = %v, want %v", what, h.HostPorts, want)
				}
				for i := range want {
					if h.HostPorts[i] != want[i] {
						t.Errorf("%s: cowrie host_ports = %v, want %v", what, h.HostPorts, want)
					}
				}
			case "dionaea":
				seen++
				if h.HostPorts == nil || len(h.HostPorts) != 0 {
					t.Errorf("%s: a honeypot that is off publishes nothing: host_ports = %#v, want []", what, h.HostPorts)
				}
			}
		}
		if seen != 2 {
			t.Errorf("%s: listed %d of cowrie and dionaea", what, seen)
		}
	}

	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, authReq(http.MethodGet, "/api/honeypots", ""))
	var list []hp
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("GET /api/honeypots: %d %v %s", rec.Code, err, rec.Body.String())
	}
	check("/api/honeypots", list)

	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, authReq(http.MethodGet, "/api/overview", ""))
	var ov struct {
		Instance  string `json:"instance"`
		Honeypots []hp   `json:"honeypots"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ov); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("GET /api/overview: %d %v %s", rec.Code, err, rec.Body.String())
	}
	if ov.Instance != "hp-ports" {
		t.Errorf("the overview lost its other fields: instance %q", ov.Instance)
	}
	check("/api/overview", ov.Honeypots)
}
