package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

func TestSetupProfilesAreKnownHoneypots(t *testing.T) {
	cfg := config.Default("profiles")
	for name, hps := range setupProfiles {
		for _, hp := range hps {
			if _, ok := cfg.Honeypots[hp]; !ok {
				t.Errorf("profile %s lists unknown honeypot %q", name, hp)
			}
		}
	}
}

func TestRenderServiceUnit(t *testing.T) {
	u := renderServiceUnit("/usr/local/bin/qpot", "/home/alice", "sensor1", "multi-user.target", true)
	for _, want := range []string{
		"ExecStart=/usr/local/bin/qpot up -i sensor1\n",
		"Environment=HOME=/home/alice\n",
		"After=network-online.target docker.service\n",
		"Restart=on-failure\n",
		"NoNewPrivileges=yes\n",
		"ProtectSystem=full\n",
		"WantedBy=multi-user.target\n",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q:\n%s", want, u)
		}
	}
	user := renderServiceUnit("/home/alice/.local/bin/qpot", "/home/alice", "s", "default.target", false)
	if strings.Contains(user, "ProtectSystem") || !strings.Contains(user, "WantedBy=default.target") {
		t.Errorf("user unit:\n%s", user)
	}
}

func listenLocal(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln, ln.Addr().(*net.TCPAddr).Port
}

func TestFreeWebPortSkipsBusyPort(t *testing.T) {
	_, busy := listenLocal(t)
	cfg := config.Default("t")
	cfg.WebUI.BindAddr = "127.0.0.1"
	cfg.WebUI.Port = busy
	p, ok := freeWebPort(cfg)
	if !ok || p == busy || p < busy {
		t.Fatalf("freeWebPort = %d, %v (busy %d)", p, ok, busy)
	}
	if err := webPortFree(cfg); err == nil || !strings.Contains(err.Error(), "web_ui.port") {
		t.Fatalf("webPortFree on a busy port = %v", err)
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
	if c := webUICheck(context.Background(), cfg); c.Level != "ok" {
		t.Fatalf("own web UI: %+v", c)
	}

	// Another instance: rejects our QPot ID.
	serve(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	if c := webUICheck(context.Background(), cfg); c.Level != "fail" {
		t.Fatalf("foreign web UI passed: %+v", c)
	}
	// Some other HTTP service entirely.
	serve(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>hi</html>")) })
	if c := webUICheck(context.Background(), cfg); c.Level != "fail" {
		t.Fatalf("unrelated HTTP service passed: %+v", c)
	}
}

// A new instance must not take a web UI port another (stopped) instance on the
// host already has configured; that instance would fail on its next start.
func TestCreateInstanceAvoidsConfiguredWebPort(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	_, port := listenLocal(t) // any port number; we close nothing, just need a free-looking base
	first := config.Default("first")
	first.WebUI.Port = port + 1
	if err := config.Save(first); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(first.DataPath, "qpot.id"), []byte(`{"id":"qp_aaaaaaaaaaaaaaaaaaaaaaaa","instance":"first"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	second := config.Default("second")
	second.WebUI.BindAddr = "127.0.0.1"
	second.WebUI.Port = port + 1
	got, ok := freeWebPort(second)
	if !ok || got == port+1 {
		t.Fatalf("freeWebPort = %d, %v; port %d is configured by instance %q", got, ok, port+1, "first")
	}
}
