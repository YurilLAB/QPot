package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/hostsetup"
)

func exposureConfig(t *testing.T, ui config.WebUIConfig) *config.Config {
	t.Helper()
	cfg := config.Default("exposure")
	cfg.QPotID = validTestID
	cfg.DataPath = t.TempDir()
	cfg.Database.Host, cfg.Database.Port = "127.0.0.1", 1 // refused at once
	cfg.Intelligence.Enabled = false
	ui.Enabled = true
	cfg.WebUI = ui
	return cfg
}

// TestAuthMatrixOverTheHandlerChain sends, for every authentication mode, a
// request with no credential, a wrong one and the right one through the real
// handler chain. Only the "none" mode lets a request without a credential
// reach the API, and Start refuses that mode off loopback (next test).
func TestAuthMatrixOverTheHandlerChain(t *testing.T) {
	type attempt struct {
		name string
		set  func(*http.Request)
		want map[string]int // by auth mode
	}
	attempts := []attempt{
		{"no credential", func(*http.Request) {},
			map[string]int{"qpot-id": http.StatusUnauthorized, "basic": http.StatusUnauthorized, "none": http.StatusOK}},
		{"wrong QPot ID", func(r *http.Request) { r.Header.Set("X-QPot-ID", "qp_zzzzzzzzzzzzzzzzzzzzzzzz") },
			map[string]int{"qpot-id": http.StatusForbidden, "basic": http.StatusUnauthorized, "none": http.StatusOK}},
		{"right QPot ID", func(r *http.Request) { r.Header.Set("X-QPot-ID", validTestID) },
			map[string]int{"qpot-id": http.StatusOK, "basic": http.StatusUnauthorized, "none": http.StatusOK}},
		{"wrong password", func(r *http.Request) { r.SetBasicAuth("admin", "nope") },
			map[string]int{"qpot-id": http.StatusUnauthorized, "basic": http.StatusUnauthorized, "none": http.StatusOK}},
		{"right password", func(r *http.Request) { r.SetBasicAuth("admin", "s3cret-pass") },
			map[string]int{"qpot-id": http.StatusUnauthorized, "basic": http.StatusOK, "none": http.StatusOK}},
		{"empty password", func(r *http.Request) { r.SetBasicAuth("admin", "") },
			map[string]int{"qpot-id": http.StatusUnauthorized, "basic": http.StatusUnauthorized, "none": http.StatusOK}},
	}
	modes := []struct {
		name string
		ui   config.WebUIConfig
	}{
		{"qpot-id", config.WebUIConfig{QPotIDAuth: true, BindAddr: "127.0.0.1"}},
		{"qpot-id", config.WebUIConfig{QPotIDAuth: true, Username: "admin", Password: "s3cret-pass", BindAddr: "0.0.0.0"}},
		{"basic", config.WebUIConfig{Username: "admin", Password: "s3cret-pass", BindAddr: "0.0.0.0"}},
		{"none", config.WebUIConfig{Username: "admin", BindAddr: "127.0.0.1"}},
		{"none", config.WebUIConfig{BindAddr: "127.0.0.1"}},
	}
	for _, mode := range modes {
		cfg := exposureConfig(t, mode.ui)
		if got := cfg.WebUI.AuthMode(); got != mode.name {
			t.Fatalf("%+v: auth mode %q, want %q", mode.ui, got, mode.name)
		}
		s, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		ts := httptest.NewServer(securityHeaders(s.authMiddleware(s.mux)))
		for _, a := range attempts {
			// /api/instance needs neither Docker nor the database.
			req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/instance", nil)
			a.set(req)
			resp, err := ts.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != a.want[mode.name] {
				t.Errorf("%s (bind %s), %s: status %d, want %d", mode.name, mode.ui.BindAddr, a.name, resp.StatusCode, a.want[mode.name])
			}
		}
		ts.Close()
	}
}

// TestStartRefusesLoginlessExposure: the server never listens with no login
// on an address other computers can reach, and does listen in every other
// combination of authentication and bind address.
func TestStartRefusesLoginlessExposure(t *testing.T) {
	auths := map[string]config.WebUIConfig{
		"qpot-id":                          {QPotIDAuth: true},
		"basic":                            {Username: "admin", Password: "s3cret-pass"},
		"none":                             {},
		"none (username without password)": {Username: "admin"},
	}
	for authName, ui := range auths {
		for _, bind := range []string{"127.0.0.1", "0.0.0.0", ""} {
			t.Run(fmt.Sprintf("%s on %q", authName, bind), func(t *testing.T) {
				ui := ui
				ui.BindAddr = bind
				// A free port, found on the address the server will use.
				probe := bind
				if probe == "" {
					probe = "0.0.0.0"
				}
				ln, err := net.Listen("tcp", net.JoinHostPort(probe, "0"))
				if err != nil {
					t.Skipf("cannot listen on %s here: %v", probe, err)
				}
				ui.Port = ln.Addr().(*net.TCPAddr).Port
				ln.Close()
				cfg := exposureConfig(t, ui)
				s, err := New(cfg)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- s.Start(ctx) }()

				refused := ui.AuthMode() == "none" && bind != "127.0.0.1"
				url := fmt.Sprintf("http://127.0.0.1:%d/", ui.Port)
				if refused {
					select {
					case err := <-done:
						var coded *hostsetup.Error
						if !errors.As(err, &coded) || coded.Code != "QP-WEB-005" {
							t.Fatalf("Start returned %v, want QP-WEB-005", err)
						}
						if !strings.Contains(coded.Cause(), "bind_addr") {
							t.Errorf("the refusal does not name the setting: %s", coded.Cause())
						}
					case <-time.After(10 * time.Second):
						t.Fatal("Start did not refuse")
					}
					if resp, err := http.Get(url); err == nil {
						resp.Body.Close()
						t.Fatal("a refused server is listening")
					}
					return
				}
				deadline := time.Now().Add(15 * time.Second)
				for {
					resp, err := http.Get(url)
					if err == nil {
						resp.Body.Close()
						break
					}
					select {
					case err := <-done:
						t.Fatalf("Start returned early: %v", err)
					default:
					}
					if time.Now().After(deadline) {
						t.Fatalf("server never answered on %s: %v", url, err)
					}
					time.Sleep(50 * time.Millisecond)
				}
				cancel()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
					t.Fatal("Start did not return after cancellation")
				}
			})
		}
	}
}
