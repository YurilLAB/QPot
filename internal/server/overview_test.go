package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/overview"
)

// /api/overview is the local replacement for the former ypanel phone-home
// agent: it must require the QPot ID and describe this instance.
func TestHandleOverview(t *testing.T) {
	cfg := config.Default("ov")
	cfg.QPotID = validTestID
	cfg.WebUI.QPotIDAuth = true
	s := &Server{config: cfg, database: &fakeDB{}, mux: http.NewServeMux()}
	h := s.withQPotAuth(s.handleOverview)

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/api/overview", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no QPot ID: status %d, want 401", rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.Header.Set("X-QPot-ID", validTestID)
	rec = httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var ov overview.Overview
	if err := json.Unmarshal(rec.Body.Bytes(), &ov); err != nil {
		t.Fatal(err)
	}
	if ov.Instance != "ov" || !ov.DatabaseOK || len(ov.Honeypots) == 0 || ov.Hostname == "" {
		t.Errorf("overview = %+v", ov)
	}
	if body := rec.Body.String(); strings.Contains(body, validTestID) {
		t.Error("overview leaked the QPot ID")
	}

	req = httptest.NewRequest(http.MethodPost, "/api/overview", nil)
	req.Header.Set("X-QPot-ID", validTestID)
	rec = httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: status %d, want 405", rec.Code)
	}
}

// TestOverviewReadsTheConfigFile: a honeypot turned off with the CLI (qpot
// honeypot disable, which stops it) stayed "on" in the overview, which read
// the server's start-up copy of the config; the honeypot list and the
// security list read the file and said it was off.
func TestOverviewReadsTheConfigFile(t *testing.T) {
	a := newAPITestServer(t, "ov-file", func(c *config.Config) { c.EnableHoneypot("adbhoney") })
	changeConfigFile(t, a, func(c *config.Config) { c.DisableHoneypot("adbhoney") })
	rec := a.do(http.MethodGet, "/api/overview", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var ov overview.Overview
	if err := json.Unmarshal(rec.Body.Bytes(), &ov); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range ov.Honeypots {
		if h.Name == "adbhoney" {
			found = true
			if h.Enabled {
				t.Error("the overview says adbhoney is on; the config file says it is off")
			}
		}
	}
	if !found {
		t.Error("adbhoney is not in the overview")
	}
}
