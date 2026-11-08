package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

func TestRestartAuthAndMethod(t *testing.T) {
	a := newAPITestServer(t, "api-restart-auth", func(c *config.Config) { c.EnableHoneypot("cowrie") })
	a.runner.running = true
	assertAuthRequired(t, a.h, http.MethodPost, "/api/honeypots/restart", `{"name":"cowrie"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/honeypots/restart", strings.NewReader(`{"name":"cowrie"}`))
	req.Header.Set("X-QPot-ID", validTestID)
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain POST: %d, want 415", rec.Code)
	}
	if rec := a.do(http.MethodGet, "/api/honeypots/restart?name=cowrie", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d, want 405", rec.Code)
	}
	if len(a.runner.restarted) != 0 {
		t.Fatalf("restarted without a valid request: %v", a.runner.restarted)
	}
}

func TestRestart(t *testing.T) {
	a := newAPITestServer(t, "api-restart", func(c *config.Config) { c.EnableHoneypot("cowrie") })

	for _, c := range []struct {
		body   string
		status int
		code   string
	}{
		{`{"name":"<script>alert(1)</script>"}`, 400, "QP-INPUT-003"},
		{`{"name":"-f"}`, 400, "QP-INPUT-003"},
		{`{"name":"cowrie","x":1}`, 400, "QP-WEB-004"},
		{`{"name":"conpot"}`, 409, "QP-INST-010"}, // turned off
		{`{"name":"cowrie"}`, 409, "QP-INST-007"},
	} {
		rec := a.do(http.MethodPost, "/api/honeypots/restart", c.body)
		if e := decodeAPIError(t, rec); rec.Code != c.status || e.Code != c.code || strings.Contains(e.Error, "script") {
			t.Errorf("%s: %d %+v, want %d %q", c.body, rec.Code, e, c.status, c.code)
		}
	}
	if len(a.runner.restarted) != 0 {
		t.Fatalf("restarted on a refused request: %v", a.runner.restarted)
	}

	a.runner.running = true
	rec := a.do(http.MethodPost, "/api/honeypots/restart", `{"name":"cowrie"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"restarted":true`) ||
		len(a.runner.restarted) != 1 || a.runner.restarted[0] != "cowrie" {
		t.Fatalf("restart: %d %s %v", rec.Code, rec.Body.String(), a.runner.restarted)
	}

	a.runner.startErr = errors.New("Error response from daemon: secret detail")
	rec = a.do(http.MethodPost, "/api/honeypots/restart", `{"name":"cowrie"}`)
	if e := decodeAPIError(t, rec); rec.Code != http.StatusBadGateway || e.Code != "QP-INST-008" || strings.Contains(e.Error, "secret detail") {
		t.Fatalf("failed restart: %d %+v", rec.Code, e)
	}

	a.runner.startErr = nil
	a.s.api.change.Lock()
	rec = a.do(http.MethodPost, "/api/honeypots/restart", `{"name":"cowrie"}`)
	a.s.api.change.Unlock()
	if e := decodeAPIError(t, rec); rec.Code != http.StatusConflict || e.Code != "QP-INST-009" {
		t.Fatalf("restart during another change: %d %+v", rec.Code, e)
	}
}
