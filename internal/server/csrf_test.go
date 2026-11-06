package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/config"
)

// newBasicAuthServer is a server in the documented basic-auth mode
// (qpot_id_auth: false with a web_ui username/password), with canaries on so
// there is a state-changing endpoint that needs no Docker.
func newBasicAuthServer(t *testing.T) *Server {
	t.Helper()
	cs, err := canary.NewStore(t.TempDir(), 0)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	s := &Server{
		config: &config.Config{
			QPotID: validTestID,
			WebUI:  config.WebUIConfig{QPotIDAuth: false, Username: "admin", Password: "s3cret-pass"},
			Canary: config.CanaryConfig{Enabled: true, Decoy: "notfound"},
		},
		mux:      http.NewServeMux(),
		canaries: cs,
	}
	s.setupRoutes()
	return s
}

// TestBasicAuthRejectsCrossSiteFormPost: browsers attach cached Basic
// credentials to a cross-site form POST, and an HTML form can send a JSON body
// as text/plain (<form enctype="text/plain">). Without a JSON content-type
// requirement any web page the operator visited could create (or, via the
// honeypot toggle, disable) things through the logged-in browser.
func TestBasicAuthRejectsCrossSiteFormPost(t *testing.T) {
	s := newBasicAuthServer(t)
	h := s.authMiddleware(s.mux)

	// What <form enctype="text/plain" method=post> with an input named
	// `{"kind":"web","name":"x","memo":"` and value `"}` submits.
	body := `{"kind":"web","name":"x","memo":"="}`
	for _, ct := range []string{"text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", ""} {
		req := httptest.NewRequest(http.MethodPost, "/api/canaries", strings.NewReader(body))
		req.SetBasicAuth("admin", "s3cret-pass")
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("POST with Content-Type %q: status %d, want 415", ct, rec.Code)
		}
	}
	if n := len(s.canaries.List()); n != 0 {
		t.Fatalf("a form-encodable POST created %d canaries", n)
	}

	// The dashboard and the CLI send application/json and still work.
	req := httptest.NewRequest(http.MethodPost, "/api/canaries", strings.NewReader(body))
	req.SetBasicAuth("admin", "s3cret-pass")
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("JSON POST: status %d body %s", rec.Code, rec.Body.String())
	}
	if n := len(s.canaries.List()); n != 1 {
		t.Fatalf("JSON POST created %d canaries, want 1", n)
	}

	// Reads and the body-less DELETE are unaffected.
	req = httptest.NewRequest(http.MethodGet, "/api/canaries", nil)
	req.SetBasicAuth("admin", "s3cret-pass")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: status %d", rec.Code)
	}
}
