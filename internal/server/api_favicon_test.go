package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

// /favicon.ico is the embedded icon, public like the other static files: a
// browser asks for it on its own (an image or a JSON answer opened in a tab)
// and sends no QPot ID or Basic credentials with it.
func TestFavicon(t *testing.T) {
	want, err := staticFS.ReadFile("static/assets/img/favicon.ico")
	if err != nil || len(want) == 0 {
		t.Fatalf("embedded icon: %v", err)
	}
	for _, mode := range []struct {
		name string
		web  config.WebUIConfig
	}{
		{"QPot ID auth", config.WebUIConfig{QPotIDAuth: true}},
		{"Basic auth", config.WebUIConfig{Username: "admin", Password: "pw-" + "basic"}},
	} {
		s := &Server{config: &config.Config{QPotID: validTestID, WebUI: mode.web}, mux: http.NewServeMux()}
		s.setupRoutes()
		h := securityHeaders(s.authMiddleware(s.mux))

		for _, method := range []string{http.MethodGet, http.MethodHead} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(method, "/favicon.ico", nil))
			if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/x-icon" {
				t.Fatalf("%s: %s /favicon.ico: %d %q", mode.name, method, rec.Code, rec.Header().Get("Content-Type"))
			}
			if method == http.MethodGet && !bytes.Equal(rec.Body.Bytes(), want) {
				t.Fatalf("%s: the body is not the embedded icon (%d bytes)", mode.name, rec.Body.Len())
			}
			if rec.Header().Get("WWW-Authenticate") != "" {
				t.Fatalf("%s: the icon asks for a login", mode.name)
			}
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/favicon.ico", nil))
		if rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("%s: POST /favicon.ico: %d", mode.name, rec.Code)
		}
		// Only that one file is public: a neighbour stays unknown.
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/favicon.png", nil))
		if rec.Code == http.StatusOK {
			t.Errorf("%s: /favicon.png answered 200", mode.name)
		}
	}
}
