package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

// validTestID is a syntactically valid QPot ID (qp_ + 24 chars = 27 total).
const validTestID = "qp_abcdefghijklmnopqrstuvwx"

func newTestServer(qpotIDAuth bool) *Server {
	return &Server{
		config: &config.Config{
			QPotID: validTestID,
			WebUI:  config.WebUIConfig{QPotIDAuth: qpotIDAuth},
		},
		mux: http.NewServeMux(),
	}
}

// TestStaticIndexDoesNotLeakQPotID guards the critical fix: the QPot ID is the
// API credential, and the index page is served without authentication, so it
// must never contain the credential.
func TestStaticIndexDoesNotLeakQPotID(t *testing.T) {
	s := newTestServer(true)

	for _, path := range []string{"/", "/static/index.html"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		s.handleStatic(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status = %d, want 200", path, rec.Code)
		}
		body := rec.Body.String()
		if strings.Contains(body, validTestID) {
			t.Errorf("GET %s leaked the QPot ID credential in the response body", path)
		}
		if strings.Contains(body, "window.QPOT_ID") {
			t.Errorf("GET %s still injects window.QPOT_ID", path)
		}
	}
}

func TestStaticRejectsNonGET(t *testing.T) {
	s := newTestServer(true)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	s.handleStatic(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /: status = %d, want 405", rec.Code)
	}
}

func TestWithQPotAuth(t *testing.T) {
	s := newTestServer(true)
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	h := s.withQPotAuth(ok)

	cases := []struct {
		name   string
		header string
		query  string
		want   int
	}{
		{"missing id", "", "", http.StatusUnauthorized},
		{"bad format", "not-a-qpot-id", "", http.StatusUnauthorized},
		{"wrong id same format", "qp_zzzzzzzzzzzzzzzzzzzzzzzz", "", http.StatusForbidden},
		{"correct id header", validTestID, "", http.StatusOK},
		{"correct id query", "", validTestID, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url := "/api/status"
			if tc.query != "" {
				url += "?qpot_id=" + tc.query
			}
			req := httptest.NewRequest(http.MethodGet, url, nil)
			if tc.header != "" {
				req.Header.Set("X-QPot-ID", tc.header)
			}
			rec := httptest.NewRecorder()
			h(rec, req)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

// TestWithQPotAuthDisabled verifies auth is bypassed when disabled.
func TestWithQPotAuthDisabled(t *testing.T) {
	s := newTestServer(false)
	called := false
	h := s.withQPotAuth(func(w http.ResponseWriter, r *http.Request) { called = true })
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	h(httptest.NewRecorder(), req)
	if !called {
		t.Error("handler not called when QPotIDAuth disabled")
	}
}
