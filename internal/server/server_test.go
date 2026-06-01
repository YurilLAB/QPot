package server

import (
	"io"
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

// TestServerEndToEnd brings up the real server (via New) over httptest and
// exercises the full handler chain: static UI serving, auth gating on the API,
// and that the unauthenticated dashboard never carries the credential. This is
// the closest we can get to "is the web UI actually working" without Docker.
func TestServerEndToEnd(t *testing.T) {
	cfg := config.Default("e2e-test")
	cfg.QPotID = validTestID
	cfg.WebUI.QPotIDAuth = true
	// Point the DB at nowhere so New's connect attempt fails fast and the
	// server comes up DB-less (endpoints that need it will 5xx, which is fine
	// for this test — we only assert routing + auth here).
	cfg.Database.Host = "127.0.0.1"
	cfg.Database.Port = 1 // unused port → connection refused

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("server.New failed: %v", err)
	}

	ts := httptest.NewServer(s.authMiddleware(s.mux))
	defer ts.Close()
	client := ts.Client()

	// 1. Dashboard loads without auth and does not leak the credential.
	resp, err := client.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /: status %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "<html") && !strings.Contains(body, "<!DOCTYPE") {
		t.Error("GET / did not return HTML dashboard")
	}
	if strings.Contains(body, validTestID) {
		t.Error("GET / leaked the QPot ID credential")
	}

	// 2. API requires auth.
	resp, err = client.Get(ts.URL + "/api/status")
	if err != nil {
		t.Fatalf("GET /api/status: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated GET /api/status: status %d, want 401", resp.StatusCode)
	}

	// 3. Wrong credential is rejected.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/status", nil)
	req.Header.Set("X-QPot-ID", "qp_zzzzzzzzzzzzzzzzzzzzzzzz")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /api/status (wrong id): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("wrong-credential GET /api/status: status %d, want 403", resp.StatusCode)
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

// TestAuthErrorDoesNotLeakCredential is the critical regression guard: an
// unauthenticated (or wrongly-authenticated) request must never receive the
// QPot ID credential back in the error body. sendError previously embedded it,
// turning every protected endpoint into a credential oracle.
func TestAuthErrorDoesNotLeakCredential(t *testing.T) {
	s := newTestServer(true)
	h := s.withQPotAuth(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })

	cases := []struct {
		name   string
		header string
	}{
		{"no credential", ""},
		{"wrong credential", "qp_zzzzzzzzzzzzzzzzzzzzzzzz"},
		{"malformed credential", "not-a-qpot-id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
			if tc.header != "" {
				req.Header.Set("X-QPot-ID", tc.header)
			}
			rec := httptest.NewRecorder()
			h(rec, req)
			if rec.Code == http.StatusOK {
				t.Fatalf("expected auth failure, got 200")
			}
			if strings.Contains(rec.Body.String(), validTestID) {
				t.Errorf("auth-failure body leaked the QPot ID: %s", rec.Body.String())
			}
		})
	}
}

func TestIsKnownHoneypot(t *testing.T) {
	s := &Server{config: &config.Config{Honeypots: map[string]config.HoneypotConfig{
		"cowrie": {}, "dionaea": {},
	}}}
	for name, want := range map[string]bool{
		"cowrie": true, "dionaea": true,
		"": false, "--help": false, "unknown": false, "cowrie; rm": false,
	} {
		if got := s.isKnownHoneypot(name); got != want {
			t.Errorf("isKnownHoneypot(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestHandleClusterStandalone verifies the Pairing endpoint reports a standalone
// node (no cluster.json) as not clustered rather than erroring.
func TestHandleClusterStandalone(t *testing.T) {
	s := &Server{config: &config.Config{QPotID: validTestID}, mux: http.NewServeMux()}
	req := httptest.NewRequest(http.MethodGet, "/api/cluster", nil)
	rec := httptest.NewRecorder()
	s.handleCluster(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"clustered":false`) {
		t.Errorf("standalone node should report clustered:false, got %s", rec.Body.String())
	}
}

func TestHandleClusterRejectsNonGET(t *testing.T) {
	s := &Server{config: &config.Config{QPotID: validTestID}, mux: http.NewServeMux()}
	req := httptest.NewRequest(http.MethodPost, "/api/cluster", nil)
	rec := httptest.NewRecorder()
	s.handleCluster(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/cluster: status %d, want 405", rec.Code)
	}
}
