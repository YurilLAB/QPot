package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
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

	for _, path := range []string{"/", "/index.html", "/dashboard", "/map/"} {
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

// TestStaticServesRealDashboard guards against the embedded UI silently
// regressing to a placeholder. The binary embeds and serves the
// internal/server/static directory; for a long time that directory held a
// 49-byte stub (<body>QPot</body>) while the real, API-wired dashboard sat unused under
// web/static and was never served. A generic "is it HTML?" check (as in
// TestServerEndToEnd) passes for the stub too, so we assert the served page
// carries the dashboard's actual wiring: the QPot-ID auth flow and live calls
// to the real API surface. If someone reintroduces a stub, this fails.
func TestStaticServesRealDashboard(t *testing.T) {
	s := newTestServer(true)
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec := httptest.NewRecorder()
	s.handleStatic(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /dashboard: status %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	// The dashboard must wire up the credential-based auth the API enforces.
	for _, marker := range []string{
		"X-QPot-ID",                      // the header withQPotAuth checks
		"localStorage.getItem('qpot_id'", // credential persisted client-side
		"const API_BASE = '/api'",        // base path for every API call
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("served dashboard missing auth/wiring marker %q (serving a stub?)", marker)
		}
	}

	// It must actually call the live endpoints registered on the mux. Each of
	// these has a corresponding s.mux.HandleFunc("/api/...") route.
	for _, ep := range []string{"/status", "/honeypots", "/events", "/stats"} {
		if !strings.Contains(body, "${API_BASE}"+ep) {
			t.Errorf("served dashboard never calls the %q API endpoint", ep)
		}
	}

	// A stub would be tiny; the real dashboard is a full single-page app.
	if len(body) < 2000 {
		t.Errorf("served dashboard is only %d bytes; looks like a placeholder, not the real UI", len(body))
	}
}

// unrouted reports whether an answer is the mux's own 404 - no route took
// the request. A handler's JSON 404 (an unknown canary) proves the route
// exists, so only a 404 whose body is the mux's text, or not JSON, counts.
func unrouted(code int, body []byte) bool {
	return code == http.StatusNotFound && (string(body) == "404 page not found\n" || !json.Valid(body))
}

// apiRouted sends GET /api<ep> through srv's mux, authenticated, and reports
// whether a route took it.
func apiRouted(srv *Server, ep string) bool {
	req := httptest.NewRequest(http.MethodGet, "/api"+ep, nil)
	req.Header.Set("X-QPot-ID", validTestID)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	return !unrouted(rec.Code, rec.Body.Bytes())
}

// dashboardFetches returns the ${API_BASE}/<ep> endpoints page fetches.
func dashboardFetches(page string) []string {
	re := regexp.MustCompile(`\$\{API_BASE\}(/[a-zA-Z][a-zA-Z0-9/_-]*)`)
	seen := map[string]bool{}
	var eps []string
	for _, m := range re.FindAllStringSubmatch(page, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			eps = append(eps, m[1])
		}
	}
	return eps
}

// TestEmbeddedDashboardEndpointsAreRouted is the other half of "connected":
// every ${API_BASE}/<ep> the dashboard fetches must have a matching route
// registered in setupRoutes. This catches the dashboard calling an endpoint
// the server doesn't serve (a 404 in the live UI) without needing a browser.
func TestEmbeddedDashboardEndpointsAreRouted(t *testing.T) {
	data, err := staticFS.ReadFile("static/dashboard.html")
	if err != nil {
		t.Fatalf("read embedded dashboard: %v", err)
	}
	page := string(data)

	// Bring up a real server so its mux carries the production routes.
	cfg := config.Default("route-test")
	cfg.QPotID = validTestID
	cfg.Database.Host = "127.0.0.1"
	cfg.Database.Port = 1
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	// The dashboard must authenticate; reaching a handler proves the route
	// exists. A handler may answer anything, a 404 of its own included
	// (the database is intentionally unreachable here).
	eps := dashboardFetches(page)
	if len(eps) == 0 {
		t.Error("found no ${API_BASE} fetch calls in the embedded dashboard")
	}
	for _, ep := range eps {
		if !apiRouted(srv, ep) {
			t.Errorf("dashboard fetches /api%s but no route is registered (404)", ep)
		}
	}

	// The landing page and the attack map call these directly.
	for _, ep := range []string{"/status", "/overview", "/iocs/export", "/map/stream"} {
		if !apiRouted(srv, ep) {
			t.Errorf("landing page / map fetch /api%s but no route is registered (404)", ep)
		}
	}

	// Negative control: a page that fetches a made-up endpoint is caught.
	t.Run("made-up endpoint", func(t *testing.T) {
		found := false
		for _, ep := range dashboardFetches(page + "\nfetch(`${API_BASE}/nope`);\n") {
			if ep == "/nope" {
				found = true
				if apiRouted(srv, ep) {
					t.Error("a fetch of ${API_BASE}/nope counts as routed")
				}
			}
		}
		if !found {
			t.Error("the made-up fetch was not found in the page")
		}
	})
	t.Run("what counts as unrouted", func(t *testing.T) {
		for _, c := range []struct {
			code int
			body string
			want bool
		}{
			{http.StatusNotFound, "404 page not found\n", true},
			{http.StatusNotFound, "<html>not found</html>", true},
			{http.StatusNotFound, `{"error":"canary not found"}` + "\n", false},
			{http.StatusBadRequest, `{"error":"id required"}`, false},
			{http.StatusServiceUnavailable, "database not available\n", false},
		} {
			if got := unrouted(c.code, []byte(c.body)); got != c.want {
				t.Errorf("unrouted(%d, %q) = %v, want %v", c.code, c.body, got, c.want)
			}
		}
	})
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
		// The credential is never taken from the URL: a query string ends up
		// in proxy and access logs, shell history and browser history.
		{"correct id query", "", validTestID, http.StatusUnauthorized},
		{"correct id header with wrong query", validTestID, "qp_zzzzzzzzzzzzzzzzzzzzzzzz", http.StatusOK},
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

// TestSecurityHeaders verifies the hardening response headers are applied to
// web UI responses (defense-in-depth against MIME sniffing, clickjacking,
// referrer leakage and injected external scripts).
func TestSecurityHeaders(t *testing.T) {
	s := newTestServer(true)
	ts := httptest.NewServer(securityHeaders(s.authMiddleware(s.mux)))
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	resp.Body.Close()
	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}
	for k, v := range want {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("header %s = %q, want %q", k, got, v)
		}
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") ||
		!strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("Content-Security-Policy missing expected directives: %q", csp)
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

// The landing page, map and their assets are served; directories are not
// listed; anything else is a 404 (not the dashboard, as "/" used to be).
func TestStaticRoutes(t *testing.T) {
	s := newTestServer(true)
	cases := map[string]int{
		"/":                         http.StatusOK,
		"/dashboard":                http.StatusOK,
		"/map":                      http.StatusMovedPermanently,
		"/map/":                     http.StatusOK,
		"/map/static/map.js":        http.StatusOK,
		"/map/static/qpot-feed.js":  http.StatusOK,
		"/assets/js/landing.js":     http.StatusOK,
		"/assets/":                  http.StatusNotFound, // no listing
		"/map/static/":              http.StatusNotFound,
		"/map/static/flags/":        http.StatusNotFound,
		"/static/index.html":        http.StatusNotFound,
		"/assets/../dashboard.html": http.StatusNotFound,
		"/map/../index.html":        http.StatusNotFound,
		"/map/static/..%2f..%2fx":   http.StatusNotFound,
		"/nope":                     http.StatusNotFound,
	}
	for path, want := range cases {
		rec := httptest.NewRecorder()
		s.handleStatic(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Errorf("GET %s: %d, want %d", path, rec.Code, want)
		}
	}
	landing := httptest.NewRecorder()
	s.handleStatic(landing, httptest.NewRequest(http.MethodGet, "/", nil))
	for _, want := range []string{"/dashboard", "/map/", "landing.js"} {
		if !strings.Contains(landing.Body.String(), want) {
			t.Errorf("landing page missing %q", want)
		}
	}
	for _, p := range []string{"/", "/dashboard", "/map/", "/assets/js/landing.js", "/c/x"} {
		if !isPublicPath(p) {
			t.Errorf("%s should be public", p)
		}
	}
	for _, p := range []string{"/api/status", "/api/map/stream", "/api/overview"} {
		if isPublicPath(p) {
			t.Errorf("%s must require auth", p)
		}
	}
}
