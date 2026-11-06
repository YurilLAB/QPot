package server

import (
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/config"
)

// FuzzCanaryBeacon drives the public, unauthenticated /c/ endpoint through the
// full middleware chain with arbitrary paths, methods and headers. It must
// never panic, always answer with the same decoy, and count a hit only for a
// GET/HEAD of exactly the planted token.
func FuzzCanaryBeacon(f *testing.F) {
	for _, s := range []struct{ method, suffix, xff, ua string }{
		{"GET", "TOKEN", "", "curl/8"},
		{"HEAD", "TOKEN", "203.0.113.1, 10.0.0.1", ""},
		{"POST", "TOKEN", "", ""},
		{"GET", "TOKEN/extra", "", ""},
		{"GET", "%2e%2e/api/status", "", ""},
		{"GET", "", "", ""},
		{"GET", "TOKEN?x=1", "\xc2\x9b2J", "\xff"},
	} {
		f.Add(s.method, s.suffix, s.xff, s.ua)
	}
	cs, err := canary.NewStore(f.TempDir(), 0)
	if err != nil {
		f.Fatal(err)
	}
	c, err := cs.Create(canary.KindWeb, "bookmark", "wiki")
	if err != nil {
		f.Fatal(err)
	}
	s := &Server{
		config: &config.Config{
			QPotID: validTestID,
			WebUI:  config.WebUIConfig{QPotIDAuth: true},
			Canary: config.CanaryConfig{Enabled: true, Decoy: "notfound"},
		},
		mux:      http.NewServeMux(),
		canaries: cs,
		database: &fakeDB{},
	}
	s.setupRoutes()
	h := securityHeaders(s.authMiddleware(s.mux))
	hits := func() int64 {
		got, _ := cs.Get(c.ID)
		return got.Trips // counts every recorded hit, repeats included
	}

	f.Fuzz(func(t *testing.T, method, suffix, xff, ua string) {
		suffix = strings.ReplaceAll(suffix, "TOKEN", c.Token)
		req, err := http.NewRequest(method, "http://qpot.local/c/"+suffix, nil)
		if err != nil {
			return // not a request a client could send
		}
		req.RemoteAddr = "198.51.100.20:4000"
		req.Header.Set("X-Forwarded-For", xff)
		req.Header.Set("User-Agent", ua)
		before := hits()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		switch {
		case rec.Code == http.StatusNotFound:
		case path.Clean(req.URL.Path) != req.URL.Path && (rec.Code == http.StatusMovedPermanently || rec.Code == http.StatusTemporaryRedirect):
			// ServeMux redirects a non-canonical path (/c//x) before any
			// handler runs, whatever the token; it must stay on this host.
			if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/") || strings.HasPrefix(loc, "//") {
				t.Fatalf("%s %q redirected off the host to %q", method, req.URL.Path, loc)
			}
		default:
			t.Fatalf("%s /c/%s: status %d, want the 404 decoy", method, suffix, rec.Code)
		}
		if body := rec.Body.String(); strings.Contains(body, c.ID) || strings.Contains(body, validTestID) {
			t.Fatalf("beacon response leaks data: %q", body)
		}
		exact := req.URL.Path == "/c/"+c.Token && (req.Method == http.MethodGet || req.Method == http.MethodHead)
		if counted := hits() != before; counted != exact {
			t.Fatalf("%s %q: hit counted = %v, want %v", method, req.URL.Path, counted, exact)
		}
	})
}
