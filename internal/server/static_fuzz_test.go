package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzStaticHandler throws arbitrary request paths at handleStatic, the one
// web-UI handler reachable WITHOUT authentication (authMiddleware skips "/" and
// "/static/"). It serves files out of the embedded FS, so the invariants that
// must hold for every input are:
//
//   - it never panics;
//   - it never returns a 5xx (a bad path is a client error, not a server one);
//   - it never escapes the embedded FS to disclose a file outside static/
//     (path traversal), which we approximate by asserting the body never
//     contains a sentinel that only appears in this Go source tree;
//   - it never leaks the QPot ID credential, since this page is unauthenticated.
func FuzzStaticHandler(f *testing.F) {
	seeds := []string{
		"/", "/static/index.html", "/static/", "/index.html",
		"/../server.go", "/static/../../server.go",
		"/static/..%2f..%2fserver.go", "/%2e%2e/%2e%2e/etc/passwd",
		"/static/" + strings.Repeat("../", 40) + "etc/passwd",
		"//static//index.html", "/static/./index.html",
		"/static/\x00", "/static/index.html\x00.png",
		"/STATIC/INDEX.HTML", "/" + strings.Repeat("a/", 500),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	s := newTestServer(true)

	f.Fuzz(func(t *testing.T, path string) {
		// Only well-formed request targets are reachable in practice; skip
		// inputs net/http itself would reject so we fuzz the handler, not
		// NewRequest's parser.
		if path == "" || path[0] != '/' {
			return
		}
		req, err := http.NewRequest(http.MethodGet, "http://example"+path, nil)
		if err != nil {
			return
		}
		rec := httptest.NewRecorder()
		s.handleStatic(rec, req) // must not panic

		if rec.Code >= 500 {
			t.Fatalf("path %q: server error %d (a malformed path must be a client error)", path, rec.Code)
		}
		body := rec.Body.String()
		// The Go source for this package contains this exact string; the
		// embedded FS (rooted at static/) does not. Seeing it in a response
		// would mean traversal escaped the embedded root.
		if strings.Contains(body, "package server") {
			t.Errorf("path %q disclosed Go source outside the embedded static root", path)
		}
		if strings.Contains(body, validTestID) {
			t.Errorf("path %q leaked the QPot ID credential from an unauthenticated handler", path)
		}
	})
}
