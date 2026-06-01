package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// FuzzWithQPotAuth is a security-invariant fuzz: regardless of what arbitrary
// attacker-supplied value is presented as the X-QPot-ID header or qpot_id query
// param, the auth gate must (a) never panic and (b) grant access ONLY when the
// value exactly equals the configured QPot ID. Anything else must be rejected.
func FuzzWithQPotAuth(f *testing.F) {
	seeds := []string{
		"", "qp_", validTestID, validTestID + "x", validTestID[:26],
		"qp_zzzzzzzzzzzzzzzzzzzzzzzz", "QP_ABCDEFGHIJKLMNOPQRSTUVWX",
		"qp_aaaaaaaaaaaaaaaaaaaaaaaa", "../../etc/passwd",
		"qp_\x00bcdefghijklmnopqrstuvwx",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	s := newTestServer(true)

	f.Fuzz(func(t *testing.T, candidate string) {
		granted := false
		h := s.withQPotAuth(func(w http.ResponseWriter, r *http.Request) {
			granted = true
			w.WriteHeader(http.StatusOK)
		})

		// Present the candidate via header.
		reqH := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		reqH.Header.Set("X-QPot-ID", candidate)
		recH := httptest.NewRecorder()
		h(recH, reqH) // must not panic

		// And via query parameter.
		granted = false
		reqQ := httptest.NewRequest(http.MethodGet, "/api/status?qpot_id="+url.QueryEscape(candidate), nil)
		recQ := httptest.NewRecorder()
		h(recQ, reqQ)

		// The security invariant: access is granted iff candidate == the real ID.
		shouldGrant := candidate == validTestID
		if granted != shouldGrant {
			t.Errorf("auth granted=%v for candidate %q, want %v", granted, candidate, shouldGrant)
		}
		// Defense in depth: a non-matching candidate must never yield 200.
		if !shouldGrant && (recH.Code == http.StatusOK || recQ.Code == http.StatusOK) {
			t.Errorf("non-matching candidate %q produced a 200", candidate)
		}
	})
}
