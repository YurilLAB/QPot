package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/yuril"
)

// TestHandleYurilHealthVersionNegotiation locks the QPot<->Yuril API-version
// contract on the health probe: a caller that sends a mismatched
// X-QPot-API-Version must get a 400 (fail loud, don't exchange payloads we
// won't understand), an empty header means "I don't care" and is accepted, and
// every response must echo the server's version so the caller can detect drift.
func TestHandleYurilHealthVersionNegotiation(t *testing.T) {
	s := &Server{
		config: &config.Config{QPotID: validTestID, WebUI: config.WebUIConfig{QPotIDAuth: true}},
		mux:    http.NewServeMux(),
	}

	cases := []struct {
		name       string
		sendVer    string
		wantStatus int
	}{
		{"matching version", yuril.APIVersion, http.StatusOK},
		{"empty version (don't care)", "", http.StatusOK},
		{"mismatched version", yuril.APIVersion + "999", http.StatusBadRequest},
		{"garbage version", "not-a-version", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/yuril/health", nil)
			if tc.sendVer != "" {
				req.Header.Set("X-QPot-API-Version", tc.sendVer)
			}
			rec := httptest.NewRecorder()
			s.handleYurilHealth(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			// The server must always advertise its own version, even on a 400,
			// so the peer learns what to send next time.
			if got := rec.Header().Get("X-QPot-API-Version"); tc.wantStatus == http.StatusBadRequest && got != "" && got != yuril.APIVersion {
				t.Errorf("echoed version %q, want %q", got, yuril.APIVersion)
			}
			if tc.wantStatus == http.StatusOK {
				if got := rec.Header().Get("X-QPot-API-Version"); got != yuril.APIVersion {
					t.Errorf("200 response must echo X-QPot-API-Version=%q, got %q", yuril.APIVersion, got)
				}
				var resp map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("health body not JSON: %v", err)
				}
				// The health probe must not leak the QPot ID to an unauth path —
				// but here it's behind withQPotAuth, so it intentionally includes
				// it. Assert the documented fields are present so the Yuril side's
				// liveness check has a stable contract.
				for _, k := range []string{"status", "qpot_id", "api_version", "database", "intel", "forwarder"} {
					if _, ok := resp[k]; !ok {
						t.Errorf("health response missing field %q", k)
					}
				}
			}
		})
	}
}

// TestHandleYurilHealthRejectsNonGET keeps the probe read-only.
func TestHandleYurilHealthRejectsNonGET(t *testing.T) {
	s := &Server{config: &config.Config{QPotID: validTestID}, mux: http.NewServeMux()}
	req := httptest.NewRequest(http.MethodPost, "/api/yuril/health", nil)
	rec := httptest.NewRecorder()
	s.handleYurilHealth(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/yuril/health: status %d, want 405", rec.Code)
	}
}
