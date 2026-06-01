package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

func newYurilTestServer(db *fakeDB) *Server {
	return &Server{
		config:   &config.Config{QPotID: validTestID, WebUI: config.WebUIConfig{QPotIDAuth: true}},
		database: db,
		mux:      http.NewServeMux(),
	}
}

// FuzzHandleYurilIntel fuzzes the inbound IOC ingestion endpoint with arbitrary
// request bodies. This is the external write surface (Yuril -> QPot IOC table),
// so it must never panic, and for any well-formed batch it must:
//   - only ever persist IOCs of an allowed type (ip/domain/url/hash),
//   - never persist an empty value,
//   - never let inbound context clobber the "origin" audit tag,
//   - report accepted+skipped == received.
func FuzzHandleYurilIntel(f *testing.F) {
	seeds := []string{
		`{"items":[{"type":"ip","value":"1.2.3.4"}]}`,
		`{"items":[{"type":"HASH","value":" abc "},{"type":"bogus","value":"x"}]}`,
		`{"items":[{"type":"url","value":"","context":{"origin":"spoofed"}}]}`,
		`{"items":[{"type":"domain","value":"e.com","context":{"origin":"x","k":"v"}}]}`,
		`{"items":[]}`,
		`{}`,
		`not json`,
		`{"items":[{"type":"ip","value":"` + strings.Repeat("9", 5000) + `"}]}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	allowed := map[string]bool{"ip": true, "domain": true, "url": true, "hash": true}

	f.Fuzz(func(t *testing.T, body string) {
		db := &fakeDB{}
		s := newYurilTestServer(db)

		req := httptest.NewRequest(http.MethodPost, "/api/yuril/intel", strings.NewReader(body))
		rec := httptest.NewRecorder()
		s.handleYurilIntel(rec, req) // must not panic

		// Every persisted IOC must satisfy the handler's contract regardless of
		// what the fuzzer fed in.
		for _, ioc := range db.insertedIOCs() {
			if !allowed[ioc.Type] {
				t.Errorf("persisted IOC with disallowed type %q (body=%q)", ioc.Type, body)
			}
			if strings.TrimSpace(ioc.Value) == "" {
				t.Errorf("persisted IOC with empty value (body=%q)", body)
			}
			if ioc.Metadata["origin"] != "yuril_inbound" {
				t.Errorf("origin tag clobbered: %q (body=%q)", ioc.Metadata["origin"], body)
			}
		}

		// On a 200, accepted+skipped must equal received.
		if rec.Code == http.StatusOK {
			var resp struct {
				Accepted int `json:"accepted"`
				Skipped  int `json:"skipped"`
				Received int `json:"received"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err == nil {
				if resp.Accepted+resp.Skipped != resp.Received {
					t.Errorf("accepted(%d)+skipped(%d) != received(%d)",
						resp.Accepted, resp.Skipped, resp.Received)
				}
				if resp.Accepted != len(db.insertedIOCs()) {
					t.Errorf("accepted=%d but %d IOCs inserted", resp.Accepted, len(db.insertedIOCs()))
				}
			}
		}
	})
}
