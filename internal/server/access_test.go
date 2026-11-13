package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/access"
)

// as sends a request with a key of its own.
func (a *apiTestServer) as(key, method, path, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.Header.Set("X-QPot-ID", key)
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, req)
	return rec
}

// reload makes the server look at the members file now, not in two seconds.
func (a *apiTestServer) reload() {
	a.s.access.mu.Lock()
	a.s.access.checked = time.Time{}
	a.s.access.mu.Unlock()
}

func accessOf(t *testing.T, rec *httptest.ResponseRecorder) accessView {
	t.Helper()
	var v accessView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("GET /api/access = %d %v: %s", rec.Code, err, rec.Body.String())
	}
	return v
}

// Each member's key does what its role allows and no more; a refusal says
// so without signing the browser out; what is changed, and what is refused,
// is in the audit log under the member's name.
func TestMembersActWithinTheirRole(t *testing.T) {
	a := newAPITestServer(t, "api-access", nil)
	a.s.database = newCaseDB()
	keys := map[access.Role]string{}
	for _, role := range access.Roles {
		key, err := access.Add(a.cfg.DataPath, string(role)+"-1", role, validTestID)
		if err != nil {
			t.Fatal(err)
		}
		keys[role] = key
	}
	a.reload()

	type call struct{ method, path, body string }
	reads := []call{{http.MethodGet, "/api/investigate", ""}, {http.MethodGet, "/api/canaries", ""}, {http.MethodGet, "/api/alerts", ""}, {http.MethodGet, "/api/access", ""}}
	analyst := []call{{http.MethodPut, "/api/alerts", `{"rule":"new-payload","enabled":false}`}, {http.MethodPost, "/api/canaries", `{"kind":"web","name":"n","memo":"m"}`}}
	admin := []call{{http.MethodPut, "/api/cleanup", `{"max_age_days":30}`}}
	allowed := map[access.Role][3]bool{access.Viewer: {true, false, false}, access.Analyst: {true, true, false}, access.Admin: {true, true, true}}
	for role, key := range keys {
		for i, group := range [][]call{reads, analyst, admin} {
			for _, c := range group {
				rec := a.as(key, c.method, c.path, c.body)
				refused := rec.Code == http.StatusForbidden && rec.Header().Get("X-QPot-Denied") == "role"
				if allowed[role][i] == refused || (!refused && rec.Code >= 400) {
					t.Errorf("%s %s %s = %d (refused for the role: %v): %s", role, c.method, c.path, rec.Code, refused, rec.Body.String())
				}
				if refused && decodeAPIError(t, rec).Code != "QP-WEB-006" {
					t.Errorf("%s %s: %s", role, c.path, rec.Body.String())
				}
			}
		}
	}
	// The owner's key is the QPot ID, as before.
	if rec := a.do(http.MethodPut, "/api/cleanup", `{"max_age_days":31}`); rec.Code != http.StatusOK {
		t.Fatalf("owner = %d", rec.Code)
	}

	// Who am I, and who else: the members and the log are for admins.
	if v := accessOf(t, a.as(keys[access.Viewer], http.MethodGet, "/api/access", "")); v.You.Name != "viewer-1" || v.You.Role != access.Viewer || v.Members != nil || v.Audit != nil {
		t.Fatalf("a viewer's view: %+v", v)
	}
	v := accessOf(t, a.do(http.MethodGet, "/api/access?audit=100", ""))
	if v.You.Role != access.Owner || len(v.Members) != 3 || v.Members[0].Name != "admin-1" {
		t.Fatalf("the owner's view: %+v", v.You)
	}
	body, _ := json.Marshal(v)
	for _, key := range keys {
		if strings.Contains(string(body), key) || strings.Contains(string(body), "key_sha256") {
			t.Fatal("the view carries a key or its hash")
		}
	}
	// The log: 5 changes that went through, 4 refusals, no reads.
	var done, denied int
	for _, e := range v.Audit {
		if e.Method == http.MethodGet || e.Who == "" || e.Time.IsZero() {
			t.Fatalf("audit entry: %+v", e)
		}
		if e.Denied {
			denied++
			if e.Status != http.StatusForbidden {
				t.Fatalf("a refusal with status %d", e.Status)
			}
		} else {
			done++
		}
	}
	if done != 6 || denied != 4 {
		t.Fatalf("%d changes and %d refusals audited: %+v", done, denied, v.Audit)
	}
	if e := v.Audit[0]; e.Who != "owner" || e.Role != access.Owner || e.Path != "/api/cleanup" || e.Status != http.StatusOK {
		t.Fatalf("newest entry: %+v", e)
	}

	// A member removed on the host is locked out; the others are not.
	if err := access.Remove(a.cfg.DataPath, "admin-1"); err != nil {
		t.Fatal(err)
	}
	a.reload()
	if rec := a.as(keys[access.Admin], http.MethodGet, "/api/status", ""); rec.Code != http.StatusForbidden || rec.Header().Get("X-QPot-Denied") != "" {
		t.Fatalf("a removed member = %d", rec.Code)
	}
	if rec := a.as(keys[access.Viewer], http.MethodGet, "/api/access", ""); rec.Code != http.StatusOK {
		t.Fatalf("another member = %d", rec.Code)
	}
	// A damaged members file lets no member in, and the owner still.
	if err := os.WriteFile(access.Path(a.cfg.DataPath), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.reload()
	if rec := a.as(keys[access.Viewer], http.MethodGet, "/api/access", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("a member with a damaged file = %d", rec.Code)
	}
	if rec := a.do(http.MethodGet, "/api/access", ""); rec.Code != http.StatusOK {
		t.Fatalf("the owner with a damaged file = %d", rec.Code)
	}
	assertAuthRequired(t, a.h, http.MethodGet, "/api/access", "")
}

// No member's key works on another instance, and a key cannot be told from
// a wrong one by anything but its hash.
func TestMemberKeysBelongToOneInstance(t *testing.T) {
	a := newAPITestServer(t, "api-access-a", nil)
	b := newAPITestServer(t, "api-access-b", nil)
	key, err := access.Add(a.cfg.DataPath, "alice", access.Admin, validTestID)
	if err != nil {
		t.Fatal(err)
	}
	if rec := a.as(key, http.MethodGet, "/api/access", ""); rec.Code != http.StatusOK {
		t.Fatalf("on its instance = %d", rec.Code)
	}
	if rec := b.as(key, http.MethodGet, "/api/access", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("on another instance = %d", rec.Code)
	}
	for _, bad := range []string{key[:26] + "a", strings.ToUpper(key), key + " ", "qp_" + strings.Repeat("a", 24)} {
		if bad == key {
			continue
		}
		if rec := a.as(bad, http.MethodGet, "/api/access", ""); rec.Code == http.StatusOK {
			t.Fatalf("key %q was let in", bad)
		}
	}
}

func FuzzMemberKey(f *testing.F) {
	a := newAPITestServer(f, "api-access-fuzz", nil)
	key, err := access.Add(a.cfg.DataPath, "alice", access.Viewer, validTestID)
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{key, validTestID, "", "qp_", key[:26], strings.Repeat("a", 27)} {
		f.Add(s, uint8(0), false)
	}
	f.Add(key, uint8(13), true)
	f.Fuzz(func(t *testing.T, sent string, route uint8, write bool) {
		// Every route the server registers, whatever method it expects.
		path := routePath(apiRoutes[int(route)%len(apiRoutes)].path)
		if strings.ContainsAny(sent, "\r\n") || apiRoutes[int(route)%len(apiRoutes)].stream {
			return
		}
		method, body := http.MethodGet, ""
		if write {
			method, body = http.MethodPost, `{}`
		}
		rec := func() (rec *httptest.ResponseRecorder) {
			defer func() {
				if recover() != nil {
					rec = nil // not a request the test client can make
				}
			}()
			return a.as(sent, method, path, body)
		}()
		if rec == nil {
			return
		}
		switch {
		case sent == validTestID:
		case sent == key:
			// A viewer never changes anything: the role is refused before
			// any handler sees the request.
			if write && (rec.Code != http.StatusForbidden || rec.Header().Get("X-QPot-Denied") != "role") {
				t.Fatalf("a viewer's POST %s = %d", path, rec.Code)
			}
		default:
			if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
				t.Fatalf("key %q on %s = %d", sent, path, rec.Code)
			}
		}
	})
}
