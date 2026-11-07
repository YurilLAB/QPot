package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/instance"
)

// apiRoute is one way of calling an authenticated endpoint. Every /api/
// route the server registers must have at least one (TestEveryAPIRouteIsListed).
type apiRoute struct {
	method, path, body string
	// stream: the answer never ends (server-sent events); the request is
	// cut after a moment.
	stream bool
}

var apiRoutes = []apiRoute{
	{method: http.MethodGet, path: "/api/status"},
	{method: http.MethodGet, path: "/api/honeypots"},
	{method: http.MethodPost, path: "/api/honeypots", body: `{"name":"nosuch","enabled":true}`},
	{method: http.MethodGet, path: "/api/events?limit=5"},
	{method: http.MethodGet, path: "/api/stats"},
	{method: http.MethodGet, path: "/api/logs?honeypot=cowrie&tail=5"},
	{method: http.MethodGet, path: "/api/ioc"},
	{method: http.MethodGet, path: "/api/techniques"},
	{method: http.MethodGet, path: "/api/iocs"},
	{method: http.MethodGet, path: "/api/iocs/export?format=misp"},
	{method: http.MethodGet, path: "/api/ttps"},
	{method: http.MethodGet, path: "/api/intelligence"},
	{method: http.MethodGet, path: "/api/canaries"},
	{method: http.MethodPost, path: "/api/canaries", body: `{"kind":"web","name":"guard","memo":"x"}`},
	{method: http.MethodDelete, path: "/api/canaries?id=nosuch"},
	{method: http.MethodGet, path: "/api/canaries/trips"},
	{method: http.MethodGet, path: "/api/canaries/artifact?id=nosuch"},
	{method: http.MethodGet, path: "/api/cluster"},
	{method: http.MethodGet, path: "/api/overview"},
	{method: http.MethodGet, path: "/api/map/stream", stream: true},
	{method: http.MethodGet, path: "/api/honeypots/settings"},
	{method: http.MethodGet, path: "/api/honeypots/settings?name=galah"},
	{method: http.MethodPut, path: "/api/honeypots/settings", body: `{"name":"cowrie","settings":{"nosuch":"x"}}`},
	{method: http.MethodPost, path: "/api/honeypots/restart", body: `{"name":"nosuch"}`},
}

func routePath(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}

// Every /api/ route registered in the server's source is in apiRoutes, so the
// auth, CSRF and secret checks below cover a new endpoint as soon as it is
// added.
func TestEveryAPIRouteIsListed(t *testing.T) {
	listed := map[string]bool{}
	for _, r := range apiRoutes {
		listed[routePath(r.path)] = true
	}
	re := regexp.MustCompile(`HandleFunc\("(/api/[^"]*)"`)
	found := 0
	for _, f := range []string{"server.go", "api_routes.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			found++
			if !listed[m[1]] {
				t.Errorf("%s registers %s, which apiRoutes does not list", f, m[1])
			}
		}
	}
	if found < len(listed) {
		t.Errorf("found %d registered routes, apiRoutes lists %d paths", found, len(listed))
	}
}

// guardServer is an API test server with secrets in every place the config
// can hold one, and a manager whose docker is missing.
type guardServer struct {
	*apiTestServer
	secrets map[string]string // what -> value
}

func randomMarker(t *testing.T, what string) string {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return what + hex.EncodeToString(b)
}

func newGuardServer(t *testing.T) *guardServer {
	t.Helper()
	t.Setenv("PATH", t.TempDir()) // no docker: the manager fails fast
	sec := map[string]string{
		"database password": randomMarker(t, "dbpw"),
		"web UI password":   randomMarker(t, "uipw"),
		"webhook token":     randomMarker(t, "hook"),
		"LLM API key":       randomMarker(t, "llmk"),
		"response hook":     randomMarker(t, "resp"),
		// The API credential: the caller has it, and a reply that repeats it
		// puts it on screen. No endpoint returns it.
		"QPot ID": validTestID,
	}
	a := newAPITestServer(t, "api-guard", func(c *config.Config) {
		c.Database.Password = sec["database password"]
		c.WebUI.Username, c.WebUI.Password = "admin", sec["web UI password"]
		c.Alerts.Enabled, c.Alerts.WebhookURL = true, "https://hooks.example.net/services/"+sec["webhook token"]
		c.Response.Enabled = true
		c.Response.OnAttackDetected = []config.ResponseAction{{Name: "block", Command: "/usr/local/bin/block --token " + sec["response hook"]}}
		// (The canary base URL is no secret: canary URLs are made to be found.)
		c.Canary.BaseURL = "https://canary.example.net"
		c.EnableHoneypot("cowrie")
		c.EnableHoneypot("galah")
		c.SetHoneypotCustomConfig("galah", map[string]string{"llm_provider": "openai", "llm_model": "gpt-x", "llm_api_key": sec["LLM API key"]})
	})
	mgr, err := instance.NewManager(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.s.manager = mgr
	a.s.database = &fakeDB{}
	return &guardServer{apiTestServer: a, secrets: sec}
}

func (g *guardServer) call(r apiRoute, id string, contentType string) *httptest.ResponseRecorder {
	var req *http.Request
	if r.body != "" {
		req = httptest.NewRequest(r.method, r.path, strings.NewReader(r.body))
	} else {
		req = httptest.NewRequest(r.method, r.path, nil)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if id != "" {
		req.Header.Set("X-QPot-ID", id)
	}
	if r.stream {
		ctx, cancel := context.WithTimeout(req.Context(), 300*time.Millisecond)
		defer cancel()
		req = req.WithContext(ctx)
	}
	rec := httptest.NewRecorder()
	g.h.ServeHTTP(rec, req)
	return rec
}

// Every endpoint: 401 without a QPot ID or with a malformed one, 403 with
// another instance's, and nothing in the refusal that helps.
func TestAPIRoutesNeedTheQPotID(t *testing.T) {
	g := newGuardServer(t)
	before := g.configFile(t)
	for _, r := range apiRoutes {
		for _, c := range []struct {
			id   string
			want int
		}{{"", http.StatusUnauthorized}, {"not-an-id", http.StatusUnauthorized}, {"qp_zzzzzzzzzzzzzzzzzzzzzzzz", http.StatusForbidden}} {
			rec := g.call(r, c.id, "application/json")
			if rec.Code != c.want {
				t.Errorf("%s %s with ID %q: %d, want %d", r.method, r.path, c.id, rec.Code, c.want)
			}
			if strings.Contains(rec.Body.String(), validTestID) {
				t.Errorf("%s %s: the refusal carries the QPot ID", r.method, r.path)
			}
		}
	}
	if string(before) != string(g.configFile(t)) {
		t.Error("an unauthenticated request changed the config file")
	}
}

// Every write (POST, PUT, PATCH) needs a JSON body type, which a cross-site
// HTML form cannot send: text/plain, form and multipart bodies get 415, even
// with the right QPot ID, before the handler runs.
func TestAPIWritesNeedJSON(t *testing.T) {
	g := newGuardServer(t)
	before := g.configFile(t)
	writes := 0
	for _, r := range apiRoutes {
		if r.method != http.MethodPost && r.method != http.MethodPut && r.method != http.MethodPatch {
			continue
		}
		writes++
		for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "application/jsonx", "text/json"} {
			if rec := g.call(r, validTestID, ct); rec.Code != http.StatusUnsupportedMediaType {
				t.Errorf("%s %s as %q: %d, want 415", r.method, r.path, ct, rec.Code)
			}
		}
	}
	if writes == 0 {
		t.Fatal("no writes checked")
	}
	if string(before) != string(g.configFile(t)) {
		t.Error("a refused write changed the config file")
	}
}

// leakyDB fails every query with an error that quotes the database password,
// as a driver error can.
type leakyDB struct {
	fakeDB
	err error
}

func (l *leakyDB) Ping(context.Context) error { return l.err }
func (l *leakyDB) GetEvents(context.Context, database.EventFilter) ([]*database.Event, error) {
	return nil, l.err
}
func (l *leakyDB) GetStats(context.Context, time.Time) (*database.Stats, error) { return nil, l.err }
func (l *leakyDB) GetTopAttackers(context.Context, int, time.Time) ([]*database.AttackerStats, error) {
	return nil, l.err
}
func (l *leakyDB) GetIOCs(context.Context, database.IOCFilter) ([]*database.IOC, error) {
	return nil, l.err
}
func (l *leakyDB) GetTTPSessions(context.Context, int) ([]*database.TTPSession, error) {
	return nil, l.err
}
func (l *leakyDB) GetSchemaVersion(context.Context) (int, error) { return 0, l.err }

// No answer of any endpoint carries a secret from the config (the QPot ID,
// database and web UI passwords, webhook URL, LLM key, response hook
// commands), with a working database or one whose errors quote its password.
func TestAPIAnswersCarryNoSecrets(t *testing.T) {
	g := newGuardServer(t)
	for _, dbCase := range []struct {
		name string
		db   database.Database
	}{
		{"working database", &fakeDB{}},
		{"failing database", &leakyDB{err: errors.New("dial tcp 127.0.0.1:9000: auth failed for qpot:" + g.secrets["database password"])}},
	} {
		g.s.database = dbCase.db
		for _, r := range apiRoutes {
			rec := g.call(r, validTestID, "application/json")
			body := rec.Body.String()
			for what, v := range g.secrets {
				if strings.Contains(body, v) {
					t.Errorf("%s, %s %s (%d): the answer carries the %s", dbCase.name, r.method, r.path, rec.Code, what)
				}
			}
			for k, v := range rec.Header() {
				for what, s := range g.secrets {
					if strings.Contains(strings.Join(v, " "), s) {
						t.Errorf("%s %s: header %s carries the %s", r.method, r.path, k, what)
					}
				}
			}
		}
	}
	// The secrets are in the file the server reads: the check is not vacuous.
	cfg := string(g.configFile(t))
	var missing []string
	for what, v := range g.secrets {
		if !strings.Contains(cfg, v) {
			missing = append(missing, what)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("not in the config file: %v", missing)
	}
}
