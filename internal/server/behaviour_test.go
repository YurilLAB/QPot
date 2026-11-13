package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/behaviour"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/intelligence"
)

// alertDB is caseDB with stored payload hashes.
type alertDB struct {
	caseDB
	iocs []*database.IOC
}

func (d *alertDB) GetIOCs(context.Context, database.IOCFilter) ([]*database.IOC, error) {
	return d.iocs, nil
}

// persisting adds a session of ip that looked around and then tried to stay.
func (d *alertDB) persisting(ip string, at time.Time) *database.TTPSession {
	b := intelligence.NewTTPBuilder(time.Hour)
	b.Update(&database.Event{Timestamp: at, Honeypot: "cowrie", SourceIP: ip, EventType: "cowrie.command.input", Command: "id"})
	s := b.GetActiveSessions()[0]
	s.KillChainStages = []string{"discovery", "persistence"}
	d.sessions = append(d.sessions, s)
	return s
}

func getAlerts(t *testing.T, a *apiTestServer) behaviourView {
	t.Helper()
	rec := a.do(http.MethodGet, "/api/alerts", "")
	var v behaviourView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("GET /api/alerts = %d %v: %s", rec.Code, err, rec.Body.String())
	}
	return v
}

// A behaviour alert is raised once, kept, posted to the webhook without the
// instance's login, and handed to the hooks; a rule turned off in the
// settings stays quiet, and the settings survive in the config file.
func TestBehaviourAlertsAreRaisedKeptAndSent(t *testing.T) {
	var mu sync.Mutex
	var posts []map[string]any
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), validTestID) {
			t.Error("the webhook was sent the QPot ID")
		}
		var p map[string]any
		_ = json.Unmarshal(body, &p)
		mu.Lock()
		posts = append(posts, p)
		mu.Unlock()
	}))
	defer hook.Close()
	out := filepath.Join(t.TempDir(), "hook.txt")
	command := `echo "$QPOT_ALERT_RULE $QPOT_ALERT_SEVERITY $QPOT_ALERT_SOURCE_IP $QPOT_ALERT_SESSION" >> "` + out + `"`
	if runtime.GOOS == "windows" {
		command = `echo %QPOT_ALERT_RULE% %QPOT_ALERT_SEVERITY% %QPOT_ALERT_SOURCE_IP% %QPOT_ALERT_SESSION%>> ` + out
	}
	a := newAPITestServer(t, "api-behaviour", func(c *config.Config) {
		c.Intelligence.Enabled = true
		c.Alerts.WebhookURL = hook.URL
		c.Response.Enabled = true
		c.Response.OnBehaviour = []config.ResponseAction{{Name: "note", Command: command}}
	})
	db := &alertDB{}
	a.s.database = db
	now := time.Now().UTC()
	db.persisting("198.51.100.1", now.Add(-time.Hour)) // there before the feature first ran

	if got := a.s.behaviourPass(context.Background(), now); len(got) != 0 {
		t.Fatalf("the baseline raised %d alerts", len(got))
	}
	if v := getAlerts(t, a); !v.Enabled || !v.Running || !v.Webhook || v.Hooks != 1 || len(v.Rules) != 5 || len(v.Alerts) != 0 || v.Since == nil {
		t.Fatalf("view: %+v", v)
	}

	s := db.persisting("198.51.100.2", now.Add(time.Minute))
	db.iocs = []*database.IOC{{Type: intelligence.IOCTypeHash, Value: strings.Repeat("ab", 32), Honeypot: "cowrie", SourceIP: "198.51.100.2", FirstSeen: now.Add(time.Minute)}}
	got := a.s.behaviourPass(context.Background(), now.Add(2*time.Minute))
	if len(got) != 2 {
		t.Fatalf("raised %+v", got)
	}
	if again := a.s.behaviourPass(context.Background(), now.Add(3*time.Minute)); len(again) != 0 {
		t.Fatalf("raised again: %+v", again)
	}
	v := getAlerts(t, a)
	if len(v.Alerts) != 2 || v.Alerts[0].Rule != behaviour.RuleProgression || v.Alerts[0].SessionID != s.SessionID || v.Alerts[1].Rule != behaviour.RuleNewPayload {
		t.Fatalf("kept alerts: %+v", v.Alerts)
	}
	mu.Lock()
	if len(posts) != 2 || posts[1]["kind"] != "behaviour" || posts[1]["rule"] != behaviour.RuleProgression || posts[1]["session_id"] != s.SessionID ||
		posts[1]["instance"] != "api-behaviour" || posts[1]["severity"] != "high" || posts[1]["timestamp"] == nil || posts[1]["source_ips"] == nil {
		t.Fatalf("webhook posts: %+v", posts)
	}
	mu.Unlock()
	data, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(data), "progression high 198.51.100.2 "+s.SessionID) || !strings.Contains(string(data), "new-payload high 198.51.100.2") {
		t.Fatalf("hook output: %v %q", err, data)
	}
	// The state is on disk: another server of the instance does not repeat.
	if st, err := behaviour.Load(a.cfg.DataPath); err != nil || len(st.Alerts) != 2 {
		t.Fatalf("saved state: %v", err)
	}

	// Turn one rule off: saved, shown, and quiet.
	rec := a.do(http.MethodPut, "/api/alerts", `{"rule":"progression","enabled":false}`)
	if rec.Code != http.StatusOK || !strings.Contains(string(a.configFile(t)), "- progression") {
		t.Fatalf("PUT = %d: %s\n%s", rec.Code, rec.Body.String(), a.configFile(t))
	}
	if v := getAlerts(t, a); v.Rules[1].Name != behaviour.RuleProgression || v.Rules[1].Enabled || !v.Rules[0].Enabled {
		t.Fatalf("rules: %+v", v.Rules)
	}
	db.persisting("198.51.100.3", now.Add(4*time.Minute))
	if got := a.s.behaviourPass(context.Background(), now.Add(5*time.Minute)); len(got) != 0 {
		t.Fatalf("a rule that is off raised: %+v", got)
	}
	// All off, then one on again: asking for a rule turns the feature on.
	if rec := a.do(http.MethodPut, "/api/alerts", `{"enabled":false}`); rec.Code != http.StatusOK || !strings.Contains(string(a.configFile(t)), "disabled: true") {
		t.Fatalf("PUT all off = %d", rec.Code)
	}
	db.persisting("198.51.100.4", now.Add(6*time.Minute))
	if got := a.s.behaviourPass(context.Background(), now.Add(7*time.Minute)); len(got) != 0 || getAlerts(t, a).Running {
		t.Fatalf("turned off, raised %+v", got)
	}
	if rec := a.do(http.MethodPut, "/api/alerts", `{"rule":"progression","enabled":true}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT on = %d", rec.Code)
	}
	if v := getAlerts(t, a); !v.Enabled || !v.Rules[1].Enabled || strings.Contains(string(a.configFile(t)), "- progression") {
		t.Fatalf("on again: %+v", v.Rules)
	}

	for body, want := range map[string]int{
		`{"rule":"nosuch","enabled":true}`: http.StatusBadRequest,
		`{"rule":"progression"}`:           http.StatusBadRequest,
		`{}`:                               http.StatusBadRequest,
		`{"enabled":"yes"}`:                http.StatusBadRequest,
		`{"enabled":true,"extra":1}`:       http.StatusBadRequest,
	} {
		if rec := a.do(http.MethodPut, "/api/alerts", body); rec.Code != want {
			t.Errorf("PUT %s = %d", body, rec.Code)
		}
	}
	assertAuthRequired(t, a.h, http.MethodGet, "/api/alerts", "")
	assertAuthRequired(t, a.h, http.MethodPut, "/api/alerts", `{"enabled":false}`)
	if rec := a.do(http.MethodGet, "/api/alerts?limit=0", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("limit=0 = %d", rec.Code)
	}
}

// Without the intelligence worker there are no sessions to look at: the
// rules do not run, and the view says so. A state file that cannot be read
// stops the alerts and is reported, never silently replaced.
func TestBehaviourAlertsNeedTheWorkerAndTheirState(t *testing.T) {
	a := newAPITestServer(t, "api-behaviour-off", func(c *config.Config) { c.Intelligence.Enabled = false })
	db := &alertDB{}
	a.s.database = db
	if got := a.s.behaviourPass(context.Background(), time.Now()); got != nil {
		t.Fatal("ran without the worker")
	}
	if v := getAlerts(t, a); !v.Enabled || v.Running || v.Webhook {
		t.Fatalf("view: %+v", v)
	}

	b := newAPITestServer(t, "api-behaviour-bad", func(c *config.Config) { c.Intelligence.Enabled = true })
	b.s.database = db
	if err := os.WriteFile(behaviour.StatePath(b.cfg.DataPath), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	db.persisting("198.51.100.9", time.Now())
	if got := b.s.behaviourPass(context.Background(), time.Now()); got != nil {
		t.Fatal("ran on a broken state")
	}
	if v := getAlerts(t, b); v.Problem == "" {
		t.Fatal("the broken state is not reported")
	}
	if data, _ := os.ReadFile(behaviour.StatePath(b.cfg.DataPath)); string(data) != "{broken" {
		t.Fatal("the unreadable state file was replaced")
	}
}
