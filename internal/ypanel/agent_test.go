package ypanel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
)

// newTestAgent builds a ready white-box agent pointed at base, with no manager
// or database (the snapshot builder tolerates both), so tests exercise the wire
// without Docker or a live store.
func newTestAgent(base string, hps map[string]config.HoneypotConfig) *Agent {
	cfg := &config.Config{
		InstanceName: "test",
		Honeypots:    hps,
		Ypanel: config.YpanelConfig{
			Enabled:     true,
			Base:        base,
			InstanceID:  "qp_000000000000000000000001",
			EnrollToken: "yp_" + strings.Repeat("a", 48),
			Region:      "EU · Test",
		},
	}
	return &Agent{
		cfg:     cfg,
		version: "test-1.2.3",
		jws:     "h.p.s",
		http:    &http.Client{Timeout: 5 * time.Second},
		log:     func(string, ...any) {},
		ready:   true,
	}
}

func TestBuildSnapshotShape(t *testing.T) {
	a := newTestAgent("https://example.test", map[string]config.HoneypotConfig{
		"cowrie":   {Enabled: true, Port: 22, RiskLevel: "medium"},
		"dionaea":  {Enabled: false, Port: 445, RiskLevel: "high"},
		"notareal": {Enabled: true, Port: 1234, RiskLevel: "low"}, // must be filtered
	})

	snap := a.buildSnapshot(context.Background())

	if snap["v"] != 1 {
		t.Errorf("v = %v, want 1", snap["v"])
	}
	if snap["instance_id"] != "qp_000000000000000000000001" {
		t.Errorf("instance_id = %v", snap["instance_id"])
	}
	if snap["status"] != "online" {
		t.Errorf("status = %v, want online", snap["status"])
	}
	if snap["version"] != "test-1.2.3" {
		t.Errorf("version = %v", snap["version"])
	}
	// Every required gauge must be present and within [0,100].
	for _, k := range []string{"cpu", "mem", "disk", "procs"} {
		g, ok := snap[k].(gauge)
		if !ok {
			t.Fatalf("%s gauge missing/wrong type: %T", k, snap[k])
		}
		if g.Pct < 0 || g.Pct > 100 {
			t.Errorf("%s pct out of range: %d", k, g.Pct)
		}
	}

	hps, ok := snap["honeypots"].([]snapHoneypot)
	if !ok {
		t.Fatalf("honeypots wrong type: %T", snap["honeypots"])
	}
	if len(hps) != 2 {
		t.Fatalf("expected 2 known honeypots (notareal filtered), got %d: %+v", len(hps), hps)
	}
	for _, h := range hps {
		if !knownHoneypotTypes[h.Type] {
			t.Errorf("unknown honeypot type leaked into snapshot: %q", h.Type)
		}
	}
	// Stable ordering: cowrie before dionaea.
	if hps[0].Type != "cowrie" || hps[1].Type != "dionaea" {
		t.Errorf("honeypots not sorted: %+v", hps)
	}

	// Snapshot must marshal cleanly with camelCase keys.
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(b)
	for _, key := range []string{`"eventsPerSec"`, `"recentEvents"`, `"bootedAt"`, `"clusterId"`} {
		if !strings.Contains(js, key) {
			t.Errorf("snapshot missing key %s", key)
		}
	}
}

func TestPushOnceRoundTrip(t *testing.T) {
	var gotAuth, gotPath, gotMethod, gotInstance string
	var gotV float64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotMethod = r.Method
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if v, ok := body["v"].(float64); ok {
			gotV = v
		}
		if s, ok := body["instance_id"].(string); ok {
			gotInstance = s
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"status":"ok"}`))
	}))
	defer srv.Close()

	a := newTestAgent(srv.URL, map[string]config.HoneypotConfig{"cowrie": {Enabled: true, Port: 22}})
	a.http = srv.Client()

	status, err := a.PushOnce(context.Background())
	if err != nil {
		t.Fatalf("PushOnce: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %s, want POST", gotMethod)
	}
	if gotPath != "/v1/ypanel/push" {
		t.Errorf("path = %s, want /v1/ypanel/push", gotPath)
	}
	wantAuth := "Bearer DIREC-YPANEL h.p.s yp_" + strings.Repeat("a", 48)
	if gotAuth != wantAuth {
		t.Errorf("auth = %q, want %q", gotAuth, wantAuth)
	}
	if gotV != 1 {
		t.Errorf("body v = %v, want 1", gotV)
	}
	if gotInstance != "qp_000000000000000000000001" {
		t.Errorf("body instance_id = %q", gotInstance)
	}
}

func TestPollApplyAckRoundTrip(t *testing.T) {
	var polled, acked bool
	var ackBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/ypanel/jobs"):
			polled = true
			if r.URL.Query().Get("instance") != "qp_000000000000000000000001" {
				t.Errorf("poll missing instance query: %s", r.URL.RawQuery)
			}
			// An unsupported verb so applyJob refuses it without needing a
			// manager/Docker — the agent must still ack honestly (ok=false).
			_, _ = w.Write([]byte(`{"ok":true,"jobs":[{"job_id":"job_x","verb":"honeypot.frobnicate","target":"cowrie"}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/ypanel/jobs/ack":
			acked = true
			_ = json.NewDecoder(r.Body).Decode(&ackBody)
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	a := newTestAgent(srv.URL, map[string]config.HoneypotConfig{"cowrie": {Enabled: true, Port: 22}})
	a.http = srv.Client()

	a.pollOnce(context.Background())

	if !polled {
		t.Error("worker was not polled")
	}
	if !acked {
		t.Fatal("job was not acked")
	}
	if ackBody["ok"] != false {
		t.Errorf("ack ok = %v, want false (unsupported verb)", ackBody["ok"])
	}
	if ackBody["job_id"] != "job_x" {
		t.Errorf("ack job_id = %v", ackBody["job_id"])
	}
}

func TestApplyJobRefusals(t *testing.T) {
	a := newTestAgent("https://example.test", map[string]config.HoneypotConfig{"cowrie": {Enabled: true, Port: 22}})

	// Unsupported verb is refused before any manager interaction.
	if ok, _ := a.applyJob(context.Background(), job{JobID: "j1", Verb: "honeypot.nuke", Target: "cowrie"}); ok {
		t.Error("unsupported verb should be refused")
	}
	// Valid verb but unknown target is refused before any manager interaction.
	if ok, msg := a.applyJob(context.Background(), job{JobID: "j2", Verb: "honeypot.enable", Target: "ghost"}); ok {
		t.Errorf("unknown target should be refused, got ok with %q", msg)
	}
}

func TestSeverity(t *testing.T) {
	cases := []struct {
		name string
		ev   database.Event
		want string
	}{
		{"credential access tactic", database.Event{TacticID: "TA0006"}, "critical"},
		{"high confidence", database.Event{Confidence: 0.9}, "critical"},
		{"classified", database.Event{Classified: true}, "warn"},
		{"has creds", database.Event{Username: "root", Password: "x"}, "warn"},
		{"bare", database.Event{EventType: "connect"}, "info"},
	}
	for _, c := range cases {
		if got := severity(&c.ev); got != c.want {
			t.Errorf("%s: severity = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestCountryNormalisation(t *testing.T) {
	cases := map[string]string{
		"RU": "RU", "ru": "RU", "Russia": "", "": "", "U1": "", "USA": "",
	}
	for in, want := range cases {
		if got := country(in); got != want {
			t.Errorf("country(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEventIDStableAndPrefixed(t *testing.T) {
	ts := time.Date(2026, 6, 7, 22, 14, 5, 0, time.UTC)
	ev := database.Event{Timestamp: ts, Honeypot: "cowrie", SourceIP: "203.0.113.66", DestPort: 22, EventType: "login", Username: "root"}
	id1 := eventID(&ev)
	id2 := eventID(&ev)
	if id1 != id2 {
		t.Errorf("eventID not stable: %q vs %q", id1, id2)
	}
	if !strings.HasPrefix(id1, "ev_") {
		t.Errorf("eventID missing ev_ prefix: %q", id1)
	}
	ev.SourceIP = "198.51.100.23"
	if eventID(&ev) == id1 {
		t.Error("eventID should differ for a different source IP")
	}
}

func TestSanitizeAndClamp(t *testing.T) {
	if got := sanitize("a\x00b\x1fc\x7fd"); got != "a b c d" {
		t.Errorf("sanitize stripped wrong: %q", got)
	}
	if got := clampStr("héllo", 3); got != "hél" {
		t.Errorf("clampStr rune-split: %q", got)
	}
	if got := clampStr("hi", 10); got != "hi" {
		t.Errorf("clampStr over-trimmed: %q", got)
	}
}

func TestResolveLicenseJWS(t *testing.T) {
	// Inline wins.
	if got, err := ResolveLicenseJWS(config.YpanelConfig{LicenseJWS: "  inline.jws  "}); err != nil || got != "inline.jws" {
		t.Errorf("inline: got %q err %v", got, err)
	}

	// Path is read and trimmed.
	dir := t.TempDir()
	p := filepath.Join(dir, "license.dat")
	if err := os.WriteFile(p, []byte("file.jws\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := ResolveLicenseJWS(config.YpanelConfig{LicenseJWSPath: p}); err != nil || got != "file.jws" {
		t.Errorf("path: got %q err %v", got, err)
	}

	// Missing path is an error.
	if _, err := ResolveLicenseJWS(config.YpanelConfig{LicenseJWSPath: filepath.Join(dir, "nope.dat")}); err == nil {
		t.Error("expected error for missing path")
	}
}

func TestNewDisabledReturnsNil(t *testing.T) {
	a, err := New(&config.Config{Ypanel: config.YpanelConfig{Enabled: false}}, nil, "v")
	if err != nil || a != nil {
		t.Errorf("disabled New should return (nil,nil), got (%v,%v)", a, err)
	}
}
