package server

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
)

// hookDB is a stubDB that can return a configurable top attacker, so the
// QPOT_TOP_SOURCE_IP env path in responseEnv is exercised.
type hookDB struct {
	stubDB
	attackerIP string
}

func (h hookDB) GetTopAttackers(ctx context.Context, limit int, since time.Time) ([]*database.AttackerStats, error) {
	if h.attackerIP == "" {
		return nil, nil
	}
	return []*database.AttackerStats{{SourceIP: h.attackerIP}}, nil
}

func hookTestServer(db database.Database) *Server {
	return &Server{
		config: &config.Config{
			QPotID:       validTestID,
			InstanceName: "edge-1",
			Alerts:       config.AlertConfig{Enabled: true, Threshold: 10},
			Response:     config.ResponseConfig{Enabled: true},
		},
		database: db,
	}
}

// TestAlertingConfigured is the regression guard for the bug where the alert
// loop only started when a webhook URL was set, silently disabling
// response-hooks-only deployments.
func TestAlertingConfigured(t *testing.T) {
	action := config.ResponseAction{Name: "fw", Command: "true"}
	cases := []struct {
		name string
		cfg  config.Config
		want bool
	}{
		{"disabled", config.Config{Alerts: config.AlertConfig{Enabled: false, WebhookURL: "http://x"}}, false},
		{"webhook only", config.Config{Alerts: config.AlertConfig{Enabled: true, WebhookURL: "http://x"}}, true},
		{"hooks only (the regression)", config.Config{
			Alerts:   config.AlertConfig{Enabled: true},
			Response: config.ResponseConfig{Enabled: true, OnAttackDetected: []config.ResponseAction{action}},
		}, true},
		{"both", config.Config{
			Alerts:   config.AlertConfig{Enabled: true, WebhookURL: "http://x"},
			Response: config.ResponseConfig{Enabled: true, OnAttackDetected: []config.ResponseAction{action}},
		}, true},
		{"enabled but nothing to do", config.Config{Alerts: config.AlertConfig{Enabled: true}}, false},
		{"response enabled but no actions", config.Config{
			Alerts:   config.AlertConfig{Enabled: true},
			Response: config.ResponseConfig{Enabled: true},
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{config: &tc.cfg}
			if got := s.alertingConfigured(); got != tc.want {
				t.Errorf("alertingConfigured() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestResponseEnv verifies the stable env-var contract hooks depend on,
// including the trigger-derived values.
func TestResponseEnv(t *testing.T) {
	s := hookTestServer(hookDB{attackerIP: "203.0.113.9"})
	stats := &database.Stats{
		TotalEvents:  42,
		UniqueIPs:    7,
		TopHoneypots: []database.HoneypotCount{{Honeypot: "cowrie", Count: 30}},
	}
	env := s.responseEnv(context.Background(), stats)
	got := map[string]string{}
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			t.Fatalf("env entry %q is not KEY=VALUE", kv)
		}
		got[k] = v
	}
	want := map[string]string{
		"QPOT_ID":            validTestID,
		"QPOT_INSTANCE":      "edge-1",
		"QPOT_TOTAL_EVENTS":  "42",
		"QPOT_UNIQUE_IPS":    "7",
		"QPOT_THRESHOLD":     "10",
		"QPOT_TOP_HONEYPOT":  "cowrie",
		"QPOT_TOP_SOURCE_IP": "203.0.113.9",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("env[%s] = %q, want %q", k, got[k], v)
		}
	}
	if _, err := time.Parse(time.RFC3339, got["QPOT_TIMESTAMP"]); err != nil {
		t.Errorf("QPOT_TIMESTAMP %q is not RFC3339: %v", got["QPOT_TIMESTAMP"], err)
	}
}

// TestRunResponseHooksExecutesWithEnv runs a real hook that records the env it
// received, proving the command executes and the variables are delivered.
func TestRunResponseHooksExecutesWithEnv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hook uses sh redirection")
	}
	out := filepath.Join(t.TempDir(), "hook.out")
	s := hookTestServer(hookDB{attackerIP: "9.9.9.9"})
	s.config.Response.OnAttackDetected = []config.ResponseAction{
		{Name: "record", Command: `printf '%s|%s|%s|%s|%s' "$QPOT_TOP_SOURCE_IP" "$QPOT_TOTAL_EVENTS" "$QPOT_TOP_HONEYPOT" "$QPOT_THRESHOLD" "$QPOT_UNIQUE_IPS" > ` + out},
	}
	stats := &database.Stats{
		TotalEvents:  42,
		UniqueIPs:    7,
		TopHoneypots: []database.HoneypotCount{{Honeypot: "cowrie"}},
	}
	s.runResponseHooks(context.Background(), stats)

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("hook did not run (no output file): %v", err)
	}
	if string(data) != "9.9.9.9|42|cowrie|10|7" {
		t.Errorf("hook saw wrong env: %q", string(data))
	}
}

// TestRunResponseHooksTimeout verifies a hung hook is killed at its per-action
// timeout instead of blocking the alert loop.
func TestRunResponseHooksTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hook uses sleep")
	}
	s := hookTestServer(nil)
	s.config.Response.OnAttackDetected = []config.ResponseAction{
		{Name: "hang", Command: "sleep 30", Timeout: 200 * time.Millisecond},
	}
	start := time.Now()
	s.runResponseHooks(context.Background(), &database.Stats{})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("hook was not killed at its timeout; took %v", elapsed)
	}
}

// TestRunResponseHooksEmptyCommandSkipped verifies an empty command is skipped
// (not run through sh) and does not prevent later hooks from running.
func TestRunResponseHooksEmptyCommandSkipped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hook uses sh redirection")
	}
	out := filepath.Join(t.TempDir(), "second.out")
	s := hookTestServer(nil)
	s.config.Response.OnAttackDetected = []config.ResponseAction{
		{Name: "empty", Command: "   "},
		{Name: "second", Command: "echo ran > " + out},
	}
	s.runResponseHooks(context.Background(), &database.Stats{})
	if _, err := os.Stat(out); err != nil {
		t.Errorf("the second hook did not run after an empty command was skipped: %v", err)
	}
}

// TestCapWriter checks the bounded output capture: at most max bytes retained,
// overflow flagged, and writes always fully acknowledged so the child never
// blocks.
func TestCapWriter(t *testing.T) {
	cw := &capWriter{max: 10}
	n, err := cw.Write([]byte("hello"))
	if n != 5 || err != nil {
		t.Fatalf("Write returned (%d, %v), want (5, nil)", n, err)
	}
	// Writing past the cap: the writer must still acknowledge the full length.
	n, err = cw.Write([]byte("world!!!!!extra"))
	if n != len("world!!!!!extra") || err != nil {
		t.Fatalf("Write past cap returned (%d, %v); must ack full length", n, err)
	}
	if cw.buf.Len() != 10 {
		t.Errorf("captured %d bytes, want cap of 10", cw.buf.Len())
	}
	if cw.buf.String() != "helloworld" {
		t.Errorf("captured %q, want %q", cw.buf.String(), "helloworld")
	}
	if !cw.overflow {
		t.Error("overflow flag not set after exceeding cap")
	}
}

// TestRunResponseHooksOutputTruncated runs a hook that floods stdout and
// confirms the process completes (no deadlock) under the bounded writer.
func TestRunResponseHooksOutputTruncated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hook uses sh")
	}
	done := filepath.Join(t.TempDir(), "done")
	s := hookTestServer(nil)
	// Emit ~1MB to stdout (far over the 16KiB cap), then touch a marker so we
	// can confirm the command ran to completion despite the flood.
	s.config.Response.OnAttackDetected = []config.ResponseAction{
		{Name: "flood", Command: "head -c 1000000 /dev/zero | tr '\\0' 'x'; touch " + done, Timeout: 10 * time.Second},
	}
	start := time.Now()
	s.runResponseHooks(context.Background(), &database.Stats{})
	if _, err := os.Stat(done); err != nil {
		t.Errorf("flooding hook did not complete (deadlock on full pipe?): %v", err)
	}
	if elapsed := time.Since(start); elapsed > 8*time.Second {
		t.Errorf("flooding hook took too long: %v", elapsed)
	}
}

// FuzzResponseEnv throws arbitrary instance metadata and trigger values at the
// env builder and asserts every entry is a well-formed KEY=VALUE with a known
// QPOT_ key. Because these values are attacker-influenced (source IP, honeypot
// name) and delivered as environment variables, the invariant that matters is
// that each remains a single discrete env entry - the key segment never picks
// up injected content - so a hook's `$QPOT_*` expansions stay predictable.
func FuzzResponseEnv(f *testing.F) {
	f.Add("edge-1", "qp_x", "cowrie", "1.2.3.4", int64(5), int64(2))
	f.Add("", "", "", "", int64(0), int64(0))
	f.Add("inst=evil", "id\nx", "hp=`reboot`", "1.2.3.4; rm -rf /", int64(-1), int64(1<<40))
	f.Add("é—ñ", "\x00\x01", "a\tb", "::1", int64(9999), int64(7))

	knownKeys := map[string]bool{
		"QPOT_ID": true, "QPOT_INSTANCE": true, "QPOT_TOTAL_EVENTS": true,
		"QPOT_UNIQUE_IPS": true, "QPOT_THRESHOLD": true, "QPOT_TIMESTAMP": true,
		"QPOT_TOP_HONEYPOT": true, "QPOT_TOP_SOURCE_IP": true,
	}

	f.Fuzz(func(t *testing.T, instance, qpotID, honeypot, ip string, total, unique int64) {
		s := &Server{
			config: &config.Config{
				QPotID:       qpotID,
				InstanceName: instance,
				Alerts:       config.AlertConfig{Threshold: 10},
			},
			database: hookDB{attackerIP: ip},
		}
		stats := &database.Stats{
			TotalEvents:  total,
			UniqueIPs:    unique,
			TopHoneypots: []database.HoneypotCount{{Honeypot: honeypot}},
		}
		env := s.responseEnv(context.Background(), stats) // must not panic
		for _, kv := range env {
			key, _, ok := strings.Cut(kv, "=")
			if !ok {
				t.Errorf("env entry %q has no '='", kv)
				continue
			}
			if !knownKeys[key] {
				t.Errorf("env entry %q has unexpected/injected key %q", kv, key)
			}
		}
	})
}
