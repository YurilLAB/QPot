package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// TestAlertWebhookPayload verifies the alert webhook POST carries the fields a
// SIEM/chat integration needs: a parseable RFC3339 timestamp (for ordering and
// correlation) and the top honeypot under attack, alongside the instance
// and the counters.
func TestAlertWebhookPayload(t *testing.T) {
	var got map[string]interface{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := newTestServer(false)
	s.config.InstanceName = "edge-1"
	s.config.Alerts.WebhookURL = ts.URL

	stats := &database.Stats{
		TotalEvents:  42,
		UniqueIPs:    7,
		TopHoneypots: []database.HoneypotCount{{Honeypot: "cowrie", Count: 30}},
	}
	s.fireWebhook(context.Background(), stats)

	if got == nil {
		t.Fatal("webhook received no/!invalid JSON payload")
	}
	tsStr, _ := got["timestamp"].(string)
	if tsStr == "" {
		t.Error("alert payload missing timestamp")
	} else if _, err := time.Parse(time.RFC3339, tsStr); err != nil {
		t.Errorf("alert timestamp %q is not RFC3339: %v", tsStr, err)
	}
	if got["top_honeypot"] != "cowrie" {
		t.Errorf("alert payload top_honeypot = %v, want cowrie", got["top_honeypot"])
	}
	if got["instance"] != "edge-1" {
		t.Errorf("alert payload instance = %v, want edge-1", got["instance"])
	}
}

// TestAlertWebhookCarriesNoQPotID: the QPot ID is the web API's credential
// and a webhook hands its payload to a third party (a Slack or Discord
// channel), so the payload names the instance instead.
func TestAlertWebhookCarriesNoQPotID(t *testing.T) {
	var raw []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := newTestServer(false)
	s.config.InstanceName = "edge-1"
	s.config.Alerts.WebhookURL = ts.URL
	s.fireWebhook(context.Background(), &database.Stats{TotalEvents: 42, UniqueIPs: 7})

	if len(raw) == 0 {
		t.Fatal("the webhook received nothing")
	}
	if s.config.QPotID == "" || strings.Contains(string(raw), s.config.QPotID) || strings.Contains(string(raw), "qpot_id") {
		t.Fatalf("the alert carries the QPot ID (%q): %s", s.config.QPotID, raw)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	if got["instance"] != "edge-1" || got["total_events"] != float64(42) || got["timestamp"] == nil ||
		!strings.Contains(fmt.Sprint(got["message"]), "42 events") {
		t.Fatalf("payload lost a field: %s", raw)
	}
}

// TestAlertWebhookDoesNotLogSecretURL: Slack, Discord and most webhook URLs
// carry their credential in the path or query, so the URL must not reach the
// log (qpot-serve.log, the journal) on success or on a failed request.
func TestAlertWebhookDoesNotLogSecretURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(prev)

	s := newTestServer(false)
	stats := &database.Stats{TotalEvents: 1}
	for _, u := range []string{
		ts.URL + "/services/T0000/B0000/XoXbSeCrEtToKeN?token=QuErYsEcReT", // delivered
		"http://127.0.0.1:1/api/webhooks/123/UnReAcHaBlEsEcReT",            // refused
	} {
		s.config.Alerts.WebhookURL = u
		s.fireWebhook(context.Background(), stats)
	}
	out := logs.String()
	if !strings.Contains(out, "Alert webhook fired") || !strings.Contains(out, "request failed") {
		t.Fatalf("expected both webhook log lines, got:\n%s", out)
	}
	for _, secret := range []string{"XoXbSeCrEtToKeN", "QuErYsEcReT", "UnReAcHaBlEsEcReT", "T0000"} {
		if strings.Contains(out, secret) {
			t.Errorf("webhook secret %q written to the log:\n%s", secret, out)
		}
	}
}
