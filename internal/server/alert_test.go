package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// TestAlertWebhookPayload verifies the alert webhook POST carries the fields a
// SIEM/chat integration needs: a parseable RFC3339 timestamp (for ordering and
// correlation) and the top honeypot under attack, alongside the existing
// qpot_id/instance/counters.
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
	if got["qpot_id"] != validTestID || got["instance"] != "edge-1" {
		t.Errorf("alert payload missing/incorrect qpot_id/instance: %v / %v", got["qpot_id"], got["instance"])
	}
}
