package server

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/instance"
)

func TestRefrigerationExportOnlyTripsOnCapturedCredentialReuse(t *testing.T) {
	s := newCanaryTestServer(t, &fakeDB{})
	cfg := config.Default("refrigeration-canary")
	cfg.QPotID = validTestID
	cfg.DataPath, cfg.ConfigPath = t.TempDir(), ""
	for name, hp := range cfg.Honeypots {
		hp.Enabled = name == "refrigeration"
		cfg.Honeypots[name] = hp
	}
	s.config = cfg
	planted := instance.PlantedCanaries(cfg)
	if len(planted) != 1 {
		t.Fatalf("refrigeration-only instance has %d export credential watches", len(planted))
	}
	if err := s.canaries.SyncPlanted(planted); err != nil {
		t.Fatal(err)
	}
	m := &canaryMatcher{s: s}
	now := time.Now().UTC()
	export := &database.Event{Timestamp: now, Honeypot: "refrigeration", EventType: "refrigeration.export", SourceIP: "203.0.113.70", Protocol: "http", Payload: []byte("GET /exports/maintenance.zip")}
	if m.MatchEvent(context.Background(), export) || len(s.canaries.Trips(0)) != 0 {
		t.Fatal("downloading the export alone tripped the archive credential")
	}
	login := &database.Event{Timestamp: now.Add(time.Second), Honeypot: "refrigeration", EventType: "refrigeration.auth.failed", SourceIP: "203.0.113.71", Protocol: "http", Username: "svc_refrigeration", Password: planted[0].Values[0]}
	if !m.MatchEvent(context.Background(), login) {
		t.Fatal("copied archive password in a captured login did not trip")
	}
	trips := s.canaries.Trips(0)
	if len(trips) != 1 || trips[0].SourceIP != login.SourceIP || trips[0].CanaryID != planted[0].ID {
		t.Fatalf("trip lost source or canary attribution: %+v", trips)
	}
	if m.MatchEvent(context.Background(), login) || len(s.canaries.Trips(0)) != 1 {
		t.Fatal("worker reprocessing the same observation duplicated the trip")
	}
	// The native collector preserves the raw target and a decoded query. A
	// percent-encoded password is absent from Payload and matches only the
	// decoded metadata; the User-Agent observation matches only that header.
	password := planted[0].Values[0]
	var encoded strings.Builder
	for _, b := range []byte(password) {
		fmt.Fprintf(&encoded, "%%%02X", b)
	}
	for i, tc := range []struct {
		payload  string
		metadata map[string]string
	}{
		{"/metadata?archive=" + encoded.String(), map[string]string{"request_uri": "/metadata?archive=" + encoded.String(), "query": "archive=" + password}},
		{"/metadata", map[string]string{"request_uri": "/metadata", "user_agent": "fleet-agent " + password}},
	} {
		if strings.Contains(tc.payload, password) {
			t.Fatal("fixture must prove metadata-only credential reuse")
		}
		event := &database.Event{Timestamp: now.Add(time.Duration(i+2) * time.Second), Honeypot: "refrigeration", EventType: "refrigeration.read", SourceIP: fmt.Sprintf("203.0.113.%d", 72+i), Protocol: "http", Payload: []byte(tc.payload), Metadata: tc.metadata}
		if !m.MatchEvent(context.Background(), event) {
			t.Errorf("captured credential reuse in native metadata %d did not trip", i)
		}
	}
	if len(s.canaries.Trips(0)) != 3 {
		t.Fatal("query and User-Agent reuse did not retain distinct captured observations")
	}
	literalQuery := &database.Event{Timestamp: now.Add(5 * time.Second), Honeypot: "refrigeration", EventType: "refrigeration.read", SourceIP: "203.0.113.74", Protocol: "http", Payload: []byte("/unknown?archive=" + password)}
	if !m.MatchEvent(context.Background(), literalQuery) || len(s.canaries.Trips(0)) != 4 {
		t.Fatal("literal credential reuse in an unknown GET target was not watched")
	}
}
