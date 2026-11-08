package intelligence

import (
	"context"
	"slices"
	"testing"

	"github.com/qpot/qpot/internal/database"
)

func TestRefrigerationEventsPreserveEvidenceLimits(t *testing.T) {
	c := newTestClassifierT(t)
	for _, suffix := range []string{"read", "export", "auth.success", "alarm", "malformed"} {
		ev := &database.Event{Honeypot: "refrigeration", EventType: "refrigeration." + suffix, Protocol: "http", Username: "admin", Payload: []byte("GET /readings")}
		c.Classify(context.Background(), ev)
		if ev.TechniqueID != "" || len(ev.Categories) != 0 {
			t.Errorf("ordinary observation %s treated as certain attack: %+v", suffix, ev)
		}
	}
	for _, suffix := range []string{"write.attempt", "write.success", "write.denied"} {
		ev := &database.Event{Honeypot: "refrigeration", EventType: "refrigeration." + suffix, Protocol: "http"}
		c.Classify(context.Background(), ev)
		if ev.TechniqueID != "T0855" || ev.Confidence >= 1 || !slices.Contains(ev.Categories, CatICSAttack) {
			t.Errorf("emulated control attempt lost qualified classification: %+v", ev)
		}
	}
	ev := &database.Event{Honeypot: "refrigeration", EventType: "refrigeration.auth.failed", Protocol: "http", Username: "admin"}
	c.Classify(context.Background(), ev)
	if ev.TechniqueID == "" || !slices.Contains(ev.Categories, CatBruteForce) {
		t.Errorf("captured failed authentication not classified: %+v", ev)
	}
	ev = &database.Event{Honeypot: "refrigeration", EventType: "refrigeration.exploit.attempt", Protocol: "http", Payload: []byte("GET /../../etc/passwd")}
	c.Classify(context.Background(), ev)
	if !slices.Contains(ev.Categories, CatExploitAttempt) || ev.TechniqueID != "T1190" {
		t.Errorf("exploit attempt not retained as an attempt: %+v", ev)
	}
}
