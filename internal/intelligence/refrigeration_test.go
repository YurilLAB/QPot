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
	// What a write does names its technique: a setpoint is a parameter, defrost
	// and the main switch are commands, acknowledging alarms silences them.
	// An emulated write proves no physical effect, so none is certain.
	for _, suffix := range []string{"write.attempt", "write.success", "write.denied"} {
		for action, want := range map[string]string{"write_val": "T0836", "": "T0836", "set_defrost": "T1692.001",
			"set_main_switch": "T1692.001", "write_alarm_ack": "T0878"} {
			ev := &database.Event{Honeypot: "refrigeration", EventType: "refrigeration." + suffix, Protocol: "http",
				Metadata: map[string]string{"action": action}}
			c.Classify(context.Background(), ev)
			if ev.TechniqueID != want || ev.Confidence >= 1 || !slices.Contains(ev.Categories, CatICSAttack) || ev.TacticID == "" {
				t.Errorf("%s %q: emulated control attempt lost qualified classification: %+v", suffix, action, ev)
			}
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
