package intelligence

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

func mispOf(iocs []*database.IOC) map[string]string {
	// returns value -> type for the produced attributes
	ev := BuildMISPEvent(iocs, "edge-1", time.Now())
	out := map[string]string{}
	for _, a := range ev.Event.Attribute {
		out[a.Value] = a.Type
	}
	return out
}

func TestBuildMISPEventTypeMapping(t *testing.T) {
	iocs := []*database.IOC{
		{Type: IOCTypeIP, Value: "203.0.113.7", Honeypot: "cowrie", Count: 12},
		{Type: IOCTypeDomain, Value: "evil.com"},
		{Type: IOCTypeURL, Value: "http://evil.com/x.sh"},
		{Type: IOCTypeHash, Value: strings.Repeat("a", 32)},  // md5
		{Type: IOCTypeHash, Value: strings.Repeat("b", 40)},  // sha1
		{Type: IOCTypeHash, Value: strings.Repeat("c", 64)},  // sha256
		{Type: IOCTypeHash, Value: strings.Repeat("d", 128)}, // sha512
		{Type: IOCTypeWallet, Value: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
		{Type: IOCTypeWallet, Value: "0x52908400098527886e0f7030069857d2e4169ee7"},
		{Type: IOCTypeUserAgent, Value: "curl/8.0"},
		{Type: IOCTypeCredential, Value: "root:toor"},    // skipped
		{Type: IOCTypeCommand, Value: "cat /etc/passwd"}, // skipped
	}
	got := mispOf(iocs)
	want := map[string]string{
		"203.0.113.7":                                "ip-dst",
		"evil.com":                                   "domain",
		"http://evil.com/x.sh":                       "url",
		strings.Repeat("a", 32):                      "md5",
		strings.Repeat("b", 40):                      "sha1",
		strings.Repeat("c", 64):                      "sha256",
		strings.Repeat("d", 128):                     "sha512",
		"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa":         "btc",
		"0x52908400098527886e0f7030069857d2e4169ee7": "text",
		"curl/8.0":                                   "user-agent",
	}
	for v, ty := range want {
		if got[v] != ty {
			t.Errorf("value %q: MISP type = %q, want %q", v, got[v], ty)
		}
	}
	// credential/command must be skipped.
	if _, ok := got["root:toor"]; ok {
		t.Error("credential IOC should not be exported to MISP")
	}
	if _, ok := got["cat /etc/passwd"]; ok {
		t.Error("command IOC should not be exported to MISP")
	}
}

func TestBuildMISPEventStructureAndDedup(t *testing.T) {
	iocs := []*database.IOC{
		{Type: IOCTypeIP, Value: "1.2.3.4"},
		{Type: IOCTypeIP, Value: "1.2.3.4"}, // dup
		{Type: IOCTypeIP, Value: ""},        // empty -> skipped
		nil,                                 // nil -> skipped
	}
	ev := BuildMISPEvent(iocs, "", time.Now())
	if ev.Event.Info == "" || ev.Event.Date == "" {
		t.Error("MISP event missing info/date")
	}
	if len(ev.Event.Attribute) != 1 {
		t.Fatalf("expected 1 deduped attribute, got %d", len(ev.Event.Attribute))
	}
	a := ev.Event.Attribute[0]
	if !a.ToIDS {
		t.Error("ip attribute should be to_ids=true")
	}
	// Must marshal to valid JSON with the {"Event":{"Attribute":[...]}} shape.
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("MISP event does not marshal: %v", err)
	}
	if !strings.Contains(string(b), `"Event"`) || !strings.Contains(string(b), `"Attribute"`) {
		t.Errorf("MISP JSON missing expected keys: %s", b)
	}
}

// validMISPTypes is the set the exporter is allowed to emit.
var validMISPTypes = map[string]bool{
	"ip-dst": true, "domain": true, "url": true, "user-agent": true,
	"md5": true, "sha1": true, "sha256": true, "sha512": true,
	"btc": true, "text": true,
}

func TestBuildMISPEventUserAgentNotToIDS(t *testing.T) {
	ev := BuildMISPEvent([]*database.IOC{{Type: IOCTypeUserAgent, Value: "x"}}, "i", time.Now())
	if len(ev.Event.Attribute) != 1 || ev.Event.Attribute[0].ToIDS {
		t.Error("user-agent should be exported with to_ids=false")
	}
}

func FuzzBuildMISPEvent(f *testing.F) {
	f.Add("ip", "1.2.3.4", "cowrie")
	f.Add("hash", strings.Repeat("a", 64), "x")
	f.Add("wallet", "0xabc", "y")
	f.Add("url", "http://a\x00b/'; DROP--", "z")
	f.Add("domain", "", "")

	f.Fuzz(func(t *testing.T, typ, value, honeypot string) {
		iocs := []*database.IOC{{
			Type: typ, Value: value, Honeypot: honeypot, Count: 1,
			LastSeen: time.Now().UTC(),
		}}
		ev := BuildMISPEvent(iocs, honeypot, time.Now()) // must not panic
		// Result must always marshal to valid JSON.
		if _, err := json.Marshal(ev); err != nil {
			t.Fatalf("MISP event failed to marshal for %q/%q: %v", typ, value, err)
		}
		// Every emitted attribute must be a known MISP type with a non-empty value.
		for _, a := range ev.Event.Attribute {
			if !validMISPTypes[a.Type] {
				t.Errorf("emitted unknown MISP type %q", a.Type)
			}
			if a.Value == "" {
				t.Errorf("emitted MISP attribute with empty value (type %q)", a.Type)
			}
		}
	})
}
