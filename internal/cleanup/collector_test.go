package cleanup

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/vectorstate"
)

// putLog writes a log of n lines of about lineLen bytes, whose first line
// names it, last changed age ago.
func putLog(t *testing.T, cfg *config.Config, rel string, n, lineLen int, age time.Duration) string {
	t.Helper()
	var b strings.Builder
	for i := range n {
		line := fmt.Sprintf(`{"log":%q,"n":%d}`, rel, i)
		b.WriteString(line + strings.Repeat(" ", max(0, lineLen-len(line)-1)) + "\n")
	}
	p := put(t, cfg, rel, 0, age)
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	when := now.Add(-age)
	if err := os.Chtimes(p, when, when); err != nil {
		t.Fatal(err)
	}
	return p
}

type checkpointDoc struct {
	Version     string           `json:"version"`
	Checkpoints []checkpointJSON `json:"checkpoints"`
}

type checkpointJSON struct {
	Fingerprint map[string]uint64 `json:"fingerprint"`
	Position    int64             `json:"position"`
	Modified    string            `json:"modified"`
}

// deliver records, as the collector does once its sinks have acknowledged
// them, that it has delivered the log at p up to pos (-1: all of it now).
func deliver(t *testing.T, cfg *config.Config, honeypot, p string, pos int64) {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	fp, ok := vectorstate.Fingerprint(f)
	f.Close()
	if !ok {
		t.Fatalf("%s has no whole first line", p)
	}
	if pos < 0 {
		pos = size(t, p)
	}
	setCheckpoint(t, cfg, honeypot, fp, pos)
}

func setCheckpoint(t *testing.T, cfg *config.Config, honeypot string, fp uint64, pos int64) {
	t.Helper()
	cp := filepath.Join(cfg.DataPath, vectorstate.Dir, vectorstate.HoneypotSource(honeypot), "checkpoints.json")
	doc := checkpointDoc{Version: "1"}
	if data, err := os.ReadFile(cp); err == nil {
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
	}
	doc.Checkpoints = slices.DeleteFunc(doc.Checkpoints, func(c checkpointJSON) bool { return c.Fingerprint["first_lines_checksum"] == fp })
	doc.Checkpoints = append(doc.Checkpoints, checkpointJSON{Fingerprint: map[string]uint64{"first_lines_checksum": fp}, Position: pos,
		Modified: time.Now().UTC().Format(time.RFC3339Nano)})
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(cp), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cp, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestAnOpenLogWaitsForDelivery: a honeypot holds its log open and keeps
// writing; the collector delivers late. The log is never removed, however
// old; it is emptied only once everything in it is delivered, never while
// lines the collector has not delivered are in it, and it stays the file the
// honeypot writes to. Every line written reaches the collector, once.
func TestAnOpenLogWaitsForDelivery(t *testing.T) {
	cfg := testInstance(t)
	p := filepath.Join(cfg.DataPath, "honeypots", "cowrie", "logs", "cowrie.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	w, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	written := 0
	write := func(n int) {
		t.Helper()
		for range n {
			line := fmt.Sprintf(`{"eventid":"cowrie.command.input","seq":%d}`, written)
			if _, err := w.WriteString(line + strings.Repeat(" ", 1000) + "\n"); err != nil {
				t.Fatal(err)
			}
			written++
		}
	}
	c := &collectorModel{t: t, cfg: cfg, path: p}
	run := func() *Report {
		t.Helper()
		rep := Run(context.Background(), cfg, limits(), Options{Now: time.Now(), CollectorRunning: true})
		if len(rep.Errors) != 0 {
			t.Fatalf("errors: %q", rep.Errors)
		}
		return rep
	}
	stillWritten := func() {
		t.Helper()
		wi, err := w.Stat()
		if err != nil {
			t.Fatal(err)
		}
		pi, err := os.Stat(p)
		if err != nil || !os.SameFile(wi, pi) {
			t.Fatalf("the honeypot no longer writes to %s: %v", p, err)
		}
	}

	write(2000) // about 2 MB, over the 1 MB log limit
	c.read()
	c.deliver(1500) // late: a quarter is read but not yet in the database
	if rep := run(); rep.Emptied != 0 || len(rep.Notes) == 0 || !strings.Contains(strings.Join(rep.Notes, " "), "not yet delivered") {
		t.Fatalf("emptied a log not all delivered: %+v", rep)
	}
	// Nor does a preview say it would.
	if rep := Run(context.Background(), cfg, limits(), Options{Now: time.Now(), CollectorRunning: true, DryRun: true}); rep.Emptied != 0 {
		t.Fatalf("a dry run would empty a log not all delivered: %+v", rep)
	}

	c.deliver(-1)
	write(5) // written after the collector's checkpoint
	if rep := run(); rep.Emptied != 0 {
		t.Fatal("emptied a log with lines written since the collector's checkpoint")
	}

	// However old, an open log is never removed.
	old := time.Now().Add(-400 * day)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	c.read()
	c.deliver(-1)
	if rep := run(); rep.Emptied != 1 || rep.Removed != 0 {
		t.Fatalf("a delivered log over the limit: %+v", rep)
	}
	stillWritten()
	if fi, _ := os.Stat(p); fi.Size() != 0 {
		t.Fatalf("not emptied: %d bytes", fi.Size())
	}

	// The honeypot goes on writing to the same file; the collector finds the
	// new lines there, from the start (a new first line, a new fingerprint).
	write(300)
	c.read()
	c.deliver(-1)
	if rep := run(); rep.Emptied != 0 || rep.Removed != 0 {
		t.Fatalf("a delivered log under the limit: %+v", rep)
	}
	stillWritten()
	if len(c.delivered) != written {
		t.Fatalf("the collector got %d lines of %d", len(c.delivered), written)
	}
	for i, l := range c.delivered {
		if !strings.Contains(l, fmt.Sprintf(`"seq":%d}`, i)) {
			t.Fatalf("line %d delivered is %.60q", i, l)
		}
	}
}

// collectorModel reads a log as the collector does, from where it left off
// or from the start once the first line (the fingerprint) changes, and
// delivers what it read only when told: its checkpoint then moves.
type collectorModel struct {
	t                 *testing.T
	cfg               *config.Config
	path              string
	fp                uint64
	pos               int64    // read up to
	pending           []string // read, not delivered
	pendingEnd        []int64  // where each pending line ends
	delivered         []string
	deliveredPosition int64
}

func (c *collectorModel) read() {
	c.t.Helper()
	data, err := os.ReadFile(c.path)
	if err != nil {
		c.t.Fatal(err)
	}
	fp, ok := vectorstate.Fingerprint(strings.NewReader(string(data)))
	if !ok {
		return
	}
	if fp != c.fp || int64(len(data)) < c.pos {
		c.fp, c.pos, c.deliveredPosition = fp, 0, 0
		c.pending, c.pendingEnd = nil, nil
	}
	rest := string(data[c.pos:])
	for {
		i := strings.IndexByte(rest, '\n')
		if i < 0 {
			break
		}
		c.pending = append(c.pending, rest[:i])
		c.pos += int64(i + 1)
		c.pendingEnd = append(c.pendingEnd, c.pos)
		rest = rest[i+1:]
	}
}

// deliver delivers the first n lines read (-1: all) and checkpoints them.
func (c *collectorModel) deliver(n int) {
	c.t.Helper()
	if n < 0 || n > len(c.pending) {
		n = len(c.pending)
	}
	if n == 0 {
		return
	}
	c.delivered = append(c.delivered, c.pending[:n]...)
	c.deliveredPosition = c.pendingEnd[n-1]
	c.pending, c.pendingEnd = c.pending[n:], c.pendingEnd[n:]
	setCheckpoint(c.t, c.cfg, "cowrie", c.fp, c.deliveredPosition)
}

// TestLogsSharingAFingerprintAreNotEmptied: two logs with the same first
// line look like one log to the collector, so neither counts as delivered.
func TestLogsSharingAFingerprintAreNotEmptied(t *testing.T) {
	cfg := testInstance(t)
	a := putLog(t, cfg, "honeypots/cowrie/logs/a.json", 2000, 1024, time.Minute)
	data, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	b := filepath.Join(filepath.Dir(a), "b.json")
	if err := os.WriteFile(b, data, 0o644); err != nil {
		t.Fatal(err)
	}
	deliver(t, cfg, "cowrie", a, -1)
	rep := Run(context.Background(), cfg, limits(), Options{Now: now, CollectorRunning: true})
	if rep.Emptied != 0 || size(t, a) == 0 || size(t, b) == 0 {
		t.Fatalf("emptied a log the collector cannot tell from another: %+v", rep)
	}
	// Control: once b differs, a is emptied.
	if err := os.WriteFile(b, []byte("{\"other\":1}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep = Run(context.Background(), cfg, limits(), Options{Now: now, CollectorRunning: true})
	if rep.Emptied != 1 || size(t, a) != 0 {
		t.Fatalf("control: %+v", rep)
	}
}
