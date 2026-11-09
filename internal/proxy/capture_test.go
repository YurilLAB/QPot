package proxy

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeHeartbeat(t *testing.T, dir, value string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, CaptureHeartbeat), []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The converter is live only while its heartbeat keeps changing, by the
// broker's own clock; a heartbeat seen once, or long unchanged, is not.
func TestCaptureLiveNeedsAChangingHeartbeat(t *testing.T) {
	dir := t.TempDir()
	g := NewGenerationGate(dir)
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return now }
	g.sampleCapture()
	if g.CaptureLive() {
		t.Fatal("live without a heartbeat")
	}
	writeHeartbeat(t, dir, "1")
	g.sampleCapture()
	if g.CaptureLive() {
		t.Fatal("live on a heartbeat seen only once: it may be a dead control plane's last")
	}
	writeHeartbeat(t, dir, "2")
	g.sampleCapture()
	if !g.CaptureLive() {
		t.Fatal("a changing heartbeat was not live")
	}
	now = now.Add(CaptureStale - time.Second)
	g.sampleCapture()
	if !g.CaptureLive() {
		t.Fatal("went stale inside the window")
	}
	now = now.Add(2 * time.Second)
	g.sampleCapture()
	if g.CaptureLive() {
		t.Fatal("an unchanged heartbeat stayed live")
	}
	writeHeartbeat(t, dir, "3")
	g.sampleCapture()
	if !g.CaptureLive() {
		t.Fatal("a resumed heartbeat was not live")
	}
}

// Without live capture the broker turns connections away before leasing a
// cell; once the converter runs, the same source gets in.
func TestBrokerTakesConnectionsOnlyWithLiveCapture(t *testing.T) {
	backend, stopBackend := echoBackend(t)
	defer stopBackend()
	dir := t.TempDir()
	gate := NewGenerationGate(dir)
	sink := &capSink{}
	pool := NewPool([]Backend{{ID: "be1", Addr: backend}}, nil)
	addr, stop := startBroker(t, Config{Sink: sink, Gate: gate, RequireCapture: true}, pool)
	defer stop()
	connect := func() {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = c.Write([]byte("x"))
		_, _ = c.Read(make([]byte, 1))
		_ = c.Close()
	}
	connect()
	rejected := sink.wait(t, EventRejected, 2*time.Second)
	if rejected.Reason != ReasonCaptureUnavailable {
		t.Fatalf("rejected for %q", rejected.Reason)
	}
	if _, ok := sink.find(EventConnect); ok {
		t.Fatal("a connection reached a backend without live capture")
	}
	if available, _, _ := pool.Stats(); available != 1 {
		t.Fatal("a turned-away connection leased a cell")
	}
	writeHeartbeat(t, dir, "1")
	gate.sampleCapture()
	writeHeartbeat(t, dir, "2")
	gate.sampleCapture()
	connect()
	if e := sink.wait(t, EventConnect, 2*time.Second); e.Backend != "be1" {
		t.Fatalf("connect %+v", e)
	}
}
