package proxy

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

func TestJSONSinkEmitsValidLine(t *testing.T) {
	var buf bytes.Buffer
	s := NewJSONSink(&buf)
	s.Emit(Event{EventType: EventSession, Honeypot: "ssh-proxy", SrcIP: "1.2.3.4", SrcPort: 4444, Backend: "be1", BytesIn: 10, BytesOut: 20})

	line := buf.String()
	if !strings.HasSuffix(line, "\n") {
		t.Fatal("event line must end with newline (NDJSON)")
	}
	var got Event
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &got); err != nil {
		t.Fatalf("emitted line is not valid JSON: %v", err)
	}
	if got.Timestamp == "" {
		t.Error("Emit should fill a timestamp when absent")
	}
	if got.SrcIP != "1.2.3.4" || got.Backend != "be1" || got.BytesIn != 10 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

// TestJSONSinkConcurrentNoInterleave verifies concurrent Emits never interleave
// a partial line (each line stays valid JSON).
func TestJSONSinkConcurrentNoInterleave(t *testing.T) {
	var buf bytes.Buffer
	s := NewJSONSink(&buf)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				s.Emit(Event{EventType: EventRejected, SrcIP: "9.9.9.9", SrcPort: i, Reason: ReasonRateLimited})
			}
		}(i)
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 50*50 {
		t.Fatalf("got %d lines, want %d", len(lines), 50*50)
	}
	for i, ln := range lines {
		var e Event
		if err := json.Unmarshal([]byte(ln), &e); err != nil {
			t.Fatalf("line %d not valid JSON (interleaved write?): %q: %v", i, ln, err)
		}
	}
}

// TestNopSinkSafe ensures the default discard sink never panics.
func TestNopSinkSafe(t *testing.T) {
	var s EventSink = nopSink{}
	s.Emit(Event{EventType: EventSession})
}
