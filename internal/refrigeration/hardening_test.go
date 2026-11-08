package refrigeration

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// budgetRig is a controller with a write budget and a real-time clock the
// test moves by hand.
func budgetRig(t *testing.T, rate float64, burst int) (*Server, *time.Time) {
	t.Helper()
	root := t.TempDir()
	clock := &protocolClock{t: time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)}
	s, err := New(Config{ListenAddr: "127.0.0.1:8080", StateDir: filepath.Join(root, "state"),
		EventLog: filepath.Join(root, "logs/events.json"), DeviceSeed: "write-budget-test-seed", Now: clock.now,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), WriteRate: rate, WriteBurst: burst})
	if err != nil {
		t.Fatal(err)
	}
	real := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	s.clock = func() time.Time { return real }
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("close controller: %v", err)
		}
	})
	return s, &real
}

func journalEvents(t *testing.T, s *Server) []event {
	t.Helper()
	data, err := os.ReadFile(s.cfg.EventLog)
	if err != nil {
		t.Fatal(err)
	}
	var out []event
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var e event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("journal line %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

func savesOf(s *Server) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saves
}

// TestWriteBudgetBoundsStateSaves: every accepted write rewrites and syncs
// the state file, so a logged-in flood of setpoint writes wrote ~77 MB in 10
// seconds to the host disk. Writes over the budget are refused (and logged),
// writes that change nothing save nothing, and the budget refills with time.
func TestWriteBudgetBoundsStateSaves(t *testing.T) {
	s, real := budgetRig(t, 2, 3)
	admin := loginCookie(t, s, "Supervisor", "12345")
	write := func(v string) *httptest.ResponseRecorder {
		return callXML(t, s, `<cmd action="write_val"><val node="1" tag="Setpoint" set="`+v+`"/></cmd>`, admin, false, nil)
	}
	base := savesOf(s)
	for i, v := range []string{"-21", "-22", "-23"} {
		if w := write(v); w.Code != 200 {
			t.Fatalf("write %d inside the burst: HTTP %d %s", i, w.Code, w.Body.String())
		}
	}
	if got := savesOf(s) - base; got != 3 {
		t.Fatalf("%d saves for 3 writes", got)
	}
	// The burst is spent: the next change is refused and not applied.
	w := write("-24")
	decoded(t, w, 4)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "1" {
		t.Fatalf("over-budget write: HTTP %d, Retry-After %q", w.Code, w.Header().Get("Retry-After"))
	}
	s.mu.Lock()
	sp := s.plant.Devices[0].Setpoint
	s.mu.Unlock()
	if sp != -23 || savesOf(s)-base != 3 {
		t.Fatalf("a refused write changed the plant (setpoint %v) or saved (%d saves)", sp, savesOf(s)-base)
	}
	// Writing the value it already has changes nothing, saves nothing and
	// is not refused, budget or not.
	if w := write("-23"); w.Code != 200 || savesOf(s)-base != 3 {
		t.Fatalf("no-op write: HTTP %d, %d saves", w.Code, savesOf(s)-base)
	}
	var refused bool
	for _, e := range journalEvents(t, s) {
		if e.Type == "refrigeration.write.denied" && e.Metadata["reason"] == "rate" {
			refused = true
		}
	}
	if !refused {
		t.Fatal("the refused write left no write.denied event with reason rate")
	}
	// A second later two more writes fit.
	*real = real.Add(time.Second)
	for _, v := range []string{"-24", "-25"} {
		if w := write(v); w.Code != 200 {
			t.Fatalf("write after refill: HTTP %d", w.Code)
		}
	}
	if w := write("-26"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("third write after a one-second refill: HTTP %d", w.Code)
	}
}

// TestRepeatedControlsChangeNothing: a defrost stop with none running and an
// acknowledgement of an acknowledged alarm reported a change, so each one
// rewrote the state file.
func TestRepeatedControlsChangeNothing(t *testing.T) {
	s, _ := newProtocolRig(t)
	admin := loginCookie(t, s, "Supervisor", "12345")
	base := savesOf(s)
	decoded(t, callXML(t, s, `<cmd action="set_defrost" nodetype="16" node="1" operation="0"/>`, admin, false, nil), 0)
	if got := savesOf(s) - base; got != 0 {
		t.Fatalf("stopping a defrost that is not running saved %d times", got)
	}
	decoded(t, callXML(t, s, `<cmd action="set_defrost" nodetype="16" node="1" operation="1"/>`, admin, false, nil), 0)
	if got := savesOf(s) - base; got != 1 {
		t.Fatalf("starting a defrost saved %d times, want 1", got)
	}
	decoded(t, callXML(t, s, `<cmd action="write_alarm_ack" ref="all"/>`, admin, false, nil), 0)
	after := savesOf(s)
	decoded(t, callXML(t, s, `<cmd action="write_alarm_ack" ref="all"/>`, admin, false, nil), 0)
	if savesOf(s) != after {
		t.Fatal("acknowledging acknowledged alarms saved again")
	}
}

// TestConnectionLimiterCapsOneSource: one host held all 64 connection slots
// with idle sockets; now it gets its share and the rest stay free.
func TestConnectionLimiterCapsOneSource(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := limitConnections(base, 8, 2)
	defer l.Close()
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	var clients []net.Conn
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()
	dial := func() net.Conn {
		c, err := net.Dial("tcp", base.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
		return c
	}
	var held []net.Conn
	for i := 0; i < 2; i++ {
		dial()
		select {
		case c := <-accepted:
			held = append(held, c)
		case <-time.After(2 * time.Second):
			t.Fatalf("connection %d inside the share not accepted", i)
		}
	}
	// A third connection from the same host is closed at once.
	third := dial()
	_ = third.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := third.Read(make([]byte, 1)); err == nil {
		t.Fatal("a connection over the source's share was kept open")
	}
	select {
	case <-accepted:
		t.Fatal("a connection over the source's share was handed to the server")
	default:
	}
	// Closing one frees its share again.
	held[0].Close()
	dial()
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("a freed share was not reused")
	}
	held[1].Close()
}

// TestBusyRejectionsAreObserved: when a flood fills every request slot, the
// other sources it turns away are recorded, once per source and second.
func TestBusyRejectionsAreObserved(t *testing.T) {
	s, real := budgetRig(t, 0, 0)
	for i := 0; i < cap(s.inflight); i++ {
		s.inflight <- struct{}{}
	}
	get := func(remote string) int {
		r := httptest.NewRequest(http.MethodGet, "http://controller/metadata.json", nil)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code
	}
	var wg sync.WaitGroup
	for _, remote := range []string{"198.51.100.1:1000", "198.51.100.1:1001", "203.0.113.5:2000"} {
		wg.Add(1)
		go func() { defer wg.Done(); _ = get(remote) }()
	}
	wg.Wait()
	*real = real.Add(time.Second)
	if code := get("198.51.100.1:1002"); code != http.StatusServiceUnavailable {
		t.Fatalf("busy request: HTTP %d", code)
	}
	for i := 0; i < cap(s.inflight); i++ {
		<-s.inflight
	}
	counts := map[string]int{}
	for _, e := range journalEvents(t, s) {
		if e.Type == "refrigeration.overload" {
			counts[e.SourceIP]++
		}
	}
	if counts["198.51.100.1"] != 2 || counts["203.0.113.5"] != 1 {
		t.Fatalf("overload events per source: %v, want one per source and second", counts)
	}
}

func TestWriteRateMustBeAPositiveNumber(t *testing.T) {
	root := t.TempDir()
	_, err := New(Config{ListenAddr: "127.0.0.1:8080", StateDir: filepath.Join(root, "s"), EventLog: filepath.Join(root, "e.json"),
		DeviceSeed: "write-budget-test-seed", Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), WriteRate: -1})
	if err == nil {
		t.Fatal("a negative write rate was accepted")
	}
	t.Setenv("DEVICE_SEED", "write-budget-test-seed")
	t.Setenv("STATE_DIR", filepath.Join(root, "s"))
	t.Setenv("EVENT_LOG", filepath.Join(root, "e.json"))
	t.Setenv("LISTEN_ADDR", "")
	t.Setenv("SITE_PROFILE", "")
	c, err := ConfigFromEnv()
	if err != nil || c.WriteRate != serviceWriteRate || c.WriteBurst != serviceWriteBurst {
		t.Fatalf("the service config has no write budget: %+v, %v", c, err)
	}
}
