package overview

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
)

// fakeDB implements only what Build calls; any other method would panic on
// the nil embedded interface, which is what we want to catch.
type fakeDB struct {
	database.Database
	stats  *database.Stats
	events []*database.Event
	err    error
}

func (f *fakeDB) GetStats(ctx context.Context, since time.Time) (*database.Stats, error) {
	return f.stats, f.err
}
func (f *fakeDB) GetEvents(ctx context.Context, fl database.EventFilter) ([]*database.Event, error) {
	if f.err != nil {
		return nil, f.err
	}
	if fl.Limit > 0 && len(f.events) > fl.Limit {
		return f.events[:fl.Limit], nil
	}
	return f.events, nil
}

func testConfig() *config.Config {
	cfg := config.Default("ovtest")
	cfg.EnableHoneypot("cowrie")
	cfg.EnableHoneypot("dionaea")
	return cfg
}

func TestBuildFromDatabase(t *testing.T) {
	now := time.Now().UTC()
	db := &fakeDB{
		stats: &database.Stats{TotalEvents: 86400, UniqueIPs: 7,
			TopHoneypots: []database.HoneypotCount{{Honeypot: "cowrie", Count: 80000}, {Honeypot: "Dionaea ", Count: 6400}}},
		events: []*database.Event{
			{Timestamp: now, Honeypot: "cowrie", SourceIP: "203.0.113.9", DestPort: 22, EventType: "cowrie.command.input",
				Command: "uname -a\x1b[31m", TechniqueID: "T1082", TechniqueName: "System Information Discovery", TacticID: "TA0007", TacticName: "discovery"},
			{Timestamp: now, Honeypot: "cowrie", SourceIP: "203.0.113.9", EventType: "cowrie.login.failed", Username: "root", Password: "x", TacticID: "TA0006"},
			{Timestamp: now, Honeypot: "dionaea", SourceIP: "198.51.100.1", EventType: "dionaea.connection.accept"},
			{Timestamp: now, Honeypot: "canary", SourceIP: "198.51.100.2", EventType: "canary.trip"},
		},
	}
	ov := Build(context.Background(), testConfig(), db, &Cluster{Name: "g", Nodes: 2, Healthy: 1}, "1.2.3")

	if ov.Instance != "ovtest" || ov.Version != "1.2.3" || !ov.DatabaseOK || ov.Cluster == nil {
		t.Fatalf("header: %+v", ov)
	}
	if ov.Events24h != 86400 || ov.UniqueIPs24h != 7 || ov.EventsPerSec != 1 {
		t.Errorf("24h stats: events=%d ips=%d rate=%v", ov.Events24h, ov.UniqueIPs24h, ov.EventsPerSec)
	}
	// Enabled honeypots first, busiest first; names normalised for the join.
	if len(ov.Honeypots) < 2 || ov.Honeypots[0].Name != "cowrie" || ov.Honeypots[0].Hits24h != 80000 ||
		ov.Honeypots[1].Name != "dionaea" || ov.Honeypots[1].Hits24h != 6400 {
		t.Errorf("honeypots: %+v", ov.Honeypots[:2])
	}
	seenDisabled := false
	for _, hp := range ov.Honeypots {
		if !hp.Enabled {
			seenDisabled = true
		} else if seenDisabled {
			t.Fatalf("enabled honeypot %s sorted after a disabled one", hp.Name)
		}
	}
	want := []string{"warn", "critical", "info", "critical"}
	for i, e := range ov.RecentEvents {
		if e.Severity != want[i] {
			t.Errorf("event %d severity %q, want %q", i, e.Severity, want[i])
		}
	}
	if s := ov.RecentEvents[0].Summary; s != "ran: uname -a [31m" || strings.ContainsRune(s, 0x1b) {
		t.Errorf("control characters not cleaned: %q", s)
	}
	if ov.RecentEvents[0].Technique != "T1082 System Information Discovery" {
		t.Errorf("technique: %q", ov.RecentEvents[0].Technique)
	}
	if ov.RecentEvents[1].Summary != "login root / x" {
		t.Errorf("login summary: %q", ov.RecentEvents[1].Summary)
	}
}

// A missing or failing database still yields a usable overview.
func TestBuildWithoutDatabase(t *testing.T) {
	for _, db := range []database.Database{nil, &fakeDB{err: errors.New("down")}} {
		ov := Build(context.Background(), testConfig(), db, nil, "")
		if ov.DatabaseOK || ov.Events24h != 0 || ov.Version != "dev" {
			t.Errorf("db=%v: %+v", db, ov)
		}
		if ov.RecentEvents == nil || ov.Honeypots == nil || len(ov.Honeypots) == 0 {
			t.Errorf("lists must be non-nil and honeypots listed from config: %+v", ov)
		}
	}
}

func TestCleanBoundsRunes(t *testing.T) {
	long := strings.Repeat("é", 500)
	if got := clean(long, 10); got != strings.Repeat("é", 10) {
		t.Errorf("clean split or failed to bound: %q", got)
	}
	if got := clean("a\x00b\nc\x7f", 10); got != "a b c " {
		t.Errorf("clean: %q", got)
	}
}

func TestGaugesWithinRange(t *testing.T) {
	ov := Build(context.Background(), testConfig(), nil, nil, "")
	for name, g := range map[string]Gauge{"cpu": ov.CPU, "mem": ov.Memory, "disk": ov.Disk, "procs": ov.Processes} {
		if g.Pct < 0 || g.Pct > 100 || g.Caption == "" {
			t.Errorf("%s gauge %+v", name, g)
		}
	}
}

func FuzzSummaryAndClean(f *testing.F) {
	f.Add("cmd", "user", "pw", []byte("payload"), "evt")
	f.Add("", "", "", []byte{0xff, 0x00}, "")
	f.Fuzz(func(t *testing.T, cmd, user, pw string, payload []byte, et string) {
		e := &database.Event{Command: cmd, Username: user, Password: pw, Payload: payload, EventType: et}
		got := clean(Summary(e), maxText)
		if len([]rune(got)) > maxText {
			t.Fatalf("summary longer than %d runes", maxText)
		}
		for _, r := range got {
			if r < 0x20 || r == 0x7f {
				t.Fatalf("control character %q survived", r)
			}
		}
		_ = Severity(e)
	})
}
