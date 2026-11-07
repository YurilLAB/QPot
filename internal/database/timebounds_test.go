package database

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// GetEvents keeps since and until to the millisecond in every backend (the
// web API takes RFC 3339 times with fractions). Each test skips unless its
// QPOT_TEST_* switch is set.

func TestClickHouseEventTimeBounds(t *testing.T) { checkEventTimeBounds(t, connectCH(t), nil) }

func TestPGEventTimeBounds(t *testing.T) { checkEventTimeBounds(t, connectPG(t), nil) }

func TestESEventTimeBounds(t *testing.T) {
	es := connectES(t)
	checkEventTimeBounds(t, es, func() { esRefresh(t, es) })
}

func checkEventTimeBounds(t *testing.T, db Database, refresh func()) {
	t.Helper()
	ctx := context.Background()
	hp := fmt.Sprintf("tb%d", time.Now().UnixNano()%1e9)
	sec := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	at := func(ms int) time.Time { return sec.Add(time.Duration(ms) * time.Millisecond) }
	evs := []*Event{
		{Timestamp: at(200), Honeypot: hp, SourceIP: "198.51.100.1", Protocol: "tcp", EventType: "early"},
		{Timestamp: at(800), Honeypot: hp, SourceIP: "198.51.100.1", Protocol: "tcp", EventType: "late"},
	}
	if err := db.InsertEvents(ctx, evs); err != nil {
		t.Fatal(err)
	}
	if refresh != nil {
		refresh()
	}
	for _, c := range []struct {
		name         string
		since, until time.Time
		want         string
	}{
		{"since half a second in", at(500), time.Time{}, "late"},
		{"until half a second in", time.Time{}, at(500), "early"},
		{"since exactly the late event", at(800), time.Time{}, "late"},
		{"until exactly the early event", time.Time{}, at(200), "early"},
		{"both around both", at(100), at(900), "late,early"},
		{"between them", at(201), at(799), ""},
	} {
		got, err := db.GetEvents(ctx, EventFilter{Honeypots: []string{hp}, StartTime: c.since, EndTime: c.until, Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		var types string
		for i, e := range got {
			if i > 0 {
				types += ","
			}
			types += e.EventType
		}
		if types != c.want {
			t.Errorf("%s: got %q, want %q", c.name, types, c.want)
		}
	}
}
