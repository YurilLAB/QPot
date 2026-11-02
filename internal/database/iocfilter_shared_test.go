package database

import (
	"context"
	"sort"
	"testing"
	"time"
)

// checkIOCValueAndSourceFilters stores three IOCs and checks that GetIOCs
// filters by exact value and by observed source IP in the database.
func checkIOCValueAndSourceFilters(t *testing.T, db Database, refresh func()) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	iocs := []*IOC{
		{ID: "ip:198.51.100.10:cowrie", Type: "ip", Value: "198.51.100.10", Honeypot: "cowrie", SourceIP: "198.51.100.10", FirstSeen: now, LastSeen: now, Count: 1},
		{ID: "url:http://198.51.100.11/x:cowrie", Type: "url", Value: "http://198.51.100.11/x", Honeypot: "cowrie", SourceIP: "198.51.100.10", FirstSeen: now, LastSeen: now, Count: 1},
		{ID: "hash:abc123:dionaea", Type: "hash", Value: "abc123", Honeypot: "dionaea", SourceIP: "203.0.113.50", FirstSeen: now, LastSeen: now, Count: 1},
	}
	if err := db.InsertIOCs(ctx, iocs); err != nil {
		t.Fatal(err)
	}
	if refresh != nil {
		refresh()
	}
	values := func(got []*IOC) []string {
		var v []string
		for _, i := range got {
			v = append(v, i.Value)
		}
		sort.Strings(v)
		return v
	}
	got, err := db.GetIOCs(ctx, IOCFilter{Values: []string{"abc123", "nope"}, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if v := values(got); len(v) != 1 || v[0] != "abc123" {
		t.Errorf("Values filter returned %v, want [abc123]", v)
	}
	got, err = db.GetIOCs(ctx, IOCFilter{SourceIPs: []string{"198.51.100.10"}, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if v := values(got); len(v) != 2 {
		t.Errorf("SourceIPs filter returned %v, want the 2 IOCs seen from 198.51.100.10", v)
	}
}

// checkIOCSightingsAccumulate: every write of an indicator is one more sighting.
// The stored count must add up (also for repeats inside one batch), first_seen
// must stay at the earliest sighting and last_seen move to the latest. The
// ClickHouse ReplacingMergeTree and Elasticsearch index-by-_id writes used to
// replace the row, so count stayed at 1 and first_seen tracked the latest hit.
func checkIOCSightingsAccumulate(t *testing.T, db Database, value string, refresh func()) {
	t.Helper()
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Hour)
	mk := func(at time.Time) *IOC {
		return &IOC{ID: "ip:" + value + ":cowrie", Type: "ip", Value: value, Honeypot: "cowrie",
			SourceIP: value, FirstSeen: at, LastSeen: at, Count: 1}
	}
	if err := db.InsertIOCs(ctx, []*IOC{mk(t0)}); err != nil {
		t.Fatal(err)
	}
	refresh()
	if err := db.InsertIOCs(ctx, []*IOC{mk(t0.Add(time.Minute)), mk(t0.Add(2 * time.Minute))}); err != nil {
		t.Fatal(err)
	}
	refresh()
	got, err := db.GetIOCs(ctx, IOCFilter{Values: []string{value}, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("GetIOCs = %d rows, want 1: %+v", len(got), got)
	}
	g := got[0]
	if g.Count != 3 || !g.FirstSeen.Equal(t0) || !g.LastSeen.Equal(t0.Add(2*time.Minute)) {
		t.Fatalf("count=%d first=%v last=%v; want 3, %v, %v", g.Count, g.FirstSeen, g.LastSeen, t0, t0.Add(2*time.Minute))
	}
}
