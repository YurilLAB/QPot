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
