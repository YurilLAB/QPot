package database

import (
	"context"
	"testing"
	"time"
)

// checkSameMillisecondTagging is the regression for classifications landing
// on the wrong rows: the collector stamps many events from one attacker in
// the same millisecond, and tagging by (source_ip, timestamp) wrote every
// event's technique onto all of them (last write wins). Each event must keep
// its own classification, and none may be re-fetched as unclassified.
func checkSameMillisecondTagging(t *testing.T, db Database, ip string, refresh func()) {
	t.Helper()
	ctx := context.Background()
	ts := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Minute)
	want := map[string]string{"cowrie.session.connect": "T1046", "cowrie.login.failed": "T1110", "cowrie.command.input": "T1082"}
	var evs []*Event
	for et := range want {
		evs = append(evs, &Event{Timestamp: ts, Honeypot: "cowrie", SourceIP: ip, EventType: et})
	}
	if err := db.InsertEvents(ctx, evs); err != nil {
		t.Fatal(err)
	}
	refresh()

	mine := func() []*Event {
		all, err := db.GetUnclassifiedEvents(ctx, 1000)
		if err != nil {
			t.Fatal(err)
		}
		var out []*Event
		for _, e := range all {
			if e.SourceIP == ip {
				out = append(out, e)
			}
		}
		return out
	}
	un := mine()
	if len(un) != 3 {
		t.Fatalf("unclassified = %d, want 3", len(un))
	}
	for _, e := range un {
		if e.ID == "" {
			t.Fatalf("GetUnclassifiedEvents returned no row id: %+v", e)
		}
		e.TechniqueID = want[e.EventType]
		e.Classified = true
	}
	if bt, ok := db.(BatchTagger); ok {
		if err := bt.TagEvents(ctx, un); err != nil {
			t.Fatal(err)
		}
	} else {
		for _, e := range un {
			if err := db.TagEvent(ctx, e); err != nil {
				t.Fatal(err)
			}
		}
	}
	refresh()

	if left := mine(); len(left) != 0 {
		t.Fatalf("%d events still unclassified right after tagging", len(left))
	}
	got, err := db.GetEvents(ctx, EventFilter{SourceIPs: []string{ip}, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("GetEvents = %d rows, want 3", len(got))
	}
	for _, e := range got {
		if e.TechniqueID != want[e.EventType] {
			t.Errorf("%s tagged %q, want %q", e.EventType, e.TechniqueID, want[e.EventType])
		}
	}
}
