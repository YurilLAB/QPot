package database

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestSlotQueryBounds(t *testing.T) {
	from := time.Unix(1_800_000_000, 0)
	for _, q := range []SlotQuery{
		{From: from, Step: time.Second, Slots: 1}, {From: from, Step: 2 * time.Second, Slots: 30},
		{From: from, Step: 30 * time.Minute, Slots: 48}, {From: from, Step: 24 * time.Hour, Slots: MaxSlots},
	} {
		if err := q.check(); err != nil {
			t.Errorf("%+v refused: %v", q, err)
		}
	}
	for _, q := range []SlotQuery{
		{Step: time.Minute, Slots: 1}, {From: from, Step: 999 * time.Millisecond, Slots: 1},
		{From: from, Step: 25 * time.Hour, Slots: 1}, {From: from, Step: time.Second + time.Microsecond, Slots: 1},
		{From: from, Step: time.Minute}, {From: from, Step: time.Minute, Slots: MaxSlots + 1}, {From: from, Step: time.Minute, Slots: -1},
	} {
		if err := q.check(); err == nil {
			t.Errorf("%+v accepted", q)
		}
	}
	if q := (SlotQuery{From: from, Step: time.Minute, Slots: 60}); !q.End().Equal(from.Add(time.Hour)) {
		t.Errorf("End: %v", q.End())
	}
}

func TestPGSlotsQuery(t *testing.T) {
	q := SlotQuery{From: time.UnixMilli(1_800_000_000_123), Step: 30 * time.Minute, Slots: 48}
	sql, args := pgSlotsQuery(q)
	want := []interface{}{int64(1_800_000_000_123), int64(1_800_000), q.From, q.End()}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args %v, want %v", args, want)
	}
	for i := 1; i <= len(args); i++ {
		if !strings.Contains(sql, fmt.Sprintf("$%d", i)) {
			t.Errorf("$%d missing: %s", i, sql)
		}
	}
	if strings.Contains(sql, "$5") || strings.Contains(sql, "1800000") {
		t.Errorf("values in the SQL: %s", sql)
	}
}

func TestESSlots(t *testing.T) {
	q := SlotQuery{From: time.UnixMilli(1_800_000_000_000), Step: 2 * time.Second, Slots: 3}
	body, err := json.Marshal(esSlotsBody(q))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"size":0`, `"field":"honeypot"`, `"format":"epoch_millis"`,
		`{"from":"1800000000000","key":"0","to":"1800000002000"}`, `{"from":"1800000004000","key":"2","to":"1800000006000"}`,
		`"gte":"2027-01-15T08:00:00Z"`, `"lt":"2027-01-15T08:00:06Z"`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("%s not in %s", want, body)
		}
	}
	answer := `{"aggregations":{"hp":{"buckets":[
		{"key":"cowrie","slots":{"buckets":[{"key":"0","doc_count":4},{"key":"1","doc_count":0},{"key":"2","doc_count":1},{"key":"3","doc_count":5}]}},
		{"key":"dionaea","slots":{"buckets":[{"key":"9","doc_count":7},{"key":"x","doc_count":7},{"key":"1","doc_count":2}]}}]}}}`
	got, err := parseESSlots(q, []byte(answer))
	if err != nil {
		t.Fatal(err)
	}
	want := []SlotCount{{"cowrie", 0, 4}, {"cowrie", 2, 1}, {"dionaea", 1, 2}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if _, err := parseESSlots(q, []byte("{")); err == nil {
		t.Error("a broken answer was accepted")
	}
}

// checkCountSlots stores events at known times and checks that CountSlots
// puts each in its slot, per honeypot, and leaves out events before, at and
// after the edges. Honeypot names of its own keep a shared database's other
// rows out.
func checkCountSlots(t *testing.T, db Database, refresh func()) {
	t.Helper()
	sc, ok := db.(SlotCounter)
	if !ok {
		t.Fatalf("%T counts no slots", db)
	}
	ctx := context.Background()
	tag := fmt.Sprintf("s%d", time.Now().UnixNano()%1e9)
	a, b := tag+"a", tag+"b"
	from := time.Now().UTC().Truncate(time.Minute).Add(-time.Hour)
	q := SlotQuery{From: from, Step: time.Minute, Slots: 10}
	at := func(min, ms int) time.Time {
		return from.Add(time.Duration(min)*time.Minute + time.Duration(ms)*time.Millisecond)
	}
	var evs []*Event
	add := func(hp string, ts time.Time) {
		evs = append(evs, &Event{Timestamp: ts, Honeypot: hp, SourceIP: "198.51.100.1", Protocol: "tcp", EventType: "x"})
	}
	add(a, at(0, 0))      // the first instant of slot 0
	add(a, at(0, 59_999)) // its last millisecond
	add(a, at(3, 500))    // slot 3
	add(b, at(3, 1))      // slot 3, another honeypot
	add(b, at(9, 59_999)) // the last millisecond of the last slot
	add(a, at(0, -1))     // before the first slot
	add(b, at(10, 0))     // the end: not in a slot
	add(b, at(-120, 0))   // long before
	if err := db.InsertEvents(ctx, evs); err != nil {
		t.Fatal(err)
	}
	if refresh != nil {
		refresh()
	}
	count := func(q SlotQuery) []SlotCount {
		t.Helper()
		got, err := sc.CountSlots(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		var mine []SlotCount
		for _, c := range got {
			if c.Honeypot == a || c.Honeypot == b {
				mine = append(mine, c)
			}
		}
		sort.Slice(mine, func(i, j int) bool {
			if mine[i].Honeypot != mine[j].Honeypot {
				return mine[i].Honeypot < mine[j].Honeypot
			}
			return mine[i].Slot < mine[j].Slot
		})
		return mine
	}
	if got, want := count(q), []SlotCount{{a, 0, 2}, {a, 3, 1}, {b, 3, 1}, {b, 9, 1}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// Slots that start half a second past the minute: the edges are kept to
	// the millisecond (at(0,0) is before the first slot, at(10,0) is in the
	// last one).
	q.From = from.Add(500 * time.Millisecond)
	if got, want := count(q), []SlotCount{{a, 0, 1}, {a, 3, 1}, {b, 2, 1}, {b, 9, 2}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("from +500 ms: got %v, want %v", got, want)
	}
	if _, err := sc.CountSlots(ctx, SlotQuery{From: from, Step: time.Minute}); err == nil {
		t.Error("zero slots accepted")
	}
}
