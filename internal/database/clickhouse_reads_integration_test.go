package database

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"
)

// TestClickHouseIOCPages: a page of indicators, chosen from keys and times
// and then read by key, is the same rows in the same order as that slice of
// a read of everything: with and without rows in the legacy table, with a
// key that both tables hold, and with filters.
func TestClickHouseIOCPages(t *testing.T) {
	db := connectCH(t)
	ch := db.(*ClickHouse)
	ctx := context.Background()
	hp := fmt.Sprintf("pages%d", time.Now().UnixNano())
	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	worker := func(revision, n int, typ string, last time.Time, count int) {
		t.Helper()
		if err := ch.conn.Exec(ctx, `INSERT INTO intelligence_iocs (revision, id, type, value, honeypot, source_ip, technique_id, first_seen, last_seen, count, metadata)
			VALUES (?, ?, ?, ?, ?, ?, 'T1110', ?, ?, ?, map('n', ?))`,
			uint64(revision), fmt.Sprintf("id-%s-%d", hp, n), typ, fmt.Sprintf("value-%03d", n), hp, fmt.Sprintf("198.51.100.%d", n%200),
			base, last, uint64(count), fmt.Sprint(n)); err != nil {
			t.Fatal(err)
		}
	}
	for n := 0; n < 40; n++ {
		typ := []string{"ip", "url", "command"}[n%3]
		// Pairs share a moment, so the order within one is by key.
		worker(1, n, typ, base.Add(time.Duration(n/2)*time.Minute), 1)
	}
	// A newer revision of one indicator: it must appear once, as revised.
	worker(2, 7, "url", base.Add(90*time.Minute), 9)

	all := func(filter IOCFilter) []*IOC {
		t.Helper()
		filter.Honeypots, filter.Limit, filter.Offset = []string{hp}, 0, 0
		out, err := db.GetIOCs(ctx, filter)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	check := func(what string) {
		t.Helper()
		for _, filter := range []IOCFilter{{}, {Types: []string{"url"}}, {Values: []string{"value-007", "value-012", "value-900"}},
			{StartTime: base.Add(-time.Hour), EndTime: base.Add(10 * time.Minute)}} {
			full := all(filter)
			for _, page := range [][2]int{{5, 0}, {5, 3}, {15, 0}, {100, 0}, {4, len(full) - 2}, {3, len(full) + 5}} {
				if page[1] < 0 {
					continue
				}
				f := filter
				f.Honeypots, f.Limit, f.Offset = []string{hp}, page[0], page[1]
				got, err := db.GetIOCs(ctx, f)
				if err != nil {
					t.Fatalf("%s: page %v of %+v: %v", what, page, filter, err)
				}
				want := full[min(page[1], len(full)):min(page[1]+page[0], len(full))]
				if len(got) != len(want) {
					t.Fatalf("%s: page %v of %+v has %d rows, want %d", what, page, filter, len(got), len(want))
				}
				for i := range want {
					if !reflect.DeepEqual(got[i], want[i]) {
						t.Fatalf("%s: page %v of %+v, row %d:\n got %+v\nwant %+v", what, page, filter, i, got[i], want[i])
					}
				}
			}
		}
	}
	full := all(IOCFilter{})
	if len(full) != 40 || full[0].Value != "value-007" || full[0].Count != 9 || full[0].Metadata["n"] != "7" {
		t.Fatalf("a read of everything: %d rows, first %+v; want 40 with the revised value-007 first", len(full), full[0])
	}
	before, err := ch.CountIOCs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	check("worker table only")

	// The legacy table: one indicator of its own, and one the worker's table
	// holds too (the worker's wins).
	legacy := func(n int, last time.Time, count int) {
		t.Helper()
		if err := ch.conn.Exec(ctx, `INSERT INTO iocs (id, type, value, honeypot, source_ip, technique_id, first_seen, last_seen, count, metadata)
			VALUES (?, 'ip', ?, ?, '203.0.113.9', 'T1110', ?, ?, ?, map('legacy', '1'))`,
			fmt.Sprintf("legacy-%s-%d", hp, n), fmt.Sprintf("value-%03d", n), hp, base, last, uint64(count)); err != nil {
			t.Fatal(err)
		}
	}
	legacy(900, base.Add(3*time.Minute), 4)
	legacy(0, base.Add(200*time.Minute), 77) // value-000 is type ip in the worker's table as well
	full = all(IOCFilter{})
	if len(full) != 41 {
		t.Fatalf("with the legacy table: %d rows, want 41", len(full))
	}
	for _, ioc := range full {
		if ioc.Value == "value-000" && (ioc.Count != 1 || ioc.Metadata["legacy"] != "") {
			t.Fatalf("an indicator both tables hold came from the legacy table: %+v", ioc)
		}
	}
	check("with the legacy table")
	after, err := ch.CountIOCs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after != before+1 {
		t.Errorf("CountIOCs went from %d to %d when the legacy table gained one indicator of its own and one shared", before, after)
	}
	everything, err := db.GetIOCs(ctx, IOCFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(everything)) != after {
		t.Errorf("CountIOCs says %d, a read of everything returns %d", after, len(everything))
	}
}

// TestClickHouseSessionPages: the newest sessions, chosen by ID and time and
// then read by ID, are the same as the head of a read of everything.
func TestClickHouseSessionPages(t *testing.T) {
	db := connectCH(t)
	ch := db.(*ClickHouse)
	ctx := context.Background()
	tag := fmt.Sprintf("pages%d", time.Now().UnixNano())
	// Later than anything another test stores, so these are the newest.
	base := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	insert := func(table string, revision, n int, last time.Time, events int) {
		t.Helper()
		columns, values := "revision, ", "?, "
		args := []any{uint64(revision)}
		if table == "ttp_sessions" {
			columns, values, args = "", "", nil
		}
		args = append(args, fmt.Sprintf("%s-%02d", tag, n), "fp-"+tag, []string{"198.51.100.7"}, []string{"exploitation"}, []string{"T1110"}, []string{"ioc"}, uint64(events), base, last)
		if err := ch.conn.Exec(ctx, `INSERT INTO `+table+` (`+columns+`session_id, campaign_fingerprint, source_ips, shared_infrastructure, kill_chain_stages, techniques, ioc_ids, event_count, first_seen, last_seen, confidence)
			VALUES (`+values+`?, ?, ?, 0, ?, ?, ?, ?, ?, ?, 0.5)`, args...); err != nil {
			t.Fatal(err)
		}
	}
	for n := 0; n < 12; n++ {
		insert("intelligence_sessions", 1, n, base.Add(time.Duration(n/2)*time.Minute), 1)
	}
	insert("intelligence_sessions", 2, 3, base.Add(30*time.Minute), 8) // revised: now the newest
	check := func(what string, wantFirst string, total int) {
		t.Helper()
		full, err := db.GetTTPSessions(ctx, 0)
		if err != nil {
			t.Fatal(err)
		}
		var ours []*TTPSession
		for _, s := range full {
			if s.CampaignFingerprint == "fp-"+tag {
				ours = append(ours, s)
			}
		}
		if len(ours) != total || ours[0].SessionID != wantFirst {
			t.Fatalf("%s: %d sessions, first %s; want %d, first %s", what, len(ours), ours[0].SessionID, total, wantFirst)
		}
		if !sort.SliceIsSorted(full, func(i, j int) bool {
			if !full[i].LastSeen.Equal(full[j].LastSeen) {
				return full[i].LastSeen.After(full[j].LastSeen)
			}
			return full[i].SessionID < full[j].SessionID
		}) {
			t.Fatalf("%s: a read of everything is not newest first, then by ID", what)
		}
		for _, limit := range []int{1, 5, total, total + 50} {
			got, err := db.GetTTPSessions(ctx, limit)
			if err != nil {
				t.Fatalf("%s: newest %d: %v", what, limit, err)
			}
			want := full[:min(limit, len(full))]
			if len(got) != len(want) {
				t.Fatalf("%s: newest %d returned %d sessions, want %d", what, limit, len(got), len(want))
			}
			for i := range want {
				if !reflect.DeepEqual(got[i], want[i]) {
					t.Fatalf("%s: newest %d, row %d:\n got %+v\nwant %+v", what, limit, i, got[i], want[i])
				}
			}
		}
	}
	check("worker table only", tag+"-03", 12)
	if s, _ := db.GetTTPSessions(ctx, 1); len(s) != 1 || s[0].EventCount != 8 {
		t.Fatalf("the revised session is not returned as revised: %+v", s)
	}
	insert("ttp_sessions", 0, 50, base.Add(40*time.Minute), 2) // only the legacy table has it
	insert("ttp_sessions", 0, 3, base.Add(50*time.Minute), 99) // both have it: the worker's wins
	check("with the legacy table", tag+"-50", 13)
	if s, _ := db.GetTTPSessions(ctx, 2); len(s) != 2 || s[1].SessionID != tag+"-03" || s[1].EventCount != 8 {
		t.Fatalf("a session both tables hold came from the legacy table: %+v", s)
	}
}

// TestClickHouseRecentSummaries: the database's own counts over the newest
// events are what counting the events GetEvents returns gives.
func TestClickHouseRecentSummaries(t *testing.T) {
	db := connectCH(t)
	ch := db.(*ClickHouse)
	ctx := context.Background()
	marker := fmt.Sprintf("summary-%d", time.Now().UnixNano())
	for i, row := range []struct {
		technique, name, tactic string
		categories              []string
	}{
		{"T1110", "Brute Force", "Credential Access", []string{"brute-force"}},
		{"T1110", "Brute Force", "Credential Access", []string{"brute-force", "scan"}},
		{"T1105", "Ingress Tool Transfer", "Command and Control", []string{"download"}},
		{"", "", "", nil},
	} {
		if err := ch.conn.Exec(ctx, `INSERT INTO events (timestamp, honeypot, source_ip, event_type, technique_id, technique_name, tactic_name, categories, classified)
			VALUES (now64(3) - toIntervalSecond(?), 'cowrie', '198.51.100.92', ?, ?, ?, ?, ?, 1)`, i, marker, row.technique, row.name, row.tactic, chCategories(row.categories)); err != nil {
			t.Fatal(err)
		}
	}
	// More than the test database holds, so both ways see the same events.
	const sample = 5_000_000
	events, err := db.GetEvents(ctx, EventFilter{Limit: sample})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) >= sample {
		t.Skipf("the test database holds %d events or more; the comparison needs fewer", sample)
	}
	wantTechniques, wantCategories := map[string]int{}, map[string]int{}
	for _, e := range events {
		if e.TechniqueID != "" {
			wantTechniques[e.TechniqueID]++
		}
		for _, c := range e.Categories {
			wantCategories[c]++
		}
	}
	techniques, err := ch.RecentTechniques(ctx, sample)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for i, tc := range techniques {
		got[tc.TechniqueID] = tc.Count
		if tc.TechniqueID == "" {
			t.Error("events without a technique were counted as one")
		}
		if i > 0 && (techniques[i-1].Count < tc.Count || techniques[i-1].Count == tc.Count && techniques[i-1].TechniqueID > tc.TechniqueID) {
			t.Errorf("techniques are not most frequent first, then by ID: %+v before %+v", techniques[i-1], tc)
		}
		if tc.TechniqueID == "T1105" && (tc.TechniqueName != "Ingress Tool Transfer" || tc.TacticName != "Command and Control") {
			t.Errorf("T1105 came back as %+v", tc)
		}
	}
	if !reflect.DeepEqual(got, wantTechniques) || got["T1110"] < 2 {
		t.Errorf("techniques: %v\nwant:       %v", got, wantTechniques)
	}
	categories, err := ch.RecentCategories(ctx, sample)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(categories, wantCategories) || categories["brute-force"] < 2 {
		t.Errorf("categories: %v\nwant:       %v", categories, wantCategories)
	}
	// A sample of the newest event only: the newest of the four has T1110.
	if one, err := ch.RecentTechniques(ctx, 1); err != nil || len(one) > 1 {
		t.Errorf("a sample of one event counted %d techniques (%v)", len(one), err)
	}
	if none, err := ch.RecentTechniques(ctx, 0); err != nil || len(none) != 0 {
		t.Errorf("an empty sample counted %d techniques (%v)", len(none), err)
	}
}

// TestClickHouseClassifiedIDs: the set of classified observation IDs answers
// the worker's question once it is complete, is filled from a database an
// earlier version classified, and gains what tagging classifies.
func TestClickHouseClassifiedIDs(t *testing.T) {
	db := connectCH(t)
	ch := db.(*ClickHouse)
	ctx := context.Background()
	marker := fmt.Sprintf("idset-%d", time.Now().UnixNano())
	id := func(name string) string { return obsID(marker + name) }
	send := func(command, eventID string, classified int) *Event {
		t.Helper()
		at := time.Now().UTC().Truncate(time.Millisecond)
		if err := ch.conn.Exec(ctx, `INSERT INTO events (timestamp, honeypot, source_ip, event_type, command, event_id, classified)
			VALUES (fromUnixTimestamp64Milli(?), 'cowrie', '198.51.100.93', ?, ?, ?, ?)`, at.UnixMilli(), marker, command, eventID, uint8(classified)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond) // every row its own moment
		return &Event{ID: eventID, Timestamp: at, Honeypot: "cowrie", EventType: marker, Command: command}
	}
	inSet := func(eventID string) bool {
		t.Helper()
		var n uint64
		if err := ch.conn.QueryRow(ctx, "SELECT count() FROM "+classifiedIDsTable+" WHERE event_id = toUUID(?)", eventID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n > 0
	}
	remove := func(events ...*Event) (kept, removed int) {
		t.Helper()
		k, r, err := ch.RemoveReplayedEvents(ctx, events)
		if err != nil {
			t.Fatal(err)
		}
		return len(k), r
	}

	// A database as an earlier version left it: classified rows, no set.
	send("old-first", id("old"), 1)
	send("old2-first", id("old2"), 1)
	if err := ch.conn.Exec(ctx, "TRUNCATE TABLE "+classifiedIDsTable); err != nil {
		t.Fatal(err)
	}
	ch.ids.mu.Lock()
	ch.ids.ready, ch.ids.next = false, time.Time{}
	ch.ids.mu.Unlock()

	// Before the set is complete the events table answers, and rightly.
	again := send("old-again", id("old"), 0)
	if kept, removed := remove(again, send("fresh", id("fresh"), 0)); kept != 1 || removed != 1 {
		t.Fatalf("before the set is complete: kept %d, removed %d; want 1, 1", kept, removed)
	}
	// That lookup started the copy.
	deadline := time.Now().Add(90 * time.Second)
	for !ch.classifiedIDsUsable(ctx) {
		if time.Now().After(deadline) {
			t.Fatal("the IDs of the rows classified earlier were not copied within 90 s")
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !inSet(id("old")) || !inSet(id("old2")) || !inSet(classifiedIDsReady) {
		t.Fatal("the copy does not hold the IDs classified before it, or is not marked complete")
	}
	if inSet(id("fresh")) {
		t.Fatal("an unclassified event's ID is in the set")
	}

	// Now the set answers. An ID that only the set holds proves it: the
	// events table has no classified row for it.
	if err := ch.conn.Exec(ctx, "INSERT INTO "+classifiedIDsTable+" (event_id) VALUES (toUUID(?))", id("set-only")); err != nil {
		t.Fatal(err)
	}
	if kept, removed := remove(send("old2-again", id("old2"), 0), send("set-only-copy", id("set-only"), 0), send("single", id("single"), 0)); kept != 1 || removed != 2 {
		t.Fatalf("with the set complete: kept %d, removed %d; want 1 (the single one), 2", kept, removed)
	}

	// Tagging marks the row first and adds the ID after it.
	tagged := send("tagged", id("tagged"), 0)
	tagged.TechniqueID = "T1059"
	if inSet(id("tagged")) {
		t.Fatal("an ID is in the set before its event was classified")
	}
	if err := db.(BatchTagger).TagEvents(ctx, []*Event{tagged}); err != nil {
		t.Fatal(err)
	}
	var classified uint64
	if err := ch.conn.QueryRow(ctx, "SELECT count() FROM events WHERE event_id = toUUID(?) AND classified = 1", id("tagged")).Scan(&classified); err != nil || classified != 1 {
		t.Fatalf("tagging classified %d rows (%v), want 1", classified, err)
	}
	if !inSet(id("tagged")) {
		t.Fatal("tagging did not add the ID to the set")
	}
	if kept, removed := remove(send("tagged-again", id("tagged"), 0)); kept != 0 || removed != 1 {
		t.Fatalf("a second copy of a tagged event: kept %d, removed %d; want 0, 1", kept, removed)
	}
	// A new connection finds the set complete without copying again.
	other := connectCH(t).(*ClickHouse)
	if !other.classifiedIDsUsable(ctx) {
		t.Fatal("a second connection does not see the set as complete")
	}
}
