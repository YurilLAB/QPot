package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func newCHLeaseFixture(t *testing.T) (*ClickHouse, *ClickHouse) {
	t.Helper()
	cfg := chTestConfig(t)
	admin, err := NewClickHouse(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	nonce, err := intelligenceLeaseNonce()
	if err != nil {
		t.Fatal(err)
	}
	name := "qpot_lease_test_" + nonce
	if err := admin.conn.Exec(t.Context(), "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := admin.conn.Exec(ctx, "DROP DATABASE IF EXISTS "+name); err != nil {
			t.Errorf("remove owned lease fixture database: %v", err)
		}
	})
	connect := func() *ClickHouse {
		copyCfg := *cfg
		copyCfg.Database = name
		db, err := NewClickHouse(&copyCfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Connect(t.Context()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	a, b := connect(), connect()
	if err := a.InitializeSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	return a, b
}

func TestCHIntelligenceLeaseNativeContentionAndFencing(t *testing.T) {
	a, b := newCHLeaseFixture(t)
	ctx := t.Context()
	type result struct {
		db    *ClickHouse
		lease IntelligenceLease
	}
	winners := make(chan result, 16)
	var wg sync.WaitGroup
	for n := 0; n < 16; n++ {
		db := a
		if n%2 == 1 {
			db = b
		}
		wg.Add(1)
		go func(n int, db *ClickHouse) {
			defer wg.Done()
			lease, err := db.AcquireIntelligenceLease(ctx, fmt.Sprintf("keeper-owner-%016d", n), 30*time.Second, 0)
			if errors.Is(err, ErrIntelligenceLeaseBusy) {
				return
			}
			if err != nil {
				t.Errorf("real Keeper acquisition: %v", err)
				return
			}
			winners <- result{db, lease}
		}(n, db)
	}
	wg.Wait()
	close(winners)
	var winner result
	count := 0
	for got := range winners {
		winner = got
		count++
	}
	if count != 1 {
		t.Fatalf("real Keeper admitted %d owners, want one", count)
	}
	revision, err := winner.db.ReserveIntelligenceRevision(ctx, winner.lease, 50)
	if err != nil || revision <= 50 {
		t.Fatalf("global reserve: %d %v", revision, err)
	}
	leased := WithIntelligenceLease(ctx, winner.lease)
	now := time.Now().UTC()
	rows := []*IOC{{ID: "lease-ioc", Type: "ip", Value: "203.0.113.8", Honeypot: "cowrie", Count: 7, FirstSeen: now, LastSeen: now}}
	events := []*Event{{Timestamp: now, Honeypot: "cowrie", SourceIP: "203.0.113.8"}, {Timestamp: now, Honeypot: "cowrie", SourceIP: "203.0.113.9"}}
	for _, event := range events {
		if err := winner.db.InsertEvent(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	events, err = winner.db.GetUnclassifiedEvents(ctx, 10)
	if err != nil || len(events) != 2 {
		t.Fatalf("read exact stored row identities: %d %v", len(events), err)
	}
	for _, event := range events {
		if event.ID == "" {
			t.Fatal("stored row identity missing")
		}
		event.Classified = true
	}
	cp := &IntelligenceCheckpoint{Revision: revision, IOCs: rows, Events: events}
	if err := winner.db.SaveIntelligenceCheckpoint(leased, cp); err != nil {
		t.Fatal(err)
	}
	if err := winner.db.ReplaceIntelligenceIOCs(leased, revision, rows); err != nil {
		t.Fatal(err)
	}
	// A legitimate single-event public call remains valid in a multi-event WAL.
	if err := winner.db.TagEvent(leased, events[0]); err != nil {
		t.Fatalf("one prepared event rejected: %v", err)
	}
	if err := winner.db.TagEvents(leased, events); err != nil {
		t.Fatalf("complete prepared event batch rejected: %v", err)
	}
	var tagged uint64
	if err := winner.db.conn.QueryRow(ctx, "SELECT count() FROM events WHERE classified=1").Scan(&tagged); err != nil || tagged != 2 {
		t.Fatalf("prepared tagging did not change actual rows: %d %v", tagged, err)
	}
	changed := *rows[0]
	changed.Count = 99
	if err := winner.db.ReplaceIntelligenceIOCs(leased, revision, []*IOC{&changed}); !errors.Is(err, ErrIntelligenceLeaseLost) {
		t.Fatalf("unprepared row accepted: %v", err)
	}
	if err := winner.db.SaveIntelligenceCheckpoint(ctx, cp); !errors.Is(err, ErrIntelligenceLeaseLost) {
		t.Fatalf("unleased save accepted after activation: %v", err)
	}
	if err := winner.db.ReleaseIntelligenceLease(ctx, winner.lease); err != nil {
		t.Fatal(err)
	}
	nextDB := a
	if winner.db == a {
		nextDB = b
	}
	next, err := nextDB.AcquireIntelligenceLease(ctx, "successor-owner-0123456789", 30*time.Second, 0)
	if err != nil || next.Fence <= winner.lease.Fence || next.Namespace != winner.lease.Namespace {
		t.Fatalf("real Keeper takeover: %+v %v", next, err)
	}
	nextCtx := WithIntelligenceLease(ctx, next)
	recovered, err := nextDB.LoadIntelligenceCheckpoint(nextCtx)
	if err != nil || recovered == nil || recovered.Revision != revision {
		t.Fatalf("recover published WAL: %+v %v", recovered, err)
	}
	if err := nextDB.ReplaceIntelligenceIOCs(nextCtx, revision, recovered.IOCs); err != nil {
		t.Fatalf("replay inherited row: %v", err)
	}
	if err := winner.db.ReplaceIntelligenceIOCs(leased, revision, rows); !errors.Is(err, ErrIntelligenceLeaseLost) {
		t.Fatalf("stale projection accepted: %v", err)
	}
	if err := winner.db.TagEvent(leased, events[0]); !errors.Is(err, ErrIntelligenceLeaseLost) {
		t.Fatalf("stale event accepted: %v", err)
	}
	if _, err := winner.db.ReserveIntelligenceRevision(ctx, winner.lease, revision); !errors.Is(err, ErrIntelligenceLeaseLost) {
		t.Fatalf("stale reserve accepted: %v", err)
	}
	completion, err := nextDB.ReserveIntelligenceRevision(ctx, next, revision)
	if err != nil || completion <= revision {
		t.Fatalf("successor counter regressed: %d %v", completion, err)
	}
	future := &IntelligenceCheckpoint{Revision: completion + 10, Complete: true}
	futureDigest, err := intelligenceLeaseDigest(future)
	if err != nil {
		t.Fatal(err)
	}
	if err := nextDB.intelligenceLeaseStoreCheckpoint(ctx, future, futureDigest); err != nil {
		t.Fatal(err)
	}
	if err := nextDB.SaveIntelligenceCheckpoint(nextCtx, &IntelligenceCheckpoint{Revision: completion, Complete: true}); err != nil {
		t.Fatal(err)
	}
	var retained uint64
	if err := nextDB.conn.QueryRow(ctx, "SELECT count() FROM "+intelligenceLeaseCHRecords+" FINAL WHERE revision IN (?, ?)", completion, future.Revision).Scan(&retained); err != nil || retained != 2 {
		t.Fatalf("checkpoint maintenance removed current/future payloads: %d %v", retained, err)
	}
	var obsolete uint64
	if err := nextDB.conn.QueryRow(ctx, "SELECT count() FROM "+intelligenceLeaseCHRecords+" FINAL WHERE revision < ?", completion).Scan(&obsolete); err != nil || obsolete != 0 {
		t.Fatalf("completed checkpoint history was not reclaimed: %d %v", obsolete, err)
	}
	var got uint64
	if err := nextDB.conn.QueryRow(ctx, "SELECT count FROM intelligence_iocs FINAL WHERE id = 'lease-ioc'").Scan(&got); err != nil || got != 7 {
		t.Fatalf("replay changed count: %d %v", got, err)
	}
	_ = nextDB.ReleaseIntelligenceLease(ctx, next)
}

func TestCHIntelligenceLeaseNativeExpiryAndLargeCheckpoint(t *testing.T) {
	a, b := newCHLeaseFixture(t)
	ctx := t.Context()
	lease, err := a.AcquireIntelligenceLease(ctx, "keeper-large-owner-0123456789", 30*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := a.ReserveIntelligenceRevision(ctx, lease, 0)
	if err != nil {
		t.Fatal(err)
	}
	state, _ := json.Marshal(map[string]string{"padding": strings.Repeat("x", 2<<20)})
	cp := &IntelligenceCheckpoint{Revision: revision, State: state}
	if err := a.SaveIntelligenceCheckpoint(WithIntelligenceLease(ctx, lease), cp); err != nil {
		t.Fatal(err)
	}
	var size uint64
	if err := a.conn.QueryRow(ctx, "SELECT length(value) FROM "+intelligenceLeaseCHControl+" WHERE key='worker'").Scan(&size); err != nil || size >= 16<<10 {
		t.Fatalf("large WAL leaked into Keeper: %d %v", size, err)
	}
	lease, err = a.RenewIntelligenceLease(ctx, lease, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(1150 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-timer.C:
	}
	next, err := b.AcquireIntelligenceLease(ctx, "keeper-next-owner-0123456789", 30*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := b.LoadIntelligenceCheckpoint(WithIntelligenceLease(ctx, next))
	if err != nil || loaded == nil || string(loaded.State) != string(state) {
		t.Fatalf("large immutable checkpoint recovery: %v", err)
	}
	if _, err := a.RenewIntelligenceLease(ctx, lease, time.Second); !errors.Is(err, ErrIntelligenceLeaseLost) {
		t.Fatalf("expired owner renewed: %v", err)
	}
	_ = b.ReleaseIntelligenceLease(ctx, next)
}

func TestCHIntelligenceLeaseRejectsNonAtomicControlCatalog(t *testing.T) {
	a, _ := newCHLeaseFixture(t)
	if err := a.conn.Exec(t.Context(), "CREATE TABLE "+intelligenceLeaseCHControl+" (key String,value String) ENGINE=Memory"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AcquireIntelligenceLease(t.Context(), "unsupported-owner-0123456789", 30*time.Second, 0); !errors.Is(err, ErrIntelligenceLeaseUnavailable) {
		t.Fatalf("non-atomic table accepted: %v", err)
	}
	if err := a.InsertEvent(t.Context(), &Event{Timestamp: time.Now().UTC(), Honeypot: "cowrie", SourceIP: "203.0.113.5", EventType: "login_failed"}); err != nil {
		t.Fatalf("collection stopped with unsupported coordination: %v", err)
	}
}

func TestCHIntelligenceLeaseMissingKeeperFailsClosed(t *testing.T) {
	if os.Getenv("QPOT_TEST_CH_EXPECT_NO_KEEPER") != "1" {
		t.Skip("set QPOT_TEST_CH_EXPECT_NO_KEEPER=1 only on the owned no-Keeper fixture")
	}
	a, _ := newCHLeaseFixture(t)
	if _, err := a.AcquireIntelligenceLease(t.Context(), "missing-keeper-owner-0123456789", 30*time.Second, 0); !errors.Is(err, ErrIntelligenceLeaseUnavailable) {
		t.Fatalf("missing Keeper did not fail closed: %v", err)
	}
	if err := a.InsertEvent(t.Context(), &Event{Timestamp: time.Now().UTC(), Honeypot: "cowrie", SourceIP: "203.0.113.5", EventType: "login_failed"}); err != nil {
		t.Fatalf("collection stopped without Keeper: %v", err)
	}
}
