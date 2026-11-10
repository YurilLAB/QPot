package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func newPGLeaseFixture(t *testing.T) (*TimescaleDB, *TimescaleDB, string) {
	t.Helper()
	if os.Getenv("QPOT_TEST_POSTGRES") != "1" {
		t.Skip("set QPOT_TEST_POSTGRES=1 for real PostgreSQL lease tests")
	}
	port := envOr("QPOT_TEST_PG_PORT", "5432")
	if _, err := strconv.Atoi(port); err != nil {
		t.Fatal("invalid PostgreSQL fixture port")
	}
	values := url.Values{"sslmode": {"disable"}}
	dsn := (&url.URL{Scheme: "postgres", User: url.UserPassword(envOr("QPOT_TEST_PG_USER", "postgres"), envOr("QPOT_TEST_PG_PASS", "postgres")), Host: net.JoinHostPort(envOr("QPOT_TEST_PG_HOST", "127.0.0.1"), port), Path: "/" + envOr("QPOT_TEST_PG_DB", "qpot_test"), RawQuery: values.Encode()}).String()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	if err := admin.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	nonce, err := intelligenceLeaseNonce()
	if err != nil {
		t.Fatal(err)
	}
	databaseName := "qpot_lease_" + nonce
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+pgx.Identifier{databaseName}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, `DROP DATABASE `+pgx.Identifier{databaseName}.Sanitize()+` WITH (FORCE)`); err != nil {
			t.Errorf("remove owned lease fixture database: %v", err)
		}
	})
	ownedURL, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ownedURL.Path = "/" + databaseName
	dsn = ownedURL.String()
	ownedAdmin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ownedAdmin.Close)
	schema := "lease_test_" + nonce
	prefix := schema + "_alias"
	for _, name := range []string{schema, prefix} {
		if _, err := ownedAdmin.Exec(ctx, `CREATE SCHEMA `+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Fatal(err)
		}
	}
	connect := func(alias bool) *TimescaleDB {
		pc, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		search := pgx.Identifier{schema}.Sanitize()
		if alias {
			search = pgx.Identifier{prefix}.Sanitize() + "," + search
		}
		pc.ConnConfig.RuntimeParams["search_path"] = search
		pc.ConnConfig.RuntimeParams["application_name"] = schema + map[bool]string{false: "_first", true: "_second"}[alias]
		pc.MaxConns = 8
		pool, err := pgxpool.NewWithConfig(ctx, pc)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		if err := pool.Ping(ctx); err != nil {
			t.Fatal(err)
		}
		return &TimescaleDB{pool: pool}
	}
	a, b := connect(false), connect(true)
	// This shared legacy object makes alias search_path resolution explicit.
	if _, err := a.pool.Exec(ctx, `CREATE TABLE intelligence_checkpoint (id integer PRIMARY KEY CHECK(id=1),revision bigint NOT NULL,payload jsonb NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	return a, b, schema
}

func pgLeaseTestOperation(t *testing.T, kind, owner string, current *intelligenceLeaseState) intelligenceLeaseOperation {
	t.Helper()
	nonce, err := intelligenceLeaseNonce()
	if err != nil {
		t.Fatal(err)
	}
	op := intelligenceLeaseOperation{Kind: kind, Owner: owner, Namespace: nonce, TTLMillis: 30000, Nonce: nonce}
	if current != nil {
		op.Owner, op.Fence, op.Namespace = current.Owner, current.Fence, current.Namespace
	}
	return op
}

func TestPGIntelligenceLeaseIndependentOwnersAndAliases(t *testing.T) {
	a, b, schema := newPGLeaseFixture(t)
	ctx := t.Context()
	var successes int
	var result intelligenceLeaseState
	var mu sync.Mutex
	var wg sync.WaitGroup
	for n := 0; n < 12; n++ {
		db := a
		if n%2 == 1 {
			db = b
		}
		op := pgLeaseTestOperation(t, "acquire", fmt.Sprintf("contender-owner-%03d", n), nil)
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := db.intelligenceLeaseMutate(ctx, op)
			if errors.Is(err, ErrIntelligenceLeaseBusy) {
				return
			}
			if err != nil {
				t.Errorf("lease acquisition: %v", err)
				return
			}
			mu.Lock()
			successes++
			result = got
			mu.Unlock()
		}()
	}
	wg.Wait()
	if successes != 1 || result.Fence != 1 {
		t.Fatalf("independent pools acquired %d owners (fence %d), want one", successes, result.Fence)
	}
	state, _, err := b.intelligenceLeaseRead(ctx)
	if err != nil || state == nil || state.Owner != result.Owner || state.Namespace != result.Namespace {
		t.Fatalf("alias did not observe shared owner: %v %v", state, err)
	}
	var privateControl bool
	if err := b.pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, pgIntelligenceTable(schema+"_alias", pgIntelligenceControlTable)).Scan(&privateControl); err != nil || privateControl {
		t.Fatalf("account search_path created a separate owner: %v %v", privateControl, err)
	}
}

func TestPGIntelligenceLeaseShadowCheckpointCannotSplitOwner(t *testing.T) {
	a, b, _ := newPGLeaseFixture(t)
	ctx := t.Context()
	for _, query := range []string{`CREATE TABLE events(id bigint)`, `CREATE TABLE iocs(id bigint)`, `CREATE TABLE ttp_sessions(id text)`} {
		if _, err := a.pool.Exec(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	// The second account/search_path shadows only its old checkpoint. Both
	// accounts still resolve the same actual event/IOC/session storage.
	if _, err := b.pool.Exec(ctx, `CREATE TABLE intelligence_checkpoint (id integer PRIMARY KEY CHECK(id=1),revision bigint NOT NULL,payload jsonb NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := a.intelligenceLeaseMutate(ctx, pgLeaseTestOperation(t, "acquire", "shadow-first-owner-1", nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.intelligenceLeaseMutate(ctx, pgLeaseTestOperation(t, "acquire", "shadow-second-owner1", nil)); !errors.Is(err, ErrIntelligenceLeaseBusy) {
		t.Fatalf("private checkpoint shadow split shared database ownership: %v", err)
	}
}

func TestPGIntelligenceLeaseRejectsDifferentProjectionScope(t *testing.T) {
	a, b, _ := newPGLeaseFixture(t)
	ctx := t.Context()
	for _, query := range []string{`CREATE TABLE events(id bigint)`, `CREATE TABLE iocs(id bigint)`, `CREATE TABLE ttp_sessions(id text)`} {
		if _, err := a.pool.Exec(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	first, err := a.intelligenceLeaseMutate(ctx, pgLeaseTestOperation(t, "acquire", "scope-first-owner-01", nil))
	if err != nil {
		t.Fatal(err)
	}
	// A takeover must not replay the durable WAL into a different relation
	// merely because another account resolves the same unqualified name.
	if _, err := b.pool.Exec(ctx, `CREATE TABLE events(id bigint)`); err != nil {
		t.Fatal(err)
	}
	if _, err := b.intelligenceLeaseMutate(ctx, pgLeaseTestOperation(t, "acquire", "scope-second-owner1", nil)); !errors.Is(err, ErrIntelligenceLeaseUnavailable) {
		t.Fatalf("different storage scope was admitted: %v", err)
	}
	if _, _, err := b.intelligenceLeaseRead(ctx); !errors.Is(err, ErrIntelligenceLeaseUnavailable) {
		t.Fatalf("different storage scope read was accepted: %v", err)
	}
	current, _, err := a.intelligenceLeaseRead(ctx)
	if err != nil || current.Owner != first.Owner || current.Fence != first.Fence {
		t.Fatalf("foreign storage view altered the legitimate owner: %v %v", current, err)
	}
}

func TestPGIntelligenceLeaseCoordinatesDifferentDatabaseRoles(t *testing.T) {
	a, _, schema := newPGLeaseFixture(t)
	ctx := t.Context()
	first, err := a.AcquireIntelligenceLease(ctx, "database-role-owner1", 30*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := intelligenceLeaseNonce()
	if err != nil {
		t.Fatal(err)
	}
	role := "lease_role_" + nonce
	password, err := intelligenceLeaseNonce()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.pool.Exec(ctx, `CREATE ROLE `+pgx.Identifier{role}.Sanitize()+` LOGIN PASSWORD '`+password+`'`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := a.pool.Exec(cleanup, `DROP OWNED BY `+pgx.Identifier{role}.Sanitize()); err != nil {
			t.Errorf("revoke owned test-role grants: %v", err)
		}
		if _, err := a.pool.Exec(cleanup, `DROP ROLE `+pgx.Identifier{role}.Sanitize()); err != nil {
			t.Errorf("remove owned test role: %v", err)
		}
	})
	for _, namespace := range []string{schema, schema + "_alias", pgIntelligenceCoordinatorSchema} {
		if _, err := a.pool.Exec(ctx, `GRANT USAGE ON SCHEMA `+pgx.Identifier{namespace}.Sanitize()+` TO `+pgx.Identifier{role}.Sanitize()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.pool.Exec(ctx, `GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA `+pgx.Identifier{pgIntelligenceCoordinatorSchema}.Sanitize()+` TO `+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	pc := a.pool.Config()
	pc.ConnConfig.User, pc.ConnConfig.Password = role, password
	pc.ConnConfig.RuntimeParams["search_path"] = pgx.Identifier{schema + "_alias"}.Sanitize() + "," + pgx.Identifier{schema}.Sanitize()
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	secondDB := &TimescaleDB{pool: pool}
	if _, err := secondDB.AcquireIntelligenceLease(ctx, "database-role-owner2", 30*time.Second, 0); !errors.Is(err, ErrIntelligenceLeaseBusy) {
		t.Fatalf("different database role did not share the existing owner: %v", err)
	}
	if err := a.ReleaseIntelligenceLease(ctx, first); err != nil {
		t.Fatal(err)
	}
	second, err := secondDB.AcquireIntelligenceLease(ctx, "database-role-owner2", 30*time.Second, 0)
	if err != nil || second.Fence <= first.Fence {
		t.Fatalf("DML-authorized successor unnecessarily required database CREATE: %v", err)
	}
}

func TestPGIntelligenceLeaseExpiryRecoveryAndLargeCheckpoint(t *testing.T) {
	a, b, _ := newPGLeaseFixture(t)
	ctx := t.Context()
	large, err := json.Marshal(strings.Repeat("large-session-state-", 120000))
	if err != nil {
		t.Fatal(err)
	}
	legacy := &IntelligenceCheckpoint{Revision: 77, State: large}
	payload, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.pool.Exec(ctx, `INSERT INTO intelligence_checkpoint VALUES(1,77,$1)`, payload); err != nil {
		t.Fatal(err)
	}
	op := pgLeaseTestOperation(t, "acquire", "first-owner-00000001", nil)
	op.Minimum = 5
	first, err := a.intelligenceLeaseMutate(ctx, op)
	if err != nil || first.Reserved != 77 || first.CheckpointRevision != 77 {
		t.Fatalf("legacy migration lost revision: %v %v", first, err)
	}
	loaded, err := a.intelligenceLeaseLoadCheckpoint(ctx, first.CheckpointRevision, first.CheckpointDigest)
	if err != nil || loaded.Revision != legacy.Revision || string(loaded.State) != string(legacy.State) {
		t.Fatalf("large checkpoint migration: %v", err)
	}
	reserve := pgLeaseTestOperation(t, "reserve", "", &first)
	reserved, err := a.intelligenceLeaseMutate(ctx, reserve)
	if err != nil || reserved.Reserved != 78 {
		t.Fatalf("global reservation: %v %v", reserved, err)
	}
	cp := &IntelligenceCheckpoint{Revision: 78, State: large}
	digest, err := intelligenceLeaseDigest(cp)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.intelligenceLeaseStoreCheckpoint(ctx, cp, digest); err != nil {
		t.Fatal(err)
	}
	publish := pgLeaseTestOperation(t, "publish", "", &first)
	publish.Revision, publish.Digest = cp.Revision, digest
	if _, err := a.intelligenceLeaseMutate(ctx, publish); err != nil {
		t.Fatal(err)
	}
	renew := pgLeaseTestOperation(t, "renew", "", &first)
	renew.TTLMillis = 1000
	if _, err := a.intelligenceLeaseMutate(ctx, renew); err != nil {
		t.Fatal(err)
	}
	// Expiry is driven by PostgreSQL's clock, without mutating control state.
	if _, err := a.pool.Exec(ctx, `SELECT pg_sleep(1.1)`); err != nil {
		t.Fatal(err)
	}
	second, err := b.intelligenceLeaseMutate(ctx, pgLeaseTestOperation(t, "acquire", "second-owner-000001", nil))
	if err != nil || second.Fence <= first.Fence || second.Reserved != 78 || second.CheckpointDigest != digest {
		t.Fatalf("expiry takeover lost durable WAL: %v %v", second, err)
	}
	for _, kind := range []string{"renew", "reserve", "publish", "release"} {
		stale := pgLeaseTestOperation(t, kind, "", &first)
		stale.Revision, stale.Digest = cp.Revision, digest
		if _, err := a.intelligenceLeaseMutate(ctx, stale); !errors.Is(err, ErrIntelligenceLeaseLost) {
			t.Errorf("stale %s accepted after takeover: %v", kind, err)
		}
	}
	recovered, err := b.intelligenceLeaseLoadCheckpoint(ctx, second.CheckpointRevision, second.CheckpointDigest)
	if err != nil || recovered.Revision != cp.Revision || string(recovered.State) != string(cp.State) {
		t.Fatalf("successor could not recover exact large WAL: %v", err)
	}
	next, err := b.intelligenceLeaseMutate(ctx, pgLeaseTestOperation(t, "reserve", "", &second))
	if err != nil || next.Reserved != 79 {
		t.Fatalf("successor reused prior revision: %v %v", next, err)
	}
	changed := *cp
	changed.Complete = true
	changedDigest, err := intelligenceLeaseDigest(&changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.intelligenceLeaseStoreCheckpoint(ctx, &changed, changedDigest); err == nil {
		t.Fatal("same revision accepted different immutable payload")
	}
	released, err := b.intelligenceLeaseMutate(ctx, pgLeaseTestOperation(t, "release", "", &second))
	if err != nil || released.Owner != "" || released.Reserved != 79 || released.Fence != second.Fence {
		t.Fatalf("release reset ownership history: %v %v", released, err)
	}
	third, err := a.intelligenceLeaseMutate(ctx, pgLeaseTestOperation(t, "acquire", "third-owner-0000001", nil))
	if err != nil || third.Fence <= second.Fence || third.Reserved != 79 {
		t.Fatalf("restart reset fencing or reservations: %v %v", third, err)
	}
}

func TestPGIntelligenceLeaseClockCheckedAfterRowLock(t *testing.T) {
	a, b, schema := newPGLeaseFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	op := pgLeaseTestOperation(t, "acquire", "row-lock-owner-0001", nil)
	op.TTLMillis = 1000
	first, err := a.intelligenceLeaseMutate(ctx, op)
	if err != nil {
		t.Fatal(err)
	}
	locker, err := a.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Rollback(context.Background())
	var state []byte
	if err := locker.QueryRow(ctx, `SELECT state FROM `+pgIntelligenceTable(pgIntelligenceCoordinatorSchema, pgIntelligenceControlTable)+` WHERE id=1 FOR UPDATE`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	renew := pgLeaseTestOperation(t, "renew", "", &first)
	go func() {
		_, err := b.intelligenceLeaseMutate(ctx, renew)
		finished <- err
	}()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiting bool
		if err := a.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock')`, schema+"_second").Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-finished:
			t.Fatalf("renewal bypassed held row lock: %v", err)
		case <-ctx.Done():
			t.Fatal("renewal did not reach row-lock wait")
		case <-tick.C:
		}
	}
	if _, err := locker.Exec(ctx, `SELECT pg_sleep(1.1)`); err != nil {
		t.Fatal(err)
	}
	if err := locker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-finished; !errors.Is(err, ErrIntelligenceLeaseLost) {
		t.Fatalf("expired queued renewal used a pre-lock clock: %v", err)
	}
}

func TestPGIntelligenceLeasePublicCheckpointProjectionAndTags(t *testing.T) {
	a, b, _ := newPGLeaseFixture(t)
	ctx := t.Context()
	if err := a.createIOCTable(ctx); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`ALTER TABLE iocs ADD COLUMN intelligence_revision bigint NOT NULL DEFAULT 0`,
		`CREATE TABLE events(id bigint PRIMARY KEY,timestamp timestamptz NOT NULL,source_ip inet,technique_id text,technique_name text,tactic_id text,tactic_name text,kill_chain_stage text,confidence double precision,categories text[],classified boolean NOT NULL DEFAULT false)`,
	} {
		if _, err := a.pool.Exec(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	first, err := a.AcquireIntelligenceLease(ctx, "public-first-owner-01", 30*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	firstCtx := WithIntelligenceLease(ctx, first)
	revision, err := a.ReserveIntelligenceRevision(ctx, first, 0)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	event := &Event{ID: "1", Timestamp: now, SourceIP: "198.51.100.7", TechniqueID: "T1082", TechniqueName: "System Information Discovery", Classified: true}
	if _, err := a.pool.Exec(ctx, `INSERT INTO events(id,timestamp,source_ip) VALUES(1,$1,$2)`, now, event.SourceIP); err != nil {
		t.Fatal(err)
	}
	ioc := &IOC{ID: "fixture-ip", Type: "ip", Value: "198.51.100.7", Honeypot: "cowrie", FirstSeen: now, LastSeen: now, Count: 1}
	prepared := &IntelligenceCheckpoint{Revision: revision, Events: []*Event{event}, IOCs: []*IOC{ioc}}
	if err := a.SaveIntelligenceCheckpoint(firstCtx, prepared); err != nil {
		t.Fatal(err)
	}
	bad := *ioc
	bad.Count = 999
	if err := a.ReplaceIntelligenceIOCs(firstCtx, revision, []*IOC{&bad}); !errors.Is(err, ErrIntelligenceLeaseLost) {
		t.Fatalf("projection not matching the durable WAL was accepted: %v", err)
	}
	if err := a.SaveIntelligenceCheckpoint(ctx, &IntelligenceCheckpoint{Revision: revision + 1, Complete: true}); !errors.Is(err, ErrIntelligenceLeaseLost) {
		t.Fatalf("unleased checkpoint write bypassed active ownership: %v", err)
	}
	if err := a.ReplaceIntelligenceIOCs(firstCtx, revision, prepared.IOCs); err != nil {
		t.Fatal(err)
	}
	if err := a.TagEvent(firstCtx, event); err != nil {
		t.Fatal(err)
	}
	var classified bool
	if err := a.pool.QueryRow(ctx, `SELECT classified FROM events WHERE id=1`).Scan(&classified); err != nil || !classified {
		t.Fatalf("authorized exact-row acknowledgment failed: %v %v", classified, err)
	}
	if err := a.ReleaseIntelligenceLease(ctx, first); err != nil {
		t.Fatal(err)
	}
	second, err := b.AcquireIntelligenceLease(ctx, "public-second-owner-1", 30*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	secondCtx := WithIntelligenceLease(ctx, second)
	recovered, err := b.LoadIntelligenceCheckpoint(secondCtx)
	if err != nil || recovered == nil || recovered.Revision != revision || len(recovered.IOCs) != 1 || recovered.IOCs[0].Count != 1 {
		t.Fatalf("successor could not recover the acknowledged prepared WAL: %v %v", recovered, err)
	}
	if err := b.ReplaceIntelligenceIOCs(secondCtx, recovered.Revision, recovered.IOCs); err != nil {
		t.Fatal(err)
	}
	if err := b.TagEvent(secondCtx, recovered.Events[0]); err != nil {
		t.Fatal(err)
	}
	if err := a.ReplaceIntelligenceIOCs(firstCtx, revision, prepared.IOCs); !errors.Is(err, ErrIntelligenceLeaseLost) {
		t.Fatalf("old worker projection survived takeover: %v", err)
	}
	if err := a.TagEvent(firstCtx, event); !errors.Is(err, ErrIntelligenceLeaseLost) {
		t.Fatalf("old worker event tag survived takeover: %v", err)
	}
	completion, err := b.ReserveIntelligenceRevision(ctx, second, recovered.Revision)
	if err != nil || completion <= revision {
		t.Fatalf("completion revision was not globally reserved: %d %v", completion, err)
	}
	futureRevision, err := b.ReserveIntelligenceRevision(ctx, second, completion)
	if err != nil {
		t.Fatal(err)
	}
	future := &IntelligenceCheckpoint{Revision: futureRevision}
	futureDigest, err := intelligenceLeaseDigest(future)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.intelligenceLeaseStoreCheckpoint(ctx, future, futureDigest); err != nil {
		t.Fatal(err)
	}
	if err := b.SaveIntelligenceCheckpoint(secondCtx, &IntelligenceCheckpoint{Revision: completion, Complete: true}); err != nil {
		t.Fatal(err)
	}
	var older, preserved int
	table := pgIntelligenceTable(pgIntelligenceCoordinatorSchema, pgIntelligenceRecordsTable)
	if err := b.pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE revision<$1),count(*) FILTER(WHERE revision IN($1,$2)) FROM `+table, int64(completion), int64(futureRevision)).Scan(&older, &preserved); err != nil || older != 0 || preserved != 2 {
		t.Fatalf("checkpoint GC did not preserve current/future records: older=%d preserved=%d error=%v", older, preserved, err)
	}
	var count int64
	if err := b.pool.QueryRow(ctx, `SELECT count FROM iocs WHERE id=$1`, ioc.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("recovery counted the same batch twice: %d %v", count, err)
	}
}

func TestIntelligencePostgresLeaseUnavailableDoesNotMutate(t *testing.T) {
	db := &TimescaleDB{}
	if _, _, err := db.intelligenceLeaseRead(t.Context()); !errors.Is(err, ErrIntelligenceLeaseUnavailable) {
		t.Fatal(err)
	}
	if _, err := db.intelligenceLeaseMutate(t.Context(), intelligenceLeaseOperation{}); !errors.Is(err, ErrIntelligenceLeaseUnavailable) {
		t.Fatal(err)
	}
	if err := db.intelligenceLeaseStoreCheckpoint(t.Context(), nil, ""); !errors.Is(err, ErrIntelligenceLeaseUnavailable) {
		t.Fatal(err)
	}
	if _, err := db.intelligenceLeaseLoadCheckpoint(t.Context(), 1, ""); !errors.Is(err, ErrIntelligenceLeaseUnavailable) {
		t.Fatal(err)
	}
}
