package database

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	pgIntelligenceCoordinatorSchema = "qpot_intelligence"
	pgIntelligenceControlTable      = "intelligence_worker_control"
	pgIntelligenceRecordsTable      = "intelligence_checkpoint_records"
	// This transaction-scoped lock serializes first-time DDL only. Actual worker
	// ownership is the durable control row and its fenced, expiring state.
	pgIntelligenceSchemaLock int64 = 0x51504f54494e544c
)

type pgLeaseQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func pgLegacyIntelligenceNamespace(ctx context.Context, q pgLeaseQuerier) (string, error) {
	var namespace string
	// Resolve the actual shared storage object rather than the account's first
	// search_path entry; otherwise two accounts could elect separate owners.
	err := q.QueryRow(ctx, `SELECT COALESCE(
		(SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=to_regclass('intelligence_checkpoint')),
		(SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=to_regclass('events')),
		current_schema())`).Scan(&namespace)
	if err != nil || namespace == "" {
		return "", fmt.Errorf("resolve intelligence storage namespace: %w", errors.Join(ErrIntelligenceLeaseUnavailable, err))
	}
	return namespace, nil
}

func pgIntelligenceStorageScope(ctx context.Context, q pgLeaseQuerier) (string, error) {
	var scope string
	err := q.QueryRow(ctx, `SELECT json_build_array(
		(SELECT json_build_array(n.nspname,c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=to_regclass('events')),
		(SELECT json_build_array(n.nspname,c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=to_regclass('iocs')),
		(SELECT json_build_array(n.nspname,c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=to_regclass('ttp_sessions')))::text`).Scan(&scope)
	return scope, err
}

func pgIntelligenceScopeMismatch() error {
	return fmt.Errorf("intelligence database resolves a different projection namespace: %w", ErrIntelligenceLeaseUnavailable)
}

func pgIntelligenceTable(namespace, name string) string {
	return pgx.Identifier{namespace, name}.Sanitize()
}

func pgIntelligenceTableExists(ctx context.Context, q pgLeaseQuerier, namespace, name string) (bool, error) {
	var exists bool
	err := q.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, pgIntelligenceTable(namespace, name)).Scan(&exists)
	return exists, err
}

func decodePGIntelligenceControl(data []byte) (intelligenceLeaseState, error) {
	var state intelligenceLeaseState
	if err := json.Unmarshal(data, &state); err != nil {
		return state, fmt.Errorf("decode intelligence ownership record: %w", err)
	}
	if err := validateIntelligenceLeaseState(state); err != nil {
		return state, err
	}
	return state, nil
}

func (ts *TimescaleDB) intelligenceLeaseRead(ctx context.Context) (*intelligenceLeaseState, time.Time, error) {
	if ts.pool == nil {
		return nil, time.Time{}, ErrIntelligenceLeaseUnavailable
	}
	namespace := pgIntelligenceCoordinatorSchema
	exists, err := pgIntelligenceTableExists(ctx, ts.pool, namespace, pgIntelligenceControlTable)
	if err != nil {
		return nil, time.Time{}, err
	}
	var now time.Time
	if !exists {
		err = ts.pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now)
		return nil, now, err
	}
	var data []byte
	var storedScope string
	err = ts.pool.QueryRow(ctx, `SELECT state,storage_scope,clock_timestamp() FROM `+pgIntelligenceTable(namespace, pgIntelligenceControlTable)+` WHERE id=1`).Scan(&data, &storedScope, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, now, nil
	}
	if err != nil {
		return nil, now, err
	}
	scope, err := pgIntelligenceStorageScope(ctx, ts.pool)
	if err != nil {
		return nil, now, err
	}
	if scope != storedScope {
		return nil, now, pgIntelligenceScopeMismatch()
	}
	state, err := decodePGIntelligenceControl(data)
	return &state, now, err
}

func initializePGIntelligenceLease(ctx context.Context, tx pgx.Tx, namespace string) error {
	ready := func() (bool, error) {
		var exists bool
		err := tx.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL AND to_regclass($2) IS NOT NULL`, pgIntelligenceTable(namespace, pgIntelligenceControlTable), pgIntelligenceTable(namespace, pgIntelligenceRecordsTable)).Scan(&exists)
		return exists, err
	}
	// A role granted access to an existing coordinator need not retain
	// database/schema CREATE privileges merely to acquire its next lease.
	if initialized, err := ready(); err != nil || initialized {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, pgIntelligenceSchemaLock); err != nil {
		return err
	}
	if initialized, err := ready(); err != nil || initialized {
		return err
	}
	var schemaExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1)`, namespace).Scan(&schemaExists); err != nil {
		return err
	}
	if !schemaExists {
		if _, err := tx.Exec(ctx, `CREATE SCHEMA `+pgx.Identifier{namespace}.Sanitize()); err != nil {
			return err
		}
	}
	for _, query := range []string{
		`CREATE TABLE IF NOT EXISTS ` + pgIntelligenceTable(namespace, pgIntelligenceControlTable) + ` (id integer PRIMARY KEY CHECK(id=1),storage_scope text NOT NULL,state jsonb NOT NULL CHECK(jsonb_typeof(state)='object'))`,
		`CREATE TABLE IF NOT EXISTS ` + pgIntelligenceTable(namespace, pgIntelligenceRecordsTable) + ` (revision bigint PRIMARY KEY CHECK(revision>0),digest text NOT NULL CHECK(length(digest)=64),payload bytea NOT NULL)`,
	} {
		if _, err := tx.Exec(ctx, query); err != nil {
			return err
		}
	}
	return nil
}

func pgLegacyIntelligenceCheckpoint(ctx context.Context, tx pgx.Tx, namespace string) (*IntelligenceCheckpoint, error) {
	exists, err := pgIntelligenceTableExists(ctx, tx, namespace, "intelligence_checkpoint")
	if err != nil || !exists {
		return nil, err
	}
	var payload []byte
	var revision int64
	err = tx.QueryRow(ctx, `SELECT revision,payload FROM `+pgIntelligenceTable(namespace, "intelligence_checkpoint")+` WHERE id=1 FOR SHARE`).Scan(&revision, &payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var cp IntelligenceCheckpoint
	if err = json.Unmarshal(payload, &cp); err != nil {
		return nil, err
	}
	if revision <= 0 || revision >= math.MaxInt64-1 || cp.Revision != uint64(revision) {
		return nil, fmt.Errorf("invalid legacy intelligence checkpoint revision")
	}
	return &cp, nil
}

func pgStoreIntelligenceCheckpoint(ctx context.Context, q pgLeaseQuerier, namespace string, cp *IntelligenceCheckpoint, digest string) error {
	if cp == nil || cp.Revision == 0 || cp.Revision >= math.MaxInt64 {
		return fmt.Errorf("invalid immutable intelligence checkpoint revision")
	}
	actual, err := intelligenceLeaseDigest(cp)
	if err != nil {
		return err
	}
	if digest != actual {
		return fmt.Errorf("immutable intelligence checkpoint digest mismatch")
	}
	payload, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	table := pgIntelligenceTable(namespace, pgIntelligenceRecordsTable)
	var written int64
	err = q.QueryRow(ctx, `INSERT INTO `+table+` AS stored (revision,digest,payload) VALUES ($1,$2,$3)
		ON CONFLICT(revision) DO UPDATE SET payload=stored.payload
		WHERE stored.digest=EXCLUDED.digest AND stored.payload=EXCLUDED.payload
		RETURNING revision`, int64(cp.Revision), digest, payload).Scan(&written)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("conflicting immutable intelligence checkpoint")
	}
	if err != nil {
		return err
	}
	if written != int64(cp.Revision) {
		return fmt.Errorf("immutable intelligence checkpoint acknowledgment mismatch")
	}
	return nil
}

func (ts *TimescaleDB) intelligenceLeaseMutate(ctx context.Context, op intelligenceLeaseOperation) (intelligenceLeaseState, error) {
	var empty intelligenceLeaseState
	if ts.pool == nil {
		return empty, ErrIntelligenceLeaseUnavailable
	}
	tx, err := ts.pool.Begin(ctx)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback(ctx)
	namespace := pgIntelligenceCoordinatorSchema
	if op.Kind == "acquire" {
		if err := initializePGIntelligenceLease(ctx, tx, namespace); err != nil {
			return empty, err
		}
	} else {
		exists, err := pgIntelligenceTableExists(ctx, tx, namespace, pgIntelligenceControlTable)
		if err != nil {
			return empty, err
		}
		if !exists {
			return empty, ErrIntelligenceLeaseLost
		}
	}
	table := pgIntelligenceTable(namespace, pgIntelligenceControlTable)
	var data []byte
	var storedScope string
	err = tx.QueryRow(ctx, `SELECT state,storage_scope FROM `+table+` WHERE id=1 FOR UPDATE`).Scan(&data, &storedScope)
	missing := errors.Is(err, pgx.ErrNoRows)
	if err != nil && !missing {
		return empty, err
	}
	var current *intelligenceLeaseState
	if !missing {
		state, err := decodePGIntelligenceControl(data)
		if err != nil {
			return empty, err
		}
		current = &state
	} else if op.Kind != "acquire" {
		return empty, ErrIntelligenceLeaseLost
	}
	scope, err := pgIntelligenceStorageScope(ctx, tx)
	if err != nil {
		return empty, err
	}
	if !missing && scope != storedScope {
		return empty, pgIntelligenceScopeMismatch()
	}
	var legacy *IntelligenceCheckpoint
	if missing {
		legacyNamespace, err := pgLegacyIntelligenceNamespace(ctx, tx)
		if err != nil {
			return empty, err
		}
		legacy, err = pgLegacyIntelligenceCheckpoint(ctx, tx, legacyNamespace)
		if err != nil {
			return empty, err
		}
		if legacy != nil {
			op.Minimum = max(op.Minimum, legacy.Revision)
		}
	}
	if op.Kind == "publish" {
		if op.Revision == 0 || op.Revision >= math.MaxInt64 {
			return empty, fmt.Errorf("invalid immutable intelligence checkpoint reference")
		}
		var revision int64
		if err := tx.QueryRow(ctx, `SELECT revision FROM `+pgIntelligenceTable(namespace, pgIntelligenceRecordsTable)+` WHERE revision=$1 AND digest=$2 FOR SHARE`, int64(op.Revision), op.Digest).Scan(&revision); err != nil {
			return empty, fmt.Errorf("intelligence checkpoint is not durably stored: %w", err)
		}
	}
	var now time.Time
	// Sampling after every row lock prevents lock-wait time from extending an
	// expired lease using an earlier statement/client timestamp.
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return empty, err
	}
	next, err := applyIntelligenceLeaseOperation(current, op, now)
	if err != nil {
		return empty, err
	}
	if legacy != nil {
		digest, err := intelligenceLeaseDigest(legacy)
		if err != nil {
			return empty, err
		}
		if err := pgStoreIntelligenceCheckpoint(ctx, tx, namespace, legacy, digest); err != nil {
			return empty, err
		}
		next.CheckpointRevision, next.CheckpointDigest = legacy.Revision, digest
	}
	data, err = json.Marshal(next)
	if err != nil {
		return empty, err
	}
	if missing {
		result, err := tx.Exec(ctx, `INSERT INTO `+table+` (id,storage_scope,state) VALUES (1,$1,$2) ON CONFLICT(id) DO NOTHING`, scope, data)
		if err != nil {
			return empty, err
		}
		if result.RowsAffected() != 1 {
			return empty, fmt.Errorf("intelligence ownership initialization conflicted")
		}
	} else {
		result, err := tx.Exec(ctx, `UPDATE `+table+` SET state=$1 WHERE id=1`, data)
		if err != nil {
			return empty, err
		}
		if result.RowsAffected() != 1 {
			return empty, ErrIntelligenceLeaseLost
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, err
	}
	return next, nil
}

func (ts *TimescaleDB) intelligenceLeaseStoreCheckpoint(ctx context.Context, cp *IntelligenceCheckpoint, digest string) error {
	if ts.pool == nil {
		return ErrIntelligenceLeaseUnavailable
	}
	return pgStoreIntelligenceCheckpoint(ctx, ts.pool, pgIntelligenceCoordinatorSchema, cp, digest)
}

func (ts *TimescaleDB) intelligenceLeaseLoadCheckpoint(ctx context.Context, revision uint64, digest string) (*IntelligenceCheckpoint, error) {
	if ts.pool == nil {
		return nil, ErrIntelligenceLeaseUnavailable
	}
	if revision == 0 || revision >= math.MaxInt64 {
		return nil, fmt.Errorf("invalid immutable intelligence checkpoint reference")
	}
	var payload []byte
	err := ts.pool.QueryRow(ctx, `SELECT payload FROM `+pgIntelligenceTable(pgIntelligenceCoordinatorSchema, pgIntelligenceRecordsTable)+` WHERE revision=$1 AND digest=$2`, int64(revision), digest).Scan(&payload)
	if err != nil {
		return nil, err
	}
	var cp IntelligenceCheckpoint
	if err := json.Unmarshal(payload, &cp); err != nil {
		return nil, err
	}
	actual, err := intelligenceLeaseDigest(&cp)
	if err != nil || actual != digest || cp.Revision != revision {
		return nil, fmt.Errorf("immutable intelligence checkpoint content mismatch")
	}
	canonical, err := json.Marshal(&cp)
	if err != nil || !bytes.Equal(canonical, payload) {
		return nil, fmt.Errorf("noncanonical immutable intelligence checkpoint payload")
	}
	return &cp, nil
}

// Completion has already been acknowledged before this best-effort cleanup.
// The strict published-revision cutoff cannot remove the current checkpoint or
// a future prepared record, even when an older cleanup request arrives late.
func (ts *TimescaleDB) intelligenceLeaseGCCheckpoints(ctx context.Context, revision uint64) error {
	if ts.pool == nil {
		return ErrIntelligenceLeaseUnavailable
	}
	if revision == 0 || revision >= math.MaxInt64 {
		return fmt.Errorf("invalid intelligence checkpoint cleanup revision")
	}
	_, err := ts.pool.Exec(ctx, `DELETE FROM `+pgIntelligenceTable(pgIntelligenceCoordinatorSchema, pgIntelligenceRecordsTable)+` WHERE revision<$1`, int64(revision))
	return err
}
