package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

const (
	intelligenceLeaseCHControl = "intelligence_worker_control"
	intelligenceLeaseCHRecords = "intelligence_checkpoint_records"
)

func (ch *ClickHouse) intelligenceLeaseRead(ctx context.Context) (*intelligenceLeaseState, time.Time, error) {
	s, _, now, err := ch.intelligenceLeaseReadVersion(ctx)
	return s, now, err
}

func (ch *ClickHouse) intelligenceLeaseReadVersion(ctx context.Context) (*intelligenceLeaseState, int32, time.Time, error) {
	if ch.conn == nil {
		return nil, 0, time.Time{}, ErrIntelligenceLeaseUnavailable
	}
	rows, err := ch.conn.Query(ctx, "SELECT value, _version, toUnixTimestamp64Milli(now64(3)) FROM "+intelligenceLeaseCHControl+" WHERE key = 'worker'")
	if err != nil {
		var exception *clickhouse.Exception
		if errors.As(err, &exception) && exception.Code == 60 {
			return nil, 0, time.Time{}, nil
		}
		return nil, 0, time.Time{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, 0, time.Time{}, rows.Err()
	}
	var raw string
	var version int32
	var millis int64
	if err := rows.Scan(&raw, &version, &millis); err != nil {
		return nil, 0, time.Time{}, err
	}
	if len(raw) > 16<<10 || version < 0 || millis < 0 {
		return nil, 0, time.Time{}, fmt.Errorf("invalid intelligence Keeper control record")
	}
	var s intelligenceLeaseState
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return nil, 0, time.Time{}, err
	}
	if err := validateIntelligenceLeaseState(s); err != nil {
		return nil, 0, time.Time{}, err
	}
	if rows.Next() {
		return nil, 0, time.Time{}, fmt.Errorf("ambiguous intelligence Keeper control record")
	}
	return &s, version, time.UnixMilli(millis).UTC(), rows.Err()
}

func (ch *ClickHouse) intelligenceLeaseEnsure(ctx context.Context) error {
	if ch.conn == nil {
		return ErrIntelligenceLeaseUnavailable
	}
	if err := ch.intelligenceLeaseValidateCatalog(ctx); err != nil {
		return err
	}
	root, err := intelligenceLeaseNonce()
	if err != nil {
		return err
	}
	// CREATE IF NOT EXISTS chooses this path only for the first creation of
	// the actual database table. Later clients/host aliases use its persisted
	// engine metadata, not a namespace computed from their connection address.
	query := "CREATE TABLE IF NOT EXISTS " + intelligenceLeaseCHControl + " (key String, value String) ENGINE = KeeperMap('/qpot/intelligence/" + root + "', 1) PRIMARY KEY key"
	if err := ch.conn.Exec(ctx, query); err != nil {
		return fmt.Errorf("%w: ClickHouse KeeperMap is required: %w", ErrIntelligenceLeaseUnavailable, err)
	}
	var engine, key string
	if err := ch.conn.QueryRow(ctx, "SELECT engine, primary_key FROM system.tables WHERE database = currentDatabase() AND name = ?", intelligenceLeaseCHControl).Scan(&engine, &key); err != nil {
		return err
	}
	if engine != "KeeperMap" || key != "key" {
		return fmt.Errorf("%w: worker control table is not an atomic KeeperMap", ErrIntelligenceLeaseUnavailable)
	}
	return ch.conn.Exec(ctx, "CREATE TABLE IF NOT EXISTS "+intelligenceLeaseCHRecords+" (revision UInt64, digest FixedString(64), payload String) ENGINE = ReplacingMergeTree ORDER BY (revision, digest)")
}

// The managed schema is one local storage catalog. Separate replica-local
// metadata/control tables cannot fence a shared Distributed/Replicated data
// set, so those deployments require a separately designed shared binding.
func (ch *ClickHouse) intelligenceLeaseValidateCatalog(ctx context.Context) error {
	var databaseEngine string
	if err := ch.conn.QueryRow(ctx, "SELECT engine FROM system.databases WHERE name = currentDatabase()").Scan(&databaseEngine); err != nil {
		return err
	}
	if databaseEngine != "Atomic" && databaseEngine != "Ordinary" {
		return fmt.Errorf("%w: distributed ClickHouse database catalogs require shared coordination", ErrIntelligenceLeaseUnavailable)
	}
	wanted := map[string]string{"events": "MergeTree", "iocs": "ReplacingMergeTree", "ttp_sessions": "ReplacingMergeTree", "intelligence_checkpoint": "ReplacingMergeTree", "intelligence_iocs": "ReplacingMergeTree", "intelligence_sessions": "ReplacingMergeTree"}
	names := make([]string, 0, len(wanted))
	for name := range wanted {
		names = append(names, name)
	}
	rows, err := ch.conn.Query(ctx, "SELECT name, engine FROM system.tables WHERE database = currentDatabase() AND name IN ?", names)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name, engine string
		if err := rows.Scan(&name, &engine); err != nil {
			return err
		}
		if wanted[name] != engine {
			return fmt.Errorf("%w: unsupported distributed or substituted intelligence table", ErrIntelligenceLeaseUnavailable)
		}
	}
	return rows.Err()
}

func (ch *ClickHouse) intelligenceLeaseMutate(ctx context.Context, op intelligenceLeaseOperation) (intelligenceLeaseState, error) {
	var empty intelligenceLeaseState
	if ch.conn == nil {
		return empty, ErrIntelligenceLeaseUnavailable
	}
	if op.Kind == "acquire" {
		if err := ch.intelligenceLeaseEnsure(ctx); err != nil {
			return empty, err
		}
	}
	current, version, now, err := ch.intelligenceLeaseReadVersion(ctx)
	if err != nil {
		return empty, err
	}
	if current == nil {
		if op.Kind != "acquire" {
			return empty, ErrIntelligenceLeaseLost
		}
		var millis int64
		if err := ch.conn.QueryRow(ctx, "SELECT toUnixTimestamp64Milli(now64(3))").Scan(&millis); err != nil {
			return empty, err
		}
		now = time.UnixMilli(millis).UTC()
		legacy, err := ch.loadLegacyIntelligenceCheckpoint(ctx)
		if err != nil {
			var exception *clickhouse.Exception
			if !errors.As(err, &exception) || exception.Code != 60 {
				return empty, err
			}
		}
		if legacy != nil {
			op.Minimum = max(op.Minimum, legacy.Revision)
		}
		next, err := applyIntelligenceLeaseOperation(nil, op, now)
		if err != nil {
			return empty, err
		}
		if legacy != nil {
			digest, err := intelligenceLeaseDigest(legacy)
			if err != nil {
				return empty, err
			}
			if err := ch.intelligenceLeaseStoreCheckpoint(ctx, legacy, digest); err != nil {
				return empty, err
			}
			next.CheckpointRevision, next.CheckpointDigest = legacy.Revision, digest
		}
		data, err := json.Marshal(next)
		if err != nil {
			return empty, err
		}
		strict := clickhouse.Context(ctx, clickhouse.WithSettings(clickhouse.Settings{"keeper_map_strict_mode": 1}))
		writeErr := ch.conn.Exec(strict, "INSERT INTO "+intelligenceLeaseCHControl+" (key, value) VALUES ('worker', ?)", string(data))
		return ch.intelligenceLeaseConfirm(ctx, op, writeErr)
	}
	if version >= math.MaxInt32-1 {
		return empty, fmt.Errorf("intelligence Keeper version exhausted")
	}
	next, err := applyIntelligenceLeaseOperation(current, op, now)
	if err != nil {
		return empty, err
	}
	data, err := json.Marshal(next)
	if err != nil {
		return empty, err
	}
	// Both the observed Keeper version AND expiry at the actual server-side
	// mutation are required. A zero-row ALTER is verified by a unique operation
	// nonce below, never mistaken for a successful acquisition/publication.
	where := "key = 'worker' AND _version = ?"
	args := []any{string(data), version}
	if op.Kind == "acquire" {
		where += " AND (JSONExtractString(value, 'owner') = '' OR JSONExtractInt(value, 'expires_ms') <= toUnixTimestamp64Milli(now64(3)))"
	} else {
		where += " AND JSONExtractString(value, 'owner') = ? AND JSONExtractUInt(value, 'fence') = ? AND JSONExtractString(value, 'namespace') = ? AND JSONExtractInt(value, 'expires_ms') > toUnixTimestamp64Milli(now64(3))"
		args = append(args, op.Owner, op.Fence, op.Namespace)
	}
	strict := clickhouse.Context(ctx, clickhouse.WithSettings(clickhouse.Settings{"keeper_map_strict_mode": 1}))
	writeErr := ch.conn.Exec(strict, "ALTER TABLE "+intelligenceLeaseCHControl+" UPDATE value = ? WHERE "+where, args...)
	return ch.intelligenceLeaseConfirm(ctx, op, writeErr)
}

func (ch *ClickHouse) intelligenceLeaseConfirm(ctx context.Context, op intelligenceLeaseOperation, writeErr error) (intelligenceLeaseState, error) {
	s, _, now, err := ch.intelligenceLeaseReadVersion(ctx)
	if err != nil {
		if writeErr != nil {
			return intelligenceLeaseState{}, writeErr
		}
		return intelligenceLeaseState{}, err
	}
	if s != nil && s.Operation == op.Nonce && (op.Kind == "release" && s.Owner == "" || op.Kind != "release" && s.Owner == op.Owner && s.ExpiresMS > now.UnixMilli()) {
		return *s, nil
	}
	if op.Kind == "acquire" && s != nil && s.Owner != "" && s.ExpiresMS > now.UnixMilli() {
		return intelligenceLeaseState{}, ErrIntelligenceLeaseBusy
	}
	if writeErr != nil {
		return intelligenceLeaseState{}, fmt.Errorf("%w: Keeper compare-and-swap was not acknowledged: %w", ErrIntelligenceLeaseLost, writeErr)
	}
	return intelligenceLeaseState{}, ErrIntelligenceLeaseLost
}

func (ch *ClickHouse) intelligenceLeaseStoreCheckpoint(ctx context.Context, cp *IntelligenceCheckpoint, digest string) error {
	if ch.conn == nil {
		return ErrIntelligenceLeaseUnavailable
	}
	data, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if cp == nil || cp.Revision == 0 || hex.EncodeToString(sum[:]) != digest {
		return fmt.Errorf("invalid immutable intelligence checkpoint")
	}
	batch, err := ch.conn.PrepareBatch(ctx, "INSERT INTO "+intelligenceLeaseCHRecords+" (revision, digest, payload)")
	if err != nil {
		return err
	}
	defer batch.Abort()
	if err := batch.Append(cp.Revision, digest, string(data)); err != nil {
		return err
	}
	return batch.Send()
}

func (ch *ClickHouse) intelligenceLeaseLoadCheckpoint(ctx context.Context, revision uint64, digest string) (*IntelligenceCheckpoint, error) {
	if ch.conn == nil {
		return nil, ErrIntelligenceLeaseUnavailable
	}
	rows, err := ch.conn.Query(ctx, "SELECT payload FROM "+intelligenceLeaseCHRecords+" FINAL WHERE revision = ? AND digest = ?", revision, digest)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("missing immutable intelligence checkpoint")
	}
	var data string
	if err := rows.Scan(&data); err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(data))
	if hex.EncodeToString(sum[:]) != digest {
		return nil, fmt.Errorf("immutable intelligence checkpoint hash mismatch")
	}
	var cp IntelligenceCheckpoint
	if err := json.Unmarshal([]byte(data), &cp); err != nil {
		return nil, err
	}
	if cp.Revision != revision || rows.Next() {
		return nil, fmt.Errorf("ambiguous immutable intelligence checkpoint")
	}
	return &cp, rows.Err()
}

func (ch *ClickHouse) intelligenceLeaseGCCheckpoints(ctx context.Context, revision uint64) error {
	if ch.conn == nil {
		return ErrIntelligenceLeaseUnavailable
	}
	bounded := clickhouse.Context(ctx, clickhouse.WithSettings(clickhouse.Settings{"mutations_sync": 1}))
	return ch.conn.Exec(bounded, "ALTER TABLE "+intelligenceLeaseCHRecords+" DELETE WHERE revision < ?", revision)
}
