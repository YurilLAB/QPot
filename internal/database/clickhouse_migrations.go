// Package database provides ClickHouse-specific migration support
package database

import (
	"context"
	"fmt"
	"time"
)

// ClickHouseMigrationManager handles ClickHouse-specific migrations
type ClickHouseMigrationManager struct {
	*MigrationManager
	ch *ClickHouse
}

// NewClickHouseMigrationManager creates a new ClickHouse migration manager
func NewClickHouseMigrationManager(ch *ClickHouse) *ClickHouseMigrationManager {
	base := NewMigrationManager(ch)
	
	// Register core migrations
	for _, m := range GetClickHouseMigrations() {
		base.Register(m)
	}
	
	return &ClickHouseMigrationManager{
		MigrationManager: base,
		ch:               ch,
	}
}

// InitializeMigrationsTable creates the schema migrations table
func (chm *ClickHouseMigrationManager) InitializeMigrationsTable(ctx context.Context) error {
	if chm.ch.conn == nil {
		return fmt.Errorf("not connected")
	}

	query := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version UInt32,
			name String,
			applied_at DateTime64(3),
			execution_time_ms UInt64
		) ENGINE = ReplacingMergeTree(applied_at)
		ORDER BY version
	`

	if err := chm.ch.conn.Exec(ctx, query); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	return nil
}

// getAppliedVersions returns list of applied migration versions for ClickHouse
func (chm *ClickHouseMigrationManager) getAppliedVersions(ctx context.Context) ([]int, error) {
	if chm.ch.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	query := `
		SELECT version 
		FROM schema_migrations 
		FINAL
		ORDER BY version
	`

	rows, err := chm.ch.conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query migrations: %w", err)
	}
	defer rows.Close()

	var versions []int
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		versions = append(versions, version)
	}

	return versions, nil
}

// recordMigration records that a migration was applied
func (chm *ClickHouseMigrationManager) recordMigration(ctx context.Context, version int) error {
	if chm.ch.conn == nil {
		return fmt.Errorf("not connected")
	}

	// Get migration name
	var name string
	for _, m := range chm.migrations {
		if m.Version == version {
			name = m.Name
			break
		}
	}

	query := `
		INSERT INTO schema_migrations (version, name, applied_at, execution_time_ms)
		VALUES (?, ?, ?, ?)
	`

	if err := chm.ch.conn.Exec(ctx, query, version, name, time.Now(), 0); err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	return nil
}

// removeMigration removes a migration record
func (chm *ClickHouseMigrationManager) removeMigration(ctx context.Context, version int) error {
	if chm.ch.conn == nil {
		return fmt.Errorf("not connected")
	}

	query := `ALTER TABLE schema_migrations DELETE WHERE version = ?`

	if err := chm.ch.conn.Exec(ctx, query, version); err != nil {
		return fmt.Errorf("failed to remove migration: %w", err)
	}

	return nil
}

// GetClickHouseMigrations returns ClickHouse-specific migrations
func GetClickHouseMigrations() []*Migration {
	return []*Migration{
		{
			Version: 1,
			Name:    "create_initial_schema",
			Up: func(ctx context.Context, db Database) error {
				// Initial schema is created by InitializeSchema
				return nil
			},
			Down: func(ctx context.Context, db Database) error {
				ch := db.(*ClickHouse)
				if ch.conn == nil {
					return fmt.Errorf("not connected")
				}
				return ch.conn.Exec(ctx, "DROP TABLE IF EXISTS events")
			},
		},
		{
			Version: 2,
			Name:    "add_cluster_nodes_table",
			Up: func(ctx context.Context, db Database) error {
				ch := db.(*ClickHouse)
				if ch.conn == nil {
					return fmt.Errorf("not connected")
				}
				query := `
					CREATE TABLE IF NOT EXISTS cluster_nodes (
						node_id String,
						cluster_id String,
						name String,
						address String,
						port UInt16,
						status LowCardinality(String),
						joined_at DateTime64(3),
						last_seen DateTime64(3),
						total_events UInt64,
						metadata Map(String, String)
					) ENGINE = ReplacingMergeTree(last_seen)
					ORDER BY (cluster_id, node_id)
				`
				return ch.conn.Exec(ctx, query)
			},
			Down: func(ctx context.Context, db Database) error {
				ch := db.(*ClickHouse)
				if ch.conn == nil {
					return fmt.Errorf("not connected")
				}
				return ch.conn.Exec(ctx, "DROP TABLE IF EXISTS cluster_nodes")
			},
		},
		{
			Version: 3,
			Name:    "add_retention_policies_table",
			Up: func(ctx context.Context, db Database) error {
				ch := db.(*ClickHouse)
				if ch.conn == nil {
					return fmt.Errorf("not connected")
				}
				query := `
					CREATE TABLE IF NOT EXISTS retention_policies (
						policy_id String,
						name String,
						enabled UInt8,
						table_name String,
						hot_retention_days UInt32,
						warm_retention_days UInt32,
						cold_retention_days UInt32,
						archive_type LowCardinality(String),
						archive_config String,
						last_run DateTime64(3),
						next_run DateTime64(3),
						total_archived UInt64,
						total_deleted UInt64
					) ENGINE = ReplacingMergeTree(last_run)
					ORDER BY policy_id
				`
				return ch.conn.Exec(ctx, query)
			},
			Down: func(ctx context.Context, db Database) error {
				ch := db.(*ClickHouse)
				if ch.conn == nil {
					return fmt.Errorf("not connected")
				}
				return ch.conn.Exec(ctx, "DROP TABLE IF EXISTS retention_policies")
			},
		},
		{
			Version: 4,
			Name:    "add_threat_intelligence_table",
			Up: func(ctx context.Context, db Database) error {
				ch := db.(*ClickHouse)
				if ch.conn == nil {
					return fmt.Errorf("not connected")
				}
				query := `
					CREATE TABLE IF NOT EXISTS threat_intel (
						ip IPv4,
						first_seen DateTime64(3),
						last_seen DateTime64(3),
						attack_count UInt64,
						honeypots Array(String),
						reputation_score Float32,
						tags Array(String),
						vt_score Float32,
						abuseipdb_score Int32,
						updated_at DateTime64(3)
					) ENGINE = ReplacingMergeTree(updated_at)
					ORDER BY ip
				`
				return ch.conn.Exec(ctx, query)
			},
			Down: func(ctx context.Context, db Database) error {
				ch := db.(*ClickHouse)
				if ch.conn == nil {
					return fmt.Errorf("not connected")
				}
				return ch.conn.Exec(ctx, "DROP TABLE IF EXISTS threat_intel")
			},
		},
	}
}
