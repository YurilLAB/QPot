// Package database provides schema migration management
package database

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// Migration represents a single database schema migration
type Migration struct {
	Version   int
	Name      string
	Up        func(ctx context.Context, db Database) error
	Down      func(ctx context.Context, db Database) error
	AppliedAt *time.Time
}

// MigrationManager handles database migrations
type MigrationManager struct {
	db         Database
	migrations []*Migration
	tableName  string
}

// NewMigrationManager creates a new migration manager
func NewMigrationManager(db Database) *MigrationManager {
	return &MigrationManager{
		db:         db,
		migrations: make([]*Migration, 0),
		tableName:  "schema_migrations",
	}
}

// Register adds a migration to the manager
func (m *MigrationManager) Register(migration *Migration) {
	m.migrations = append(m.migrations, migration)
}

// Initialize creates the migrations tracking table
func (m *MigrationManager) Initialize(ctx context.Context) error {
	// Create migrations table - this is database-specific
	// Each database implementation should handle this
	return m.db.InitializeSchema(ctx)
}

// GetPendingMigrations returns migrations that haven't been applied
func (m *MigrationManager) GetPendingMigrations(ctx context.Context) ([]*Migration, error) {
	applied, err := m.getAppliedVersions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get applied versions: %w", err)
	}

	appliedMap := make(map[int]bool)
	for _, v := range applied {
		appliedMap[v] = true
	}

	var pending []*Migration
	for _, mig := range m.migrations {
		if !appliedMap[mig.Version] {
			pending = append(pending, mig)
		}
	}

	// Sort by version
	sort.Slice(pending, func(i, j int) bool {
		return pending[i].Version < pending[j].Version
	})

	return pending, nil
}

// Migrate runs all pending migrations
func (m *MigrationManager) Migrate(ctx context.Context) error {
	pending, err := m.GetPendingMigrations(ctx)
	if err != nil {
		return err
	}

	if len(pending) == 0 {
		return nil
	}

	for _, mig := range pending {
		if err := m.runMigration(ctx, mig); err != nil {
			return fmt.Errorf("migration %d (%s) failed: %w", mig.Version, mig.Name, err)
		}
	}

	return nil
}

// MigrateToVersion migrates to a specific version
func (m *MigrationManager) MigrateToVersion(ctx context.Context, targetVersion int) error {
	// Sort migrations
	sort.Slice(m.migrations, func(i, j int) bool {
		return m.migrations[i].Version < m.migrations[j].Version
	})

	applied, err := m.getAppliedVersions(ctx)
	if err != nil {
		return err
	}

	currentVersion := 0
	if len(applied) > 0 {
		currentVersion = applied[len(applied)-1]
	}

	if targetVersion > currentVersion {
		// Migrate up
		for _, mig := range m.migrations {
			if mig.Version > currentVersion && mig.Version <= targetVersion {
				if err := m.runMigration(ctx, mig); err != nil {
					return fmt.Errorf("migration up %d failed: %w", mig.Version, err)
				}
			}
		}
	} else if targetVersion < currentVersion {
		// Migrate down
		for i := len(m.migrations) - 1; i >= 0; i-- {
			mig := m.migrations[i]
			if mig.Version <= currentVersion && mig.Version > targetVersion {
				if err := m.rollbackMigration(ctx, mig); err != nil {
					return fmt.Errorf("migration down %d failed: %w", mig.Version, err)
				}
			}
		}
	}

	return nil
}

// GetCurrentVersion returns the current schema version
func (m *MigrationManager) GetCurrentVersion(ctx context.Context) (int, error) {
	applied, err := m.getAppliedVersions(ctx)
	if err != nil {
		return 0, err
	}

	if len(applied) == 0 {
		return 0, nil
	}

	return applied[len(applied)-1], nil
}

// Status returns detailed migration status
func (m *MigrationManager) Status(ctx context.Context) (*MigrationStatus, error) {
	applied, err := m.getAppliedVersions(ctx)
	if err != nil {
		return nil, err
	}

	appliedMap := make(map[int]time.Time)
	for _, v := range applied {
		// We'd store the actual time in a real implementation
		appliedMap[v] = time.Now()
	}

	var items []MigrationStatusItem
	for _, mig := range m.migrations {
		item := MigrationStatusItem{
			Version: mig.Version,
			Name:    mig.Name,
			Applied: appliedMap[mig.Version] != time.Time{},
		}
		if item.Applied {
			appliedAt := appliedMap[mig.Version]
			item.AppliedAt = &appliedAt
		}
		items = append(items, item)
	}

	currentVersion := 0
	if len(applied) > 0 {
		currentVersion = applied[len(applied)-1]
	}

	return &MigrationStatus{
		CurrentVersion: currentVersion,
		LatestVersion:  m.getLatestVersion(),
		PendingCount:   len(items) - len(applied),
		Migrations:     items,
	}, nil
}

// runMigration executes a single migration
func (m *MigrationManager) runMigration(ctx context.Context, mig *Migration) error {
	if mig.Up == nil {
		return fmt.Errorf("migration %d has no up function", mig.Version)
	}

	if err := mig.Up(ctx, m.db); err != nil {
		return err
	}

	return m.recordMigration(ctx, mig.Version)
}

// rollbackMigration rolls back a single migration
func (m *MigrationManager) rollbackMigration(ctx context.Context, mig *Migration) error {
	if mig.Down == nil {
		return fmt.Errorf("migration %d has no down function", mig.Version)
	}

	if err := mig.Down(ctx, m.db); err != nil {
		return err
	}

	return m.removeMigration(ctx, mig.Version)
}

// getAppliedVersions returns the list of applied migration versions by querying
// the database's current schema version. Versions 1..currentVersion are assumed applied.
func (m *MigrationManager) getAppliedVersions(ctx context.Context) ([]int, error) {
	current, err := m.db.GetSchemaVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get schema version: %w", err)
	}
	if current == 0 {
		return []int{}, nil
	}
	versions := make([]int, current)
	for i := range versions {
		versions[i] = i + 1
	}
	return versions, nil
}

// recordMigration records that a migration was applied by setting the schema version.
func (m *MigrationManager) recordMigration(ctx context.Context, version int) error {
	return m.db.SetSchemaVersion(ctx, version)
}

// removeMigration records a rollback by setting the schema version to version-1.
func (m *MigrationManager) removeMigration(ctx context.Context, version int) error {
	prev := version - 1
	if prev < 0 {
		prev = 0
	}
	return m.db.SetSchemaVersion(ctx, prev)
}

// getLatestVersion returns the highest migration version
func (m *MigrationManager) getLatestVersion() int {
	latest := 0
	for _, mig := range m.migrations {
		if mig.Version > latest {
			latest = mig.Version
		}
	}
	return latest
}

// MigrationStatus represents the status of all migrations
type MigrationStatus struct {
	CurrentVersion int                    `json:"current_version"`
	LatestVersion  int                    `json:"latest_version"`
	PendingCount   int                    `json:"pending_count"`
	Migrations     []MigrationStatusItem  `json:"migrations"`
}

// MigrationStatusItem represents status of a single migration
type MigrationStatusItem struct {
	Version   int        `json:"version"`
	Name      string     `json:"name"`
	Applied   bool       `json:"applied"`
	AppliedAt *time.Time `json:"applied_at,omitempty"`
}

// GetCoreMigrations returns the core QPot migrations
func GetCoreMigrations() []*Migration {
	return []*Migration{
		{
			Version: 1,
			Name:    "create_events_table",
			Up: func(ctx context.Context, db Database) error {
				// Migration handled in InitializeSchema
				return nil
			},
			Down: func(ctx context.Context, db Database) error {
				// Drop events table
				return nil
			},
		},
		{
			Version: 2,
			Name:    "add_cluster_support",
			Up: func(ctx context.Context, db Database) error {
				// Add cluster_nodes table
				return nil
			},
			Down: func(ctx context.Context, db Database) error {
				return nil
			},
		},
		{
			Version: 3,
			Name:    "add_retention_policies",
			Up: func(ctx context.Context, db Database) error {
				// Add retention policy metadata table
				return nil
			},
			Down: func(ctx context.Context, db Database) error {
				return nil
			},
		},
	}
}
