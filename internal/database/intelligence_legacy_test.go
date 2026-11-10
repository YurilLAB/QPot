package database

import "context"

// These tests deliberately exercise the immutable replay/storage primitives,
// independently of worker coordination. Native lease tests use the public
// front door and require an issued capability and acknowledged prepared WAL.
type legacyIntelligenceStoreForTest struct{ Database }

func (s legacyIntelligenceStoreForTest) LoadIntelligenceCheckpoint(ctx context.Context) (*IntelligenceCheckpoint, error) {
	switch db := s.Database.(type) {
	case *ClickHouse:
		return db.loadLegacyIntelligenceCheckpoint(ctx)
	case *TimescaleDB:
		return db.loadLegacyIntelligenceCheckpoint(ctx)
	case *Elasticsearch:
		return db.loadLegacyIntelligenceCheckpoint(ctx)
	}
	panic("unexpected primitive fixture backend")
}
func (s legacyIntelligenceStoreForTest) SaveIntelligenceCheckpoint(ctx context.Context, cp *IntelligenceCheckpoint) error {
	switch db := s.Database.(type) {
	case *ClickHouse:
		return db.saveLegacyIntelligenceCheckpoint(ctx, cp)
	case *TimescaleDB:
		return db.saveLegacyIntelligenceCheckpoint(ctx, cp)
	case *Elasticsearch:
		return db.saveLegacyIntelligenceCheckpoint(ctx, cp)
	}
	panic("unexpected primitive fixture backend")
}
func (s legacyIntelligenceStoreForTest) ReplaceIntelligenceIOCs(ctx context.Context, rev uint64, rows []*IOC) error {
	switch db := s.Database.(type) {
	case *ClickHouse:
		return db.replaceLegacyIntelligenceIOCs(ctx, rev, rows)
	case *TimescaleDB:
		return db.replaceLegacyIntelligenceIOCs(ctx, rev, rows)
	case *Elasticsearch:
		return db.replaceLegacyIntelligenceIOCs(ctx, rev, rows)
	}
	panic("unexpected primitive fixture backend")
}
func (s legacyIntelligenceStoreForTest) ReplaceIntelligenceSessions(ctx context.Context, rev uint64, rows []*TTPSession) error {
	switch db := s.Database.(type) {
	case *ClickHouse:
		return db.replaceLegacyIntelligenceSessions(ctx, rev, rows)
	case *TimescaleDB:
		return db.replaceLegacyIntelligenceSessions(ctx, rev, rows)
	case *Elasticsearch:
		return db.replaceLegacyIntelligenceSessions(ctx, rev, rows)
	}
	panic("unexpected primitive fixture backend")
}
func (s legacyIntelligenceStoreForTest) ReadIntelligenceIOCs(ctx context.Context, rows []*IOC) ([]*IOC, error) {
	return s.Database.(IntelligenceStore).ReadIntelligenceIOCs(ctx, rows)
}
