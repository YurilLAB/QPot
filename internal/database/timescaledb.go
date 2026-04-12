// Package database provides TimescaleDB implementation
package database

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/qpot/qpot/internal/config"
)

// TimescaleDB implements Database interface for TimescaleDB
type TimescaleDB struct {
	config *config.DatabaseConfig
	pool   *pgxpool.Pool
}

// NewTimescaleDB creates a new TimescaleDB database instance
func NewTimescaleDB(cfg *config.DatabaseConfig) (*TimescaleDB, error) {
	return &TimescaleDB{
		config: cfg,
	}, nil
}

// Connect establishes connection to TimescaleDB
func (ts *TimescaleDB) Connect(ctx context.Context) error {
	connString := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s&pool_max_conns=10&pool_max_conn_lifetime=1h",
		ts.config.Username,
		ts.config.Password,
		ts.config.Host,
		ts.config.Port,
		ts.config.Database,
		ts.config.SSLMode,
	)

	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return fmt.Errorf("failed to parse connection string: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	ts.pool = pool
	return nil
}

// Close closes the database connection
func (ts *TimescaleDB) Close() error {
	if ts.pool != nil {
		ts.pool.Close()
	}
	return nil
}

// Ping checks database connectivity
func (ts *TimescaleDB) Ping(ctx context.Context) error {
	if ts.pool == nil {
		return fmt.Errorf("not connected")
	}
	return ts.pool.Ping(ctx)
}

// InitializeSchema creates database tables and hypertables
func (ts *TimescaleDB) InitializeSchema(ctx context.Context) error {
	if ts.pool == nil {
		return fmt.Errorf("not connected")
	}

	// Create events table
	eventsTable := `
		CREATE TABLE IF NOT EXISTS events (
			id BIGSERIAL,
			timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			honeypot TEXT NOT NULL,
			source_ip INET,
			source_port INTEGER,
			dest_port INTEGER,
			protocol TEXT,
			event_type TEXT,
			username TEXT,
			password TEXT,
			command TEXT,
			payload BYTEA,
			metadata JSONB,
			country TEXT,
			city TEXT,
			asn TEXT,
			technique_id TEXT DEFAULT '',
			technique_name TEXT DEFAULT '',
			tactic_id TEXT DEFAULT '',
			tactic_name TEXT DEFAULT '',
			kill_chain_stage TEXT DEFAULT '',
			confidence DOUBLE PRECISION DEFAULT 0,
			classified BOOLEAN DEFAULT FALSE
		)
	`
	if _, err := ts.pool.Exec(ctx, eventsTable); err != nil {
		return fmt.Errorf("failed to create events table: %w", err)
	}

	// Convert to hypertable
	hypertableSQL := `
		SELECT create_hypertable('events', 'timestamp', 
			chunk_time_interval => INTERVAL '1 day',
			if_not_exists => TRUE
		)
	`
	if _, err := ts.pool.Exec(ctx, hypertableSQL); err != nil {
		return fmt.Errorf("failed to create hypertable: %w", err)
	}

	// Create indexes
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_events_honeypot ON events (honeypot, timestamp DESC)",
		"CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events (source_ip, timestamp DESC)",
		"CREATE INDEX IF NOT EXISTS idx_events_country ON events (country, timestamp DESC)",
		"CREATE INDEX IF NOT EXISTS idx_events_event_type ON events (event_type, timestamp DESC)",
	}

	for _, idx := range indexes {
		if _, err := ts.pool.Exec(ctx, idx); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	// Create continuous aggregate for hourly stats
	hourlyAgg := `
		CREATE MATERIALIZED VIEW IF NOT EXISTS events_hourly
		WITH (timescaledb.continuous) AS
		SELECT
			time_bucket('1 hour', timestamp) AS bucket,
			honeypot,
			country,
			count(*) as event_count,
			count(DISTINCT source_ip) as unique_ips
		FROM events
		GROUP BY bucket, honeypot, country
	`
	if _, err := ts.pool.Exec(ctx, hourlyAgg); err != nil {
		return fmt.Errorf("failed to create hourly aggregate: %w", err)
	}

	// Create retention policy
	retentionPolicy := `
		SELECT add_retention_policy('events', INTERVAL '90 days', if_not_exists => TRUE)
	`
	if _, err := ts.pool.Exec(ctx, retentionPolicy); err != nil {
		return fmt.Errorf("failed to create retention policy: %w", err)
	}

	// Create IOCs table
	iocsTable := `
		CREATE TABLE IF NOT EXISTS iocs (
			id TEXT NOT NULL,
			type TEXT NOT NULL,
			value TEXT NOT NULL,
			honeypot TEXT NOT NULL,
			source_ip TEXT,
			technique_id TEXT DEFAULT '',
			first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			count BIGINT DEFAULT 1,
			metadata JSONB,
			UNIQUE (type, value, honeypot)
		)
	`
	if _, err := ts.pool.Exec(ctx, iocsTable); err != nil {
		return fmt.Errorf("failed to create iocs table: %w", err)
	}

	// Create TTP sessions table
	ttpTable := `
		CREATE TABLE IF NOT EXISTS ttp_sessions (
			session_id TEXT PRIMARY KEY,
			campaign_fingerprint TEXT NOT NULL,
			source_ips TEXT[],
			shared_infrastructure BOOLEAN DEFAULT FALSE,
			kill_chain_stages TEXT[],
			techniques TEXT[],
			ioc_ids TEXT[],
			event_count BIGINT DEFAULT 0,
			first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			confidence DOUBLE PRECISION DEFAULT 0
		)
	`
	if _, err := ts.pool.Exec(ctx, ttpTable); err != nil {
		return fmt.Errorf("failed to create ttp_sessions table: %w", err)
	}

	return nil
}

// InsertEvent inserts a single event
func (ts *TimescaleDB) InsertEvent(ctx context.Context, event *Event) error {
	return ts.InsertEvents(ctx, []*Event{event})
}

// InsertEvents inserts multiple events in batch
func (ts *TimescaleDB) InsertEvents(ctx context.Context, events []*Event) error {
	if ts.pool == nil {
		return fmt.Errorf("not connected")
	}

	// Fall back to batch insert
	return ts.insertBatchFallback(ctx, events)
}

// insertBatchFallback falls back to regular INSERT for batch
func (ts *TimescaleDB) insertBatchFallback(ctx context.Context, events []*Event) error {
	batch := &pgx.Batch{}

	for _, event := range events {
		batch.Queue(`
			INSERT INTO events (
				timestamp, honeypot, source_ip, source_port, dest_port,
				protocol, event_type, username, password, command,
				payload, metadata, country, city, asn
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		`,
			event.Timestamp,
			event.Honeypot,
			event.SourceIP,
			event.SourcePort,
			event.DestPort,
			event.Protocol,
			event.EventType,
			event.Username,
			event.Password,
			event.Command,
			event.Payload,
			event.Metadata,
			event.Country,
			event.City,
			event.ASN,
		)
	}

	br := ts.pool.SendBatch(ctx, batch)
	defer br.Close()

	if _, err := br.Exec(); err != nil {
		return fmt.Errorf("failed to execute batch: %w", err)
	}

	return nil
}

// GetEvents retrieves events based on filter
func (ts *TimescaleDB) GetEvents(ctx context.Context, filter EventFilter) ([]*Event, error) {
	if ts.pool == nil {
		return nil, fmt.Errorf("not connected")
	}

	query := `
		SELECT
			id, timestamp, honeypot, source_ip::text, source_port, dest_port,
			protocol, event_type, username, password, command,
			payload, metadata, country, city, asn,
			technique_id, technique_name, tactic_id, tactic_name,
			kill_chain_stage, confidence, classified
		FROM events
		WHERE 1=1`

	var args []interface{}
	argIdx := 1

	if !filter.StartTime.IsZero() {
		query += fmt.Sprintf(" AND timestamp >= $%d", argIdx)
		args = append(args, filter.StartTime)
		argIdx++
	}
	if !filter.EndTime.IsZero() {
		query += fmt.Sprintf(" AND timestamp <= $%d", argIdx)
		args = append(args, filter.EndTime)
		argIdx++
	}
	if len(filter.Honeypots) > 0 {
		query += fmt.Sprintf(" AND honeypot = ANY($%d)", argIdx)
		args = append(args, filter.Honeypots)
		argIdx++
	}
	if len(filter.SourceIPs) > 0 {
		query += fmt.Sprintf(" AND source_ip::text = ANY($%d)", argIdx)
		args = append(args, filter.SourceIPs)
		argIdx++
	}
	if len(filter.Countries) > 0 {
		query += fmt.Sprintf(" AND country = ANY($%d)", argIdx)
		args = append(args, filter.Countries)
		argIdx++
	}

	query += " ORDER BY timestamp DESC"

	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, filter.Limit)
		argIdx++
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, filter.Offset)
	}

	rows, err := ts.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		var event Event
		var id int64
		err := rows.Scan(
			&id,
			&event.Timestamp,
			&event.Honeypot,
			&event.SourceIP,
			&event.SourcePort,
			&event.DestPort,
			&event.Protocol,
			&event.EventType,
			&event.Username,
			&event.Password,
			&event.Command,
			&event.Payload,
			&event.Metadata,
			&event.Country,
			&event.City,
			&event.ASN,
			&event.TechniqueID,
			&event.TechniqueName,
			&event.TacticID,
			&event.TacticName,
			&event.KillChainStage,
			&event.Confidence,
			&event.Classified,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}
		events = append(events, &event)
	}
	return events, nil
}

// GetEventByID retrieves a single event by ID
func (ts *TimescaleDB) GetEventByID(ctx context.Context, id string) (*Event, error) {
	if ts.pool == nil {
		return nil, fmt.Errorf("not connected")
	}

	var event Event
	var dbID int64
	err := ts.pool.QueryRow(ctx, `
		SELECT
			id, timestamp, honeypot, source_ip::text, source_port, dest_port,
			protocol, event_type, username, password, command,
			payload, metadata, country, city, asn
		FROM events
		WHERE id = $1
	`, id).Scan(
		&dbID,
		&event.Timestamp,
		&event.Honeypot,
		&event.SourceIP,
		&event.SourcePort,
		&event.DestPort,
		&event.Protocol,
		&event.EventType,
		&event.Username,
		&event.Password,
		&event.Command,
		&event.Payload,
		&event.Metadata,
		&event.Country,
		&event.City,
		&event.ASN,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get event: %w", err)
	}

	return &event, nil
}

// GetStats retrieves aggregate statistics
func (ts *TimescaleDB) GetStats(ctx context.Context, since time.Time) (*Stats, error) {
	if ts.pool == nil {
		return nil, fmt.Errorf("not connected")
	}

	stats := &Stats{}

	// Total events
	err := ts.pool.QueryRow(ctx, 
		"SELECT COUNT(*) FROM events WHERE timestamp >= $1", 
		since).Scan(&stats.TotalEvents)
	if err != nil {
		return nil, fmt.Errorf("failed to get total events: %w", err)
	}

	// Unique IPs
	err = ts.pool.QueryRow(ctx,
		"SELECT COUNT(DISTINCT source_ip) FROM events WHERE timestamp >= $1",
		since).Scan(&stats.UniqueIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to get unique IPs: %w", err)
	}

	// Top countries
	countryRows, err := ts.pool.Query(ctx,
		"SELECT country, COUNT(*) FROM events WHERE timestamp >= $1 AND country != '' GROUP BY country ORDER BY COUNT(*) DESC LIMIT 10",
		since)
	if err != nil {
		return nil, fmt.Errorf("failed to get top countries: %w", err)
	}
	defer countryRows.Close()

	for countryRows.Next() {
		var cc CountryCount
		if err := countryRows.Scan(&cc.Country, &cc.Count); err != nil {
			return nil, err
		}
		stats.TopCountries = append(stats.TopCountries, cc)
	}

	return stats, nil
}

// GetTopAttackers retrieves top attackers
func (ts *TimescaleDB) GetTopAttackers(ctx context.Context, limit int, since time.Time) ([]*AttackerStats, error) {
	if ts.pool == nil {
		return nil, fmt.Errorf("not connected")
	}

	query := `
		SELECT 
			source_ip::text,
			country,
			MIN(timestamp) as first_seen,
			MAX(timestamp) as last_seen,
			COUNT(*) as attack_count,
			ARRAY_AGG(DISTINCT honeypot) as honeypots
		FROM events 
		WHERE timestamp >= $1
		GROUP BY source_ip, country
		ORDER BY attack_count DESC
		LIMIT $2
	`

	rows, err := ts.pool.Query(ctx, query, since, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query attackers: %w", err)
	}
	defer rows.Close()

	var attackers []*AttackerStats
	for rows.Next() {
		var a AttackerStats
		err := rows.Scan(
			&a.SourceIP,
			&a.Country,
			&a.FirstSeen,
			&a.LastSeen,
			&a.AttackCount,
			&a.Honeypots,
		)
		if err != nil {
			return nil, err
		}
		attackers = append(attackers, &a)
	}

	return attackers, nil
}

// GetHoneypotStats retrieves statistics for a specific honeypot
func (ts *TimescaleDB) GetHoneypotStats(ctx context.Context, honeypot string, since time.Time) (*HoneypotStats, error) {
	if ts.pool == nil {
		return nil, fmt.Errorf("not connected")
	}

	stats := &HoneypotStats{Honeypot: honeypot}

	err := ts.pool.QueryRow(ctx,
		"SELECT COUNT(*), COUNT(DISTINCT source_ip) FROM events WHERE honeypot = $1 AND timestamp >= $2",
		honeypot, since).Scan(&stats.TotalEvents, &stats.UniqueIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to get honeypot totals: %w", err)
	}

	usernameRows, err := ts.pool.Query(ctx,
		"SELECT username, COUNT(*) FROM events WHERE honeypot = $1 AND timestamp >= $2 AND username != '' GROUP BY username ORDER BY COUNT(*) DESC LIMIT 20",
		honeypot, since)
	if err != nil {
		return nil, fmt.Errorf("failed to get top usernames: %w", err)
	}
	defer usernameRows.Close()
	for usernameRows.Next() {
		var cc CredentialCount
		if err := usernameRows.Scan(&cc.Value, &cc.Count); err != nil {
			return nil, err
		}
		stats.TopUsernames = append(stats.TopUsernames, cc)
	}

	passwordRows, err := ts.pool.Query(ctx,
		"SELECT password, COUNT(*) FROM events WHERE honeypot = $1 AND timestamp >= $2 AND password != '' GROUP BY password ORDER BY COUNT(*) DESC LIMIT 20",
		honeypot, since)
	if err != nil {
		return nil, fmt.Errorf("failed to get top passwords: %w", err)
	}
	defer passwordRows.Close()
	for passwordRows.Next() {
		var cc CredentialCount
		if err := passwordRows.Scan(&cc.Value, &cc.Count); err != nil {
			return nil, err
		}
		stats.TopPasswords = append(stats.TopPasswords, cc)
	}

	commandRows, err := ts.pool.Query(ctx,
		"SELECT command, COUNT(*) FROM events WHERE honeypot = $1 AND timestamp >= $2 AND command != '' GROUP BY command ORDER BY COUNT(*) DESC LIMIT 20",
		honeypot, since)
	if err != nil {
		return nil, fmt.Errorf("failed to get top commands: %w", err)
	}
	defer commandRows.Close()
	for commandRows.Next() {
		var cc CommandCount
		if err := commandRows.Scan(&cc.Command, &cc.Count); err != nil {
			return nil, err
		}
		stats.Commands = append(stats.Commands, cc)
	}

	return stats, nil
}

// RetentionCleanup removes data older than olderThan. The TimescaleDB retention
// policy handles automatic expiry at the configured interval, but this method
// supports ad-hoc deletion for custom retention windows.
func (ts *TimescaleDB) RetentionCleanup(ctx context.Context, olderThan time.Time) error {
	if ts.pool == nil {
		return fmt.Errorf("not connected")
	}
	_, err := ts.pool.Exec(ctx, "DELETE FROM events WHERE timestamp < $1", olderThan)
	return err
}

// Optimize runs maintenance tasks
func (ts *TimescaleDB) Optimize(ctx context.Context) error {
	// Materialized views are automatically maintained
	return nil
}


// ExportData exports data to a writer in CSV format
func (ts *TimescaleDB) ExportData(ctx context.Context, start, end time.Time, w io.Writer) error {
	if ts.pool == nil {
		return fmt.Errorf("not connected")
	}

	header := "timestamp,honeypot,source_ip,source_port,dest_port,protocol,event_type,username,password,command,country,city,asn,technique_id,technique_name,confidence\n"
	if _, err := w.Write([]byte(header)); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	rows, err := ts.pool.Query(ctx, `
		SELECT timestamp, honeypot, source_ip::text, source_port, dest_port,
		       protocol, event_type, username, password, command, country, city, asn,
		       technique_id, technique_name, confidence
		FROM events
		WHERE timestamp >= $1 AND timestamp <= $2
		ORDER BY timestamp ASC
	`, start, end)
	if err != nil {
		return fmt.Errorf("failed to query data: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			ts2           time.Time
			honeypot      string
			sourceIP      string
			sourcePort    int
			destPort      int
			protocol      string
			eventType     string
			username      string
			password      string
			command       string
			country       string
			city          string
			asn           string
			techniqueID   string
			techniqueName string
			confidence    float64
		)
		if err := rows.Scan(
			&ts2, &honeypot, &sourceIP, &sourcePort, &destPort,
			&protocol, &eventType, &username, &password, &command,
			&country, &city, &asn, &techniqueID, &techniqueName, &confidence,
		); err != nil {
			return fmt.Errorf("failed to scan row: %w", err)
		}
		line := fmt.Sprintf("%s,%s,%s,%d,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%.4f\n",
			ts2.UTC().Format(time.RFC3339),
			csvEscape(honeypot), csvEscape(sourceIP),
			sourcePort, destPort,
			csvEscape(protocol), csvEscape(eventType),
			csvEscape(username), csvEscape(password), csvEscape(command),
			csvEscape(country), csvEscape(city), csvEscape(asn),
			csvEscape(techniqueID), csvEscape(techniqueName),
			confidence,
		)
		if _, err := w.Write([]byte(line)); err != nil {
			return fmt.Errorf("failed to write row: %w", err)
		}
	}

	return rows.Err()
}

// csvEscape wraps a field in quotes if it contains a comma, quote, or newline.
func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// ImportData imports CSV data exported by ExportData back into the database.
func (ts *TimescaleDB) ImportData(ctx context.Context, r io.Reader) error {
	if ts.pool == nil {
		return fmt.Errorf("not connected")
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read data: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		return nil // empty or header-only
	}

	// Skip header line
	imported := 0
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 16 {
			continue
		}

		ts2, err := time.Parse(time.RFC3339, fields[0])
		if err != nil {
			continue
		}

		_, err = ts.pool.Exec(ctx, `
			INSERT INTO events (
				timestamp, honeypot, source_ip, source_port, dest_port,
				protocol, event_type, username, password, command,
				country, city, asn, technique_id, technique_name
			) VALUES ($1,$2,$3::inet,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
			ON CONFLICT DO NOTHING
		`,
			ts2, fields[1], fields[2], fields[3], fields[4],
			fields[5], fields[6], fields[7], fields[8], fields[9],
			fields[10], fields[11], fields[12], fields[13], fields[14],
		)
		if err != nil {
			slog.Warn("ImportData: failed to insert row", "error", err)
			continue
		}
		imported++
	}

	slog.Info("ImportData complete", "imported", imported)
	return nil
}

// GetSchemaVersion returns the current schema version
func (ts *TimescaleDB) GetSchemaVersion(ctx context.Context) (int, error) {
	if ts.pool == nil {
		return 0, fmt.Errorf("not connected")
	}

	var exists bool
	err := ts.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT FROM information_schema.tables
			WHERE table_name = 'schema_migrations'
		)
	`).Scan(&exists)
	
	if err != nil || !exists {
		return 0, nil
	}

	var version int
	err = ts.pool.QueryRow(ctx, `
		SELECT COALESCE(MAX(version), 0) FROM schema_migrations
	`).Scan(&version)
	
	if err != nil {
		return 0, nil
	}

	return version, nil
}

// SetSchemaVersion sets the schema version
func (ts *TimescaleDB) SetSchemaVersion(ctx context.Context, version int) error {
	if ts.pool == nil {
		return fmt.Errorf("not connected")
	}

	_, err := ts.pool.Exec(ctx, `
		INSERT INTO schema_migrations (version, applied_at)
		VALUES ($1, NOW())
		ON CONFLICT (version) DO UPDATE SET applied_at = NOW()
	`, version)

	return err
}

// WithPool returns a new TimescaleDB instance with connection pooling
func (ts *TimescaleDB) WithPool(pool *Pool) Database {
	// TimescaleDB already uses pgxpool internally
	return ts
}

// GetPoolStats returns pool statistics
func (ts *TimescaleDB) GetPoolStats() PoolStats {
	if ts.pool == nil {
		return PoolStats{}
	}

	stat := ts.pool.Stat()
	return PoolStats{
		TotalConnections:     int(stat.TotalConns()),
		AvailableConnections: int(stat.IdleConns()),
		InUseConnections:     int(stat.AcquiredConns()),
	}
}

// TagEvent updates the ATT&CK classification fields on an existing event row.
func (ts *TimescaleDB) TagEvent(ctx context.Context, event *Event) error {
	if ts.pool == nil {
		return fmt.Errorf("not connected")
	}
	_, err := ts.pool.Exec(ctx, `
		UPDATE events SET
			technique_id     = $1,
			technique_name   = $2,
			tactic_id        = $3,
			tactic_name      = $4,
			kill_chain_stage = $5,
			confidence       = $6,
			classified       = TRUE
		WHERE source_ip = $7 AND timestamp = $8
	`,
		event.TechniqueID,
		event.TechniqueName,
		event.TacticID,
		event.TacticName,
		event.KillChainStage,
		event.Confidence,
		event.SourceIP,
		event.Timestamp,
	)
	return err
}

// InsertIOC upserts an IOC, incrementing count and updating last_seen on conflict.
func (ts *TimescaleDB) InsertIOC(ctx context.Context, ioc *IOC) error {
	if ts.pool == nil {
		return fmt.Errorf("not connected")
	}
	_, err := ts.pool.Exec(ctx, `
		INSERT INTO iocs (id, type, value, honeypot, source_ip, technique_id,
		                  first_seen, last_seen, count, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (type, value, honeypot) DO UPDATE SET
			last_seen    = EXCLUDED.last_seen,
			count        = iocs.count + 1,
			technique_id = COALESCE(EXCLUDED.technique_id, iocs.technique_id)
	`,
		ioc.ID,
		ioc.Type,
		ioc.Value,
		ioc.Honeypot,
		ioc.SourceIP,
		ioc.TechniqueID,
		ioc.FirstSeen,
		ioc.LastSeen,
		ioc.Count,
		ioc.Metadata,
	)
	return err
}

// GetIOCs retrieves IOCs with optional filtering.
func (ts *TimescaleDB) GetIOCs(ctx context.Context, filter IOCFilter) ([]*IOC, error) {
	if ts.pool == nil {
		return nil, fmt.Errorf("not connected")
	}

	query := `SELECT id, type, value, honeypot, source_ip, technique_id,
	                 first_seen, last_seen, count, metadata
	          FROM iocs WHERE 1=1`
	var args []interface{}
	argIdx := 1

	if len(filter.Types) > 0 {
		query += fmt.Sprintf(" AND type = ANY($%d)", argIdx)
		args = append(args, filter.Types)
		argIdx++
	}
	if len(filter.Honeypots) > 0 {
		query += fmt.Sprintf(" AND honeypot = ANY($%d)", argIdx)
		args = append(args, filter.Honeypots)
		argIdx++
	}
	if !filter.StartTime.IsZero() {
		query += fmt.Sprintf(" AND first_seen >= $%d", argIdx)
		args = append(args, filter.StartTime)
		argIdx++
	}
	if !filter.EndTime.IsZero() {
		query += fmt.Sprintf(" AND last_seen <= $%d", argIdx)
		args = append(args, filter.EndTime)
		argIdx++
	}
	query += " ORDER BY last_seen DESC"
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, filter.Limit)
		argIdx++
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, filter.Offset)
	}

	rows, err := ts.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query iocs: %w", err)
	}
	defer rows.Close()

	var iocs []*IOC
	for rows.Next() {
		var ioc IOC
		if err := rows.Scan(
			&ioc.ID, &ioc.Type, &ioc.Value, &ioc.Honeypot,
			&ioc.SourceIP, &ioc.TechniqueID, &ioc.FirstSeen,
			&ioc.LastSeen, &ioc.Count, &ioc.Metadata,
		); err != nil {
			return nil, fmt.Errorf("failed to scan ioc: %w", err)
		}
		iocs = append(iocs, &ioc)
	}
	return iocs, nil
}

// UpsertTTPSession inserts or updates a TTP session record.
func (ts *TimescaleDB) UpsertTTPSession(ctx context.Context, session *TTPSession) error {
	if ts.pool == nil {
		return fmt.Errorf("not connected")
	}
	_, err := ts.pool.Exec(ctx, `
		INSERT INTO ttp_sessions (
			session_id, campaign_fingerprint, source_ips,
			shared_infrastructure, kill_chain_stages, techniques,
			ioc_ids, event_count, first_seen, last_seen, confidence
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (session_id) DO UPDATE SET
			source_ips            = EXCLUDED.source_ips,
			shared_infrastructure = EXCLUDED.shared_infrastructure,
			kill_chain_stages     = EXCLUDED.kill_chain_stages,
			techniques            = EXCLUDED.techniques,
			ioc_ids               = EXCLUDED.ioc_ids,
			event_count           = EXCLUDED.event_count,
			last_seen             = EXCLUDED.last_seen,
			confidence            = EXCLUDED.confidence
	`,
		session.SessionID,
		session.CampaignFingerprint,
		session.SourceIPs,
		session.SharedInfrastructure,
		session.KillChainStages,
		session.Techniques,
		session.IOCIDs,
		session.EventCount,
		session.FirstSeen,
		session.LastSeen,
		session.Confidence,
	)
	return err
}

// GetTTPSessions retrieves TTP sessions ordered by last_seen descending.
func (ts *TimescaleDB) GetTTPSessions(ctx context.Context, limit int) ([]*TTPSession, error) {
	if ts.pool == nil {
		return nil, fmt.Errorf("not connected")
	}

	query := `
		SELECT session_id, campaign_fingerprint, source_ips,
		       shared_infrastructure, kill_chain_stages, techniques,
		       ioc_ids, event_count, first_seen, last_seen, confidence
		FROM ttp_sessions
		ORDER BY last_seen DESC
	`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := ts.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query ttp_sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*TTPSession
	for rows.Next() {
		var s TTPSession
		if err := rows.Scan(
			&s.SessionID, &s.CampaignFingerprint, &s.SourceIPs,
			&s.SharedInfrastructure, &s.KillChainStages, &s.Techniques,
			&s.IOCIDs, &s.EventCount, &s.FirstSeen, &s.LastSeen, &s.Confidence,
		); err != nil {
			return nil, fmt.Errorf("failed to scan ttp_session: %w", err)
		}
		sessions = append(sessions, &s)
	}
	return sessions, nil
}

// GetUnclassifiedEvents returns events that have not yet been classified.
func (ts *TimescaleDB) GetUnclassifiedEvents(ctx context.Context, limit int) ([]*Event, error) {
	if ts.pool == nil {
		return nil, fmt.Errorf("not connected")
	}

	query := `
		SELECT timestamp, honeypot, source_ip::text, source_port, dest_port,
		       protocol, event_type, username, password, command,
		       payload, metadata, country, city, asn,
		       technique_id, technique_name, tactic_id, tactic_name,
		       kill_chain_stage, confidence, classified
		FROM events
		WHERE classified = FALSE
		ORDER BY timestamp ASC
	`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := ts.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query unclassified events: %w", err)
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		var event Event
		if err := rows.Scan(
			&event.Timestamp, &event.Honeypot, &event.SourceIP,
			&event.SourcePort, &event.DestPort, &event.Protocol,
			&event.EventType, &event.Username, &event.Password,
			&event.Command, &event.Payload, &event.Metadata,
			&event.Country, &event.City, &event.ASN,
			&event.TechniqueID, &event.TechniqueName,
			&event.TacticID, &event.TacticName,
			&event.KillChainStage, &event.Confidence, &event.Classified,
		); err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}
		events = append(events, &event)
	}
	return events, nil
}
