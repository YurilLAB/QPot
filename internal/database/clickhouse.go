// Package database provides ClickHouse implementation
package database

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/qpot/qpot/internal/config"
)

// ClickHouse implements Database interface for ClickHouse
type ClickHouse struct {
	config *config.DatabaseConfig
	conn   driver.Conn
}

// NewClickHouse creates a new ClickHouse database instance
func NewClickHouse(cfg *config.DatabaseConfig) (*ClickHouse, error) {
	return &ClickHouse{
		config: cfg,
	}, nil
}

// Connect establishes connection to ClickHouse
func (ch *ClickHouse) Connect(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", ch.config.Host, ch.config.Port)
	
	options := &clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{
			Database: ch.config.Database,
			Username: ch.config.Username,
			Password: ch.config.Password,
		},
		Settings: clickhouse.Settings{
			"max_execution_time": 60,
		},
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
		DialTimeout:      10 * time.Second,
		MaxOpenConns:     10,
		MaxIdleConns:     5,
		ConnMaxLifetime:  time.Hour,
	}

	conn, err := clickhouse.Open(options)
	if err != nil {
		return fmt.Errorf("failed to open clickhouse connection: %w", err)
	}

	if err := conn.Ping(ctx); err != nil {
		return fmt.Errorf("failed to ping clickhouse: %w", err)
	}

	ch.conn = conn
	return nil
}

// Close closes the database connection
func (ch *ClickHouse) Close() error {
	if ch.conn != nil {
		return ch.conn.Close()
	}
	return nil
}

// Ping checks database connectivity
func (ch *ClickHouse) Ping(ctx context.Context) error {
	if ch.conn == nil {
		return fmt.Errorf("not connected")
	}
	return ch.conn.Ping(ctx)
}

// InitializeSchema creates database tables
func (ch *ClickHouse) InitializeSchema(ctx context.Context) error {
	if ch.conn == nil {
		return fmt.Errorf("not connected")
	}

	// Create events table with MergeTree engine
	eventsTable := `
		CREATE TABLE IF NOT EXISTS events (
			timestamp DateTime64(3),
			honeypot LowCardinality(String),
			source_ip IPv4,
			source_port UInt16,
			dest_port UInt16,
			protocol LowCardinality(String),
			event_type LowCardinality(String),
			username String,
			password String,
			command String,
			payload String,
			metadata Map(String, String),
			country LowCardinality(String),
			city String,
			asn String,
			technique_id String DEFAULT '',
			technique_name String DEFAULT '',
			tactic_id String DEFAULT '',
			tactic_name String DEFAULT '',
			kill_chain_stage String DEFAULT '',
			confidence Float64 DEFAULT 0,
			classified UInt8 DEFAULT 0
		) ENGINE = MergeTree()
		PARTITION BY toYYYYMM(timestamp)
		ORDER BY (timestamp, honeypot, source_ip)
		TTL timestamp + INTERVAL 90 DAY
		SETTINGS index_granularity = 8192
	`

	if err := ch.conn.Exec(ctx, eventsTable); err != nil {
		return fmt.Errorf("failed to create events table: %w", err)
	}

	// Create materialized view for hourly statistics
	hourlyMV := `
		CREATE MATERIALIZED VIEW IF NOT EXISTS events_hourly_mv
		ENGINE = SummingMergeTree()
		PARTITION BY toYYYYMM(hour)
		ORDER BY (hour, honeypot, country)
		AS SELECT
			toStartOfHour(timestamp) as hour,
			honeypot,
			country,
			count() as event_count,
			uniqExact(source_ip) as unique_ips
		FROM events
		GROUP BY hour, honeypot, country
	`

	if err := ch.conn.Exec(ctx, hourlyMV); err != nil {
		return fmt.Errorf("failed to create hourly materialized view: %w", err)
	}

	// Create materialized view for attacker statistics
	attackerMV := `
		CREATE MATERIALIZED VIEW IF NOT EXISTS attackers_mv
		ENGINE = AggregatingMergeTree()
		PARTITION BY toYYYYMM(first_seen)
		ORDER BY source_ip
		AS SELECT
			source_ip,
			country,
			min(timestamp) as first_seen,
			max(timestamp) as last_seen,
			count() as attack_count,
			groupUniqArray(honeypot) as honeypots,
			groupUniqArray(username) as usernames,
			groupUniqArray(password) as passwords
		FROM events
		GROUP BY source_ip, country
	`

	if err := ch.conn.Exec(ctx, attackerMV); err != nil {
		return fmt.Errorf("failed to create attackers materialized view: %w", err)
	}

	// Create IOCs table
	iocsTable := `
		CREATE TABLE IF NOT EXISTS iocs (
			id String,
			type LowCardinality(String),
			value String,
			honeypot LowCardinality(String),
			source_ip String,
			technique_id String,
			first_seen DateTime64(3),
			last_seen DateTime64(3),
			count UInt64,
			metadata Map(String, String)
		) ENGINE = ReplacingMergeTree(last_seen)
		ORDER BY (type, value, honeypot)
	`
	if err := ch.conn.Exec(ctx, iocsTable); err != nil {
		return fmt.Errorf("failed to create iocs table: %w", err)
	}

	// Create TTP sessions table
	ttpTable := `
		CREATE TABLE IF NOT EXISTS ttp_sessions (
			session_id String,
			campaign_fingerprint String,
			source_ips Array(String),
			shared_infrastructure UInt8,
			kill_chain_stages Array(String),
			techniques Array(String),
			ioc_ids Array(String),
			event_count UInt64,
			first_seen DateTime64(3),
			last_seen DateTime64(3),
			confidence Float64
		) ENGINE = ReplacingMergeTree(last_seen)
		ORDER BY session_id
	`
	if err := ch.conn.Exec(ctx, ttpTable); err != nil {
		return fmt.Errorf("failed to create ttp_sessions table: %w", err)
	}

	return nil
}

// InsertEvent inserts a single event
func (ch *ClickHouse) InsertEvent(ctx context.Context, event *Event) error {
	return ch.InsertEvents(ctx, []*Event{event})
}

// InsertEvents inserts multiple events in batch
func (ch *ClickHouse) InsertEvents(ctx context.Context, events []*Event) error {
	if ch.conn == nil {
		return fmt.Errorf("not connected")
	}

	batch, err := ch.conn.PrepareBatch(ctx, "INSERT INTO events")
	if err != nil {
		return fmt.Errorf("failed to prepare batch: %w", err)
	}

	for _, event := range events {
		classified := uint8(0)
		if event.Classified {
			classified = 1
		}
		err := batch.Append(
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
			string(event.Payload),
			event.Metadata,
			event.Country,
			event.City,
			event.ASN,
			event.TechniqueID,
			event.TechniqueName,
			event.TacticID,
			event.TacticName,
			event.KillChainStage,
			event.Confidence,
			classified,
		)
		if err != nil {
			return fmt.Errorf("failed to append event: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		return fmt.Errorf("failed to send batch: %w", err)
	}

	return nil
}

// GetEvents retrieves events based on filter
func (ch *ClickHouse) GetEvents(ctx context.Context, filter EventFilter) ([]*Event, error) {
	if ch.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	query := `SELECT timestamp, honeypot, source_ip, source_port, dest_port,
		protocol, event_type, username, password, command,
		payload, metadata, country, city, asn,
		technique_id, technique_name, tactic_id, tactic_name,
		kill_chain_stage, confidence, classified
	FROM events WHERE 1=1`
	var args []interface{}

	if !filter.StartTime.IsZero() {
		query += " AND timestamp >= ?"
		args = append(args, filter.StartTime)
	}
	if !filter.EndTime.IsZero() {
		query += " AND timestamp <= ?"
		args = append(args, filter.EndTime)
	}
	if len(filter.Honeypots) > 0 {
		query += " AND honeypot IN ?"
		args = append(args, filter.Honeypots)
	}
	if len(filter.SourceIPs) > 0 {
		query += " AND source_ip IN ?"
		args = append(args, filter.SourceIPs)
	}
	if len(filter.Countries) > 0 {
		query += " AND country IN ?"
		args = append(args, filter.Countries)
	}
	if len(filter.EventTypes) > 0 {
		query += " AND event_type IN ?"
		args = append(args, filter.EventTypes)
	}

	query += " ORDER BY timestamp DESC"

	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
		if filter.Offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", filter.Offset)
		}
	}

	rows, err := ch.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		var event Event
		var payloadStr string
		var classified uint8
		err := rows.Scan(
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
			&payloadStr,
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
			&classified,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}
		event.Payload = []byte(payloadStr)
		event.Classified = classified != 0
		events = append(events, &event)
	}

	return events, nil
}

// GetEventByID retrieves a single event by ID (timestamp-based)
func (ch *ClickHouse) GetEventByID(ctx context.Context, id string) (*Event, error) {
	// ClickHouse doesn't have traditional IDs, we use timestamp
	return nil, fmt.Errorf("not implemented for clickhouse")
}

// GetStats retrieves aggregate statistics
func (ch *ClickHouse) GetStats(ctx context.Context, since time.Time) (*Stats, error) {
	if ch.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	stats := &Stats{}

	// Total events
	err := ch.conn.QueryRow(ctx, 
		"SELECT count() FROM events WHERE timestamp >= ?", 
		since).Scan(&stats.TotalEvents)
	if err != nil {
		return nil, fmt.Errorf("failed to get total events: %w", err)
	}

	// Unique IPs
	err = ch.conn.QueryRow(ctx,
		"SELECT uniqExact(source_ip) FROM events WHERE timestamp >= ?",
		since).Scan(&stats.UniqueIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to get unique IPs: %w", err)
	}

	// Top countries
	countryRows, err := ch.conn.Query(ctx,
		"SELECT country, count() as c FROM events WHERE timestamp >= ? AND country != '' GROUP BY country ORDER BY c DESC LIMIT 10",
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

	// Top honeypots
	hpRows, err := ch.conn.Query(ctx,
		"SELECT honeypot, count() as c FROM events WHERE timestamp >= ? GROUP BY honeypot ORDER BY c DESC",
		since)
	if err != nil {
		return nil, fmt.Errorf("failed to get top honeypots: %w", err)
	}
	defer hpRows.Close()

	for hpRows.Next() {
		var hc HoneypotCount
		if err := hpRows.Scan(&hc.Honeypot, &hc.Count); err != nil {
			return nil, err
		}
		stats.TopHoneypots = append(stats.TopHoneypots, hc)
	}

	return stats, nil
}

// GetTopAttackers retrieves top attackers
func (ch *ClickHouse) GetTopAttackers(ctx context.Context, limit int, since time.Time) ([]*AttackerStats, error) {
	if ch.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	query := `
		SELECT 
			source_ip,
			country,
			min(timestamp),
			max(timestamp),
			count(),
			groupUniqArray(honeypot),
			groupUniqArray(username),
			groupUniqArray(password)
		FROM events 
		WHERE timestamp >= ?
		GROUP BY source_ip, country
		ORDER BY count() DESC
		LIMIT ?
	`

	rows, err := ch.conn.Query(ctx, query, since, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query attackers: %w", err)
	}
	defer rows.Close()

	var attackers []*AttackerStats
	for rows.Next() {
		var a AttackerStats
		var honeypots []string
		var usernames []string
		var passwords []string

		err := rows.Scan(
			&a.SourceIP,
			&a.Country,
			&a.FirstSeen,
			&a.LastSeen,
			&a.AttackCount,
			&honeypots,
			&usernames,
			&passwords,
		)
		if err != nil {
			return nil, err
		}

		a.Honeypots = honeypots
		a.Usernames = usernames
		a.Passwords = passwords
		attackers = append(attackers, &a)
	}

	return attackers, nil
}

// GetHoneypotStats retrieves statistics for a specific honeypot
func (ch *ClickHouse) GetHoneypotStats(ctx context.Context, honeypot string, since time.Time) (*HoneypotStats, error) {
	if ch.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	stats := &HoneypotStats{Honeypot: honeypot}

	err := ch.conn.QueryRow(ctx,
		"SELECT count(), uniqExact(source_ip) FROM events WHERE honeypot = ? AND timestamp >= ?",
		honeypot, since).Scan(&stats.TotalEvents, &stats.UniqueIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to get honeypot totals: %w", err)
	}

	usernameRows, err := ch.conn.Query(ctx,
		"SELECT username, count() FROM events WHERE honeypot = ? AND timestamp >= ? AND username != '' GROUP BY username ORDER BY count() DESC LIMIT 20",
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

	passwordRows, err := ch.conn.Query(ctx,
		"SELECT password, count() FROM events WHERE honeypot = ? AND timestamp >= ? AND password != '' GROUP BY password ORDER BY count() DESC LIMIT 20",
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

	commandRows, err := ch.conn.Query(ctx,
		"SELECT command, count() FROM events WHERE honeypot = ? AND timestamp >= ? AND command != '' GROUP BY command ORDER BY count() DESC LIMIT 20",
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

// RetentionCleanup removes data older than olderThan. ClickHouse TTL handles
// automatic expiry at 90 days, but this method allows ad-hoc deletion for
// custom retention windows shorter than the TTL.
func (ch *ClickHouse) RetentionCleanup(ctx context.Context, olderThan time.Time) error {
	if ch.conn == nil {
		return fmt.Errorf("not connected")
	}
	return ch.conn.Exec(ctx,
		"ALTER TABLE events DELETE WHERE timestamp < ?",
		olderThan,
	)
}

// Optimize runs maintenance tasks
func (ch *ClickHouse) Optimize(ctx context.Context) error {
	if ch.conn == nil {
		return fmt.Errorf("not connected")
	}

	return ch.conn.Exec(ctx, "OPTIMIZE TABLE events FINAL")
}


// ExportData exports data to a writer in CSV format
func (ch *ClickHouse) ExportData(ctx context.Context, start, end time.Time, w io.Writer) error {
	if ch.conn == nil {
		return fmt.Errorf("not connected")
	}

	header := "timestamp,honeypot,source_ip,source_port,dest_port,protocol,event_type,username,password,command,country,city,asn,technique_id,technique_name,confidence\n"
	if _, err := w.Write([]byte(header)); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	rows, err := ch.conn.Query(ctx, `
		SELECT timestamp, honeypot, source_ip, source_port, dest_port,
		       protocol, event_type, username, password, command,
		       country, city, asn, technique_id, technique_name, confidence
		FROM events
		WHERE timestamp >= ? AND timestamp <= ?
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
			sourcePort    uint16
			destPort      uint16
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
			chCSVEscape(honeypot), chCSVEscape(sourceIP),
			sourcePort, destPort,
			chCSVEscape(protocol), chCSVEscape(eventType),
			chCSVEscape(username), chCSVEscape(password), chCSVEscape(command),
			chCSVEscape(country), chCSVEscape(city), chCSVEscape(asn),
			chCSVEscape(techniqueID), chCSVEscape(techniqueName),
			confidence,
		)
		if _, err := w.Write([]byte(line)); err != nil {
			return fmt.Errorf("failed to write row: %w", err)
		}
	}

	return nil
}

// chCSVEscape wraps a field in quotes if it contains a comma, quote, or newline.
func chCSVEscape(s string) string {
	if len(s) == 0 {
		return s
	}
	needsQuote := false
	for _, c := range s {
		if c == ',' || c == '"' || c == '\n' || c == '\r' {
			needsQuote = true
			break
		}
	}
	if !needsQuote {
		return s
	}
	// Replace " with ""
	escaped := make([]byte, 0, len(s)+2)
	escaped = append(escaped, '"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			escaped = append(escaped, '"', '"')
		} else {
			escaped = append(escaped, s[i])
		}
	}
	escaped = append(escaped, '"')
	return string(escaped)
}

// ImportData imports CSV data exported by ExportData back into the database.
func (ch *ClickHouse) ImportData(ctx context.Context, r io.Reader) error {
	if ch.conn == nil {
		return fmt.Errorf("not connected")
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read data: %w", err)
	}

	lines := splitLines(string(data))
	if len(lines) < 2 {
		return nil
	}

	batch, err := ch.conn.PrepareBatch(ctx, "INSERT INTO events (timestamp,honeypot,source_ip,source_port,dest_port,protocol,event_type,username,password,command,country,city,asn,technique_id,technique_name,confidence)")
	if err != nil {
		return fmt.Errorf("failed to prepare import batch: %w", err)
	}

	imported := 0
	for _, line := range lines[1:] {
		line = trimString(line)
		if line == "" {
			continue
		}
		fields := splitCSVLine(line)
		if len(fields) < 16 {
			continue
		}

		ts2, err := time.Parse(time.RFC3339, fields[0])
		if err != nil {
			continue
		}
		var sourcePort, destPort uint16
		fmt.Sscanf(fields[3], "%d", &sourcePort)
		fmt.Sscanf(fields[4], "%d", &destPort)
		var confidence float64
		fmt.Sscanf(fields[15], "%f", &confidence)

		if err := batch.Append(
			ts2, fields[1], fields[2], sourcePort, destPort,
			fields[5], fields[6], fields[7], fields[8], fields[9],
			fields[10], fields[11], fields[12], fields[13], fields[14], confidence,
		); err != nil {
			slog.Warn("ImportData: failed to append row", "error", err)
			continue
		}
		imported++
	}

	if imported > 0 {
		if err := batch.Send(); err != nil {
			return fmt.Errorf("failed to send import batch: %w", err)
		}
	}

	slog.Info("ImportData complete", "imported", imported)
	return nil
}

// splitLines splits a string into lines, handling \r\n and \n.
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			end := i
			if end > start && s[end-1] == '\r' {
				end--
			}
			lines = append(lines, s[start:end])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// trimString trims spaces from a string.
func trimString(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// splitCSVLine splits a CSV line respecting double-quoted fields.
func splitCSVLine(line string) []string {
	var fields []string
	var current []byte
	inQuote := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inQuote {
			if c == '"' {
				if i+1 < len(line) && line[i+1] == '"' {
					current = append(current, '"')
					i++
				} else {
					inQuote = false
				}
			} else {
				current = append(current, c)
			}
		} else {
			if c == '"' {
				inQuote = true
			} else if c == ',' {
				fields = append(fields, string(current))
				current = current[:0]
			} else {
				current = append(current, c)
			}
		}
	}
	fields = append(fields, string(current))
	return fields
}

// GetSchemaVersion returns the current schema version
func (ch *ClickHouse) GetSchemaVersion(ctx context.Context) (int, error) {
	if ch.conn == nil {
		return 0, fmt.Errorf("not connected")
	}

	// Check if schema_migrations table exists
	var exists uint64
	err := ch.conn.QueryRow(ctx, `
		SELECT count() 
		FROM system.tables 
		WHERE database = currentDatabase() AND name = 'schema_migrations'
	`).Scan(&exists)
	
	if err != nil || exists == 0 {
		return 0, nil // No migrations table means version 0
	}

	var version int
	err = ch.conn.QueryRow(ctx, `
		SELECT version 
		FROM schema_migrations 
		FINAL
		ORDER BY version DESC
		LIMIT 1
	`).Scan(&version)
	
	if err != nil {
		return 0, nil
	}

	return version, nil
}

// SetSchemaVersion sets the schema version
func (ch *ClickHouse) SetSchemaVersion(ctx context.Context, version int) error {
	if ch.conn == nil {
		return fmt.Errorf("not connected")
	}

	query := `
		INSERT INTO schema_migrations (version, name, applied_at, execution_time_ms)
		VALUES (?, ?, ?, ?)
	`

	return ch.conn.Exec(ctx, query, version, "manual", time.Now(), 0)
}

// WithPool returns a new ClickHouse instance with connection pooling
func (ch *ClickHouse) WithPool(pool *Pool) Database {
	// ClickHouse already has internal connection pooling
	// This is for interface compliance
	return ch
}

// GetPoolStats returns pool statistics
func (ch *ClickHouse) GetPoolStats() PoolStats {
	// ClickHouse-go handles its own pooling
	return PoolStats{
		TotalConnections: 1,
	}
}

// TagEvent updates an event's ATT&CK classification fields in ClickHouse.
func (ch *ClickHouse) TagEvent(ctx context.Context, event *Event) error {
	if ch.conn == nil {
		return fmt.Errorf("not connected")
	}
	query := `
		ALTER TABLE events UPDATE
			technique_id    = ?,
			technique_name  = ?,
			tactic_id       = ?,
			tactic_name     = ?,
			kill_chain_stage = ?,
			confidence      = ?,
			classified      = 1
		WHERE source_ip = ? AND timestamp = ?
	`
	return ch.conn.Exec(ctx, query,
		event.TechniqueID,
		event.TechniqueName,
		event.TacticID,
		event.TacticName,
		event.KillChainStage,
		event.Confidence,
		event.SourceIP,
		event.Timestamp,
	)
}

// InsertIOC inserts or updates an IOC record using ClickHouse REPLACE semantics.
func (ch *ClickHouse) InsertIOC(ctx context.Context, ioc *IOC) error {
	if ch.conn == nil {
		return fmt.Errorf("not connected")
	}
	query := `
		INSERT INTO iocs (id, type, value, honeypot, source_ip, technique_id,
		                  first_seen, last_seen, count, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	return ch.conn.Exec(ctx, query,
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
}

// GetIOCs retrieves IOCs with optional filtering.
func (ch *ClickHouse) GetIOCs(ctx context.Context, filter IOCFilter) ([]*IOC, error) {
	if ch.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	query := "SELECT id, type, value, honeypot, source_ip, technique_id, first_seen, last_seen, count, metadata FROM iocs WHERE 1=1"
	var args []interface{}

	if len(filter.Types) > 0 {
		query += " AND type IN ?"
		args = append(args, filter.Types)
	}
	if len(filter.Honeypots) > 0 {
		query += " AND honeypot IN ?"
		args = append(args, filter.Honeypots)
	}
	if !filter.StartTime.IsZero() {
		query += " AND first_seen >= ?"
		args = append(args, filter.StartTime)
	}
	if !filter.EndTime.IsZero() {
		query += " AND last_seen <= ?"
		args = append(args, filter.EndTime)
	}
	query += " ORDER BY last_seen DESC"
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
		if filter.Offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", filter.Offset)
		}
	}

	rows, err := ch.conn.Query(ctx, query, args...)
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

// UpsertTTPSession inserts or replaces a TTP session record.
func (ch *ClickHouse) UpsertTTPSession(ctx context.Context, session *TTPSession) error {
	if ch.conn == nil {
		return fmt.Errorf("not connected")
	}
	query := `
		INSERT INTO ttp_sessions (
			session_id, campaign_fingerprint, source_ips,
			shared_infrastructure, kill_chain_stages, techniques,
			ioc_ids, event_count, first_seen, last_seen, confidence
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	return ch.conn.Exec(ctx, query,
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
}

// GetTTPSessions retrieves TTP sessions ordered by last_seen descending.
func (ch *ClickHouse) GetTTPSessions(ctx context.Context, limit int) ([]*TTPSession, error) {
	if ch.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	query := `
		SELECT session_id, campaign_fingerprint, source_ips,
		       shared_infrastructure, kill_chain_stages, techniques,
		       ioc_ids, event_count, first_seen, last_seen, confidence
		FROM ttp_sessions FINAL
		ORDER BY last_seen DESC
	`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := ch.conn.Query(ctx, query)
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
func (ch *ClickHouse) GetUnclassifiedEvents(ctx context.Context, limit int) ([]*Event, error) {
	if ch.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	query := `
		SELECT timestamp, honeypot, source_ip, source_port, dest_port,
		       protocol, event_type, username, password, command,
		       payload, metadata, country, city, asn,
		       technique_id, technique_name, tactic_id, tactic_name,
		       kill_chain_stage, confidence, classified
		FROM events
		WHERE classified = 0
		ORDER BY timestamp ASC
	`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := ch.conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query unclassified events: %w", err)
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		var event Event
		var payloadStr string
		if err := rows.Scan(
			&event.Timestamp, &event.Honeypot, &event.SourceIP,
			&event.SourcePort, &event.DestPort, &event.Protocol,
			&event.EventType, &event.Username, &event.Password,
			&event.Command, &payloadStr, &event.Metadata,
			&event.Country, &event.City, &event.ASN,
			&event.TechniqueID, &event.TechniqueName,
			&event.TacticID, &event.TacticName,
			&event.KillChainStage, &event.Confidence, &event.Classified,
		); err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}
		event.Payload = []byte(payloadStr)
		events = append(events, &event)
	}
	return events, nil
}
