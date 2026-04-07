// Package database provides ClickHouse implementation
package database

import (
	"context"
	"fmt"
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
			asn String
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

	query := "SELECT * FROM events WHERE 1=1"
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
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}
		event.Payload = []byte(payloadStr)
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
	return nil, fmt.Errorf("not implemented")
}

// RetentionCleanup removes old data
func (ch *ClickHouse) RetentionCleanup(ctx context.Context, olderThan time.Time) error {
	// ClickHouse handles this via TTL
	return nil
}

// Optimize runs maintenance tasks
func (ch *ClickHouse) Optimize(ctx context.Context) error {
	if ch.conn == nil {
		return fmt.Errorf("not connected")
	}

	return ch.conn.Exec(ctx, "OPTIMIZE TABLE events FINAL")
}
