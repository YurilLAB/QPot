// Package database provides database abstraction for QPot
package database

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/qpot/qpot/internal/config"
)

// Event represents a honeypot event
type Event struct {
	Timestamp   time.Time         `json:"timestamp"`
	Honeypot    string            `json:"honeypot"`
	SourceIP    string            `json:"source_ip"`
	SourcePort  int               `json:"source_port"`
	DestPort    int               `json:"dest_port"`
	Protocol    string            `json:"protocol"`
	EventType   string            `json:"event_type"`
	Username    string            `json:"username,omitempty"`
	Password    string            `json:"password,omitempty"`
	Command     string            `json:"command,omitempty"`
	Payload     []byte            `json:"payload,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Country     string            `json:"country,omitempty"`
	City        string            `json:"city,omitempty"`
	ASN         string            `json:"asn,omitempty"`
}

// Stats represents aggregate statistics
type Stats struct {
	TotalEvents    int64            `json:"total_events"`
	UniqueIPs      int64            `json:"unique_ips"`
	TopCountries   []CountryCount   `json:"top_countries"`
	TopHoneypots   []HoneypotCount  `json:"top_honeypots"`
	EventsPerHour  []TimeSeries     `json:"events_per_hour"`
}

// CountryCount represents attack counts by country
type CountryCount struct {
	Country string `json:"country"`
	Count   int64  `json:"count"`
}

// HoneypotCount represents event counts by honeypot
type HoneypotCount struct {
	Honeypot string `json:"honeypot"`
	Count    int64  `json:"count"`
}

// TimeSeries represents time-based data
type TimeSeries struct {
	Timestamp time.Time `json:"timestamp"`
	Count     int64     `json:"count"`
}

// Database is the interface for database operations
type Database interface {
	// Connection
	Connect(ctx context.Context) error
	Close() error
	Ping(ctx context.Context) error

	// Schema
	InitializeSchema(ctx context.Context) error
	GetSchemaVersion(ctx context.Context) (int, error)
	SetSchemaVersion(ctx context.Context, version int) error
	
	// Events
	InsertEvent(ctx context.Context, event *Event) error
	InsertEvents(ctx context.Context, events []*Event) error
	GetEvents(ctx context.Context, filter EventFilter) ([]*Event, error)
	GetEventByID(ctx context.Context, id string) (*Event, error)
	
	// Statistics
	GetStats(ctx context.Context, since time.Time) (*Stats, error)
	GetTopAttackers(ctx context.Context, limit int, since time.Time) ([]*AttackerStats, error)
	GetHoneypotStats(ctx context.Context, honeypot string, since time.Time) (*HoneypotStats, error)
	
	// Maintenance
	RetentionCleanup(ctx context.Context, olderThan time.Time) error
	Optimize(ctx context.Context) error
	
	// Backup/Restore
	ExportData(ctx context.Context, start, end time.Time, w io.Writer) error
	ImportData(ctx context.Context, r io.Reader) error
	
	// Connection
	WithPool(pool *Pool) Database
	GetPoolStats() PoolStats
}

// EventFilter filters for querying events
type EventFilter struct {
	Honeypots   []string  `json:"honeypots,omitempty"`
	SourceIPs   []string  `json:"source_ips,omitempty"`
	Countries   []string  `json:"countries,omitempty"`
	EventTypes  []string  `json:"event_types,omitempty"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	Limit       int       `json:"limit"`
	Offset      int       `json:"offset"`
}

// AttackerStats represents statistics about an attacker
type AttackerStats struct {
	SourceIP      string    `json:"source_ip"`
	Country       string    `json:"country"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	AttackCount   int64     `json:"attack_count"`
	Honeypots     []string  `json:"honeypots"`
	Usernames     []string  `json:"usernames,omitempty"`
	Passwords     []string  `json:"passwords,omitempty"`
}

// HoneypotStats represents statistics for a specific honeypot
type HoneypotStats struct {
	Honeypot      string            `json:"honeypot"`
	TotalEvents   int64             `json:"total_events"`
	UniqueIPs     int64             `json:"unique_ips"`
	TopUsernames  []CredentialCount `json:"top_usernames,omitempty"`
	TopPasswords  []CredentialCount `json:"top_passwords,omitempty"`
	Commands      []CommandCount    `json:"commands,omitempty"`
}

// CredentialCount represents credential usage count
type CredentialCount struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

// CommandCount represents command usage count
type CommandCount struct {
	Command string `json:"command"`
	Count   int64  `json:"count"`
}

// New creates a new database instance based on config
func New(cfg *config.DatabaseConfig) (Database, error) {
	switch cfg.Type {
	case "clickhouse":
		return NewClickHouse(cfg)
	case "timescaledb":
		return NewTimescaleDB(cfg)
	case "elasticsearch":
		return NewElasticsearch(cfg)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", cfg.Type)
	}
}

// ValidateConfig validates database configuration
func ValidateConfig(cfg *config.DatabaseConfig) error {
	if cfg.Type == "" {
		return fmt.Errorf("database type is required")
	}
	
	validTypes := map[string]bool{
		"clickhouse":    true,
		"timescaledb":   true,
		"elasticsearch": true,
	}
	
	if !validTypes[cfg.Type] {
		return fmt.Errorf("invalid database type: %s", cfg.Type)
	}
	
	if cfg.Host == "" {
		return fmt.Errorf("database host is required")
	}
	
	if cfg.Port <= 0 {
		return fmt.Errorf("invalid database port: %d", cfg.Port)
	}
	
	return nil
}
