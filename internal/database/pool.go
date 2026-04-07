// Package database provides connection pooling for databases
package database

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// PoolConfig defines connection pool settings
type PoolConfig struct {
	MaxOpenConns    int           `yaml:"max_open_conns" json:"max_open_conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns" json:"max_idle_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime" json:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `yaml:"conn_max_idle_time" json:"conn_max_idle_time"`
	HealthCheckInterval time.Duration `yaml:"health_check_interval" json:"health_check_interval"`
	AcquireTimeout  time.Duration `yaml:"acquire_timeout" json:"acquire_timeout"`
}

// DefaultPoolConfig returns default pool configuration
func DefaultPoolConfig() *PoolConfig {
	return &PoolConfig{
		MaxOpenConns:        25,
		MaxIdleConns:        10,
		ConnMaxLifetime:     time.Hour,
		ConnMaxIdleTime:     30 * time.Minute,
		HealthCheckInterval: 5 * time.Minute,
		AcquireTimeout:      30 * time.Second,
	}
}

// PooledConnection wraps a database connection with pool metadata
type PooledConnection struct {
	Database
	id          string
	pool        *Pool
	createdAt   time.Time
	lastUsedAt  time.Time
	inUse       atomic.Bool
	useCount    atomic.Int64
}

// newPooledConnection creates a new pooled connection wrapper
func newPooledConnection(id string, db Database, pool *Pool) *PooledConnection {
	now := time.Now()
	return &PooledConnection{
		Database:   db,
		id:         id,
		pool:       pool,
		createdAt:  now,
		lastUsedAt: now,
	}
}

// Release returns the connection to the pool
func (pc *PooledConnection) Release() {
	if pc.inUse.CompareAndSwap(true, false) {
		pc.lastUsedAt = time.Now()
		pc.useCount.Add(1)
		pc.pool.release(pc)
	}
}

// IsHealthy checks if the connection is still valid
func (pc *PooledConnection) IsHealthy(ctx context.Context) bool {
	return pc.Ping(ctx) == nil
}

// Stats returns connection statistics
func (pc *PooledConnection) Stats() ConnectionStats {
	return ConnectionStats{
		ID:         pc.id,
		CreatedAt:  pc.createdAt,
		LastUsedAt: pc.lastUsedAt,
		InUse:      pc.inUse.Load(),
		UseCount:   pc.useCount.Load(),
		Age:        time.Since(pc.createdAt),
		IdleTime:   time.Since(pc.lastUsedAt),
	}
}

// Pool manages a pool of database connections
type Pool struct {
	config      *PoolConfig
	factory     ConnectionFactory
	
	// Connection management
	mu          sync.RWMutex
	connections []*PooledConnection
	available   chan *PooledConnection
	
	// Statistics
	stats       PoolStats
	
	// Lifecycle
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// ConnectionFactory creates new database connections
type ConnectionFactory func() (Database, error)

// NewPool creates a new connection pool
func NewPool(config *PoolConfig, factory ConnectionFactory) (*Pool, error) {
	if config == nil {
		config = DefaultPoolConfig()
	}

	if config.MaxOpenConns <= 0 {
		config.MaxOpenConns = 25
	}
	if config.MaxIdleConns <= 0 {
		config.MaxIdleConns = 10
	}
	if config.MaxIdleConns > config.MaxOpenConns {
		config.MaxIdleConns = config.MaxOpenConns
	}

	ctx, cancel := context.WithCancel(context.Background())

	pool := &Pool{
		config:      config,
		factory:     factory,
		connections: make([]*PooledConnection, 0, config.MaxOpenConns),
		available:   make(chan *PooledConnection, config.MaxOpenConns),
		ctx:         ctx,
		cancel:      cancel,
	}

	// Initialize minimum connections
	for i := 0; i < config.MaxIdleConns; i++ {
		if err := pool.createConnection(); err != nil {
			pool.Close()
			return nil, fmt.Errorf("failed to create initial connection: %w", err)
		}
	}

	// Start background maintenance
	pool.wg.Add(1)
	go pool.maintenance()

	slog.Info("Connection pool initialized", 
		"max_open", config.MaxOpenConns,
		"max_idle", config.MaxIdleConns)

	return pool, nil
}

// Acquire gets a connection from the pool
func (p *Pool) Acquire(ctx context.Context) (*PooledConnection, error) {
	// Try to get from available channel first
	select {
	case conn := <-p.available:
		if conn.inUse.CompareAndSwap(false, true) {
			conn.lastUsedAt = time.Now()
			return conn, nil
		}
		// Connection was marked in use, try again
		return p.Acquire(ctx)
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// No available connections
	}

	// Try to create a new connection if under limit
	p.mu.Lock()
	if len(p.connections) < p.config.MaxOpenConns {
		p.mu.Unlock()
		if err := p.createConnection(); err != nil {
			return nil, fmt.Errorf("failed to create connection: %w", err)
		}
		// New connection is added to available, try again
		return p.Acquire(ctx)
	}
	p.mu.Unlock()

	// Wait for a connection to become available
	acquireCtx, cancel := context.WithTimeout(ctx, p.config.AcquireTimeout)
	defer cancel()

	select {
	case conn := <-p.available:
		if conn.inUse.CompareAndSwap(false, true) {
			conn.lastUsedAt = time.Now()
			return conn, nil
		}
		return p.Acquire(ctx)
	case <-acquireCtx.Done():
		return nil, fmt.Errorf("timeout acquiring connection: %w", acquireCtx.Err())
	}
}

// AcquireWithRetry attempts to acquire a connection with retries
func (p *Pool) AcquireWithRetry(ctx context.Context, maxRetries int) (*PooledConnection, error) {
	var lastErr error
	for i := 0; i <= maxRetries; i++ {
		conn, err := p.Acquire(ctx)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		
		if i < maxRetries {
			backoff := time.Duration(i+1) * 100 * time.Millisecond
			time.Sleep(backoff)
		}
	}
	return nil, fmt.Errorf("failed to acquire connection after %d retries: %w", maxRetries, lastErr)
}

// release returns a connection to the pool
func (p *Pool) release(conn *PooledConnection) {
	// Check if connection is still healthy
	if !conn.IsHealthy(p.ctx) {
		p.removeConnection(conn)
		return
	}

	// Return to available pool
	select {
	case p.available <- conn:
		// Successfully returned
	default:
		// Pool is full, close this connection
		p.removeConnection(conn)
	}
}

// createConnection creates a new pooled connection
func (p *Pool) createConnection() error {
	db, err := p.factory()
	if err != nil {
		return err
	}

	if err := db.Connect(p.ctx); err != nil {
		db.Close()
		return err
	}

	conn := newPooledConnection(
		fmt.Sprintf("conn_%d", time.Now().UnixNano()),
		db,
		p,
	)

	p.mu.Lock()
	p.connections = append(p.connections, conn)
	p.stats.TotalCreated++
	p.mu.Unlock()

	// Add to available pool
	select {
	case p.available <- conn:
	default:
	}

	return nil
}

// removeConnection removes and closes a connection
func (p *Pool) removeConnection(conn *PooledConnection) {
	p.mu.Lock()
	for i, c := range p.connections {
		if c == conn {
			p.connections = append(p.connections[:i], p.connections[i+1:]...)
			break
		}
	}
	p.stats.TotalClosed++
	p.mu.Unlock()

	conn.Close()
}

// maintenance runs background maintenance tasks
func (p *Pool) maintenance() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.cleanup()
		}
	}
}

// cleanup removes stale connections
func (p *Pool) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	var toRemove []*PooledConnection

	for _, conn := range p.connections {
		// Skip connections in use
		if conn.inUse.Load() {
			continue
		}

		// Check max lifetime
		if p.config.ConnMaxLifetime > 0 && now.Sub(conn.createdAt) > p.config.ConnMaxLifetime {
			toRemove = append(toRemove, conn)
			continue
		}

		// Check max idle time
		if p.config.ConnMaxIdleTime > 0 && now.Sub(conn.lastUsedAt) > p.config.ConnMaxIdleTime {
			toRemove = append(toRemove, conn)
			continue
		}
	}

	// Remove expired connections
	for _, conn := range toRemove {
		for i, c := range p.connections {
			if c == conn {
				p.connections = append(p.connections[:i], p.connections[i+1:]...)
				break
			}
		}
		p.stats.TotalClosed++
		go conn.Close()
	}

	// Ensure minimum idle connections
	needed := p.config.MaxIdleConns - len(p.connections)
	for i := 0; i < needed && len(p.connections) < p.config.MaxOpenConns; i++ {
		go func() {
			if err := p.createConnection(); err != nil {
				slog.Error("Failed to create connection in cleanup", "error", err)
			}
		}()
	}

	if len(toRemove) > 0 {
		slog.Debug("Pool cleanup complete", "removed", len(toRemove), "remaining", len(p.connections))
	}
}

// Stats returns pool statistics
func (p *Pool) Stats() PoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := p.stats
	stats.TotalConnections = len(p.connections)
	stats.AvailableConnections = len(p.available)

	var inUse int
	for _, conn := range p.connections {
		if conn.inUse.Load() {
			inUse++
		}
	}
	stats.InUseConnections = inUse

	return stats
}

// ConnectionStats represents statistics for a single connection
type ConnectionStats struct {
	ID         string        `json:"id"`
	CreatedAt  time.Time     `json:"created_at"`
	LastUsedAt time.Time     `json:"last_used_at"`
	InUse      bool          `json:"in_use"`
	UseCount   int64         `json:"use_count"`
	Age        time.Duration `json:"age"`
	IdleTime   time.Duration `json:"idle_time"`
}

// PoolStats represents pool statistics
type PoolStats struct {
	TotalConnections     int           `json:"total_connections"`
	AvailableConnections int           `json:"available_connections"`
	InUseConnections     int           `json:"in_use_connections"`
	TotalCreated         int64         `json:"total_created"`
	TotalClosed          int64         `json:"total_closed"`
}

// Close closes the pool and all connections
func (p *Pool) Close() error {
	p.cancel()
	p.wg.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Close all connections
	for _, conn := range p.connections {
		conn.Close()
	}
	p.connections = p.connections[:0]
	close(p.available)

	slog.Info("Connection pool closed")
	return nil
}

// ReadReplicaConfig defines a read replica configuration
type ReadReplicaConfig struct {
	Name     string            `yaml:"name" json:"name"`
	Host     string            `yaml:"host" json:"host"`
	Port     int               `yaml:"port" json:"port"`
	Priority int               `yaml:"priority" json:"priority"`
	Weight   int               `yaml:"weight" json:"weight"`
	Region   string            `yaml:"region,omitempty" json:"region,omitempty"`
	Tags     map[string]string `yaml:"tags,omitempty" json:"tags,omitempty"`
}

// ReadReplicaPool manages a pool of read replicas
type ReadReplicaPool struct {
	replicas []*Replica
	strategy ReplicaSelectionStrategy
}

// Replica represents a read replica
type Replica struct {
	Config    *ReadReplicaConfig
	Pool      *Pool
	Healthy   atomic.Bool
	LastCheck time.Time
}

// ReplicaSelectionStrategy defines how to select a replica
type ReplicaSelectionStrategy int

const (
	// RoundRobin cycles through replicas
	RoundRobin ReplicaSelectionStrategy = iota
	// Random selects a random replica
	Random
	// Weighted selects based on weight
	Weighted
	// Priority selects highest priority first
	Priority
	// Nearest selects based on latency/region
	Nearest
)

// NewReadReplicaPool creates a new read replica pool
func NewReadReplicaPool(replicas []*ReadReplicaConfig, factory func(cfg *ReadReplicaConfig) (Database, error)) (*ReadReplicaPool, error) {
	pool := &ReadReplicaPool{
		replicas: make([]*Replica, 0, len(replicas)),
		strategy: RoundRobin,
	}

	for _, cfg := range replicas {
		replicaFactory := func() (Database, error) {
			return factory(cfg)
		}

		replicaPool, err := NewPool(DefaultPoolConfig(), replicaFactory)
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("failed to create pool for replica %s: %w", cfg.Name, err)
		}

		replica := &Replica{
			Config:    cfg,
			Pool:      replicaPool,
			Healthy:   atomic.Bool{},
			LastCheck: time.Now(),
		}
		replica.Healthy.Store(true)

		pool.replicas = append(pool.replicas, replica)
	}

	return pool, nil
}

// Acquire gets a connection from a read replica
func (rrp *ReadReplicaPool) Acquire(ctx context.Context) (*PooledConnection, error) {
	replica := rrp.selectReplica()
	if replica == nil {
		return nil, fmt.Errorf("no healthy replicas available")
	}

	return replica.Pool.Acquire(ctx)
}

// selectReplica selects a replica based on the strategy
func (rrp *ReadReplicaPool) selectReplica() *Replica {
	switch rrp.strategy {
	case RoundRobin:
		return rrp.selectRoundRobin()
	case Random:
		return rrp.selectRandom()
	case Weighted:
		return rrp.selectWeighted()
	case Priority:
		return rrp.selectPriority()
	default:
		return rrp.selectRoundRobin()
	}
}

// selectRoundRobin selects replicas in round-robin fashion
func (rrp *ReadReplicaPool) selectRoundRobin() *Replica {
	// Simple implementation - in production, use atomic counter
	for _, r := range rrp.replicas {
		if r.Healthy.Load() {
			return r
		}
	}
	return nil
}

// selectRandom selects a random healthy replica
func (rrp *ReadReplicaPool) selectRandom() *Replica {
	// Simplified - in production use crypto/rand
	return rrp.selectRoundRobin()
}

// selectWeighted selects based on weight
func (rrp *ReadReplicaPool) selectWeighted() *Replica {
	return rrp.selectRoundRobin()
}

// selectPriority selects highest priority first
func (rrp *ReadReplicaPool) selectPriority() *Replica {
	var best *Replica
	for _, r := range rrp.replicas {
		if !r.Healthy.Load() {
			continue
		}
		if best == nil || r.Config.Priority < best.Config.Priority {
			best = r
		}
	}
	return best
}

// HealthCheck performs health checks on all replicas
func (rrp *ReadReplicaPool) HealthCheck(ctx context.Context) {
	for _, r := range rrp.replicas {
		conn, err := r.Pool.Acquire(ctx)
		if err != nil {
			r.Healthy.Store(false)
			continue
		}
		defer conn.Release()

		r.Healthy.Store(conn.IsHealthy(ctx))
		r.LastCheck = time.Now()
	}
}

// GetHealthyReplicas returns list of healthy replicas
func (rrp *ReadReplicaPool) GetHealthyReplicas() []*Replica {
	var healthy []*Replica
	for _, r := range rrp.replicas {
		if r.Healthy.Load() {
			healthy = append(healthy, r)
		}
	}
	return healthy
}

// Close closes all replica pools
func (rrp *ReadReplicaPool) Close() error {
	for _, r := range rrp.replicas {
		r.Pool.Close()
	}
	return nil
}
