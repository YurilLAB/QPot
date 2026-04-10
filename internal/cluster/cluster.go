// Package cluster provides multi-instance cluster management for QPot
package cluster

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	ClusterIDPrefix     = "qc_"
	ClusterIDLength     = 24
	NodeIDPrefix        = "qn_"
	NodeIDLength        = 16
	DefaultClusterPort  = 7946
)

// Cluster represents a QPot cluster
type Cluster struct {
	ID           string                 `json:"id" yaml:"id"`
	Name         string                 `json:"name" yaml:"name"`
	PasswordHash string                 `json:"password_hash" yaml:"password_hash"`
	CreatedAt    time.Time              `json:"created_at" yaml:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at" yaml:"updated_at"`
	Metadata     map[string]string      `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	
	// Node management
	LocalNode   *Node                  `json:"local_node" yaml:"local_node"`
	Nodes       map[string]*Node       `json:"nodes" yaml:"nodes"`
	
	// Configuration
	Config      *ClusterConfig         `json:"config" yaml:"config"`
	
	// State (not serialized)
	mu            sync.RWMutex `json:"-" yaml:"-"`
	isInitialized bool         `json:"-" yaml:"-"`
	isRunning     bool         `json:"-" yaml:"-"`
}

// ClusterConfig defines cluster-wide settings
type ClusterConfig struct {
	BindAddr            string            `json:"bind_addr" yaml:"bind_addr"`
	BindPort            int               `json:"bind_port" yaml:"bind_port"`
	AdvertiseAddr       string            `json:"advertise_addr" yaml:"advertise_addr"`
	GossipInterval      time.Duration     `json:"gossip_interval" yaml:"gossip_interval"`
	ProbeInterval       time.Duration     `json:"probe_interval" yaml:"probe_interval"`
	ProbeTimeout        time.Duration     `json:"probe_timeout" yaml:"probe_timeout"`
	SuspicionMult       int               `json:"suspicion_mult" yaml:"suspicion_mult"`
	RetransmitMult      int               `json:"retransmit_mult" yaml:"retransmit_mult"`
	SyncInterval        time.Duration     `json:"sync_interval" yaml:"sync_interval"`
	EnableEncryption    bool              `json:"enable_encryption" yaml:"enable_encryption"`
	TLSCertPath         string            `json:"tls_cert_path,omitempty" yaml:"tls_cert_path,omitempty"`
	TLSKeyPath          string            `json:"tls_key_path,omitempty" yaml:"tls_key_path,omitempty"`
	CACertPath          string            `json:"ca_cert_path,omitempty" yaml:"ca_cert_path,omitempty"`
}

// DefaultClusterConfig returns default cluster configuration
func DefaultClusterConfig() *ClusterConfig {
	return &ClusterConfig{
		BindAddr:         "0.0.0.0",
		BindPort:         DefaultClusterPort,
		GossipInterval:   200 * time.Millisecond,
		ProbeInterval:    1 * time.Second,
		ProbeTimeout:     500 * time.Millisecond,
		SuspicionMult:    4,
		RetransmitMult:   4,
		SyncInterval:     30 * time.Second,
		EnableEncryption: true,
	}
}

// Node represents a cluster member
type Node struct {
	ID           string            `json:"id" yaml:"id"`
	Name         string            `json:"name" yaml:"name"`
	Address      string            `json:"address" yaml:"address"`
	Port         int               `json:"port" yaml:"port"`
	QPotID       string            `json:"qpot_id" yaml:"qpot_id"`
	InstanceName string            `json:"instance_name" yaml:"instance_name"`
	Status       NodeStatus        `json:"status" yaml:"status"`
	LastSeen     time.Time         `json:"last_seen" yaml:"last_seen"`
	JoinedAt     time.Time         `json:"joined_at" yaml:"joined_at"`
	Metadata     map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	
	// Stats
	Stats        NodeStats         `json:"stats" yaml:"stats"`
}

// NodeStatus represents the state of a node
type NodeStatus string

const (
	NodeStatusUnknown     NodeStatus = "unknown"
	NodeStatusHealthy     NodeStatus = "healthy"
	NodeStatusSuspect     NodeStatus = "suspect"
	NodeStatusFailed      NodeStatus = "failed"
	NodeStatusLeft        NodeStatus = "left"
	NodeStatusMaintenance NodeStatus = "maintenance"
)

// NodeStats contains node statistics
type NodeStats struct {
	TotalEvents    int64         `json:"total_events" yaml:"total_events"`
	ActiveAttacks  int64         `json:"active_attacks" yaml:"active_attacks"`
	Uptime         time.Duration `json:"uptime" yaml:"uptime"`
	CPUUsage       float64       `json:"cpu_usage" yaml:"cpu_usage"`
	MemoryUsage    float64       `json:"memory_usage" yaml:"memory_usage"`
	DiskUsage      float64       `json:"disk_usage" yaml:"disk_usage"`
	LastSync       time.Time     `json:"last_sync" yaml:"last_sync"`
}

// JoinRequest represents a request to join a cluster
type JoinRequest struct {
	ClusterID    string            `json:"cluster_id"`
	Password     string            `json:"password"`
	NodeName     string            `json:"node_name"`
	NodeAddress  string            `json:"node_address"`
	NodePort     int               `json:"node_port"`
	QPotID       string            `json:"qpot_id"`
	InstanceName string            `json:"instance_name"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty"`
}

// JoinResponse represents the response to a join request
type JoinResponse struct {
	Success      bool           `json:"success"`
	NodeID       string         `json:"node_id,omitempty"`
	ClusterName  string         `json:"cluster_name,omitempty"`
	Nodes        []*Node        `json:"nodes,omitempty"`
	Config       *ClusterConfig `json:"config,omitempty"`
	Error        string         `json:"error,omitempty"`
}

// ClusterStatus represents the overall cluster status
type ClusterStatus struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	NodeCount     int               `json:"node_count"`
	HealthyNodes  int               `json:"healthy_nodes"`
	SuspectNodes  int               `json:"suspect_nodes"`
	FailedNodes   int               `json:"failed_nodes"`
	TotalEvents   int64             `json:"total_events"`
	Leader        string            `json:"leader,omitempty"`
	IsRunning     bool              `json:"is_running"`
}

// ThreatIntel holds aggregated threat intelligence shared across cluster nodes.
type ThreatIntel struct {
	// TopSourceIPs contains the most active attacker IPs seen in the last hour
	// along with their hit counts, collected from this node.
	TopSourceIPs []IPCount `json:"top_source_ips"`
	// NodeID is the originating node.
	NodeID    string    `json:"node_id"`
	Timestamp time.Time `json:"timestamp"`
}

// IPCount pairs an IP address with an event count.
type IPCount struct {
	IP    string `json:"ip"`
	Count int64  `json:"count"`
}

// GossipMessage is the payload exchanged during gossip rounds.
type GossipMessage struct {
	SenderID  string    `json:"sender_id"`
	Timestamp time.Time `json:"timestamp"`
	// NodeDigest contains the current status of all nodes the sender knows about.
	NodeDigest []*Node `json:"node_digest"`
}

// Manager handles cluster lifecycle
type Manager struct {
	mu            sync.RWMutex
	cluster       *Cluster
	dataPath      string
	apiServer     *http.Server
	gossipTicker  *time.Ticker
	syncTicker    *time.Ticker
	stopCh        chan struct{}
	stopOnce      sync.Once
	// localIntel holds threat intelligence for the local node, updated externally.
	localIntel    *ThreatIntel
	// peerIntel aggregates intel received from other nodes, keyed by node ID.
	peerIntel     map[string]*ThreatIntel
}

// NewManager creates a new cluster manager
func NewManager(dataPath string) *Manager {
	return &Manager{
		dataPath:  dataPath,
		stopCh:    make(chan struct{}),
		peerIntel: make(map[string]*ThreatIntel),
	}
}

// UpdateThreatIntel updates the local node's threat intelligence data.
// Callers should pass the top source IPs seen in the last hour.
func (m *Manager) UpdateThreatIntel(topIPs []IPCount) {
	m.mu.Lock()
	defer m.mu.Unlock()

	nodeID := ""
	if m.cluster != nil && m.cluster.LocalNode != nil {
		nodeID = m.cluster.LocalNode.ID
	}
	m.localIntel = &ThreatIntel{
		TopSourceIPs: topIPs,
		NodeID:       nodeID,
		Timestamp:    time.Now(),
	}
}

// GetThreatIntel returns the merged threat intelligence from all cluster nodes.
func (m *Manager) GetThreatIntel() []*ThreatIntel {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*ThreatIntel
	if m.localIntel != nil {
		result = append(result, m.localIntel)
	}
	for _, intel := range m.peerIntel {
		result = append(result, intel)
	}
	return result
}

// InitCluster initializes a new cluster with password authentication
func (m *Manager) InitCluster(name, password string, cfg *ClusterConfig) (*Cluster, error) {
	if name == "" {
		return nil, fmt.Errorf("cluster name is required")
	}
	if password == "" {
		return nil, fmt.Errorf("cluster password is required")
	}
	if len(password) < 8 {
		return nil, fmt.Errorf("password must be at least 8 characters")
	}

	clusterID, err := generateClusterID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate cluster ID: %w", err)
	}

	if cfg == nil {
		cfg = DefaultClusterConfig()
	}

	// Hash the password
	passwordHash := hashPassword(password)

	now := time.Now()
	cluster := &Cluster{
		ID:            clusterID,
		Name:          name,
		PasswordHash:  passwordHash,
		CreatedAt:     now,
		UpdatedAt:     now,
		Metadata:      make(map[string]string),
		Nodes:         make(map[string]*Node),
		Config:        cfg,
		isInitialized: true,
	}

	// Create local node
	localNodeID, err := generateNodeID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate node ID: %w", err)
	}

	localNode := &Node{
		ID:       localNodeID,
		Name:     "leader",
		Address:  cfg.AdvertiseAddr,
		Port:     cfg.BindPort,
		Status:   NodeStatusHealthy,
		LastSeen: now,
		JoinedAt: now,
		Metadata: make(map[string]string),
	}

	cluster.LocalNode = localNode
	cluster.Nodes[localNode.ID] = localNode

	m.mu.Lock()
	m.cluster = cluster
	m.mu.Unlock()

	// Save cluster configuration
	if err := m.saveCluster(); err != nil {
		return nil, fmt.Errorf("failed to save cluster: %w", err)
	}

	slog.Info("Cluster initialized",
		"id", clusterID,
		"name", name,
		"password_protected", true)

	return cluster, nil
}

// JoinCluster joins an existing cluster with password authentication
func (m *Manager) JoinCluster(clusterID, password string, localNode *Node, seedNodes []string) (*Cluster, error) {
	if clusterID == "" {
		return nil, fmt.Errorf("cluster ID is required")
	}
	if password == "" {
		return nil, fmt.Errorf("cluster password is required")
	}
	if localNode == nil {
		return nil, fmt.Errorf("local node info is required")
	}
	if len(seedNodes) == 0 {
		return nil, fmt.Errorf("at least one seed node is required")
	}

	// Try to join via seed nodes
	var lastErr error
	for _, seed := range seedNodes {
		cluster, err := m.attemptJoin(seed, clusterID, password, localNode)
		if err == nil {
			m.mu.Lock()
			m.cluster = cluster
			m.mu.Unlock()
			
			if err := m.saveCluster(); err != nil {
				slog.Warn("Failed to save cluster config", "error", err)
			}
			return cluster, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("failed to join cluster: %w", lastErr)
}

// attemptJoin tries to join a cluster via a specific seed node
func (m *Manager) attemptJoin(seedAddr, clusterID, password string, localNode *Node) (*Cluster, error) {
	joinReq := JoinRequest{
		ClusterID:    clusterID,
		Password:     password,
		NodeName:     localNode.Name,
		NodeAddress:  localNode.Address,
		NodePort:     localNode.Port,
		QPotID:       localNode.QPotID,
		InstanceName: localNode.InstanceName,
		Metadata:     localNode.Metadata,
		Capabilities: localNode.Capabilities,
	}

	reqBody, err := json.Marshal(joinReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal join request: %w", err)
	}

	url := fmt.Sprintf("http://%s/api/v1/cluster/join", seedAddr)
	resp, err := http.Post(url, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to contact seed node: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var joinResp JoinResponse
	if err := json.Unmarshal(body, &joinResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if !joinResp.Success {
		return nil, fmt.Errorf("join rejected: %s", joinResp.Error)
	}

	// Create local cluster state
	now := time.Now()
	localNode.ID = joinResp.NodeID
	localNode.JoinedAt = now
	localNode.LastSeen = now
	localNode.Status = NodeStatusHealthy

	cluster := &Cluster{
		ID:            clusterID,
		Name:          joinResp.ClusterName,
		PasswordHash:  hashPassword(password), // bcrypt hash for local verification
		CreatedAt:     now,
		UpdatedAt:     now,
		LocalNode:     localNode,
		Nodes:         make(map[string]*Node),
		Config:        joinResp.Config,
		isInitialized: true,
	}

	// Add all nodes from response
	for _, node := range joinResp.Nodes {
		cluster.Nodes[node.ID] = node
	}
	cluster.Nodes[localNode.ID] = localNode

	slog.Info("Joined cluster",
		"cluster_id", clusterID,
		"cluster_name", joinResp.ClusterName,
		"node_id", localNode.ID,
		"total_nodes", len(cluster.Nodes))

	return cluster, nil
}

// Start starts the cluster manager
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cluster == nil {
		return fmt.Errorf("cluster not initialized")
	}

	if m.cluster.isRunning {
		return nil
	}

	// Re-create stopCh so Start() works correctly after a previous Stop()
	m.stopCh = make(chan struct{})
	m.stopOnce = sync.Once{}

	// Start API server
	if err := m.startAPIServer(); err != nil {
		return fmt.Errorf("failed to start API server: %w", err)
	}

	// Start background tasks
	m.gossipTicker = time.NewTicker(m.cluster.Config.GossipInterval)
	m.syncTicker = time.NewTicker(m.cluster.Config.SyncInterval)

	go m.gossipLoop()
	go m.syncLoop()

	m.cluster.isRunning = true
	slog.Info("Cluster manager started", "cluster_id", m.cluster.ID)

	return nil
}

// Stop stops the cluster manager
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cluster == nil || !m.cluster.isRunning {
		return nil
	}

	// Use sync.Once to prevent double-close panics
	m.stopOnce.Do(func() {
		close(m.stopCh)
	})

	if m.gossipTicker != nil {
		m.gossipTicker.Stop()
	}
	if m.syncTicker != nil {
		m.syncTicker.Stop()
	}

	if m.apiServer != nil {
		m.apiServer.Close()
	}

	m.cluster.isRunning = false
	slog.Info("Cluster manager stopped")

	return nil
}

// GetStatus returns the current cluster status
func (m *Manager) GetStatus() *ClusterStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.cluster == nil {
		return nil
	}

	status := &ClusterStatus{
		ID:        m.cluster.ID,
		Name:      m.cluster.Name,
		NodeCount: len(m.cluster.Nodes),
		IsRunning: m.cluster.isRunning,
	}

	var totalEvents int64
	for _, node := range m.cluster.Nodes {
		switch node.Status {
		case NodeStatusHealthy:
			status.HealthyNodes++
		case NodeStatusSuspect:
			status.SuspectNodes++
		case NodeStatusFailed:
			status.FailedNodes++
		}
		totalEvents += node.Stats.TotalEvents
	}

	status.TotalEvents = totalEvents

	return status
}

// GetNodes returns all nodes in the cluster
func (m *Manager) GetNodes() []*Node {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.cluster == nil {
		return nil
	}

	nodes := make([]*Node, 0, len(m.cluster.Nodes))
	for _, node := range m.cluster.Nodes {
		nodes = append(nodes, node)
	}

	return nodes
}

// GetCluster returns the cluster
func (m *Manager) GetCluster() *Cluster {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cluster
}

// UpdateNodeStats updates the local node's statistics
func (m *Manager) UpdateNodeStats(stats NodeStats) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cluster == nil || m.cluster.LocalNode == nil {
		return
	}

	m.cluster.LocalNode.Stats = stats
	m.cluster.LocalNode.LastSeen = time.Now()
}

// VerifyPassword verifies the cluster password against the stored bcrypt hash.
func (m *Manager) VerifyPassword(password string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.cluster == nil {
		return false
	}

	return checkPassword(password, m.cluster.PasswordHash)
}

// HandleJoinRequest handles a join request from another node
func (m *Manager) HandleJoinRequest(req *JoinRequest) *JoinResponse {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cluster == nil {
		return &JoinResponse{
			Success: false,
			Error:   "cluster not initialized",
		}
	}

	// Verify cluster ID
	if req.ClusterID != m.cluster.ID {
		return &JoinResponse{
			Success: false,
			Error:   "invalid cluster ID",
		}
	}

	// Verify password using bcrypt comparison
	if !checkPassword(req.Password, m.cluster.PasswordHash) {
		slog.Warn("Join attempt with invalid password",
			"cluster_id", req.ClusterID,
			"from", req.NodeAddress)
		return &JoinResponse{
			Success: false,
			Error:   "invalid password",
		}
	}

	// Generate node ID
	nodeID, err := generateNodeID()
	if err != nil {
		return &JoinResponse{
			Success: false,
			Error:   "failed to generate node ID",
		}
	}

	// Create node
	now := time.Now()
	node := &Node{
		ID:           nodeID,
		Name:         req.NodeName,
		Address:      req.NodeAddress,
		Port:         req.NodePort,
		QPotID:       req.QPotID,
		InstanceName: req.InstanceName,
		Status:       NodeStatusHealthy,
		LastSeen:     now,
		JoinedAt:     now,
		Metadata:     req.Metadata,
		Capabilities: req.Capabilities,
	}

	// Add to cluster
	m.cluster.Nodes[nodeID] = node
	m.cluster.UpdatedAt = now

	// Prepare response with all nodes
	nodes := make([]*Node, 0, len(m.cluster.Nodes))
	for _, n := range m.cluster.Nodes {
		nodes = append(nodes, n)
	}

	slog.Info("Node joined cluster",
		"node_id", nodeID,
		"node_name", req.NodeName,
		"node_address", req.NodeAddress,
		"total_nodes", len(m.cluster.Nodes))

	return &JoinResponse{
		Success:     true,
		NodeID:      nodeID,
		ClusterName: m.cluster.Name,
		Nodes:       nodes,
		Config:      m.cluster.Config,
	}
}

// startAPIServer starts the cluster API server
func (m *Manager) startAPIServer() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/cluster/join", m.handleJoinHTTP)
	mux.HandleFunc("/api/v1/cluster/status", m.handleStatusHTTP)
	mux.HandleFunc("/api/v1/cluster/nodes", m.handleNodesHTTP)
	mux.HandleFunc("/api/v1/cluster/leave", m.handleLeaveHTTP)
	mux.HandleFunc("/api/v1/cluster/gossip", m.handleGossipHTTP)
	mux.HandleFunc("/api/v1/cluster/intel", m.handleIntelHTTP)

	addr := fmt.Sprintf("%s:%d", m.cluster.Config.BindAddr, m.cluster.Config.BindPort)
	m.apiServer = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		if err := m.apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("API server error", "error", err)
		}
	}()

	return nil
}

// HTTP handlers
func (m *Manager) handleJoinHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var req JoinRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	resp := m.HandleJoinRequest(&req)
	w.Header().Set("Content-Type", "application/json")
	if !resp.Success {
		w.WriteHeader(http.StatusUnauthorized)
	}
	json.NewEncoder(w).Encode(resp)
}

func (m *Manager) handleStatusHTTP(w http.ResponseWriter, r *http.Request) {
	status := m.GetStatus()
	if status == nil {
		http.Error(w, "Cluster not initialized", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (m *Manager) handleNodesHTTP(w http.ResponseWriter, r *http.Request) {
	nodes := m.GetNodes()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(nodes)
}

func (m *Manager) handleLeaveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var req struct {
		NodeID string `json:"node_id"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.NodeID == "" {
		http.Error(w, "Invalid JSON or missing node_id", http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	if m.cluster != nil {
		if node, ok := m.cluster.Nodes[req.NodeID]; ok {
			node.Status = NodeStatusLeft
			delete(m.cluster.Nodes, req.NodeID)
			slog.Info("Node left cluster", "node_id", req.NodeID)
		}
	}
	m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// gossipLoop periodically gossips with other nodes
func (m *Manager) gossipLoop() {
	for {
		select {
		case <-m.stopCh:
			return
		case <-m.gossipTicker.C:
			m.gossip()
		}
	}
}

// syncLoop periodically syncs data with other nodes
func (m *Manager) syncLoop() {
	for {
		select {
		case <-m.stopCh:
			return
		case <-m.syncTicker.C:
			m.sync()
		}
	}
}

// gossip sends a heartbeat/state-digest to each known peer node and merges
// any updated node information returned in the response.
func (m *Manager) gossip() {
	m.mu.RLock()
	if m.cluster == nil || m.cluster.LocalNode == nil {
		m.mu.RUnlock()
		return
	}

	localID := m.cluster.LocalNode.ID
	// Build a snapshot of current node states to share.
	digest := make([]*Node, 0, len(m.cluster.Nodes))
	for _, n := range m.cluster.Nodes {
		digest = append(digest, n)
	}

	// Collect peer addresses to contact (all nodes except ourselves).
	type peerInfo struct {
		id      string
		address string
		port    int
	}
	var peers []peerInfo
	for _, n := range m.cluster.Nodes {
		if n.ID == localID {
			continue
		}
		if n.Status == NodeStatusLeft || n.Status == NodeStatusFailed {
			continue
		}
		peers = append(peers, peerInfo{id: n.ID, address: n.Address, port: n.Port})
	}
	m.mu.RUnlock()

	msg := GossipMessage{
		SenderID:   localID,
		Timestamp:  time.Now(),
		NodeDigest: digest,
	}

	body, err := json.Marshal(msg)
	if err != nil {
		slog.Error("Gossip: failed to marshal message", "error", err)
		return
	}

	for _, peer := range peers {
		url := fmt.Sprintf("http://%s:%d/api/v1/cluster/gossip", peer.address, peer.port)
		resp, err := http.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			slog.Debug("Gossip: peer unreachable", "node_id", peer.id, "error", err)
			// Mark node as suspect after failed gossip contact.
			m.mu.Lock()
			if node, ok := m.cluster.Nodes[peer.id]; ok && node.Status == NodeStatusHealthy {
				node.Status = NodeStatusSuspect
			}
			m.mu.Unlock()
			continue
		}

		var peerMsg GossipMessage
		if err := json.NewDecoder(resp.Body).Decode(&peerMsg); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		// Merge peer's node knowledge into our own map.
		now := time.Now()
		m.mu.Lock()
		for _, peerNode := range peerMsg.NodeDigest {
			if peerNode.ID == localID {
				continue
			}
			existing, ok := m.cluster.Nodes[peerNode.ID]
			if !ok {
				// New node discovered via gossip.
				m.cluster.Nodes[peerNode.ID] = peerNode
				slog.Info("Gossip: discovered new node", "node_id", peerNode.ID, "name", peerNode.Name)
			} else if peerNode.LastSeen.After(existing.LastSeen) {
				// Peer has fresher info about this node.
				existing.Status = peerNode.Status
				existing.LastSeen = peerNode.LastSeen
				existing.Stats = peerNode.Stats
			}
		}
		// Mark the responding peer as healthy and update its last-seen time.
		if node, ok := m.cluster.Nodes[peer.id]; ok {
			node.Status = NodeStatusHealthy
			node.LastSeen = now
		}
		m.mu.Unlock()
	}

	// Mark nodes that haven't been seen for a long time as failed.
	m.mu.Lock()
	deadline := time.Now().Add(-3 * m.cluster.Config.GossipInterval * time.Duration(m.cluster.Config.SuspicionMult*10))
	for _, node := range m.cluster.Nodes {
		if node.ID == localID {
			continue
		}
		if node.Status == NodeStatusSuspect && node.LastSeen.Before(deadline) {
			node.Status = NodeStatusFailed
			slog.Warn("Gossip: node marked as failed", "node_id", node.ID, "last_seen", node.LastSeen)
		}
	}
	m.mu.Unlock()
}

// sync aggregates node statistics and shares threat intelligence with peers.
func (m *Manager) sync() {
	m.mu.RLock()
	if m.cluster == nil || m.cluster.LocalNode == nil {
		m.mu.RUnlock()
		return
	}

	localID := m.cluster.LocalNode.ID
	type peerInfo struct {
		id      string
		address string
		port    int
	}
	var peers []peerInfo
	for _, n := range m.cluster.Nodes {
		if n.ID == localID {
			continue
		}
		if n.Status == NodeStatusLeft || n.Status == NodeStatusFailed {
			continue
		}
		peers = append(peers, peerInfo{id: n.ID, address: n.Address, port: n.Port})
	}

	var localIntel *ThreatIntel
	if m.localIntel != nil {
		localIntel = m.localIntel
	}
	m.mu.RUnlock()

	// Share local intel with peers and collect theirs.
	if localIntel != nil {
		intelBody, err := json.Marshal(localIntel)
		if err == nil {
			for _, peer := range peers {
				url := fmt.Sprintf("http://%s:%d/api/v1/cluster/intel", peer.address, peer.port)
				resp, err := http.Post(url, "application/json", bytes.NewReader(intelBody))
				if err != nil {
					slog.Debug("Sync: failed to send intel to peer", "node_id", peer.id, "error", err)
					continue
				}

				var peerIntel ThreatIntel
				if err := json.NewDecoder(resp.Body).Decode(&peerIntel); err != nil {
					resp.Body.Close()
					continue
				}
				resp.Body.Close()

				m.mu.Lock()
				m.peerIntel[peerIntel.NodeID] = &peerIntel
				// Update event count for this peer node based on intel total.
				if node, ok := m.cluster.Nodes[peer.id]; ok {
					var total int64
					for _, ip := range peerIntel.TopSourceIPs {
						total += ip.Count
					}
					node.Stats.TotalEvents += total
					node.Stats.LastSync = time.Now()
				}
				m.mu.Unlock()
			}
		}
	}

	// Aggregate total event counts across all known nodes and log a summary.
	m.mu.RLock()
	var totalEvents int64
	for _, node := range m.cluster.Nodes {
		totalEvents += node.Stats.TotalEvents
	}
	nodeCount := len(m.cluster.Nodes)
	m.mu.RUnlock()

	slog.Debug("Cluster sync complete",
		"total_nodes", nodeCount,
		"total_events", totalEvents)
}

// handleGossipHTTP accepts a gossip ping from another node and responds with
// the local node's own state digest.
func (m *Manager) handleGossipHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var incoming GossipMessage
	if err := json.Unmarshal(body, &incoming); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	now := time.Now()
	m.mu.Lock()
	if m.cluster != nil {
		// Merge the sender's node digest.
		for _, node := range incoming.NodeDigest {
			if m.cluster.LocalNode != nil && node.ID == m.cluster.LocalNode.ID {
				continue
			}
			existing, ok := m.cluster.Nodes[node.ID]
			if !ok {
				m.cluster.Nodes[node.ID] = node
				slog.Info("Gossip: discovered node via ping", "node_id", node.ID)
			} else if node.LastSeen.After(existing.LastSeen) {
				existing.Status = node.Status
				existing.LastSeen = node.LastSeen
				existing.Stats = node.Stats
			}
		}
		// Update the sender's own record.
		if existing, ok := m.cluster.Nodes[incoming.SenderID]; ok {
			existing.Status = NodeStatusHealthy
			existing.LastSeen = now
		}
	}

	// Build response with our own digest.
	digest := make([]*Node, 0)
	if m.cluster != nil {
		for _, n := range m.cluster.Nodes {
			digest = append(digest, n)
		}
	}
	var localID string
	if m.cluster != nil && m.cluster.LocalNode != nil {
		localID = m.cluster.LocalNode.ID
	}
	m.mu.Unlock()

	response := GossipMessage{
		SenderID:   localID,
		Timestamp:  now,
		NodeDigest: digest,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleIntelHTTP accepts threat intel from a peer node and responds with
// the local node's own intel.
func (m *Manager) handleIntelHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var incoming ThreatIntel
	if err := json.Unmarshal(body, &incoming); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	if incoming.NodeID != "" {
		m.peerIntel[incoming.NodeID] = &incoming
	}
	localIntel := m.localIntel
	m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if localIntel != nil {
		json.NewEncoder(w).Encode(localIntel)
	} else {
		json.NewEncoder(w).Encode(&ThreatIntel{Timestamp: time.Now()})
	}
}

// saveCluster saves cluster configuration to disk
func (m *Manager) saveCluster() error {
	if m.cluster == nil {
		return fmt.Errorf("no cluster to save")
	}

	clusterPath := filepath.Join(m.dataPath, "cluster.json")
	if err := os.MkdirAll(m.dataPath, 0750); err != nil {
		return err
	}

	data, err := json.MarshalIndent(m.cluster, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(clusterPath, data, 0600)
}

// LoadCluster loads cluster configuration from disk
func (m *Manager) LoadCluster() (*Cluster, error) {
	clusterPath := filepath.Join(m.dataPath, "cluster.json")
	data, err := os.ReadFile(clusterPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var cluster Cluster
	if err := json.Unmarshal(data, &cluster); err != nil {
		return nil, err
	}

	// Preserve the nodes map that was deserialized from JSON.
	// Only create a new map when there are no nodes at all.
	if cluster.Nodes == nil {
		cluster.Nodes = make(map[string]*Node)
	}
	// Ensure the local node is always present in the map.
	if cluster.LocalNode != nil {
		cluster.Nodes[cluster.LocalNode.ID] = cluster.LocalNode
	}

	m.mu.Lock()
	m.cluster = &cluster
	m.mu.Unlock()

	return &cluster, nil
}

// LeaveCluster removes this node from the cluster
func (m *Manager) LeaveCluster() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cluster == nil {
		return fmt.Errorf("not in a cluster")
	}

	// Notify other nodes with a short timeout so a dead peer doesn't block.
	leaveClient := &http.Client{Timeout: 3 * time.Second}
	localNodeID := m.cluster.LocalNode.ID
	leaveBody, _ := json.Marshal(map[string]string{"node_id": localNodeID})
	for _, node := range m.cluster.Nodes {
		if node.ID == localNodeID {
			continue
		}
		url := fmt.Sprintf("http://%s:%d/api/v1/cluster/leave", node.Address, node.Port)
		resp, err := leaveClient.Post(url, "application/json", bytes.NewReader(leaveBody))
		if err != nil {
			slog.Debug("LeaveCluster: failed to notify peer", "node_id", node.ID, "error", err)
			continue
		}
		resp.Body.Close()
	}

	// Remove cluster file
	clusterPath := filepath.Join(m.dataPath, "cluster.json")
	os.Remove(clusterPath)

	m.cluster = nil
	slog.Info("Left cluster")
	return nil
}

// Utility functions

func generateClusterID() (string, error) {
	return generateID(ClusterIDPrefix, ClusterIDLength)
}

func generateNodeID() (string, error) {
	return generateID(NodeIDPrefix, NodeIDLength)
}

func generateID(prefix string, length int) (string, error) {
	bytes := make([]byte, (length+1)/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	encoded := hex.EncodeToString(bytes)
	return strings.ToLower(prefix + encoded[:length]), nil
}

// hashPassword hashes a password using bcrypt with a random salt.
func hashPassword(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		// Fall back to a hex-encoded error marker that will never match
		return "invalid"
	}
	return string(hash)
}

// checkPassword verifies a plain-text password against a bcrypt hash.
// Returns true when they match.
func checkPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
