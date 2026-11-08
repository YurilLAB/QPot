// Package cluster provides multi-instance cluster management for QPot
package cluster

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qpot/qpot/internal/hostsetup"
	"golang.org/x/crypto/bcrypt"
)

const (
	// ProtocolVersion requires node-specific certificate enrollment. Older
	// QPot clients must update before they can join or run this cluster.
	ProtocolVersion    = 2
	ClusterIDPrefix    = "qc_"
	ClusterIDLength    = 24
	NodeIDPrefix       = "qn_"
	NodeIDLength       = 16
	DefaultClusterPort = 7946
)

// Cluster represents a QPot cluster
type Cluster struct {
	Version      int    `json:"version,omitempty" yaml:"version,omitempty"`
	ID           string `json:"id" yaml:"id"`
	Name         string `json:"name" yaml:"name"`
	PasswordHash string `json:"password_hash" yaml:"password_hash"`
	// MemberKey is given to a node only when it is admitted. The peer
	// endpoints require it besides the password, which every joiner has, so
	// a node the host denied (or has not approved) cannot take part. Empty
	// for clusters created before it existed: their peers use the password.
	MemberKey string `json:"member_key,omitempty" yaml:"member_key,omitempty"`
	// CAKey exists only on the host that initialized the cluster, which acts
	// as its enrollment authority. It is never sent to admitted members.
	CAKey string `json:"ca_key,omitempty" yaml:"ca_key,omitempty"`
	// NodeKey is generated locally; NodeCertificate is the CA-signed leaf and
	// public CA chain. Both survive restart in this node's private state.
	NodeKey         string            `json:"node_key,omitempty" yaml:"node_key,omitempty"`
	NodeCertificate string            `json:"node_certificate,omitempty" yaml:"node_certificate,omitempty"`
	CreatedAt       time.Time         `json:"created_at" yaml:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at" yaml:"updated_at"`
	Metadata        map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// Node management
	LocalNode *Node            `json:"local_node" yaml:"local_node"`
	Nodes     map[string]*Node `json:"nodes" yaml:"nodes"`
	// Revocations are the enrollment host's signed removals of nodes (see
	// peerauth.go), kept so the removed nodes stay refused after a restart.
	Revocations []Revocation `json:"revocations,omitempty" yaml:"revocations,omitempty"`

	// Configuration
	Config *ClusterConfig `json:"config" yaml:"config"`

	// State (not serialized). Synchronization is handled by the owning Manager's
	// mutex, so the Cluster value itself carries no lock.
	isInitialized bool `json:"-" yaml:"-"`
	isRunning     bool `json:"-" yaml:"-"`
}

// ClusterConfig defines cluster-wide settings
type ClusterConfig struct {
	BindAddr         string        `json:"bind_addr" yaml:"bind_addr"`
	BindPort         int           `json:"bind_port" yaml:"bind_port"`
	AdvertiseAddr    string        `json:"advertise_addr" yaml:"advertise_addr"`
	GossipInterval   time.Duration `json:"gossip_interval" yaml:"gossip_interval"`
	ProbeInterval    time.Duration `json:"probe_interval" yaml:"probe_interval"`
	ProbeTimeout     time.Duration `json:"probe_timeout" yaml:"probe_timeout"`
	SuspicionMult    int           `json:"suspicion_mult" yaml:"suspicion_mult"`
	RetransmitMult   int           `json:"retransmit_mult" yaml:"retransmit_mult"`
	SyncInterval     time.Duration `json:"sync_interval" yaml:"sync_interval"`
	EnableEncryption bool          `json:"enable_encryption" yaml:"enable_encryption"`
	// RequireApproval gates membership behind explicit host approval: a node
	// that supplies the correct cluster password is not admitted immediately but
	// placed in a pending queue the host reviews (with the requester's source IP
	// and hostname) and approves or denies. On by default for new clusters.
	RequireApproval bool   `json:"require_approval" yaml:"require_approval"`
	TLSCertPath     string `json:"tls_cert_path,omitempty" yaml:"tls_cert_path,omitempty"`
	TLSKeyPath      string `json:"tls_key_path,omitempty" yaml:"tls_key_path,omitempty"`
	CACertPath      string `json:"ca_cert_path,omitempty" yaml:"ca_cert_path,omitempty"`
	// TrustOperatorCerts makes this node accept peers serving an operator
	// certificate (checked against CACertPath, or the system roots without
	// one) besides those of the cluster CA. Set on a node that joined with
	// operator certificates allowed (qpot cluster join --operator-cert).
	TrustOperatorCerts bool `json:"trust_operator_certs,omitempty" yaml:"trust_operator_certs,omitempty"`
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
		RequireApproval:  true,
	}
}

// Cluster safety bounds. Cluster config can arrive over the wire from a seed
// node (JoinResponse.Config) or be reloaded from disk, so every numeric/duration
// field that feeds a timer or arithmetic must be clamped before use. Without
// this, a hostile/garbage seed can set GossipInterval=0 (panics time.NewTicker)
// or a huge SuspicionMult (overflows the failure-detection deadline to a
// negative/huge value, corrupting membership).
const (
	maxClusterBodyBytes = 1 << 20 // 1 MiB cap on any cluster HTTP request/response body
	minSuspicionMult    = 1
	maxSuspicionMult    = 100
	maxGossipInterval   = 1 * time.Minute
	maxSyncInterval     = 10 * time.Minute
	// maxClusterNodes bounds the member map so a peer can't grow it without
	// limit by gossiping fabricated node records (memory DoS).
	maxClusterNodes = 4096
)

// sanitizeClusterConfig clamps all numeric/duration fields to sane bounds and
// substitutes the default config for a nil input. This is the trust boundary
// for any ClusterConfig that did not originate locally.
func sanitizeClusterConfig(c *ClusterConfig) *ClusterConfig {
	d := DefaultClusterConfig()
	if c == nil {
		return d
	}
	if c.GossipInterval <= 0 || c.GossipInterval > maxGossipInterval {
		c.GossipInterval = d.GossipInterval
	}
	if c.SyncInterval <= 0 || c.SyncInterval > maxSyncInterval {
		c.SyncInterval = d.SyncInterval
	}
	if c.ProbeInterval <= 0 {
		c.ProbeInterval = d.ProbeInterval
	}
	if c.ProbeTimeout <= 0 {
		c.ProbeTimeout = d.ProbeTimeout
	}
	if c.SuspicionMult < minSuspicionMult || c.SuspicionMult > maxSuspicionMult {
		c.SuspicionMult = d.SuspicionMult
	}
	if c.RetransmitMult < 1 {
		c.RetransmitMult = d.RetransmitMult
	}
	return c
}

// Node represents a cluster member
type Node struct {
	ID      string `json:"id" yaml:"id"`
	Name    string `json:"name" yaml:"name"`
	Address string `json:"address" yaml:"address"`
	Port    int    `json:"port" yaml:"port"`
	// A node carries no QPot ID: that is the instance's web API credential,
	// and gossip, the join answer and cluster.json handed every member the
	// others'. An older node's "qpot_id" is an unknown field, dropped when
	// read (LoadCluster also rewrites a cluster.json that has one).
	InstanceName string            `json:"instance_name" yaml:"instance_name"`
	Status       NodeStatus        `json:"status" yaml:"status"`
	LastSeen     time.Time         `json:"last_seen" yaml:"last_seen"`
	JoinedAt     time.Time         `json:"joined_at" yaml:"joined_at"`
	Metadata     map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`

	// Stats
	Stats NodeStats `json:"stats" yaml:"stats"`
}

// clone returns a deep copy of n, so it can be read or encoded after the
// manager lock is released without racing concurrent updates.
func (n *Node) clone() *Node {
	c := *n
	if n.Metadata != nil {
		c.Metadata = make(map[string]string, len(n.Metadata))
		for k, v := range n.Metadata {
			c.Metadata[k] = v
		}
	}
	c.Capabilities = append([]string(nil), n.Capabilities...)
	return &c
}

// snapshotNodesLocked returns deep copies of every member. Caller holds m.mu.
func (m *Manager) snapshotNodesLocked() []*Node {
	nodes := make([]*Node, 0, len(m.cluster.Nodes))
	for _, n := range m.cluster.Nodes {
		nodes = append(nodes, n.clone())
	}
	return nodes
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
	TotalEvents   int64         `json:"total_events" yaml:"total_events"`
	ActiveAttacks int64         `json:"active_attacks" yaml:"active_attacks"`
	Uptime        time.Duration `json:"uptime" yaml:"uptime"`
	CPUUsage      float64       `json:"cpu_usage" yaml:"cpu_usage"`
	MemoryUsage   float64       `json:"memory_usage" yaml:"memory_usage"`
	DiskUsage     float64       `json:"disk_usage" yaml:"disk_usage"`
	LastSync      time.Time     `json:"last_sync" yaml:"last_sync"`
}

// JoinRequest represents a request to join a cluster
type JoinRequest struct {
	Version      int               `json:"version"`
	ClusterID    string            `json:"cluster_id"`
	Password     string            `json:"password"`
	NodeName     string            `json:"node_name"`
	NodeAddress  string            `json:"node_address"`
	NodePort     int               `json:"node_port"`
	InstanceName string            `json:"instance_name"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty"`
	// PollSecret is a random secret of the joiner's. A join that waits for
	// host approval is collected only by a poll that carries it (the outcome
	// holds the member key and node certificate), not by anyone who has the
	// password and the request ID. The host keeps only its hash.
	PollSecret string `json:"poll_secret,omitempty"`
	// NodeCSR proves possession of the joining node's locally generated key.
	NodeCSR string `json:"node_csr"`
}

// JoinResponse represents the response to a join request
type JoinResponse struct {
	Version int  `json:"version"`
	Success bool `json:"success"`
	// Status is "approved" when the node was admitted, or "pending" when the
	// cluster requires host approval and the request is now awaiting it.
	Status string `json:"status,omitempty"`
	// RequestID identifies a pending join so the joiner can poll its status and
	// the host can approve/deny it.
	RequestID   string         `json:"request_id,omitempty"`
	NodeID      string         `json:"node_id,omitempty"`
	ClusterName string         `json:"cluster_name,omitempty"`
	Nodes       []*Node        `json:"nodes,omitempty"`
	Config      *ClusterConfig `json:"config,omitempty"`
	// No private signing key is part of the enrollment response.
	MemberKey       string `json:"member_key,omitempty"`
	NodeCertificate string `json:"node_certificate,omitempty"`
	Error           string `json:"error,omitempty"`
	ErrorCode       string `json:"error_code,omitempty"`
}

func joinFailure(err error) *JoinResponse {
	response := &JoinResponse{Error: err.Error()}
	var coded *hostsetup.Error
	if errors.As(err, &coded) {
		response.ErrorCode = coded.Code
		response.Error = coded.Cause()
	}
	return response
}

// memberKeyHeader carries Cluster.MemberKey on peer requests.
const memberKeyHeader = "X-Cluster-Member"

const clusterVersionHeader = "X-Cluster-Version"

// ClusterStatus represents the overall cluster status
type ClusterStatus struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	NodeCount    int    `json:"node_count"`
	HealthyNodes int    `json:"healthy_nodes"`
	SuspectNodes int    `json:"suspect_nodes"`
	FailedNodes  int    `json:"failed_nodes"`
	TotalEvents  int64  `json:"total_events"`
	Leader       string `json:"leader,omitempty"`
	IsRunning    bool   `json:"is_running"`
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
	// Revocations are the node removals the sender holds, each signed by the
	// cluster CA (see peerauth.go).
	Revocations []Revocation `json:"revocations,omitempty"`
}

// Manager handles cluster lifecycle
type Manager struct {
	mu           sync.RWMutex
	cluster      *Cluster
	dataPath     string
	apiServer    *http.Server
	gossipTicker *time.Ticker
	syncTicker   *time.Ticker
	stopCh       chan struct{}
	stopOnce     sync.Once
	// plainPassword is the cluster password stored in memory (never on disk).
	// Used to authenticate outbound gossip and intel requests to peer nodes.
	plainPassword string
	// localIntel holds threat intelligence for the local node, updated externally.
	localIntel *ThreatIntel
	// peerIntel aggregates intel received from other nodes, keyed by node ID.
	peerIntel map[string]*ThreatIntel
	// pendingJoins holds password-authenticated join requests awaiting host
	// approval, keyed by request ID. joinOutcomes records the decision so the
	// joiner can poll its result after it has been approved or denied.
	pendingJoins map[string]*PendingJoin
	joinOutcomes map[string]*JoinOutcome
	// joinPollInterval/joinPollTimeout control how a joiner polls for approval;
	// overridable in tests. Zero means use the production defaults.
	joinPollInterval time.Duration
	joinPollTimeout  time.Duration
	// upgradeActivate is an optional filesystem activation hook for fault
	// tests. Production uses an atomic rename in the cluster state directory.
	upgradeActivate      func(staged, active string) error
	upgradeWrite         func(file *os.File, data []byte) error
	upgradeSyncDirectory func(path string) error
	// authLimit throttles sources that keep sending wrong passwords.
	authLimit authLimiter
	// probedFailed is when gossip last tried each failed peer (see gossip).
	probeMu      sync.Mutex
	probedFailed map[string]time.Time
	// certWarned is when peerHTTPClient last warned that this node's
	// certificate is unusable (Unix seconds), so a round every 200 ms does
	// not repeat it.
	certWarned atomic.Int64
}

// NewManager creates a new cluster manager
// DefaultDataPath returns the directory holding cluster.json (~/.qpot/cluster).
// The CLI writes the membership there, and the web server and control plane
// must read it from the same place.
func DefaultDataPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".qpot", "cluster"), nil
}

func NewManager(dataPath string) *Manager {
	return &Manager{
		dataPath:     dataPath,
		stopCh:       make(chan struct{}),
		peerIntel:    make(map[string]*ThreatIntel),
		pendingJoins: make(map[string]*PendingJoin),
		joinOutcomes: make(map[string]*JoinOutcome),
	}
}

// schemeLocked returns "https" when the cluster config has TLS enabled
// AND both a cert and key path configured; otherwise "http". Caller must
// hold m.mu (read or write).
func (m *Manager) schemeLocked() string {
	if m.cluster == nil || m.cluster.Config == nil {
		return "http"
	}
	// Encryption on = HTTPS: with an operator certificate, or with the
	// automatic cluster-CA certificate when none is configured.
	if m.cluster.Config.EnableEncryption {
		return "https"
	}
	return "http"
}

// peerHTTPClient builds an HTTP client suitable for talking to other
// cluster members. When TLS is enabled it verifies peers by the cluster CA.
// A cluster that names an operator certificate (TLSCertPath) or a CA bundle
// (CACertPath) also accepts operator certificates, verified against that
// bundle or, without one, the system trust store - operators using
// self-signed certs should always set CACertPath to avoid mid-rotation
// verification failures. One that names neither runs on cluster-CA
// certificates alone and accepts nothing else.
func (m *Manager) peerHTTPClient(timeout time.Duration) *http.Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cluster == nil || m.cluster.Config == nil || !m.cluster.Config.EnableEncryption {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		return &http.Client{Timeout: timeout, Transport: transport}
	}
	var pool *x509.CertPool
	if caPath := m.cluster.Config.CACertPath; caPath != "" {
		caData, err := os.ReadFile(caPath)
		if err != nil {
			slog.Warn("Cluster TLS: failed to read CA cert; falling back to system roots",
				"path", caPath, "error", err)
		} else {
			pool = x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caData) {
				slog.Warn("Cluster TLS: CA cert file contained no PEM blocks", "path", caPath)
				pool = nil
			}
		}
	}
	operatorCerts := m.cluster.Config.TLSCertPath != "" || m.cluster.Config.CACertPath != "" ||
		m.cluster.Config.TrustOperatorCerts
	// The node certificate goes with every request: it is how peers know
	// which member is asking (see peerauth.go).
	var node *tls.Certificate
	if m.cluster.LocalNode != nil {
		if cert, err := nodeCertificate(m.cluster.ID, m.cluster.LocalNode.ID, m.cluster.NodeCertificate, m.cluster.NodeKey); err == nil {
			node = &cert
		} else if now := time.Now().Unix(); now-m.certWarned.Load() >= 600 {
			m.certWarned.Store(now)
			slog.Warn("Cluster TLS: this node's certificate is unusable; peers will refuse its requests", "error", err)
		}
	}
	return clusterPeerClient(timeout, m.cluster.ID, pool, operatorCerts, node)
}

// HTTPClient returns a client for talking to this cluster's API (e.g. the
// local node's, from the host-side approval commands), with the same peer
// verification the members use.
func (m *Manager) HTTPClient(timeout time.Duration) *http.Client { return m.peerHTTPClient(timeout) }

// APIScheme is "https" when the cluster encrypts, else "http".
func (m *Manager) APIScheme() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.schemeLocked()
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
	if len(password) > maxPasswordBytes {
		return nil, fmt.Errorf("password must be at most %d bytes", maxPasswordBytes)
	}

	caKey, clusterID, err := newClusterCA()
	if err != nil {
		return nil, fmt.Errorf("failed to make the cluster CA: %w", err)
	}

	if cfg == nil {
		cfg = DefaultClusterConfig()
	}

	// Hash the password
	passwordHash := hashPassword(password)
	memberKey, err := generateID("qk_", 64)
	if err != nil {
		return nil, fmt.Errorf("failed to generate member key: %w", err)
	}

	now := time.Now()
	cluster := &Cluster{
		Version:       ProtocolVersion,
		ID:            clusterID,
		Name:          name,
		PasswordHash:  passwordHash,
		MemberKey:     memberKey,
		CAKey:         caKey,
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
	key, csr, err := newNodeRequest()
	if err != nil {
		return nil, fmt.Errorf("failed to make the node key: %w", err)
	}
	cluster.NodeCertificate, err = issueNodeCertificate(caKey, localNodeID, csr)
	if err != nil {
		return nil, fmt.Errorf("failed to issue the node certificate: %w", err)
	}
	cluster.NodeKey = key

	// Do not activate signing credentials until the state file was saved.
	if err := m.installLocalCluster(cluster, password); err != nil {
		return nil, fmt.Errorf("failed to save cluster: %w", err)
	}

	slog.Info("Cluster initialized",
		"id", clusterID,
		"name", name,
		"password_protected", true)

	return cluster, nil
}

// JoinTrust says which seed certificates a joiner accepts. By default only a
// certificate from the cluster CA its cluster ID pins: the join request and
// the approval polls carry the cluster password and the poll secret, and the
// approval hands back the member key. The node certificate in the approval is
// checked against the cluster ID whatever certificate the seed serves.
type JoinTrust struct {
	// OperatorCerts also accepts a seed serving an operator certificate for
	// the address dialled, checked against CAFile or, without one, the
	// system roots. Only for clusters set up with operator certificates.
	OperatorCerts bool
	// CAFile is a PEM bundle operator certificates are checked against
	// (implies OperatorCerts).
	CAFile string
}

// JoinCluster joins an existing cluster with password authentication,
// trusting only the cluster CA the cluster ID names.
func (m *Manager) JoinCluster(clusterID, password string, localNode *Node, seedNodes []string) (*Cluster, error) {
	return m.JoinClusterTrusting(clusterID, password, localNode, seedNodes, JoinTrust{})
}

// JoinClusterTrusting is JoinCluster with the seed certificates trust allows.
func (m *Manager) JoinClusterTrusting(clusterID, password string, localNode *Node, seedNodes []string, trust JoinTrust) (*Cluster, error) {
	if clusterID == "" {
		return nil, fmt.Errorf("cluster ID is required")
	}
	if password == "" {
		return nil, fmt.Errorf("cluster password is required")
	}
	if len(password) > maxPasswordBytes {
		return nil, fmt.Errorf("password must be at most %d bytes", maxPasswordBytes)
	}
	if localNode == nil {
		return nil, fmt.Errorf("local node info is required")
	}
	if len(seedNodes) == 0 {
		return nil, fmt.Errorf("at least one seed node is required")
	}
	var pool *x509.CertPool
	if trust.CAFile != "" {
		trust.OperatorCerts = true
		data, err := os.ReadFile(trust.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA bundle: %w", err)
		}
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("CA bundle %s holds no PEM certificate", trust.CAFile)
		}
	}
	tlsClient := clusterHTTPClient(15*time.Second, clusterID, pool, trust.OperatorCerts)

	// Keep the caller's local identity unchanged if enrollment cannot be saved.
	originalNode := *localNode
	// Try to join via seed nodes
	var lastErr error
	for _, seed := range seedNodes {
		cluster, err := m.attemptJoin(seed, clusterID, password, localNode, tlsClient)
		if err == nil {
			// The config came from the seed: its bind address/port and
			// certificate paths describe THAT host. This node listens on its own
			// node port and uses the automatic cluster-CA certificate.
			if cluster.Config != nil {
				cluster.Config.BindAddr = "0.0.0.0"
				if localNode.Port > 0 {
					cluster.Config.BindPort = localNode.Port
				}
				cluster.Config.AdvertiseAddr = localNode.Address
				cluster.Config.TLSCertPath, cluster.Config.TLSKeyPath = "", ""
				// What this node trusts is its operator's choice, never the seed's.
				cluster.Config.CACertPath = trust.CAFile
				cluster.Config.TrustOperatorCerts = trust.OperatorCerts
			}
			if err := m.installLocalCluster(cluster, password); err != nil {
				*localNode = originalNode
				// This is a local failure, not a reason to enroll again through
				// another seed and create more unreachable member identities.
				return nil, fmt.Errorf("failed to save joined cluster identity; fix local storage and re-enroll: %w", err)
			}
			return cluster, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("failed to join cluster: %w", lastErr)
}

// attemptJoin tries to join a cluster via a specific seed node, over
// tlsClient when the seed speaks TLS.
func (m *Manager) attemptJoin(seedAddr, clusterID, password string, localNode *Node, tlsClient *http.Client) (*Cluster, error) {
	nodeKey, nodeCSR, err := newNodeRequest()
	if err != nil {
		return nil, fmt.Errorf("failed to make the node key: %w", err)
	}
	pollSecret, err := newPollSecret()
	if err != nil {
		return nil, err
	}
	joinReq := JoinRequest{
		Version:      ProtocolVersion,
		NodeCSR:      nodeCSR,
		PollSecret:   pollSecret,
		ClusterID:    clusterID,
		Password:     password,
		NodeName:     localNode.Name,
		NodeAddress:  localNode.Address,
		NodePort:     localNode.Port,
		InstanceName: localNode.InstanceName,
		Metadata:     localNode.Metadata,
		Capabilities: localNode.Capabilities,
	}

	reqBody, err := json.Marshal(joinReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal join request: %w", err)
	}

	// The seed address may name the scheme:
	//   https://1.2.3.4:7946 or 1.2.3.4:7946 -> TLS (the default: new clusters
	//     encrypt). The seed is verified against the cluster CA the cluster
	//     ID names (or, when JoinTrust allows it, an operator certificate),
	//     so the password is never sent to an impostor or in cleartext.
	//   http://1.2.3.4:7946 -> plain HTTP, only for clusters that turned
	//     encryption off.
	scheme := "https"
	host := seedAddr
	switch {
	case strings.HasPrefix(seedAddr, "https://"):
		host = strings.TrimPrefix(seedAddr, "https://")
	case strings.HasPrefix(seedAddr, "http://"):
		scheme = "http"
		host = strings.TrimPrefix(seedAddr, "http://")
	}
	url := fmt.Sprintf("%s://%s/api/v1/cluster/join", scheme, host)

	joinClient := &http.Client{Timeout: 15 * time.Second}
	if scheme == "https" {
		joinClient = tlsClient
	}
	resp, err := joinClient.Post(url, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to contact seed node: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxClusterBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var joinResp JoinResponse
	if err := json.Unmarshal(body, &joinResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if !joinResp.Success {
		// When the cluster requires host approval, the request was accepted and
		// queued rather than rejected: poll its status until the host approves
		// (we receive the membership), denies, or we time out.
		if joinResp.Status == "pending" && joinResp.RequestID != "" {
			slog.Info("Join request submitted; awaiting host approval",
				"request_id", joinResp.RequestID, "cluster_id", clusterID)
			approved, perr := m.pollJoinApproval(joinClient, scheme, host, password, joinResp.RequestID, pollSecret)
			if perr != nil {
				return nil, perr
			}
			joinResp = *approved
		} else {
			switch joinResp.ErrorCode {
			case "QP-CLUSTER-001", "QP-CLUSTER-002", "QP-CLUSTER-003", "QP-CLUSTER-004", "QP-CLUSTER-005":
				return nil, hostsetup.E(joinResp.ErrorCode)
			}
			return nil, fmt.Errorf("join rejected: %s", joinResp.Error)
		}
	}

	// The authority signs our public key; no CA or node private key crosses
	// the wire. Reject old seeds and substituted identities before saving.
	if joinResp.Version != ProtocolVersion {
		return nil, hostsetup.E("QP-CLUSTER-002").WithWhy("The seed uses protocol %d; all nodes must update to protocol %d.", joinResp.Version, ProtocolVersion)
	}
	if _, err := nodeCertificate(clusterID, joinResp.NodeID, joinResp.NodeCertificate, nodeKey); err != nil {
		return nil, fmt.Errorf("join: the seed sent no valid node certificate for cluster %s: %w", clusterID, err)
	}
	if err := checkMemberKey(joinResp.MemberKey); err != nil {
		return nil, err
	}

	// Create local cluster state
	now := time.Now()
	localNode.ID = joinResp.NodeID
	localNode.JoinedAt = now
	localNode.LastSeen = now
	localNode.Status = NodeStatusHealthy

	cluster := &Cluster{
		Version:         ProtocolVersion,
		ID:              clusterID,
		Name:            joinResp.ClusterName,
		PasswordHash:    hashPassword(password), // bcrypt hash for local verification
		MemberKey:       joinResp.MemberKey,
		NodeKey:         nodeKey,
		NodeCertificate: joinResp.NodeCertificate,
		CreatedAt:       now,
		UpdatedAt:       now,
		LocalNode:       localNode,
		Nodes:           make(map[string]*Node),
		// The seed's Config is untrusted wire input: a nil or out-of-range
		// value would panic time.NewTicker in Start or overflow the
		// failure-detection deadline in gossip(). Clamp it.
		Config:        sanitizeClusterConfig(joinResp.Config),
		isInitialized: true,
	}

	// Add all nodes from the seed's response. The seed is untrusted wire input
	// (a compromised seed, or a MITM on a plain-HTTP join): a JSON null decodes
	// to a nil *Node and would nil-deref on node.ID, and an empty-ID/blank-addr
	// node would pollute the membership map. Screen every entry through
	// validPeerNode (which also nil-checks), exactly as the gossip path does.
	for _, node := range joinResp.Nodes {
		if !validPeerNode(node) {
			continue
		}
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

// pollJoinApproval polls a pending join's status endpoint until the host
// approves it (returning the full JoinResponse the joiner needs), denies it, or
// the overall timeout elapses. The poll is authenticated with the same cluster
// password the join used and carries the join's poll secret.
func (m *Manager) pollJoinApproval(client *http.Client, scheme, host, password, requestID, pollSecret string) (*JoinResponse, error) {
	url := fmt.Sprintf("%s://%s/api/v1/cluster/join/status?request_id=%s", scheme, host, requestID)

	pollInterval := m.joinPollInterval
	if pollInterval <= 0 {
		pollInterval = 3 * time.Second
	}
	pollTimeout := m.joinPollTimeout
	if pollTimeout <= 0 {
		pollTimeout = 5 * time.Minute
	}
	deadline := time.Now().Add(pollTimeout)
	for time.Now().Before(deadline) {
		time.Sleep(pollInterval)
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("build status request: %w", err)
		}
		req.Header.Set("X-Cluster-Password", password)
		req.Header.Set(pollSecretHeader, pollSecret)
		resp, err := client.Do(req)
		if err != nil {
			continue // transient; keep polling until the deadline
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxClusterBodyBytes))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		var out JoinResponse
		if err := json.Unmarshal(body, &out); err != nil {
			continue
		}
		switch {
		case out.Success && out.NodeID != "":
			return &out, nil // approved
		case out.Status == "denied":
			return nil, fmt.Errorf("join request was denied by the cluster host")
		}
		// still pending -> keep polling
	}
	return nil, fmt.Errorf("timed out waiting for host approval of join request %s", requestID)
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
	if err := checkClusterVersion(m.cluster.Version); err != nil {
		return err
	}
	if err := checkMemberKey(m.cluster.MemberKey); err != nil {
		return err
	}
	if m.cluster.LocalNode == nil {
		return fmt.Errorf("local node not initialized")
	}
	if err := m.renewAuthorityCertificateLocked(); err != nil {
		return identityFailure(err)
	}
	if _, err := nodeCertificate(m.cluster.ID, m.cluster.LocalNode.ID, m.cluster.NodeCertificate, m.cluster.NodeKey); err != nil {
		return err
	}
	if m.cluster.CAKey != "" {
		if err := checkClusterCA(m.cluster.ID, m.cluster.CAKey); err != nil {
			return identityFailure(err)
		}
	}
	// Members prove which node they are with their certificate in the TLS
	// handshake; without TLS no request could say which member sent it.
	if !m.cluster.Config.EnableEncryption {
		return hostsetup.E("QP-CLUSTER-010")
	}

	// Only the bcrypt hash is persisted, so a manager restored by LoadCluster
	// has no plaintext password. Gossiping without it sends an empty
	// X-Cluster-Password, every peer answers 401 and gets marked failed.
	if m.plainPassword == "" {
		return fmt.Errorf("cluster password not set (call UnlockPassword after LoadCluster)")
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

	go m.gossipLoop(m.stopCh, m.gossipTicker.C)
	go m.syncLoop(m.stopCh, m.syncTicker.C)

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

	// Saved while still marked running: a cluster.json removed by `qpot
	// cluster leave` in another process is not written again.
	if err := m.saveClusterLocked(); err != nil {
		slog.Warn("Failed to persist cluster state on stop", "error", err)
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
		IsRunning: m.cluster.isRunning,
	}

	var totalEvents int64
	for _, node := range m.cluster.Nodes {
		if node.Status == NodeStatusLeft {
			continue
		}
		status.NodeCount++
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

	// Nodes that left are kept only to stop them coming back (see
	// mergeDigestLocked); they are not members.
	nodes := m.snapshotNodesLocked()
	members := nodes[:0]
	for _, n := range nodes {
		if n.Status != NodeStatusLeft {
			members = append(members, n)
		}
	}
	return members
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

// secretFile holds the cluster password (0600) so the long-running QPot control
// plane can rejoin gossip after a restart; cluster.json only keeps its bcrypt
// hash. It has the same protection as the instance's qpot.id credential.
const secretFile = "cluster.secret"

// ClusterPasswordEnv, when set, supplies the cluster password instead of the
// secret file (for deployments that keep secrets out of the filesystem).
const ClusterPasswordEnv = "QPOT_CLUSTER_PASSWORD"

// SaveSecret stores the in-memory cluster password in the 0600 secret file.
func (m *Manager) SaveSecret() error {
	m.mu.RLock()
	pw := m.plainPassword
	m.mu.RUnlock()
	if pw == "" {
		return fmt.Errorf("no cluster password to save")
	}
	if err := os.MkdirAll(m.dataPath, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(m.dataPath, secretFile), []byte(pw), 0o600)
}

// UnlockFromSecret unlocks a loaded cluster with the password from
// QPOT_CLUSTER_PASSWORD or, failing that, the secret file.
func (m *Manager) UnlockFromSecret() error {
	pw := os.Getenv(ClusterPasswordEnv)
	if pw == "" {
		data, err := os.ReadFile(filepath.Join(m.dataPath, secretFile))
		if err != nil {
			return fmt.Errorf("cluster password unavailable (set %s or re-run 'qpot cluster init/join'): %w", ClusterPasswordEnv, err)
		}
		pw = strings.TrimRight(string(data), "\r\n")
	}
	return m.UnlockPassword(pw)
}

// Password returns the cluster password held in memory after an unlock
// ("" while locked).
func (m *Manager) Password() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.plainPassword
}

// UnlockPassword checks password against the stored hash and, if it matches,
// keeps it in memory so a cluster restored by LoadCluster can authenticate to
// its peers.
func (m *Manager) UnlockPassword(password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cluster == nil {
		return fmt.Errorf("cluster not initialized")
	}
	if !checkPassword(password, m.cluster.PasswordHash) {
		return fmt.Errorf("invalid cluster password")
	}
	m.plainPassword = password
	return nil
}

// VerifyPassword verifies the cluster password. The check runs OUTSIDE the
// manager lock: bcrypt takes tens of milliseconds, and holding the lock for it
// let anyone with the (non-secret) cluster ID stall membership with a flood of
// wrong passwords.
func (m *Manager) VerifyPassword(password string) bool {
	m.mu.RLock()
	if m.cluster == nil {
		m.mu.RUnlock()
		return false
	}
	hash, plain := m.cluster.PasswordHash, m.plainPassword
	m.mu.RUnlock()
	return verifyClusterPassword(password, hash, plain)
}

// verifyClusterPassword compares against the in-memory password when this node
// has it (constant time, cheap, so wrong-password floods cost no CPU), else
// against the bcrypt hash.
func verifyClusterPassword(password, hash, plain string) bool {
	if plain != "" {
		return subtle.ConstantTimeCompare([]byte(password), []byte(plain)) == 1
	}
	return checkPassword(password, hash)
}

// HandleJoinRequest handles a join request from another node. sourceIP is the
// authoritative peer address taken from the HTTP connection (not trusted from
// the request body), recorded so the host sees who actually connected.
func (m *Manager) HandleJoinRequest(req *JoinRequest, sourceIP string) *JoinResponse {
	// Authenticate WITHOUT holding the lock (see VerifyPassword), then take the
	// write lock only to change membership.
	m.mu.RLock()
	if m.cluster == nil {
		m.mu.RUnlock()
		return &JoinResponse{
			Success: false,
			Error:   "cluster not initialized",
		}
	}
	clusterID, hash, plain := m.cluster.ID, m.cluster.PasswordHash, m.plainPassword
	m.mu.RUnlock()

	trusted := m.isMemberAddress(sourceIP)
	src, now := authKey(sourceIP, trusted), time.Now()
	if m.authLimit.blocked(src, now, trusted) {
		return &JoinResponse{Success: false, Error: errTooManyAttempts}
	}

	// Verify cluster ID
	if req.ClusterID != clusterID {
		m.authLimit.failed(src, now, trusted)
		return &JoinResponse{
			Success: false,
			Error:   "invalid cluster ID",
		}
	}

	if !verifyClusterPassword(req.Password, hash, plain) {
		m.authLimit.failed(src, now, trusted)
		slog.Warn("Join attempt with invalid password",
			"cluster_id", req.ClusterID,
			"from", sourceIP)
		return &JoinResponse{
			Success: false,
			Error:   "invalid password",
		}
	}

	// The address and port become every member's request URL for this node.
	if !validPeerAddress(req.NodeAddress) || req.NodePort < 1 || req.NodePort > 65535 {
		return &JoinResponse{Success: false, Error: "invalid node address or port"}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	// The cluster may have been left/replaced while we verified.
	if m.cluster == nil || m.cluster.ID != clusterID {
		return &JoinResponse{Success: false, Error: "cluster not initialized"}
	}
	if err := checkClusterVersion(m.cluster.Version); err != nil {
		return joinFailure(err)
	}
	if req.Version != ProtocolVersion {
		return joinFailure(hostsetup.E("QP-CLUSTER-002").WithWhy("Unsupported cluster protocol version %d; update the joining QPot to protocol %d.", req.Version, ProtocolVersion))
	}
	if m.cluster.NodeCertificate == "" || m.cluster.NodeKey == "" {
		return joinFailure(errOldClusterFormat)
	}
	if err := checkMemberKey(m.cluster.MemberKey); err != nil {
		return joinFailure(err)
	}
	if m.cluster.CAKey == "" {
		return joinFailure(hostsetup.E("QP-CLUSTER-004").WithWhy("This node is not the enrollment authority; use the host that initialized or upgraded the cluster as the seed."))
	}
	if _, err := parseNodeRequest(req.NodeCSR); err != nil {
		return joinFailure(err)
	}

	// When the cluster requires host approval, the correct password is not
	// enough: queue the request for the host to review (with the real source IP
	// and the claimed hostname) and tell the joiner to await approval.
	if m.cluster.Config != nil && m.cluster.Config.RequireApproval {
		return m.queuePendingJoinLocked(req, sourceIP)
	}

	// Approval not required: admit immediately.
	resp, err := m.admitNodeLocked(req)
	if err != nil {
		return joinFailure(err)
	}
	return resp
}

// admitNodeLocked creates a node from a join request, adds it to the cluster,
// and returns a success response with the full node list. Caller must hold m.mu.
func (m *Manager) admitNodeLocked(req *JoinRequest) (*JoinResponse, error) {
	// The same bound gossip keeps: a full cluster admits no one, open or
	// host-approved, so a password holder cannot grow it without limit.
	if m.memberCountLocked() >= maxClusterNodes {
		return nil, fmt.Errorf("cluster is full (%d members)", maxClusterNodes)
	}
	if err := checkMemberKey(m.cluster.MemberKey); err != nil {
		return nil, err
	}
	if m.cluster.CAKey == "" {
		return nil, hostsetup.E("QP-CLUSTER-004")
	}
	if err := checkClusterCA(m.cluster.ID, m.cluster.CAKey); err != nil {
		return nil, err
	}
	nodeID, err := generateNodeID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate node ID")
	}
	certificate, err := issueNodeCertificate(m.cluster.CAKey, nodeID, req.NodeCSR)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	node := &Node{
		ID:           nodeID,
		Name:         req.NodeName,
		Address:      req.NodeAddress,
		Port:         req.NodePort,
		InstanceName: req.InstanceName,
		Status:       NodeStatusHealthy,
		LastSeen:     now,
		JoinedAt:     now,
		Metadata:     req.Metadata,
		Capabilities: req.Capabilities,
	}

	previousUpdated := m.cluster.UpdatedAt
	m.cluster.Nodes[nodeID] = node
	m.cluster.UpdatedAt = now
	if err := m.saveClusterLocked(); err != nil {
		delete(m.cluster.Nodes, nodeID)
		m.cluster.UpdatedAt = previousUpdated
		return nil, fmt.Errorf("failed to persist cluster membership: %w", err)
	}

	nodes := m.snapshotNodesLocked()

	slog.Info("Node joined cluster",
		"node_id", nodeID,
		"node_name", req.NodeName,
		"node_address", req.NodeAddress,
		"total_nodes", len(m.cluster.Nodes))

	return &JoinResponse{
		Version:         ProtocolVersion,
		Success:         true,
		Status:          "approved",
		NodeID:          nodeID,
		ClusterName:     m.cluster.Name,
		Nodes:           nodes,
		Config:          m.cluster.Config,
		MemberKey:       m.cluster.MemberKey,
		NodeCertificate: certificate,
	}, nil
}

// withClusterAuth returns a handler that verifies X-Cluster-Password before
// calling next. Used for mutation endpoints (leave, gossip, intel) to prevent
// unauthenticated nodes from disrupting the cluster.
func (m *Manager) withClusterAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		trusted := fromThisHost(r) || m.isMemberAddress(r.RemoteAddr)
		src, now := authKey(r.RemoteAddr, trusted), time.Now()
		if m.authLimit.blocked(src, now, trusted) {
			http.Error(w, "Too many failed attempts", http.StatusTooManyRequests)
			return
		}
		password := r.Header.Get("X-Cluster-Password")
		if password == "" || !m.VerifyPassword(password) {
			m.authLimit.failed(src, now, trusted)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// withMemberAuth guards the peer endpoints: the password (withClusterAuth),
// the member key only admitted nodes hold, and the sender's own node
// certificate, which names the member asking; that node must still be a
// member (see peerauth.go). The handler gets its ID from peerNode. Missing
// credentials fail closed; legacy clusters must upgrade their trust rather
// than use password-only peers.
func (m *Manager) withMemberAuth(next http.HandlerFunc) http.HandlerFunc {
	return m.withClusterAuth(func(w http.ResponseWriter, r *http.Request) {
		if key := m.memberKey(); key == "" ||
			subtle.ConstantTimeCompare([]byte(r.Header.Get(memberKeyHeader)), []byte(key)) != 1 {
			trusted := fromThisHost(r) || m.isMemberAddress(r.RemoteAddr)
			m.authLimit.failed(authKey(r.RemoteAddr, trusted), time.Now(), trusted)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Header.Get(clusterVersionHeader) != strconv.Itoa(ProtocolVersion) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUpgradeRequired)
			json.NewEncoder(w).Encode(joinFailure(hostsetup.E("QP-CLUSTER-002")))
			return
		}
		// Not counted as a password failure: the password and member key
		// were right, and a node refused here (one that left, or one a peer
		// has not heard of yet) must not get its address blocked for the
		// members that share it.
		id, err := m.authenticatePeer(r)
		switch {
		case errors.Is(err, errNotAMember):
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		case err != nil:
			http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}
		next(w, withPeerNode(r, id))
	})
}

// setPeerAuth adds the credentials of a request to another member.
func setPeerAuth(req *http.Request, password, memberKey string) {
	req.Header.Set(clusterVersionHeader, strconv.Itoa(ProtocolVersion))
	if password != "" {
		req.Header.Set("X-Cluster-Password", password)
	}
	if memberKey != "" {
		req.Header.Set(memberKeyHeader, memberKey)
	}
}

func checkMemberKey(key string) error {
	if key == "" {
		return hostsetup.E("QP-CLUSTER-005").WithWhy("The cluster membership credential is missing; restore trusted state or re-enroll this node.")
	}
	return nil
}

// memberKey returns the cluster's member key ("" for older clusters).
func (m *Manager) memberKey() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cluster == nil {
		return ""
	}
	return m.cluster.MemberKey
}

// withHostOnly restricts a handler to callers on this host. Approving or
// denying joiners is the host operator's decision, but every joiner holds the
// cluster password too (it must send it to /join), so the password alone
// cannot gate these endpoints: a pending joiner could approve itself. The CLI
// (`qpot cluster requests/approve/deny`) always connects over loopback.
func withHostOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !fromThisHost(r) {
			http.Error(w, "Forbidden: host operation", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// withHostIdentity guards the host operations (join approval, removal): the
// request must come from this host (withHostOnly), carry the password, and
// present this node's own certificate, which only a process that can read
// this node's private cluster state holds - the CLI of its operator. A member
// or a pending joiner on the same machine knows the password too, but not
// this node's key.
func (m *Manager) withHostIdentity(next http.HandlerFunc) http.HandlerFunc {
	return withHostOnly(m.withClusterAuth(func(w http.ResponseWriter, r *http.Request) {
		if !m.fromLocalNode(r) {
			http.Error(w, "Forbidden: a host operation must present this node's certificate", http.StatusForbidden)
			return
		}
		next(w, r)
	}))
}

// fromLocalNode reports whether r presented this node's own certificate.
func (m *Manager) fromLocalNode(r *http.Request) bool {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cluster == nil || m.cluster.LocalNode == nil {
		return false
	}
	id, err := verifyClusterClient(m.cluster.ID, r.TLS.PeerCertificates, time.Now())
	return err == nil && id == m.cluster.LocalNode.ID
}

// isMemberAddress reports whether addr (an address the request came from, the
// port optional) is exactly the address of one of the cluster's nodes, so the
// password throttle counts it as trusted (see authlimit.go): not the whole
// IPv6 /64, which a neighbour of the node may share.
func (m *Manager) isMemberAddress(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cluster == nil {
		return false
	}
	is := func(n *Node) bool {
		return n != nil && ip.Equal(net.ParseIP(n.Address))
	}
	if is(m.cluster.LocalNode) {
		return true
	}
	for _, n := range m.cluster.Nodes {
		if is(n) {
			return true
		}
	}
	return false
}

// fromThisHost reports whether r came from this machine: over loopback, or,
// for a cluster bound to one non-loopback address, from that same address
// (the CLI then has to dial it). A TCP connection whose peer address is our
// own address was opened here: a remote host cannot complete a handshake
// with a source address whose replies are delivered to us.
func fromThisHost(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if err != nil || ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return false
	}
	lhost, _, err := net.SplitHostPort(local.String())
	lip := net.ParseIP(lhost)
	return err == nil && lip != nil && !lip.IsUnspecified() && lip.Equal(ip)
}

// apiHandler builds the cluster API routes.
func (m *Manager) apiHandler() http.Handler {
	mux := http.NewServeMux()
	// join verifies the password internally via HandleJoinRequest.
	mux.HandleFunc("/api/v1/cluster/join", m.handleJoinHTTP)
	// Read-only endpoints are authenticated too: /nodes returns every node's
	// ID and address, and /status leaks the
	// cluster ID and topology that help an attacker target a join/password
	// brute-force. Nothing internal depends on them being public - the local
	// web UI and CLI read cluster state through in-process method calls, not
	// over HTTP. They and the mutation/peer endpoints are for admitted
	// members: the password alone, which every joiner has, is not enough.
	mux.HandleFunc("/api/v1/cluster/status", m.withMemberAuth(m.handleStatusHTTP))
	mux.HandleFunc("/api/v1/cluster/nodes", m.withMemberAuth(m.handleNodesHTTP))
	mux.HandleFunc("/api/v1/cluster/leave", m.withMemberAuth(m.handleLeaveHTTP))
	mux.HandleFunc("/api/v1/cluster/gossip", m.withMemberAuth(m.handleGossipHTTP))
	mux.HandleFunc("/api/v1/cluster/intel", m.withMemberAuth(m.handleIntelHTTP))
	// Join-approval endpoints. /pending, /approve and /deny are host operations
	// (require the password). /join/status lets a queued joiner - which already
	// proved the password on /join - poll its request; it is also password-gated
	// so an unauthenticated scanner cannot enumerate request IDs/outcomes, and
	// answers only the joiner's poll secret.
	mux.HandleFunc("/api/v1/cluster/pending", m.withHostIdentity(m.handlePendingHTTP))
	mux.HandleFunc("/api/v1/cluster/approve", m.withHostIdentity(m.handleApproveHTTP))
	mux.HandleFunc("/api/v1/cluster/deny", m.withHostIdentity(m.handleDenyHTTP))
	// Removing a node is the host operator's decision too (see RemoveNode).
	mux.HandleFunc("/api/v1/cluster/remove", m.withHostIdentity(m.handleRemoveHTTP))
	mux.HandleFunc("/api/v1/cluster/join/status", m.withClusterAuth(m.handleJoinStatusHTTP))
	return mux
}

// startAPIServer starts the cluster API server. The listener is opened here,
// synchronously, so a port that is already taken (another instance's control
// plane, or anything else) is reported to Start's caller instead of only being
// logged from a goroutine while the node carries on gossiping as if it served.
func (m *Manager) startAPIServer() error {
	mux := m.apiHandler()

	addr := fmt.Sprintf("%s:%d", m.cluster.Config.BindAddr, m.cluster.Config.BindPort)
	tlsEnabled := m.cluster.Config.EnableEncryption &&
		m.cluster.Config.TLSCertPath != "" &&
		m.cluster.Config.TLSKeyPath != ""
	autoTLS := m.cluster.Config.EnableEncryption && !tlsEnabled

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	if tlsEnabled {
		// Refuse to keep going with broken TLS rather than silently falling
		// back to plain HTTP (which would expose the cluster password header
		// in cleartext on the wire).
		if _, err := tls.LoadX509KeyPair(m.cluster.Config.TLSCertPath, m.cluster.Config.TLSKeyPath); err != nil {
			return fmt.Errorf("cluster TLS: failed to load cert/key pair: %w", err)
		}
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else if autoTLS {
		// No operator certificate: serve a node certificate signed by the
		// cluster's own CA (see autotls.go). Never fall back to plain HTTP,
		// which would expose the password header.
		cert, err := nodeCertificate(m.cluster.ID, m.cluster.LocalNode.ID, m.cluster.NodeCertificate, m.cluster.NodeKey)
		if err != nil {
			return fmt.Errorf("cluster TLS: %w", err)
		}
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	}
	if srv.TLSConfig != nil {
		// Ask every client for its node certificate. A joiner has none yet,
		// so the handshake does not require one; withMemberAuth checks it
		// for the peer endpoints. The handshake still makes a client that
		// sends one prove it holds the certificate's key.
		srv.TLSConfig.ClientAuth = tls.RequestClientCert
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("cluster API: %w", err)
	}
	m.apiServer = srv

	certPath := m.cluster.Config.TLSCertPath
	keyPath := m.cluster.Config.TLSKeyPath
	go func() {
		var err error
		if tlsEnabled {
			err = srv.ServeTLS(ln, certPath, keyPath)
		} else if autoTLS {
			err = srv.ServeTLS(ln, "", "")
		} else {
			err = srv.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Cluster API server error", "tls", tlsEnabled, "error", err)
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

	r.Body = http.MaxBytesReader(w, r.Body, maxClusterBodyBytes)
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

	// Use the connection's peer address as the authoritative source IP rather
	// than trusting NodeAddress from the (attacker-influenceable) body.
	sourceIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		sourceIP = host
	}

	resp := m.HandleJoinRequest(&req, sourceIP)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case resp.Success:
		// 200 OK
	case resp.Status == "pending":
		// Authenticated but awaiting host approval - not an auth failure.
		w.WriteHeader(http.StatusAccepted)
	case resp.Error == errTooManyAttempts:
		w.WriteHeader(http.StatusTooManyRequests)
	default:
		w.WriteHeader(http.StatusUnauthorized)
	}
	json.NewEncoder(w).Encode(resp)
}

// handlePendingHTTP lists the join requests awaiting approval (host view).
func (m *Manager) handlePendingHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(m.ListPendingJoins())
}

// handleApproveHTTP approves a pending join by request_id.
func (m *Manager) handleApproveHTTP(w http.ResponseWriter, r *http.Request) {
	m.handleJoinDecisionHTTP(w, r, true)
}

// handleDenyHTTP denies a pending join by request_id.
func (m *Manager) handleDenyHTTP(w http.ResponseWriter, r *http.Request) {
	m.handleJoinDecisionHTTP(w, r, false)
}

func (m *Manager) handleJoinDecisionHTTP(w http.ResponseWriter, r *http.Request, approve bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxClusterBodyBytes)
	var body struct {
		RequestID string `json:"request_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RequestID == "" {
		http.Error(w, "request_id required", http.StatusBadRequest)
		return
	}
	if approve {
		node, err := m.ApproveJoin(body.RequestID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(node)
		return
	}
	if err := m.DenyJoin(body.RequestID); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleJoinStatusHTTP lets a joiner poll the outcome of its pending request.
// The request ID is not a secret (it is logged and listed to the host), so the
// outcome goes only to a poll that carries the joiner's poll secret; any other
// caller gets the same answer as for an unknown ID, and counts as a failure.
func (m *Manager) handleJoinStatusHTTP(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("request_id")
	o, ok := m.joinOutcome(id)
	if !ok || !o.pollMatches(r.Header.Get(pollSecretHeader)) {
		trusted := fromThisHost(r) || m.isMemberAddress(r.RemoteAddr)
		m.authLimit.failed(authKey(r.RemoteAddr, trusted), time.Now(), trusted)
		http.Error(w, "unknown request_id", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// On approval, return the full JoinResponse the joiner needs to build its
	// local cluster state; otherwise just the status.
	if o.Status == "approved" && o.response != nil {
		json.NewEncoder(w).Encode(o.response)
		return
	}
	json.NewEncoder(w).Encode(JoinResponse{Status: o.Status})
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
	sender, ok := requirePeer(w, r)
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxClusterBodyBytes)
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

	// A node leaves by itself: the leave must name the node whose
	// certificate sent it. Removing another node is the enrollment host's
	// decision (RemoveNode).
	if req.NodeID != sender {
		slog.Warn("Refused a leave naming another node", "node_id", req.NodeID, "sender", sender, "source", r.RemoteAddr)
		http.Error(w, "a node's leave is taken only from the node itself", http.StatusForbidden)
		return
	}

	// The node is kept, marked left, and saved: deleted from memory only, it
	// came back from cluster.json at the next start, and a member that missed
	// the leave gossiped it straight back in.
	m.mu.Lock()
	if m.cluster != nil {
		if node, ok := m.cluster.Nodes[req.NodeID]; ok && node.Status != NodeStatusLeft {
			m.markLeftLocked(node, time.Now())
			delete(m.peerIntel, req.NodeID)
			if err := m.saveClusterLocked(); err != nil {
				slog.Warn("Failed to persist cluster membership", "error", err)
			}
			slog.Info("Node left cluster", "node_id", req.NodeID)
		}
	}
	m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// gossipLoop periodically gossips with other nodes. It is handed the stop
// channel and ticker of the Start that launched it: Start replaces the
// fields on a restart, and a loop re-reading them would keep running.
func (m *Manager) gossipLoop(stop <-chan struct{}, tick <-chan time.Time) {
	for {
		select {
		case <-stop:
			return
		case <-tick:
			m.gossip()
		}
	}
}

// syncLoop periodically syncs data with other nodes (see gossipLoop).
func (m *Manager) syncLoop(stop <-chan struct{}, tick <-chan time.Time) {
	for {
		select {
		case <-stop:
			return
		case <-tick:
			m.sync()
		}
	}
}

// gossip sends a heartbeat/state-digest to each known peer node and merges
// any updated node information returned in the response.
func (m *Manager) gossip() {
	if m.stopIfLeftElsewhere() {
		return
	}
	m.mu.RLock()
	if m.cluster == nil || m.cluster.LocalNode == nil {
		m.mu.RUnlock()
		return
	}

	localID := m.cluster.LocalNode.ID
	// Build a snapshot of current node states to share.
	digest := m.snapshotNodesLocked()
	revocations := m.revocationsLocked()

	// Collect peer addresses to contact (all nodes except ourselves).
	type peerInfo struct {
		id      string
		address string
		port    int
	}
	// A failed peer is tried again once per sync interval rather than every
	// round (an unreachable one costs the round its timeout): skipped for good,
	// as it was, any outage longer than the failure deadline split the cluster
	// permanently, since the status is saved and nothing else revives it.
	reprobe := m.cluster.Config.SyncInterval
	now := time.Now()
	var peers []peerInfo
	m.probeMu.Lock()
	for _, n := range m.cluster.Nodes {
		if n.ID == localID || n.Status == NodeStatusLeft {
			continue
		}
		if n.Status == NodeStatusFailed {
			if now.Sub(m.probedFailed[n.ID]) < reprobe {
				continue
			}
			if m.probedFailed == nil {
				m.probedFailed = make(map[string]time.Time)
			}
			m.probedFailed[n.ID] = now
		}
		peers = append(peers, peerInfo{id: n.ID, address: n.Address, port: n.Port})
	}
	for id := range m.probedFailed {
		if n := m.cluster.Nodes[id]; n == nil || n.Status != NodeStatusFailed {
			delete(m.probedFailed, id)
		}
	}
	m.probeMu.Unlock()
	m.mu.RUnlock()

	msg := GossipMessage{
		SenderID:    localID,
		Timestamp:   time.Now(),
		NodeDigest:  digest,
		Revocations: revocations,
	}

	body, err := json.Marshal(msg)
	if err != nil {
		slog.Error("Gossip: failed to marshal message", "error", err)
		return
	}

	m.mu.RLock()
	plainPwd := m.plainPassword
	scheme := m.schemeLocked()
	m.mu.RUnlock()
	memberKey := m.memberKey()

	gossipClient := m.peerHTTPClient(5 * time.Second)
	// Each round builds its own transport; close its pooled connections when
	// the round ends or every round leaves one idle TLS connection per peer.
	defer gossipClient.CloseIdleConnections()
	for _, peer := range peers {
		gossipURL := peerURL(scheme, peer.address, peer.port, "/api/v1/cluster/gossip")
		req, err := http.NewRequest(http.MethodPost, gossipURL, bytes.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		setPeerAuth(req, plainPwd, memberKey)
		resp, err := gossipClient.Do(req)
		if err != nil {
			slog.Debug("Gossip: peer unreachable", "node_id", peer.id, "error", err)
			m.markSuspect(peer.id)
			continue
		}

		// A non-200 (e.g. 401 auth failure, 5xx) is a failed contact, NOT a
		// success — previously the status was ignored and such a peer was still
		// marked healthy and its body merged.
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			slog.Debug("Gossip: peer returned non-OK", "node_id", peer.id, "status", resp.StatusCode)
			m.markSuspect(peer.id)
			continue
		}

		var peerMsg GossipMessage
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxClusterBodyBytes)).Decode(&peerMsg); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		// Merge peer's node knowledge into our own map.
		now := time.Now()
		m.mu.Lock()
		// Re-check after the unlocked network I/O: a concurrent LeaveCluster
		// can set m.cluster = nil.
		if m.cluster == nil {
			m.mu.Unlock()
			return
		}
		discovered := m.mergeDigestLocked(peerMsg.NodeDigest, localID, peer.id, now)
		if m.applyRevocationsLocked(peerMsg.Revocations, now) {
			discovered = true
		}
		// Mark the responding peer as healthy and update its last-seen time.
		if node, ok := m.cluster.Nodes[peer.id]; ok && node.Status != NodeStatusLeft {
			node.Status = NodeStatusHealthy
			node.LastSeen = now
		}
		// Persist once per message, not per node: a digest can carry
		// thousands of entries and each save serializes the whole cluster.
		if discovered {
			if err := m.saveClusterLocked(); err != nil {
				slog.Warn("Failed to persist cluster membership", "error", err)
			}
		}
		m.mu.Unlock()
	}

	// Mark nodes that haven't been seen for a long time as failed.
	m.mu.Lock()
	if m.cluster == nil { // concurrent LeaveCluster
		m.mu.Unlock()
		return
	}
	// Config is sanitized at the join/load boundary, so SuspicionMult and
	// GossipInterval are bounded and this product cannot overflow.
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

// markSuspect transitions a healthy node to suspect after a failed contact.
// Safe to call concurrently; a nil cluster (mid-leave) is a no-op.
func (m *Manager) markSuspect(nodeID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cluster == nil {
		return
	}
	if node, ok := m.cluster.Nodes[nodeID]; ok && node.Status == NodeStatusHealthy {
		node.Status = NodeStatusSuspect
	}
}

// validPeerNode reports whether a gossiped node record is usable: it must have
// an ID, a non-empty address, and a port in the valid range. This blocks
// fabricated records that would otherwise be stored and later interpolated into
// outbound request URLs (SSRF / wasted dials).
func validPeerNode(n *Node) bool {
	if n == nil || n.ID == "" || !validPeerAddress(n.Address) {
		return false
	}
	if n.Port < 1 || n.Port > 65535 {
		return false
	}
	return true
}

// leftRetention is how long a node that left is remembered as left (see
// mergeDigestLocked) before its record is dropped; at most maxLeftNodes such
// records are kept, the oldest dropped first. It is longer than a node
// certificate is valid: while the record lasts the node is refused, and once
// it is dropped any certificate the node kept has expired, so a member that
// missed the leave cannot bring it back with gossip.
const (
	leftRetention = nodeCertLifetime + 24*time.Hour
	maxLeftNodes  = maxClusterNodes
)

// mergeDigestLocked merges a peer's gossip digest into the member map and
// reports whether the map gained or changed a record to save. from is the
// node the digest came from when that is known: the peer this node dialled
// for a gossip round (a pushed digest's sender ID is only its own claim, so
// a push passes ""). Records that cannot yield a usable peer URL (nil,
// empty ID, bad address or port) are skipped, as is this node's own.
//
// A node that left stays left: its record is kept, so a member that missed
// the leave, or the node itself still running, cannot gossip it back in. Only
// the node itself marks itself left (its leave request, its own record in
// gossip it sends, or its own record when it answers this node's gossip
// round): a record from any other member would let it evict any node for
// leftRetention, and a left record of a node never seen creates nothing. A
// node the enrollment host removed is never discovered again. Caller holds
// m.mu.
func (m *Manager) mergeDigestLocked(digest []*Node, localID, from string, now time.Time) bool {
	members := m.memberCountLocked()
	changed := false
	for _, n := range digest {
		if !validPeerNode(n) || n.ID == localID {
			continue
		}
		existing, ok := m.cluster.Nodes[n.ID]
		switch {
		case !ok:
			if n.Status == NodeStatusLeft || members >= maxClusterNodes || m.revokedLocked(n.ID) {
				continue
			}
			m.cluster.Nodes[n.ID] = n
			members++
			changed = true
			slog.Info("Gossip: discovered node", "node_id", n.ID, "name", n.Name)
		case existing.Status == NodeStatusLeft:
			// Final until it is dropped.
		case n.Status == NodeStatusLeft:
			if n.ID == from {
				m.markLeftLocked(existing, now)
				members--
				changed = true
			}
		case n.LastSeen.After(existing.LastSeen):
			existing.Status = n.Status
			existing.LastSeen = n.LastSeen
			existing.Stats = n.Stats
		}
	}
	return changed
}

// memberCountLocked counts the nodes that have not left. Records of nodes
// that left are bounded on their own (pruneLeftLocked), so they never keep a
// node from being discovered or admitted. Caller holds m.mu.
func (m *Manager) memberCountLocked() int {
	n := 0
	for _, node := range m.cluster.Nodes {
		if node.Status != NodeStatusLeft {
			n++
		}
	}
	return n
}

// markLeftLocked records that node left, at now. Caller holds m.mu.
func (m *Manager) markLeftLocked(node *Node, now time.Time) {
	node.Status = NodeStatusLeft
	node.LastSeen = now
	m.pruneLeftLocked(now)
}

// pruneLeftLocked drops the records of nodes that left longer than
// leftRetention ago, then the oldest beyond maxLeftNodes. Caller holds m.mu.
func (m *Manager) pruneLeftLocked(now time.Time) {
	var left []*Node
	for id, n := range m.cluster.Nodes {
		if n.Status != NodeStatusLeft {
			continue
		}
		if now.Sub(n.LastSeen) > leftRetention {
			delete(m.cluster.Nodes, id)
			continue
		}
		left = append(left, n)
	}
	if len(left) <= maxLeftNodes {
		return
	}
	sort.Slice(left, func(i, j int) bool { return left[i].LastSeen.Before(left[j].LastSeen) })
	for _, n := range left[:len(left)-maxLeftNodes] {
		delete(m.cluster.Nodes, n.ID)
	}
}

// errLeftElsewhere: cluster.json was removed while this manager ran.
var errLeftElsewhere = errors.New("this node left the cluster (cluster.json was removed)")

// stopIfLeftElsewhere ends a running membership whose cluster.json is gone:
// `qpot cluster leave`, in another process, removed it after telling the
// peers. Gossiping on as the node that left put it back in their member
// lists, and saving wrote the file again, so the next start rejoined. It
// reports whether it stopped.
func (m *Manager) stopIfLeftElsewhere() bool {
	if _, err := os.Stat(filepath.Join(m.dataPath, "cluster.json")); !errors.Is(err, os.ErrNotExist) {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cluster == nil || !m.cluster.isRunning {
		return false
	}
	m.stopOnce.Do(func() { close(m.stopCh) })
	if m.gossipTicker != nil {
		m.gossipTicker.Stop()
	}
	if m.syncTicker != nil {
		m.syncTicker.Stop()
	}
	if m.apiServer != nil {
		_ = m.apiServer.Close()
	}
	m.cluster = nil
	m.plainPassword = ""
	slog.Warn("Cluster membership stopped", "reason", errLeftElsewhere)
	return true
}

// validPeerAddress reports whether a is a bare IP address or DNS host name.
// Peer addresses come from other nodes and end up in request URLs, so
// anything that could add a port, path, query or user info is refused.
func validPeerAddress(a string) bool {
	if a == "" || len(a) > 253 {
		return false
	}
	if net.ParseIP(a) != nil {
		return true
	}
	for _, label := range strings.Split(a, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// peerURL is the URL of a cluster API path on a peer. JoinHostPort brackets
// IPv6 addresses ("http://::1:7946" does not parse).
func peerURL(scheme, address string, port int, path string) string {
	return scheme + "://" + net.JoinHostPort(address, strconv.Itoa(port)) + path
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

	m.mu.RLock()
	syncPlainPwd := m.plainPassword
	syncScheme := m.schemeLocked()
	m.mu.RUnlock()
	syncMemberKey := m.memberKey()

	syncClient := m.peerHTTPClient(10 * time.Second)
	defer syncClient.CloseIdleConnections()

	// Share local intel with peers and collect theirs.
	if localIntel != nil {
		intelBody, err := json.Marshal(localIntel)
		if err == nil {
			for _, peer := range peers {
				intelURL := peerURL(syncScheme, peer.address, peer.port, "/api/v1/cluster/intel")
				intelReq, err := http.NewRequest(http.MethodPost, intelURL, bytes.NewReader(intelBody))
				if err != nil {
					continue
				}
				intelReq.Header.Set("Content-Type", "application/json")
				setPeerAuth(intelReq, syncPlainPwd, syncMemberKey)
				resp, err := syncClient.Do(intelReq)
				if err != nil {
					slog.Debug("Sync: failed to send intel to peer", "node_id", peer.id, "error", err)
					continue
				}

				var peerIntel ThreatIntel
				if err := json.NewDecoder(io.LimitReader(resp.Body, maxClusterBodyBytes)).Decode(&peerIntel); err != nil {
					resp.Body.Close()
					continue
				}
				resp.Body.Close()

				m.mu.Lock()
				if m.cluster == nil { // concurrent LeaveCluster while we did network I/O
					m.mu.Unlock()
					return
				}
				m.storePeerIntelLocked(&peerIntel)
				// Update event count for this peer node based on intel total.
				if node, ok := m.cluster.Nodes[peer.id]; ok {
					var total int64
					for _, ip := range peerIntel.TopSourceIPs {
						total += ip.Count
					}
					node.Stats.TotalEvents = total
					node.Stats.LastSync = time.Now()
				}
				m.mu.Unlock()
			}
		}
	}

	// Aggregate total event counts across all known nodes and log a summary.
	m.mu.RLock()
	if m.cluster == nil { // concurrent LeaveCluster
		m.mu.RUnlock()
		return
	}
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
// the local node's own state digest. The message must come from the node it
// names as its sender (see peerauth.go).
func (m *Manager) handleGossipHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sender, ok := requirePeer(w, r)
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxClusterBodyBytes)
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
	if incoming.SenderID != sender {
		http.Error(w, "gossip must name its own sender", http.StatusForbidden)
		return
	}

	now := time.Now()
	m.mu.Lock()
	if m.cluster != nil {
		// Merge the sender's node digest (see mergeDigestLocked): the sender
		// is authenticated, so its own record speaks for it.
		var localID string
		if m.cluster.LocalNode != nil {
			localID = m.cluster.LocalNode.ID
		}
		discovered := m.mergeDigestLocked(incoming.NodeDigest, localID, sender, now)
		if m.applyRevocationsLocked(incoming.Revocations, now) {
			discovered = true
		}
		// Update the sender's own record, unless it just said it left.
		if existing, ok := m.cluster.Nodes[sender]; ok && existing.Status != NodeStatusLeft {
			existing.Status = NodeStatusHealthy
			existing.LastSeen = now
		}
		if discovered { // once per message (see gossip)
			if err := m.saveClusterLocked(); err != nil {
				slog.Warn("Failed to persist cluster membership", "error", err)
			}
		}
	}

	// Build response with our own digest.
	digest := make([]*Node, 0)
	var revocations []Revocation
	var localID string
	if m.cluster != nil {
		digest = m.snapshotNodesLocked()
		revocations = m.revocationsLocked()
		if m.cluster.LocalNode != nil {
			localID = m.cluster.LocalNode.ID
		}
	}
	m.mu.Unlock()

	response := GossipMessage{
		SenderID:    localID,
		Timestamp:   now,
		NodeDigest:  digest,
		Revocations: revocations,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleIntelHTTP accepts threat intel from a peer node and responds with
// the local node's own intel. The intel must be the sending node's own.
func (m *Manager) handleIntelHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sender, ok := requirePeer(w, r)
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxClusterBodyBytes)
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
	if incoming.NodeID != sender {
		http.Error(w, "intel must be the sender's own", http.StatusForbidden)
		return
	}

	m.mu.Lock()
	m.storePeerIntelLocked(&incoming)
	localIntel := m.localIntel
	m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if localIntel != nil {
		json.NewEncoder(w).Encode(localIntel)
	} else {
		json.NewEncoder(w).Encode(&ThreatIntel{Timestamp: time.Now()})
	}
}

// storePeerIntelLocked keeps intel only for current members, so the map is
// bounded by the membership (maxClusterNodes) whatever node IDs peers send.
// Caller holds m.mu.
func (m *Manager) storePeerIntelLocked(intel *ThreatIntel) {
	if m.cluster == nil || intel.NodeID == "" {
		return
	}
	if _, member := m.cluster.Nodes[intel.NodeID]; !member {
		return
	}
	m.peerIntel[intel.NodeID] = intel
}

// saveCluster saves cluster configuration to disk.
func (m *Manager) saveCluster() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.saveClusterLocked()
}

// installLocalCluster publishes a new local identity only when its state file
// is saved. Holding the lock across both operations prevents Start or another
// save from observing an identity that failed to reach disk.
func (m *Manager) installLocalCluster(cluster *Cluster, password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	previous, previousPassword := m.cluster, m.plainPassword
	m.cluster, m.plainPassword = cluster, password
	if err := m.saveClusterLocked(); err != nil {
		m.cluster, m.plainPassword = previous, previousPassword
		return err
	}
	return nil
}

// saveClusterLocked writes cluster.json; the caller holds m.mu (read or
// write), so the snapshot is consistent. Membership changes (an admitted or
// gossip-discovered node) are persisted, so a restarted host still knows its
// members and `qpot cluster nodes` reads current state.
func (m *Manager) saveClusterLocked() error {
	if m.cluster == nil {
		return fmt.Errorf("no cluster to save")
	}

	clusterPath := filepath.Join(m.dataPath, "cluster.json")
	if m.cluster.isRunning {
		if _, err := os.Stat(clusterPath); errors.Is(err, os.ErrNotExist) {
			return errLeftElsewhere
		}
	}
	if err := os.MkdirAll(m.dataPath, 0750); err != nil {
		return err
	}

	data, err := json.MarshalIndent(m.cluster, "", "  ")
	if err != nil {
		return err
	}

	tmp := clusterPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, clusterPath)
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
	// An older node wrote the members' QPot IDs (web API credentials) into
	// the file; they were dropped when it was read. Rewrite it without them.
	scrub := bytes.Contains(data, []byte(`"qpot_id"`))

	// Clamp the persisted config: it may have been written by an older/buggy
	// version or tampered with on disk, and feeds tickers/deadlines.
	cluster.Config = sanitizeClusterConfig(cluster.Config)

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

	if scrub {
		if err := m.saveCluster(); err != nil {
			return nil, fmt.Errorf("remove the QPot IDs an older version stored: %w", err)
		}
	}
	return &cluster, nil
}

// LocalNodeID returns this node's ID in the cluster, "" when it is in none.
func (m *Manager) LocalNodeID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cluster == nil || m.cluster.LocalNode == nil {
		return ""
	}
	return m.cluster.LocalNode.ID
}

// UpgradeCluster prepares and validates a new trust root for a stopped legacy
// cluster, backs up the exact old state, then atomically activates the new state.
// The local instance, settings and event stores are not removed. Other members
// remain only in the backup and must update QPot and rejoin under the saved
// approval policy.
// The backup is recovery material, never an additional trusted CA.
func (m *Manager) UpgradeCluster() (result *Cluster, backupPath string, resultErr error) {
	defer func() {
		var coded *hostsetup.Error
		if resultErr != nil && !errors.As(resultErr, &coded) {
			resultErr = hostsetup.E("QP-CLUSTER-008").WithWhy("The upgrade could not be saved; the active cluster was not replaced. Check disk space and permissions.").Wrap(resultErr)
		}
	}()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cluster == nil || m.cluster.LocalNode == nil {
		return nil, "", hostsetup.E("QP-CLUSTER-006").WithWhy("No local cluster is available to upgrade.")
	}
	if m.cluster.isRunning {
		return nil, "", hostsetup.E("QP-CLUSTER-006").WithWhy("Stop the QPot control plane before upgrading the cluster.")
	}
	if m.cluster.Version >= ProtocolVersion {
		return nil, "", hostsetup.E("QP-CLUSTER-006").WithWhy("Cluster protocol %d is not a supported legacy upgrade.", m.cluster.Version)
	}
	if m.plainPassword == "" || !checkPassword(m.plainPassword, m.cluster.PasswordHash) {
		return nil, "", hostsetup.E("QP-CLUSTER-006").WithWhy("Unlock the cluster password before upgrading.")
	}
	// Reserve the configured listener for the whole transaction. This also
	// catches a separately running control plane loaded by the CLI from disk.
	cfg := m.cluster.Config
	if cfg == nil || cfg.BindPort < 1 || cfg.BindPort > 65535 {
		return nil, "", hostsetup.E("QP-CLUSTER-006").WithWhy("The saved cluster has no valid listening port.")
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(cfg.BindAddr, strconv.Itoa(cfg.BindPort)))
	if err != nil {
		return nil, "", hostsetup.E("QP-CLUSTER-006").WithWhy("Stop the QPot control plane and free its cluster port before upgrading.").Wrap(err)
	}
	defer ln.Close()
	lockPath := filepath.Join(m.dataPath, "cluster.upgrade.lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, "", hostsetup.E("QP-CLUSTER-006").WithWhy("Another upgrade may be active; inspect %s before retrying.", lockPath).Wrap(err)
	}
	lock.Close()
	defer os.Remove(lockPath)
	path := filepath.Join(m.dataPath, "cluster.json")
	oldData, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	var next Cluster
	if err := json.Unmarshal(oldData, &next); err != nil {
		return nil, "", err
	}
	if next.ID != m.cluster.ID || next.Version != m.cluster.Version || next.LocalNode == nil ||
		!checkPassword(m.plainPassword, next.PasswordHash) {
		return nil, "", hostsetup.E("QP-CLUSTER-007").WithWhy("The saved cluster changed; reload it before upgrading.")
	}
	next.Config = sanitizeClusterConfig(next.Config)
	if *next.Config != *cfg {
		return nil, "", hostsetup.E("QP-CLUSTER-007").WithWhy("The saved cluster configuration changed; reload it before upgrading.")
	}
	next.Version = ProtocolVersion
	next.CAKey, next.ID, err = newClusterCA()
	if err != nil {
		return nil, "", err
	}
	next.MemberKey, err = generateID("qk_", 64)
	if err != nil {
		return nil, "", err
	}
	var csr string
	next.NodeKey, csr, err = newNodeRequest()
	if err != nil {
		return nil, "", err
	}
	next.NodeCertificate, err = issueNodeCertificate(next.CAKey, next.LocalNode.ID, csr)
	if err != nil {
		return nil, "", err
	}
	if _, err := nodeCertificate(next.ID, next.LocalNode.ID, next.NodeCertificate, next.NodeKey); err != nil {
		return nil, "", fmt.Errorf("validate upgraded node identity: %w", err)
	}
	if next.Config.EnableEncryption && (next.Config.TLSCertPath != "" || next.Config.TLSKeyPath != "") {
		if _, err := tls.LoadX509KeyPair(next.Config.TLSCertPath, next.Config.TLSKeyPath); err != nil {
			return nil, "", hostsetup.E("QP-CLUSTER-006").WithWhy("The configured operator TLS certificate/key cannot be loaded; fix it before upgrading.").Wrap(err)
		}
	}
	next.Nodes = map[string]*Node{next.LocalNode.ID: next.LocalNode}
	next.UpdatedAt = time.Now()
	next.isInitialized = true
	newData, err := json.MarshalIndent(&next, "", "  ")
	if err != nil {
		return nil, "", err
	}
	// Unique 0600 files prevent concurrent temporary-file collisions. Sync
	// both before activation: a failure or interrupted preparation leaves the
	// original cluster.json untouched and never partially installs new trust.
	backup, err := os.CreateTemp(m.dataPath, "cluster.legacy-*.json")
	if err != nil {
		return nil, "", err
	}
	backupPath = backup.Name()
	write := m.upgradeWrite
	if write == nil {
		write = writeUpgradeFile
	}
	if err := write(backup, oldData); err != nil {
		os.Remove(backupPath)
		return nil, "", fmt.Errorf("back up old cluster: %w", err)
	}
	staged, err := os.CreateTemp(m.dataPath, "cluster.upgrade-*.tmp")
	if err != nil {
		return nil, backupPath, err
	}
	defer os.Remove(staged.Name())
	if err := write(staged, newData); err != nil {
		return nil, backupPath, fmt.Errorf("stage upgraded cluster: %w", err)
	}
	syncDirectory := m.upgradeSyncDirectory
	if syncDirectory == nil {
		syncDirectory = syncUpgradeDirectory
	}
	if err := syncDirectory(m.dataPath); err != nil {
		return nil, backupPath, fmt.Errorf("sync upgrade backup and staging directory: %w", err)
	}
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(current, oldData) {
		return nil, backupPath, hostsetup.E("QP-CLUSTER-007").WithWhy("The saved cluster changed during upgrade; the upgrade did not replace it.")
	}
	activate := m.upgradeActivate
	if activate == nil {
		activate = os.Rename
	}
	if err := activate(staged.Name(), path); err != nil {
		return nil, backupPath, fmt.Errorf("activate upgraded cluster; original state is unchanged: %w", err)
	}
	m.cluster = &next
	m.pendingJoins = make(map[string]*PendingJoin)
	m.joinOutcomes = make(map[string]*JoinOutcome)
	m.peerIntel = make(map[string]*ThreatIntel)
	if err := syncDirectory(m.dataPath); err != nil {
		// The rename committed. Never claim rollback or restore old signing
		// credentials merely because durability could not be confirmed.
		return m.cluster, backupPath, hostsetup.E("QP-CLUSTER-009").Wrap(err)
	}
	return m.cluster, backupPath, nil
}

func writeUpgradeFile(file *os.File, data []byte) error {
	n, err := file.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	return err
}

func syncUpgradeDirectory(path string) error {
	// Windows does not support fsync on a directory handle through os.File.
	// The replacement still uses os.Rename and individually synced files.
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// LeaveCluster removes this node from the cluster.
//
// Implementation note: we used to hold m.mu (write lock) for the entire
// duration of the leave-notification fan-out, which meant a single dead
// peer could block every other Manager method for up to 3 s × N peers.
// Take a snapshot of the data we need under the lock, release it, do the
// network I/O, then take the lock again to mutate state.
func (m *Manager) LeaveCluster() error {
	// A manager restored by LoadCluster (the CLI) only has the bcrypt hash; the
	// peers need the plaintext password, so unlock from the stored secret first.
	m.mu.RLock()
	locked := m.cluster != nil && m.plainPassword == ""
	m.mu.RUnlock()
	if locked {
		if err := m.UnlockFromSecret(); err != nil {
			return fmt.Errorf("cannot notify peers: %w", err)
		}
	}

	m.mu.RLock()
	if m.cluster == nil {
		m.mu.RUnlock()
		return fmt.Errorf("not in a cluster")
	}
	if m.cluster.LocalNode == nil {
		m.mu.RUnlock()
		return fmt.Errorf("local node not initialized")
	}
	localNodeID := m.cluster.LocalNode.ID
	type peerInfo struct {
		id      string
		address string
		port    int
	}
	peers := make([]peerInfo, 0, len(m.cluster.Nodes))
	for _, node := range m.cluster.Nodes {
		if node.ID == localNodeID {
			continue
		}
		peers = append(peers, peerInfo{id: node.ID, address: node.Address, port: node.Port})
	}
	plainPwd := m.plainPassword
	leaveMemberKey := m.cluster.MemberKey
	leaveScheme := m.schemeLocked()
	m.mu.RUnlock()

	// Notify other nodes with a short timeout so a dead peer doesn't block.
	leaveClient := m.peerHTTPClient(3 * time.Second)
	defer leaveClient.CloseIdleConnections()
	var unreached []string
	leaveBody, err := json.Marshal(map[string]string{"node_id": localNodeID})
	if err != nil {
		return fmt.Errorf("marshal leave body: %w", err)
	}
	for _, peer := range peers {
		url := peerURL(leaveScheme, peer.address, peer.port, "/api/v1/cluster/leave")
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(leaveBody))
		if err != nil {
			slog.Debug("LeaveCluster: build request failed", "node_id", peer.id, "error", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		// The /leave endpoint is authenticated; without these headers peers
		// reject the notification and silently keep the node in their member
		// list as 'suspect'.
		setPeerAuth(req, plainPwd, leaveMemberKey)
		resp, err := leaveClient.Do(req)
		if err != nil {
			slog.Debug("LeaveCluster: failed to notify peer", "node_id", peer.id, "error", err)
			unreached = append(unreached, fmt.Sprintf("%s:%d (%v)", peer.address, peer.port, err))
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			unreached = append(unreached, fmt.Sprintf("%s:%d (%s)", peer.address, peer.port, resp.Status))
		}
	}

	clusterPath := filepath.Join(m.dataPath, "cluster.json")
	if err := os.Remove(clusterPath); err != nil && !os.IsNotExist(err) {
		slog.Warn("LeaveCluster: failed to remove cluster file", "path", clusterPath, "error", err)
	}
	if err := os.Remove(filepath.Join(m.dataPath, secretFile)); err != nil && !os.IsNotExist(err) {
		slog.Warn("LeaveCluster: failed to remove cluster secret", "error", err)
	}

	m.mu.Lock()
	m.cluster = nil
	m.plainPassword = ""
	m.mu.Unlock()
	slog.Info("Left cluster")
	if len(unreached) > 0 {
		return fmt.Errorf("left the cluster locally, but %d of %d peers were not notified and will mark this node failed: %s",
			len(unreached), len(peers), strings.Join(unreached, "; "))
	}
	return nil
}

// Utility functions

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

// maxPasswordBytes is bcrypt's input limit. A longer password cannot be
// hashed, so a cluster created with one could never be unlocked again.
const maxPasswordBytes = 72

// hashPassword hashes a password using bcrypt with a random salt.
// On a bcrypt failure (only realistically possible if the password is
// longer than 72 bytes — bcrypt's hard limit) we log the error and return
// the literal "invalid", which is not a valid bcrypt hash and will
// therefore reject every subsequent password check. Without the log line
// these failures were impossible to diagnose.
func hashPassword(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("Failed to bcrypt cluster password (length limit exceeded?)",
			"password_len", len(password), "error", err)
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
