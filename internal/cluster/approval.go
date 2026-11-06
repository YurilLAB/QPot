package cluster

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log/slog"
	"sort"
	"time"
)

// approval.go implements host-approved cluster joins. When a cluster has
// RequireApproval set, a node that presents the correct password is NOT admitted
// immediately: the request is queued for the host, who sees every pending
// request (with the requester's real source IP and claimed hostname) and
// explicitly approves or denies it. The joiner polls the request's status until
// it is approved (and receives the membership) or denied.

// Join queue bounds. Anyone with the cluster password can file join
// requests, so the queue and the decision records are capped, and both expire
// after joinRequestTTL: a joiner stops polling after five minutes. One source
// address (an IPv6 /64 counts as one) holds at most maxPendingPerSource of the
// queue, so a single password holder cannot fill it and lock other joiners out.
const (
	maxPendingJoins     = 256
	maxPendingPerSource = 4
	maxJoinOutcomes     = 1024
	joinRequestTTL      = 10 * time.Minute
)

// A join's poll secret (JoinRequest.PollSecret) is sent in pollSecretHeader on
// every status poll. The joiner makes 32 random bytes; the host takes a secret
// of minPollSecret to maxPollSecret characters.
const (
	pollSecretHeader = "X-Join-Secret"
	minPollSecret    = 32
	maxPollSecret    = 128
)

// errNoPollSecret refuses a join that would wait for approval without a poll
// secret: its outcome could only be collected by request ID and password.
const errNoPollSecret = "join request without a poll secret: the joining QPot is older than this cluster, update it"

// newPollSecret makes a join's poll secret.
func newPollSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("make join poll secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// PendingJoin is a password-authenticated join request awaiting host approval.
type PendingJoin struct {
	RequestID string `json:"request_id"`
	NodeName  string `json:"node_name"`
	// ClaimedAddress is the address the requester put in its join request.
	ClaimedAddress string `json:"claimed_address"`
	// SourceIP is the peer address of the actual TCP connection (authoritative,
	// taken from the HTTP layer - not trusted from the request body).
	SourceIP     string            `json:"source_ip"`
	NodePort     int               `json:"node_port"`
	QPotID       string            `json:"qpot_id"`
	InstanceName string            `json:"instance_name"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty"`
	RequestedAt  time.Time         `json:"requested_at"`

	// req is the original request (without its poll secret), retained so an
	// approval can build the node.
	req *JoinRequest
	// pollHash is the SHA-256 of the joiner's poll secret.
	pollHash [sha256.Size]byte
}

// JoinOutcome records the host's decision on a pending join so the joiner can
// poll for it. Exactly one of approved/denied is meaningful once Decided.
type JoinOutcome struct {
	RequestID string    `json:"request_id"`
	Status    string    `json:"status"` // "pending", "approved", "denied"
	DecidedAt time.Time `json:"decided_at,omitempty"`
	// response is the full approved JoinResponse the joiner needs (node id,
	// member list, config). Only set when Status == "approved".
	response *JoinResponse
	// pollHash is the SHA-256 of the joiner's poll secret: only a poll with
	// that secret receives the outcome.
	pollHash [sha256.Size]byte
}

// pollMatches reports whether secret is the joiner's poll secret.
func (o *JoinOutcome) pollMatches(secret string) bool {
	if len(secret) < minPollSecret || len(secret) > maxPollSecret {
		return false
	}
	h := sha256.Sum256([]byte(secret))
	return subtle.ConstantTimeCompare(h[:], o.pollHash[:]) == 1
}

// queuePendingJoinLocked records a pending join and returns a "pending"
// response. Caller must hold m.mu. A re-request from the same joiner (same
// source IP, hostname, QPot ID and poll secret) reuses the existing request ID
// so a retrying joiner does not spawn duplicate entries; another sender with
// the same source and names is not given that ID.
func (m *Manager) queuePendingJoinLocked(req *JoinRequest, sourceIP string) *JoinResponse {
	if n := len(req.PollSecret); n < minPollSecret || n > maxPollSecret {
		return &JoinResponse{Success: false, Error: errNoPollSecret}
	}
	pollHash := sha256.Sum256([]byte(req.PollSecret))
	kept := *req
	kept.PollSecret = ""
	req = &kept

	m.pruneJoinsLocked(time.Now())
	for _, p := range m.pendingJoins {
		if p.SourceIP == sourceIP && p.NodeName == req.NodeName && p.QPotID == req.QPotID &&
			subtle.ConstantTimeCompare(p.pollHash[:], pollHash[:]) == 1 {
			return &JoinResponse{Success: false, Status: "pending", RequestID: p.RequestID,
				Error: "awaiting host approval"}
		}
	}
	if len(m.pendingJoins) >= maxPendingJoins {
		slog.Warn("Cluster join request dropped: approval queue full", "source_ip", sourceIP)
		return &JoinResponse{Success: false, Error: "too many pending join requests"}
	}
	source, fromSource := authSource(sourceIP), 0
	for _, p := range m.pendingJoins {
		if authSource(p.SourceIP) == source {
			fromSource++
		}
	}
	if fromSource >= maxPendingPerSource {
		slog.Warn("Cluster join request dropped: too many pending from one address", "source_ip", sourceIP)
		return &JoinResponse{Success: false, Error: "too many pending join requests from this address"}
	}

	id, err := generateID("req", 16)
	if err != nil {
		return &JoinResponse{Success: false, Error: "failed to generate request ID"}
	}
	p := &PendingJoin{
		RequestID:      id,
		NodeName:       req.NodeName,
		ClaimedAddress: req.NodeAddress,
		SourceIP:       sourceIP,
		NodePort:       req.NodePort,
		QPotID:         req.QPotID,
		InstanceName:   req.InstanceName,
		Metadata:       req.Metadata,
		Capabilities:   req.Capabilities,
		RequestedAt:    time.Now(),
		req:            req,
		pollHash:       pollHash,
	}
	m.pendingJoins[id] = p
	m.joinOutcomes[id] = &JoinOutcome{RequestID: id, Status: "pending", pollHash: pollHash}

	slog.Info("Cluster join request awaiting approval",
		"request_id", id, "node_name", req.NodeName,
		"source_ip", sourceIP, "claimed_address", req.NodeAddress)

	return &JoinResponse{Success: false, Status: "pending", RequestID: id,
		Error: "awaiting host approval"}
}

// pruneJoinsLocked drops pending requests and decisions older than
// joinRequestTTL, then the oldest decisions beyond maxJoinOutcomes. Caller
// holds m.mu.
func (m *Manager) pruneJoinsLocked(now time.Time) {
	for id, p := range m.pendingJoins {
		if now.Sub(p.RequestedAt) > joinRequestTTL {
			delete(m.pendingJoins, id)
			delete(m.joinOutcomes, id)
		}
	}
	var decided []*JoinOutcome
	for id, o := range m.joinOutcomes {
		if o.Status == "pending" {
			continue
		}
		if now.Sub(o.DecidedAt) > joinRequestTTL {
			delete(m.joinOutcomes, id)
			continue
		}
		decided = append(decided, o)
	}
	if extra := len(decided) - maxJoinOutcomes; extra > 0 {
		sort.Slice(decided, func(i, j int) bool { return decided[i].DecidedAt.Before(decided[j].DecidedAt) })
		for _, o := range decided[:extra] {
			delete(m.joinOutcomes, o.RequestID)
		}
	}
}

// ListPendingJoins returns the join requests awaiting approval, newest first.
// This is what the host reviews - each entry carries the source IP and hostname.
func (m *Manager) ListPendingJoins() []*PendingJoin {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*PendingJoin, 0, len(m.pendingJoins))
	for _, p := range m.pendingJoins {
		// Return a shallow copy without the retained raw request pointer.
		cp := *p
		cp.req = nil
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RequestedAt.After(out[j].RequestedAt) })
	return out
}

// ApproveJoin admits the pending request identified by requestID and returns the
// admitted node. Errors if the request is unknown (already decided or expired).
func (m *Manager) ApproveJoin(requestID string) (*Node, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cluster == nil {
		return nil, fmt.Errorf("cluster not initialized")
	}
	p, ok := m.pendingJoins[requestID]
	if !ok {
		return nil, fmt.Errorf("no pending join request %q", requestID)
	}
	resp, err := m.admitNodeLocked(p.req)
	if err != nil {
		return nil, err
	}
	delete(m.pendingJoins, requestID)
	m.joinOutcomes[requestID] = &JoinOutcome{
		RequestID: requestID, Status: "approved", DecidedAt: time.Now(), response: resp, pollHash: p.pollHash,
	}
	slog.Info("Cluster join request approved",
		"request_id", requestID, "node_id", resp.NodeID, "node_name", p.NodeName)
	return m.cluster.Nodes[resp.NodeID], nil
}

// DenyJoin rejects the pending request identified by requestID.
func (m *Manager) DenyJoin(requestID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.pendingJoins[requestID]
	if !ok {
		return fmt.Errorf("no pending join request %q", requestID)
	}
	delete(m.pendingJoins, requestID)
	m.joinOutcomes[requestID] = &JoinOutcome{
		RequestID: requestID, Status: "denied", DecidedAt: time.Now(), pollHash: p.pollHash,
	}
	slog.Info("Cluster join request denied", "request_id", requestID, "node_name", p.NodeName)
	return nil
}

// joinOutcome returns the current outcome for a request ID (a copy without the
// internal response pointer being shared), and whether it is known.
func (m *Manager) joinOutcome(requestID string) (*JoinOutcome, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	o, ok := m.joinOutcomes[requestID]
	if !ok {
		return nil, false
	}
	cp := *o
	return &cp, true
}
