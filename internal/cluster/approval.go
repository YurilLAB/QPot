package cluster

import (
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

	// req is the original request, retained so an approval can build the node.
	req *JoinRequest
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
}

// queuePendingJoinLocked records a pending join and returns a "pending"
// response. Caller must hold m.mu. An identical re-request (same source IP +
// hostname + QPot ID) reuses the existing request ID so a retrying/polling
// joiner does not spawn duplicate entries.
func (m *Manager) queuePendingJoinLocked(req *JoinRequest, sourceIP string) *JoinResponse {
	for _, p := range m.pendingJoins {
		if p.SourceIP == sourceIP && p.NodeName == req.NodeName && p.QPotID == req.QPotID {
			return &JoinResponse{Success: false, Status: "pending", RequestID: p.RequestID,
				Error: "awaiting host approval"}
		}
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
	}
	m.pendingJoins[id] = p
	m.joinOutcomes[id] = &JoinOutcome{RequestID: id, Status: "pending"}

	slog.Info("Cluster join request awaiting approval",
		"request_id", id, "node_name", req.NodeName,
		"source_ip", sourceIP, "claimed_address", req.NodeAddress)

	return &JoinResponse{Success: false, Status: "pending", RequestID: id,
		Error: "awaiting host approval"}
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
		RequestID: requestID, Status: "approved", DecidedAt: time.Now(), response: resp,
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
		RequestID: requestID, Status: "denied", DecidedAt: time.Now(),
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
