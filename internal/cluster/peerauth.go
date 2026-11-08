package cluster

// Peer identity and node removal.
//
// Every member holds the cluster password and the member key, so they prove
// only that a request comes from some member. A peer request (status, nodes,
// leave, gossip, intel) must also present, in the TLS handshake, the sender's
// own node certificate: the CA-signed leaf the node got when it was admitted,
// naming its node ID, whose private key never left the node. The request is
// served only while that node is a member: one that left, or that the
// enrollment host removed, is refused whatever credentials it kept. And a
// request speaks only for the node it comes from: gossip and intel carry the
// sender's ID, a leave the ID of the node leaving, and each must be its own.
//
// Removing a node is the enrollment host's decision: it signs a revocation
// with the cluster CA key, which the members check against the CA their
// cluster ID names, so no member can forge one. Gossip carries revocations
// to every member, and each saves them. Records of nodes that left or were
// removed are kept for longer than any certificate they hold is valid.

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/qpot/qpot/internal/hostsetup"
)

// Revocation is the enrollment host's signed statement that a node is no
// longer a member of the cluster.
type Revocation struct {
	NodeID    string    `json:"node_id"`
	RevokedAt time.Time `json:"revoked_at"`
	// Signature is the cluster CA's Ed25519 signature of revocationMessage,
	// base64.
	Signature string `json:"signature"`
}

const (
	// revocationRetention is how long a revocation is kept and gossiped:
	// longer than a certificate issued before it can be valid.
	revocationRetention = leftRetention
	// maxRevocations bounds the revocations kept and gossiped, the newest
	// kept. The removed nodes' left records refuse them as well.
	maxRevocations = 1024
)

// peerNodeKey is the request context key for the authenticated node ID.
type peerNodeKey struct{}

var (
	errNoPeerCertificate = errors.New("a peer request must present the sending node's cluster certificate (update QPot on that node)")
	errNotAMember        = errors.New("the node is not a member of this cluster: it left or was removed")
)

// withPeerNode returns r carrying nodeID as the node it was authenticated as.
func withPeerNode(r *http.Request, nodeID string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), peerNodeKey{}, nodeID))
}

// peerNode returns the node withMemberAuth authenticated r as.
func peerNode(r *http.Request) (string, bool) {
	id, ok := r.Context().Value(peerNodeKey{}).(string)
	return id, ok && id != ""
}

// requirePeer returns the node r was authenticated as, or answers 401 and
// returns false: a handler must never act for a request without one.
func requirePeer(w http.ResponseWriter, r *http.Request) (string, bool) {
	id, ok := peerNode(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
	return id, ok
}

// authenticatePeer returns the node a peer request comes from: the node ID
// its TLS client certificate, from this cluster's CA, names, while that node
// is a member.
func (m *Manager) authenticatePeer(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", errNoPeerCertificate
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cluster == nil {
		return "", errNotAMember
	}
	id, err := verifyClusterClient(m.cluster.ID, r.TLS.PeerCertificates, time.Now())
	if err != nil {
		return "", err
	}
	if n, ok := m.cluster.Nodes[id]; !ok || n.Status == NodeStatusLeft || m.revokedLocked(id) {
		return "", errNotAMember
	}
	return id, nil
}

// revokedLocked reports whether the enrollment host removed node id. Caller
// holds m.mu.
func (m *Manager) revokedLocked(id string) bool {
	for _, rv := range m.cluster.Revocations {
		if rv.NodeID == id {
			return true
		}
	}
	return false
}

// revocationMessage is what the cluster CA signs for rv.
func revocationMessage(clusterID string, rv Revocation) []byte {
	return []byte("qpot-cluster-revocation-v1\n" + clusterID + "\n" + rv.NodeID + "\n" +
		rv.RevokedAt.UTC().Format(time.RFC3339Nano))
}

// caPublicKeyLocked returns the public key of this cluster's CA: from the CA
// key on the enrollment host, else from this node's certificate chain, where
// it is the certificate whose key gives the cluster ID. nil when neither
// yields it. Caller holds m.mu.
func (m *Manager) caPublicKeyLocked() ed25519.PublicKey {
	c := m.cluster
	if c.CAKey != "" {
		if key, _, err := clusterCA(c.CAKey); err == nil {
			if pub := key.Public().(ed25519.PublicKey); clusterIDFor(pub) == c.ID {
				return pub
			}
		}
	}
	rest := []byte(c.NodeCertificate)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if pub, ok := cert.PublicKey.(ed25519.PublicKey); ok && clusterIDFor(pub) == c.ID {
			return pub
		}
	}
}

// applyRevocationsLocked takes the revocations in revs that the cluster CA
// signed and this node does not have yet: it keeps them and marks the nodes
// they name left. It reports whether anything changed (to save). Caller holds
// m.mu for writing.
func (m *Manager) applyRevocationsLocked(revs []Revocation, now time.Time) bool {
	if len(revs) > maxRevocations {
		revs = revs[:maxRevocations]
	}
	var pub ed25519.PublicKey
	changed := false
	for _, rv := range revs {
		if !validNodeID(rv.NodeID) || rv.RevokedAt.IsZero() || now.Sub(rv.RevokedAt) > revocationRetention ||
			m.revokedLocked(rv.NodeID) {
			continue
		}
		if pub == nil {
			if pub = m.caPublicKeyLocked(); pub == nil {
				return changed
			}
		}
		sig, err := base64.StdEncoding.DecodeString(rv.Signature)
		if err != nil || !ed25519.Verify(pub, revocationMessage(m.cluster.ID, rv), sig) {
			continue
		}
		m.cluster.Revocations = append(m.cluster.Revocations, rv)
		if n, ok := m.cluster.Nodes[rv.NodeID]; ok && n.Status != NodeStatusLeft {
			n.Status, n.LastSeen = NodeStatusLeft, now
		}
		if m.cluster.LocalNode != nil && rv.NodeID == m.cluster.LocalNode.ID {
			slog.Warn("The enrollment host removed this node from the cluster; the other members refuse it now")
		} else {
			slog.Info("Node removed from the cluster by the enrollment host", "node_id", rv.NodeID)
		}
		changed = true
	}
	if changed {
		m.pruneLeftLocked(now)
		m.pruneRevocationsLocked(now)
	}
	return changed
}

// pruneRevocationsLocked drops revocations older than revocationRetention,
// then the oldest beyond maxRevocations. Caller holds m.mu for writing.
func (m *Manager) pruneRevocationsLocked(now time.Time) {
	kept := m.cluster.Revocations[:0]
	for _, rv := range m.cluster.Revocations {
		if now.Sub(rv.RevokedAt) <= revocationRetention {
			kept = append(kept, rv)
		}
	}
	if len(kept) > maxRevocations {
		sort.Slice(kept, func(i, j int) bool { return kept[i].RevokedAt.Before(kept[j].RevokedAt) })
		kept = kept[len(kept)-maxRevocations:]
	}
	m.cluster.Revocations = kept
}

// revocationsLocked returns a copy of the revocations to gossip. Caller holds
// m.mu.
func (m *Manager) revocationsLocked() []Revocation {
	return append([]Revocation(nil), m.cluster.Revocations...)
}

// Errors of RemoveNode.
var (
	ErrUnknownNode = errors.New("no node with that ID in this cluster")
	errRemoveSelf  = errors.New("the enrollment host cannot remove itself")
)

// RemoveNode removes a node from the cluster: the enrollment host signs its
// revocation, marks it left and saves both before answering. The other
// members take the revocation from gossip and refuse the node too, whatever
// credentials it kept. Removing a node that is already removed does nothing.
func (m *Manager) RemoveNode(nodeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cluster == nil {
		return fmt.Errorf("not in a cluster")
	}
	if m.cluster.CAKey == "" {
		return hostsetup.E("QP-CLUSTER-004").WithWhy("Only the enrollment host can remove a node; run this on the host that initialized or upgraded the cluster.")
	}
	if m.cluster.LocalNode != nil && nodeID == m.cluster.LocalNode.ID {
		return errRemoveSelf
	}
	if m.revokedLocked(nodeID) {
		return nil
	}
	node, ok := m.cluster.Nodes[nodeID]
	if !ok {
		return ErrUnknownNode
	}
	key, _, err := clusterCA(m.cluster.CAKey)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	rv := Revocation{NodeID: nodeID, RevokedAt: now}
	rv.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, revocationMessage(m.cluster.ID, rv)))

	revs, status, seen, updated := m.cluster.Revocations, node.Status, node.LastSeen, m.cluster.UpdatedAt
	m.cluster.Revocations = append(append([]Revocation(nil), revs...), rv)
	node.Status, node.LastSeen, m.cluster.UpdatedAt = NodeStatusLeft, now, now
	if err := m.saveClusterLocked(); err != nil {
		m.cluster.Revocations, node.Status, node.LastSeen, m.cluster.UpdatedAt = revs, status, seen, updated
		return fmt.Errorf("failed to persist the removal: %w", err)
	}
	m.pruneLeftLocked(now)
	m.pruneRevocationsLocked(now)
	delete(m.peerIntel, nodeID)
	slog.Info("Node removed from the cluster", "node_id", nodeID)
	return nil
}

// handleRemoveHTTP removes a node (host only, see RemoveNode).
func (m *Manager) handleRemoveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		NodeID string `json:"node_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxClusterBodyBytes)).Decode(&body); err != nil || body.NodeID == "" {
		http.Error(w, "node_id required", http.StatusBadRequest)
		return
	}
	err := m.RemoveNode(body.NodeID)
	var coded *hostsetup.Error
	switch {
	case err == nil:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "removed", "node_id": body.NodeID})
	case errors.Is(err, ErrUnknownNode):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, errRemoveSelf):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.As(err, &coded):
		http.Error(w, coded.Cause(), http.StatusConflict)
	default:
		slog.Error("Cluster: node removal failed", "error", err)
		http.Error(w, "the removal could not be saved", http.StatusInternalServerError)
	}
}
