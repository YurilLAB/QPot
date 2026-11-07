package server

import (
	"net/http"
	"regexp"
	"time"

	"github.com/qpot/qpot/internal/cluster"
)

// The cluster ("group") in the web API. The control plane that runs the
// host's cluster (gossip, the cluster API, join requests) hands its manager
// to the server with SetCluster; the server only reads it (status, members,
// the local node's ID, pending joins). Approving or denying a join stays on
// the host (`qpot cluster approve|deny`). Until then, or in an instance whose
// control plane does not run the cluster, the server shows the membership
// cluster.json held when it started.

// SetCluster hands the server the cluster manager this control plane runs.
func (s *Server) SetCluster(cm *cluster.Manager) {
	if cm != nil {
		s.api.liveCluster.Store(cm)
	}
}

// clusterView is the cluster the API shows: the running manager when this
// control plane runs the cluster (live), else the snapshot loaded at start.
func (s *Server) clusterView() (cm *cluster.Manager, live bool) {
	if cm := s.api.liveCluster.Load(); cm != nil {
		return cm, true
	}
	return s.cluster, false
}

// clusterRunsOn names the instance the cluster's local node belongs to (the
// one whose control plane runs the cluster on this host), "" when unknown.
func clusterRunsOn(cm *cluster.Manager) string {
	id := cm.LocalNodeID()
	if id == "" {
		return ""
	}
	for _, n := range cm.GetNodes() {
		if n.ID == id {
			return n.InstanceName
		}
	}
	return ""
}

// joinRequestIDRe is what a request ID must look like to be put in a host
// command (IDs come from the cluster package; this keeps a malformed one off
// the command line shown to the operator; a leading "-" would read as a flag).
var joinRequestIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// joinCommands are the host commands that approve or deny a join request,
// "" for an ID that does not look like one.
func joinCommands(id string) (approve, deny string) {
	if !joinRequestIDRe.MatchString(id) {
		return "", ""
	}
	return "qpot cluster approve " + id, "qpot cluster deny " + id
}

// joinRequestView is one pending join, without the joiner's poll secret
// hash, its original request or anything it claims beyond name and address.
type joinRequestView struct {
	RequestID      string    `json:"request_id"`
	NodeName       string    `json:"node_name"`
	ClaimedAddress string    `json:"claimed_address"`
	SourceIP       string    `json:"source_ip"`
	RequestedAt    time.Time `json:"requested_at"`
	ApproveCommand string    `json:"approve_command,omitempty"`
	DenyCommand    string    `json:"deny_command,omitempty"`
}

type joinRequestsAnswer struct {
	Clustered bool              `json:"clustered"`
	Live      bool              `json:"live"`
	RunsOn    string            `json:"runs_on_instance,omitempty"`
	Message   string            `json:"message,omitempty"`
	Requests  []joinRequestView `json:"requests"`
}

// GET /api/cluster/requests: the join requests waiting for the host's
// approval. Read-only: approving or denying is done on the host.
func (s *Server) handleClusterRequests(w http.ResponseWriter, r *http.Request) {
	if !s.allowMethods(w, r, http.MethodGet) {
		return
	}
	out := joinRequestsAnswer{Requests: []joinRequestView{}}
	cm, live := s.clusterView()
	if cm == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	out.Clustered, out.Live, out.RunsOn = true, live, clusterRunsOn(cm)
	if !live {
		switch {
		case out.RunsOn != "" && out.RunsOn != s.config.InstanceName:
			out.Message = "Join requests are shown by the web UI of instance \"" + out.RunsOn +
				"\", whose control plane runs the cluster on this host."
		default:
			out.Message = "This control plane does not run the cluster, so it cannot see join requests. " +
				"The instance whose control plane runs the cluster shows them (start it with: qpot up -d)."
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	for _, p := range cm.ListPendingJoins() {
		v := joinRequestView{RequestID: p.RequestID, NodeName: p.NodeName, ClaimedAddress: p.ClaimedAddress,
			SourceIP: p.SourceIP, RequestedAt: p.RequestedAt.UTC()}
		v.ApproveCommand, v.DenyCommand = joinCommands(p.RequestID)
		out.Requests = append(out.Requests, v)
	}
	writeJSON(w, http.StatusOK, out)
}
