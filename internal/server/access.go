package server

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/qpot/qpot/internal/access"
)

// Team access (doc/security.md): the QPot ID is the owner's key, and each
// member added on the host (qpot access) has a key of their own with a
// role. Every request that changes something, and every request a role is
// refused, goes to the audit log.

// accessRecheck is how long a read of the members file is trusted: a
// member removed on the host is locked out within this time.
const accessRecheck = 2 * time.Second

// identity is who makes a request.
type identity struct {
	Name string      `json:"name"`
	Role access.Role `json:"role"`
}

type identityKey struct{}

// whoIs returns the identity withQPotAuth put on the request. A request
// that came without it (authentication is off) is the owner's.
func whoIs(r *http.Request) identity {
	if id, ok := r.Context().Value(identityKey{}).(identity); ok {
		return id
	}
	return identity{Name: "owner", Role: access.Owner}
}

// accessFollower keeps the members file's content current.
type accessFollower struct {
	mu      sync.Mutex
	list    *access.List
	checked time.Time
	mod     time.Time
	size    int64
	audit   *access.Audit
	failed  bool
}

// members returns the instance's members, reading the file again when it
// changed. A file that cannot be read lets no member in.
func (f *accessFollower) members(dataPath string) *access.List {
	if dataPath == "" {
		// No data folder, no members: never a file of the working directory.
		return &access.List{Version: 1}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if f.list != nil && now.Sub(f.checked) < accessRecheck {
		return f.list
	}
	f.checked = now
	var mod time.Time
	var size int64 = -1
	if info, err := os.Stat(access.Path(dataPath)); err == nil {
		mod, size = info.ModTime(), info.Size()
	}
	if f.list != nil && mod.Equal(f.mod) && size == f.size {
		return f.list
	}
	list, err := access.Load(dataPath)
	if err != nil {
		if !f.failed {
			slog.Error("Team access: the members file cannot be used; only the QPot ID signs in until it is repaired or removed", "error", err)
		}
		f.failed = true
		list = &access.List{Version: 1}
	} else {
		f.failed = false
	}
	f.list, f.mod, f.size = list, mod, size
	return list
}

// auditLog returns the instance's audit log, or nil for a server that has
// no data folder to keep one in.
func (f *accessFollower) auditLog(dataPath string) *access.Audit {
	if dataPath == "" {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.audit == nil {
		f.audit = access.NewAudit(dataPath)
	}
	return f.audit
}

// statusWriter remembers the status a handler answered with.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

// Flush keeps streaming answers (the attack map) working through the wrapper.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// authorize applies the key's role to the request and audits it. It returns
// the request to hand on, or nil when it answered the request itself.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, id identity) (http.ResponseWriter, *http.Request, func()) {
	read := r.Method == http.MethodGet || r.Method == http.MethodHead
	record := func(status int, denied bool) {
		if err := s.access.auditLog(s.config.DataPath).Record(access.Entry{Time: time.Now(), Who: id.Name, Role: id.Role,
			Method: r.Method, Path: r.URL.Path, Status: status, Denied: denied, Remote: r.RemoteAddr}); err != nil {
			slog.Warn("Audit log not written", "error", err)
		}
	}
	if !access.Allowed(id.Role, r.Method, r.URL.Path) {
		record(http.StatusForbidden, true)
		// The header tells the web UI that the key is good and the role is
		// what stopped the request: it must not sign the person out.
		w.Header().Set("X-QPot-Denied", "role")
		s.sendAPIError(w, http.StatusForbidden, "QP-WEB-006", "Your key has the role "+string(id.Role)+", which may not do this. Ask the instance's owner.")
		return nil, nil, nil
	}
	r = r.WithContext(context.WithValue(r.Context(), identityKey{}, id))
	if read {
		return w, r, func() {}
	}
	sw := &statusWriter{ResponseWriter: w}
	return sw, r, func() {
		status := sw.status
		if status == 0 {
			status = http.StatusOK
		}
		record(status, false)
	}
}

// accessView is the answer of GET /api/access.
type accessView struct {
	You identity `json:"you"`
	// Members and Audit are for the owner and admins; nil for other roles.
	Members []accessMember `json:"members"`
	Audit   []access.Entry `json:"audit"`
	// Manage says where members are managed.
	Manage string `json:"manage"`
}

type accessMember struct {
	Name    string      `json:"name"`
	Role    access.Role `json:"role"`
	Created time.Time   `json:"created"`
}

// GET /api/access?audit=N: who the request's key belongs to, and for the
// owner and admins the members and the last N audited requests. Members are
// added and removed on the host only.
func (s *Server) handleAccess(w http.ResponseWriter, r *http.Request) {
	if !s.allowMethods(w, r, http.MethodGet) {
		return
	}
	limit, err := parseIntParam(r.URL.Query(), "audit", 50, 1, access.MaxAuditRead)
	if err != nil {
		s.sendAPIError(w, http.StatusBadRequest, "", "Bad request: "+err.Error()+".")
		return
	}
	v := accessView{You: whoIs(r), Manage: "qpot access add <name> --role viewer|analyst|admin, on the host"}
	if v.You.Role == access.Owner || v.You.Role == access.Admin {
		v.Members = []accessMember{}
		for _, m := range s.access.members(s.config.DataPath).Members {
			v.Members = append(v.Members, accessMember{Name: m.Name, Role: m.Role, Created: m.Created})
		}
		entries, err := access.ReadAudit(s.config.DataPath, limit)
		if err != nil {
			slog.Warn("Audit log not read", "error", err)
		}
		if v.Audit = entries; v.Audit == nil {
			v.Audit = []access.Entry{}
		}
	}
	writeJSON(w, http.StatusOK, v)
}
