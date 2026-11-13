package access

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// The audit log records who changed what through the web API: every request
// that is not a read, and every request a role was refused. It is JSON, one
// entry a line, in the instance's data folder.
const (
	auditFile = "audit.log"
	// maxAuditBytes is the size at which the log is set aside as audit.log.1
	// (replacing the one before) and started again.
	maxAuditBytes = 4 << 20
	// MaxAuditRead is the most entries ReadAudit returns.
	MaxAuditRead = 1000
	maxAuditLine = 4 << 10
)

// Entry is one audited request.
type Entry struct {
	Time time.Time `json:"time"`
	// Who is the member's name, or "owner" for the QPot ID.
	Who    string `json:"who"`
	Role   Role   `json:"role"`
	Method string `json:"method"`
	Path   string `json:"path"`
	// Status is the answer's HTTP status. Denied is true when the role was
	// not allowed to make the request at all.
	Status int    `json:"status"`
	Denied bool   `json:"denied,omitempty"`
	Remote string `json:"remote,omitempty"`
}

// Audit appends to an instance's audit log.
type Audit struct {
	mu   sync.Mutex
	path string
	max  int64
}

// NewAudit returns the audit log of an instance's data folder.
func NewAudit(dataPath string) *Audit {
	return &Audit{path: filepath.Join(dataPath, auditFile), max: maxAuditBytes}
}

// Record appends an entry. The text fields are bounded: a path or a remote
// address is whatever the client sent.
func (a *Audit) Record(e Entry) error {
	if a == nil {
		return nil
	}
	e.Time = e.Time.UTC()
	e.Path, e.Remote, e.Method = clip(e.Path, 256), clip(e.Remote, 64), clip(e.Method, 16)
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if info, err := os.Stat(a.path); err == nil && info.Size()+int64(len(line)) > a.max {
		if err := os.Rename(a.path, a.path+".1"); err != nil {
			return fmt.Errorf("access: rotate audit log: %w", err)
		}
	}
	f, err := os.OpenFile(a.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("access: write audit log: %w", err)
	}
	_, err = f.Write(append(line, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ReadAudit returns the last limit entries of an instance's audit log,
// newest first. Lines that are no entry are skipped.
func ReadAudit(dataPath string, limit int) ([]Entry, error) {
	if limit <= 0 || limit > MaxAuditRead {
		limit = MaxAuditRead
	}
	var all []Entry
	for _, name := range []string{auditFile + ".1", auditFile} {
		f, err := os.Open(filepath.Join(dataPath, name))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("access: read audit log: %w", err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, maxAuditLine), maxAuditLine)
		for sc.Scan() {
			var e Entry
			if json.Unmarshal(sc.Bytes(), &e) == nil && !e.Time.IsZero() {
				all = append(all, e)
				if len(all) > 2*MaxAuditRead {
					all = append(all[:0], all[len(all)-MaxAuditRead:]...)
				}
			}
		}
		_ = f.Close()
		// A line longer than an entry can be ends the reading of that file:
		// what came before it is still returned.
	}
	if len(all) > limit {
		all = all[len(all)-limit:]
	}
	out := make([]Entry, 0, len(all))
	for i := len(all) - 1; i >= 0; i-- {
		out = append(out, all[i])
	}
	return out, nil
}
