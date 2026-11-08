package refrigeration

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const maxEventFile = 5 << 20

type journal struct {
	mu   sync.Mutex
	path string
	file *os.File
	size int64
}

type event struct {
	Timestamp       time.Time      `json:"timestamp"`
	Type            string         `json:"event_type"`
	SourceIP        string         `json:"src_ip"`
	SourcePort      int            `json:"src_port"`
	DestinationPort int            `json:"dst_port"`
	Protocol        string         `json:"protocol"`
	Action          string         `json:"action,omitempty"`
	Method          string         `json:"method"`
	Path            string         `json:"path"`
	Username        string         `json:"username,omitempty"`
	Password        string         `json:"password,omitempty"`
	Success         bool           `json:"success"`
	DeviceID        string         `json:"device_id,omitempty"`
	Request         string         `json:"request,omitempty"`
	Metadata        map[string]any `json:"metadata"`
}

func openJournal(path string) (*journal, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create refrigeration log directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Size() > maxEventFile {
			return nil, errors.New("refrigeration event log must be a bounded regular file")
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat refrigeration event log: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open refrigeration event log: %w", err)
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("refrigeration event log must be a regular file")
	}
	if err = f.Chmod(0o600); err != nil {
		f.Close()
		return nil, fmt.Errorf("secure refrigeration event log: %w", err)
	}
	return &journal{path: path, file: f, size: info.Size()}, nil
}

func (j *journal) append(e event) error {
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file == nil {
		return os.ErrClosed
	}
	if j.size+int64(len(data)) > maxEventFile {
		if err = j.file.Close(); err != nil {
			return err
		}
		j.file = nil
		if err = os.Remove(j.path + ".2"); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err = os.Rename(j.path+".1", j.path+".2"); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err = os.Rename(j.path, j.path+".1"); err != nil && !os.IsNotExist(err) {
			return err
		}
		j.file, err = os.OpenFile(j.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		j.size = 0
	}
	n, err := j.file.Write(data)
	j.size += int64(n)
	return err
}

func (j *journal) close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file == nil {
		return nil
	}
	err := j.file.Close()
	j.file = nil
	return err
}

func (s *Server) record(r *http.Request, kind, action, user, password, request string, success bool, node int, metadata map[string]any) bool {
	host, port, _ := net.SplitHostPort(r.RemoteAddr)
	if host == "" {
		host = r.RemoteAddr
	}
	number, _ := strconv.Atoi(port)
	destination := 8080
	if local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		if _, p, err := net.SplitHostPort(local.String()); err == nil {
			if n, err := strconv.Atoi(p); err == nil {
				destination = n
			}
		}
	} else if _, p, err := net.SplitHostPort(s.cfg.ListenAddr); err == nil {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			destination = n
		}
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["profile"] = "danfoss-ak-sm800a-3.3.0"
	metadata["model"] = Model
	metadata["firmware"] = Firmware
	metadata["site_profile"] = s.cfg.SiteProfile
	metadata["request_uri"] = bounded(r.URL.RequestURI(), 2048)
	metadata["user_agent"] = bounded(r.UserAgent(), 512)
	if r.URL.RawQuery != "" {
		query, err := url.QueryUnescape(r.URL.RawQuery)
		if err != nil {
			query = r.URL.RawQuery
		}
		metadata["query"] = bounded(query, 1024)
		request = r.URL.RequestURI() + "\n" + query + "\n" + request
	} else if request == "" {
		request = r.URL.RequestURI()
	}
	e := event{Timestamp: s.now(), Type: "refrigeration." + kind, SourceIP: bounded(host, 128), SourcePort: number, Protocol: "http", Action: bounded(action, 64), Method: r.Method, Path: bounded(r.URL.Path, 512), Username: bounded(user, 128), Password: bounded(password, 256), Success: success, Request: bounded(request, 4096), Metadata: metadata}
	e.DestinationPort = destination
	if node > 0 {
		e.DeviceID = strconv.Itoa(node)
	}
	if err := s.events.append(e); err != nil {
		s.cfg.Logger.Error("write refrigeration event", "error", err)
		s.fail(fmt.Errorf("refrigeration event journal: %w", err))
		return false
	}
	return true
}

func (s *Server) fail(err error) {
	s.mu.Lock()
	if s.failure == nil {
		s.failure = err
		select {
		case s.fatal <- err:
		default:
		}
	}
	s.mu.Unlock()
}

func bounded(value string, n int) string {
	value = strings.ToValidUTF8(value, "�")
	if len(value) > n {
		value = value[:n]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return value
}
