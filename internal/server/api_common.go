package server

// Shared plumbing of the web UI's API endpoints added on top of the original
// dashboard API (api_*.go): plain-English JSON errors with QPot error codes,
// strict JSON bodies, the per-server state those endpoints keep, and reading
// the instance's config file as it is now.

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/instance"
)

// apiState is the state of the api_*.go endpoints (Server.api).
type apiState struct {
	// change serialises the requests that change honeypots (settings,
	// restart, enable/disable): a second one while one runs gets 409.
	change sync.Mutex

	// runner, when set, replaces the Manager a honeypot change uses for
	// cfg (tests).
	runner func(cfg *config.Config) instance.HoneypotRunner

	// cfgMu guards the parsed config file cache readConfig keeps.
	cfgMu  sync.Mutex
	cfgSum [sha256.Size]byte
	cfg    *config.Config
}

// apiError is the JSON body of an error answer.
type apiError struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
	// Saved is set when the change was saved although the request failed
	// afterwards (e.g. the honeypot did not restart).
	Saved bool `json:"saved,omitempty"`
}

// sendAPIError answers with a plain-English error and, when one fits, the
// QPot error code that explains it (GET /api/doctor/explain?code=).
func (s *Server) sendAPIError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, apiError{Error: msg, Code: code})
}

// writeJSON answers with v as JSON.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// allowMethods answers 405 unless r uses one of the methods.
func (s *Server) allowMethods(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, m := range methods {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(methods, ", "))
	s.sendAPIError(w, http.StatusMethodNotAllowed, "", "method not allowed (use "+strings.Join(methods, " or ")+")")
	return false
}

// decodeJSONBody reads a JSON object of at most max bytes into v. Unknown
// fields and anything after the object are refused, so a typo in a field
// name is an error rather than silently ignored.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, max int64, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return fmt.Errorf("request body is larger than %d bytes", max)
		}
		return errors.New("request body is not the expected JSON object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("request body has data after the JSON object")
	}
	return nil
}

// extendWriteDeadline gives a request that waits for Docker longer than the
// server's write timeout.
func extendWriteDeadline(w http.ResponseWriter, d time.Duration) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(d))
}

// configFileData returns the instance's config file, or nil when the server
// has none on disk (then its in-memory config is the truth).
func (s *Server) configFileData() ([]byte, error) {
	if s.config.ConfigPath == "" {
		return nil, nil
	}
	data, err := readConfigBounded(s.config.ConfigPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

// loadConfigForChange returns a private copy of the instance config as the
// file says now, for a request to change and save. The CLI may have changed
// the file since this server started; changing the server's own copy and
// saving it would undo that. The QPot ID is the server's (the file's may be
// missing), as for a restarted server.
func (s *Server) loadConfigForChange() (*config.Config, error) {
	data, err := s.configFileData()
	if err != nil {
		return nil, err
	}
	var cfg *config.Config
	if data == nil {
		cfg, err = s.config.Clone()
	} else {
		cfg, err = config.Parse(data, s.config.ConfigPath)
	}
	if err != nil {
		return nil, err
	}
	cfg.QPotID = s.config.QPotID
	return cfg, nil
}

// readConfig returns the instance config as the file says now, for reading
// only (it is shared between requests): parsed again only when the file
// changed.
func (s *Server) readConfig() (*config.Config, error) {
	data, err := s.configFileData()
	if err != nil {
		return nil, err
	}
	if data == nil {
		return s.config, nil
	}
	sum := sha256.Sum256(data)
	a := &s.api
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	if a.cfg != nil && bytes.Equal(sum[:], a.cfgSum[:]) {
		return a.cfg, nil
	}
	cfg, err := config.Parse(data, s.config.ConfigPath)
	if err != nil {
		return nil, err
	}
	cfg.QPotID = s.config.QPotID
	a.cfg, a.cfgSum = cfg, sum
	return cfg, nil
}

// adoptHoneypots makes the server's own config carry the honeypot settings
// of cfg (just saved), and has the planted canaries follow them at once.
func (s *Server) adoptHoneypots(cfg *config.Config) {
	s.config.ReplaceHoneypots(cfg.SnapshotHoneypots())
	s.planted.mu.Lock()
	s.planted.read = false
	s.planted.mu.Unlock()
	s.followPlanted()
}

// honeypotRunner is what a honeypot change uses to reach cfg's containers.
func (s *Server) honeypotRunner(cfg *config.Config) (instance.HoneypotRunner, error) {
	if s.api.runner != nil {
		return s.api.runner(cfg), nil
	}
	return instance.NewManager(cfg)
}
