package instance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/config"
)

// BackendRecycler is the trusted, host-side half of HiFi backend reset. It
// follows the ssh-proxy broker's session log and, after every session (or
// backend error), RECREATES that backend container, discarding everything the
// attacker changed - planted files, persistence, edited accounts. The broker
// (which has no privilege) waits until it sees the recreation before it reuses
// the backend; see proxy.RecycleReset.
//
// Only backend names from this instance's configured pool are ever acted on,
// and docker is invoked with an argv (no shell), so the log cannot steer it.
type BackendRecycler struct {
	ComposeFile string
	LogPath     string
	Services    map[string]bool
	Poll        time.Duration
	// GenerationDir holds one counter file per backend, bumped after every
	// successful recreation; the broker reads it (read-only) to tell a real
	// reset from a restart staged inside the backend.
	GenerationDir string
	// Recreate recreates one backend service; defaults to docker compose.
	Recreate func(ctx context.Context, service string) error
}

// NewBackendRecycler returns a recycler for cfg's HiFi pool, or nil when the
// ssh-proxy honeypot is not enabled.
func NewBackendRecycler(cfg *config.Config) *BackendRecycler {
	if hp, ok := cfg.GetHoneypotConfig(sshProxyHoneypot); !ok || !hp.Enabled {
		return nil
	}
	r := &BackendRecycler{
		ComposeFile:   cfg.GetDockerComposePath(),
		LogPath:       filepath.Join(cfg.DataPath, "honeypots", sshProxyHoneypot, "logs", "sessions.json"),
		GenerationDir: filepath.Join(cfg.DataPath, "honeypots", sshProxyHoneypot, "generations"),
		Services:      map[string]bool{},
		Poll:          500 * time.Millisecond,
	}
	for _, s := range sshBackendServiceNames(cfg) {
		r.Services[s] = true
	}
	r.Recreate = r.composeRecreate
	return r
}

func (r *BackendRecycler) composeRecreate(ctx context.Context, service string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", r.ComposeFile,
		"up", "-d", "--force-recreate", "--no-deps", service)
	cmd.Dir = filepath.Dir(r.ComposeFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("recreate %s: %w: %s", service, err, out)
	}
	return nil
}

// Run recycles every backend once (they may hold state from before this
// process started), then recycles each backend whose session ends, until ctx
// is cancelled.
func (r *BackendRecycler) Run(ctx context.Context) {
	queue := make(chan string, len(r.Services)*4+4)
	pending := map[string]bool{}
	enqueue := func(s string) {
		if !r.Services[s] || pending[s] {
			return
		}
		pending[s] = true
		queue <- s
	}
	done := make(chan string, cap(queue))
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case s := <-queue:
				if err := r.Recreate(ctx, s); err != nil {
					slog.Warn("HiFi backend recycle failed; the broker keeps it out of rotation", "backend", s, "error", err)
				} else if err := bumpGeneration(r.GenerationDir, s); err != nil {
					// Without the bump the broker will not accept the reset and
					// keeps the backend quarantined: fail closed.
					slog.Warn("HiFi backend recreated but its generation could not be recorded", "backend", s, "error", err)
				} else {
					slog.Info("HiFi backend recycled", "backend", s)
				}
				done <- s
			}
		}
	}()

	// Start from the end of the log: everything before now is covered by the
	// initial full recycle.
	var offset int64
	if st, err := os.Stat(r.LogPath); err == nil {
		offset = st.Size()
	}
	for s := range r.Services {
		enqueue(s)
	}
	var partial []byte
	t := time.NewTicker(r.Poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case s := <-done:
			delete(pending, s)
			continue
		case <-t.C:
		}
		var lines [][]byte
		offset, partial, lines = readNewLines(r.LogPath, offset, partial)
		for _, l := range lines {
			if s := recycleTarget(l); s != "" {
				enqueue(s)
			}
		}
	}
}

// readNewLines returns the complete lines appended to path since offset. A
// shrunken file (rotation/truncation) is re-read from the start.
func readNewLines(path string, offset int64, partial []byte) (int64, []byte, [][]byte) {
	f, err := os.Open(path)
	if err != nil {
		return offset, partial, nil
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() < offset {
		offset, partial = 0, nil
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return offset, partial, nil
	}
	data, err := io.ReadAll(io.LimitReader(f, 4<<20))
	if err != nil {
		return offset, partial, nil
	}
	offset += int64(len(data))
	buf := append(partial, data...)
	var lines [][]byte
	for {
		i := bytes.IndexByte(buf, '\n')
		if i < 0 {
			break // keep an incomplete trailing line for the next read
		}
		if line := bytes.TrimSpace(buf[:i]); len(line) > 0 {
			lines = append(lines, append([]byte(nil), line...))
		}
		buf = buf[i+1:]
	}
	if len(buf) > 1<<20 { // a runaway line without newline: drop it
		buf = nil
	}
	return offset, append([]byte(nil), buf...), lines
}

// recycleTarget returns the backend a session-log line says must be recycled
// (a finished session, or a backend error), or "".
func recycleTarget(line []byte) string {
	var ev struct {
		EventType string `json:"event_type"`
		Backend   string `json:"backend"`
	}
	if json.Unmarshal(line, &ev) != nil {
		return ""
	}
	switch ev.EventType {
	case "ssh_proxy_session", "ssh_proxy_backend_error":
		return ev.Backend
	}
	return ""
}

// sshProxyGenerationsPath is where the broker sees the generation counters.
const sshProxyGenerationsPath = "/run/qpot/generations"

// bumpGeneration increments the backend's recreation counter, atomically
// (temp file + rename) so the broker never reads a partial value.
func bumpGeneration(dir, service string) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, service)
	var n uint64
	if b, err := os.ReadFile(path); err == nil {
		n, _ = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	}
	tmp, err := os.CreateTemp(dir, "."+service+".*")
	if err != nil {
		return err
	}
	_, werr := fmt.Fprintf(tmp, "%d\n", n+1)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp.Name())
		return errors.Join(werr, cerr)
	}
	// Readable by the broker's non-root user; holds no secret.
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}
