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
	"github.com/qpot/qpot/internal/hostsetup"
	"github.com/qpot/qpot/internal/proxy"
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
	InstanceName string
	ComposeFile  string
	LogPath      string
	Services     map[string]bool
	Poll         time.Duration
	// GenerationDir holds one counter file per backend, bumped after every
	// successful recreation; the broker reads it (read-only) to tell a real
	// reset from a restart staged inside the backend.
	GenerationDir string
	// Recreate recreates one backend service; defaults to docker compose.
	Recreate func(ctx context.Context, service string) error
	// Reset includes generation checking and advancement under the host's
	// lifecycle lock. Production uses this whole-cell operation.
	Reset             func(context.Context, string, *uint64) error
	RequireGeneration bool
}

// NewBackendRecycler monitors the instance, including while HiFi is disabled.
// A later live enable must have a host-side recycler before accepting sessions.
func NewBackendRecycler(cfg *config.Config) (*BackendRecycler, error) {
	logDir, err := sshBrokerLogDir(cfg)
	if err != nil {
		return nil, err
	}
	r := &BackendRecycler{
		InstanceName:      cfg.InstanceName,
		ComposeFile:       cfg.GetDockerComposePath(),
		LogPath:           filepath.Join(logDir, "sessions.json"),
		GenerationDir:     filepath.Join(cfg.DataPath, "honeypots", sshProxyHoneypot, "generations"),
		Services:          map[string]bool{},
		Poll:              500 * time.Millisecond,
		RequireGeneration: true,
	}
	for n := 1; n <= maxSSHBackends; n++ {
		r.Services[fmt.Sprintf("ssh-backend-%d", n)] = true
	}
	r.Recreate = r.composeRecreate
	r.Reset = r.resetCell
	return r, nil
}

func (r *BackendRecycler) composeRecreate(ctx context.Context, service string) error {
	lock, err := lockSSHCells(ctx, filepath.Dir(r.ComposeFile))
	if err != nil {
		return err
	}
	defer lock.Close()
	return r.composeRecreateLocked(ctx, service)
}

func (r *BackendRecycler) composeRecreateLocked(ctx context.Context, service string) error {
	if err := sshStoreReady(filepath.Dir(r.ComposeFile)); err != nil {
		return err
	}
	layout, err := readSSHLayout(r.ComposeFile, r.InstanceName)
	if err != nil {
		return err
	}
	members := layout.Groups[service]
	if !r.Services[service] || !containsSSHService(members, service) {
		return fmt.Errorf("SSH cell %q is not in the current owned layout", service)
	}
	if err := stopSSHServices(ctx, r.ComposeFile, members); err != nil {
		return err
	}
	drainSSHCaptures(ctx, filepath.Dir(r.ComposeFile), r.InstanceName, r.LogPath, members)
	if err := archiveSSHCellLogs(filepath.Dir(r.ComposeFile), members, r.generation(service)); err != nil {
		return err
	}
	if err := validateSSHLayoutImages(layout, HiFiImageRevision); err != nil {
		return err
	}
	if err := validateSSHRuntimeResources(ctx); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	args := append([]string{"compose", "-f", r.ComposeFile, "up", "-d", "--force-recreate", "--no-deps", "--wait", "--wait-timeout", "150"}, members...)
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = filepath.Dir(r.ComposeFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("recreate %s: %w: %s", service, err, out)
	}
	return nil
}

func containsSSHService(members []string, service string) bool {
	for _, member := range members {
		if member == service {
			return true
		}
	}
	return false
}

func (r *BackendRecycler) generation(service string) uint64 {
	if sshCellApp(service) != service {
		return 0
	}
	data, err := os.ReadFile(filepath.Join(r.GenerationDir, service))
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	return n
}

func (r *BackendRecycler) resetCell(ctx context.Context, service string, expected *uint64) error {
	lock, err := lockSSHCells(ctx, filepath.Dir(r.ComposeFile))
	if err != nil {
		return err
	}
	defer lock.Close()
	if expected != nil && r.generation(service) != *expected {
		// Both older and impossible future tags are stale authority. Only a
		// new broker's capture of the actual counter can recover a rollback.
		return nil
	}
	// A saved Compose file is not evidence the operator wants it running.
	// Stop leaves that file in place; delayed session/startup records must not
	// restart the graph after its broker was successfully stopped.
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	probe := exec.CommandContext(probeCtx, "docker", "compose", "-f", r.ComposeFile, "ps", "--all", "--format", "json", sshProxyHoneypot)
	probe.Dir = filepath.Dir(r.ComposeFile)
	output, err := probe.CombinedOutput()
	if err != nil {
		return fmt.Errorf("check ingress broker before cell reset: %w: %s", err, output)
	}
	if !strings.EqualFold(parseComposePS(output)[sshProxyHoneypot].State, "running") {
		return nil
	}
	if err := r.composeRecreateLocked(ctx, service); err != nil {
		return err
	}
	return bumpGeneration(r.GenerationDir, service)
}

type recycleRequest struct {
	Service    string
	Generation *uint64
}

// Run consumes bounded reset requests until ctx ends. Production requires
// trusted generation tags; the startup-quarantined broker requests its first
// reset explicitly, so merely rendering a configuration cannot start a cell.
func (r *BackendRecycler) Run(ctx context.Context) {
	var previous os.FileInfo
	r.run(ctx, func(path string, offset int64, partial []byte) (int64, []byte, [][]byte, error) {
		return readBrokerLog(path, offset, partial, &previous)
	}, slog.Default())
}

// run keeps the transport and logger explicit so finite error/recovery tests
// can exercise the production retry/cursor/reset loop on every supported OS.
func (r *BackendRecycler) run(ctx context.Context, readLog func(string, int64, []byte) (int64, []byte, [][]byte, error), logger *slog.Logger) {
	queue := make(chan recycleRequest, len(r.Services)*4+4)
	busy := map[string]recycleRequest{}
	pending := map[string]recycleRequest{}
	enqueue := func(request recycleRequest) {
		s := request.Service
		if !r.Services[s] || (r.RequireGeneration && request.Generation == nil) {
			return
		}
		if request.Generation != nil && r.generation(s) != *request.Generation {
			return
		}
		if current, ok := busy[s]; ok {
			// A new broker can capture the just-bumped generation before the
			// worker reports done. Preserve its newer one-shot startup request.
			if request.Generation != nil && current.Generation != nil && *request.Generation > *current.Generation {
				if old, found := pending[s]; !found || old.Generation == nil || *request.Generation > *old.Generation {
					pending[s] = request
				}
			}
			return
		}
		busy[s] = request
		queue <- request
	}
	done := make(chan string, cap(queue))
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case request := <-queue:
				s := request.Service
				var err error
				if r.Reset != nil {
					err = r.Reset(ctx, s, request.Generation)
				} else {
					err = r.Recreate(ctx, s)
					if err == nil {
						err = bumpGeneration(r.GenerationDir, s)
					}
				}
				if err != nil {
					logger.Warn("HiFi backend recycle failed; the broker keeps it out of rotation", "backend", s, "error", err)
				} else {
					logger.Info("HiFi cell reset request completed", "backend", s)
				}
				done <- s
			}
		}
	}()

	// Tagged startup requests can precede the control plane, so production
	// reads from the beginning. Old generations cannot reset fresh active cells.
	var offset int64
	if !r.RequireGeneration {
		if st, err := os.Stat(r.LogPath); err == nil {
			offset = st.Size()
		}
		for s := range r.Services {
			enqueue(recycleRequest{Service: s})
		}
	}
	var partial []byte
	unreadable := false
	t := time.NewTicker(r.Poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case s := <-done:
			delete(busy, s)
			if request, ok := pending[s]; ok {
				delete(pending, s)
				enqueue(request)
			}
			continue
		case <-t.C:
		}
		nextOffset, nextPartial, lines, err := readLog(r.LogPath, offset, partial)
		if err != nil {
			// A log absent before broker startup is expected. Keep an active
			// failure latched across an absent/replaced file until real read
			// success, and never consume data or reset authority on failure.
			if !errors.Is(err, os.ErrNotExist) && !unreadable {
				logger.Warn(hostsetup.E("QP-INST-014").Error(), "instance", r.InstanceName, "error", err)
				unreadable = true
			}
			continue
		}
		if unreadable {
			logger.Info("SSH recycler broker metadata is readable again", "code", "QP-INST-014", "instance", r.InstanceName)
			unreadable = false
		}
		offset, partial = nextOffset, nextPartial

		for _, l := range lines {
			if request := parseRecycleRequest(l); request.Service != "" {
				enqueue(request)
			}
		}
	}
}

// readNewLines returns the complete lines appended to path since offset. A
// shrunken file (rotation/truncation) is re-read from the start.
func readNewLines(path string, offset int64, partial []byte) (int64, []byte, [][]byte) {
	next, part, lines, _ := readNewLinesDetailed(path, offset, partial)
	return next, part, lines
}

func readNewLinesDetailed(path string, offset int64, partial []byte) (int64, []byte, [][]byte, error) {
	return readBrokerLog(path, offset, partial, nil)
}

// Track the identity returned by the same open handle that supplied the bytes.
// Windows path-based FileInfo IDs can resolve lazily after a rename; f.Stat
// captures the opened object's identity. Failed reads never replace this state.
func readBrokerLog(path string, offset int64, partial []byte, previous *os.FileInfo) (int64, []byte, [][]byte, error) {
	originalOffset, originalPartial := offset, partial
	listed, err := os.Lstat(path)
	if err != nil {
		return originalOffset, originalPartial, nil, err
	}
	if !listed.Mode().IsRegular() {
		return originalOffset, originalPartial, nil, errors.New("broker metadata is not an ordinary file")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|brokerLogReadFlags, 0)
	if err != nil {
		return originalOffset, originalPartial, nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	current, currentErr := os.Lstat(path)
	if err != nil {
		return originalOffset, originalPartial, nil, err
	}
	if currentErr != nil {
		return originalOffset, originalPartial, nil, currentErr
	}
	if !opened.Mode().IsRegular() || !current.Mode().IsRegular() || !os.SameFile(listed, opened) || !os.SameFile(current, opened) {
		return originalOffset, originalPartial, nil, errors.New("broker metadata changed while opening")
	}
	if previous != nil && *previous != nil && !os.SameFile(*previous, opened) {
		offset, partial = 0, nil
	}
	if opened.Size() < offset {
		offset, partial = 0, nil
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return originalOffset, originalPartial, nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, 4<<20))
	if err != nil {
		return originalOffset, originalPartial, nil, err
	}
	offset += int64(len(data))
	// Do not let append reuse a caller's cursor buffer before read success.
	buf := append(append([]byte(nil), partial...), data...)
	var lines [][]byte
	for {
		i := bytes.IndexByte(buf, '\n')
		if i < 0 {
			break
		}
		if line := bytes.TrimSpace(buf[:i]); len(line) > 0 {
			lines = append(lines, append([]byte(nil), line...))
		}
		buf = buf[i+1:]
	}
	if len(buf) > 1<<20 {
		buf = nil
	}
	if previous != nil {
		*previous = opened
	}
	return offset, append([]byte(nil), buf...), lines, nil
}

// recycleTarget returns the backend a session-log line says must be recycled,
// or "". Only the broker's cell reset request counts: a cell outlives the
// connections of the source that holds it, so a finished connection or a
// failed dial alone must not recreate it under its source's other connections.
func recycleTarget(line []byte) string {
	return parseRecycleRequest(line).Service
}

func parseRecycleRequest(line []byte) recycleRequest {
	var ev struct {
		EventType  string  `json:"event_type"`
		Backend    string  `json:"backend"`
		Generation *uint64 `json:"generation"`
	}
	if json.Unmarshal(line, &ev) != nil {
		return recycleRequest{}
	}
	if ev.EventType != proxy.EventCellReset {
		return recycleRequest{}
	}
	return recycleRequest{Service: ev.Backend, Generation: ev.Generation}
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
