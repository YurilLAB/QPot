package sshcapture

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strconv"
	"time"
)

// Limits on what one container's capture can make the host keep. The stream
// is the guest's sshd's, and guest root can write to it: every count and name
// in it is untrusted, so the per-account limits sit inside limits for the
// whole container that no account or session number can get round.
const (
	maxUserBytes      = 64 << 20
	maxUserFiles      = 2048
	maxContainerBytes = 256 << 20
	maxContainerFiles = 8192
	maxAccounts       = 64      // account folders per container
	maxOpen           = 1024    // pending commands, and open sessions, held in memory
	maxSessions       = 1 << 16 // distinct sessions per container
	maxCommand        = 16 << 10
	previewBytes      = 4096
	filesPerEntry     = 5
)

// SessionEvent is one line of a command's .json record. Field names and
// meanings are the collector's contract (compose.go's ssh_backend_logs).
type SessionEvent struct {
	Timestamp        string  `json:"timestamp"`
	EventType        string  `json:"event_type"`
	Phase            string  `json:"phase"`
	Session          string  `json:"session"`
	SessionID        string  `json:"session_id,omitempty"`
	Generation       *uint64 `json:"generation,omitempty"`
	PeerIP           string  `json:"peer_ip,omitempty"`
	PeerPort         int     `json:"peer_port,omitempty"`
	Attribution      string  `json:"attribution"`
	AttributionError string  `json:"attribution_error,omitempty"`
	Username         string  `json:"username"`
	UID              int     `json:"uid"`
	Hostname         string  `json:"hostname"`
	SrcIP            string  `json:"src_ip,omitempty"`
	SrcPort          int     `json:"src_port,omitempty"`
	Input            string  `json:"input,omitempty"`
	CommandTruncated bool    `json:"command_truncated,omitempty"`
	PTY              bool    `json:"pty"`
	ExitCode         *int    `json:"exit_code,omitempty"`
	DurationMS       int64   `json:"duration_ms"`
	StdoutFile       string  `json:"stdout_file"`
	StderrFile       string  `json:"stderr_file,omitempty"`
	InputFile        string  `json:"input_file,omitempty"`
	StdinRecorded    bool    `json:"stdin_recorded"`
	TimingFile       string  `json:"timing_file,omitempty"`
	Stdout           string  `json:"stdout,omitempty"`
	Stderr           string  `json:"stderr,omitempty"`
	Truncated        bool    `json:"truncated,omitempty"`
	CaptureError     string  `json:"capture_error,omitempty"`
}

// Attribution is what the broker knew about the connection that reached the
// backend: the visitor's own address and the lease.
type Attribution struct {
	SrcIP      string
	SrcPort    int
	SessionID  string
	Generation *uint64
}

// Attributor finds the broker connection behind a session, or reports none.
// since is the container's creation: a connection before it belonged to an
// earlier lease of the cell, so a forged record cannot name that visitor.
type Attributor func(o Open, since time.Time) (Attribution, bool)

// Writer turns one container's capture into evidence files in dir (a cell
// service's current log folder). Feeding it the container's whole capture
// always produces the same files: command ids derive from the container and
// the order of sessions, stream bytes are written at their own offsets, and
// a record line is appended only when the file does not hold it yet. Two
// writers replaying the same container in turns (a live follower and a
// reset's drain, each under the cells lock) therefore converge on the same
// files, whatever their order. Between Flush calls it holds no handle in
// dir, so a reset may archive the folder even on Windows.
type Writer struct {
	dir       string
	root      *os.Root // opened on demand, closed by Flush
	container string
	created   time.Time
	attribute Attributor

	pending  map[string]*command // command bytes before their open record
	active   map[string]*entry
	ordinals map[string]int
	usage    map[int]*usage
	total    usage
}

type command struct {
	text      []byte
	truncated bool
}

type usage struct {
	bytes int64
	files int
}

type entry struct {
	event     SessionEvent
	base      string // uid-N/<prefix>, slash separated
	start     time.Time
	files     map[Kind]*os.File // open until the next Flush
	offsets   map[Kind]int64    // where each stream's next byte goes
	streams   bool              // the stream files exist (not over a limit)
	lastMS    int64
	exit      *Exit
	limited   bool
	truncated bool
	errs      []string
	user      *usage
}

// NewWriter writes into dir for the container with the given Docker id,
// created at the given time.
func NewWriter(dir, containerID string, created time.Time, attribute Attributor) (*Writer, error) {
	if len(containerID) < 12 {
		return nil, errors.New("capture writer needs the container id")
	}
	if info, err := os.Stat(dir); err != nil {
		return nil, err
	} else if !info.IsDir() {
		return nil, errors.New("capture folder is not a directory")
	}
	return &Writer{dir: dir, container: containerID, created: created, attribute: attribute,
		pending: map[string]*command{}, active: map[string]*entry{}, ordinals: map[string]int{}, usage: map[int]*usage{}}, nil
}

// Apply consumes one capture line. Lines that are not records are ignored:
// the stream is the backend's own output, never the visitor's.
func (w *Writer) Apply(line []byte) error {
	r, err := ParseRecord(line)
	if err != nil {
		return nil
	}
	key := r.Conn + "/" + strconv.Itoa(r.Channel)
	switch r.Kind {
	case KindCommand:
		c := w.pending[key]
		if c == nil {
			if len(w.pending) >= maxOpen {
				return nil
			}
			c = &command{}
			w.pending[key] = c
		}
		if room := maxCommand - len(c.text); room > 0 {
			c.text = append(c.text, r.Payload[:min(len(r.Payload), room)]...)
		} else {
			c.truncated = true
		}
		return nil
	case KindCommandTruncated:
		if c := w.pending[key]; c != nil {
			c.truncated = true
		} else if len(w.pending) < maxOpen {
			w.pending[key] = &command{truncated: true}
		}
		return nil
	case KindOpen:
		return w.open(key, r)
	}
	e := w.active[key]
	if e == nil {
		return nil // its open record is gone (rotated out): nothing to attach to
	}
	switch r.Kind {
	case KindInput, KindOutput, KindError:
		return w.data(e, r)
	case KindTruncated:
		e.truncated = true
	case KindExit:
		if exit, err := ParseExit(r.Payload); err == nil {
			e.exit = &exit
		}
	case KindClosed:
		err := w.finish(e, r.Millis)
		delete(w.active, key)
		return err
	}
	return nil
}

func (w *Writer) open(key string, r Record) error {
	o, err := ParseOpen(r.Payload)
	if err != nil {
		return nil
	}
	if old := w.active[key]; old != nil {
		// A new session on a channel whose close never arrived.
		w.close(old)
		delete(w.active, key)
	}
	cmd := w.pending[key]
	delete(w.pending, key)
	u := w.usage[o.UID]
	if len(w.active) >= maxOpen || (w.ordinals[key] == 0 && len(w.ordinals) >= maxSessions) ||
		(u == nil && len(w.usage) >= maxAccounts) || w.total.files >= maxContainerFiles {
		return nil // past what one container may make the host keep
	}
	if u == nil {
		u = &usage{}
		w.usage[o.UID] = u
	}
	if u.files >= maxUserFiles {
		return nil
	}
	w.ordinals[key]++
	sum := sha256.Sum256([]byte(w.container + "/" + key + "/" + strconv.Itoa(w.ordinals[key])))
	id := hex.EncodeToString(sum[:16])
	start := time.UnixMilli(o.TimeMillis).UTC()
	prefix := start.Format("20060102T150405Z") + "-" + id
	dir := "uid-" + strconv.Itoa(o.UID)
	e := &entry{base: path.Join(dir, prefix), start: start, files: map[Kind]*os.File{}, offsets: map[Kind]int64{}}
	e.event = SessionEvent{
		Timestamp: start.Format(time.RFC3339Nano), EventType: "ssh_backend_command_start", Phase: "start",
		Session: id, PeerIP: o.PeerIP, PeerPort: o.PeerPort, Attribution: "peer-only",
		Username: o.Username, UID: o.UID, Hostname: o.Hostname, SrcIP: o.PeerIP, SrcPort: o.PeerPort, PTY: o.PTY,
		StdoutFile: prefix + ".out", StderrFile: prefix + ".err", InputFile: prefix + ".in", StdinRecorded: true,
	}
	if o.PTY {
		e.event.TimingFile = prefix + ".timing"
	}
	if cmd != nil {
		e.event.Input = string(cmd.text)
		e.event.CommandTruncated = cmd.truncated
	}
	if w.attribute != nil {
		if a, ok := w.attribute(o, w.created); ok {
			e.event.SrcIP, e.event.SrcPort = a.SrcIP, a.SrcPort
			e.event.SessionID, e.event.Generation = a.SessionID, a.Generation
			e.event.Attribution = "broker-cell"
		}
	}
	root, err := w.ensureRoot()
	if err != nil {
		return err
	}
	if err := root.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := root.Chmod(dir, 0o700); err != nil {
		return err
	}
	e.user = u
	if u.files+filesPerEntry > maxUserFiles || w.total.files+filesPerEntry > maxContainerFiles {
		// The record alone, which counts as one file.
		e.limited = true
		e.errs = append(e.errs, "account capture limit reached")
		u.files++
		w.total.files++
	} else {
		u.files += filesPerEntry
		w.total.files += filesPerEntry
		e.streams = true
		suffixes := []string{".out", ".err", ".in"}
		if o.PTY {
			suffixes = append(suffixes, ".timing")
		}
		for _, suffix := range suffixes {
			// Created empty at the start. An existing file is another
			// writer's replay of these same bytes: kept, and overwritten
			// in place with identical content.
			f, err := root.OpenFile(e.base+suffix, os.O_WRONLY|os.O_CREATE, 0o600)
			if err != nil {
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		}
	}
	if err := w.appendLine(e, e.event, 0); err != nil {
		w.close(e)
		return err
	}
	w.active[key] = e
	return nil
}

func (w *Writer) data(e *entry, r Record) error {
	if e.limited {
		e.truncated = true
		return nil
	}
	f, err := w.stream(e, r.Kind)
	if err != nil {
		e.errs = append(e.errs, "stream open failed")
		e.truncated = true
		return nil
	}
	keep := int64(len(r.Payload))
	if room := min(maxUserBytes-e.user.bytes, maxContainerBytes-w.total.bytes); keep > room {
		keep = max(room, 0)
		e.truncated = true
		if keep == 0 {
			return nil
		}
	}
	if _, err := f.WriteAt(r.Payload[:keep], e.offsets[r.Kind]); err != nil {
		e.errs = append(e.errs, "stream write failed")
		e.truncated = true
		return nil
	}
	e.offsets[r.Kind] += keep
	e.user.bytes += keep
	w.total.bytes += keep
	if e.event.PTY && r.Kind != KindError {
		timing, err := w.stream(e, KindTruncated) // the timing file's slot
		if err != nil {
			e.errs = append(e.errs, "timing open failed")
			return nil
		}
		stream := "O"
		if r.Kind == KindInput {
			stream = "I"
		}
		delta := r.Millis - e.lastMS
		if delta < 0 {
			delta = 0
		}
		e.lastMS = r.Millis
		line := fmt.Sprintf("%s %d.%03d000 %d\n", stream, delta/1000, delta%1000, keep)
		if _, err := timing.WriteAt([]byte(line), e.offsets[KindTruncated]); err != nil {
			e.errs = append(e.errs, "timing write failed")
		}
		e.offsets[KindTruncated] += int64(len(line))
	}
	return nil
}

func (w *Writer) finish(e *entry, millis int64) error {
	defer w.close(e)
	if n, err := w.existingLines(e.base + ".json"); err != nil || n >= 2 {
		return err // finished already, by this replay's twin
	}
	ev := e.event
	ev.EventType, ev.Phase = "ssh_backend_command", "finish"
	ev.Timestamp = e.start.Add(time.Duration(millis) * time.Millisecond).Format(time.RFC3339Nano)
	ev.DurationMS = millis
	if e.exit != nil {
		code := e.exit.Code
		ev.ExitCode = &code
	} else {
		e.errs = append(e.errs, "exit status not captured")
	}
	for _, f := range e.files {
		_ = f.Sync()
	}
	ev.Stdout = w.preview(e.base + ".out")
	ev.Stderr = w.preview(e.base + ".err")
	if ev.Input == "" && !e.event.CommandTruncated {
		ev.Input = w.preview(e.base + ".in")
	}
	ev.Truncated = e.truncated
	if len(e.errs) > 0 {
		ev.CaptureError = joinErrors(e.errs)
	}
	return w.appendLine(e, ev, 1)
}

// Finish ends the stream: sessions whose exit was captured are finished,
// others keep only their start record, as after an abrupt teardown.
func (w *Writer) Finish() error {
	var errs []error
	for key, e := range w.active {
		if e.exit != nil {
			errs = append(errs, w.finish(e, e.lastMS))
		} else {
			w.close(e)
		}
		delete(w.active, key)
	}
	errs = append(errs, w.Flush())
	return errors.Join(errs...)
}

// Flush closes every handle in the folder; the next write reopens them.
func (w *Writer) Flush() error {
	for _, e := range w.active {
		w.close(e)
	}
	if w.root == nil {
		return nil
	}
	err := w.root.Close()
	w.root = nil
	return err
}

func (w *Writer) ensureRoot() (*os.Root, error) {
	if w.root == nil {
		root, err := os.OpenRoot(w.dir)
		if err != nil {
			return nil, err
		}
		w.root = root
	}
	return w.root, nil
}

// stream returns a write handle to one of an entry's stream files.
func (w *Writer) stream(e *entry, kind Kind) (*os.File, error) {
	if f := e.files[kind]; f != nil {
		return f, nil
	}
	if !e.streams {
		return nil, errors.New("no stream files")
	}
	suffix := map[Kind]string{KindOutput: ".out", KindError: ".err", KindInput: ".in", KindTruncated: ".timing"}[kind]
	root, err := w.ensureRoot()
	if err != nil {
		return nil, err
	}
	f, err := root.OpenFile(e.base+suffix, os.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}
	e.files[kind] = f
	return f, nil
}

// Discard closes everything without writing: the folder was drained and
// archived by a reset, which already wrote the complete records.
func (w *Writer) Discard() {
	for key, e := range w.active {
		w.close(e)
		delete(w.active, key)
	}
	_ = w.Flush()
}

func (w *Writer) close(e *entry) {
	for _, f := range e.files {
		_ = f.Close()
	}
	e.files = map[Kind]*os.File{}
}

// appendLine writes a record's line number index (0 start, 1 finish) unless
// the file already holds it.
func (w *Writer) appendLine(e *entry, ev SessionEvent, index int) error {
	if n, err := w.existingLines(e.base + ".json"); err != nil || n != index {
		return err
	}
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	root, err := w.ensureRoot()
	if err != nil {
		return err
	}
	f, err := root.OpenFile(e.base+".json", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(append(data, '\n'))
	return errors.Join(werr, f.Sync(), f.Close())
}

func (w *Writer) existingLines(name string) (int, error) {
	root, err := w.ensureRoot()
	if err != nil {
		return 0, err
	}
	f, err := root.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := 0
	s := bufio.NewScanner(io.LimitReader(f, 1<<20))
	s.Buffer(make([]byte, 64<<10), 1<<20)
	for s.Scan() {
		if len(bytes.TrimSpace(s.Bytes())) > 0 {
			n++
		}
	}
	return n, s.Err()
}

func (w *Writer) preview(name string) string {
	root, err := w.ensureRoot()
	if err != nil {
		return ""
	}
	f, err := root.Open(name)
	if err != nil {
		return ""
	}
	defer f.Close()
	data, _ := io.ReadAll(io.LimitReader(f, previewBytes))
	return string(data)
}

func joinErrors(errs []string) string {
	out := ""
	for i, e := range errs {
		if i > 0 {
			out += "; "
		}
		out += e
	}
	return out
}
