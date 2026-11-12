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
	"maps"
	"os"
	"path"
	"slices"
	"strconv"
	"time"
)

// Limits on what one container's capture can make the host keep. The stream
// is the guest's sshd's, and guest root can write to it: every count and name
// in it is untrusted, so the per-account limits sit inside limits for the
// whole container that no account or session number can get round. Bytes
// count everything written: streams, timing lines and record lines alike.
// Sessions open when a limit is reached may still add their finish lines.
//
// A cell should not get to a limit while it serves a visitor: the last eighth
// of every limit is a reserve. Once an account or the container is inside
// it, Full says so and the follower stops the cell (Converter.Retire).
//
// Nobody stops a cell while the control plane is down, and what its visitor
// runs then waits in the container's log to be converted later. So a session
// that no longer fits the limits is not dropped: it keeps its record (who,
// when, the command, its exit status and the first bytes of each stream) in
// the account's overflow file, one file however many sessions, within an
// allowance of its own. Only a session past that allowance, or past what is
// held in memory, leaves nothing. The allowance covers what the capture
// budgets of a visitor's three connections hold of ordinary commands;
// thousands of very long commands or binary output can use it up.
const (
	maxUserBytes      = 64 << 20
	maxUserFiles      = 2048
	maxContainerBytes = 256 << 20
	maxContainerFiles = 8192
	maxAccounts       = 64      // account folders per container
	maxOpen           = 256     // pending commands, and open sessions, held in memory
	maxSessions       = 1 << 16 // distinct sessions per container
	maxCommand        = 16 << 10
	previewBytes      = 4096
	filesPerEntry     = 5
	// maxOverflowBytes bounds the record lines of sessions past the other
	// limits, for the whole container; overflowName is their file in an
	// account's folder.
	maxOverflowBytes = 128 << 20
	overflowName     = "overflow.json"

	reserveShare       = 8
	softUserBytes      = maxUserBytes - maxUserBytes/reserveShare
	softUserFiles      = maxUserFiles - maxUserFiles/reserveShare
	softContainerBytes = maxContainerBytes - maxContainerBytes/reserveShare
	softContainerFiles = maxContainerFiles - maxContainerFiles/reserveShare
	softAccounts       = maxAccounts - maxAccounts/reserveShare
	softOpen           = maxOpen - maxOpen/reserveShare
	softSessions       = maxSessions - maxSessions/reserveShare
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
	UID              int64   `json:"uid"`
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
	// Visitor: the session belongs to the lease's visitor, but no single
	// connection of its can be named (SrcPort and SessionID are empty).
	Visitor bool
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
	usage    map[int64]*usage
	total    usage
	full     string // which limit's reserve was reached first; "" while none
	// overflowBytes counts the overflow lines this replay has produced;
	// overflow holds what is known of each account's overflow file.
	overflowBytes int64
	overflow      map[int64]*overflowFile
}

// overflowFile is one account's overflow file as this writer knows it.
//
// The lines it holds are remembered, so that a line is appended once. That
// memory is only as good as the last look at the file: between two batches
// the follower lets go of the folder, and a reset's drain, which is another
// writer over the same stream, may append to the file meanwhile. (Found by
// the capture soak: a drain that timed out half-way left lines the follower
// did not know of, and the follower wrote them a second time.) So the file
// is read again, from where the last look ended, each time it is opened, and
// it is opened anew after every Flush.
type overflowFile struct {
	have  map[string]bool // session and phase of the lines the file holds
	whole int64           // the file up to here is whole lines, all in have
	torn  bool            // past whole, the file ends in part of a line
	f     *os.File        // open for appending until the next Flush
	dirty bool            // written since it was opened
}

// Full names the limit this container's capture has come within the reserve
// of, or "" while it is inside all of them. It never clears: the container's
// capture only grows.
func (w *Writer) Full() string { return w.full }

func (w *Writer) fill(limit string) {
	if w.full == "" {
		w.full = limit
	}
}

// check marks the capture full once an account (u, when known) or the
// container is inside a limit's reserve.
func (w *Writer) check(u *usage) {
	switch {
	case w.full != "":
	case u != nil && u.files > softUserFiles:
		w.full = "files kept for one account"
	case u != nil && u.bytes > softUserBytes:
		w.full = "bytes kept for one account"
	case w.total.files > softContainerFiles:
		w.full = "files kept for the cell"
	case w.total.bytes > softContainerBytes:
		w.full = "bytes kept for the cell"
	case len(w.usage) > softAccounts:
		w.full = "accounts with sessions"
	case len(w.active) > softOpen || len(w.pending) > softOpen:
		w.full = "sessions open at once"
	case len(w.ordinals) > softSessions:
		w.full = "sessions in the cell's life"
	}
}

type command struct {
	text      []byte
	truncated bool
}

type usage struct {
	bytes    int64
	files    int
	overflow bool // the account's overflow file is counted in files
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
	overflow  bool            // its record goes to the account's overflow file
	previews  map[Kind][]byte // an overflow session's first bytes per stream
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
		pending: map[string]*command{}, active: map[string]*entry{}, ordinals: map[string]int{}, usage: map[int64]*usage{},
		overflow: map[int64]*overflowFile{}}, nil
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
				w.fill("sessions open at once")
				return nil
			}
			c = &command{}
			w.pending[key] = c
			w.check(nil)
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
			w.check(nil)
		} else {
			w.fill("sessions open at once")
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
		err := w.data(e, r)
		w.check(e.user)
		return err
	case KindTruncated:
		e.truncated = true
	case KindExit:
		if exit, err := ParseExit(r.Payload); err == nil {
			e.exit = &exit
		}
	case KindClosed:
		err := w.finish(e, r.Millis)
		delete(w.active, key)
		w.check(e.user)
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
		(u == nil && len(w.usage) >= maxAccounts) {
		// Past what is held in memory for one container: no honest sshd
		// opens this many sessions at once or names this many accounts.
		w.fill("a session past the cell's limits")
		return nil
	}
	if u == nil {
		u = &usage{}
		w.usage[o.UID] = u
	}
	// Inside a reserve the session keeps its record only, in the account's
	// overflow file.
	overflow := ""
	switch {
	case u.files+filesPerEntry > softUserFiles:
		overflow = "files kept for one account"
	case w.total.files+filesPerEntry > softContainerFiles:
		overflow = "files kept for the cell"
	case u.bytes >= softUserBytes:
		overflow = "bytes kept for one account"
	case w.total.bytes >= softContainerBytes:
		overflow = "bytes kept for the cell"
	}
	if overflow != "" {
		w.fill(overflow)
		if w.overflowBytes >= maxOverflowBytes {
			return nil // past everything one container may make the host keep
		}
	}
	defer func() { w.check(u) }()
	w.ordinals[key]++
	sum := sha256.Sum256([]byte(w.container + "/" + key + "/" + strconv.Itoa(w.ordinals[key])))
	id := hex.EncodeToString(sum[:16])
	start := time.UnixMilli(o.TimeMillis).UTC()
	prefix := start.Format("20060102T150405Z") + "-" + id
	dir := "uid-" + strconv.FormatInt(o.UID, 10)
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
			if a.Visitor {
				e.event.Attribution = "broker-visitor"
			}
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
	if overflow != "" {
		e.overflow = true
		e.previews = map[Kind][]byte{}
		e.errs = append(e.errs, "account capture limit reached")
		// No stream files exist for it.
		e.event.StdoutFile, e.event.StderrFile, e.event.InputFile, e.event.TimingFile = "", "", "", ""
		e.event.StdinRecorded = false
		if !u.overflow {
			u.overflow = true
			u.files++
			w.total.files++
		}
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
	if e.overflow {
		// Only the first bytes of each stream, held in memory for the
		// finish line.
		if room := previewBytes - len(e.previews[r.Kind]); room > 0 {
			e.previews[r.Kind] = append(e.previews[r.Kind], r.Payload[:min(len(r.Payload), room)]...)
		}
		e.truncated = true
		e.lastMS = max(e.lastMS, r.Millis)
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
		if room := min(maxUserBytes-e.user.bytes, maxContainerBytes-w.total.bytes); int64(len(line)) > room {
			e.truncated = true // a timing line per byte must not outgrow the limits
			return nil
		}
		if _, err := timing.WriteAt([]byte(line), e.offsets[KindTruncated]); err != nil {
			e.errs = append(e.errs, "timing write failed")
		}
		e.offsets[KindTruncated] += int64(len(line))
		e.user.bytes += int64(len(line))
		w.total.bytes += int64(len(line))
	}
	return nil
}

func (w *Writer) finish(e *entry, millis int64) error {
	defer w.close(e)
	// Built and counted even when another replay already wrote it, so every
	// replay of the container makes the same limit decisions.
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
	if e.overflow {
		ev.Stdout, ev.Stderr = string(e.previews[KindOutput]), string(e.previews[KindError])
		if ev.Input == "" && !e.event.CommandTruncated {
			ev.Input = string(e.previews[KindInput])
		}
		ev.Truncated = true // its streams were not kept
	} else {
		ev.Stdout = w.preview(e.base + ".out")
		ev.Stderr = w.preview(e.base + ".err")
		if ev.Input == "" && !e.event.CommandTruncated {
			ev.Input = w.preview(e.base + ".in")
		}
		ev.Truncated = e.truncated
	}
	if len(e.errs) > 0 {
		ev.CaptureError = joinErrors(e.errs)
	}
	return w.appendLine(e, ev, 1)
}

// Finish ends the stream: sessions whose exit was captured are finished,
// others keep only their start record, as after an abrupt teardown.
func (w *Writer) Finish() error {
	var errs []error
	// In a fixed order, so every replay writes the same lines the same way.
	for _, key := range slices.Sorted(maps.Keys(w.active)) {
		e := w.active[key]
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
// What was appended to the overflow files reaches the disk here, once for
// the batch instead of once per line.
func (w *Writer) Flush() error {
	for _, e := range w.active {
		w.close(e)
	}
	var errs []error
	for _, o := range w.overflow {
		if o.f == nil {
			continue
		}
		if o.dirty {
			errs = append(errs, o.f.Sync())
		}
		errs = append(errs, o.f.Close())
		o.f, o.dirty = nil, false
	}
	if w.root != nil {
		errs = append(errs, w.root.Close())
		w.root = nil
	}
	return errors.Join(errs...)
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
// the file already holds it. The line counts against the limits either way.
func (w *Writer) appendLine(e *entry, ev SessionEvent, index int) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	if e.overflow {
		return w.appendOverflow(ev, data)
	}
	e.user.bytes += int64(len(data) + 1)
	w.total.bytes += int64(len(data) + 1)
	if n, err := w.existingLines(e.base + ".json"); err != nil || n != index {
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

// appendOverflow adds one record line to its account's overflow file unless
// the file holds that session's line for that phase already. Lines are told
// apart by session and phase, not by their place in the file: sessions end
// in an order that a follower cut off mid-stream need not share with the
// replay that follows it.
func (w *Writer) appendOverflow(ev SessionEvent, data []byte) error {
	w.overflowBytes += int64(len(data) + 1)
	o, err := w.openOverflow(ev.UID)
	if err != nil {
		return err
	}
	key := ev.Session + "/" + ev.Phase
	if o.have[key] {
		return nil
	}
	line := make([]byte, 0, len(data)+2)
	if o.torn {
		// The file ends in part of a line (a write the disk had no room
		// for): end it, so this line does not continue it.
		line = append(line, '\n')
	}
	line = append(append(line, data...), '\n')
	if _, err := o.f.Write(line); err != nil {
		// Whatever reached the file is read again before the next line.
		_ = o.f.Close()
		delete(w.overflow, ev.UID)
		return err
	}
	info, err := o.f.Stat()
	if err != nil {
		_ = o.f.Close()
		delete(w.overflow, ev.UID)
		return err
	}
	o.have[key] = true
	o.whole, o.torn, o.dirty = info.Size(), false, true
	return nil
}

// openOverflow returns an account's overflow file, open for appending, with
// everything the file holds now in its memory.
func (w *Writer) openOverflow(uid int64) (*overflowFile, error) {
	o := w.overflow[uid]
	if o != nil && o.f != nil {
		return o, nil
	}
	root, err := w.ensureRoot()
	if err != nil {
		return nil, err
	}
	name := path.Join("uid-"+strconv.FormatInt(uid, 10), overflowName)
	f, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if o == nil || info.Size() < o.whole {
		// Not seen before, or shorter than what was seen: another file.
		o = &overflowFile{have: map[string]bool{}}
	}
	// What is past the last whole line this writer knows of: nothing, the
	// torn end it knows, or lines another writer has appended.
	whole, torn, err := scanOverflow(io.NewSectionReader(f, o.whole, info.Size()-o.whole), o.have)
	if err != nil {
		_ = f.Close()
		delete(w.overflow, uid)
		return nil, err
	}
	o.whole, o.torn, o.f, o.dirty = o.whole+whole, torn, f, false
	w.overflow[uid] = o
	return o, nil
}

// scanOverflow adds the sessions' lines r holds to have, and returns how many
// bytes of r are whole lines and whether it ends in part of one. A line that
// is not a record is skipped. A last line that lacks only its newline is a
// record like any other (a record cut short does not parse): counting it as
// missing would write it a second time.
func scanOverflow(r io.Reader, have map[string]bool) (whole int64, torn bool, err error) {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			ended := line[len(line)-1] == '\n'
			var ev struct {
				Session string `json:"session"`
				Phase   string `json:"phase"`
			}
			if json.Unmarshal(line, &ev) == nil && ev.Session != "" {
				have[ev.Session+"/"+ev.Phase] = true
			}
			if ended {
				whole += int64(len(line))
			} else {
				torn = true
			}
		}
		if errors.Is(err, io.EOF) {
			return whole, torn, nil
		}
		if err != nil {
			return 0, false, err
		}
	}
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
