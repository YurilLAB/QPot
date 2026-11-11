package database

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// An observation is one line a honeypot wrote. The collector gives each one
// an ID derived from the file, the byte offset the line starts at and its
// text, written as a version 8 UUID (see the Vector transforms in
// internal/instance). Reading the line again gives the same ID. Three things
// build on that:
//
//   - a batch the collector sends twice is the same batch, and the store keeps
//     it once (ClickHouse insert deduplication, a unique index on PostgreSQL);
//   - a line the collector READS twice (it lost its checkpoints, or was killed
//     between delivering a batch and noting it) arrives as a second row with
//     the same ID: ReplayRemover finds and deletes that row before it is
//     counted;
//   - the collector's log backups carry the ID, so a database can be rebuilt
//     from them without storing anything twice (EventRestorer).

// IsObservationID reports whether id has the shape of an ID the collector
// derives from a log line: a version 8 UUID with the first variant nibble. A
// random ID the database made for a row that came without one (version 4)
// does not, and nothing may be concluded from two rows sharing or not sharing
// such an ID.
func IsObservationID(id string) bool {
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}
	if id[14] != '8' || id[19] != '8' {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if c == '-' {
			continue
		}
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// observationID writes the first 32 hex digits of a SHA-256 as a version 8
// UUID, the way the collector does.
func observationID(sum [sha256.Size]byte) string {
	h := hex.EncodeToString(sum[:16])
	return h[0:8] + "-" + h[8:12] + "-8" + h[13:16] + "-8" + h[17:20] + "-" + h[20:32]
}

// ReplayRemover is implemented by the stores whose event rows carry the
// collector's observation ID.
type ReplayRemover interface {
	// RemoveReplayedEvents takes the unclassified events a worker has just
	// read, oldest first, and deletes from the store every one that is a
	// second copy of an observation: a copy of one that is already
	// classified, or a later copy of one earlier in events. It returns the
	// events left to classify, in order, and how many rows it named for
	// deletion (rows that were already gone are named all the same).
	//
	// It never deletes the only copy, and it is safe to run twice or from
	// two workers at once: which copy stays is decided by the rows alone.
	RemoveReplayedEvents(ctx context.Context, events []*Event) (kept []*Event, removed int, err error)
}

// EventRestorer is implemented by the stores that can take back events from
// the collector's log backups.
type EventRestorer interface {
	// RestoreEvents stores, unclassified and with their own time and
	// observation ID (Event.ID), the events whose observation is not stored
	// yet, and returns how many it stored. dryRun only counts.
	RestoreEvents(ctx context.Context, events []*Event, dryRun bool) (stored int, err error)
	// CountEvents returns how many event rows the store holds.
	CountEvents(ctx context.Context) (int64, error)
}

// replayPlan is the store-independent half of RemoveReplayedEvents for a
// store whose Event.ID is the observation ID. classified holds the IDs that
// already have a classified row.
type replayPlan struct {
	// keep are the events to classify.
	keep []*Event
	// remove are the rows to delete: each is unclassified and has another
	// row for the same observation that stays.
	remove []*Event
}

// planReplays decides, for events in reading order, which rows are second
// copies. Two unclassified rows with the same ID AND the same time cannot be
// told apart by any column, so neither is deleted: the second one is left out
// of keep (it is counted once) and both get their tags, since tagging is by
// ID and time.
func planReplays(events []*Event, classified map[string]bool) replayPlan {
	var p replayPlan
	first := make(map[string]time.Time, len(events))
	for _, e := range events {
		if e == nil {
			continue
		}
		if !IsObservationID(e.ID) {
			p.keep = append(p.keep, e)
			continue
		}
		if classified[e.ID] {
			p.remove = append(p.remove, e)
			continue
		}
		if at, seen := first[e.ID]; seen {
			if !at.Equal(e.Timestamp) {
				p.remove = append(p.remove, e)
			}
			continue
		}
		first[e.ID] = e.Timestamp
		p.keep = append(p.keep, e)
	}
	return p
}

// observationIDs returns the distinct observation IDs among events.
func observationIDs(events []*Event) []string {
	seen := make(map[string]bool, len(events))
	var ids []string
	for _, e := range events {
		if e != nil && IsObservationID(e.ID) && !seen[e.ID] {
			seen[e.ID] = true
			ids = append(ids, e.ID)
		}
	}
	return ids
}

// Backup lines and files are bounded so a damaged backup cannot exhaust
// memory: a line longer than the limit is skipped and counted.
const (
	maxBackupLine     = 4 << 20
	restoreBatchRows  = 2000
	restoreBatchBytes = 8 << 20
	maxBackupFiles    = 200000
)

// backupTimeLayouts are the forms the collector has written an event's time
// in.
var backupTimeLayouts = []string{
	"2006-01-02 15:04:05.000",
	"2006-01-02 15:04:05",
	"2006-01-02 15:04:05.000-07",
	time.RFC3339Nano,
}

// ParseBackupEvent reads one line of a collector log backup (the event as
// JSON, the way it was sent to the database). file and offset say where the
// line is, relative to the backup folder: a line from before events carried
// an ID gets one derived from that place and its text, so restoring the same
// backup twice still stores it once.
func ParseBackupEvent(line []byte, file string, offset int64) (*Event, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, err
	}
	str := func(key string) string {
		v, ok := raw[key]
		if !ok {
			return ""
		}
		var s string
		if json.Unmarshal(v, &s) == nil {
			return s
		}
		return ""
	}
	port := func(key string) int {
		v, ok := raw[key]
		if !ok {
			return 0
		}
		var n float64
		if json.Unmarshal(v, &n) != nil {
			var s string
			if json.Unmarshal(v, &s) != nil {
				return 0
			}
			f, err := strconv.ParseFloat(s, 64)
			if err != nil {
				return 0
			}
			n = f
		}
		if n < 0 || n > 65535 || n != float64(int(n)) {
			return 0
		}
		return int(n)
	}
	e := &Event{
		Honeypot:   str("honeypot"),
		SourceIP:   str("source_ip"),
		SourcePort: port("source_port"),
		DestPort:   port("dest_port"),
		Protocol:   str("protocol"),
		EventType:  str("event_type"),
		Username:   str("username"),
		Password:   str("password"),
		Command:    str("command"),
		Payload:    []byte(str("payload")),
		Country:    str("country"),
		City:       str("city"),
		ASN:        str("asn"),
	}
	if e.Honeypot == "" {
		return nil, errors.New("no honeypot")
	}
	ts := str("timestamp")
	parsed := false
	for _, layout := range backupTimeLayouts {
		if t, err := time.ParseInLocation(layout, ts, time.UTC); err == nil {
			e.Timestamp, parsed = t.UTC(), true
			break
		}
	}
	if !parsed {
		return nil, fmt.Errorf("unreadable time %q", truncateForError(ts))
	}
	if v, ok := raw["metadata"]; ok {
		var obj map[string]json.RawMessage
		if json.Unmarshal(v, &obj) == nil && len(obj) > 0 {
			e.Metadata = make(map[string]string, len(obj))
			for k, item := range obj {
				var s string
				if json.Unmarshal(item, &s) != nil {
					s = string(item)
				}
				e.Metadata[k] = s
			}
		}
	}
	if id := str("event_id"); IsObservationID(id) {
		e.ID = id
	} else {
		h := sha256.New()
		h.Write([]byte("qpot log backup\n"))
		h.Write([]byte(file))
		h.Write([]byte("\n" + strconv.FormatInt(offset, 10) + "\n"))
		h.Write(line)
		var sum [sha256.Size]byte
		h.Sum(sum[:0])
		e.ID = observationID(sum)
	}
	return e, nil
}

func truncateForError(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

// RestoreReport says what a restore from log backups did.
type RestoreReport struct {
	Files         int   `json:"files"`
	Lines         int64 `json:"lines"`
	Stored        int64 `json:"stored"`
	AlreadyStored int64 `json:"already_stored"`
	// Unreadable counts lines that are not an event: damaged, cut off by a
	// crash, or longer than the line limit.
	Unreadable int64 `json:"unreadable"`
	// FirstDay and LastDay are the first and last backup day read
	// (YYYY/MM/DD), empty when there was none.
	FirstDay string `json:"first_day,omitempty"`
	LastDay  string `json:"last_day,omitempty"`
	DryRun   bool   `json:"dry_run"`
}

// RestoreOptions tunes RestoreBackups.
type RestoreOptions struct {
	// DryRun reads and compares but stores nothing.
	DryRun bool
	// Progress, when set, is called after each file.
	Progress func(file string, rep RestoreReport)
}

// RestoreBackups reads the collector's log backups under dir (the instance's
// backup/logs folder: YYYY/MM/DD/<honeypot>.log, one event per line) and
// stores every event the database does not hold yet. It can be stopped and
// run again: what is stored is skipped. Files are read in name order, so
// events go in oldest day first.
func RestoreBackups(ctx context.Context, restorer EventRestorer, dir string, opt RestoreOptions) (RestoreReport, error) {
	rep := RestoreReport{DryRun: opt.DryRun}
	root, err := os.OpenRoot(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return rep, fmt.Errorf("no log backups in %s", dir)
		}
		return rep, err
	}
	defer root.Close()
	var files []string
	err = fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() && strings.HasSuffix(p, ".log") {
			if len(files) >= maxBackupFiles {
				return fmt.Errorf("more than %d backup files", maxBackupFiles)
			}
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return rep, fmt.Errorf("list log backups: %w", err)
	}
	sort.Strings(files)
	var batch []*Event
	size := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		stored, err := restorer.RestoreEvents(ctx, batch, opt.DryRun)
		if err != nil {
			return err
		}
		rep.Stored += int64(stored)
		rep.AlreadyStored += int64(len(batch) - stored)
		batch, size = batch[:0], 0
		return nil
	}
	for _, name := range files {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		f, err := root.Open(name)
		if err != nil {
			return rep, fmt.Errorf("open backup %s: %w", name, err)
		}
		rd := bufio.NewReaderSize(f, 1<<16)
		var offset int64
		for {
			line, n, tooLong, err := readBackupLine(rd)
			if n == 0 && err != nil {
				if !errors.Is(err, io.EOF) {
					f.Close()
					return rep, fmt.Errorf("read backup %s: %w", name, err)
				}
				break
			}
			at := offset
			offset += int64(n)
			line = bytes.TrimSpace(line)
			if len(line) == 0 && !tooLong {
				continue
			}
			rep.Lines++
			if tooLong {
				rep.Unreadable++
				continue
			}
			ev, perr := ParseBackupEvent(line, name, at)
			if perr != nil {
				rep.Unreadable++
				continue
			}
			batch = append(batch, ev)
			size += len(line)
			if len(batch) >= restoreBatchRows || size >= restoreBatchBytes {
				if err := flush(); err != nil {
					f.Close()
					return rep, err
				}
			}
		}
		f.Close()
		if err := flush(); err != nil {
			return rep, err
		}
		rep.Files++
		if day := backupDay(name); day != "" {
			if rep.FirstDay == "" {
				rep.FirstDay = day
			}
			rep.LastDay = day
		}
		if opt.Progress != nil {
			opt.Progress(name, rep)
		}
	}
	return rep, nil
}

// backupDay returns the YYYY/MM/DD part of a backup file's path, or "".
func backupDay(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) < 4 {
		return ""
	}
	return strings.Join(parts[len(parts)-4:len(parts)-1], "/")
}

// readBackupLine reads one line, of any length, keeping at most
// maxBackupLine bytes of it. n is the number of bytes consumed.
func readBackupLine(rd *bufio.Reader) (line []byte, n int, tooLong bool, err error) {
	for {
		part, perr := rd.ReadSlice('\n')
		n += len(part)
		if !tooLong {
			if len(line)+len(part) > maxBackupLine {
				tooLong, line = true, nil
			} else {
				line = append(line, part...)
			}
		}
		if perr == nil || !errors.Is(perr, bufio.ErrBufferFull) {
			return line, n, tooLong, perr
		}
	}
}

// SharedSourceKey is the metadata key the collector sets on an event whose
// source address is one of Docker's own, shared by every visitor Docker
// forwarded that way (see intelligence.SharedSourceKey, which is this key).
const SharedSourceKey = "source_shared"

// SharedSourceCounter is implemented by the stores that can say how many
// events carry a shared source address.
type SharedSourceCounter interface {
	// CountSharedSources returns how many events since `since` have a
	// shared source address, and how many events there are in all.
	CountSharedSources(ctx context.Context, since time.Time) (shared, total int64, err error)
}
