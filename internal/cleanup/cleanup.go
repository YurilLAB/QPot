// Package cleanup keeps what an instance stores on disk outside its database
// within bounds: each honeypot's logs and captured files (downloads, session
// recordings, uploads, payloads) and the collector's backup copy of every
// event. Nothing else prunes them, and a busy honeypot fills a disk.
//
// A run, per honeypot folder (DataPath/honeypots/<name>):
//
//  1. Captured files and rotated logs older than the age limit are deleted.
//     A log the collector reads is never deleted: the honeypot may hold it
//     open, and would go on writing to a file nobody can find any more.
//  2. A log the collector reads that is larger than the log limit is emptied
//     in place, only while the collector runs and only once its checkpoint
//     shows it has delivered the whole log to the database and the backup
//     (see internal/vectorstate): an emptied log then loses nothing.
//  3. A folder above its storage limit loses its oldest captured files and
//     rotated logs, then its largest delivered logs (emptied as in 2), until
//     it is back under 90% of the limit. State and config are never touched.
//
// The backup folder (DataPath/backup/logs/YYYY/MM/DD) loses days older than
// the age limit, then its oldest days while it is above its own limit; the
// current day is never removed.
//
// Honeypots write their folders, and a compromised one can plant symlinks in
// them. Cleanup never follows a symlink: it skips them while listing, acts
// only inside an os.Root scoped to the folder it cleans, and empties a log
// only when the file it opened is the regular file it listed.
package cleanup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/instance"
	"github.com/qpot/qpot/internal/vectorstate"
)

const (
	// logsDir is the folder the collector reads in every honeypot folder.
	logsDir = "logs"
	// backupLogs is the collector's backup copy, under DataPath/backup.
	backupLogs = "logs"
	// keepFraction: a folder over its limit is pruned to this share of it,
	// so the next run does not start at the limit again.
	keepFraction = 0.9
	// maxDepth and maxFiles bound one folder's listing: a honeypot could
	// create endless folders or files.
	maxDepth = 24
	maxFiles = 2_000_000
	// maxErrors bounds the errors a report keeps.
	maxErrors = 20
)

// Limits are a run's settings.
type Limits struct {
	MaxAge    time.Duration // captured files, rotated logs and backup days older than this go
	MaxLog    int64         // a collected log larger than this is emptied
	MaxBackup int64         // the backup folder's total
	// HoneypotLimit is a honeypot folder's storage limit; 0 means none.
	HoneypotLimit func(name string) int64
}

// LimitsFor reads cfg's cleanup settings and storage limits.
func LimitsFor(cfg *config.Config) Limits {
	c := cfg.Cleanup
	return Limits{
		MaxAge:    time.Duration(c.MaxAgeDays) * 24 * time.Hour,
		MaxLog:    c.MaxLogMB << 20,
		MaxBackup: c.MaxBackupMB << 20,
		// A honeypot's own limit when it sets one, else the global one: a
		// custom profile that sets only CPU and memory leaves storage at 0.
		HoneypotLimit: func(name string) int64 {
			gb := cfg.GetEffectiveResourceLimits(name).MaxStorageGB
			if gb <= 0 {
				gb = cfg.Security.ResourceLimits.MaxStorageGB
			}
			return max(gb, 0) << 30
		},
	}
}

// Options are a run's circumstances.
type Options struct {
	DryRun bool
	// CollectorRunning: logs are emptied only while the collector reads
	// them; one emptied while it is stopped would lose unread events.
	CollectorRunning bool
	// Helper removes or empties what this process may not (nil: none).
	Helper Helper
	// Now is the run's clock (zero: time.Now).
	Now time.Time
}

// Area is one honeypot folder or the backup folder after a run.
type Area struct {
	Name    string `json:"name"` // the honeypot, or "backup"
	Bytes   int64  `json:"bytes"`
	Limit   int64  `json:"limit_bytes"`
	Freed   int64  `json:"freed_bytes"`
	Removed int    `json:"removed"`
	Emptied int    `json:"emptied"`
	// Over: still above its limit after the run.
	Over bool `json:"over_limit"`
}

// Report is what a run did, or would do on a dry run.
type Report struct {
	Started    time.Time `json:"started"`
	DurationMS int64     `json:"duration_ms"`
	DryRun     bool      `json:"dry_run"`
	Collector  bool      `json:"collector_running"`
	Removed    int       `json:"removed"`
	Emptied    int       `json:"emptied"`
	Freed      int64     `json:"freed_bytes"`
	Areas      []Area    `json:"areas"`
	Notes      []string  `json:"notes"`
	Errors     []string  `json:"errors"`
}

func (r *Report) note(format string, args ...any) {
	r.Notes = append(r.Notes, fmt.Sprintf(format, args...))
}

func (r *Report) fail(err error) {
	if len(r.Errors) < maxErrors {
		r.Errors = append(r.Errors, err.Error())
	} else if len(r.Errors) == maxErrors {
		r.Errors = append(r.Errors, "more errors were left out")
	}
}

// kind is what a file in a honeypot folder is to cleanup.
type kind int

const (
	kindOther   kind = iota // state, config: never touched
	kindCapture             // a captured file
	kindRotated             // a log the collector no longer reads
	kindActive              // a log the collector reads (*.log, *.json)
)

// file is one regular file found in a folder.
type file struct {
	rel  string // slash-separated, relative to the folder
	size int64  // bytes on disk
	mod  time.Time
	kind kind
	info fs.FileInfo
	upTo int64 // a log queued for the helper to empty: what was delivered
}

// Run cleans the instance cfg describes.
func Run(ctx context.Context, cfg *config.Config, lim Limits, opt Options) *Report {
	if opt.Now.IsZero() {
		opt.Now = time.Now()
	}
	rep := &Report{Started: opt.Now, DryRun: opt.DryRun, Collector: opt.CollectorRunning, Areas: []Area{}, Notes: []string{}, Errors: []string{}}
	start := time.Now()
	defer func() { rep.DurationMS = time.Since(start).Milliseconds() }()

	names := make([]string, 0, 32)
	for name := range cfg.SnapshotHoneypots() {
		names = append(names, name)
	}
	slices.Sort(names)
	notCollected, undelivered := 0, 0
	for _, name := range names {
		if ctx.Err() != nil {
			rep.fail(ctx.Err())
			break
		}
		dir := filepath.Join(cfg.DataPath, "honeypots", name)
		if !isDir(dir) {
			continue
		}
		var limit int64
		if lim.HoneypotLimit != nil {
			limit = lim.HoneypotLimit(name)
		}
		var got vectorstate.Delivered
		if opt.CollectorRunning {
			got = vectorstate.Load(cfg.DataPath, vectorstate.HoneypotSource(name))
		}
		a, skipped, waiting := cleanHoneypot(ctx, rep, name, dir, limit, lim, opt, got)
		notCollected += skipped
		undelivered += waiting
		rep.Areas = append(rep.Areas, a)
	}
	if notCollected > 0 {
		rep.note("%d %s above the limit not emptied: the collector is not running, and emptying a log it has not read would lose events.",
			notCollected, plural(notCollected, "log was", "logs were"))
	}
	if undelivered > 0 {
		rep.note("%d %s above the limit not emptied: the collector has not yet delivered all of %s to the database (or cannot say how far it has).",
			undelivered, plural(undelivered, "log was", "logs were"), plural(undelivered, "it", "them"))
	}
	if dir := filepath.Join(cfg.DataPath, "backup"); isDir(dir) {
		rep.Areas = append(rep.Areas, cleanBackup(ctx, rep, dir, lim, opt))
	}
	for _, a := range rep.Areas {
		rep.Removed += a.Removed
		rep.Emptied += a.Emptied
		rep.Freed += a.Freed
		if a.Over {
			rep.note("%s is still above its limit (%s of %s): what is left is not cleanup's to remove.", a.Name, humanBytes(a.Bytes), humanBytes(a.Limit))
		}
	}
	return rep
}

// isDir reports whether p is a directory, not a symlink to one.
func isDir(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.IsDir()
}

// cleanHoneypot cleans one honeypot folder; got is how far the collector has
// delivered its logs. It returns the area, how many logs were over the log
// limit but left alone with the collector stopped, and how many were left
// alone because the collector had not delivered all of them.
func cleanHoneypot(ctx context.Context, rep *Report, name, dir string, limit int64, lim Limits, opt Options, got vectorstate.Delivered) (Area, int, int) {
	area := Area{Name: name, Limit: limit}
	root, err := os.OpenRoot(dir)
	if err != nil {
		rep.fail(fmt.Errorf("%s: %w", name, err))
		return area, 0, 0
	}
	defer root.Close()

	captures := instance.CaptureDirs(name)
	files, total, complete := list(root, captures)
	if !complete {
		rep.note("%s has more files than one run lists (%d); the rest wait for the next run.", name, maxFiles)
	}
	area.Bytes = total
	cutoff := opt.Now.Add(-lim.MaxAge)
	act := newActor(rep, &area, root, dir, opt)
	defer act.close()
	if got != nil && mayEmpty(files, total, limit, lim) {
		act.fingerprints(ctx, files, got)
	}

	// 1. Age: captured files and rotated logs. Never a log the collector
	// reads, however old: a honeypot holding it open would go on writing to
	// a file nobody can find, and the collector would never see those lines.
	var keep []file
	for _, f := range files {
		old := lim.MaxAge > 0 && f.mod.Before(cutoff)
		if old && (f.kind == kindCapture || f.kind == kindRotated) {
			act.remove(ctx, f)
		} else {
			keep = append(keep, f)
		}
	}
	files = keep
	act.flush(ctx)

	// 2. Logs over the log limit, once delivered.
	skipped := 0
	for i, f := range files {
		if f.kind != kindActive || lim.MaxLog <= 0 || f.size <= lim.MaxLog {
			continue
		}
		if !opt.CollectorRunning {
			skipped++
			continue
		}
		if act.empty(ctx, f) {
			files[i].size = 0
		}
	}
	act.flush(ctx)

	// 3. The storage limit: oldest captured files and rotated logs first,
	// then (collector running) the largest delivered logs.
	if limit > 0 && area.Bytes > limit {
		target := int64(float64(limit) * keepFraction)
		var prune, logs []file
		for _, f := range files {
			switch f.kind {
			case kindCapture, kindRotated:
				prune = append(prune, f)
			case kindActive:
				if f.size > 0 {
					logs = append(logs, f)
				}
			}
		}
		slices.SortStableFunc(prune, func(a, b file) int { return a.mod.Compare(b.mod) })
		for _, f := range prune {
			if act.left() <= target || ctx.Err() != nil {
				break
			}
			act.remove(ctx, f)
		}
		slices.SortStableFunc(logs, func(a, b file) int { return int(sign(b.size - a.size)) })
		for _, f := range logs {
			// With the collector stopped no log may be emptied (step 2
			// counted those over the log limit).
			if act.left() <= target || ctx.Err() != nil || !opt.CollectorRunning {
				break
			}
			act.empty(ctx, f)
		}
	}
	act.flush(ctx)
	area.Over = limit > 0 && area.Bytes > limit
	if area.Removed+area.Emptied > 0 {
		slog.Info("Storage cleanup", "area", name, "removed", area.Removed, "emptied", area.Emptied,
			"freed_bytes", area.Freed, "bytes", area.Bytes, "dry_run", opt.DryRun)
	}
	return area, skipped, len(act.waiting)
}

func sign(n int64) int64 {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// list lists every regular file under root without following a symlink,
// classified by the capture folders, with the folder's total on disk.
func list(root *os.Root, captures []string) (files []file, total int64, complete bool) {
	w := &walker{root: root, captures: captures, complete: true}
	w.dir(".", 0)
	return w.files, w.total, w.complete
}

type walker struct {
	root     *os.Root
	captures []string
	files    []file
	total    int64
	complete bool
}

func (w *walker) dir(rel string, depth int) {
	if depth > maxDepth || len(w.files) >= maxFiles {
		w.complete = false
		return
	}
	d, err := w.root.Open(rel)
	if err != nil {
		return
	}
	defer d.Close()
	for {
		ents, err := d.ReadDir(512)
		for _, e := range ents {
			child := path.Join(rel, e.Name())
			if rel == "." {
				child = e.Name()
			}
			switch t := e.Type(); {
			case t&fs.ModeSymlink != 0:
			case t.IsDir():
				w.dir(child, depth+1)
			case t.IsRegular():
				if len(w.files) >= maxFiles {
					w.complete = false
					return
				}
				fi, err := e.Info()
				if err != nil || !fi.Mode().IsRegular() {
					continue
				}
				size := onDisk(fi)
				w.total += size
				w.files = append(w.files, file{rel: child, size: size, mod: fi.ModTime(), kind: w.kind(child), info: fi})
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				w.complete = false
			}
			return
		}
	}
}

// kind classifies a file by where it is: a capture folder, the logs folder
// (a name the collector reads, or a rotated one), or anything else.
func (w *walker) kind(rel string) kind {
	for _, c := range w.captures {
		if rel == c || strings.HasPrefix(rel, c+"/") {
			return kindCapture
		}
	}
	if !strings.HasPrefix(rel, logsDir+"/") {
		return kindOther
	}
	// The collector reads logs/**/*.log and logs/**/*.json (see the
	// collector config in internal/instance/compose.go).
	if base := path.Base(rel); strings.HasSuffix(base, ".log") || strings.HasSuffix(base, ".json") {
		return kindActive
	}
	return kindRotated
}

// actor removes and empties files, in place or through the helper. It acts
// inside the file's volume folder (the first part of its path): a folder the
// honeypot's container has mounted, so cannot replace, and the only place a
// symlink it plants deeper down can lead. Cleanup therefore never changes
// anything the honeypot could not change itself, even if a folder is swapped
// for a link after it was listed.
type actor struct {
	rep  *Report
	area *Area
	root *os.Root // the honeypot's folder
	dir  string
	opt  Options
	vols map[string]*os.Root
	// Files this process may not change, by volume, for the helper; pending
	// is their size until the helper is done with them.
	helpRemove, helpEmpty map[string][]file
	pending               int64
	// got is how far the collector has delivered this folder's logs; fps
	// their fingerprints, and shared how many logs have each.
	got    vectorstate.Delivered
	fps    map[string]uint64
	shared map[uint64]int
	// waiting: logs not emptied because the collector has not delivered
	// all of them yet.
	waiting map[string]bool
}

func newActor(rep *Report, area *Area, root *os.Root, dir string, opt Options) *actor {
	return &actor{rep: rep, area: area, root: root, dir: dir, opt: opt,
		vols: map[string]*os.Root{}, helpRemove: map[string][]file{}, helpEmpty: map[string][]file{},
		waiting: map[string]bool{}}
}

// mayEmpty reports whether a run could empty any log in a folder: one is
// over the log limit, or the folder over its storage limit.
func mayEmpty(files []file, total, limit int64, lim Limits) bool {
	if limit > 0 && total > limit {
		return true
	}
	return lim.MaxLog > 0 && slices.ContainsFunc(files, func(f file) bool { return f.kind == kindActive && f.size > lim.MaxLog })
}

// fingerprints reads the collector's fingerprint of each log it reads: in
// this process, or through the helper for a log a container's own user
// keeps from it (cowrie writes its log 0640).
func (a *actor) fingerprints(ctx context.Context, files []file, got vectorstate.Delivered) {
	a.got, a.fps, a.shared = got, map[string]uint64{}, map[uint64]int{}
	unreadable := map[string][]file{}
	for _, f := range files {
		if f.kind != kindActive {
			continue
		}
		fp, ok, err := a.fingerprintOf(f)
		switch {
		case ok:
			a.fps[f.rel] = fp
			a.shared[fp]++
		case a.canHelp(err):
			vol, _, _ := split(f.rel)
			unreadable[vol] = append(unreadable[vol], f)
		}
	}
	for _, vol := range slices.Sorted(maps.Keys(unreadable)) {
		batch := unreadable[vol]
		inner := make([]string, len(batch))
		for i, f := range batch {
			_, inner[i], _ = split(f.rel)
		}
		lines, err := a.opt.Helper.FirstLines(ctx, filepath.Join(a.dir, vol), inner)
		if err != nil {
			a.rep.fail(fmt.Errorf("%s: %w", a.area.Name, err))
			continue
		}
		for i, f := range batch {
			if fp, ok := vectorstate.Fingerprint(bytes.NewReader(lines[i])); ok {
				a.fps[f.rel] = fp
				a.shared[fp]++
			}
		}
	}
}

func (a *actor) fingerprintOf(f file) (uint64, bool, error) {
	vol, inner, ok := split(f.rel)
	if !ok {
		return 0, false, nil
	}
	r, err := a.volume(vol)
	if err != nil {
		return 0, false, err
	}
	h, err := r.OpenFile(inner, os.O_RDONLY|noFollow, 0)
	if err != nil {
		return 0, false, err
	}
	defer h.Close()
	fi, err := h.Stat()
	if err != nil || !fi.Mode().IsRegular() || !os.SameFile(fi, f.info) {
		return 0, false, err
	}
	fp, ok := vectorstate.Fingerprint(h)
	return fp, ok, nil
}

// confirm returns how far the collector has delivered f, if that is all of
// f as listed. A log two logs' fingerprints share is never confirmed: the
// collector cannot tell them apart either.
func (a *actor) confirm(f file) (int64, bool) {
	fp, ok := a.fps[f.rel]
	if !ok || a.shared[fp] != 1 {
		return 0, false
	}
	pos, ok := a.got[fp]
	if !ok || pos < f.info.Size() {
		return 0, false
	}
	return pos, true
}

func (a *actor) close() {
	for _, r := range a.vols {
		r.Close()
	}
}

// left is the folder's size once queued helper work is done.
func (a *actor) left() int64 { return a.area.Bytes - a.pending }

// split is a file's volume folder and its path inside it.
func split(rel string) (vol, inner string, ok bool) {
	vol, inner, ok = strings.Cut(rel, "/")
	return vol, inner, ok && vol != "" && inner != ""
}

// volume opens a volume folder, refusing one that is not a plain folder.
func (a *actor) volume(vol string) (*os.Root, error) {
	if r, ok := a.vols[vol]; ok {
		return r, nil
	}
	fi, err := a.root.Lstat(vol)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a folder", vol)
	}
	r, err := a.root.OpenRoot(vol)
	if err != nil {
		return nil, err
	}
	a.vols[vol] = r
	return r, nil
}

func (a *actor) done(f file, emptied bool) {
	a.area.Bytes -= f.size
	a.area.Freed += f.size
	if emptied {
		a.area.Emptied++
	} else {
		a.area.Removed++
	}
	slog.Debug("Storage cleanup", "area", a.area.Name, "file", f.rel, "emptied", emptied, "bytes", f.size, "dry_run", a.opt.DryRun)
}

func (a *actor) remove(ctx context.Context, f file) {
	if a.opt.DryRun {
		a.done(f, false)
		return
	}
	vol, inner, ok := split(f.rel)
	if !ok {
		return
	}
	r, err := a.volume(vol)
	if err == nil {
		err = r.Remove(inner)
	}
	switch {
	case err == nil:
		a.done(f, false)
	case errors.Is(err, fs.ErrNotExist):
	case a.canHelp(err):
		a.queue(ctx, a.helpRemove, vol, f)
	default:
		a.rep.fail(fmt.Errorf("%s: remove %s: %w", a.area.Name, f.rel, err))
	}
}

// empty empties a log the collector has delivered all of, and reports
// whether it did (or would).
func (a *actor) empty(ctx context.Context, f file) bool {
	upTo, ok := a.confirm(f)
	if !ok {
		a.waiting[f.rel] = true
		return false
	}
	if a.opt.DryRun {
		a.done(f, true)
		return true
	}
	vol, inner, ok := split(f.rel)
	if !ok {
		return false
	}
	r, err := a.volume(vol)
	if err == nil {
		err = emptyFile(r, inner, f.info, upTo)
	}
	switch {
	case err == nil:
		a.done(f, true)
		return true
	case errors.Is(err, errGrew):
		a.waiting[f.rel] = true
		return false
	case errors.Is(err, errChanged), errors.Is(err, fs.ErrNotExist):
		return false
	case a.canHelp(err):
		f.upTo = upTo
		a.queue(ctx, a.helpEmpty, vol, f)
		return true
	default:
		a.rep.fail(fmt.Errorf("%s: empty %s: %w", a.area.Name, f.rel, err))
		return false
	}
}

func (a *actor) queue(ctx context.Context, m map[string][]file, vol string, f file) {
	m[vol] = append(m[vol], f)
	a.pending += f.size
	if len(m[vol]) >= helperBatch {
		a.flush(ctx)
	}
}

// canHelp: a permission error the helper may get past (a container's own
// user owns the file).
func (a *actor) canHelp(err error) bool {
	return a.opt.Helper != nil && runtime.GOOS != "windows" && errors.Is(err, fs.ErrPermission)
}

// flush hands what this process could not change to the helper, with the
// volume folder mounted, then counts what it changed.
func (a *actor) flush(ctx context.Context) {
	for _, emptied := range []bool{false, true} {
		m := a.helpRemove
		if emptied {
			m = a.helpEmpty
		}
		for _, vol := range slices.Sorted(maps.Keys(m)) {
			batch := m[vol]
			delete(m, vol)
			inner := make([]string, len(batch))
			upTo := make([]int64, len(batch))
			for i, f := range batch {
				_, inner[i], _ = split(f.rel)
				upTo[i] = f.upTo
				a.pending -= f.size
			}
			dir := filepath.Join(a.dir, vol)
			var err error
			if emptied {
				err = a.opt.Helper.Empty(ctx, dir, inner, upTo)
			} else {
				err = a.opt.Helper.Remove(ctx, dir, inner)
			}
			if err != nil {
				a.rep.fail(fmt.Errorf("%s: %w", a.area.Name, err))
			}
			r, err := a.volume(vol)
			if err != nil {
				continue
			}
			for i, f := range batch {
				fi, err := r.Lstat(inner[i])
				switch {
				case !emptied && errors.Is(err, fs.ErrNotExist):
					a.done(f, false)
				case emptied && err == nil && fi.Size() < f.info.Size():
					a.done(f, true)
				case emptied && err == nil:
					a.waiting[f.rel] = true // written since: the helper left it
				}
			}
		}
	}
}

// errChanged: the path no longer names the file that was listed.
var errChanged = errors.New("the file changed since it was listed")

// errGrew: the log has lines the collector has not delivered yet.
var errGrew = errors.New("written since the collector delivered it")

// emptyFile empties name, only if it still names the regular file listed and
// holds no more than upTo bytes, what the collector has delivered of it. The
// check and the emptying use one handle, back to back; a line the honeypot
// writes between the two would be lost, as with copytruncate.
func emptyFile(root *os.Root, name string, listed fs.FileInfo, upTo int64) error {
	h, err := root.OpenFile(name, os.O_WRONLY|noFollow, 0)
	if err != nil {
		return err
	}
	defer h.Close()
	fi, err := h.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || !os.SameFile(fi, listed) {
		return errChanged
	}
	if fi.Size() > upTo {
		return errGrew
	}
	return h.Truncate(0)
}

// cleanBackup removes the backup folder's days older than the age limit,
// then its oldest days while it is above its limit; never the current day.
func cleanBackup(ctx context.Context, rep *Report, dir string, lim Limits, opt Options) Area {
	area := Area{Name: "backup", Limit: lim.MaxBackup}
	root, err := os.OpenRoot(dir)
	if err != nil {
		rep.fail(fmt.Errorf("backup: %w", err))
		return area
	}
	defer root.Close()
	files, total, _ := list(root, nil)
	area.Bytes = total
	// The day folders (logs/YYYY/MM/DD), found as folders so that one a
	// failed run left empty still goes, with what they hold.
	order := backupDays(root)
	byRel := map[string]*backupDay{}
	for _, d := range order {
		byRel[d.rel] = d
	}
	for _, f := range files {
		if parts := strings.SplitN(f.rel, "/", 5); len(parts) == 5 {
			if d := byRel[strings.Join(parts[:4], "/")]; d != nil {
				d.size += f.size
			}
		}
	}

	// The collector names days by the event's UTC date; the current one is
	// still being written.
	today := opt.Now.UTC().Truncate(24 * time.Hour)
	cutoff := today.Add(-lim.MaxAge)
	target := int64(float64(lim.MaxBackup) * keepFraction)
	over := lim.MaxBackup > 0 && area.Bytes > lim.MaxBackup
	for _, d := range order {
		if ctx.Err() != nil || !d.date.Before(today) {
			break
		}
		old := lim.MaxAge > 0 && d.date.Before(cutoff)
		if !old && !(over && area.Bytes > target) {
			continue
		}
		if removeDay(ctx, rep, root, dir, d.rel, opt) {
			area.Bytes -= d.size
			area.Freed += d.size
			area.Removed++
		}
	}
	if !opt.DryRun {
		// Month and year folders left empty (Remove refuses a full one).
		for _, d := range order {
			parts := strings.Split(d.rel, "/")
			_ = root.Remove(strings.Join(parts[:3], "/"))
			_ = root.Remove(strings.Join(parts[:2], "/"))
		}
	}
	area.Over = lim.MaxBackup > 0 && area.Bytes > lim.MaxBackup
	if area.Removed > 0 {
		slog.Info("Storage cleanup", "area", "backup", "days_removed", area.Removed, "freed_bytes", area.Freed, "bytes", area.Bytes, "dry_run", opt.DryRun)
	}
	return area
}

// backupDay is one day folder of the backup copy.
type backupDay struct {
	rel  string // logs/YYYY/MM/DD
	date time.Time
	size int64
}

// backupDays lists the backup's day folders, oldest first, without
// following a symlink.
func backupDays(root *os.Root) []*backupDay {
	var out []*backupDay
	sub := func(rel string, digits int) []string {
		d, err := root.Open(rel)
		if err != nil {
			return nil
		}
		defer d.Close()
		ents, _ := d.ReadDir(4096)
		var names []string
		for _, e := range ents {
			if e.Type().IsDir() && len(e.Name()) == digits && strings.Trim(e.Name(), "0123456789") == "" {
				names = append(names, e.Name())
			}
		}
		return names
	}
	for _, y := range sub(backupLogs, 4) {
		for _, m := range sub(backupLogs+"/"+y, 2) {
			for _, dd := range sub(backupLogs+"/"+y+"/"+m, 2) {
				date, err := time.Parse("2006/01/02", y+"/"+m+"/"+dd)
				if err != nil {
					continue
				}
				out = append(out, &backupDay{rel: backupLogs + "/" + y + "/" + m + "/" + dd, date: date})
			}
		}
	}
	slices.SortFunc(out, func(a, b *backupDay) int { return a.date.Compare(b.date) })
	return out
}

// removeDay removes one backup day folder, and reports whether it is gone.
func removeDay(ctx context.Context, rep *Report, root *os.Root, dir, rel string, opt Options) bool {
	if opt.DryRun {
		return true
	}
	err := root.RemoveAll(rel)
	if err == nil {
		return true
	}
	if opt.Helper != nil && runtime.GOOS != "windows" && errors.Is(err, fs.ErrPermission) {
		if herr := opt.Helper.Remove(ctx, dir, []string{rel}); herr != nil {
			rep.fail(fmt.Errorf("backup: %w", herr))
		}
		_, err = root.Lstat(rel)
		return errors.Is(err, fs.ErrNotExist)
	}
	rep.fail(fmt.Errorf("backup: remove %s: %w", rel, err))
	return false
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// humanBytes is n in the largest unit that keeps it at least 1.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	v, i := float64(n), 0
	for v >= unit && i < 4 {
		v /= unit
		i++
	}
	return fmt.Sprintf("%.1f %ciB", v, "KMGT"[i-1])
}
