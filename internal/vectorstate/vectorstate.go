// Package vectorstate reads and seeds the state of an instance's collector
// (Vector): for each of its file sources, how far it has delivered each log.
//
// The collector keeps that state in the instance folder (Dir, mounted as its
// data_dir), one checkpoints.json per source. Its sinks acknowledge what they
// have stored, so a checkpoint moves only once the database and the backup
// hold a log's lines: disk cleanup empties a log only up to there, and a
// collector that restarts reads again whatever it had not delivered. A
// checkpoint names a log by the collector's fingerprint of it: the
// CRC-64/ECMA-182 of its first line, newline included.
package vectorstate

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"time"
)

// Dir is the instance folder holding the collector's state, its data_dir.
const Dir = "collector"

// HoneypotSource is the collector's source reading a honeypot's logs.
func HoneypotSource(honeypot string) string { return honeypot + "_logs" }

const (
	// maxCheckpoints bounds the checkpoints file read.
	maxCheckpoints = 16 << 20
	// MaxLine is the collector's longest line (its max_line_bytes default):
	// a first line longer than this gets no fingerprint here.
	MaxLine = 102400
	// maxDepth and maxFiles bound the logs one source lists when seeding.
	maxDepth = 24
	maxFiles = 100_000
)

// A Source is one of the collector's file sources: its name, the instance
// folder it reads in, and which files there it reads (Read takes a slash
// path relative to Dir).
type Source struct {
	Name string
	Dir  string
	Read func(rel string) bool
}

// Delivered maps a log's fingerprint to how far the collector has delivered
// it; -1 marks a fingerprint two checkpoints share.
type Delivered map[uint64]int64

func checkpointsPath(dataPath, source string) string {
	return filepath.Join(dataPath, Dir, source, "checkpoints.json")
}

type checkpointsDoc struct {
	Version     string       `json:"version"`
	Checkpoints []checkpoint `json:"checkpoints"`
}

type checkpoint struct {
	Fingerprint fingerprintJSON `json:"fingerprint"`
	Position    int64           `json:"position"`
	Modified    string          `json:"modified,omitempty"`
}

type fingerprintJSON struct {
	FirstLines *uint64 `json:"first_lines_checksum,omitempty"`
	FirstLine  *uint64 `json:"first_line_checksum,omitempty"` // an older name
}

// Load reads the collector's checkpoints for a source: nil when there are
// none or they cannot be read, so nothing counts as delivered.
func Load(dataPath, source string) Delivered {
	f, err := os.Open(checkpointsPath(dataPath, source)) // #nosec G304 -- the collector's own state, under the instance folder
	if err != nil {
		return nil
	}
	defer f.Close()
	var doc checkpointsDoc
	if err := json.NewDecoder(io.LimitReader(f, maxCheckpoints)).Decode(&doc); err != nil || doc.Version != "1" {
		return nil
	}
	d := Delivered{}
	for _, c := range doc.Checkpoints {
		fp := c.Fingerprint.FirstLines
		if fp == nil {
			fp = c.Fingerprint.FirstLine
		}
		if fp == nil || c.Position < 0 {
			continue
		}
		if _, dup := d[*fp]; dup {
			d[*fp] = -1
			continue
		}
		d[*fp] = c.Position
	}
	return d
}

// Fingerprint is the collector's fingerprint of the log r reads from its
// start; ok is false while it has no whole first line.
func Fingerprint(r io.Reader) (fp uint64, ok bool) {
	line, err := bufio.NewReader(io.LimitReader(r, MaxLine+1)).ReadBytes('\n')
	if err != nil {
		return 0, false
	}
	return crc64ECMA182(line), true
}

var ecma182 = func() (t [256]uint64) {
	const poly = 0x42F0E1EBA9EA3693
	for i := range t {
		c := uint64(i) << 56
		for range 8 {
			if c&(1<<63) != 0 {
				c = c<<1 ^ poly
			} else {
				c <<= 1
			}
		}
		t[i] = c
	}
	return t
}()

// crc64ECMA182 is CRC-64/ECMA-182: not reflected, no initial or final XOR.
func crc64ECMA182(b []byte) uint64 {
	var c uint64
	for _, x := range b {
		c = ecma182[byte(c>>56)^x] ^ c<<8
	}
	return c
}

// Seed records, for a source the collector has no state for yet, every log
// it reads as delivered as far as it goes now, and reports how many. The
// collector reads a log it has no checkpoint for from its start, so without
// this, a collector that gained its kept state (an older QPot kept none)
// would deliver all those lines again. A source with state is left alone.
func Seed(dataPath string, src Source, now time.Time) (int, error) {
	cp := checkpointsPath(dataPath, src.Name)
	if _, err := os.Lstat(cp); !errors.Is(err, fs.ErrNotExist) {
		return 0, err
	}
	sizes, logs := map[uint64]int64{}, map[uint64]int{}
	if root, err := os.OpenRoot(filepath.Join(dataPath, filepath.FromSlash(src.Dir))); err == nil {
		walk(root, ".", 0, src.Read, func(size int64, fp uint64) {
			sizes[fp] = size
			logs[fp]++
		})
		root.Close()
	}
	doc := checkpointsDoc{Version: "1", Checkpoints: []checkpoint{}}
	for _, fp := range slices.Sorted(maps.Keys(sizes)) {
		// Logs sharing a first line are one log to the collector; a position
		// from one could fall inside a line of another. Left unseeded, they
		// are read again from the start: sent twice rather than cut.
		if logs[fp] != 1 {
			continue
		}
		v := fp
		doc.Checkpoints = append(doc.Checkpoints, checkpoint{Fingerprint: fingerprintJSON{FirstLines: &v},
			Position: sizes[fp], Modified: now.UTC().Format(time.RFC3339Nano)})
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(cp), 0o750); err != nil {
		return 0, fmt.Errorf("collector state: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(cp), ".checkpoints-*.json")
	if err != nil {
		return 0, fmt.Errorf("collector state: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}
	// The collector (root in its container) reads and replaces it.
	if err := os.Chmod(tmp.Name(), 0o644); err != nil { // #nosec G302 -- holds fingerprints and offsets only
		return 0, err
	}
	if err := os.Rename(tmp.Name(), cp); err != nil {
		return 0, fmt.Errorf("collector state: %w", err)
	}
	return len(doc.Checkpoints), nil
}

// walk calls found with the size and fingerprint of each regular file under
// dir that read selects, never following a symlink.
func walk(root *os.Root, dir string, depth int, read func(string) bool, found func(int64, uint64)) {
	if depth > maxDepth {
		return
	}
	d, err := root.Open(dir)
	if err != nil {
		return
	}
	ents, _ := d.ReadDir(maxFiles)
	d.Close()
	for _, e := range ents {
		rel := e.Name()
		if dir != "." {
			rel = path.Join(dir, e.Name())
		}
		switch t := e.Type(); {
		case t.IsDir():
			walk(root, rel, depth+1, read, found)
		case t.IsRegular() && read(rel):
			f, err := root.OpenFile(rel, os.O_RDONLY|noFollow, 0)
			if err != nil {
				continue
			}
			fi, err := f.Stat()
			if err == nil && fi.Mode().IsRegular() {
				if fp, ok := Fingerprint(f); ok {
					found(fi.Size(), fp)
				}
			}
			f.Close()
		}
	}
}
