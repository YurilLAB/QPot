package investigate

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/qpot/qpot/internal/database"
)

// Names of the files in an evidence bundle.
const (
	bundleCase     = "case.json"
	bundleRecords  = "records.jsonl"
	bundleTimeline = "timeline.txt"
	bundleReadme   = "README.txt"
	bundleManifest = "MANIFEST.sha256"
	bundleOutput   = "output/"
)

// Limits of a bundle being checked: it may come from anywhere.
const (
	maxBundleFiles = 100000
	maxBundleFile  = 1 << 30
	maxBundleTotal = 4 << 30
)

const bundleReadmeText = `QPot evidence bundle

This archive holds what one QPot instance recorded about one session or one
campaign, as it stood when the bundle was made.

  case.json        The case: summary, timelines, files, links between
                   sessions, related sessions and gaps. Every statement in
                   it names the records it rests on by reference.
  records.jsonl    Those records, one JSON object a line: the reference, the
                   session and the stored event.
  timeline.txt     The same case as text.
  output/          What captured commands printed, as bytes:
                   <record reference>.stdout and .stderr.
  MANIFEST.sha256  The SHA-256 of every other file, in sha256sum's format.

Checking it

  sha256sum -c MANIFEST.sha256          the files are as they were written
  qpot investigate verify <bundle.zip>  the same, and that every record still
                                        has the reference it is cited by

A record's reference is the first 32 hex characters of the SHA-256 of its
stored fields, each written as "<length in bytes>:<bytes>", in this order:
the text "qpot/record/1", the timestamp in nanoseconds since 1970 UTC, the
honeypot, source address, source port, destination port, protocol, event
type, user name, password, command, payload, the number of metadata entries,
and each metadata key and value in key order. Text is taken as this file
holds it (a byte that was not UTF-8 is U+FFFD); the payload is its bytes.
Changing any of them changes the reference, so a record cannot be altered
without the case no longer citing it.

The manifest shows that the bundle is whole. It does not show who made it:
keep its SHA-256 somewhere the bundle is not if that must be provable later.

Passwords and commands in a case are what visitors sent to a decoy. The
instance's own login is never part of a bundle.
`

// ManifestEntry is one file of a bundle and its hash.
type ManifestEntry struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// WriteBundle writes the case as an evidence bundle: a zip archive of the
// case, its records, its timeline as text, the captured output and a
// manifest of hashes. The same case gives the same bytes. It returns the
// manifest.
func WriteBundle(w io.Writer, c *Case) ([]ManifestEntry, error) {
	if c == nil {
		return nil, errors.New("investigate: no case to export")
	}
	files := map[string][]byte{bundleReadme: []byte(bundleReadmeText)}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("investigate: encode case: %w", err)
	}
	files[bundleCase] = append(data, '\n')

	var records bytes.Buffer
	enc := json.NewEncoder(&records)
	for _, r := range c.Records {
		if err := enc.Encode(r); err != nil {
			return nil, fmt.Errorf("investigate: encode record: %w", err)
		}
	}
	files[bundleRecords] = records.Bytes()

	var text bytes.Buffer
	if err := WriteText(&text, c); err != nil {
		return nil, err
	}
	files[bundleTimeline] = text.Bytes()

	for _, sc := range c.Sessions {
		for _, st := range sc.Timeline {
			if st.Output == nil || len(st.Refs) == 0 {
				continue
			}
			// The finish record is the one that names the capture.
			ref := st.Refs[len(st.Refs)-1]
			if len(st.Output.stdout) > 0 {
				files[bundleOutput+ref+".stdout"] = st.Output.stdout
			}
			if len(st.Output.stderr) > 0 {
				files[bundleOutput+ref+".stderr"] = st.Output.stderr
			}
		}
	}

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	manifest := make([]ManifestEntry, 0, len(names))
	var list bytes.Buffer
	for _, name := range names {
		sum := sha256.Sum256(files[name])
		manifest = append(manifest, ManifestEntry{Name: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(files[name]))})
		fmt.Fprintf(&list, "%s  %s\n", hex.EncodeToString(sum[:]), name)
	}
	files[bundleManifest] = list.Bytes()
	names = append(names, bundleManifest)

	zw := zip.NewWriter(w)
	for _, name := range names {
		// A fixed time, so the archive's bytes depend on the case alone.
		fw, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: c.Generated.UTC()})
		if err != nil {
			return nil, fmt.Errorf("investigate: write bundle: %w", err)
		}
		if _, err := fw.Write(files[name]); err != nil {
			return nil, fmt.Errorf("investigate: write bundle: %w", err)
		}
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("investigate: write bundle: %w", err)
	}
	return manifest, nil
}

// BundleReport is what checking a bundle found.
type BundleReport struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Files   int    `json:"files"`
	Records int    `json:"records"`
	// Cited is how many distinct records the case cites.
	Cited int `json:"cited"`
	// Problems lists everything wrong; a whole bundle has none.
	Problems []string `json:"problems"`
}

// OK reports whether the bundle is whole.
func (r *BundleReport) OK() bool { return len(r.Problems) == 0 }

// VerifyBundle checks an evidence bundle: every file has the hash the
// manifest gives and the manifest lists every file; every record has the
// reference it is stored under; and every record the case cites is there.
// It reads the bundle as untrusted input and reports problems instead of
// failing on them; the error is for an archive that cannot be read at all.
func VerifyBundle(r io.ReaderAt, size int64) (*BundleReport, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("investigate: not a zip archive: %w", err)
	}
	if len(zr.File) > maxBundleFiles {
		return nil, fmt.Errorf("investigate: the archive holds more than %d files", maxBundleFiles)
	}
	rep := &BundleReport{Problems: []string{}}
	problem := func(format string, args ...any) {
		if len(rep.Problems) < 100 {
			rep.Problems = append(rep.Problems, fmt.Sprintf(format, args...))
		}
	}
	contents := map[string][]byte{}
	sums := map[string]string{}
	var total int64
	for _, f := range zr.File {
		name := f.Name
		if _, dup := sums[name]; dup {
			problem("%s is in the archive more than once", Clean(name))
			continue
		}
		if f.UncompressedSize64 > maxBundleFile {
			return nil, fmt.Errorf("investigate: %s is larger than a bundle's files may be", Clean(name))
		}
		rc, err := f.Open()
		if err != nil {
			problem("%s cannot be read: %v", Clean(name), err)
			continue
		}
		h := sha256.New()
		var keep bytes.Buffer
		var dst io.Writer = h
		if name == bundleCase || name == bundleRecords || name == bundleManifest {
			dst = io.MultiWriter(h, &keep)
		}
		n, err := io.Copy(dst, io.LimitReader(rc, maxBundleFile+1))
		_ = rc.Close()
		if err != nil {
			problem("%s cannot be read: %v", Clean(name), err)
			continue
		}
		if total += n; n > maxBundleFile || total > maxBundleTotal {
			return nil, errors.New("investigate: the archive unpacks to more than a bundle may hold")
		}
		sums[name] = hex.EncodeToString(h.Sum(nil))
		if dst != io.Writer(h) {
			contents[name] = keep.Bytes()
		}
		rep.Files++
	}

	// The manifest names every other file, with its hash.
	manifest, ok := contents[bundleManifest]
	if !ok {
		problem("%s is missing", bundleManifest)
	}
	listed := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(manifest))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		sum, name, found := strings.Cut(line, "  ")
		if !found || len(sum) != 64 || name == "" {
			problem("a manifest line is not \"<sha256>  <name>\"")
			continue
		}
		listed[name] = true
		switch got, present := sums[name]; {
		case !present:
			problem("%s is in the manifest and not in the archive", Clean(name))
		case got != sum:
			problem("%s does not have the hash the manifest gives", Clean(name))
		}
	}
	for name := range sums {
		if name != bundleManifest && !listed[name] {
			problem("%s is in the archive and not in the manifest", Clean(name))
		}
	}

	// Every record has the reference it is stored under.
	have := map[string]bool{}
	recs, ok := contents[bundleRecords]
	if !ok {
		problem("%s is missing", bundleRecords)
	}
	lines := bufio.NewScanner(bytes.NewReader(recs))
	lines.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for lines.Scan() {
		if len(lines.Bytes()) == 0 {
			continue
		}
		var rec struct {
			Ref   string          `json:"ref"`
			Event *database.Event `json:"event"`
		}
		if err := json.Unmarshal(lines.Bytes(), &rec); err != nil || rec.Event == nil {
			problem("record %d cannot be read", rep.Records+1)
			rep.Records++
			continue
		}
		rep.Records++
		if RecordRef(rec.Event) != rec.Ref {
			problem("record %s does not match its reference: it was changed", Clean(cut(rec.Ref, 40)))
			continue
		}
		have[rec.Ref] = true
	}
	if err := lines.Err(); err != nil {
		problem("%s cannot be read to its end: %v", bundleRecords, err)
	}

	// Every record the case cites is there.
	raw, ok := contents[bundleCase]
	if !ok {
		problem("%s is missing", bundleCase)
		return rep, nil
	}
	var c Case
	if err := json.Unmarshal(raw, &c); err != nil {
		problem("%s cannot be read: %v", bundleCase, err)
		return rep, nil
	}
	rep.Kind, rep.ID = c.Kind, c.ID
	cited := map[string]bool{}
	cite := func(refs ...string) {
		for _, ref := range refs {
			if ref == "" || strings.HasPrefix(ref, "trip:") || cited[ref] {
				continue
			}
			cited[ref] = true
			if !have[ref] {
				problem("the case cites record %s, which is not among the records", Clean(cut(ref, 40)))
			}
		}
	}
	for _, s := range c.Sessions {
		if s == nil {
			continue
		}
		for _, st := range s.Timeline {
			cite(st.Refs...)
			cite(st.CausedBy)
		}
		for _, f := range s.Files {
			cite(f.Refs...)
			cite(f.Commands...)
		}
		for _, ev := range s.Evidence {
			cite(ev.Refs...)
		}
	}
	for _, l := range c.Links {
		for _, side := range l.Sessions {
			cite(side.Refs...)
		}
	}
	for _, g := range c.Gaps {
		cite(g.Refs...)
	}
	for _, r := range c.Records {
		if !have[r.Ref] {
			problem("the case lists record %s, which is not among the records", Clean(cut(r.Ref, 40)))
		}
	}
	rep.Cited = len(cited)
	return rep, nil
}
