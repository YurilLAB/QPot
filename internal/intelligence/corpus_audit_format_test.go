package intelligence

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// auditCorpusSample is one line of a testdata/attack_corpus/*.jsonl file.
type auditCorpusSample struct {
	ID        string            `json:"id"`
	Source    string            `json:"source"`
	Honeypot  string            `json:"honeypot"`
	EventType string            `json:"event_type"`
	Protocol  string            `json:"protocol"`
	DestPort  int               `json:"dest_port"`
	Username  string            `json:"username"`
	Password  string            `json:"password"`
	Command   string            `json:"command"`
	Payload   string            `json:"payload"`
	Metadata  map[string]string `json:"metadata"`
	Expect    []string          `json:"expect"`
	ExpectNot []string          `json:"expect_not"`
}

// auditCorpusDir is the attack corpus directory.
const auditCorpusDir = "testdata/attack_corpus"

// auditLoadCorpus reads every *.jsonl sample under testdata/attack_corpus.
func auditLoadCorpus(t *testing.T) []auditCorpusSample {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(auditCorpusDir, "*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no corpus files under %s", auditCorpusDir)
	}
	var samples []auditCorpusSample
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		ln := 0
		for sc.Scan() {
			ln++
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var s auditCorpusSample
			dec := json.NewDecoder(strings.NewReader(line))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&s); err != nil {
				t.Errorf("%s:%d does not parse: %v", filepath.Base(path), ln, err)
				continue
			}
			samples = append(samples, s)
		}
		f.Close()
		if err := sc.Err(); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	return samples
}

// TestCorpusAuditFormat checks every corpus line: it parses, its id is
// unique, its categories are from the published set, a negative has an empty
// expect with a filled expect_not, expect and expect_not never overlap, and
// it carries a source.
func TestCorpusAuditFormat(t *testing.T) {
	samples := auditLoadCorpus(t)
	if len(samples) < 150 {
		t.Errorf("corpus has %d samples, want at least 150", len(samples))
	}
	ids := make(map[string]bool)
	negatives := 0
	for _, s := range samples {
		if s.ID == "" {
			t.Errorf("sample with empty id (source %q)", s.Source)
			continue
		}
		if ids[s.ID] {
			t.Errorf("duplicate id %q", s.ID)
		}
		ids[s.ID] = true
		if strings.TrimSpace(s.Source) == "" {
			t.Errorf("%s: empty source", s.ID)
		}
		if s.Honeypot == "" || s.EventType == "" {
			t.Errorf("%s: honeypot and event_type are required", s.ID)
		}
		for _, c := range s.Expect {
			if !IsCategory(c) {
				t.Errorf("%s: expect has unknown category %q", s.ID, c)
			}
		}
		for _, c := range s.ExpectNot {
			if !IsCategory(c) {
				t.Errorf("%s: expect_not has unknown category %q", s.ID, c)
			}
		}
		seen := map[string]bool{}
		for _, c := range s.Expect {
			seen[c] = true
		}
		for _, c := range s.ExpectNot {
			if seen[c] {
				t.Errorf("%s: %q is in both expect and expect_not", s.ID, c)
			}
		}
		if len(s.Expect) == 0 {
			negatives++
			if len(s.ExpectNot) == 0 {
				t.Errorf("%s: a negative needs a filled expect_not", s.ID)
			}
		}
	}
	if min := len(samples) / 3; negatives < min {
		t.Errorf("corpus has %d negatives, want at least a third (%d)", negatives, min)
	}
	t.Logf("corpus: %d samples, %d negatives", len(samples), negatives)
}
