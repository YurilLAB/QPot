package intelligence

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/database"
)

// catCorpusSample is one line of a *.jsonl file under testdata/attack_corpus.
// expect lists the category IDs the sample must get; expect_not those it must
// not. A benign or near-miss sample has an empty expect and a filled
// expect_not.
type catCorpusSample struct {
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
	// Technique is the ATT&CK technique the classifier must assign with
	// its built-in rules ("" for none). Every sample states one.
	Technique *string `json:"technique"`
}

func (s catCorpusSample) event() *database.Event {
	return &database.Event{
		Honeypot:  s.Honeypot,
		EventType: s.EventType,
		Protocol:  s.Protocol,
		DestPort:  s.DestPort,
		Username:  s.Username,
		Password:  s.Password,
		Command:   s.Command,
		Payload:   []byte(s.Payload),
		Metadata:  s.Metadata,
	}
}

const catCorpusDir = "testdata/attack_corpus"

// TestCategoryCorpus loads every *.jsonl under testdata/attack_corpus, runs
// the categoriser over each sample, and fails on a missing expected category
// or a forbidden one, naming the sample id. It passes when the folder is
// empty or absent (the auditor writes the corpus concurrently).
func TestCategoryCorpus(t *testing.T) {
	entries, err := os.ReadDir(catCorpusDir)
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("no attack corpus yet")
	}
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".jsonl") {
			files = append(files, filepath.Join(catCorpusDir, e.Name()))
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		t.Skip("no attack corpus files yet")
	}

	total := 0
	for _, file := range files {
		samples, err := catReadCorpus(file)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(file), err)
			continue
		}
		for _, s := range samples {
			total++
			got := Categorize(s.event())
			set := make(map[string]bool, len(got))
			for _, c := range got {
				set[c] = true
			}
			for _, want := range s.Expect {
				if !set[want] {
					t.Errorf("%s [%s]: missing category %q (got %v)", filepath.Base(file), s.ID, want, got)
				}
			}
			for _, no := range s.ExpectNot {
				if set[no] {
					t.Errorf("%s [%s]: forbidden category %q (got %v)", filepath.Base(file), s.ID, no, got)
				}
			}
		}
	}
	t.Logf("category corpus: %d samples across %d file(s)", total, len(files))
}

// TestTechniqueCorpus classifies every corpus sample with the built-in rules
// (the worker's offline state) and requires the technique the sample states:
// the technique a category's evidence names, the same one online, where the
// rules generated from ATT&CK only add to commands no category names.
func TestTechniqueCorpus(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(catCorpusDir, "*.jsonl"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus: %v", err)
	}
	c := newTestClassifierT(t)
	total, right := 0, 0
	for _, file := range files {
		samples, err := catReadCorpus(file)
		if err != nil {
			t.Fatalf("%s: %v", filepath.Base(file), err)
		}
		for _, s := range samples {
			total++
			if s.Technique == nil {
				t.Errorf("%s [%s]: states no technique", filepath.Base(file), s.ID)
				continue
			}
			ev := s.event()
			c.Classify(context.Background(), ev)
			if ev.TechniqueID != *s.Technique {
				t.Errorf("%s [%s]: technique %q (%s), want %q; categories %v", filepath.Base(file), s.ID, ev.TechniqueID, ev.TechniqueName, *s.Technique, ev.Categories)
				continue
			}
			if ev.TechniqueID != "" && (ev.TacticID == "" || ev.TacticName == "" || ev.KillChainStage == "" || ev.Confidence <= 0 || ev.Confidence > 1) {
				t.Errorf("%s [%s]: incomplete classification %+v", filepath.Base(file), s.ID, ev)
			}
			right++
		}
	}
	if total < 200 {
		t.Fatalf("only %d samples", total)
	}
	t.Logf("technique corpus: %d/%d samples", right, total)
}

// The rules assign only current ATT&CK IDs: these were revoked in Enterprise
// v18 (Defense Evasion split into stealth and defense-impairment) and the
// current ICS matrix. Each rule's tactic ID is the one of its tactic.
func TestDefaultRulesUseCurrentATTCKIDs(t *testing.T) {
	revoked := map[string]string{
		"T0855": "T1692.001", "T0856": "T1692.002", "T0803": "T1691.001", "T0804": "T1691.002",
		"T0812": "T1694.001", "T0891": "T1694.002", "T0839": "T1693.002", "T0857": "T1693.001", "T0805": "T1695.001",
		"T1562": "T1685", "T1562.001": "T1685", "T1562.003": "T1690", "T1562.004": "T1686",
		"T1562.006": "T1685", "T1562.012": "T1685.004", "T1070.002": "T1685.006",
	}
	for _, r := range DefaultRules() {
		if by, ok := revoked[r.TechniqueID]; ok {
			t.Errorf("%s %q is revoked (by %s)", r.TechniqueID, r.Name, by)
		}
		want := enterpriseTactics[r.TacticName]
		if strings.HasPrefix(r.TechniqueID, "T0") || r.TechniqueID == "T1692.001" {
			want = icsTactics[r.TacticName]
		}
		if want == "" || r.TacticID != want {
			t.Errorf("%s %q: tactic %q has ID %q, want %q", r.TechniqueID, r.Name, r.TacticName, r.TacticID, want)
		}
		if r.KillChain == "" {
			t.Errorf("%s %q: no kill-chain stage", r.TechniqueID, r.Name)
		}
	}
}

// catReadCorpus reads one JSONL file, rejecting unknown contract fields so a
// typo in a label field is a failure, not a silent miss.
func catReadCorpus(path string) ([]catCorpusSample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []catCorpusSample
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		var s catCorpusSample
		if err := dec.Decode(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, sc.Err()
}
