package intelligence

import (
	"bufio"
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
