package instance

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/vectorstate"
	"gopkg.in/yaml.v3"
)

// globRe turns one of the collector's include or exclude patterns into a
// regexp: ** spans folders, * and ? stay within one.
func globRe(t *testing.T, g string) *regexp.Regexp {
	t.Helper()
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(g); i++ {
		switch {
		case strings.HasPrefix(g[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 2
		case strings.HasPrefix(g[i:], "**"):
			b.WriteString(".*")
			i++
		case g[i] == '*':
			b.WriteString("[^/]*")
		case g[i] == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(g[i : i+1]))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// TestCollectorSourcesMatchTheConfig: CollectorSources, which seeding
// follows, selects exactly the files each generated file source reads, and
// every file source reads a log it has no checkpoint for from its start.
func TestCollectorSourcesMatchTheConfig(t *testing.T) {
	cfg := collectorTestConfig(func(c *config.Config) {
		c.Collector.IngestSuricata, c.Collector.IngestP0f, c.Collector.IngestFatt = true, true, true
	})
	_, vc := collectorVolumes(t, cfg)
	var doc struct {
		Sources map[string]struct {
			Type     string   `yaml:"type"`
			Include  []string `yaml:"include"`
			Exclude  []string `yaml:"exclude"`
			ReadFrom string   `yaml:"read_from"`
		} `yaml:"sources"`
	}
	if err := yaml.Unmarshal([]byte(vc), &doc); err != nil {
		t.Fatal(err)
	}
	srcs := requireCollectorSources(t, cfg)
	files := 0
	for _, s := range doc.Sources {
		if s.Type == "file" {
			files++
			if s.ReadFrom != "beginning" {
				t.Errorf("a file source reads from %q: what it never delivered before a restart would be skipped", s.ReadFrom)
			}
		}
	}
	if len(srcs) != files || files < 4 {
		t.Fatalf("CollectorSources lists %d sources, the config has %d file sources", len(srcs), files)
	}
	samples := []string{"cowrie.json", "cowrie.log", "a/b.json", "a/b/c.log", "cowrie.json.1", "x.txt", ".hidden.json",
		"tty/x.log", "tty/a/b.json", "tty", "eve.json", "x.json", "sub/x.json", "p0f.json", "fatt.log", "sub/fatt.log"}
	for _, src := range srcs {
		s, ok := doc.Sources[src.Name]
		if !ok || s.Type != "file" {
			t.Errorf("no file source %s in the config", src.Name)
			continue
		}
		for _, rel := range samples {
			p := "/data/" + src.Dir + "/" + rel
			reads := false
			for _, g := range s.Include {
				reads = reads || globRe(t, g).MatchString(p)
			}
			for _, g := range s.Exclude {
				reads = reads && !globRe(t, g).MatchString(p)
			}
			if reads != src.Read(rel) {
				t.Errorf("%s: the collector reads %s: %v; CollectorSources says %v", src.Name, rel, reads, src.Read(rel))
			}
		}
	}
}

// TestCollectorStateIsSeededOnce: the first time the collector keeps its
// state, what the logs hold counts as delivered; after that QPot never
// touches the collector's checkpoints again.
func TestCollectorStateIsSeededOnce(t *testing.T) {
	cfg := collectorTestConfig(nil)
	cfg.DataPath = t.TempDir()
	cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
	log := filepath.Join(cfg.DataPath, "honeypots", "cowrie", "logs", "cowrie.json")
	if err := os.MkdirAll(filepath.Dir(log), 0o755); err != nil {
		t.Fatal(err)
	}
	old := "{\"before\":\"the upgrade\"}\n"
	if err := os.WriteFile(log, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.generateServiceConfigs(); err != nil {
		t.Fatal(err)
	}
	src := vectorstate.HoneypotSource("cowrie")
	fp, _ := vectorstate.Fingerprint(strings.NewReader(old))
	if d := vectorstate.Load(cfg.DataPath, src); d[fp] != int64(len(old)) {
		t.Fatalf("the log there before was not seeded as delivered: %v", d)
	}
	// The collector's own checkpoints from then on are left alone.
	cp := filepath.Join(cfg.DataPath, vectorstate.Dir, src, "checkpoints.json")
	own := `{"version":"1","checkpoints":[]}`
	if err := os.WriteFile(cp, []byte(own), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cp); err != nil { // even with them gone
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := m.generateServiceConfigs(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cp); !os.IsNotExist(err) {
		t.Errorf("seeded again once the collector kept its state: %v", err)
	}
}
