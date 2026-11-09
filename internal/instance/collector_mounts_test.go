package instance

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
	"github.com/qpot/qpot/internal/vectorstate"
	"gopkg.in/yaml.v3"
)

// collectorVolumes renders the compose file and returns the collector's
// volumes as host -> "container[:ro]", with the vector config it reads.
func collectorVolumes(t *testing.T, cfg *config.Config) (map[string]string, string) {
	t.Helper()
	sb, err := security.NewSandbox(&cfg.Security)
	if err != nil {
		t.Fatal(err)
	}
	g := &ComposeGenerator{Config: cfg, Sandbox: sb}
	out, err := g.Generate()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]struct {
			Volumes []string `yaml:"volumes"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	vols := map[string]string{}
	for _, v := range doc.Services["collector"].Volumes {
		// The host side may hold a drive colon ("C:\..."); the container side
		// always starts with "/".
		i := strings.Index(v, ":/")
		if i < 0 {
			t.Fatalf("collector volume %q has no container path", v)
		}
		vols[v[:i]] = v[i+1:]
	}
	vc, err := g.GenerateVectorConfig()
	if err != nil {
		t.Fatal(err)
	}
	return vols, vc
}

func collectorTestConfig(mut func(*config.Config)) *config.Config {
	cfg := config.Default("collector-mounts")
	cfg.QPotID = "qp_collectormountscollecto"
	for _, n := range []string{"cowrie", "conpot", "refrigeration"} {
		hp := cfg.Honeypots[n]
		hp.Enabled = true
		cfg.Honeypots[n] = hp
	}
	if mut != nil {
		mut(cfg)
	}
	return cfg
}

// The collector reads attacker-written logs and follows symlinks a compromised
// honeypot plants in its logs folder, so it must not see the instance folder's
// secrets: the database password in config.yaml, canary tokens, keys, the
// database files. Every path its own config reads must still be mounted.
func TestCollectorMountsOnlyWhatVectorReads(t *testing.T) {
	cases := map[string]func(*config.Config){
		"default": nil,
		"no sensors": func(c *config.Config) {
			c.Collector.IngestSuricata, c.Collector.IngestP0f, c.Collector.IngestFatt = false, false, false
		},
		"geoip from qpot":    func(c *config.Config) { c.Collector.GeoIPDBPath = "/data/geoip/dbip-country-lite.mmdb" },
		"geoip at top level": func(c *config.Config) { c.Collector.GeoIPDBPath = "/data/city.mmdb" },
		"geoip in honeypots": func(c *config.Config) { c.Collector.GeoIPDBPath = "/data/honeypots/geo/city.mmdb" },
		"geoip outside data": func(c *config.Config) { c.Collector.GeoIPDBPath = "/opt/geo/city.mmdb" },
	}
	includeRe := regexp.MustCompile(`(?m)^\s+- "(/data/[^"]+)"$`)
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := collectorTestConfig(mut)
			vols, vc := collectorVolumes(t, cfg)
			dp := cfg.DataPath
			for host, ctr := range vols {
				if host == dp || host == dp+"/" {
					t.Errorf("collector mounts the whole instance folder at %s", ctr)
				}
				for _, secret := range []string{"config.yaml", "canaries.json", "certs", "db", "intelligence", "logs", "cluster"} {
					if host == dp+"/"+secret {
						t.Errorf("collector mounts %s", secret)
					}
				}
				if strings.HasPrefix(ctr, "/data/") && !strings.HasSuffix(ctr, ":ro") && ctr != "/data/backup" {
					t.Errorf("collector mount %s -> %s is writable", host, ctr)
				}
			}
			mounted := func(p string) bool {
				for _, ctr := range vols {
					c := strings.TrimSuffix(ctr, ":ro")
					if p == c || strings.HasPrefix(p, c+"/") {
						return true
					}
				}
				return false
			}
			reads := []string{}
			for _, m := range includeRe.FindAllStringSubmatch(vc, -1) {
				reads = append(reads, path.Dir(strings.SplitN(m[1], "*", 2)[0]+"x"))
			}
			if len(reads) == 0 {
				t.Fatal("found no file sources in the vector config")
			}
			if g := cfg.Collector.GeoIPDBPath; strings.HasPrefix(g, "/data/") {
				reads = append(reads, g)
			}
			for _, p := range reads {
				if !mounted(p) {
					t.Errorf("vector reads %s but the collector does not mount it (mounts %v)", p, vols)
				}
			}
			if !strings.Contains(vols[dp+"/backup"], "/data/backup") || strings.HasSuffix(vols[dp+"/backup"], ":ro") {
				t.Errorf("collector backup folder is not writable: %v", vols)
			}
		})
	}
}

// The folders QPot creates before the collector starts: Docker would create a
// missing one owned by root. A file mount is never created as a folder.
func TestCollectorMountFoldersAreCreated(t *testing.T) {
	cfg := collectorTestConfig(func(c *config.Config) { c.Collector.GeoIPDBPath = "/data/city.mmdb" })
	cfg.DataPath = filepath.ToSlash(t.TempDir())
	var dirs, files int
	for _, cm := range collectorMounts(cfg) {
		if cm.Dir {
			dirs++
		} else if !cm.ReadOnly {
			t.Errorf("%s is writable but not a created folder", cm.Container)
		} else {
			files++
			if cm.Container != "/data/city.mmdb" {
				t.Errorf("unexpected file mount %s", cm.Container)
			}
		}
	}
	// honeypots, three sensors, backup, the collector's state; the GeoIP
	// file is mounted as a file.
	if dirs != 6 || files != 1 {
		t.Errorf("got %d folders and %d files, want 6 and 1", dirs, files)
	}
}

// The collector's checkpoints survive the container being recreated, and
// move only once the database and the backup acknowledge the events: disk
// cleanup empties a log only up to them, and a database outage must hold
// events back rather than drop them.
func TestCollectorCheckpointsMeanDelivered(t *testing.T) {
	for _, db := range []string{"clickhouse", "timescaledb"} {
		t.Run(db, func(t *testing.T) {
			cfg := collectorTestConfig(func(c *config.Config) { c.Database.Type = db })
			vols, vc := collectorVolumes(t, cfg)
			if got := vols[cfg.DataPath+"/"+vectorstate.Dir]; got != "/var/lib/vector" {
				t.Errorf("collector state mounted at %q, want a writable /var/lib/vector", got)
			}
			if !strings.Contains(vc, `data_dir: "/var/lib/vector"`) {
				t.Error("vector's data_dir moved")
			}
			var doc struct {
				Sinks   map[string]map[string]any `yaml:"sinks"`
				Sources map[string]map[string]any `yaml:"sources"`
			}
			if err := yaml.Unmarshal([]byte(vc), &doc); err != nil {
				t.Fatal(err)
			}
			for _, sink := range []string{db, "file_backup"} {
				s, ok := doc.Sinks[sink]
				if !ok {
					t.Fatalf("no %s sink (have %v)", sink, doc.Sinks)
				}
				if ack, _ := s["acknowledgements"].(map[string]any); ack["enabled"] != true {
					t.Errorf("%s sink does not acknowledge what it stored: %v", sink, s["acknowledgements"])
				}
				if req, _ := s["request"].(map[string]any); req["retry_attempts"] != nil {
					t.Errorf("%s sink gives up after %v retries: a long outage would drop events", sink, req["retry_attempts"])
				}
			}
			enabled := cfg.GetEnabledHoneypots()
			if len(enabled) == 0 {
				t.Fatal("no honeypot enabled")
			}
			for _, hp := range enabled {
				src, ok := doc.Sources[vectorstate.HoneypotSource(hp)]
				if !ok || src["type"] != "file" {
					t.Errorf("no file source %s", vectorstate.HoneypotSource(hp))
				}
				if _, set := src["fingerprint"]; set {
					t.Errorf("%s sets its own fingerprint: cleanup matches checkpoints by the default one", vectorstate.HoneypotSource(hp))
				}
			}
		})
	}
}

// CI's ClickHouse integration job must test the image instances run, and no
// third-party image may run a moving tag. QPot's own images
// (ghcr.io/yurillab/...) are rebuilt from main by images.yml.
func TestCIClickHouseImageMatchesCompose(t *testing.T) {
	ci, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ci), "image: "+ClickHouseImage+"\n") {
		t.Errorf("ci.yml does not run %s", ClickHouseImage)
	}
	for _, db := range []string{"clickhouse", "timescaledb"} {
		cfg := collectorTestConfig(func(c *config.Config) { c.Database.Type = db })
		out := renderComposeCfg(t, cfg)
		for _, line := range strings.Split(out, "\n") {
			l := strings.TrimSpace(line)
			if strings.HasPrefix(l, "image:") && !strings.HasPrefix(l, "image: ghcr.io/yurillab/") &&
				(strings.Contains(l, ":latest") || strings.HasSuffix(l, "-latest")) {
				t.Errorf("%s: moving image tag %q", db, l)
			}
		}
		want := map[string]string{"clickhouse": ClickHouseImage, "timescaledb": TimescaleDBImage}[db]
		if !strings.Contains(serviceBlock(out, "database"), "image: "+want+"\n") {
			t.Errorf("%s: database does not run %s", db, want)
		}
		if !strings.Contains(serviceBlock(out, "collector"), "image: "+CollectorImage+"\n") {
			t.Errorf("%s: collector does not run %s", db, CollectorImage)
		}
	}
	for _, img := range []string{ClickHouseImage, TimescaleDBImage, CollectorImage} {
		if !regexp.MustCompile(`^[a-z0-9./-]+:[0-9][0-9A-Za-z.-]*@sha256:[0-9a-f]{64}$`).MatchString(img) {
			t.Errorf("%s is not pinned to a version and digest", img)
		}
	}
}
