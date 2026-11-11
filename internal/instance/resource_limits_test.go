package instance

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"gopkg.in/yaml.v3"
)

// TestEveryServiceCapsMemoryAndSwap renders the widest stacks (every
// honeypot with both databases, and the SSH organization's cells) and checks
// that every service has CPU and memory limits and a swap limit equal to its
// memory limit. Without memswap_limit Docker gives a container as much again
// in swap, so a 512M honeypot held 1 GiB, and unlimited swap where the daemon
// cannot limit it; cgroup v2 ignores mem_swappiness.
func TestEveryServiceCapsMemoryAndSwap(t *testing.T) {
	type service struct {
		Deploy struct {
			Resources struct {
				Limits struct {
					CPUs   string `yaml:"cpus"`
					Memory string `yaml:"memory"`
				} `yaml:"limits"`
			} `yaml:"resources"`
		} `yaml:"deploy"`
		MemswapLimit string `yaml:"memswap_limit"`
	}
	check := func(t *testing.T, out string, want ...string) {
		t.Helper()
		var doc struct {
			Services map[string]service `yaml:"services"`
		}
		if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("compose does not parse: %v", err)
		}
		for _, name := range want {
			if _, ok := doc.Services[name]; !ok {
				t.Errorf("service %q missing from the rendered stack", name)
			}
		}
		for name, s := range doc.Services {
			limits := s.Deploy.Resources.Limits
			if limits.CPUs == "" || limits.Memory == "" || !strings.HasSuffix(limits.Memory, "M") {
				t.Errorf("%s: cpus %q memory %q, want both limited", name, limits.CPUs, limits.Memory)
			}
			if s.MemswapLimit != limits.Memory {
				t.Errorf("%s: memswap_limit %q, want the memory limit %q", name, s.MemswapLimit, limits.Memory)
			}
		}
	}
	for _, db := range []string{"clickhouse", "timescaledb"} {
		t.Run("all-honeypots-"+db, func(t *testing.T) {
			cfg := config.Default("limits-" + db)
			cfg.QPotID = "qp_limits000000000000000000"
			cfg.Database.Type = db
			for name, hp := range cfg.Honeypots {
				hp.Enabled = true
				cfg.Honeypots[name] = hp
			}
			// A honeypot's own limits must reach its swap limit too.
			cowrie := cfg.Honeypots["cowrie"]
			cowrie.Resources = config.HoneypotResources{UseCustomLimits: true, MaxCPUPercent: 30, MaxMemoryMB: 200, MaxPids: 40}
			cfg.Honeypots["cowrie"] = cowrie
			out := renderComposeCfg(t, cfg)
			check(t, out, "database", "collector", "netguard", "cowrie", "tanner", "ssh-proxy")
			if !strings.Contains(out, "memory: 200M\n") || !strings.Contains(out, "memswap_limit: 200M\n") {
				t.Error("cowrie's custom 200M limit did not reach its memory and swap limits")
			}
		})
	}
	t.Run("ssh-organization", func(t *testing.T) {
		cfg := organizationTestConfig(t)
		if err := prepareSSHOrganization(cfg); err != nil {
			t.Fatal(err)
		}
		cells := requireSSHOrgCells(t, cfg)
		want := []string{"collector", "netguard", "ssh-proxy"}
		for _, cell := range cells {
			want = append(want, cell.App, cell.Backup, cell.Database)
		}
		check(t, renderComposeCfg(t, cfg), want...)
	})
}

// TestDatabaseHasItsOwnLimits: the global limits are sized for one honeypot.
// With them (512 MiB, half a CPU by default) and swap capped, the pinned
// ClickHouse ran at its memory limit within minutes and a single client
// started inside the container stalled it. The database gets at least 1 GiB
// and one CPU, more when the operator sets more, and a server configuration
// sized for that.
func TestDatabaseHasItsOwnLimits(t *testing.T) {
	for _, tc := range []struct {
		name          string
		memMB         int64
		cpuPercent    float64
		wantMem, cpus string
	}{
		{"defaults", 512, 50, "1024M", "1"},
		{"small host limits", 128, 10, "1024M", "1"},
		{"operator gives more", 4096, 200, "4096M", "2"},
	} {
		for _, db := range []string{"clickhouse", "timescaledb"} {
			cfg := everyHoneypotConfig(t, func(c *config.Config) {
				c.Database.Type = db
				c.Security.ResourceLimits.MaxMemoryMB = tc.memMB
				c.Security.ResourceLimits.MaxCPUPercent = tc.cpuPercent
			})
			var doc struct {
				Services map[string]struct {
					Volumes []string `yaml:"volumes"`
					MemSwap string   `yaml:"memswap_limit"`
					Deploy  struct {
						Resources struct {
							Limits struct {
								CPUs   string `yaml:"cpus"`
								Memory string `yaml:"memory"`
							} `yaml:"limits"`
						} `yaml:"resources"`
					} `yaml:"deploy"`
				} `yaml:"services"`
			}
			if err := yaml.Unmarshal([]byte(renderComposeFor(t, cfg)), &doc); err != nil {
				t.Fatal(err)
			}
			svc := doc.Services["database"]
			lim := svc.Deploy.Resources.Limits
			if lim.Memory != tc.wantMem || svc.MemSwap != tc.wantMem || lim.CPUs != tc.cpus {
				t.Errorf("%s/%s: database memory %q swap %q cpus %q, want %s %s %s", tc.name, db, lim.Memory, svc.MemSwap, lim.CPUs, tc.wantMem, tc.wantMem, tc.cpus)
			}
			// A honeypot keeps the limit the operator set.
			if got := doc.Services["cowrie"].Deploy.Resources.Limits.Memory; got != fmt.Sprintf("%dM", tc.memMB) {
				t.Errorf("%s/%s: cowrie memory %q, want %dM", tc.name, db, got, tc.memMB)
			}
			mounted := slices.ContainsFunc(svc.Volumes, func(v string) bool {
				return strings.HasSuffix(v, "clickhouse-limits.xml:/etc/clickhouse-server/config.d/qpot-limits.xml:ro")
			})
			if mounted != (db == "clickhouse") {
				t.Errorf("%s/%s: server limits file mounted = %v", tc.name, db, mounted)
			}
		}
	}
}

// TestClickHouseLimitsConfig: the embedded server configuration is well
// formed, written next to the Keeper configuration, and removes the internal
// tables that grow without limit.
func TestClickHouseLimitsConfig(t *testing.T) {
	var root struct {
		XMLName xml.Name
		Removed []struct {
			XMLName xml.Name
			Remove  string `xml:"remove,attr"`
		} `xml:",any"`
	}
	if err := xml.Unmarshal(clickHouseLimitsConfig, &root); err != nil || root.XMLName.Local != "clickhouse" {
		t.Fatalf("clickhouse_limits.xml is not a <clickhouse> document: %v", err)
	}
	removed := map[string]bool{}
	for _, e := range root.Removed {
		if e.Remove == "1" {
			removed[e.XMLName.Local] = true
		}
	}
	for _, table := range []string{"metric_log", "asynchronous_metric_log", "trace_log", "text_log", "processors_profile_log", "part_log"} {
		if !removed[table] {
			t.Errorf("system.%s is not removed: it is written every few seconds and never trimmed", table)
		}
	}
	// What ran and what crashed stay, with an expiry.
	for _, kept := range []string{"query_log", "crash_log"} {
		if removed[kept] || !bytes.Contains(clickHouseLimitsConfig, []byte("<"+kept+">")) {
			t.Errorf("system.%s must stay, with a TTL", kept)
		}
	}
	cfg := config.Default("ch-limits")
	cfg.DataPath = t.TempDir()
	if err := prepareClickHouseKeeper(cfg); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{clickHouseLimitsPath(cfg), clickHouseKeeperPath(cfg)} {
		if st, err := os.Stat(path); err != nil || st.Size() == 0 {
			t.Errorf("%s was not written: %v", path, err)
		}
	}
	cfg.Database.Type = "timescaledb"
	cfg.DataPath = t.TempDir()
	if err := prepareClickHouseKeeper(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(clickHouseLimitsPath(cfg)); err == nil {
		t.Error("a TimescaleDB instance got ClickHouse configuration")
	}
}
