package instance

import (
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
