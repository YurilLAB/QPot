package instance

import (
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/netguard"
	"github.com/qpot/qpot/internal/security"
)

type composeDoc struct {
	Services map[string]struct {
		Image       string   `yaml:"image"`
		NetworkMode string   `yaml:"network_mode"`
		User        string   `yaml:"user"`
		ReadOnly    bool     `yaml:"read_only"`
		CapDrop     []string `yaml:"cap_drop"`
		CapAdd      []string `yaml:"cap_add"`
		Entrypoint  []string `yaml:"entrypoint"`
		Ports       []string `yaml:"ports"`
		Volumes     []string `yaml:"volumes"`
		Networks    any      `yaml:"networks"`
		Environment any      `yaml:"environment"`
		DependsOn   map[string]struct {
			Condition string `yaml:"condition"`
		} `yaml:"depends_on"`
		Healthcheck struct {
			Test []string `yaml:"test"`
		} `yaml:"healthcheck"`
	} `yaml:"services"`
	Networks map[string]struct {
		DriverOpts map[string]string `yaml:"driver_opts"`
	} `yaml:"networks"`
}

func renderGuardCompose(t *testing.T, cfg *config.Config) composeDoc {
	t.Helper()
	sb, err := security.NewSandbox(&cfg.Security)
	if err != nil {
		t.Skip("no sandbox:", err)
	}
	out, err := (&ComposeGenerator{Config: cfg, Sandbox: sb}).Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var doc composeDoc
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("compose is not YAML: %v", err)
	}
	return doc
}

// envMap reads a service's environment written as a map.
func envMap(v any) map[string]string {
	out := map[string]string{}
	if m, ok := v.(map[string]any); ok {
		for k, val := range m {
			if s, ok := val.(string); ok {
				out[k] = s
			}
		}
	}
	return out
}

func enableOnly(cfg *config.Config, names ...string) {
	for name := range cfg.Honeypots {
		hp := cfg.Honeypots[name]
		hp.Enabled = slices.Contains(names, name)
		cfg.Honeypots[name] = hp
	}
}

// TestEgressGuardService checks the guard the compose renders by default: it
// covers exactly the bridges of the honeypot networks, runs with nothing but
// the host network and NET_ADMIN, and every honeypot waits for it.
func TestEgressGuardService(t *testing.T) {
	cfg := config.Default("egress-guard")
	enableOnly(cfg, "cowrie", "conpot", "dionaea", "tanner")
	doc := renderGuardCompose(t, cfg)

	ng, ok := doc.Services["netguard"]
	if !ok {
		t.Fatal("no netguard service by default")
	}
	if ng.NetworkMode != "host" || ng.User != "0:0" || !ng.ReadOnly {
		t.Errorf("netguard: network_mode=%q user=%q read_only=%v", ng.NetworkMode, ng.User, ng.ReadOnly)
	}
	if !slices.Equal(ng.CapDrop, []string{"ALL"}) || !slices.Equal(ng.CapAdd, []string{"NET_ADMIN"}) {
		t.Errorf("netguard capabilities: drop %v add %v", ng.CapDrop, ng.CapAdd)
	}
	if len(ng.Ports) != 0 || len(ng.Volumes) != 0 || ng.Networks != nil {
		t.Errorf("netguard must publish, mount and join nothing: %v %v %v", ng.Ports, ng.Volumes, ng.Networks)
	}
	if ng.Image != GetHoneypotImage("ssh-proxy") || !slices.Equal(ng.Entrypoint, []string{"/qpot-netguard"}) {
		t.Errorf("netguard image %q entrypoint %v", ng.Image, ng.Entrypoint)
	}
	if !slices.Equal(ng.Healthcheck.Test, []string{"CMD", "/qpot-netguard", "check"}) {
		t.Errorf("netguard healthcheck %v", ng.Healthcheck.Test)
	}
	env := envMap(ng.Environment)
	if env["QPOT_NETGUARD_MODE"] != string(netguard.ModePrivate) || env["QPOT_NETGUARD_TABLE"] != egressGuardTable(cfg.InstanceName) {
		t.Errorf("netguard env %v", env)
	}

	// Its interfaces are the honeypot networks' bridges, all of them.
	var bridges []string
	for name, n := range doc.Networks {
		if strings.HasSuffix(name, "_net") {
			bridges = append(bridges, n.DriverOpts["com.docker.network.bridge.name"])
		}
	}
	sort.Strings(bridges)
	guarded := netguard.ParseIfaces(env["QPOT_NETGUARD_IFACES"])
	if !slices.Equal(guarded, bridges) || len(bridges) != 4 {
		t.Errorf("guarded %v, honeypot bridges %v", guarded, bridges)
	}
	spec := netguard.Spec{Table: env["QPOT_NETGUARD_TABLE"], Ifaces: guarded, Mode: netguard.ModePrivate}
	if err := spec.Validate(); err != nil {
		t.Errorf("rendered guard would not start: %v", err)
	}

	// Every attacker-facing service waits for it.
	for _, svc := range []string{"cowrie", "conpot", "dionaea", "tanner", "snare"} {
		s, ok := doc.Services[svc]
		if !ok {
			t.Errorf("service %s missing", svc)
			continue
		}
		if s.DependsOn["netguard"].Condition != "service_healthy" {
			t.Errorf("%s does not wait for the egress guard: %v", svc, s.DependsOn)
		}
	}
}

func TestEgressGuardSettings(t *testing.T) {
	cfg := config.Default("egress-off")
	enableOnly(cfg, "cowrie")
	cfg.Security.NetworkIsolation.AllowPrivateEgress = true
	doc := renderGuardCompose(t, cfg)
	if _, ok := doc.Services["netguard"]; ok {
		t.Error("allow_private_egress still renders the guard")
	}
	if len(doc.Services["cowrie"].DependsOn) != 0 {
		t.Errorf("cowrie depends on %v without a guard", doc.Services["cowrie"].DependsOn)
	}

	// block_outbound wins over allow_private_egress: it blocks more.
	cfg.Security.NetworkIsolation.BlockOutbound = true
	doc = renderGuardCompose(t, cfg)
	if m := envMap(doc.Services["netguard"].Environment)["QPOT_NETGUARD_MODE"]; m != string(netguard.ModeAll) {
		t.Errorf("block_outbound renders mode %q", m)
	}

	// No honeypots, no guard (and no dangling dependency).
	none := config.Default("egress-none")
	enableOnly(none)
	if _, ok := renderGuardCompose(t, none).Services["netguard"]; ok {
		t.Error("guard rendered for an instance without honeypots")
	}

	// Instances share the host's nftables, so each owns its table.
	if egressGuardTable("a") == egressGuardTable("b") {
		t.Error("two instances share an egress table")
	}
}

// TestEgressGuardCoversEveryHoneypot: with every honeypot enabled the guard
// still validates (interface names, count) and covers each network.
func TestEgressGuardCoversEveryHoneypot(t *testing.T) {
	cfg := config.Default("egress-all")
	var all []string
	for name := range cfg.Honeypots {
		all = append(all, name)
	}
	enableOnly(cfg, all...)
	eg, err := egressGuardFor(cfg)
	if err != nil || !eg.Enabled {
		t.Fatalf("guard for all honeypots: %+v %v", eg, err)
	}
	ifaces := netguard.ParseIfaces(eg.Ifaces)
	for _, name := range all {
		if !slices.Contains(ifaces, bridgeName(cfg.InstanceName, name)) {
			t.Errorf("%s's bridge is not guarded", name)
		}
	}
}

func FuzzEgressGuardInstanceName(f *testing.F) {
	f.Add("default")
	f.Add("a b;c\n")
	f.Add(strings.Repeat("x", 300))
	f.Fuzz(func(t *testing.T, inst string) {
		cfg := config.Default("fuzz")
		cfg.InstanceName = inst
		enableOnly(cfg, "cowrie", "ssh-proxy", "heralding")
		eg, err := egressGuardFor(cfg)
		if err != nil || !eg.Enabled {
			t.Fatalf("instance %q: guard %+v %v", inst, eg, err)
		}
	})
}
