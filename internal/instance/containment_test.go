package instance

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/hostsetup"
	"github.com/qpot/qpot/internal/security"
	"gopkg.in/yaml.v3"
)

// everyHoneypotConfig returns a config with every honeypot of the default
// catalog enabled, for checks that must hold whatever is switched on.
func everyHoneypotConfig(t *testing.T, mut func(*config.Config)) *config.Config {
	t.Helper()
	cfg := config.Default("contain")
	cfg.QPotID = "qp_containcontaincontainco"
	for name, hp := range cfg.Honeypots {
		hp.Enabled = true
		cfg.Honeypots[name] = hp
	}
	hp := cfg.Honeypots[sshProxyHoneypot]
	if hp.CustomConfig == nil {
		hp.CustomConfig = map[string]string{}
	}
	hp.CustomConfig["image_source"] = "local"
	cfg.Honeypots[sshProxyHoneypot] = hp
	if mut != nil {
		mut(cfg)
	}
	return cfg
}

func renderComposeFor(t *testing.T, cfg *config.Config) string {
	t.Helper()
	sb, err := security.NewSandbox(&cfg.Security)
	if err != nil {
		t.Fatal(err)
	}
	out, err := (&ComposeGenerator{Config: cfg, Sandbox: sb}).Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return out
}

// TestMandatoryContainmentCannotBeSwitchedOff renders every honeypot with the
// former off switches all set to false. Each attacker-facing service must
// still have a read-only root, no capabilities beyond a reviewed add-back,
// no-new-privileges, resource limits with swap capped, its own network, and
// none of the settings that hand a container the host.
func TestMandatoryContainmentCannotBeSwitchedOff(t *testing.T) {
	for _, db := range []string{"clickhouse", "timescaledb"} {
		cfg := everyHoneypotConfig(t, func(c *config.Config) {
			c.Database.Type = db
			c.Security.ReadOnlyFilesystem = false
			c.Security.DropCapabilities = false
			c.Security.NoNewPrivileges = false
			c.Security.NetworkIsolation.SeparateNetworks = false
		})
		out := renderComposeFor(t, cfg)
		var doc struct {
			Services map[string]struct {
				ReadOnly    bool              `yaml:"read_only"`
				SecurityOpt []string          `yaml:"security_opt"`
				CapDrop     []string          `yaml:"cap_drop"`
				CapAdd      []string          `yaml:"cap_add"`
				Privileged  bool              `yaml:"privileged"`
				NetworkMode string            `yaml:"network_mode"`
				PID         string            `yaml:"pid"`
				IPC         string            `yaml:"ipc"`
				UsernsMode  string            `yaml:"userns_mode"`
				Devices     []string          `yaml:"devices"`
				Volumes     []string          `yaml:"volumes"`
				Labels      map[string]string `yaml:"labels"`
				Networks    yaml.Node         `yaml:"networks"`
				MemSwap     string            `yaml:"memswap_limit"`
				Deploy      struct {
					Resources struct {
						Limits struct {
							CPUs   string `yaml:"cpus"`
							Memory string `yaml:"memory"`
							Pids   int    `yaml:"pids"`
						} `yaml:"limits"`
					} `yaml:"resources"`
				} `yaml:"deploy"`
			} `yaml:"services"`
		}
		if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("%s: compose is not YAML: %v", db, err)
		}
		// Capabilities a honeypot image may get back. Anything else here
		// (SYS_ADMIN, NET_ADMIN, SYS_PTRACE, ...) is a way out of the box.
		allowedCaps := map[string]bool{
			"SETUID": true, "SETGID": true, "NET_BIND_SERVICE": true, "CHOWN": true, "DAC_OVERRIDE": true,
			"FOWNER": true, "SETPCAP": true, "KILL": true, "SYS_CHROOT": true, "AUDIT_WRITE": true,
			"NET_RAW": true, "SYS_NICE": true,
		}
		// The only writable roots, each for a stated reason. HiFi backends
		// (matched by label below) are disposable real systems whose
		// writable layer is thrown away after every session. snare writes
		// its log and its cloned pages under /opt/snare, next to the pages
		// the image ships, so that folder cannot be a tmpfs; it is listed
		// in doc/security.md as the one exception.
		writableRoot := map[string]bool{"snare": true}
		guests := 0
		networkUse := map[string][]string{}
		for name, svc := range doc.Services {
			if svc.Labels["qpot.honeypot"] == "" {
				continue // database, collector, egress guard: not attacker-facing
			}
			guests++
			if !svc.ReadOnly && !writableRoot[name] && svc.Labels["qpot.honeypot"] != "ssh-backend" {
				t.Errorf("%s/%s: root filesystem is writable", db, name)
			}
			if !slices.Contains(svc.SecurityOpt, "no-new-privileges:true") {
				t.Errorf("%s/%s: no-new-privileges missing (%v)", db, name, svc.SecurityOpt)
			}
			if !slices.Contains(svc.CapDrop, "ALL") {
				t.Errorf("%s/%s: capabilities not dropped (%v)", db, name, svc.CapDrop)
			}
			for _, c := range svc.CapAdd {
				if !allowedCaps[c] {
					t.Errorf("%s/%s: adds capability %s", db, name, c)
				}
			}
			if svc.Privileged || svc.NetworkMode == "host" || svc.PID != "" || svc.IPC == "host" || svc.UsernsMode == "host" || len(svc.Devices) != 0 {
				t.Errorf("%s/%s: shares the host (privileged=%v network=%q pid=%q ipc=%q userns=%q devices=%v)",
					db, name, svc.Privileged, svc.NetworkMode, svc.PID, svc.IPC, svc.UsernsMode, svc.Devices)
			}
			for _, v := range svc.Volumes {
				if strings.Contains(v, "docker.sock") || strings.HasPrefix(v, "/:") || strings.HasPrefix(v, "/proc") || strings.HasPrefix(v, "/sys") {
					t.Errorf("%s/%s: mounts %s", db, name, v)
				}
				if strings.Contains(v, "qpot.id") {
					t.Errorf("%s/%s: is given the QPot ID file (%s)", db, name, v)
				}
			}
			lim := svc.Deploy.Resources.Limits
			if lim.CPUs == "" || lim.CPUs == "0" || lim.Memory == "" || lim.Memory == "0M" || lim.Pids <= 0 {
				t.Errorf("%s/%s: unbounded resources %+v", db, name, lim)
			}
			if svc.MemSwap == "" || svc.MemSwap != lim.Memory {
				t.Errorf("%s/%s: swap limit %q is not the memory limit %q", db, name, svc.MemSwap, lim.Memory)
			}
			var nets []string
			switch svc.Networks.Kind {
			case yaml.SequenceNode:
				for _, n := range svc.Networks.Content {
					nets = append(nets, n.Value)
				}
			case yaml.MappingNode:
				for i := 0; i < len(svc.Networks.Content); i += 2 {
					nets = append(nets, svc.Networks.Content[i].Value)
				}
			}
			if len(nets) == 0 {
				t.Errorf("%s/%s: no network of its own", db, name)
			}
			for _, n := range nets {
				if n == "qpot_internal" || n == "qpot_dbhost" {
					t.Errorf("%s/%s: joins the control network %s", db, name, n)
				}
				networkUse[n] = append(networkUse[n], svc.Labels["qpot.honeypot"])
			}
		}
		if guests < 20 {
			t.Fatalf("%s: only %d attacker-facing services rendered", db, guests)
		}
		// No bridge is shared by two different honeypots (a honeypot and its
		// own companions - HiFi's cells, tanner's services - share theirs).
		for n, users := range networkUse {
			owners := map[string]bool{}
			for _, u := range users {
				if u == "ssh-backend" {
					u = sshProxyHoneypot
				}
				owners[u] = true
			}
			if len(owners) > 1 {
				t.Errorf("%s: network %s is shared by %v", db, n, users)
			}
		}
	}
}

// TestGeneratedFilesNeverCarryTheQPotID is the regression test for the QPot
// ID (the API credential) reaching the collector: it was stamped into every
// event (and so into the collector's console log and the log backups), set
// in the database's and collector's environment (and copied from there into
// every line of their container logs) and mounted into both as a file.
func TestGeneratedFilesNeverCarryTheQPotID(t *testing.T) {
	for _, db := range []string{"clickhouse", "timescaledb"} {
		for _, geo := range []string{"", "/data/geoip/GeoLite2-City.mmdb"} {
			cfg := everyHoneypotConfig(t, func(c *config.Config) {
				c.Database.Type = db
				c.Collector.GeoIPDBPath = geo
				c.Collector.IngestSuricata, c.Collector.IngestP0f, c.Collector.IngestFatt = true, true, true
			})
			sb, _ := security.NewSandbox(&cfg.Security)
			g := &ComposeGenerator{Config: cfg, Sandbox: sb}
			vector, err := g.GenerateVectorConfig()
			if err != nil {
				t.Fatal(err)
			}
			for name, out := range map[string]string{"docker-compose.yml": renderComposeFor(t, cfg), "vector.yaml": vector} {
				if strings.Contains(out, cfg.QPotID) {
					i := strings.Index(out, cfg.QPotID)
					t.Errorf("%s (%s, geoip=%q) contains the QPot ID near: %q", name, db, geo, out[max(0, i-80):i])
				}
				for _, banned := range []string{"QPOT_ID", "qpot.id", "/run/secrets/qpot_id"} {
					if strings.Contains(out, banned) {
						t.Errorf("%s (%s): still refers to %s", name, db, banned)
					}
				}
			}
			sensor := cfg.SensorID()
			if sensor == "" || sensor == cfg.QPotID {
				t.Fatalf("sensor ID %q is not a distinct identifier", sensor)
			}
			// Each event transform stamps the sensor ID and removes a
			// qpot_id a log line brought with it.
			if got, want := strings.Count(vector, `.sensor_id = "`+sensor+`"`), 4; got != want {
				t.Errorf("%s: sensor ID stamped %d times, want %d (honeypots, suricata, p0f, fatt)", db, got, want)
			}
			if got := strings.Count(vector, "del(.qpot_id)"); got != 4 {
				t.Errorf("%s: qpot_id removed in %d transforms, want 4", db, got)
			}
		}
	}
}

// TestScannerEventsAreNeverFiltered: the collector used to drop every event
// whose text named a scanner (nmap, masscan, zgrab, censys, shodan), on by
// default, so an attacker running nmap inside a honeypot left no stored
// event. No transform between the logs and the sinks may drop on content.
func TestScannerEventsAreNeverFiltered(t *testing.T) {
	for _, on := range []bool{true, false} {
		out := genVectorCfg(t, func(c *config.Config) { c.Stealth.BlockCommonProbes = on })
		var vc struct {
			Transforms map[string]struct {
				Type   string   `yaml:"type"`
				Inputs []string `yaml:"inputs"`
				Source string   `yaml:"source"`
			} `yaml:"transforms"`
			Sinks map[string]struct {
				Inputs []string `yaml:"inputs"`
			} `yaml:"sinks"`
		}
		if err := yaml.Unmarshal([]byte(out), &vc); err != nil {
			t.Fatal(err)
		}
		for name, tr := range vc.Transforms {
			if tr.Type != "remap" {
				t.Errorf("tagging=%v: transform %s is a %q; only remaps may sit in the event path", on, name, tr.Type)
			}
		}
		tag, ok := vc.Transforms["tag_scanners"]
		if !ok {
			t.Fatalf("tagging=%v: no tag_scanners transform", on)
		}
		if strings.Contains(tag.Source, "abort") {
			t.Errorf("tagging=%v: tag_scanners can drop an event:\n%s", on, tag.Source)
		}
		if on != strings.Contains(tag.Source, ".metadata.scanner") {
			t.Errorf("tagging=%v: tag source is\n%s", on, tag.Source)
		}
		for name, sink := range vc.Sinks {
			if len(sink.Inputs) != 1 || sink.Inputs[0] != "tag_scanners" {
				t.Errorf("tagging=%v: sink %s reads %v, want tag_scanners", on, name, sink.Inputs)
			}
		}
	}
}

func TestContainmentSettingsGate(t *testing.T) {
	cases := []struct {
		name         string
		enabled      []string
		allowPrivate bool
		blockAll     bool
		target       string
		want         string // error code, "" for allowed
	}{
		{"default guard on, everything", []string{"cowrie", "dionaea", "tanner", "ssh-proxy"}, false, false, "", ""},
		{"guard off, emulators only", []string{"cowrie", "conpot", "refrigeration"}, true, false, "", ""},
		{"guard off, dionaea", []string{"cowrie", "dionaea"}, true, false, "", "QP-INST-015"},
		{"guard off, tanner", []string{"tanner"}, true, false, "", "QP-INST-015"},
		{"guard off, unknown honeypot", []string{"endlessh"}, true, false, "", "QP-INST-015"},
		{"guard off, HiFi keeps its own guard", []string{"cowrie", "ssh-proxy"}, true, false, "", ""},
		{"guard off, but all outbound blocked", []string{"dionaea"}, true, true, "", ""},
		{"guard off, enabling a sensitive target", []string{"cowrie"}, true, false, "dionaea", "QP-INST-015"},
		{"guard off, enabling an emulator target", []string{"cowrie"}, true, false, "conpot", ""},
		// An operation on one honeypot answers for that honeypot; the whole
		// instance is judged at qpot up and by the doctor.
		{"guard off, restarting an emulator beside a sensitive honeypot", []string{"cowrie", "dionaea"}, true, false, "cowrie", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := sandboxInstanceConfig(t, tc.enabled...)
			cfg.Security.NetworkIsolation.AllowPrivateEgress = tc.allowPrivate
			cfg.Security.NetworkIsolation.BlockOutbound = tc.blockAll
			var targets []string
			if tc.target != "" {
				targets = append(targets, tc.target)
			}
			err := checkContainmentSettings(cfg, targets...)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			sandboxAssertCode(t, err, tc.want)
			var coded *hostsetup.Error
			errors.As(err, &coded)
			if !strings.Contains(coded.Cause(), "allow_private_egress") || !strings.Contains(coded.Remedy(), "allow_private_egress: false") {
				t.Errorf("the refusal does not name the setting: %s / %s", coded.Cause(), coded.Remedy())
			}
		})
	}
}

// TestSensitiveWorkloadsNeedEnforcedLimits: a honeypot that handles attacker
// input in real services does not start on a Docker that cannot enforce its
// limits, and the reviewed emulators still do. Nothing is written or started
// before the refusal.
func TestSensitiveWorkloadsNeedEnforcedLimits(t *testing.T) {
	const noSwapLimit = `{"CgroupDriver":"cgroupfs","MemoryLimit":true,"SwapLimit":false,"PidsLimit":true,"CPUCfsQuota":true}`
	// Each case copies the test binary as its docker stand-in, so the
	// matrix is kept to what differs: every entry point for the plain
	// refusal, one entry point for the other answers.
	all := []string{"start", "honeypot", "restart"}
	for _, tc := range []struct {
		honeypot string
		info     string
		want     string
		actions  []string
	}{
		{"dionaea", noSwapLimit, "QP-RES-007", all},
		{"dionaea", `{"CgroupDriver":"none"}`, "QP-RES-007", all[:1]},
		{"dionaea", `not json`, "QP-RES-007", all[:1]},
		{"dionaea", "", "", all[:1]},
		{"cowrie", noSwapLimit, "", all[:1]},
	} {
		for _, action := range tc.actions {
			t.Run(tc.honeypot+"/"+action+"/"+tc.info, func(t *testing.T) {
				h := newSandboxDockerHarness(t)
				h.fixture.ResourceInfo = tc.info
				h.save()
				cfg := sandboxInstanceConfig(t, tc.honeypot)
				cfg.Security.SandboxMode = "none"
				if action == "restart" {
					sandboxWriteCompose(t, cfg, "", tc.honeypot)
				}
				manager, err := NewManager(cfg)
				if err != nil {
					t.Fatal(err)
				}
				switch action {
				case "start":
					err = manager.Start(t.Context(), true)
				case "honeypot":
					err = manager.StartHoneypot(t.Context(), tc.honeypot)
				case "restart":
					err = manager.RestartHoneypot(t.Context(), tc.honeypot)
				}
				if tc.want == "" {
					if err != nil {
						t.Fatalf("refused: %v", err)
					}
					return
				}
				sandboxAssertCode(t, err, tc.want)
				for _, call := range h.calls() {
					if len(call) == 0 || (call[0] != "info" && !(call[0] == "compose" && slices.Contains(call, "ps"))) {
						t.Fatalf("the refusal reached Docker: %v", call)
					}
				}
				if action != "restart" {
					if _, err := os.Stat(cfg.GetDockerComposePath()); !os.IsNotExist(err) {
						t.Fatal("a refused start wrote the compose file")
					}
				}
			})
		}
	}
}

// TestGuardOffRefusesSensitiveStart drives the settings gate through the
// manager: the refusal comes before anything is written or started.
func TestGuardOffRefusesSensitiveStart(t *testing.T) {
	for _, action := range []string{"start", "honeypot", "restart"} {
		t.Run(action, func(t *testing.T) {
			h := newSandboxDockerHarness(t)
			cfg := sandboxInstanceConfig(t, "dionaea")
			cfg.Security.SandboxMode = "none"
			cfg.Security.NetworkIsolation.AllowPrivateEgress = true
			if action == "restart" {
				sandboxWriteCompose(t, cfg, "", "dionaea")
			}
			manager, err := NewManager(cfg)
			if err != nil {
				t.Fatal(err)
			}
			switch action {
			case "start":
				err = manager.Start(t.Context(), true)
			case "honeypot":
				err = manager.StartHoneypot(t.Context(), "dionaea")
			case "restart":
				err = manager.RestartHoneypot(t.Context(), "dionaea")
			}
			sandboxAssertCode(t, err, "QP-INST-015")
			if h.called("up") || h.called("restart") {
				t.Fatal("a refused configuration reached Docker")
			}
		})
	}
}
