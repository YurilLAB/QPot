package instance

import (
	"context"
	"errors"
	"maps"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/hostsetup"
	"github.com/qpot/qpot/internal/netguard"
	"gopkg.in/yaml.v3"
)

const sshSupportedResourceInfo = `{"CgroupDriver":"systemd","MemoryLimit":true,"PidsLimit":true,"CPUCfsQuota":true}`

func TestHiFiResourceCapabilityJSONFailsClosed(t *testing.T) {
	for _, raw := range []string{
		"", "null", "[]", "{}", "not JSON", sshSupportedResourceInfo + " garbage",
		`{"CgroupDriver":"none","MemoryLimit":true,"PidsLimit":true,"CPUCfsQuota":true}`,
		`{"CgroupDriver":"unknown","MemoryLimit":true,"PidsLimit":true,"CPUCfsQuota":true}`,
		`{"CgroupDriver":"systemd","MemoryLimit":false,"PidsLimit":true,"CPUCfsQuota":true}`,
		`{"CgroupDriver":"systemd","MemoryLimit":true,"PidsLimit":false,"CPUCfsQuota":true}`,
		`{"CgroupDriver":"systemd","MemoryLimit":true,"PidsLimit":true,"CPUCfsQuota":false}`,
		`{"CgroupDriver":"systemd","MemoryLimit":true,"PidsLimit":true}`,
		`{"CgroupDriver":"systemd","MemoryLimit":null,"PidsLimit":true,"CPUCfsQuota":true}`,
		`{"CgroupDriver":"systemd","MemoryLimit":"true","PidsLimit":true,"CPUCfsQuota":true}`,
		strings.Repeat(" ", 17<<10) + sshSupportedResourceInfo,
	} {
		if err := validateSSHResourceInfo([]byte(raw)); err == nil || hostsetup.AsError(err).Code != "QP-RES-005" {
			t.Fatalf("unverified cgroup controls were accepted: %q: %v", raw, err)
		}
	}
	for _, driver := range []string{"systemd", "cgroupfs"} {
		if err := validateSSHResourceInfo([]byte(strings.Replace(sshSupportedResourceInfo, "systemd", driver, 1))); err != nil {
			t.Fatalf("supported cgroup controls rejected: %v", err)
		}
	}
}

func TestHiFiResourcePreflightRefusesBeforeGuestMutation(t *testing.T) {
	for _, action := range []string{"start", "start honeypot", "recreate", "restart"} {
		t.Run(action, func(t *testing.T) {
			cfg := organizationTestConfig(t)
			cfg.Security.SandboxMode = "none"
			if err := config.Save(cfg); err != nil {
				t.Fatal(err)
			}
			previousConfig, err := os.ReadFile(cfg.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			previousCompose := string(organizationComposeFixture(t, cfg.InstanceName, 2, true))
			if err := os.WriteFile(cfg.GetDockerComposePath(), []byte(previousCompose), 0o600); err != nil {
				t.Fatal(err)
			}
			trace := organizationFakeDocker(t)
			if err := os.WriteFile(trace+".stopped", nil, 0o600); err != nil {
				t.Fatal(err)
			}
			capabilities := trace + ".resources"
			if err := os.WriteFile(capabilities, []byte(`{"CgroupDriver":"none","MemoryLimit":false,"PidsLimit":false,"CPUCfsQuota":false}`), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("SSH_TEST_RESOURCE_FILE", capabilities)
			manager, err := NewManager(cfg)
			if err != nil {
				t.Fatal(err)
			}
			switch action {
			case "start":
				err = manager.Start(t.Context(), true)
			case "start honeypot":
				err = manager.StartHoneypot(t.Context(), sshProxyHoneypot)
			case "recreate":
				err = manager.RecreateHoneypot(t.Context(), sshProxyHoneypot)
			case "restart":
				err = manager.RestartHoneypot(t.Context(), sshProxyHoneypot)
			}
			if err == nil || hostsetup.AsError(err).Code != "QP-RES-005" {
				t.Fatalf("unsupported cgroups reached %s: %v", action, err)
			}
			commands, _ := os.ReadFile(trace)
			if !strings.Contains(string(commands), "\ninfo\n") {
				t.Fatal("runtime capabilities were not queried")
			}
			for _, mutation := range []string{"up", "stop", "rm", "restart", "pull", "run"} {
				if strings.Contains(string(commands), "\n"+mutation+"\n") {
					t.Fatalf("unsupported cgroups reached Docker mutation %s: %s", mutation, commands)
				}
			}
			if got, err := os.ReadFile(cfg.ConfigPath); err != nil || string(got) != string(previousConfig) {
				t.Fatalf("unsupported cgroups replaced config: %v", err)
			}
			if got, err := os.ReadFile(cfg.GetDockerComposePath()); err != nil || string(got) != previousCompose {
				t.Fatalf("unsupported cgroups replaced deployment: %v", err)
			}
		})
	}
}

func TestHiFiResourcePreflightRejectsDaemonFailureAndCancellation(t *testing.T) {
	organizationFakeDocker(t)
	t.Setenv("SSH_TEST_RESOURCE_EXIT", "17")
	if err := validateSSHRuntimeResources(t.Context()); err == nil || hostsetup.AsError(err).Code != "QP-RES-005" {
		t.Fatalf("daemon failure lost resource error: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := validateSSHRuntimeResources(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("preflight cancellation was not preserved: %v", err)
	}
}

func TestHiFiResourcePreflightBoundsDaemonOutput(t *testing.T) {
	trace := organizationFakeDocker(t)
	output := trace + ".resources"
	if err := os.WriteFile(output, []byte(strings.Repeat(" ", 17<<10)+sshSupportedResourceInfo), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_TEST_RESOURCE_FILE", output)
	if err := validateSSHRuntimeResources(t.Context()); err == nil || hostsetup.AsError(err).Code != "QP-RES-005" {
		t.Fatalf("oversized daemon output was accepted: %v", err)
	}
}

func TestHiFiResourcePreflightStopsDirtyCellWithoutReuse(t *testing.T) {
	cfg := organizationTestConfig(t)
	trace := organizationFakeDocker(t)
	capabilities := trace + ".resources"
	if err := os.WriteFile(capabilities, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_TEST_RESOURCE_FILE", capabilities)
	if err := os.WriteFile(cfg.GetDockerComposePath(), organizationComposeFixture(t, cfg.InstanceName, 1, true), 0o600); err != nil {
		t.Fatal(err)
	}
	recycler := requireBackendRecycler(t, cfg)
	if err := recycler.composeRecreate(t.Context(), "ssh-backend-1"); err == nil || hostsetup.AsError(err).Code != "QP-RES-005" {
		t.Fatalf("unverified recycler started a cell: %v", err)
	}
	commands, _ := os.ReadFile(trace)
	if !strings.Contains(string(commands), "\nstop\n") || strings.Contains(string(commands), "\nup\n") || recycler.generation("ssh-backend-1") != 0 {
		t.Fatalf("dirty cell was not stopped/quarantined: %s", commands)
	}
}

func FuzzHiFiResourceCaps(f *testing.F) {
	f.Add(false, true, 7.5, int64(96), int64(17), int64(1))
	f.Add(true, true, 0.0, int64(0), int64(17), int64(0))
	f.Add(true, true, math.SmallestNonzeroFloat64, int64(96), int64(17), int64(1))
	f.Add(false, true, 1e-10, int64(96), int64(17), int64(1))
	f.Add(true, true, math.Nextafter(1e-7, math.Inf(1)), int64(96), int64(17), int64(1))
	f.Add(true, true, 1.0, int64(96), int64(17), int64(1))
	f.Add(false, true, 0.5, int64(96), int64(17), int64(1))
	f.Add(true, true, math.MaxFloat64, int64(96), int64(17), int64(1))
	f.Add(false, true, 7.5, int64(math.MaxInt64), int64(17), int64(1))
	f.Add(true, true, 7.5, int64(5), int64(17), int64(1))
	f.Add(true, true, 7.5, int64(6), int64(17), int64(1))
	f.Add(true, false, -1.0, int64(-1), int64(-1), int64(-1))
	f.Fuzz(func(t *testing.T, organization, custom bool, cpu float64, memory, pids, storage int64) {
		cfg := config.Default("resource-fuzz")
		cfg.QPotID = "qp_abcdefghijklmnopqrstuvwx"
		cfg.DataPath = "/tmp/resource-fuzz"
		cfg.Security.SandboxMode = "none"
		enableOnly(cfg, sshProxyHoneypot)
		hp := cfg.Honeypots[sshProxyHoneypot]
		hp.Resources = config.HoneypotResources{UseCustomLimits: custom, MaxCPUPercent: cpu, MaxMemoryMB: memory, MaxPids: pids, MaxStorageGB: storage}
		mode := "standalone"
		if organization {
			mode = "organization"
		}
		hp.CustomConfig = map[string]string{"environment": mode, "backends": "1"}
		cfg.Honeypots[sshProxyHoneypot] = hp
		out, err := (&ComposeGenerator{Config: cfg, Sandbox: mustSandbox(t, cfg)}).Generate()
		if err != nil {
			if out != "" || !strings.Contains(err.Error(), "ssh-proxy.resources") {
				t.Fatalf("resource refusal changed the deployment or lost its field: %v", err)
			}
			return
		}
		var doc sshCellCompose
		if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatal(err)
		}
		reference := doc.Services[sshProxyHoneypot].Deploy.Resources.Limits
		CPU, err := strconv.ParseFloat(reference["cpus"], 64)
		if err != nil || math.IsNaN(CPU) || math.IsInf(CPU, 0) || CPU < 0.01 || CPU*1e9 > math.MaxInt64/100000 {
			t.Fatalf("rendered CPU cap is not a representable positive Docker CFS quota: %v", reference)
		}
		mem, memErr := strconv.ParseInt(strings.TrimSuffix(reference["memory"], "M"), 10, 64)
		PID, pidErr := strconv.ParseInt(reference["pids"], 10, 64)
		if memErr != nil || pidErr != nil || mem < 6 || PID <= 0 {
			t.Fatalf("rendered memory/PID cap violates Docker's minimum bounds: %v", reference)
		}
		for _, name := range append([]string{sshProxyHoneypot}, allSSHCellServiceNames(cfg)...) {
			if got := doc.Services[name].Deploy.Resources.Limits; !maps.Equal(got, reference) {
				t.Fatalf("cell service %s differs from the operator's broker caps: got %v, broker %v", name, got, reference)
			}
			checkHiFiReservations(t, name, doc.Services[name].Deploy.Resources.Reservations, CPU, mem)
		}
	})
}

func TestHiFiInvalidResourceCapsPreserveDeployment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Docker argument recorder uses a Unix executable fixture")
	}
	cfg := organizationTestConfig(t)
	cfg.Security.SandboxMode = "none"
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	previousConfig, err := os.ReadFile(cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	previousCompose := "previous valid deployment\n"
	if err := os.WriteFile(cfg.GetDockerComposePath(), []byte(previousCompose), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	hp := cfg.Honeypots[sshProxyHoneypot]
	hp.Resources.UseCustomLimits = true
	hp.Resources.MaxPids = -1
	cfg.Honeypots[sshProxyHoneypot] = hp
	trace := argsDocker(t)
	if err := manager.Initialize(t.Context()); err == nil || !strings.Contains(err.Error(), "ssh-proxy.resources.max_pids") {
		t.Fatalf("invalid cell caps reached initialization: %v", err)
	}
	if got, err := os.ReadFile(cfg.ConfigPath); err != nil || string(got) != string(previousConfig) {
		t.Fatalf("invalid caps changed the saved config: %v", err)
	}
	if got, err := os.ReadFile(cfg.GetDockerComposePath()); err != nil || string(got) != previousCompose {
		t.Fatalf("invalid caps replaced the live layout: %v", err)
	}
	if got, err := os.ReadFile(trace); err != nil && !os.IsNotExist(err) || len(got) != 0 {
		t.Fatalf("invalid caps reached Docker: %q %v", got, err)
	}
}

func TestHiFiRejectsInvalidResourceCapsBeforeRendering(t *testing.T) {
	for _, set := range []func(*config.HoneypotResources){
		func(r *config.HoneypotResources) { r.MaxCPUPercent = -1 },
		func(r *config.HoneypotResources) { r.MaxCPUPercent = math.NaN() },
		func(r *config.HoneypotResources) { r.MaxCPUPercent = math.Inf(1) },
		func(r *config.HoneypotResources) { r.MaxCPUPercent = math.SmallestNonzeroFloat64 },
		func(r *config.HoneypotResources) { r.MaxCPUPercent = 1e-10 },
		func(r *config.HoneypotResources) { r.MaxMemoryMB = -1 },
		func(r *config.HoneypotResources) { r.MaxPids = -1 },
	} {
		cfg := enableSSHProxy(t, "invalid-cell-caps")
		hp := cfg.Honeypots[sshProxyHoneypot]
		hp.Resources.UseCustomLimits = true
		set(&hp.Resources)
		cfg.Honeypots[sshProxyHoneypot] = hp
		if out, err := (&ComposeGenerator{Config: cfg}).Generate(); err == nil || out != "" || !strings.Contains(err.Error(), "ssh-proxy.resources") {
			t.Fatalf("invalid HiFi caps reached rendered services: %v", err)
		}
	}
	cfg := enableSSHProxy(t, "invalid-global-cell-caps")
	hp := cfg.Honeypots[sshProxyHoneypot]
	hp.Resources.UseCustomLimits = false
	cfg.Honeypots[sshProxyHoneypot] = hp
	cfg.Security.ResourceLimits.MaxPids = 0
	if out, err := (&ComposeGenerator{Config: cfg}).Generate(); err == nil || out != "" {
		t.Fatal("direct config with an unbounded inherited PID limit reached rendering")
	}
}

type sshCellCompose struct {
	Services map[string]struct {
		Image       string                                `yaml:"image"`
		PullPolicy  string                                `yaml:"pull_policy"`
		Ports       []string                              `yaml:"ports"`
		Networks    any                                   `yaml:"networks"`
		Environment any                                   `yaml:"environment"`
		CapAdd      []string                              `yaml:"cap_add"`
		ReadOnly    bool                                  `yaml:"read_only"`
		User        string                                `yaml:"user"`
		Volumes     []string                              `yaml:"volumes"`
		Tmpfs       []string                              `yaml:"tmpfs"`
		Healthcheck struct{ Test []string }               `yaml:"healthcheck"`
		DependsOn   map[string]struct{ Condition string } `yaml:"depends_on"`
		Deploy      struct {
			Resources struct {
				Limits       map[string]string `yaml:"limits"`
				Reservations map[string]string `yaml:"reservations"`
			} `yaml:"resources"`
		} `yaml:"deploy"`
	} `yaml:"services"`
	Networks map[string]struct {
		Internal   bool                                       `yaml:"internal"`
		DriverOpts map[string]string                          `yaml:"driver_opts"`
		IPAM       struct{ Config []struct{ Subnet string } } `yaml:"ipam"`
	} `yaml:"networks"`
}

func TestHiFiResourceLimitsApplyToEveryCell(t *testing.T) {
	for _, mode := range []string{"standalone", "organization"} {
		for _, tc := range []struct {
			name   string
			custom config.HoneypotResources
			CPU    string
			memory string
			PIDs   string
		}{
			{"custom disabled", config.HoneypotResources{MaxCPUPercent: 7.5, MaxMemoryMB: 96, MaxPids: 17}, "0.45", "384M", "113"},
			{"all unset", config.HoneypotResources{UseCustomLimits: true}, "0.45", "384M", "113"},
			{"explicit lower limits", config.HoneypotResources{UseCustomLimits: true, MaxCPUPercent: 7.5, MaxMemoryMB: 96, MaxPids: 17}, "0.075", "96M", "17"},
			{"PIDs only", config.HoneypotResources{UseCustomLimits: true, MaxPids: 19}, "0.45", "384M", "19"},
			{"CPU only", config.HoneypotResources{UseCustomLimits: true, MaxCPUPercent: 30}, "0.3", "384M", "113"},
			{"minimum Engine limits", config.HoneypotResources{UseCustomLimits: true, MaxCPUPercent: 1, MaxMemoryMB: 6, MaxPids: 17}, "0.01", "6M", "17"},
			{"below default reservation", config.HoneypotResources{UseCustomLimits: true, MaxCPUPercent: 4, MaxMemoryMB: 31, MaxPids: 17}, "0.04", "31M", "17"},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				cfg := enableSSHProxy(t, "cell-resource-limits")
				enableOnly(cfg, sshProxyHoneypot)
				cfg.Security.ResourceLimits = config.ResourceLimits{MaxCPUPercent: 45, MaxMemoryMB: 384, MaxStorageGB: 9, MaxPids: 113, RestartAttempts: 5}
				hp := cfg.Honeypots[sshProxyHoneypot]
				hp.CustomConfig = map[string]string{"backends": "2", "environment": mode}
				hp.Resources = tc.custom
				cfg.Honeypots[sshProxyHoneypot] = hp
				var doc sshCellCompose
				if err := yaml.Unmarshal([]byte(renderComposeCfg(t, cfg)), &doc); err != nil {
					t.Fatal(err)
				}
				for _, name := range append([]string{sshProxyHoneypot}, allSSHCellServiceNames(cfg)...) {
					svc, ok := doc.Services[name]
					if !ok {
						t.Fatalf("missing service %s", name)
					}
					limits := svc.Deploy.Resources.Limits
					if limits["cpus"] != tc.CPU || limits["memory"] != tc.memory || limits["pids"] != tc.PIDs {
						t.Errorf("%s limits = %v, want cpus=%s memory=%s pids=%s", name, limits, tc.CPU, tc.memory, tc.PIDs)
					}
					CPU, _ := strconv.ParseFloat(tc.CPU, 64)
					memory, _ := strconv.ParseInt(strings.TrimSuffix(tc.memory, "M"), 10, 64)
					checkHiFiReservations(t, name, svc.Deploy.Resources.Reservations, CPU, memory)
				}
			})
		}
	}
}

func checkHiFiReservations(t *testing.T, name string, reservations map[string]string, CPU float64, memory int64) {
	t.Helper()
	// PostgreSQL has no reservations. Where present, reservations must remain
	// positive and at or below the selected cap so Docker can create the guest.
	if len(reservations) == 0 {
		if !strings.HasSuffix(name, "-db") {
			t.Fatalf("missing CPU/memory reservations for %s", name)
		}
		return
	}
	reservedCPU, cpuErr := strconv.ParseFloat(reservations["cpus"], 64)
	reservedMemory, memErr := strconv.ParseInt(strings.TrimSuffix(reservations["memory"], "M"), 10, 64)
	if cpuErr != nil || memErr != nil || reservedCPU != min(0.05, CPU) || reservedMemory != min(int64(32), memory) {
		t.Fatalf("%s reservations %v do not fit limits CPU=%v memory=%vM", name, reservations, CPU, memory)
	}
}

func sshCellEnv(raw any) map[string]string {
	m := envMap(raw)
	if entries, ok := raw.([]any); ok {
		for _, entry := range entries {
			if s, ok := entry.(string); ok {
				k, v, _ := strings.Cut(s, "=")
				m[k] = v
			}
		}
	}
	return m
}

func TestHiFiPrivateCellTopologyAndIngress(t *testing.T) {
	for _, mode := range []string{"standalone", "organization"} {
		t.Run(mode, func(t *testing.T) {
			cfg := enableSSHProxy(t, "private-cell-"+mode)
			enableOnly(cfg, "ssh-proxy")
			// The ordinary private-egress override must never expose real HiFi guests.
			cfg.Security.NetworkIsolation.AllowPrivateEgress = true
			hp := cfg.Honeypots["ssh-proxy"]
			hp.CustomConfig = map[string]string{"backends": "2", "environment": mode, "image_source": "local"}
			cfg.Honeypots["ssh-proxy"] = hp
			var doc sshCellCompose
			if err := yaml.Unmarshal([]byte(renderComposeCfg(t, cfg)), &doc); err != nil {
				t.Fatal(err)
			}
			guard := doc.Services["netguard"]
			env := sshCellEnv(guard.Environment)
			cells := netguard.ParseIfaces(env["QPOT_NETGUARD_CELLS"])
			if len(cells) != 2 || !slices.Equal(guard.Healthcheck.Test, []string{"CMD", "/qpot-netguard", "check-cells"}) {
				t.Fatalf("missing mandatory feature-aware cell guard: %+v %v", guard.Healthcheck, cells)
			}
			if guard.PullPolicy != "never" || guard.Image != "qpot-local/ssh-proxy:development" {
				t.Fatal("local guard image can be overwritten by a registry pull")
			}
			broker := doc.Services["ssh-proxy"]
			listen := sshCellEnv(broker.Environment)["QPOT_SSHPROXY_LISTEN"]
			addr, port, err := net.SplitHostPort(listen)
			if err != nil || port != "2222" || net.ParseIP(addr) == nil || net.ParseIP(addr).IsUnspecified() {
				t.Fatalf("broker must bind a concrete ingress address, got %q", listen)
			}
			public := doc.Networks["ssh-proxy_net"]
			_, publicRange, _ := net.ParseCIDR(public.IPAM.Config[0].Subnet)
			if !publicRange.Contains(net.ParseIP(addr)) {
				t.Fatal("broker listener is not on its ingress network")
			}
			seen := map[string]string{}
			for _, app := range sshBackendServiceNames(cfg) {
				members := sshCellServiceNames(cfg, app)
				for _, name := range members {
					svc, exists := doc.Services[name]
					if !exists || len(svc.Ports) != 0 || len(netNames(svc.Networks)) != 1 {
						t.Fatalf("%s missing or exposes/joins another network: %+v", name, svc)
					}
					network := netNames(svc.Networks)[0]
					if owner, exists := seen[network]; exists && owner != app {
						t.Fatalf("unrelated cells %s and %s share %s", app, owner, network)
					}
					seen[network] = app
					def := doc.Networks[network]
					if !def.Internal || !slices.Contains(cells, def.DriverOpts["com.docker.network.bridge.name"]) {
						t.Fatalf("%s is not a guarded private cell", network)
					}
					_, cellRange, _ := net.ParseCIDR(def.IPAM.Config[0].Subnet)
					if cellRange.Contains(net.ParseIP(addr)) {
						t.Fatalf("guest can re-enter the broker listener through cell %s", network)
					}
					if svc.DependsOn["netguard"].Condition != "service_healthy" || slices.Contains(svc.CapAdd, "NET_ADMIN") || slices.Contains(svc.CapAdd, "SYS_ADMIN") || slices.Contains(svc.CapAdd, "NET_RAW") {
						t.Fatalf("unsafe cell startup/capabilities on %s", name)
					}
					if strings.HasSuffix(name, "-db") {
						if !svc.ReadOnly || svc.User != "999:999" || len(svc.Tmpfs) != 3 {
							t.Fatalf("database state is not bounded/non-root: %+v", svc)
						}
					} else {
						if svc.PullPolicy != "never" || svc.Image != "qpot-local/ssh-backend:development" {
							t.Fatalf("local backend image not protected: %s", name)
						}
						contextMount := false
						for _, mount := range svc.Volumes {
							if strings.HasSuffix(mount, ":/run/audit-context:ro") {
								contextDir, err := sshStoreContext(cfg, app)
								if err != nil {
									t.Fatal(err)
								}
								contextMount = strings.HasPrefix(filepath.ToSlash(mount), filepath.ToSlash(contextDir)+":")
							}
						}
						if !contextMount {
							t.Fatalf("%s lacks its own read-only lease context", name)
						}
					}
				}
			}
			if len(seen) != 2 || len(netNames(broker.Networks)) != 3 {
				t.Fatal("broker must join ingress and each of two distinct cells")
			}
		})
	}
}

func TestHiFiRejectsInvalidEnvironmentBeforeRendering(t *testing.T) {
	cfg := enableSSHProxy(t, "bad-scene")
	hp := cfg.Honeypots["ssh-proxy"]
	hp.CustomConfig["environment"] = "unknown"
	cfg.Honeypots["ssh-proxy"] = hp
	g := &ComposeGenerator{Config: cfg}
	if out, err := g.Generate(); err == nil || out != "" {
		t.Fatal("invalid scene must not silently produce a standalone deployment")
	}
}
