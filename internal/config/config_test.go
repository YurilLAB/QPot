package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDefaultConfigValid(t *testing.T) {
	cfg := Default("test")
	if cfg == nil {
		t.Fatal("Default returned nil")
	}
	if cfg.InstanceName != "test" {
		t.Errorf("InstanceName = %q, want test", cfg.InstanceName)
	}
	if cfg.Database.Type == "" {
		t.Error("default database type should not be empty")
	}
	if cfg.Database.Host == "" {
		t.Error("default database host should not be empty")
	}
	if cfg.Database.Port <= 0 {
		t.Errorf("default database port %d should be positive", cfg.Database.Port)
	}
	if cfg.WebUI.Port <= 0 {
		t.Errorf("default web UI port %d should be positive", cfg.WebUI.Port)
	}
	if cfg.Intelligence.WorkerBatchSize <= 0 {
		t.Error("default intelligence worker batch size should be positive")
	}
	if cfg.Intelligence.WorkerInterval <= 0 {
		t.Error("default intelligence worker interval should be positive")
	}
}

func TestDefaultConfigHoneypots(t *testing.T) {
	cfg := Default("test")
	if len(cfg.Honeypots) == 0 {
		t.Fatal("default config should have at least one honeypot defined")
	}
	// cowrie and endlessh should be enabled by default.
	for _, name := range []string{"cowrie", "endlessh"} {
		hp, ok := cfg.Honeypots[name]
		if !ok {
			t.Errorf("default config missing honeypot %q", name)
			continue
		}
		if !hp.Enabled {
			t.Errorf("honeypot %q should be enabled by default", name)
		}
	}
}

func TestAllocatePortDeterministic(t *testing.T) {
	cfg := Default("myinstance")
	p1 := cfg.AllocatePort(22)
	p2 := cfg.AllocatePort(22)
	if p1 != p2 {
		t.Errorf("AllocatePort is not deterministic: %d vs %d", p1, p2)
	}
}

func TestAllocatePortDifferentForDifferentInstances(t *testing.T) {
	cfg1 := Default("instance1")
	cfg2 := Default("instance2")
	p1 := cfg1.AllocatePort(22)
	p2 := cfg2.AllocatePort(22)
	if p1 == p2 {
		t.Error("different instances should get different allocated ports")
	}
}

func TestAllocatePortInValidRange(t *testing.T) {
	for _, name := range []string{"a", "abc", "very-long-instance-name-here", "test123"} {
		cfg := Default(name)
		for _, base := range []int{22, 80, 443, 9000, 8080} {
			p := cfg.AllocatePort(base)
			if p <= 1024 {
				t.Errorf("instance %q: allocated port %d should be > 1024", name, p)
			}
			if p > 65535 {
				t.Errorf("instance %q: allocated port %d exceeds 65535", name, p)
			}
		}
	}
}

// TestAllocatePortBelowEphemeral is the regression guard for the intermittent
// "address already in use" bind failure seen with the full honeypot set: a
// published host port allocated inside the Linux ephemeral range (default
// 32768..60999) races the kernel's dynamic port allocator. Every auto-allocated
// port must stay strictly below the ephemeral floor.
func TestAllocatePortBelowEphemeral(t *testing.T) {
	const ephemeralFloor = 32768
	for _, name := range []string{"a", "prod", "instance-x", "z9", "verylonginstancenamevalue"} {
		cfg := Default(name)
		for _, base := range []int{20, 22, 23, 25, 53, 80, 102, 443, 445, 1433, 3306, 5060, 5432, 5900, 6379, 8080, 9100, 9200, 11112} {
			p := cfg.AllocatePortFor("some-honeypot", base)
			if p < 10000 || p >= ephemeralFloor {
				t.Errorf("instance %q base %d: host port %d is outside [10000,%d) (ephemeral-range collision risk)", name, base, p, ephemeralFloor)
			}
		}
	}
	// The spread constant itself must keep base(10000)+spread below the floor.
	if 10000+HostPortSpread > ephemeralFloor {
		t.Errorf("HostPortSpread=%d puts the top host port (%d) into the ephemeral range (>=%d)", HostPortSpread, 10000+HostPortSpread, ephemeralFloor)
	}
}

func TestGetEnabledHoneypots(t *testing.T) {
	cfg := Default("test")
	enabled := cfg.GetEnabledHoneypots()
	if len(enabled) == 0 {
		t.Fatal("expected at least one enabled honeypot")
	}
	// Verify each returned name is actually enabled.
	for _, name := range enabled {
		hp, ok := cfg.Honeypots[name]
		if !ok {
			t.Errorf("GetEnabledHoneypots returned unknown honeypot %q", name)
			continue
		}
		if !hp.Enabled {
			t.Errorf("GetEnabledHoneypots returned disabled honeypot %q", name)
		}
	}
}

func TestEnableDisableHoneypot(t *testing.T) {
	cfg := Default("test")
	cfg.DisableHoneypot("cowrie")
	if hp := cfg.Honeypots["cowrie"]; hp.Enabled {
		t.Error("cowrie should be disabled after DisableHoneypot")
	}

	cfg.EnableHoneypot("cowrie")
	if hp := cfg.Honeypots["cowrie"]; !hp.Enabled {
		t.Error("cowrie should be enabled after EnableHoneypot")
	}
}

func TestGetEffectiveResourceLimitsGlobal(t *testing.T) {
	cfg := Default("test")
	// cowrie uses UseCustomLimits=false, so it should get global limits.
	limits := cfg.GetEffectiveResourceLimits("cowrie")
	global := cfg.Security.ResourceLimits
	if limits.MaxCPUPercent != global.MaxCPUPercent {
		t.Errorf("expected global CPU limit %f, got %f", global.MaxCPUPercent, limits.MaxCPUPercent)
	}
}

func TestGetEffectiveResourceLimitsPerHoneypot(t *testing.T) {
	cfg := Default("test")
	// dionaea uses UseCustomLimits=true.
	hp := cfg.Honeypots["dionaea"]
	hp.Resources.UseCustomLimits = true
	hp.Resources.MaxMemoryMB = 999
	cfg.Honeypots["dionaea"] = hp

	limits := cfg.GetEffectiveResourceLimits("dionaea")
	if limits.MaxMemoryMB != 999 {
		t.Errorf("expected per-honeypot memory limit 999, got %d", limits.MaxMemoryMB)
	}
}

func TestGetEffectiveResourceLimitsPartialCustom(t *testing.T) {
	global := ResourceLimits{MaxCPUPercent: 45, MaxMemoryMB: 384, MaxStorageGB: 9, MaxPids: 113, RestartAttempts: 5}
	for _, tc := range []struct {
		name   string
		custom HoneypotResources
		want   ResourceLimits
	}{
		{"custom disabled", HoneypotResources{MaxCPUPercent: 7.5, MaxMemoryMB: 96, MaxStorageGB: 1, MaxPids: 17}, global},
		{"all unset", HoneypotResources{UseCustomLimits: true}, global},
		{"CPU only", HoneypotResources{UseCustomLimits: true, MaxCPUPercent: 7.5}, ResourceLimits{7.5, 384, 9, 113, 5}},
		{"memory only", HoneypotResources{UseCustomLimits: true, MaxMemoryMB: 96}, ResourceLimits{45, 96, 9, 113, 5}},
		{"storage only", HoneypotResources{UseCustomLimits: true, MaxStorageGB: 1}, ResourceLimits{45, 384, 1, 113, 5}},
		{"PIDs only", HoneypotResources{UseCustomLimits: true, MaxPids: 17}, ResourceLimits{45, 384, 9, 17, 5}},
		{"all explicit", HoneypotResources{UseCustomLimits: true, MaxCPUPercent: 7.5, MaxMemoryMB: 96, MaxStorageGB: 1, MaxPids: 17}, ResourceLimits{7.5, 96, 1, 17, 5}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default("partial-limits")
			cfg.Security.ResourceLimits = global
			hp := cfg.Honeypots["cowrie"]
			hp.Resources = tc.custom
			cfg.Honeypots["cowrie"] = hp
			if got := cfg.GetEffectiveResourceLimits("cowrie"); got != tc.want {
				t.Fatalf("effective limits = %+v, want %+v", got, tc.want)
			}
			if got := cfg.GetEffectiveResourceLimits("unknown"); got != global {
				t.Fatalf("unknown honeypot limits = %+v, want global %+v", got, global)
			}
			if cfg.Security.ResourceLimits != global || cfg.Honeypots["cowrie"].Resources != tc.custom {
				t.Fatal("reading effective limits modified the saved settings")
			}
		})
	}
}

func TestGetEffectiveResourceLimitsConcurrentHoneypotChanges(t *testing.T) {
	cfg := Default("concurrent-resource-limits")
	want := cfg.GetEffectiveResourceLimits("ssh-proxy")
	var tasks sync.WaitGroup
	tasks.Add(2)
	go func() {
		defer tasks.Done()
		for range 200 {
			cfg.SetHoneypotCustomConfig("ssh-proxy", map[string]string{"environment": "organization"})
		}
	}()
	go func() {
		defer tasks.Done()
		for range 200 {
			if got := cfg.GetEffectiveResourceLimits("ssh-proxy"); got != want {
				t.Errorf("concurrent settings changed resource caps: got %+v, want %+v", got, want)
			}
		}
	}()
	tasks.Wait()
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	cfg := Default("savetest")
	cfg.DataPath = dir
	cfg.ConfigPath = filepath.Join(dir, "config.yaml")
	cfg.InstanceName = "savetest"

	if err := Save(cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	if _, err := os.Stat(cfg.ConfigPath); err != nil {
		t.Fatalf("config file not written: %v", err)
	}

	// Clear cache so Load reads from disk.
	configMu.Lock()
	delete(configs, "savetest")
	configMu.Unlock()

	loaded, err := Load("savetest")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.Database.Type != cfg.Database.Type {
		t.Errorf("database type mismatch after save/load: got %q, want %q",
			loaded.Database.Type, cfg.Database.Type)
	}
	if loaded.InstanceName != cfg.InstanceName {
		t.Errorf("instance name mismatch: got %q, want %q",
			loaded.InstanceName, cfg.InstanceName)
	}
}

func TestLoadFallsBackToDefault(t *testing.T) {
	// Load a non-existent instance — should return default config without error.
	// Use a clearly non-existent name.
	cfg, err := Load("definitely-does-not-exist-xyzzy")
	if err != nil {
		t.Fatalf("Load of unknown instance should return default, got error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load returned nil config")
	}
}

// TestLoadClampsIntelligenceDefaults verifies that a config file which enables
// intelligence but omits the worker tunables gets safe defaults merged on
// load. A zero WorkerInterval would otherwise panic time.NewTicker in the
// worker, and a zero WorkerBatchSize would make classification a silent no-op.
func TestLoadClampsIntelligenceDefaults(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir on Windows

	const inst = "clamp-test-instance"
	dir := filepath.Join(home, ".qpot", "instances", inst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Minimal config: intelligence enabled, no worker tunables.
	yaml := "instance_name: " + inst + "\nintelligence:\n  enabled: true\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	// Ensure Load reads from disk, not the in-memory cache.
	configMu.Lock()
	delete(configs, inst)
	configMu.Unlock()

	cfg, err := Load(inst)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if !cfg.Intelligence.Enabled {
		t.Fatal("precondition: intelligence should be enabled from the file")
	}
	if cfg.Intelligence.WorkerInterval <= 0 {
		t.Errorf("WorkerInterval not clamped on load: got %v", cfg.Intelligence.WorkerInterval)
	}
	if cfg.Intelligence.WorkerBatchSize <= 0 {
		t.Errorf("WorkerBatchSize not clamped on load: got %d", cfg.Intelligence.WorkerBatchSize)
	}
	if cfg.Intelligence.InactivityWindow <= 0 {
		t.Errorf("InactivityWindow not clamped on load: got %v", cfg.Intelligence.InactivityWindow)
	}
}

// TestParseMovesWorkerInterval: a saved config holds the old 15m default and
// moves to the new one; a set cadence is kept, and one too short is raised to
// the floor.
func TestParseMovesWorkerInterval(t *testing.T) {
	for _, c := range []struct {
		in   string
		want time.Duration
	}{
		{"", DefaultWorkerInterval},
		{"0s", DefaultWorkerInterval},
		{"15m0s", DefaultWorkerInterval},
		// Negative controls: only the old default exactly is moved.
		{"15m1s", 15*time.Minute + time.Second},
		{"10m", 10 * time.Minute},
		{"2m", 2 * time.Minute},
		{"1m", time.Minute},
		{"30s", MinWorkerInterval},
		{"1ns", MinWorkerInterval},
	} {
		data := "instance_name: x\nintelligence:\n  enabled: true\n"
		if c.in != "" {
			data += "  worker_interval: " + c.in + "\n"
		}
		cfg, err := Parse([]byte(data), filepath.Join(t.TempDir(), "config.yaml"))
		if err != nil {
			t.Fatalf("%q: %v", c.in, err)
		}
		if got := cfg.Intelligence.WorkerInterval; got != c.want {
			t.Errorf("worker_interval %q: got %v, want %v", c.in, got, c.want)
		}
	}
	if d := Default("x").Intelligence.WorkerInterval; d != DefaultWorkerInterval {
		t.Errorf("new configs get %v, want %v", d, DefaultWorkerInterval)
	}
}

// TestValidateInstanceNameRejectsTraversal guards the path-traversal fix: a name
// that is not a single safe path component must be rejected before it is
// interpolated into ~/.qpot/instances/<name>/...
func TestValidateInstanceNameRejectsTraversal(t *testing.T) {
	bad := []string{
		"", ".", "..", "../etc", "../../etc/passwd", "a/b", `a\b`,
		"foo/..", "..foo/..", "/etc", "x/../../y",
	}
	for _, n := range bad {
		if err := ValidateInstanceName(n); err == nil {
			t.Errorf("ValidateInstanceName(%q) = nil, want error", n)
		}
		if _, err := Load(n); err == nil {
			t.Errorf("Load(%q) = nil error, want rejection", n)
		}
	}
	good := []string{"default", "test", "my-instance_1", "savetest"}
	for _, n := range good {
		if err := ValidateInstanceName(n); err != nil {
			t.Errorf("ValidateInstanceName(%q) = %v, want nil", n, err)
		}
	}
}

func TestAllocatePortForUniqueAcrossHoneypots(t *testing.T) {
	cfg := Default("alloc-test")
	cfg.Ports.AutoAllocate = true
	// Two honeypots both listening on container port 22 must get distinct host
	// ports (otherwise they'd collide on the host).
	if cfg.AllocatePortFor("cowrie", 22) == cfg.AllocatePortFor("heralding", 22) {
		t.Error("AllocatePortFor collides for two honeypots on the same container port")
	}
	// Deterministic: two calls with the same inputs must agree.
	if first, second := cfg.AllocatePortFor("cowrie", 22), cfg.AllocatePortFor("cowrie", 22); first != second {
		t.Errorf("AllocatePortFor is not deterministic: %d != %d", first, second)
	}
	// In a valid, non-privileged host range.
	seen := map[int]string{}
	for _, hp := range []string{"cowrie", "dionaea", "conpot", "heralding", "mailoney"} {
		for _, p := range []int{21, 22, 23, 80, 443} {
			hostPort := cfg.AllocatePortFor(hp, p)
			if hostPort <= 1024 || hostPort > 65535 {
				t.Errorf("%s:%d -> host port %d out of range", hp, p, hostPort)
			}
			key := hostPort
			if prev, ok := seen[key]; ok {
				t.Logf("note: host-port collision %d between %s and %s:%d", key, prev, hp, p)
			}
			seen[key] = hp
		}
	}
}

// A config saved before a honeypot was added has no entry for it; enabling it
// must add the default entry rather than silently doing nothing.
func TestEnableHoneypotAddsMissingEntry(t *testing.T) {
	cfg := Default("enable-test")
	delete(cfg.Honeypots, "wordpot")
	cfg.EnableHoneypot("wordpot")
	hp, ok := cfg.Honeypots["wordpot"]
	if !ok || !hp.Enabled {
		t.Fatalf("wordpot after EnableHoneypot: present=%v enabled=%v", ok, hp.Enabled)
	}
	if hp.Port == 0 {
		t.Error("added entry lacks the default port")
	}
	cfg.EnableHoneypot("no-such-honeypot")
	if _, ok := cfg.Honeypots["no-such-honeypot"]; ok {
		t.Error("unknown honeypot name was added to the config")
	}
}

func TestSaveFailureLeavesProfilesAndExistingFilesUnchanged(t *testing.T) {
	for _, scenario := range []string{"blocked-data-path", "blocked-config-parent", "target-is-directory", "readonly-directory", "invalid-profile"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			cfg := Default("save-failure-" + scenario)
			cfg.QPotID = "qp_abcdefghijklmnopqrstuvwx"
			cfg.DataPath = root
			cfg.ConfigPath = filepath.Join(root, "config.yaml")
			previous := []byte("previous complete config\n")
			preservedPath := cfg.ConfigPath
			if err := os.WriteFile(preservedPath, previous, 0600); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "blocked-data-path":
				cfg.DataPath = filepath.Join(root, "blocker")
				if err := os.WriteFile(cfg.DataPath, []byte("not a directory"), 0600); err != nil {
					t.Fatal(err)
				}
			case "blocked-config-parent":
				blocker := filepath.Join(root, "blocker")
				if err := os.WriteFile(blocker, []byte("not a directory"), 0600); err != nil {
					t.Fatal(err)
				}
				cfg.ConfigPath = filepath.Join(blocker, "config.yaml")
			case "target-is-directory":
				cfg.ConfigPath = filepath.Join(root, "config-directory")
				if err := os.Mkdir(cfg.ConfigPath, 0700); err != nil {
					t.Fatal(err)
				}
				preservedPath = filepath.Join(cfg.ConfigPath, "keep.yaml")
				if err := os.WriteFile(preservedPath, previous, 0600); err != nil {
					t.Fatal(err)
				}
			case "readonly-directory":
				if err := os.Chmod(root, 0500); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(root, 0700) })
				probe, err := os.CreateTemp(root, "permission-probe-*")
				if err == nil {
					probe.Close()
					os.Remove(probe.Name())
					t.Skip("executor can bypass directory write permissions")
				}
			case "invalid-profile":
				cfg.SetHoneypotCustomConfig("conpot", map[string]string{"template": "unsupported-device"})
			}
			before := cfg.SnapshotHoneypots()
			if before["conpot"].DeviceProfile != (ResolvedDeviceProfile{}) {
				t.Fatal("test requires an unresolved legacy device")
			}
			if err := Save(cfg); err == nil {
				t.Fatal("Save unexpectedly succeeded")
			}
			if after := cfg.SnapshotHoneypots(); !reflect.DeepEqual(before, after) {
				t.Fatalf("failed save changed honeypots: before %+v after %+v", before["conpot"], after["conpot"])
			}
			contents, err := os.ReadFile(preservedPath)
			if err != nil || !bytes.Equal(contents, previous) {
				t.Fatalf("failed save damaged previous file: %q, %v", contents, err)
			}
			staged, err := filepath.Glob(filepath.Join(root, ".qpot-config-*.tmp"))
			if err != nil || len(staged) != 0 {
				t.Fatalf("failed save left staged files: %v, %v", staged, err)
			}
		})
	}
}

func TestSaveActivatesPrivateResolvedProfileWithoutLoadDefaults(t *testing.T) {
	root := t.TempDir()
	cfg := Default("save-atomic-success")
	cfg.QPotID = "qp_abcdefghijklmnopqrstuvwx"
	cfg.DataPath = filepath.Join(root, "new-data")
	cfg.ConfigPath = filepath.Join(root, "separate", "config.yaml")
	cfg.WebUI.BindAddr = ""
	cfg.Security.SandboxMode = ""
	want := ConpotAutomaticProfileID(cfg)
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	hp, _ := cfg.GetHoneypotConfig("conpot")
	if hp.DeviceProfile != (ResolvedDeviceProfile{ID: want, Version: 1}) {
		t.Fatalf("successful save did not adopt resolved profile: %+v", hp.DeviceProfile)
	}
	data, err := os.ReadFile(cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	var persisted Config
	if err := yaml.Unmarshal(data, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Honeypots["conpot"].DeviceProfile != hp.DeviceProfile {
		t.Fatal("saved and in-memory profiles disagree")
	}
	if persisted.WebUI.BindAddr != "" || persisted.Security.SandboxMode != "" {
		t.Fatal("Save applied load-time defaults")
	}
	// Replacing an existing public-mode file must also make the new file private.
	if err := os.Chmod(cfg.ConfigPath, 0644); err != nil {
		t.Fatal(err)
	}
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("saved credentials have mode %04o", info.Mode().Perm())
	}
	staged, err := filepath.Glob(filepath.Join(filepath.Dir(cfg.ConfigPath), ".qpot-config-*.tmp"))
	if err != nil || len(staged) != 0 {
		t.Fatalf("successful save left staged files: %v, %v", staged, err)
	}
}

func TestSandboxFallbackDefaultsAndRoundTrip(t *testing.T) {
	initial := Default("sandbox-policy")
	if initial.Security.SandboxMode != "gvisor" || initial.Security.SandboxFallback != "deny" {
		t.Fatal("default isolation does not require the requested stronger runtime")
	}
	for _, policy := range []string{"", "deny", "docker"} {
		t.Run(policy, func(t *testing.T) {
			cfg := Default("sandbox-policy")
			cfg.QPotID = "qp_abcdefghijklmnopqrstuvwx"
			cfg.DataPath = t.TempDir()
			cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
			cfg.Security.SandboxMode = "none"
			cfg.Security.SandboxFallback = policy
			if err := Save(cfg); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(cfg.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			var saved Config
			if err := yaml.Unmarshal(data, &saved); err != nil {
				t.Fatal(err)
			}
			if saved.Security.SandboxFallback != policy {
				t.Fatal("Save reinterpreted the operator's fallback policy")
			}
			loaded, err := Parse(data, cfg.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			want := policy
			if want == "" {
				want = "deny"
			}
			if loaded.Security.SandboxFallback != want || loaded.Security.SandboxMode != "none" {
				t.Fatalf("loaded policy changed: %+v", loaded.Security)
			}
		})
	}
}

func TestConcurrentSaveAndHoneypotChangesProduceCompleteFiles(t *testing.T) {
	cfg := Default("save-concurrent")
	cfg.DataPath = t.TempDir()
	cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	ready := make(chan struct{})
	errs := make(chan error, 20)
	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		first := true
		defer func() {
			if first {
				close(ready)
			}
		}()
		for {
			select {
			case <-stop:
				return
			default:
			}
			data, err := ReadFile(cfg.ConfigPath, 0)
			if err != nil {
				errs <- err
				return
			}
			var current Config
			if err := yaml.Unmarshal(data, &current); err != nil {
				errs <- fmt.Errorf("reader saw partial YAML: %w", err)
				return
			}
			if current.Honeypots["conpot"].DeviceProfile.ID == "" {
				errs <- fmt.Errorf("reader saw incomplete config")
				return
			}
			if first {
				close(ready)
				first = false
			}
		}
	}()
	<-ready
	var writers sync.WaitGroup
	for _, name := range []string{"cowrie", "dionaea", "conpot", "heralding", "endlessh", "adbhoney"} {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for range 3 {
				cfg.EnableHoneypot(name)
				if err := Save(cfg); err != nil {
					errs <- err
					return
				}
				cfg.DisableHoneypot(name)
				if err := Save(cfg); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	writers.Wait()
	close(stop)
	readers.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	data, err := os.ReadFile(cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	var persisted Config
	if err := yaml.Unmarshal(data, &persisted); err != nil {
		t.Fatal(err)
	}
	want, err := yaml.Marshal(cfg.SnapshotHoneypots())
	if err != nil {
		t.Fatal(err)
	}
	got, err := yaml.Marshal(persisted.SnapshotHoneypots())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("concurrent save lost a honeypot update")
	}
}

// TestCleanupDefaults: a config without a cleanup section (written before
// cleanup existed) gets it on with the defaults; an explicit "off" and set
// limits are kept; values out of range fall back to the defaults.
func TestCleanupDefaults(t *testing.T) {
	parse := func(extra string) CleanupConfig {
		t.Helper()
		cfg, err := Parse([]byte("instance_name: x\n"+extra), filepath.Join(t.TempDir(), "config.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		return cfg.Cleanup
	}
	def := CleanupConfig{MaxAgeDays: DefaultCleanupMaxAgeDays, MaxLogMB: DefaultCleanupMaxLogMB, MaxBackupMB: DefaultCleanupMaxBackupMB}
	if c := parse(""); !c.On() || c.MaxAgeDays != def.MaxAgeDays || c.MaxLogMB != def.MaxLogMB || c.MaxBackupMB != def.MaxBackupMB {
		t.Errorf("no section: %+v", c)
	}
	if c := parse("cleanup:\n  enabled: false\n  max_age_days: 7\n  max_log_mb: 64\n  max_backup_mb: 100\n"); c.On() || c.MaxAgeDays != 7 || c.MaxLogMB != 64 || c.MaxBackupMB != 100 {
		t.Errorf("set values: %+v", c)
	}
	if c := parse("cleanup:\n  enabled: true\n  max_age_days: -1\n  max_log_mb: 0\n  max_backup_mb: 99999999999\n"); !c.On() || c.MaxAgeDays != def.MaxAgeDays || c.MaxLogMB != def.MaxLogMB || c.MaxBackupMB != def.MaxBackupMB {
		t.Errorf("out of range: %+v", c)
	}
	// Saved and read again, "off" stays off.
	cfg, _ := Parse([]byte("instance_name: x\ncleanup:\n  enabled: false\n"), filepath.Join(t.TempDir(), "config.yaml"))
	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Parse(out, cfg.ConfigPath)
	if err != nil || again.Cleanup.On() {
		t.Errorf("off did not survive a save: %v %+v", err, again.Cleanup)
	}
}

// TestDiskGuardSettings: the disk guard is on with its defaults in a config
// that does not mention it (written before the guard existed), 0 turns it
// off, set values are kept, and marks that cannot work are refused when the
// file is read and when it is saved.
func TestDiskGuardSettings(t *testing.T) {
	parse := func(extra string) (*Config, error) {
		return Parse([]byte("instance_name: x\n"+extra), filepath.Join(t.TempDir(), "config.yaml"))
	}
	good := []struct {
		name, yaml  string
		min, resume int64
	}{
		{"no cleanup section", "", 512, 1024},
		{"cleanup section without the guard", "cleanup:\n  enabled: false\n  max_age_days: 7\n", 512, 1024},
		{"both set", "cleanup:\n  min_free_mb: 2000\n  resume_free_mb: 5000\n", 2000, 5000},
		{"only the floor, below the default resume mark", "cleanup:\n  min_free_mb: 100\n", 100, 1024},
		{"only the floor, above the default resume mark", "cleanup:\n  min_free_mb: 4096\n", 4096, 8192},
		{"only the floor, at the default resume mark", "cleanup:\n  min_free_mb: 1024\n", 1024, 2048},
		{"only the resume mark", "cleanup:\n  resume_free_mb: 600\n", 512, 600},
		{"resume one above the floor", "cleanup:\n  min_free_mb: 512\n  resume_free_mb: 513\n", 512, 513},
		{"off", "cleanup:\n  min_free_mb: 0\n", 0, 0},
		{"off, with a resume mark left in", "cleanup:\n  min_free_mb: 0\n  resume_free_mb: 1024\n", 0, 0},
		{"null means unset", "cleanup:\n  min_free_mb: null\n", 512, 1024},
		{"the largest floor", fmt.Sprintf("cleanup:\n  min_free_mb: %d\n", MaxCleanupMB/2), MaxCleanupMB / 2, MaxCleanupMB},
	}
	for _, c := range good {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := parse(c.yaml)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			min, resume := cfg.Cleanup.DiskGuard()
			if min != c.min || resume != c.resume {
				t.Errorf("DiskGuard() = %d, %d, want %d, %d", min, resume, c.min, c.resume)
			}
			if min > 0 && resume <= min {
				t.Errorf("resume mark %d is not above the floor %d", resume, min)
			}
			// The guard does not depend on the hourly cleanup being on.
			if c.name == "cleanup section without the guard" && cfg.Cleanup.On() {
				t.Error("cleanup.enabled: false was lost")
			}
			// Saved and read again, the marks are the same.
			out, err := yaml.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			again, err := Parse(out, cfg.ConfigPath)
			if err != nil {
				t.Fatalf("Parse of the saved config: %v", err)
			}
			if m2, r2 := again.Cleanup.DiskGuard(); m2 != min || r2 != resume {
				t.Errorf("after a save: %d, %d, want %d, %d", m2, r2, min, resume)
			}
		})
	}

	bad := []struct{ name, yaml, want string }{
		{"resume equal to the floor", "cleanup:\n  min_free_mb: 512\n  resume_free_mb: 512\n", "must be greater than cleanup.min_free_mb"},
		{"resume below the floor", "cleanup:\n  min_free_mb: 2048\n  resume_free_mb: 1024\n", "must be greater than cleanup.min_free_mb"},
		{"resume below the default floor", "cleanup:\n  resume_free_mb: 100\n", "must be greater than cleanup.min_free_mb 512"},
		{"negative floor", "cleanup:\n  min_free_mb: -1\n", "cleanup.min_free_mb -1"},
		{"negative resume mark", "cleanup:\n  resume_free_mb: -5\n", "cleanup.resume_free_mb -5"},
		{"floor too large", fmt.Sprintf("cleanup:\n  min_free_mb: %d\n", MaxCleanupMB/2+1), "cleanup.min_free_mb"},
		{"resume mark too large", fmt.Sprintf("cleanup:\n  resume_free_mb: %d\n", MaxCleanupMB+1), "cleanup.resume_free_mb"},
		{"negative resume mark with the guard off", "cleanup:\n  min_free_mb: 0\n  resume_free_mb: -1\n", "cleanup.resume_free_mb -1"},
		{"not a number", "cleanup:\n  min_free_mb: lots\n", "parse config file"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := parse(c.yaml)
			if err == nil {
				min, resume := cfg.Cleanup.DiskGuard()
				t.Fatalf("Parse accepted it: floor %d, resume %d", min, resume)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not contain %q", err, c.want)
			}
		})
	}

	// A new instance has the guard on, written out in its config file.
	def := Default("guard-default")
	if def.Cleanup.MinFreeMB == nil || *def.Cleanup.MinFreeMB != DefaultDiskGuardMinFreeMB || def.Cleanup.ResumeFreeMB != DefaultDiskGuardResumeFreeMB {
		t.Fatalf("Default: %+v", def.Cleanup)
	}
	// Each instance has its own floor: changing one does not change another.
	other := Default("guard-other")
	*other.Cleanup.MinFreeMB = 9
	if *def.Cleanup.MinFreeMB != DefaultDiskGuardMinFreeMB {
		t.Fatal("two default configs share one min_free_mb")
	}
	out, err := yaml.Marshal(def)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "min_free_mb: 512") || !strings.Contains(string(out), "resume_free_mb: 1024") {
		t.Errorf("the default config file does not show the guard's marks")
	}

	// Save refuses what Parse would refuse, and leaves the file alone.
	dir := t.TempDir()
	cfg := Default("guard-save")
	cfg.DataPath, cfg.ConfigPath = dir, filepath.Join(dir, "config.yaml")
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Cleanup.ResumeFreeMB = 10
	if err := Save(cfg); err == nil || !strings.Contains(err.Error(), "must be greater than cleanup.min_free_mb") {
		t.Fatalf("Save with a resume mark below the floor: %v", err)
	}
	after, err := os.ReadFile(cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("a refused save changed the config file")
	}
}

func TestDiskGuardReserve(t *testing.T) {
	mb := func(n int64) *int64 { return &n }
	for _, c := range []struct {
		name          string
		cleanup       CleanupConfig
		want          int64
		refuseContain string
	}{
		{name: "defaults", cleanup: CleanupConfig{}, want: 64},
		{name: "small floor", cleanup: CleanupConfig{MinFreeMB: mb(100)}, want: 50},
		{name: "guard off", cleanup: CleanupConfig{MinFreeMB: mb(0)}, want: 0},
		{name: "none", cleanup: CleanupConfig{ReserveMB: mb(0)}, want: 0},
		{name: "set", cleanup: CleanupConfig{ReserveMB: mb(200)}, want: 200},
		{name: "as large as the floor", cleanup: CleanupConfig{ReserveMB: mb(512)}, refuseContain: "cleanup.reserve_mb 512"},
		{name: "negative", cleanup: CleanupConfig{ReserveMB: mb(-1)}, refuseContain: "cleanup.reserve_mb -1"},
	} {
		err := c.cleanup.ValidateDiskGuard()
		if c.refuseContain != "" {
			if err == nil || !strings.Contains(err.Error(), c.refuseContain) {
				t.Errorf("%s: ValidateDiskGuard = %v, want a refusal naming %q", c.name, err, c.refuseContain)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: ValidateDiskGuard = %v", c.name, err)
		}
		if got := c.cleanup.DiskGuardReserveMB(); got != c.want {
			t.Errorf("%s: reserve %d MB, want %d", c.name, got, c.want)
		}
	}
}
