package instance

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/hostsetup"
	"github.com/qpot/qpot/internal/security"
	"gopkg.in/yaml.v3"
)

func TestSandboxOutputBoundsCopyFastPath(t *testing.T) {
	const limit = 4 << 20
	for _, size := range []int{0, limit, limit + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			var output sandboxOutput
			// A pipe reader has no WriterTo method. io.Copy must not discover
			// an embedded Buffer.ReadFrom that bypasses our bounded Write.
			reader := struct{ io.Reader }{strings.NewReader(strings.Repeat("x", size))}
			n, err := io.Copy(&output, reader)
			if (err != nil) != (size > limit) || n > limit || len(output.Bytes()) > limit {
				t.Fatalf("copy size=%d accepted=%d stored=%d error=%v", size, n, len(output.Bytes()), err)
			}
			if size <= limit && (n != int64(size) || len(output.Bytes()) != size) {
				t.Fatal("a valid isolation report was truncated")
			}
		})
	}
}

// The test executable also provides a portable, isolated Docker stand-in.
// Using an executable rather than a shell wrapper covers these cases on Windows.
func init() {
	path := os.Getenv("QPOT_TEST_SANDBOX_DOCKER_FIXTURE")
	if path == "" {
		return
	}
	os.Exit(runSandboxDockerFixture(path, os.Args[1:]))
}

type sandboxDockerFixture struct {
	Registry                 map[string]json.RawMessage
	RegistryError            bool
	List, Inspect, ComposePS string
	StopError                bool
	Calls                    string
}

func runSandboxDockerFixture(path string, args []string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 80
	}
	var fixture sandboxDockerFixture
	if json.Unmarshal(data, &fixture) != nil {
		return 81
	}
	f, err := os.OpenFile(fixture.Calls, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return 82
	}
	line, _ := json.Marshal(args)
	_, err = f.Write(append(line, '\n'))
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return 83
	}
	if len(args) == 0 {
		return 84
	}
	switch args[0] {
	case "info":
		if strings.Contains(strings.Join(args, " "), "Runtimes") {
			if fixture.RegistryError {
				return 19
			}
			data, _ := json.Marshal(fixture.Registry)
			fmt.Println(string(data))
		} else {
			fmt.Println(sshSupportedResourceInfo)
		}
	case "ps":
		fmt.Print(fixture.List)
	case "inspect":
		if slices.Contains(args, "--type") {
			fmt.Fprintln(os.Stderr, "Error: No such container")
			return 1
		}
		fmt.Print(fixture.Inspect)
	case "compose":
		if slices.Contains(args, "ps") {
			fmt.Print(fixture.ComposePS)
		}
		if slices.Contains(args, "stop") && fixture.StopError {
			return 20
		}
	}
	return 0
}

type sandboxDockerHarness struct {
	t       *testing.T
	path    string
	fixture sandboxDockerFixture
}

func newSandboxDockerHarness(t *testing.T) *sandboxDockerHarness {
	t.Helper()
	dir := t.TempDir()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	name := "docker"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	target := filepath.Join(dir, name)
	// Windows refuses to delete any link to a running image, and this one
	// would name the running test binary itself, so it gets a copy there.
	if runtime.GOOS == "windows" || os.Link(binary, target) != nil {
		src, openErr := os.Open(binary)
		if openErr != nil {
			t.Fatal(openErr)
		}
		defer src.Close()
		dst, createErr := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
		if createErr != nil {
			t.Fatal(createErr)
		}
		_, copyErr := io.Copy(dst, src)
		closeErr := dst.Close()
		if copyErr != nil || closeErr != nil {
			t.Fatal(errors.Join(copyErr, closeErr))
		}
	}
	h := &sandboxDockerHarness{t: t, path: filepath.Join(dir, "fixture.json"), fixture: sandboxDockerFixture{Registry: map[string]json.RawMessage{"runc": nil}, Calls: filepath.Join(dir, "calls.jsonl")}}
	h.save()
	t.Setenv("QPOT_TEST_SANDBOX_DOCKER_FIXTURE", h.path)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	// Race instrumentation remains enabled for helper processes, but they do
	// not need the race runtime's one-second default exit delay per Docker call.
	// The parent test's race runtime was initialized before this setting.
	t.Setenv("GORACE", strings.TrimSpace(os.Getenv("GORACE")+" atexit_sleep_ms=0"))
	return h
}
func (h *sandboxDockerHarness) save() {
	h.t.Helper()
	data, err := json.Marshal(h.fixture)
	if err != nil {
		h.t.Fatal(err)
	}
	if err = os.WriteFile(h.path, data, 0o600); err != nil {
		h.t.Fatal(err)
	}
}
func (h *sandboxDockerHarness) calls() [][]string {
	h.t.Helper()
	data, err := os.ReadFile(h.fixture.Calls)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		h.t.Fatal(err)
	}
	var out [][]string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var call []string
		if err := json.Unmarshal([]byte(line), &call); err != nil {
			h.t.Fatal(err)
		}
		out = append(out, call)
	}
	return out
}
func (h *sandboxDockerHarness) called(action string) bool {
	for _, call := range h.calls() {
		if len(call) > 0 && call[0] == "compose" && slices.Contains(call, action) {
			return true
		}
	}
	return false
}
func (h *sandboxDockerHarness) metadata(rows ...sandboxContainer) {
	h.fixture.List = ""
	h.fixture.Inspect = ""
	for _, row := range rows {
		h.fixture.List += row.ID + "\n"
		data, _ := json.Marshal(row)
		h.fixture.Inspect += string(data) + "\n"
	}
	h.save()
}
func sandboxInstanceConfig(t *testing.T, names ...string) *config.Config {
	t.Helper()
	cfg := config.Default("sandbox-integration")
	cfg.QPotID = "qp_abcdefghijklmnopqrstuvwx"
	cfg.DataPath = filepath.Join(t.TempDir(), "instance")
	cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
	enabled := map[string]bool{}
	for _, name := range names {
		enabled[name] = true
	}
	for name, hp := range cfg.Honeypots {
		hp.Enabled = enabled[name]
		cfg.Honeypots[name] = hp
	}
	if enabled[sshProxyHoneypot] {
		hp := cfg.Honeypots[sshProxyHoneypot]
		hp.CustomConfig["image_source"] = "local"
		hp.CustomConfig["backends"] = "1"
		cfg.Honeypots[sshProxyHoneypot] = hp
	}
	return cfg
}
func sandboxAssertCode(t *testing.T, err error, want string) {
	t.Helper()
	var coded *hostsetup.Error
	if !errors.As(err, &coded) || coded == nil || coded.Code != want {
		t.Fatalf("got %v; want %s", err, want)
	}
}
func sandboxRow(cfg *config.Config, number int, service, rt string) sandboxContainer {
	return sandboxContainer{ID: fmt.Sprintf("%064x", number), Runtime: rt, Service: service, Instance: cfg.InstanceName, Honeypot: service, Running: true}
}
func sandboxWriteCompose(t *testing.T, cfg *config.Config, rt string, services ...string) {
	t.Helper()
	mapping := map[string]any{}
	for _, service := range services {
		mapping[service] = map[string]any{"runtime": rt, "labels": map[string]string{"qpot.instance": cfg.InstanceName, "qpot.honeypot": service}}
	}
	data, err := yaml.Marshal(map[string]any{"services": mapping})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.DataPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.GetDockerComposePath(), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSandboxDeploymentRefusesBeforeLocalMutations(t *testing.T) {
	for _, mode := range []string{"gvisor", "kata", "firejail", "gvsior"} {
		for _, action := range []string{"start", "honeypot", "recreate"} {
			t.Run(mode+"/"+action, func(t *testing.T) {
				h := newSandboxDockerHarness(t)
				cfg := sandboxInstanceConfig(t, "cowrie")
				cfg.Security.SandboxMode = mode
				manager, err := NewManager(cfg)
				if err != nil {
					t.Fatalf("inspection/recovery constructor failed: %v", err)
				}
				switch action {
				case "start":
					err = manager.Start(t.Context(), true)
				case "honeypot":
					err = manager.StartHoneypot(t.Context(), "cowrie")
				case "recreate":
					err = manager.RecreateHoneypot(t.Context(), "cowrie")
				}
				want := "QP-DOCKER-011"
				if mode == "firejail" || mode == "gvsior" {
					want = "QP-DOCKER-010"
				}
				sandboxAssertCode(t, err, want)
				if _, err := os.Lstat(cfg.DataPath); !os.IsNotExist(err) {
					t.Fatal("refused deployment created or changed its data directory")
				}
				for _, call := range h.calls() {
					if len(call) == 0 || call[0] != "info" {
						t.Fatalf("refusal reached a runtime operation: %v", call)
					}
				}
			})
		}
	}
}

func TestSandboxRenderingCannotBeWeakenedByInjectedSandbox(t *testing.T) {
	for _, mode := range []string{"gvisor", "kata"} {
		for _, injected := range []string{"nil", "none", "other"} {
			t.Run(mode+"/"+injected, func(t *testing.T) {
				h := newSandboxDockerHarness(t)
				h.fixture.RegistryError = true
				h.save()
				cfg := sandboxInstanceConfig(t, "cowrie", "tanner")
				cfg.Security.SandboxMode = mode
				var sb *security.Sandbox
				if injected != "nil" {
					selected := "none"
					if injected == "other" {
						selected = "kata"
						if mode == "kata" {
							selected = "gvisor"
						}
					}
					sb, _ = security.NewSandbox(&config.SecurityConfig{SandboxMode: selected})
				}
				text, err := (&ComposeGenerator{Config: cfg, Sandbox: sb}).Generate()
				if err != nil {
					t.Fatal(err)
				}
				var doc struct {
					Services map[string]struct {
						Runtime string
						Labels  map[string]string
					}
				}
				if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
					t.Fatal(err)
				}
				want := "runsc"
				if mode == "kata" {
					want = "kata-runtime"
				}
				count := 0
				for name, service := range doc.Services {
					if service.Labels["qpot.honeypot"] != "" {
						count++
						if service.Runtime != want {
							t.Fatalf("%s silently selected %q instead of %q", name, service.Runtime, want)
						}
					}
				}
				if count < 4 {
					t.Fatal("fixture did not exercise attacker-facing companions")
				}
				if len(h.calls()) != 0 {
					t.Fatal("offline rendering required daemon availability")
				}
			})
		}
	}
}

func TestSandboxInitializePreservesDeclaredUnavailableRuntime(t *testing.T) {
	h := newSandboxDockerHarness(t)
	h.fixture.RegistryError = true
	h.save()
	cfg := sandboxInstanceConfig(t, "cowrie")
	cfg.Security.SandboxMode = "gvisor"
	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Initialize(t.Context()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(cfg.GetDockerComposePath())
	if err != nil || !strings.Contains(string(data), "runtime: runsc") {
		t.Fatalf("offline initialization dropped declared isolation: %v", err)
	}
	for _, call := range h.calls() {
		if len(call) > 0 && call[0] == "info" && strings.Contains(strings.Join(call, " "), "Runtimes") {
			t.Fatal("offline initialization probed live runtime availability")
		}
		if slices.Contains(call, "up") {
			t.Fatal("offline initialization started services")
		}
	}
}

func TestSandboxApprovedDockerFallbackAndExplicitNoneStart(t *testing.T) {
	for _, mode := range []string{"none", "gvisor"} {
		t.Run(mode, func(t *testing.T) {
			h := newSandboxDockerHarness(t)
			cfg := sandboxInstanceConfig(t, "cowrie")
			cfg.Security.SandboxMode = mode
			cfg.Security.SandboxFallback = "docker"
			manager, err := NewManager(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.StartHoneypot(t.Context(), "cowrie"); err != nil {
				t.Fatal(err)
			}
			if !h.called("up") {
				t.Fatal("legitimate deployment never reached Docker")
			}
			if cfg.Security.SandboxMode != mode {
				t.Fatal("effective fallback mutated declared policy")
			}
			data, err := os.ReadFile(cfg.GetDockerComposePath())
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(serviceBlock(string(data), "cowrie"), "runtime: runsc") {
				t.Fatal("explicit fallback did not render its approved effective runtime")
			}
		})
	}
}

func TestSandboxFallbackCannotBeGrantedByRiskMetadata(t *testing.T) {
	for _, name := range []string{"ssh-proxy", "tanner", "beelzebub", "endlessh"} {
		t.Run(name, func(t *testing.T) {
			h := newSandboxDockerHarness(t)
			cfg := sandboxInstanceConfig(t, name)
			cfg.Security.SandboxMode = "gvisor"
			cfg.Security.SandboxFallback = "docker"
			hp := cfg.Honeypots[name]
			hp.RiskLevel = "low"
			hp.Sandbox = false
			cfg.Honeypots[name] = hp
			_, err := resolveSandbox(t.Context(), cfg)
			sandboxAssertCode(t, err, "QP-DOCKER-011")
			if h.called("up") {
				t.Fatal("unreviewed/executing service was started under fallback")
			}
		})
	}
}

func TestSandboxDisabledExecutionTargetCannotUseEmulatorFallback(t *testing.T) {
	for _, target := range []string{"ssh-proxy", "tanner", "beelzebub"} {
		t.Run(target, func(t *testing.T) {
			h := newSandboxDockerHarness(t)
			cfg := sandboxInstanceConfig(t, "cowrie")
			cfg.Security.SandboxMode = "gvisor"
			cfg.Security.SandboxFallback = "docker"
			hp := cfg.Honeypots[target]
			hp.Enabled, hp.Sandbox, hp.RiskLevel = false, false, "low"
			if target == sshProxyHoneypot {
				if hp.CustomConfig == nil {
					hp.CustomConfig = map[string]string{}
				}
				hp.CustomConfig["image_source"] = "local"
			}
			cfg.Honeypots[target] = hp
			manager, err := NewManager(cfg)
			if err != nil {
				t.Fatal(err)
			}
			err = manager.RestartHoneypot(t.Context(), target)
			sandboxAssertCode(t, err, "QP-DOCKER-011")
			if h.called("restart") {
				t.Fatal("disabled execution target bypassed the fallback classification")
			}
		})
	}
}

func TestSandboxControlOnlyConfigurationDoesNotRequireGuestRuntime(t *testing.T) {
	h := newSandboxDockerHarness(t)
	h.fixture.RegistryError = true
	h.save()
	cfg := sandboxInstanceConfig(t)
	selection, err := resolveSandbox(t.Context(), cfg)
	if err != nil || selection.Requested != security.SandboxGVisor || selection.Runtime != "runsc" || selection.Fallback {
		t.Fatalf("control-only operation changed its declared policy: %+v %v", selection, err)
	}
	if len(h.calls()) != 0 {
		t.Fatal("control-only operation probed an unused honeypot runtime")
	}
	cfg.Security.SandboxMode = "firejail"
	_, err = resolveSandbox(t.Context(), cfg)
	sandboxAssertCode(t, err, "QP-DOCKER-010")
}

func TestSandboxRunningExecutionCompanionPreventsFallback(t *testing.T) {
	h := newSandboxDockerHarness(t)
	cfg := sandboxInstanceConfig(t, "cowrie")
	cfg.Security.SandboxFallback = "docker"
	row := sandboxRow(cfg, 1, "tanner_phpox", "runc")
	row.Honeypot = "tanner"
	h.metadata(row)
	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	status, err := manager.SandboxStatus(t.Context())
	sandboxAssertCode(t, err, "QP-DOCKER-011")
	if status.Verified || status.Runtime != "runc" || status.Code != "QP-DOCKER-011" {
		t.Fatalf("running execution companion was reported as safe fallback: %+v", status)
	}
}

func TestSandboxRestartChecksStoredAndActualRuntime(t *testing.T) {
	for _, scenario := range []string{"valid", "stored mismatch", "actual mismatch", "availability removed", "changed policy after construction"} {
		t.Run(scenario, func(t *testing.T) {
			h := newSandboxDockerHarness(t)
			cfg := sandboxInstanceConfig(t, "cowrie")
			cfg.Security.SandboxMode = "gvisor"
			h.fixture.Registry = map[string]json.RawMessage{"runsc": nil}
			h.save()
			sandboxWriteCompose(t, cfg, "runsc", "cowrie")
			h.metadata(sandboxRow(cfg, 1, "cowrie", "runsc"))
			manager, err := NewManager(cfg)
			if err != nil {
				t.Fatal(err)
			}
			want := ""
			switch scenario {
			case "stored mismatch":
				sandboxWriteCompose(t, cfg, "runc", "cowrie")
				want = "QP-DOCKER-012"
			case "actual mismatch":
				h.metadata(sandboxRow(cfg, 1, "cowrie", "runc"))
				want = "QP-DOCKER-012"
			case "availability removed":
				h.fixture.Registry = map[string]json.RawMessage{"runc": nil}
				h.save()
				want = "QP-DOCKER-011"
			case "changed policy after construction":
				cfg.Security.SandboxMode = "kata"
				want = "QP-DOCKER-011"
			}
			err = manager.RestartHoneypot(t.Context(), "cowrie")
			if want != "" {
				sandboxAssertCode(t, err, want)
				if h.called("restart") {
					t.Fatal("runtime refusal still restarted a container")
				}
			} else if err != nil || !h.called("restart") {
				t.Fatalf("legitimate restart failed: %v", err)
			}
		})
	}
}

func TestSandboxPostStartMismatchStopsAffectedGuests(t *testing.T) {
	for _, stopFails := range []bool{false, true} {
		t.Run(fmt.Sprint(stopFails), func(t *testing.T) {
			h := newSandboxDockerHarness(t)
			cfg := sandboxInstanceConfig(t, "cowrie")
			cfg.Security.SandboxMode = "gvisor"
			h.fixture.Registry = map[string]json.RawMessage{"runsc": nil}
			h.fixture.StopError = stopFails
			h.save()
			h.metadata(sandboxRow(cfg, 1, "cowrie", "runc"))
			manager, err := NewManager(cfg)
			if err != nil {
				t.Fatal(err)
			}
			err = manager.StartHoneypot(t.Context(), "cowrie")
			sandboxAssertCode(t, err, "QP-DOCKER-012")
			if !h.called("up") || !h.called("stop") {
				t.Fatalf("post-start mismatch did not stop unsafe guests: %v", h.calls())
			}
		})
	}
}

func TestSandboxCancelledRuntimeVerificationStillStopsGuests(t *testing.T) {
	h := newSandboxDockerHarness(t)
	cfg := sandboxInstanceConfig(t, "cowrie")
	if err := os.MkdirAll(cfg.DataPath, 0o700); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	selection := security.RuntimeSelection{Requested: security.SandboxGVisor, Effective: security.SandboxGVisor, Runtime: "runsc"}
	err = manager.verifyStartedSandbox(ctx, []string{"cowrie"}, selection)
	sandboxAssertCode(t, err, "QP-DOCKER-012")
	if !h.called("stop") {
		t.Fatal("cancelled runtime verification prevented emergency guest stopping")
	}
}

func TestSandboxStatusRejectsInvalidContainerMetadata(t *testing.T) {
	for _, scenario := range []string{"valid", "none running", "no services", "runtime mismatch", "mixed", "foreign instance", "missing honeypot", "missing service", "duplicate service", "duplicate report", "duplicate ID list", "truncated ID", "unlisted ID", "missing report", "malformed report", "trailing delimiter", "oversized report", "too many IDs", "explicit fallback", "explicit none"} {
		t.Run(scenario, func(t *testing.T) {
			h := newSandboxDockerHarness(t)
			cfg := sandboxInstanceConfig(t, "cowrie", "conpot")
			cfg.Security.SandboxMode = "gvisor"
			h.fixture.Registry = map[string]json.RawMessage{"runsc": nil}
			h.save()
			row := sandboxRow(cfg, 1, "cowrie", "runsc")
			h.metadata(row)
			wantCode := ""
			wantVerified := true
			wantRuntime := "runsc"
			wantFallback := false
			switch scenario {
			case "none running":
				row.Running = false
				h.metadata(row)
				wantVerified = false
				wantRuntime = ""
			case "no services":
				h.metadata()
				wantVerified = false
				wantRuntime = ""
			case "runtime mismatch":
				row.Runtime = "runc"
				h.metadata(row)
				wantCode = "QP-DOCKER-012"
				wantRuntime = "runc"
			case "mixed":
				h.metadata(row, sandboxRow(cfg, 2, "conpot", "runc"))
				wantCode = "QP-DOCKER-012"
				wantRuntime = "mixed"
			case "foreign instance":
				row.Instance = "foreign"
				h.metadata(row)
				wantCode = "QP-DOCKER-012"
				wantRuntime = ""
			case "missing honeypot":
				row.Honeypot = ""
				h.metadata(row)
				wantCode = "QP-DOCKER-012"
				wantRuntime = ""
			case "missing service":
				row.Service = ""
				h.metadata(row)
				wantCode = "QP-DOCKER-012"
				wantRuntime = ""
			case "duplicate service":
				other := row
				other.ID = fmt.Sprintf("%064x", 2)
				h.metadata(row, other)
				wantCode = "QP-DOCKER-012"
			case "duplicate report":
				data, _ := json.Marshal(row)
				h.fixture.Inspect = string(data) + "\n" + string(data) + "\n"
				h.save()
				wantCode = "QP-DOCKER-012"
				wantRuntime = ""
			case "duplicate ID list":
				h.fixture.List = row.ID + "\n" + row.ID + "\n"
				h.save()
				wantCode = "QP-DOCKER-012"
				wantRuntime = ""
			case "truncated ID":
				h.fixture.List = "0123456789ab\n"
				h.save()
				wantCode = "QP-DOCKER-012"
				wantRuntime = ""
			case "unlisted ID":
				row.ID = fmt.Sprintf("%064x", 2)
				data, _ := json.Marshal(row)
				h.fixture.Inspect = string(data)
				h.save()
				wantCode = "QP-DOCKER-012"
				wantRuntime = ""
			case "missing report":
				h.fixture.List += fmt.Sprintf("%064x\n", 2)
				h.save()
				wantCode = "QP-DOCKER-012"
				wantRuntime = ""
			case "malformed report":
				h.fixture.Inspect = "{"
				h.save()
				wantCode = "QP-DOCKER-012"
				wantRuntime = ""
			case "trailing delimiter":
				h.fixture.Inspect += "]\n"
				h.save()
				wantCode = "QP-DOCKER-012"
				wantRuntime = ""
			case "oversized report":
				h.fixture.Inspect = strings.Repeat("x", (4<<20)+1)
				h.save()
				wantCode = "QP-DOCKER-012"
				wantRuntime = ""
			case "too many IDs":
				h.fixture.List = ""
				for i := 1; i <= 513; i++ {
					h.fixture.List += fmt.Sprintf("%064x\n", i)
				}
				h.save()
				wantCode = "QP-DOCKER-012"
				wantRuntime = ""
			case "explicit fallback":
				cfg.Security.SandboxFallback = "docker"
				h.fixture.Registry = map[string]json.RawMessage{"runc": nil}
				row.Runtime = "runc"
				h.metadata(row)
				wantRuntime = "runc"
				wantFallback = true
			case "explicit none":
				cfg.Security.SandboxMode = "none"
				row.Runtime = "runc"
				h.metadata(row)
				wantRuntime = "runc"
			}
			manager, err := NewManager(cfg)
			if err != nil {
				t.Fatal(err)
			}
			status, err := manager.SandboxStatus(t.Context())
			if wantCode != "" {
				sandboxAssertCode(t, err, wantCode)
				wantVerified = false
				if status.Code != wantCode {
					t.Fatal("health response omitted its runtime error code")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if status.Runtime != wantRuntime || status.Verified != wantVerified || status.Fallback != wantFallback {
				t.Fatalf("unexpected actual-runtime health: %+v", status)
			}
			if strings.Contains(fmt.Sprintf("%+v", status), "QPOT_TEST_") {
				t.Fatal("private helper metadata entered health response")
			}
		})
	}
}

func TestSandboxRecyclerUsesSavedPolicyAndKeepsFailedCellStopped(t *testing.T) {
	for _, scenario := range []string{"changed policy", "stored mismatch", "actual mismatch"} {
		t.Run(scenario, func(t *testing.T) {
			cfg := organizationTestConfig(t)
			cfg.Security.SandboxMode = "none"
			if err := config.Save(cfg); err != nil {
				t.Fatal(err)
			}
			h := newSandboxDockerHarness(t)
			h.fixture.ComposePS = `[{"Service":"ssh-proxy","State":"running"}]`
			h.save()
			recycler := requireBackendRecycler(t, cfg)
			cfg.Security.SandboxMode = "gvisor"
			if err := config.Save(cfg); err != nil {
				t.Fatal(err)
			}
			var document map[string]any
			if err := yaml.Unmarshal(organizationComposeFixture(t, cfg.InstanceName, 2, true), &document); err != nil {
				t.Fatal(err)
			}
			runtimeName := "runsc"
			if scenario == "stored mismatch" {
				runtimeName = "runc"
			}
			for _, value := range document["services"].(map[string]any) {
				value.(map[string]any)["runtime"] = runtimeName
			}
			data, _ := yaml.Marshal(document)
			storageWrite(t, cfg.GetDockerComposePath(), data, 0o600)
			want := "QP-DOCKER-011"
			if scenario != "changed policy" {
				h.fixture.Registry = map[string]json.RawMessage{"runsc": nil}
				h.save()
				want = "QP-DOCKER-012"
			}
			if scenario == "actual mismatch" {
				h.metadata(sandboxRow(cfg, 1, "ssh-backend-1", "runc"), sandboxRow(cfg, 2, "ssh-backend-1-db", "runsc"), sandboxRow(cfg, 3, "ssh-backend-1-backup", "runsc"))
			}
			generation := uint64(0)
			err := recycler.resetCell(t.Context(), "ssh-backend-1", &generation)
			sandboxAssertCode(t, err, want)
			if !h.called("stop") {
				t.Fatal("failed policy reset left the dirty cell running")
			}
			if recycler.generation("ssh-backend-1") != 0 {
				t.Fatal("failed policy reset advanced its generation")
			}
			if scenario != "actual mismatch" && h.called("up") {
				t.Fatal("refused policy reset still recreated a cell")
			}
			if scenario == "actual mismatch" && !h.called("up") {
				t.Fatal("fixture did not reach actual post-create runtime verification")
			}
		})
	}
}

// This opt-in gate observes Docker's actual selected runtime, rather than
// inferring isolation from an installed binary or generated Compose text.
func TestSandboxRuntimeWithRealDocker(t *testing.T) {
	if os.Getenv("QPOT_TEST_SANDBOX_RUNTIME") != "1" {
		t.Skip("set QPOT_TEST_SANDBOX_RUNTIME=1 for the isolated real-Docker runtime gate")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("this managed-socket live gate requires a Linux Docker host")
	}
	t.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
	for _, key := range []string{"DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"} {
		t.Setenv(key, "")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", "public.ecr.aws/docker/library/alpine:3.20").CombinedOutput()
	if err != nil {
		t.Fatalf("live gate requires the cached Alpine fixture; it never pulls: %v %s", err, output)
	}
	image := strings.TrimSpace(string(output))
	if len(image) != 71 || !strings.HasPrefix(image, "sha256:") || strings.Trim(strings.TrimPrefix(image, "sha256:"), "0123456789abcdef") != "" {
		t.Fatal("cached fixture did not provide a complete image identity")
	}
	var nonce [6]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	cfg := sandboxInstanceConfig(t, "cowrie")
	cfg.InstanceName = fmt.Sprintf("sb-live-%x", nonce)
	cfg.Security.SandboxMode = "none"
	name := cfg.InstanceName + "-cowrie"
	// docker run can create a stopped container before reporting a startup
	// failure. Verify ownership and clean that case too, without touching a
	// pre-existing container which happens to have the same name.
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		owner, err := exec.CommandContext(cleanup, "docker", "inspect", "--format", `{{index .Config.Labels "qpot.instance"}}`, name).CombinedOutput()
		if err != nil {
			if strings.Contains(string(owner), "No such") {
				return
			}
			t.Errorf("verify owned runtime fixture for cleanup: %v %s", err, owner)
			return
		}
		if strings.TrimSpace(string(owner)) != cfg.InstanceName {
			t.Error("runtime fixture name belongs to another owner; refusing removal")
			return
		}
		if output, err := exec.CommandContext(cleanup, "docker", "rm", "--force", name).CombinedOutput(); err != nil {
			t.Errorf("remove owned runtime fixture: %v %s", err, output)
		}
	})
	command := exec.CommandContext(ctx, "docker", "run", "--detach", "--name", name,
		"--runtime", "runc", "--network", "none", "--read-only", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--user", "65534:65534", "--pids-limit", "16", "--memory", "32m",
		"--label", "qpot.instance="+cfg.InstanceName, "--label", "qpot.honeypot=cowrie",
		"--label", "com.docker.compose.service=cowrie", "--entrypoint", "/bin/sleep", image, "30")
	output, err = command.CombinedOutput()
	if err != nil {
		t.Fatalf("start owned, network-none fixture: %v %s", err, output)
	}
	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	status, err := manager.SandboxStatus(ctx)
	if err != nil || !status.Verified || status.Runtime != "runc" || status.Services["cowrie"] != "runc" || status.Fallback || status.Requested != "none" {
		t.Fatalf("actual Docker runtime was not verified: %+v %v", status, err)
	}
	cfg.Security.SandboxMode = "gvisor"
	status, err = manager.SandboxStatus(ctx)
	var coded *hostsetup.Error
	if !errors.As(err, &coded) || coded == nil || (coded.Code != "QP-DOCKER-011" && coded.Code != "QP-DOCKER-012") || status.Verified || status.Runtime != "runc" {
		t.Fatalf("ordinary Docker was misreported as requested gVisor: %+v %v", status, err)
	}
	cfg.Security.SandboxMode = "firejail"
	status, err = manager.SandboxStatus(ctx)
	sandboxAssertCode(t, err, "QP-DOCKER-010")
	if status.Verified || status.Runtime != "runc" {
		t.Fatalf("ordinary Docker was misreported as Firejail: %+v", status)
	}
	t.Logf("Real Docker runtime %q verified using cached image %s; requested stronger/unsupported modes rejected without claiming their isolation", "runc", image)
}
