package security

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/hostsetup"
)

// This regression failed against the original implementation for both
// requested strong runtimes; the explicit ordinary-Docker control passed.
func TestSandboxRetainsRequestedRuntime(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, tc := range []struct{ mode, want string }{{"", "runsc"}, {"gvisor", "runsc"}, {"kata", "kata-runtime"}, {"none", ""}} {
		t.Run(tc.mode, func(t *testing.T) {
			sb, err := NewSandbox(&config.SecurityConfig{SandboxMode: tc.mode})
			if err != nil {
				t.Fatal(err)
			}
			if got := sb.ContainerRuntime(); got != tc.want {
				t.Fatalf("declared %s runtime became %q; want %q", tc.mode, got, tc.want)
			}
		})
	}
}

func sandboxForTest(t *testing.T, mode, fallback string) *Sandbox {
	t.Helper()
	sb, err := NewSandbox(&config.SecurityConfig{SandboxMode: mode, SandboxFallback: fallback})
	if err != nil {
		t.Fatal(err)
	}
	return sb
}
func requireSandboxCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("unsafe operation accepted; want %s", code)
	}
	var coded *hostsetup.Error
	if !errors.As(err, &coded) || coded.Code != code {
		t.Fatalf("error %v does not carry %s", err, code)
	}
}
func runtimeRegistryForTest(t *testing.T, probe func(context.Context) (map[string]json.RawMessage, error)) {
	t.Helper()
	old := dockerRuntimes
	dockerRuntimes = probe
	t.Cleanup(func() { dockerRuntimes = old })
}

func TestSandboxConstructionAndPolicyInspectionDoNotProbeDocker(t *testing.T) {
	runtimeRegistryForTest(t, func(context.Context) (map[string]json.RawMessage, error) {
		t.Fatal("construction or policy inspection probed Docker")
		return nil, nil
	})
	for _, mode := range []string{"", "gvisor", "kata", "none", "firejail", "gvsior", "GVISOR", " gvisor", "gvisor\n", "gvisor\x00"} {
		sb := sandboxForTest(t, mode, "")
		selection, err := sb.Selection()
		switch mode {
		case "", "gvisor", "kata", "none":
			if err != nil || selection.Fallback {
				t.Fatalf("valid declared policy: %+v %v", selection, err)
			}
		default:
			requireSandboxCode(t, err, "QP-DOCKER-010")
		}
	}
	for _, fallback := range []string{"doker", "DENY", "none", " docker", "deny\n"} {
		_, err := sandboxForTest(t, "none", fallback).Selection()
		requireSandboxCode(t, err, "QP-DOCKER-010")
	}
	sb, err := NewSandbox(nil)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := sb.Selection()
	if err != nil || selection.Runtime != "runsc" {
		t.Fatalf("missing policy lost secure default: %+v %v", selection, err)
	}
}

func TestFirejailExecutableDoesNotClaimContainerIsolation(t *testing.T) {
	dir := t.TempDir()
	name := "firejail"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("unused executable fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if _, err := exec.LookPath("firejail"); err != nil {
		t.Fatalf("fixture executable is not discoverable: %v", err)
	}
	runtimeRegistryForTest(t, func(context.Context) (map[string]json.RawMessage, error) {
		t.Fatal("unsupported firejail reached daemon discovery")
		return nil, nil
	})
	sb := sandboxForTest(t, "firejail", "docker")
	_, err := sb.Selection()
	requireSandboxCode(t, err, "QP-DOCKER-010")
	_, err = sb.ResolveForStart(t.Context(), false)
	requireSandboxCode(t, err, "QP-DOCKER-010")
}

func TestResolveRuntimeRequiresDaemonRegistrationAndExplicitFallback(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // The execution daemon may be remote.
	sentinel := errors.New("unavailable execution daemon")
	tests := []struct {
		name, mode, fallback string
		high                 bool
		runtimes             map[string]json.RawMessage
		probeErr             error
		wantRuntime          string
		wantFallback         bool
		wantCode             string
	}{
		{name: "registered gvisor without client binary", mode: "gvisor", high: true, runtimes: map[string]json.RawMessage{"runsc": nil}, wantRuntime: "runsc"},
		{name: "registered kata without client binary", mode: "kata", runtimes: map[string]json.RawMessage{"kata-runtime": nil}, wantRuntime: "kata-runtime"},
		{name: "default refuses missing runtime", mode: "gvisor", runtimes: map[string]json.RawMessage{"runc": nil}, wantCode: "QP-DOCKER-011"},
		{name: "deny refuses missing runtime", mode: "kata", fallback: "deny", runtimes: map[string]json.RawMessage{"runc": nil}, wantCode: "QP-DOCKER-011"},
		{name: "explicit non hifi fallback", mode: "gvisor", fallback: "docker", runtimes: map[string]json.RawMessage{"runc": nil}, wantFallback: true},
		{name: "hifi cannot weaken requested runtime", mode: "gvisor", fallback: "docker", high: true, runtimes: map[string]json.RawMessage{"runc": nil}, wantCode: "QP-DOCKER-011"},
		{name: "registered strong runtime preferred", mode: "gvisor", fallback: "docker", runtimes: map[string]json.RawMessage{"runsc": nil, "runc": nil}, wantRuntime: "runsc"},
		{name: "unreachable daemon cannot authorize fallback", mode: "gvisor", fallback: "docker", probeErr: sentinel, wantCode: "QP-DOCKER-011"},
		{name: "null registry cannot authorize fallback", mode: "gvisor", fallback: "docker", wantCode: "QP-DOCKER-011"},
		{name: "empty registry cannot authorize fallback", mode: "gvisor", fallback: "docker", runtimes: map[string]json.RawMessage{}, wantCode: "QP-DOCKER-011"},
		{name: "explicit Docker requires no runtime probe", mode: "none", high: true, probeErr: sentinel},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			runtimeRegistryForTest(t, func(ctx context.Context) (map[string]json.RawMessage, error) {
				calls++
				if ctx != t.Context() {
					t.Fatal("operation context was not propagated")
				}
				return tc.runtimes, tc.probeErr
			})
			sb := sandboxForTest(t, tc.mode, tc.fallback)
			selection, err := sb.ResolveForStart(t.Context(), tc.high)
			if tc.wantCode != "" {
				requireSandboxCode(t, err, tc.wantCode)
				if tc.probeErr != nil && !errors.Is(err, tc.probeErr) {
					t.Fatal("daemon failure cause was lost")
				}
				return
			}
			if err != nil || selection.Runtime != tc.wantRuntime || selection.Fallback != tc.wantFallback {
				t.Fatalf("resolved %+v, %v", selection, err)
			}
			if err := sb.ValidateSelection(selection, tc.high); err != nil {
				t.Fatalf("fresh resolution did not satisfy its own policy: %v", err)
			}
			if tc.mode == "none" && calls != 0 {
				t.Fatal("explicit Docker deployment depended on a stronger-runtime probe")
			}
		})
	}
}

// TestUnregisteredRuntimeErrorExplainsTheChoices: on Docker Desktop (runc
// only) the default policy refused to start with nothing but the catalog
// title, so a Windows user never learned what to change.
func TestUnregisteredRuntimeErrorExplainsTheChoices(t *testing.T) {
	desktop := map[string]json.RawMessage{"runc": nil, "io.containerd.runc.v2": nil}
	tests := []struct {
		mode, fallback string
		high           bool
		runtimes       map[string]json.RawMessage
		why, fix       []string
		notFix         []string
	}{
		{mode: "gvisor", runtimes: desktop,
			why:    []string{`no "runsc" runtime`, `"io.containerd.runc.v2", "runc"`},
			fix:    []string{"runsc install", "Docker Desktop", "sandbox_mode: none", "sandbox_fallback: docker runs them"},
			notFix: []string{"kata-runtime"}},
		{mode: "kata", fallback: "deny", runtimes: desktop,
			why: []string{`no "kata-runtime" runtime`},
			fix: []string{"kata-runtime", "KVM", "sandbox_mode: none"}, notFix: []string{"runsc install"}},
		{mode: "gvisor", fallback: "docker", high: true, runtimes: desktop,
			fix: []string{"sandbox_fallback: docker is set, but it applies only when every enabled honeypot"}},
		{mode: "gvisor", runtimes: map[string]json.RawMessage{"a\x1b[2Jb": nil, "r1": nil, "r2": nil, "r3": nil, "r4": nil, "r5": nil, "r6": nil},
			why: []string{`"a\x1b[2Jb"`, "1 more"}},
	}
	for _, tc := range tests {
		runtimeRegistryForTest(t, func(context.Context) (map[string]json.RawMessage, error) { return tc.runtimes, nil })
		_, err := sandboxForTest(t, tc.mode, tc.fallback).ResolveForStart(t.Context(), tc.high)
		requireSandboxCode(t, err, "QP-DOCKER-011")
		var coded *hostsetup.Error
		errors.As(err, &coded)
		for _, s := range tc.why {
			if !strings.Contains(coded.Cause(), s) {
				t.Errorf("%s/%s: why %q lacks %q", tc.mode, tc.fallback, coded.Cause(), s)
			}
		}
		if strings.ContainsRune(coded.Cause(), 0x1b) {
			t.Errorf("a runtime name put a raw escape byte in the message: %q", coded.Cause())
		}
		for _, s := range tc.fix {
			if !strings.Contains(coded.Remedy(), s) {
				t.Errorf("%s/%s: fix %q lacks %q", tc.mode, tc.fallback, coded.Remedy(), s)
			}
		}
		for _, s := range tc.notFix {
			if strings.Contains(coded.Remedy(), s) {
				t.Errorf("%s/%s: fix %q names %q", tc.mode, tc.fallback, coded.Remedy(), s)
			}
		}
	}
}

func TestResolveRuntimeRechecksAvailabilityWithoutStickyDowngrade(t *testing.T) {
	registered := true
	calls := 0
	runtimeRegistryForTest(t, func(context.Context) (map[string]json.RawMessage, error) {
		calls++
		if registered {
			return map[string]json.RawMessage{"runsc": nil}, nil
		}
		return map[string]json.RawMessage{"runc": nil}, nil
	})
	for _, fallback := range []string{"deny", "docker"} {
		registered = true
		sb := sandboxForTest(t, "gvisor", fallback)
		first, err := sb.ResolveForStart(t.Context(), false)
		if err != nil || first.Runtime != "runsc" {
			t.Fatalf("available runtime failed: %+v %v", first, err)
		}
		registered = false
		second, err := sb.ResolveForStart(t.Context(), false)
		if fallback == "deny" {
			requireSandboxCode(t, err, "QP-DOCKER-011")
		} else if err != nil || !second.Fallback {
			t.Fatalf("explicit fallback failed: %+v %v", second, err)
		}
		registered = true
		third, err := sb.ResolveForStart(t.Context(), false)
		if err != nil || third.Runtime != "runsc" || third.Fallback {
			t.Fatalf("fallback was cached: %+v %v", third, err)
		}
		if sb.ContainerRuntime() != "runsc" {
			t.Fatal("availability probing mutated declared policy")
		}
	}
	if calls != 6 {
		t.Fatalf("resolved six operations with %d live probes", calls)
	}
}

func TestResolveRuntimeCancellationDoesNotFallback(t *testing.T) {
	runtimeRegistryForTest(t, func(context.Context) (map[string]json.RawMessage, error) {
		t.Fatal("cancelled operation reached daemon")
		return nil, nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, mode := range []string{"gvisor", "none"} {
		_, err := sandboxForTest(t, mode, "docker").ResolveForStart(ctx, false)
		requireSandboxCode(t, err, "QP-DOCKER-011")
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation cause was lost")
		}
	}
	//lint:ignore SA1012 Deliberately test rejection of an invalid nil caller context.
	_, err := sandboxForTest(t, "gvisor", "docker").ResolveForStart(nil, false)
	requireSandboxCode(t, err, "QP-DOCKER-011")
}

func TestSandboxSnapshotDoesNotChangeAfterConstruction(t *testing.T) {
	cfg := &config.SecurityConfig{SandboxMode: "gvisor", SandboxFallback: "deny"}
	sb, err := NewSandbox(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.SandboxMode = "none"
	cfg.SandboxFallback = "docker"
	selection, err := sb.Selection()
	if err != nil || selection.Runtime != "runsc" || sb.fallbackPolicy() != "deny" {
		t.Fatalf("mutable policy escaped into snapshot: %+v %v", selection, err)
	}
}

func TestValidateSelectionRejectsPolicyBypasses(t *testing.T) {
	good := RuntimeSelection{Requested: SandboxGVisor, Effective: SandboxGVisor, Runtime: "runsc"}
	fallback := RuntimeSelection{Requested: SandboxGVisor, Effective: SandboxNone, Fallback: true}
	for _, tc := range []struct {
		name, policy string
		selection    RuntimeSelection
		high, want   bool
	}{
		{"declared", "deny", good, true, true},
		{"explicit fallback", "docker", fallback, false, true},
		{"denied fallback", "deny", fallback, false, false},
		{"hifi fallback", "docker", fallback, true, false},
		{"unmarked fallback", "docker", RuntimeSelection{Requested: SandboxGVisor, Effective: SandboxNone}, false, false},
		{"wrong requested", "docker", RuntimeSelection{Requested: SandboxKata, Effective: SandboxNone, Fallback: true}, false, false},
		{"wrong runtime", "docker", RuntimeSelection{Requested: SandboxGVisor, Effective: SandboxGVisor, Runtime: "runc"}, false, false},
		{"contradictory fallback", "docker", RuntimeSelection{Requested: SandboxGVisor, Effective: SandboxGVisor, Runtime: "runsc", Fallback: true}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := sandboxForTest(t, "gvisor", tc.policy).ValidateSelection(tc.selection, tc.high)
			if tc.want {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				requireSandboxCode(t, err, "QP-DOCKER-012")
			}
		})
	}
}

func FuzzSandboxPolicySelection(f *testing.F) {
	for _, seed := range []struct {
		mode, policy, effective, rt string
		fallback, high              bool
	}{
		{"gvisor", "deny", "gvisor", "runsc", false, true}, {"gvisor", "docker", "none", "", true, false}, {"gvisor", "docker", "none", "", true, true}, {"none", "deny", "none", "", false, true}, {"firejail", "docker", "none", "", true, false}, {"kata", "deny", "kata", "kata-runtime", false, false}, {"", "", "gvisor", "runsc", false, false},
	} {
		f.Add(seed.mode, seed.policy, seed.effective, seed.rt, seed.fallback, seed.high)
	}
	f.Fuzz(func(t *testing.T, mode, policy, effective, rt string, fallback, high bool) {
		if len(mode)+len(policy)+len(effective)+len(rt) > 16384 {
			t.Skip("bounded policy input")
		}
		sb, err := NewSandbox(&config.SecurityConfig{SandboxMode: mode, SandboxFallback: policy})
		if err != nil {
			t.Fatal(err)
		}
		declared, err := sb.Selection()
		wantMode := mode
		if wantMode == "" {
			wantMode = "gvisor"
		}
		wantPolicy := policy
		if wantPolicy == "" {
			wantPolicy = "deny"
		}
		knownMode := wantMode == "none" || wantMode == "gvisor" || wantMode == "kata"
		knownPolicy := wantPolicy == "deny" || wantPolicy == "docker"
		if !knownMode || !knownPolicy {
			if err == nil {
				t.Fatal("unknown policy was accepted")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		wantRuntime := ""
		switch wantMode {
		case "gvisor":
			wantRuntime = "runsc"
		case "kata":
			wantRuntime = "kata-runtime"
		}
		if declared.Requested != SandboxType(wantMode) || declared.Effective != SandboxType(wantMode) || declared.Runtime != wantRuntime || declared.Fallback {
			t.Fatal("declared mode was weakened")
		}
		candidate := RuntimeSelection{Requested: declared.Requested, Effective: SandboxType(effective), Runtime: rt, Fallback: fallback}
		allowed := effective == wantMode && rt == wantRuntime && !fallback
		allowed = allowed || !high && wantPolicy == "docker" && wantMode != "none" && effective == "none" && rt == "" && fallback
		if accepted := sb.ValidateSelection(candidate, high) == nil; accepted != allowed {
			t.Fatalf("policy boundary mismatch accepted=%v want=%v", accepted, allowed)
		}
	})
}
