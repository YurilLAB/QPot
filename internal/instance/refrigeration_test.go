package instance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/refrigeration"
	"gopkg.in/yaml.v3"
)

func TestRefrigerationYAMLProfileMatchesSettingsRuntimeIdentityAndCache(t *testing.T) {
	for _, tc := range []struct {
		name, value, want string
	}{
		{"quoted plasma", " plasma ", "plasma"},
		{"whitespace default", " \t ", "retail"},
		{"quoted retail", " retail ", "retail"},
		{"invalid", " unknown ", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := fmt.Sprintf(`instance_name: refrigeration-normalized
qpot_id: qp_refrigerationnormalization
security:
  sandbox_mode: none
honeypots:
  cowrie:
    enabled: true
    custom_config:
      persona: debian-bookworm
      bait: "on"
      bait_profile: industrial
      bait_target: refrigeration
  refrigeration:
    enabled: true
    custom_config:
      site_profile: %q
`, tc.value)
			cfg, err := config.Parse([]byte(data), filepath.Join(t.TempDir(), "config.yaml"))
			if tc.want == "" {
				if err == nil || !strings.Contains(err.Error(), "site_profile") {
					t.Fatalf("invalid YAML profile accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			settings := DescribeSettings(cfg, "refrigeration")
			if len(settings) != 1 {
				t.Fatalf("missing profile setting: %+v", settings)
			}
			setting := settings[0]
			if setting.Value != strings.TrimSpace(tc.value) || setting.Set != (strings.TrimSpace(tc.value) != "") {
				t.Fatalf("settings selector received an unselectable value: %+v", setting)
			}
			effective := setting.Value
			if setting.Effective != "" {
				effective = setting.Effective
			}
			if effective != tc.want || deployProfile(cfg, "refrigeration").Env["SITE_PROFILE"] != tc.want {
				t.Fatalf("display/runtime profile disagree: %+v / %+v", setting, deployProfile(cfg, "refrigeration").Env)
			}
			mgr, err := NewManager(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := (&ComposeGenerator{Config: cfg, Sandbox: mgr.sandbox}).Generate(); err != nil {
				t.Fatalf("valid normalized YAML cannot deploy: %v", err)
			}
			wantIdentity, err := refrigeration.IdentityForSeed(refrigerationDeviceSeed(cfg), tc.want)
			if err != nil {
				t.Fatal(err)
			}
			plan, _ := cowrieBait(cfg)
			var inventory struct {
				Controller refrigeration.Identity `json:"controller"`
			}
			if err := json.Unmarshal([]byte(baitFileAt(t, plan, industrialRoot+"/inventory.json").Text), &inventory); err != nil {
				t.Fatal(err)
			}
			if inventory.Controller != wantIdentity {
				t.Fatalf("support archive identity disagrees with runtime: %+v / %+v", inventory.Controller, wantIdentity)
			}
			canonical, err := cfg.Clone()
			if err != nil {
				t.Fatal(err)
			}
			canonical.SetHoneypotCustomConfig("refrigeration", map[string]string{"site_profile": tc.want})
			if baitCacheKey(cfg) != baitCacheKey(canonical) || !bytes.Equal(cowrieBaitJSON(cfg), cowrieBaitJSON(canonical)) {
				t.Fatal("equivalent YAML profiles produce different support cache or artifacts")
			}
			if hp, _ := cfg.GetHoneypotConfig("refrigeration"); hp.CustomConfig["site_profile"] != tc.value {
				t.Fatal("reading profile metadata changed the operator's config")
			}
		})
	}
}

func TestRefrigerationComposeUsesLocalSourcesAndIsolatedRuntime(t *testing.T) {
	cfg := settingsTestConfig(t, "refrigeration-compose")
	cfg.Security.SandboxMode = "none"
	enableOnly(cfg, "refrigeration")
	cfg.SetHoneypotCustomConfig("refrigeration", map[string]string{"site_profile": "plasma"})
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	out, err := (&ComposeGenerator{Config: cfg, Sandbox: m.sandbox}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]map[string]any `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	svc := doc.Services["refrigeration"]
	if svc["image"] != refrigeration.BuildImage() || svc["pull_policy"] != "build" {
		t.Fatalf("must build bundled image rather than pull an unpublished image: %+v", svc)
	}
	build := svc["build"].(map[string]any)
	if build["context"] != refrigerationBuildPath(cfg) || build["dockerfile"] != "Dockerfile" {
		t.Fatalf("bad build context: %+v", build)
	}
	if svc["read_only"] != true || svc["privileged"] == true || svc["network_mode"] == "host" || svc["cap_add"] != nil {
		t.Fatalf("unsafe native runtime: %+v", svc)
	}
	env := map[string]string{}
	for _, item := range svc["environment"].([]any) {
		key, value, _ := strings.Cut(item.(string), "=")
		env[key] = value
	}
	if env["SITE_PROFILE"] != "plasma" || env["DEVICE_SEED"] != refrigerationDeviceSeed(cfg) || env["DEVICE_SEED"] == cfg.QPotID || env["DEVICE_SEED"] == deceptionSeed(cfg) {
		t.Fatalf("profile/seed not isolated: %+v", env)
	}
	d := deployProfile(cfg, "refrigeration")
	if d.RunAsUID != "65532:65532" || !slices.Equal(d.OwnedSubdirs, []string{"logs", "state"}) || len(HostProbePorts(cfg, "refrigeration")) != 1 {
		t.Fatalf("ownership/host probe contract missing: %+v", d)
	}
	if _, err := ValidateSettings(cfg, "refrigeration", ParseSettingArgs([]string{"site_profile=unknown"})); err == nil {
		t.Fatal("invalid profile accepted")
	}
	settings := DescribeSettings(cfg, "refrigeration")
	if len(settings) != 1 || settings[0].Key != "site_profile" || settings[0].Type != "choice" || !slices.Equal(settings[0].Allowed, []string{"retail", "plasma"}) {
		t.Fatalf("real profiles missing from settings API: %+v", settings)
	}
	cfg.SetHoneypotCustomConfig("refrigeration", nil)
	if got := DescribeSettings(cfg, "refrigeration")[0].Effective; got != "retail" {
		t.Fatalf("cleared setting does not return to retail: %s", got)
	}
}

func TestRefrigerationPublishedPortAvoidsManagementAndSiblingHTTPServices(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default("refrigeration-ports")
	cfg.DataPath = filepath.Join(root, "first")
	cfg.Security.SandboxMode = "none"
	enableOnly(cfg, "refrigeration", "honeyaml", "galah", "go-pot")
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	g := &ComposeGenerator{Config: cfg, Sandbox: m.sandbox}
	ports := g.buildHostPortMap()
	if ports[portKey("refrigeration", 8080)] == 8080 {
		t.Fatal("default decoy mapping reused the management listener")
	}
	// Place management exactly where refrigeration's deterministic hash would
	// put it: allocation must move the decoy while retaining its container8080.
	cfg.WebUI.Port = cfg.AllocatePortFor("refrigeration", 8080)
	ports = g.buildHostPortMap()
	seen := map[int]bool{cfg.WebUI.Port: true}
	for key, port := range ports {
		if seen[port] {
			t.Fatalf("management or HTTP service collision for %q on %d", key, port)
		}
		seen[port] = true
	}
	compose, err := g.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.DataPath, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.DataPath, "docker-compose.yml"), []byte(compose), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.DataPath, "config.yaml"), []byte("web_ui:\n  enabled: true\n  port: "+fmt.Sprint(cfg.WebUI.Port)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sibling := config.Default("refrigeration-second")
	sibling.DataPath = filepath.Join(root, "second")
	enableOnly(sibling, "refrigeration", "honeyaml")
	reserved, _ := siblingReservations(sibling.DataPath)
	if !reserved[cfg.WebUI.Port] {
		t.Fatal("sibling in-process management listener was not reserved")
	}
	other := (&ComposeGenerator{Config: sibling, ReservedPorts: reserved}).buildHostPortMap()
	for key, port := range other {
		if seen[port] {
			t.Fatalf("second instance collides with first instance %q on %d", key, port)
		}
	}
	cfg.Ports.AutoAllocate = false
	cfg.WebUI.Port = 8080
	if _, err := g.Generate(); err == nil || !strings.Contains(err.Error(), "management web port") {
		t.Fatalf("fixed8080 must reject the management conflict: %v", err)
	}
}

func TestRefrigerationEnableRecreateEmitCompleteFreshContext(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stand-in Docker uses a shell script")
	}
	cfg := settingsTestConfig(t, "refrigeration-lifecycle")
	cfg.Security.SandboxMode = "none"
	enableOnly(cfg, "refrigeration")
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	log := argsDocker(t)
	if err := m.StartHoneypot(context.Background(), "refrigeration"); err != nil {
		t.Fatal(err)
	}
	files, err := refrigeration.BuildFiles()
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range files {
		got, err := os.ReadFile(filepath.Join(refrigerationBuildPath(cfg), path))
		if err != nil || string(got) != string(want) {
			t.Fatalf("installed source context differs for %s: %v", path, err)
		}
	}
	stale := filepath.Join(refrigerationBuildPath(cfg), "internal/refrigeration/assets/retired.html")
	if err := os.WriteFile(stale, []byte("retired asset"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.RecreateHoneypot(context.Background(), "refrigeration"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("retired sources survive rebuild and invalidate source hash: %v", err)
	}
	ups := composeUps(t, log)
	if len(ups) != 2 || !strings.HasSuffix(ups[0], " up -d refrigeration") || !strings.HasSuffix(ups[1], " up -d --force-recreate refrigeration") {
		t.Fatalf("start/recreate not applied: %v", ups)
	}
	if err := m.pullImages(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), " pull --ignore-buildable") {
		t.Fatal("startup would pull a nonexistent registry image for native service")
	}
}
