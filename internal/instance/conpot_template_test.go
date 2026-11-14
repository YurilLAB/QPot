package instance

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
)

// conpotConfig returns a config with conpot enabled and, when template is not
// empty, pinned to it.
func conpotConfig(qpotID, template string) *config.Config {
	cfg := config.Default("conpot-template-test")
	cfg.QPotID = qpotID
	hp := cfg.Honeypots["conpot"]
	hp.Enabled = true
	if template != "" {
		hp.CustomConfig = map[string]string{"template": template}
	}
	cfg.Honeypots["conpot"] = hp
	return cfg
}

var publishedPortRe = regexp.MustCompile(`^- "\d+:(\d+)(/udp)?"$`)

// publishedPorts renders the compose and returns a honeypot's service block
// and the container ports it publishes.
func publishedPorts(t *testing.T, cfg *config.Config, name string) (svc string, tcp, udp []int) {
	t.Helper()
	sb, err := security.NewSandbox(&cfg.Security)
	if err != nil {
		t.Skip("no sandbox:", err)
	}
	out, err := (&ComposeGenerator{Config: cfg, Sandbox: sb}).Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	svc = composeService(t, out, name)
	for _, ln := range strings.Split(svc, "\n") {
		m := publishedPortRe.FindStringSubmatch(strings.TrimSpace(ln))
		if m == nil {
			continue
		}
		p, _ := strconv.Atoi(m[1])
		if m[2] == "" {
			tcp = append(tcp, p)
		} else {
			udp = append(udp, p)
		}
	}
	slices.Sort(tcp)
	slices.Sort(udp)
	return svc, tcp, udp
}

// TestConpotTemplateSelection guards the device choice: a deployed T-Pot
// template, stable for an instance, different across instances, pinnable, and
// never the static "default" template (identical on every install).
func TestConpotTemplateSelection(t *testing.T) {
	seen := map[string]bool{}
	for i := range 300 {
		cfg := conpotConfig(fmt.Sprintf("qp_conpotseed%06d", i), "")
		got := conpotTemplate(cfg).ID
		if got != conpotTemplate(cfg).ID {
			t.Fatal("conpot template is not stable for one instance")
		}
		seen[got] = true
	}
	if len(seen) != len(tpotConpotTemplates) {
		t.Errorf("300 instances drew %d of %d templates: %v", len(seen), len(tpotConpotTemplates), seen)
	}
	for _, bad := range []string{"default", "proxy"} {
		if containsString(ConpotTemplateIDs(), bad) {
			t.Errorf("template %q must not be offered", bad)
		}
		if CheckSetting("conpot", "template", bad) == nil {
			t.Errorf("CheckSetting accepts template %q", bad)
		}
		cfg := conpotConfig("qp_conpotpin0000000001", bad)
		if got, want := conpotTemplate(cfg).ID, conpotTemplate(conpotConfig("qp_conpotpin0000000001", "")).ID; got != want {
			t.Errorf("unknown pin %q gave %q, want the seed pick %q", bad, got, want)
		}
	}
	for _, id := range ConpotTemplateIDs() {
		if err := CheckSetting("conpot", "template", id); err != nil {
			t.Errorf("CheckSetting rejects %q: %v", id, err)
		}
		if got := conpotTemplate(conpotConfig("qp_conpotpin0000000001", " "+id+" ")).ID; got != id {
			t.Errorf("pin %q gave %q", id, got)
		}
	}
	if !slices.Contains(SettingKeys("conpot"), "template") {
		t.Error("`qpot honeypot set conpot template=` is not accepted")
	}
}

// TestConpotPublishesOnlyTemplatePorts renders every template and checks the
// compose publishes exactly the ports that template listens on (measured by
// running the image), runs that template, and health-checks one of its ports.
// The old profile published twelve ports of several templates while running
// one, so most of them accepted a connection and dropped it.
func TestConpotPublishesOnlyTemplatePorts(t *testing.T) {
	for _, tpl := range tpotConpotTemplates {
		t.Run(tpl.ID, func(t *testing.T) {
			cfg := conpotConfig("qp_conpotports00000001", tpl.ID)
			svc, tcp, udp := publishedPorts(t, cfg, "conpot")
			if !slices.Equal(tcp, tpl.TCP) || !slices.Equal(udp, tpl.UDP) {
				t.Errorf("published tcp %v udp %v, template listens on tcp %v udp %v", tcp, udp, tpl.TCP, tpl.UDP)
			}
			if n := strings.Count(svc, "- CONPOT_TEMPLATE="+tpl.ID+"\n"); n != 1 {
				t.Errorf("CONPOT_TEMPLATE=%s rendered %d times", tpl.ID, n)
			}
			probe, table := tpl.TCP, "/proc/net/tcp"
			if len(probe) == 0 {
				probe, table = tpl.UDP, "/proc/net/udp"
			}
			hc := ""
			for _, ln := range strings.Split(svc, "\n") {
				if strings.Contains(ln, "grep -qE") {
					hc = ln
				}
			}
			for _, p := range probe {
				if !strings.Contains(hc, fmt.Sprintf("%04X", p)) || !strings.Contains(hc, table) {
					t.Errorf("healthcheck %q does not probe %s port %d", hc, table, p)
				}
			}
			if !strings.Contains(svc, "/honeypots/conpot/state:/var/lib/conpot\n") {
				t.Error("identity volume not mounted")
			}
			d := deployProfile(cfg, "conpot")
			if d.NeedsNetBind() != slices.ContainsFunc(append(slices.Clone(tpl.TCP), tpl.UDP...), func(p int) bool { return p < 1024 }) {
				t.Errorf("NeedsNetBind = %v for ports %v %v", d.NeedsNetBind(), tpl.TCP, tpl.UDP)
			}
		})
	}
	// The profile is a copy: changing it must not change the shared table.
	d := deployProfile(conpotConfig("qp_conpotports00000001", "IEC104"), "conpot")
	d.Ports[0] = 1
	d.Env["CONPOT_TEMPLATE"] = "x"
	if tpotConpotTemplates[0].TCP[0] != 2404 || deployProfileFor("conpot").Env["CONPOT_TEMPLATE"] != "" {
		t.Fatal("deployProfile shares memory with the template table or the static profile")
	}
}

// FuzzConpotTemplateSetting drives custom_config "template" (validated by
// `qpot honeypot set`, not by a hand-edited config) and the instance ID through
// the compose generator: the conpot service must run exactly one deployed
// template and publish exactly its ports, and CheckSetting must agree with
// what the generator accepts.
func FuzzConpotTemplateSetting(f *testing.F) {
	f.Add("IEC104", "qp_a")
	f.Add("default", "qp_b")
	f.Add("ipmi\nCONPOT_TEMPLATE=default", "")
	f.Add(" plc_modbus ", "qp_{{.X}}")
	f.Add("../default", "qp_\x00")
	f.Add(strings.Repeat("A", 4096), "qp_c")

	f.Fuzz(func(t *testing.T, template, qpotID string) {
		cfg := conpotConfig(qpotID, template)
		svc, tcp, udp := publishedPorts(t, cfg, "conpot")
		var ids []string
		for _, ln := range strings.Split(svc, "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(ln), "- CONPOT_TEMPLATE="); ok {
				ids = append(ids, v)
			}
		}
		if len(ids) != 1 || !containsString(ConpotTemplateIDs(), ids[0]) {
			t.Fatalf("CONPOT_TEMPLATE lines %q: want one deployed template (config %q)", ids, template)
		}
		want := conpotTemplate(cfg)
		if ids[0] != want.ID || !slices.Equal(tcp, want.TCP) || !slices.Equal(udp, want.UDP) {
			t.Fatalf("runs %s on tcp %v udp %v, want %s on %v %v", ids[0], tcp, udp, want.ID, want.TCP, want.UDP)
		}
		pinned := containsString(ConpotTemplateIDs(), strings.TrimSpace(template))
		if pinned && ids[0] != strings.TrimSpace(template) {
			t.Fatalf("pin %q ignored, runs %s", template, ids[0])
		}
		if CheckSetting("conpot", "template", template) == nil && template != "" && ids[0] != template {
			t.Fatalf("CheckSetting accepts %q but conpot runs %s", template, ids[0])
		}
	})
}

func TestConpotSettingsProfilePreviewAndPinRemoval(t *testing.T) {
	cfg := conpotConfig("qp_savedautoprofile", "")
	cfg.DataPath = t.TempDir()
	cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
	cfg.DisableHoneypot("conpot") // Settings changes should not need Docker.
	auto := conpotTemplate(cfg).ID
	pin := "plc_modbus"
	if auto == pin {
		pin = "IEC104"
	}
	if _, err := ApplySettings(t.Context(), cfg, "conpot", []SettingChange{{Key: "template", Value: pin}}, nil); err != nil {
		t.Fatal(err)
	}
	infos := DescribeSettings(cfg, "conpot")
	if len(infos) != 1 || infos[0].Default != auto || infos[0].Value != pin || len(infos[0].Options) != len(ConpotTemplateIDs()) {
		t.Fatalf("missing rich profile preview: %+v", infos)
	}
	if got := ConpotProfile(cfg).ID; got != pin {
		t.Fatalf("explicit pin not effective: %s", got)
	}
	for i, option := range infos[0].Options {
		if infos[0].Allowed[i] != option.ID {
			t.Fatal("rich choices disagree with accepted IDs")
		}
	}
	// Each choice comes with what this instance's device would say of
	// itself: the same names the support archive is written from, and none
	// for a device that reports none.
	rtu := conpotSiteFor("IEC104", conpotSiteSeed(cfg))
	if got := infos[0].Sites["IEC104"]; len(got) != 4 || got[0] != (SiteFact{"Device name", rtu.Name}) || got[1] != (SiteFact{"Site", rtu.Facility}) ||
		got[2] != (SiteFact{"Location", rtu.Location}) || got[3] != (SiteFact{"Site contact", rtu.Contact}) {
		t.Fatalf("what the RTU says of itself: %+v, want %+v", got, rtu)
	}
	if got := infos[0].Sites["guardian_ast"]; len(got) < 5 || got[0].Label != "Device name" || !strings.HasPrefix(got[2].Label, "Tank 1") {
		t.Fatalf("what the gauge says of itself: %+v", got)
	}
	for _, quiet := range []string{"plc_modbus", "beckhoff_cx", "hart_gateway"} {
		if got, listed := infos[0].Sites[quiet]; listed {
			t.Fatalf("%s reports no names, the preview gives it %+v", quiet, got)
		}
	}
	if len(ConpotSiteFacts(cfg, "no-such-device")) != 0 {
		t.Fatal("an unknown device was given a site")
	}
	infos[0].Options[0].Protocols[0] = "changed"
	if DescribeSettings(cfg, "conpot")[0].Options[0].Protocols[0] == "changed" {
		t.Fatal("metadata shares the catalog")
	}
	if _, err := ApplySettings(t.Context(), cfg, "conpot", []SettingChange{{Key: "template", Value: ""}}, nil); err != nil {
		t.Fatal(err)
	}
	if got := ConpotProfile(cfg).ID; got != auto {
		t.Fatalf("clearing pin changed the saved automatic device from %s to %s", auto, got)
	}
	if got := DescribeSettings(cfg, "conpot")[0]; got.Set || got.Default != auto || got.Effective != auto {
		t.Fatalf("automatic settings: %+v", got)
	}
}

func TestConpotSavedProfileSurvivesCatalogReordering(t *testing.T) {
	cfg := conpotConfig("qp_savedcatalogorder", "")
	cfg.DataPath = t.TempDir()
	cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
	want := ConpotProfile(cfg).ID
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	original := tpotConpotTemplates
	t.Cleanup(func() { tpotConpotTemplates = original })
	tpotConpotTemplates = slices.Clone(original)
	slices.Reverse(tpotConpotTemplates)
	tpotConpotTemplates = append(tpotConpotTemplates, tpotConpotTemplate{ID: "future-controller"})
	if got := ConpotProfile(cfg).ID; got != want {
		t.Fatalf("catalog update changed device from %s to %s", want, got)
	}
	// An unsaved legacy configuration must keep its old choice as well.
	legacy := conpotConfig("qp_savedcatalogorder", "")
	if got := ConpotProfile(legacy).ID; got != want {
		t.Fatalf("legacy migration changed device from %s to %s", want, got)
	}
}

// Run the launcher normalization with Docker's duplicate-case proxy defaults.
// The image uses ConfigParser(os.environ), so duplicate keys would prevent startup.
func TestConpotProxyEnvironment(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("POSIX shell not available")
	}
	for _, both := range []bool{true, false} {
		cmd := exec.Command("sh", "-c", conpotProxySetup+"env")
		for _, entry := range os.Environ() {
			key, _, _ := strings.Cut(entry, "=")
			if strings.HasSuffix(strings.ToLower(key), "proxy") {
				continue
			}
			cmd.Env = append(cmd.Env, entry)
		}
		for _, key := range []string{"http_proxy", "https_proxy", "ftp_proxy", "no_proxy", "all_proxy"} {
			cmd.Env = append(cmd.Env, key+"=lower-value")
			if both {
				cmd.Env = append(cmd.Env, strings.ToUpper(key)+"=upper-value")
			}
		}
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"http_proxy", "https_proxy", "ftp_proxy", "no_proxy", "all_proxy"} {
			lower := strings.Contains(string(out), key+"=lower-value")
			upper := strings.Contains(string(out), strings.ToUpper(key)+"=upper-value")
			if both && (lower || !upper) || !both && (!lower || upper) {
				t.Fatalf("proxy normalization both=%v key=%s: lowerPresent=%v upperPresent=%v", both, key, lower, upper)
			}
		}
	}
	cfg := conpotConfig("qp_proxylaunch", "plc_modbus")
	svc, _, _ := publishedPorts(t, cfg, "conpot")
	if !strings.Contains(svc, conpotSitePath) || !strings.Contains(svc, "unset") {
		t.Fatal("Conpot image launcher does not normalize duplicate proxy settings")
	}
}
