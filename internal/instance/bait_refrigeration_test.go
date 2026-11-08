package instance

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/refrigeration"
)

func TestRefrigerationCanaryIndependentOfCowrieAndHistorical(t *testing.T) {
	cfg := config.Default("refrigeration-canary")
	cfg.QPotID = "qp_refrigerationmaintenanceone"
	enableOnly(cfg, "refrigeration")
	first := PlantedCanaries(cfg)
	if len(first) != 1 || first[0].Kind != canary.KindCredential || !first[0].Planted {
		t.Fatalf("controller export is unwatched with Cowrie off: %+v", first)
	}
	_, password := refrigeration.MaintenanceCredential(refrigerationDeviceSeed(cfg))
	if first[0].Values[0] != password || refrigerationDeviceSeed(cfg) == deceptionSeed(cfg) || strings.Contains(refrigerationDeviceSeed(cfg), cfg.QPotID) {
		t.Fatal("runtime credential and watch disagree, or runtime receives base identity")
	}
	store, err := canary.NewStore(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SyncPlanted(first); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"GET /exports/maintenance.zip", "cat /root/.netrc"} {
		if _, hit, err := store.Match(input, "203.0.113.70", "refrigeration"); hit || err != nil {
			t.Fatalf("file read/export alone tripped canary: %q %v", input, err)
		}
	}
	if _, hit, err := store.Match("login password="+password, "203.0.113.71", "refrigeration"); !hit || err != nil {
		t.Fatalf("captured credential reuse did not trip: %v", err)
	}
	enableOnly(cfg, "heralding")
	if err := store.SyncPlanted(PlantedCanaries(cfg)); err != nil {
		t.Fatal(err)
	}
	old, ok := store.Get(first[0].ID)
	if !ok || !old.Historical || old.Trips != 1 {
		t.Fatalf("turning controller off lost copied credential watch: %+v", old)
	}
}

func TestRefrigerationSupportArchiveSharesOneStableCanary(t *testing.T) {
	cfg := baitCfg("qp_refrigerationsupportarchive", "debian-bookworm")
	hp := cfg.Honeypots["cowrie"]
	hp.CustomConfig[baitProfileSetting] = "industrial"
	hp.CustomConfig[baitTargetSetting] = "refrigeration"
	cfg.Honeypots["cowrie"] = hp
	rhp := cfg.Honeypots["refrigeration"]
	rhp.Enabled = true
	cfg.Honeypots["refrigeration"] = rhp
	plan, planted := cowrieBait(cfg)
	if len(planted) != 1 || len(PlantedCanaries(cfg)) != 1 {
		t.Fatal("support copy and controller export registered duplicate watches")
	}
	user, password := refrigeration.MaintenanceCredential(refrigerationDeviceSeed(cfg))
	netrc := baitFileAt(t, plan, "/root/.netrc")
	if netrc.Mode != 0o600 || !strings.Contains(netrc.Text, "login "+user+"\n") || !strings.Contains(netrc.Text, "password "+password+"\n") {
		t.Fatal("support .netrc is unprotected or differs from exported archive account")
	}
	before := cowrieBaitJSON(cfg)
	if !bytes.Equal(before, cowrieBaitJSON(cfg)) {
		t.Fatal("support archive changed across regeneration")
	}
	for _, siteProfile := range []string{"retail", "plasma"} {
		rhp := cfg.Honeypots["refrigeration"]
		rhp.CustomConfig = map[string]string{"site_profile": siteProfile}
		cfg.Honeypots["refrigeration"] = rhp
		plan, _ := cowrieBait(cfg)
		var inventory struct {
			Controller refrigeration.Identity `json:"controller"`
		}
		if err := json.Unmarshal([]byte(baitFileAt(t, plan, industrialRoot+"/inventory.json").Text), &inventory); err != nil {
			t.Fatal(err)
		}
		want, err := refrigeration.IdentityForSeed(refrigerationDeviceSeed(cfg), siteProfile)
		if err != nil || inventory.Controller != want {
			t.Fatalf("%s support archive identifies a different controller/site: %+v / %+v (%v)", siteProfile, inventory.Controller, want, err)
		}
		if siteProfile == "plasma" && bytes.Equal(before, cowrieBaitJSON(cfg)) {
			t.Fatal("changing site did not refresh support inventory")
		}
	}
	for _, f := range plan.Files {
		if strings.Contains(f.Text, cfg.QPotID) || strings.Contains(f.Text, refrigerationDeviceSeed(cfg)) || strings.Contains(f.Text, "synthetic") {
			t.Fatalf("support file leaks management identity or deception mechanism: %s", f.Path)
		}
	}
	cfg.Honeypots["cowrie"].CustomConfig[baitTargetSetting] = "conpot"
	if bytes.Equal(before, cowrieBaitJSON(cfg)) {
		t.Fatal("changing referenced asset did not rebuild support archive")
	}
	for _, value := range []string{"", "conpot", "refrigeration"} {
		if err := CheckSetting("cowrie", baitTargetSetting, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := CheckSetting("cowrie", baitTargetSetting, "arbitrary-host"); err == nil {
		t.Fatal("arbitrary bait target accepted")
	}
}

func TestRefrigerationSupportHostsResolveWithinBait(t *testing.T) {
	cfg := baitCfg("qp_refrigerationhostreference", "debian-bookworm")
	cfg.Honeypots["cowrie"].CustomConfig[baitProfileSetting] = "industrial"
	cfg.Honeypots["cowrie"].CustomConfig[baitTargetSetting] = "refrigeration"
	plan, _ := cowrieBait(cfg)
	py := python(t)
	if len(plan.Hosts) != 2 || plan.Hosts[0].IP == plan.Hosts[1].IP {
		t.Fatalf("archive and controller need separate reference addresses: %+v", plan.Hosts)
	}
	const installed, booted = int64(1700000000), int64(1760000000)
	for _, host := range plan.Hosts {
		for _, name := range host.Names {
			out := runBait(t, py, cowrieBaitJSON(cfg), installed, booted, name)
			if out.Host == nil || *out.Host != host.IP {
				t.Errorf("rendered Cowrie host %q does not resolve to its reference address %s", name, host.IP)
			}
		}
	}
}
