package instance

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// conpotSiteHarness runs site_identity.py with the image's tpot_templates
// module replaced by a stand-in, over profile files that hold the lines the
// image's profiles hold. It prints a JSON object.
const conpotSiteHarness = `
import importlib.util, json, pathlib, sys, types

module, work = sys.argv[1], pathlib.Path(sys.argv[2])
died = []
class Died(Exception): pass
def die(msg):
    died.append(msg)
    raise Died(msg)
tpot = types.ModuleType("tpot_templates")
tpot.IDENTITY_DIR = str(work / "state")
tpot.DEFAULT_SPEC = "unused"
tpot.die = die
tpot.info = lambda msg: None
sys.modules["tpot_templates"] = tpot
spec = importlib.util.spec_from_file_location("site_identity", module)
site = importlib.util.module_from_spec(spec)
spec.loader.exec_module(site)

# The lines the image's rendered profiles hold (copied from the image).
PROFILES = {
    "IEC104": {"template.toml": '[core.databus.key_value_mappings]\nsysContact = "Corporate IT"\nsysName = "DE-BER01"\nsysLocation = "BER01, T2E"\nFacilityName = "BER01 Substation"\nSystemName = "CP 343-1 IT"\n',
        "dnp3.toml": '[dnp3]\nmaster_address = 0\nbinary_inputs = [\n    { index = 0, value = false },\n    { index = 1, value = true },\n]\nanalog_inputs = [\n    { index = 0, value = 25 },\n    { index = 1, value = 100 },\n]\n'},
    "ipmi": {"template.toml": '[core.databus.key_value_mappings]\nSystemName = "DoE"\n'},
    "kamstrup_382": {"template.toml": "[a]\nvalue = \"'pwr_ctrl_mgmt01.int.local'\"\n[b]\nvalue = \"'10.232.15.242'\"\n"},
    "building_automation": {"bacnet.toml": '[bacnet]\nlocation = "Technikzentrale"\n'},
    "iccp": {"iccp.toml": '[iccp]\ndomain = "BER01_ICC"\ndata_points = [\n    { name = "BER01_T1_MW", type = "float", value = 125.5 },\n    { name = "BER01_Q0_CB", type = "boolean", value = true },\n    { name = "BER01_T1_TAP", type = "integer", value = 3 },\n]\n'},
    "plc_modbus": {"modbus.toml": '[modbus]\nvendor = "Schneider Electric  "\n'},
    "guardian_ast": {"template.toml": '[core]\nx = 1\n'},
    "beckhoff_cx": {"ads.toml": '[ads]\ndevice_name = "Plc30 App"\n'},
    "hart_gateway": {"hartip.toml": '[hartip]\nx = 1\n'},
}
SHARED = ["BER01", "Corporate IT", '"DoE"', "pwr_ctrl_mgmt01", "10.232.15.242", "Technikzentrale"]

def render(name, seed):
    out = work / "rendered" / seed / name
    out.mkdir(parents=True, exist_ok=True)
    for filename, text in PROFILES[name].items():
        (out / filename).write_text(text, encoding="utf-8")
    site.apply_site(name, out, seed)
    return {f: (out / f).read_text(encoding="utf-8") for f in PROFILES[name]}

result = {"failures": [], "values": {}}
def check(ok, what):
    if not ok:
        result["failures"].append(what)

seeds = ["%032x" % (i * 7919 + 1) for i in range(40)]
seen = {name: set() for name in PROFILES}
for seed in seeds:
    for name in PROFILES:
        files = render(name, seed)
        text = "".join(files.values())
        for shared in SHARED:
            check(shared not in text, "%s: %r is still there" % (name, shared))
        check(all(32 <= ord(c) < 127 or c == "\n" for c in text), "%s: a value is not plain text" % name)
        check(files == render(name, seed), "%s: the same seed gave other values" % name)
        seen[name].add(text)
for name in ("IEC104", "ipmi", "kamstrup_382", "building_automation", "iccp"):
    check(len(seen[name]) >= 6, "%s: only %d different sites from 40 seeds" % (name, len(seen[name])))
for name in ("plc_modbus", "guardian_ast", "beckhoff_cx", "hart_gateway"):
    check(seen[name] == {"".join(PROFILES[name].values())}, "%s was changed" % name)

# One site hangs together: the RTU's name, location and facility share a station.
import tomllib
rtu = tomllib.loads(render("IEC104", seeds[3])["template.toml"])["core"]["databus"]["key_value_mappings"]
station = rtu["FacilityName"].removesuffix(" Substation")
check(rtu["sysName"].startswith(station + "-RTU") and rtu["sysLocation"].startswith(station + ", "), "the RTU's names disagree: %r" % rtu)
check(rtu["SystemName"] == "CP 343-1 IT", "a value that is the device's own was changed")
# The outstation's points: this site's, not the image's 25 and 100.
points = set()
for seed in seeds:
    dnp3 = tomllib.loads(render("IEC104", seed)["dnp3.toml"])["dnp3"]
    analog = [p["value"] for p in dnp3["analog_inputs"]]
    check([p["index"] for p in dnp3["analog_inputs"] + dnp3["binary_inputs"]] == [0, 1, 0, 1] and dnp3["master_address"] == 0, "the DNP3 points were rearranged: %r" % dnp3)
    check(all(type(p["value"]) is bool for p in dnp3["binary_inputs"]) and 12 <= analog[0] <= 480 and 500 <= analog[1] < 12000, "DNP3 points out of range: %r" % dnp3)
    points.add(tuple(analog))
check(len(points) == len(seeds) and (25, 100) not in points, "DNP3 analog points: %d different in %d sites" % (len(points), len(seeds)))
iccp = tomllib.loads(render("iccp", seeds[3])["iccp.toml"])["iccp"]
check(iccp["domain"].endswith("_ICC") and all(p["name"].startswith(iccp["domain"][:-4] + "_") for p in iccp["data_points"]), "ICCP names disagree: %r" % iccp)
result["values"] = {"rtu": rtu, "iccp_domain": iccp["domain"], "bmc": render("ipmi", seeds[3])["template.toml"], "meter": render("kamstrup_382", seeds[3])["template.toml"]}

# A profile that no longer holds a value the image is known to carry stops the start.
PROFILES["ipmi"] = {"template.toml": '[core.databus.key_value_mappings]\nSystemName = "Other"\n'}
try:
    render("ipmi", seeds[0])
    check(False, "a changed image profile was accepted")
except Died:
    check("the image has changed" in died[-1], "what it said: %r" % died[-1])

# The seed is kept: a second start has the same site; a damaged file is replaced.
state = pathlib.Path(tpot.IDENTITY_DIR)
state.mkdir(parents=True)
first = site.load_seed(str(state))
check(site.load_seed(str(state)) == first and len(first) == 32, "the site's seed was not kept")
(state / site.SITE_FILE).write_text("not json")
check(site.load_seed(str(state)) != first and site.load_seed(str(state)) == site.load_seed(str(state)), "a damaged seed file was not replaced")
print(json.dumps(result))
`

// TestConpotSiteIdentity: values that are the same on every install of the
// image (T-Pot's station "DE-BER01", contact "Corporate IT", BMC name "DoE",
// meter server and plant room) are replaced per instance, consistently
// within one site, stably for one seed, and a changed image stops the start.
func TestConpotSiteIdentity(t *testing.T) {
	py := python(t)
	if exec.Command(py, "-c", "import tomllib").Run() != nil {
		t.Skip("needs Python 3.11+ (tomllib)")
	}
	dir := t.TempDir()
	module := filepath.Join(dir, "site_identity.py")
	harness := filepath.Join(dir, "harness.py")
	if err := os.WriteFile(module, conpotSitePy, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(harness, []byte(conpotSiteHarness), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(py, harness, module, dir).Output()
	if err != nil {
		t.Fatalf("harness: %v\n%s", err, out)
	}
	var res struct {
		Failures []string       `json:"failures"`
		Values   map[string]any `json:"values"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("harness output: %v\n%s", err, out)
	}
	for _, f := range res.Failures {
		t.Error(f)
	}
	t.Logf("one site: %v", res.Values)

	// Every Conpot profile starts through the site step, mounted read-only.
	want := conpotSiteVolume()
	for _, id := range ConpotTemplateIDs() {
		found := false
		for _, mount := range deployProfile(conpotConfig("qp_site_mount", id), "conpot").Volumes {
			if mount.ContainerPath == want.ContainerPath {
				found = mount.File && mount.ReadOnly && len(mount.Content) > 0
			}
		}
		if !found {
			t.Errorf("%s: the site step is not mounted read-only", id)
		}
	}
	if !strings.Contains(conpotStartScript(), "exec python3 "+conpotSitePath+` "$CONPOT_TEMPLATE"`) {
		t.Errorf("Conpot does not start through the site step: %q", conpotStartScript())
	}
	if strings.Contains(string(conpotSitePy), "\r") {
		t.Error("site_identity.py has CR bytes")
	}
}
