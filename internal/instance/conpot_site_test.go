package instance

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
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

# The seed is QPot's: without one, or with one that is not a seed, the
# start stops instead of making up a site for this start only.
import os
for bad in (None, "", "short", "x" * 129, "abcdef0123456789!", "\u00e4" * 20):
    if bad is None:
        os.environ.pop("QPOT_SITE_SEED", None)
    else:
        os.environ["QPOT_SITE_SEED"] = bad
    try:
        site.site_seed()
        check(False, "a missing or malformed seed %r was accepted" % (bad,))
    except Died:
        pass
os.environ["QPOT_SITE_SEED"] = seeds[5]
check(site.site_seed() == seeds[5], "the seed QPot passes was not used")

# What the image draws on a first start comes from the seed: the same on
# every start that kept nothing, another for another seed or template, and
# the image's own secrets module is put back afterwards. resolve_identity is
# the image's (tpot_templates.py): it draws what is not kept, in order.
import os
SPEC = {"identity": {
    "IP": {"gen": "lan_ip"}, "MAC": {"gen": "mac", "oui": "00:1b:1b"}, "SERIAL": {"gen": "digits", "n": 8},
    "HEX": {"gen": "hex", "n": 6, "upper": True}, "BYTES": {"gen": "hexbytes", "n": 3},
    "NUM": {"gen": "int", "min": 1, "max": 254}, "KIND": {"gen": "choice", "values": ["a", "b"]},
    "MAC_TAIL": {"derive": "mac_tail", "of": "MAC"}}}
def image_resolve_identity(tpl, stored):
    s = tpot.secrets
    values = dict(stored)
    for token, gen in tpl["identity"].items():
        if "gen" in gen and token not in values:
            kind = gen["gen"]
            if kind == "lan_ip":
                values[token] = "10.%d.%d.%d" % (s.randbelow(256), s.randbelow(256), 10 + s.randbelow(240))
            elif kind == "mac":
                values[token] = gen["oui"].upper() + "".join(":%02X" % s.randbelow(256) for _ in range(3))
            elif kind == "digits":
                values[token] = str(1 + s.randbelow(9)) + "".join(str(s.randbelow(10)) for _ in range(gen["n"] - 1))
            elif kind == "hex":
                values[token] = "".join(s.choice("0123456789abcdef") for _ in range(gen["n"])).upper()
            elif kind == "hexbytes":
                values[token] = " ".join("%02X" % s.randbelow(256) for _ in range(gen["n"]))
            elif kind == "int":
                values[token] = gen["min"] + s.randbelow(gen["max"] - gen["min"] + 1)
            else:
                values[token] = s.choice(gen["values"])
    values["MAC_TAIL"] = values["MAC"].replace(":", "")[-6:]
    return values, True
tpot.secrets = "the module"
tpot.resolve_identity = image_resolve_identity
first = site.load_identity("IEC104", SPEC, seeds[1])
check(first == site.load_identity("IEC104", SPEC, seeds[1]), "the same seed drew other first-start values")
check(first != site.load_identity("IEC104", SPEC, seeds[2]), "two seeds drew the same first-start values")
check(first != site.load_identity("ipmi", SPEC, seeds[1]), "two templates drew the same first-start values")
check(all(site.plausible(SPEC["identity"][k], v) for k, v in first.items() if "gen" in SPEC["identity"][k]), "drawn values the image would not draw: %r" % first)
check(tpot.secrets == "the module", "the image's secrets module was not put back")

# Values an earlier start kept are used where the image could have drawn
# them; whatever else the container leaves in its state folder is ignored,
# never stops the start and never blocks it.
state = pathlib.Path(tpot.IDENTITY_DIR)
state.mkdir(parents=True, exist_ok=True)
ident = state / "IEC104.json"
kept = {"IP": "192.168.7.23", "MAC": "00:1B:1B:0A:0B:0C", "SERIAL": "12345678", "HEX": "ABCDEF", "BYTES": "01 02 03", "NUM": 9, "KIND": "b"}
ident.write_text(json.dumps({"version": 1, "template": "IEC104", "values": kept}))
got = site.load_identity("IEC104", SPEC, seeds[1])
check(all(got[k] == v for k, v in kept.items()) and got["MAC_TAIL"] == "0A0B0C", "kept plausible values were not used: %r" % got)
bad = {"IP": "8.8.8.8", "MAC": "AA:BB:CC:0A:0B:0C", "SERIAL": "0123", "HEX": "xyz", "BYTES": "1 2", "NUM": 10**9, "KIND": "c"}
ident.write_text(json.dumps({"values": bad}))
check(site.load_identity("IEC104", SPEC, seeds[1]) == first, "implausible kept values were used")
written = (site.read_state_json(ident) or {}).get("values")
check(written == {k: v for k, v in first.items() if k != "MAC_TAIL"}, "the identity was not kept where the image keeps it: %r" % written)
hostile = {
    "garbage": lambda: ident.write_bytes(b"\x00\xff{not json"),
    "a list": lambda: ident.write_text("[1, 2]"),
    "a large file": lambda: ident.write_bytes(b" " * (site.IDENTITY_MAX_BYTES + 10) + b"{}"),
    "a directory": lambda: ident.mkdir(),
    "a link": lambda: ident.symlink_to(work / "elsewhere.json"),
    "a FIFO": lambda: os.mkfifo(ident),
}
(work / "elsewhere.json").write_text(json.dumps({"values": kept}))
for what, plant in hostile.items():
    if ident.is_dir() and not ident.is_symlink():
        ident.rmdir()
    elif ident.exists() or ident.is_symlink():
        ident.unlink()
    try:
        plant()
    except (OSError, AttributeError, NotImplementedError):
        continue  # not on this system (a FIFO on Windows)
    try:
        got = site.load_identity("IEC104", SPEC, seeds[1])
        check(got == first, "%s in the state folder changed the identity: %r" % (what, got))
    except Died:
        check(False, "%s in the state folder stopped the start" % what)
# A leftover seed file of the earlier site step is not read.
if ident.is_dir() and not ident.is_symlink():
    ident.rmdir()
elif ident.exists() or ident.is_symlink():
    ident.unlink()
(state / "qpot_site.json").write_text('{"version": 1, "seed": "0123456789abcdef0123456789abcdef"}')
os.environ["QPOT_SITE_SEED"] = seeds[5]
check(site.site_seed() == seeds[5], "a leftover qpot_site.json was used")
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
	// Conpot gets its site's seed from QPot, on every template.
	for _, id := range ConpotTemplateIDs() {
		cfg := conpotConfig("qp_site_mount", id)
		want := conpotSiteSeed(cfg)
		if got := deployProfile(cfg, "conpot").Env[conpotSiteSeedEnv]; got != want || !siteSeedShape.MatchString(got) {
			t.Errorf("%s: %s = %q, want %q", id, conpotSiteSeedEnv, got, want)
		}
	}
	if strings.Contains(string(conpotSitePy), "\r") {
		t.Error("site_identity.py has CR bytes")
	}
}

// siteSeedShape is what conpotSiteSeed gives and the site step accepts.
var siteSeedShape = regexp.MustCompile(`^[0-9a-f]{32}$`)

// TestConpotSiteSeed: the site's seed is QPot's, the same on every start of an
// instance and another for another instance, and nothing the container leaves
// in its state folder changes it or keeps the compose file from being made.
// (The container writes that folder: a compromised Conpot must not be able to
// change its plant or stop the instance from starting.)
func TestConpotSiteSeed(t *testing.T) {
	newConfig := func(id string) *config.Config {
		cfg := conpotConfig(id, "IEC104")
		cfg.DataPath = t.TempDir()
		return cfg
	}
	one := newConfig("qp_siteseedone")
	a := conpotSiteSeed(one)
	if b := conpotSiteSeed(one); a != b || !siteSeedShape.MatchString(a) {
		t.Fatalf("one instance: %q then %q", a, b)
	}
	// Nothing is kept anywhere: another folder for the same instance (a
	// restored or moved instance) gives the same site.
	if b := conpotSiteSeed(newConfig("qp_siteseedone")); a != b {
		t.Errorf("the same instance in another folder: %q, want %q", b, a)
	}
	if b := conpotSiteSeed(newConfig("qp_siteseedtwo")); a == b {
		t.Errorf("two instances share the site seed %q", a)
	}
	// The seed is not the QPot ID, nor shows it.
	if strings.Contains(a, "siteseedone") {
		t.Errorf("the seed %q shows the QPot ID", a)
	}

	gen := &ComposeGenerator{Config: one}
	clean, err := gen.Generate()
	if err != nil {
		t.Fatalf("compose with an empty state folder: %v", err)
	}
	stateDir := filepath.Join(one.DataPath, "honeypots", "conpot", "state")
	site := filepath.Join(stateDir, "qpot_site.json")
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte(`{"seed": "0123456789abcdef0123456789abcdef"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	hostile := map[string]func() error{
		"a seed of its own": func() error {
			return os.WriteFile(site, []byte(`{"version": 1, "seed": "0123456789abcdef0123456789abcdef"}`), 0o644)
		},
		"garbage":      func() error { return os.WriteFile(site, []byte("\x00\xff not json"), 0o644) },
		"a large file": func() error { return os.WriteFile(site, make([]byte, 1<<20), 0o644) },
		"unreadable":   func() error { return os.WriteFile(site, []byte(`{"seed": "x"}`), 0o000) },
		"a directory":  func() error { return os.Mkdir(site, 0o755) },
		"a link out":   func() error { return os.Symlink(outside, site) },
	}
	for what, plant := range hostile {
		if err := os.RemoveAll(stateDir); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(stateDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := plant(); err != nil {
			t.Logf("%s: cannot be made here: %v", what, err)
			continue
		}
		if got := conpotSiteSeed(one); got != a {
			t.Errorf("%s in the state folder changed the seed to %q", what, got)
		}
		if got := deployProfile(one, "conpot").Env[conpotSiteSeedEnv]; got != a {
			t.Errorf("%s in the state folder: Conpot is given %q", what, got)
		}
		out, err := gen.Generate()
		if err != nil {
			t.Errorf("%s in the state folder stops the compose: %v", what, err)
		} else if out != clean {
			t.Errorf("%s in the state folder changed the compose", what)
		}
	}
	_ = os.Chmod(site, 0o644)
}
