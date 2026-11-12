package instance

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// conpotOPCUAHarness runs the mounted OPC UA server's process model, and the
// part of the server that creates and writes the variables, outside Conpot:
// asyncua and Conpot's own modules are stubbed. It prints a JSON object:
// {"failures": [...], "sample": {...}}.
const conpotOPCUAHarness = `
import asyncio, importlib.util, json, math, os, sys, types
from datetime import timezone

def stub(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m

class Variant:
    def __init__(self, value, kind=None): self.Value, self.VariantType = value, kind
class DataValue:
    def __init__(self, value, SourceTimestamp=None, ServerTimestamp=None):
        self.Value, self.SourceTimestamp, self.ServerTimestamp = value, SourceTimestamp, ServerTimestamp
ua = types.SimpleNamespace(Variant=Variant, DataValue=DataValue,
    VariantType=types.SimpleNamespace(Int32="Int32"), SecurityPolicyType=types.SimpleNamespace(NoSecurity="none"))

class Node:
    def __init__(self, name, value, kind): self.name, self.value, self.kind, self.writes, self.writable = name, value, kind, [], False
    async def set_writable(self): self.writable = True
    async def write_value(self, value): self.writes.append(value)
class Folder:
    def __init__(self): self.nodes, self.plain = [], []
    async def add_variable(self, idx, name, value, **kw):
        node = Node(name, value, kw.get("varianttype"))
        self.nodes.append(node)
        if not kw: self.plain.append(name)
        return node
class Objects:
    def __init__(self): self.folder = Folder()
    async def add_object(self, idx, name): return self.folder
class Server:
    def __init__(self): self.nodes = types.SimpleNamespace(objects=Objects())
    def set_server_name(self, name): pass
    async def set_application_uri(self, uri): pass
    def set_security_policy(self, policies): pass
    async def register_namespace(self, uri): return 2

stub("asyncua", Server=Server, ua=ua)
core = stub("conpot.core", get_databus=lambda: object())
stub("conpot", core=core)
stub("conpot.core.protocol_wrapper", conpot_protocol=lambda c: c)
stub("conpot.protocols")
stub("conpot.protocols.opcua")
stub("conpot.protocols.opcua.session", run_opcua_session=None)
stub("conpot.utils")
stub("conpot.utils.asyncio_serve", _set_listener_addrs=None)
spec = importlib.util.spec_from_file_location("opcua_server", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

failures = []
def check(ok, what):
    if not ok and len(failures) < 40:
        failures.append(what)

SEED = "0123456789abcdef0123456789abcdef"
T0 = 1794000000  # a fixed moment in November 2026
IMAGE = {"MAIN.fTemperature": 21.4, "MAIN.fPressure": 3.82, "MAIN.bPumpRunning": True, "MAIN.nBatchId": 1187}

# 1. The model: one process per seed, the same at any restart.
p = m.Process(SEED)
check(p.values(T0) == m.Process(SEED).values(T0), "the same seed and moment give different readings")
other = m.Process("fedcba9876543210fedcba9876543210")
check((p.cycle, p.temperature, p.pressure) != (other.cycle, other.temperature, other.pressure), "two seeds give the same plant")
check(set(p.values(T0)) == set(m.Process.NAMES) == set(IMAGE), "the model does not give the profile's four variables")

# 2. Two whole batches, second by second, from the start of one.
start = p.started + (int((T0 - p.started) // p.cycle) + 1) * p.cycle
first = p.values(start + 0.5)
before, running, stopped, on, steps, batches = first, [], [], 0, int(2 * p.cycle), 0
for i in range(1, steps):
    now = start + 0.5 + i
    v = p.values(now)
    phase = (now - start) % p.cycle
    check(v["MAIN.bPumpRunning"] == (phase < p.on), "the pump is not on for the first part of a batch at %.0f s" % phase)
    check(v["MAIN.nBatchId"] - before["MAIN.nBatchId"] in (0, 1), "the batch counter moved by %d" % (v["MAIN.nBatchId"] - before["MAIN.nBatchId"]))
    batches += v["MAIN.nBatchId"] - before["MAIN.nBatchId"]
    check(p.rest - 0.02 <= v["MAIN.fPressure"] <= p.pressure + 0.02, "pressure %.3f outside %.2f..%.2f" % (v["MAIN.fPressure"], p.rest, p.pressure))
    check(p.temperature - 0.6 <= v["MAIN.fTemperature"] <= p.temperature + p.rise + 0.6, "temperature %.3f outside its range" % v["MAIN.fTemperature"])
    # Nothing jumps: a second moves a reading by what its lag allows plus noise.
    most = (p.pressure - p.rest) * (1 - math.exp(-1 / p.pressure_tau)) + 0.03
    check(abs(v["MAIN.fPressure"] - before["MAIN.fPressure"]) <= most, "pressure jumped by %.3f in a second at %.0f s" % (v["MAIN.fPressure"] - before["MAIN.fPressure"], phase))
    check(abs(v["MAIN.fTemperature"] - before["MAIN.fTemperature"]) <= 0.08, "temperature jumped by %.3f in a second at %.0f s" % (v["MAIN.fTemperature"] - before["MAIN.fTemperature"], phase))
    check(v["MAIN.fPressure"] != before["MAIN.fPressure"] and v["MAIN.fTemperature"] != before["MAIN.fTemperature"], "a reading stood still for a second")
    (running if v["MAIN.bPumpRunning"] else stopped).append(v["MAIN.fPressure"])
    on += v["MAIN.bPumpRunning"]
    # The pressure follows the pump: there after five time constants.
    if 5 * p.pressure_tau < phase < p.on:
        check(v["MAIN.fPressure"] > p.rest + 0.9 * (p.pressure - p.rest), "pressure %.2f with the pump long running" % v["MAIN.fPressure"])
    before = v
check(batches == 1, "two batches from the start of one moved the counter by %d, not 1" % batches)
check(abs(on / steps - p.on / p.cycle) < 0.01, "the pump ran %.3f of the time, not %.3f" % (on / steps, p.on / p.cycle))
check(sum(running) / len(running) > sum(stopped) / len(stopped) + 0.5 * (p.pressure - p.rest), "the pressure does not follow the pump")
day = [p.values(T0 + h * 3600)["MAIN.fTemperature"] for h in range(24)]
check(max(day) - min(day) > 0.5, "the temperature does not move over a day")

# 3. Any seed: numbers in the ranges the documentation gives, never the image's.
plants = set()
for i in range(300):
    s = m.Process("%032x" % (i * 7919 + 13))
    v = s.values(T0)
    plants.add((s.cycle, round(s.temperature, 3), round(s.pressure, 3)))
    check(18 * 60 <= s.cycle <= 55 * 60 and 0.55 * s.cycle <= s.on <= 0.85 * s.cycle, "seed %d: batch %.0f s, pump %.0f s" % (i, s.cycle, s.on))
    check(24 <= s.temperature <= 58 and 2.6 <= s.pressure <= 5.8 and 0.2 <= s.rest <= 0.8, "seed %d: plant out of range" % i)
    check(5000 < v["MAIN.nBatchId"] < 90000, "seed %d: batch %d is not a plant one to three years old" % (i, v["MAIN.nBatchId"]))
    check(type(v["MAIN.bPumpRunning"]) is bool and type(v["MAIN.nBatchId"]) is int and type(v["MAIN.fPressure"]) is float, "seed %d: wrong types" % i)
    for name, value in IMAGE.items():
        check(name == "MAIN.bPumpRunning" or v[name] != value, "seed %d reads the image's %s" % (i, name))
check(len(plants) == 300, "300 seeds gave %d plants" % len(plants))
check(m.Process(SEED).values(p.started - 5)["MAIN.nBatchId"] == 1, "a clock before commissioning does not read batch 1")

# 4. The server: creates the variables with the model's readings and writes
# them on every tick; with no seed it is the image's server.
TEMPLATE = {"folder_name": "PLC1", "variables": [
    {"name": "MAIN.fTemperature", "type": "float", "value": 21.4},
    {"name": "MAIN.fPressure", "type": "float", "value": 3.82},
    {"name": "MAIN.bPumpRunning", "type": "boolean", "value": True},
    {"name": "MAIN.nBatchId", "type": "integer", "value": 1187},
    {"name": "MAIN.sRecipe", "type": "string", "value": "R-12"},
]}
m.PROCESS_TICK = 0.01

async def serve(seed, template):
    if seed is None: os.environ.pop(m.SEED_ENV, None)
    else: os.environ[m.SEED_ENV] = seed
    server = m.OPCUAServer(template, "", None)
    server._ua = Server()
    await server._init_address_space()
    folder = server._ua.nodes.objects.folder
    if server._driven:
        task = asyncio.create_task(server._run_process())
        await asyncio.sleep(0.2)
        server.stop()
        await asyncio.wait_for(task, 2)
    return server, folder

server, folder = asyncio.run(serve(SEED, TEMPLATE))
nodes = {n.name: n for n in folder.nodes}
check(list(nodes) == [e["name"] for e in TEMPLATE["variables"]], "the variables are not the template's, in its order")
check(all(n.writable for n in folder.nodes), "a variable is not writable as in the image")
check(len(server._driven) == 4 and folder.plain == ["MAIN.sRecipe"] and nodes["MAIN.sRecipe"].value == "R-12", "a variable the model does not know did not keep its value")
check(nodes["MAIN.nBatchId"].kind == "Int32" and nodes["MAIN.fPressure"].kind is None and nodes["MAIN.bPumpRunning"].kind is None, "the batch counter is not 32 bits wide or another variable was given a width")
for name in m.Process.NAMES:
    n = nodes[name]
    check(name == "MAIN.bPumpRunning" or n.value != IMAGE[name], "%s starts at the image's value" % name)
    check(len(n.writes) >= 3, "%s was written %d times in 20 ticks" % (name, len(n.writes)))
    for w in n.writes:
        check(type(w.Value.Value) is type(IMAGE[name]) and w.Value.VariantType == n.kind, "%s was written as %r" % (name, w.Value.Value))
        check(w.SourceTimestamp is not None and w.SourceTimestamp.tzinfo is timezone.utc and w.SourceTimestamp == w.ServerTimestamp, "%s was written without a UTC time" % name)
check(not nodes["MAIN.sRecipe"].writes, "a variable the model does not know was written")

server, folder = asyncio.run(serve(None, TEMPLATE))
check(not server._driven and [n.value for n in folder.nodes] == [21.4, 3.82, True, 1187, "R-12"] and len(folder.plain) == 5, "with no seed the variables are not the template's")
check(not any(n.writes for n in folder.nodes), "with no seed a variable was written")
server, folder = asyncio.run(serve("short", TEMPLATE))
check(not server._driven, "a seed of five characters was used")
# A template whose variable has another type keeps it.
odd = {"variables": [{"name": "MAIN.fTemperature", "type": "string", "value": "n/a"}, {"name": "MAIN.nBatchId", "type": "integer", "value": 7}]}
server, folder = asyncio.run(serve(SEED, odd))
check(folder.nodes[0].value == "n/a" and not folder.nodes[0].writes and len(server._driven) == 1, "a variable of another type was replaced")
server, folder = asyncio.run(serve(SEED, {}))
check([n.name for n in folder.nodes] == ["Temperature"] and not server._driven, "a template without variables does not get the image's default")

print(json.dumps({"failures": failures, "sample": {k: p.values(T0)[k] for k in m.Process.NAMES},
    "plant": {"batch_minutes": p.cycle / 60, "pump_share": p.on / p.cycle, "bar": p.pressure, "degrees": p.temperature}}))
`

// TestConpotOPCUAProcess checks the Beckhoff profile's process variables: a
// plant of its own per seed, readings that move without jumping and keep
// their relations, and a server that writes them.
func TestConpotOPCUAProcess(t *testing.T) {
	py := python(t)
	dir := t.TempDir()
	module := filepath.Join(dir, "opcua_server.py")
	harness := filepath.Join(dir, "harness.py")
	if err := os.WriteFile(module, conpotOPCUAServerPy, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(harness, []byte(conpotOPCUAHarness), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(py, harness, module).CombinedOutput()
	if err != nil {
		t.Fatalf("harness: %v\n%s", err, out)
	}
	var res struct {
		Failures []string       `json:"failures"`
		Sample   map[string]any `json:"sample"`
		Plant    map[string]any `json:"plant"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("harness output: %v\n%s", err, out)
	}
	for _, f := range res.Failures {
		t.Error(f)
	}
	t.Logf("one plant: %v reads %v", res.Plant, res.Sample)
}

// TestConpotOPCUAMounts checks that the server is mounted over the image's,
// read-only, for the Beckhoff profile and no other.
func TestConpotOPCUAMounts(t *testing.T) {
	want := conpotOPCUAPatchVolume()
	if len(conpotOPCUAOriginalSHA256) != 64 || len(want.Content) == 0 {
		t.Fatal("the OPC UA server or the hash of the file it replaces is missing")
	}
	for _, id := range ConpotTemplateIDs() {
		found := false
		for _, mount := range deployProfile(conpotConfig("qp_opcua_patch_mount", id), "conpot").Volumes {
			if mount.ContainerPath != want.ContainerPath {
				continue
			}
			found = true
			if !mount.File || !mount.ReadOnly || !bytes.Equal(mount.Content, want.Content) {
				t.Fatalf("%s: the OPC UA server is not a populated read-only file", id)
			}
		}
		if found != (id == "beckhoff_cx") {
			t.Fatalf("%s: OPC UA server mounted=%v", id, found)
		}
	}
	svc, _, _ := publishedPorts(t, conpotConfig("qp_opcua_patch_compose", "beckhoff_cx"), "conpot")
	line := "/honeypots/conpot/" + want.HostSubdir + ":" + want.ContainerPath + ":ro\n"
	if !strings.Contains(svc, line) {
		t.Fatalf("generated Compose does not mount the OPC UA server read-only: want %q", strings.TrimSpace(line))
	}
	if bytes.Contains(want.Content, []byte("\r")) {
		t.Error("the OPC UA server has CR bytes")
	}
	// The start step hands the seed on, under the name the server reads.
	if !bytes.Contains(conpotSitePy, []byte(`os.environ["QPOT_SITE_SEED"] = seed`)) || !bytes.Contains(want.Content, []byte(`SEED_ENV = "QPOT_SITE_SEED"`)) {
		t.Error("the start step and the OPC UA server do not agree on how the seed is passed")
	}
}
