package instance

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// tankGaugeHarness runs the patched Guardian AST server outside Conpot (its
// three imports from Conpot are stubbed) and checks the replies against what
// a real gauge sends: the layout of a published capture and of the vendor's
// serial interface manual, and the relations a real site's numbers keep.
// It prints a JSON object: {"failures": [...], "sample": "..."}.
const tankGaugeHarness = `
import importlib.util, json, re, sys, types

def stub(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m

class Session:
    id = "test"
    def __init__(self): self.events = []
    def log_event(self, **k): self.events.append(k)

session = Session()
core = stub("conpot.core", get_databus=lambda: object(), get_session=lambda *a: session)
stub("conpot", core=core)
stub("conpot.core.protocol_wrapper", conpot_protocol=lambda c: c)
stub("conpot.utils", )
stub("conpot.utils.asyncio_serve", serve_tcp_sync_handler=None)
spec = importlib.util.spec_from_file_location("gast", sys.argv[1])
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
g.STATE_FILE = sys.argv[2]

failures = []
def check(ok, what):
    if not ok:
        failures.append(what)

T0 = 1794000000  # a fixed moment in November 2026
ANCHOR = T0 - 10 * 86400
site = g.Site("0123456789abcdef0123456789abcdef", None, ANCHOR)

# 1. Framing, date line and the inventory report's layout.
reply = g.report(site, "I20100", T0)
check(reply[:1] == b"\x01" and reply[-1:] == b"\x03", "a reply is not framed by SOH and ETX")
text = reply[1:-1].decode("ascii")
check("\n" not in text.replace("\r\n", ""), "a line does not end in CR LF")
lines = text.split("\r\n")
check(lines[0] == "" and lines[1] == "I20100", "the function code is not on the line after SOH: %r" % lines[:2])
DATE = r"^(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC) [ 123]\d, 20\d\d [ 1]\d:[0-5]\d (AM|PM)$"
check(re.match(DATE, lines[2]), "date line %r is not like 'OCT  1, 2015  6:07 PM'" % lines[2])
check(lines[3] == "" and len(lines[4:8]) == 4 and lines[8] == "", "no four header lines between blank lines")
check(lines[9] == "IN-TANK INVENTORY" and lines[10] == "", "no IN-TANK INVENTORY title")
HEADER = "TANK PRODUCT             VOLUME TC VOLUME   ULLAGE   HEIGHT    WATER     TEMP"
check(lines[11] == HEADER, "column headings differ from a real gauge's: %r" % lines[11])
rows = lines[12:12 + len(site.tanks)]
ROW = r"^ {2}\d {2}.{20} *\d+ +\d+ +\d+ +\d+\.\d\d +\d+\.\d\d +\d+\.\d\d$"
for row in rows:
    check(re.match(ROW, row) and len(row) == 77 == len(HEADER), "inventory row %r is not laid out like a real one" % row)
    # Numbers end under the last letter of their headings.
    for end in (31, 41, 50, 59, 68, 77):
        check(row[end - 1].isdigit() and HEADER[end - 1] != " " and (end == 77 or row[end] == " " == HEADER[end]), "row %r: no number ends at column %d" % (row, end))
# The published real row, rebuilt with the same layout code.
class Real:
    number, label = 1, "REGULAR"
real = g._row(Real, {"volume": 4812, "tc": 4771, "ullage": 4708, "height": 44.45, "water": 0.0, "temp": 71.95})
check(real == "  1  REGULAR               4812      4771     4708    44.45     0.00    71.95", "a real gauge's row is not reproduced: %r" % real)
check(g.stamp(g._utc(1443722820)) == "OCT  1, 2015  6:07 PM", "date of the published capture: %r" % g.stamp(g._utc(1443722820)))

# 2. The numbers keep the relations a real site's keep, and move as a real
# site's move: three days, a look every twenty minutes.
previous, changed, delivered = {}, {t.number: False for t in site.tanks}, 0
first = {t.number: g.report(site, "I201%02d" % t.number, T0) for t in site.tanks}
for step in range(0, 3 * 24 * 3):
    now = T0 + step * 1200
    state = site.state(now)
    for t in site.tanks:
        r = site.reading(t, now)
        check(abs(r["volume"] + r["ullage"] - t.full) <= 1, "tank %d: volume %d + ullage %d is not its size %d" % (t.number, r["volume"], r["ullage"], t.full))
        want = round(state[t.number]["volume"] * (1 + t.coefficient * (60.0 - r["temp"])))
        check(abs(r["tc"] - want) <= 1, "tank %d: TC volume %d does not follow from volume and temperature (%d)" % (t.number, r["tc"], want))
        check((r["tc"] > r["volume"]) == (r["temp"] < 60.0) or r["tc"] == r["volume"], "tank %d: TC volume on the wrong side of volume at %.1f F" % (t.number, r["temp"]))
        check(0 < r["height"] < t.diameter, "tank %d: height %.2f outside a %d inch tank" % (t.number, r["height"], t.diameter))
        check(0.03 * t.full <= r["volume"] <= 0.95 * t.full, "tank %d: volume %d of %d" % (t.number, r["volume"], t.full))
        check(35 <= r["temp"] <= 90 and 0 <= r["water"] <= 2, "tank %d: temperature %.1f, water %.2f" % (t.number, r["temp"], r["water"]))
        if t.number in previous:
            before = previous[t.number]
            if r["volume"] > before["volume"] + 1:
                delivered += 1
                pouring = state[t.number]["pending"] is not None and state[t.number]["pending"][0] <= now
                check(pouring or any(now - 1200 <= d["end"] + 300 and d["start"] <= now for d in state[t.number]["deliveries"]),
                      "tank %d rose by %d gallons with no delivery" % (t.number, r["volume"] - before["volume"]))
            else:
                check(before["volume"] - r["volume"] <= 0.05 * t.full, "tank %d fell by %d gallons in twenty minutes" % (t.number, before["volume"] - r["volume"]))
            # A fuller tank stands higher.
            check((r["height"] - before["height"]) * (r["volume"] - before["volume"]) >= -0.01, "tank %d: height and volume moved apart" % t.number)
            if r["volume"] != before["volume"]:
                changed[t.number] = True
        previous[t.number] = r
check(all(changed.values()), "a tank's volume never changed in three days: %r" % changed)
check(delivered >= 1, "no delivery in three days on any tank")
thirteen = {t.number: g.report(site, "I201%02d" % t.number, T0 + 13 * 3600) for t in site.tanks}
check(all(first[n][30:] != thirteen[n][30:] for n in first), "a tank's row is the same after thirteen hours")

# 3. The same seed gives the same site after a restart; another seed another.
check(g.report(g.Site("0123456789abcdef0123456789abcdef", None, ANCHOR), "I20100", T0) == reply, "the same seed gave another reply")
# A restart continues from the last midnight the model had reached.
reached = site.checkpoint()
days = [c["t"] for c in reached or []]
check(1 <= len(days) <= g.KEPT_DAYS and days == sorted(days) and all(d % 86400 == 0 and d > ANCHOR for d in days), "the midnights kept: %r" % days)
check(site.checkpoint() is None, "the same midnights were handed out twice")
resumed = g.Site("0123456789abcdef0123456789abcdef", None, ANCHOR, json.loads(json.dumps(reached)))
fresh = g.Site("0123456789abcdef0123456789abcdef", None, ANCHOR)
later = T0 + 3 * 86400 + 5000
check(g.report(resumed, "I20100", later) == g.report(fresh, "I20100", later) and g.report(resumed, "I20200", later) == g.report(fresh, "I20200", later),
      "a model resumed from its checkpoint differs from one run from the start")
# The state file of an earlier version held one midnight.
single = g.Site("0123456789abcdef0123456789abcdef", None, ANCHOR, json.loads(json.dumps(reached[-1])))
check(list(single._days) == days[-1:] and g.report(single, "I20100", later) == g.report(fresh, "I20100", later), "one kept midnight, as an earlier version wrote it, is not used")
# A gauge that has run for months is restarted. Its reports look back as far
# as the day before; none may replay the model from its first day, which
# would hold every other connection for seconds.
OLD = T0 - 120 * 86400
months = g.Site("0123456789abcdef0123456789abcdef", None, OLD)
months.state(T0 - 2 * 86400)
months.state(T0)  # as the server does when it starts
restarted = g.Site("0123456789abcdef0123456789abcdef", None, OLD, json.loads(json.dumps(months.checkpoint())))
check(len(restarted._days) == g.KEPT_DAYS, "a restart kept %d midnights" % len(restarted._days))
steps, advance = [0], restarted._advance
def counted(tank, state, t):
    steps[0] += 1
    return advance(tank, state, t)
restarted._advance = counted
for command in ("I20100", "I20200", "I20300", "I20400", "I20500"):
    check(g.report(restarted, command, T0 + 600) == g.report(months, command, T0 + 600), "%s differs after a restart" % command)
check(0 < steps[0] <= 3 * (86400 // g.STEP) * len(restarted.tanks), "the reports after a restart replayed %d steps of the model" % steps[0])
check(len(resumed._days) <= 5 and not g.Site("0123456789abcdef0123456789abcdef", None, ANCHOR, {"t": 5, "tanks": {}})._days, "a damaged checkpoint was used")
other = g.Site("fedcba9876543210fedcba9876543210", None, ANCHOR)
check(g.report(other, "I20100", T0) != reply and other.header != site.header, "another seed gave the same site")

# 4. The delivery report agrees with itself and with the inventory.
text = g.report(site, "I20200", T0 + 3 * 86400)[1:-1].decode("ascii")
check("DELIVERY REPORT" in text and "INCREASE   DATE / TIME" in text, "delivery report headings")
ends = [int(m) for m in re.findall(r"END: .{21} +(\d+) ", text)]
starts = [int(m) for m in re.findall(r"START: .{21} +(\d+) ", text)]
amounts = [int(m) for m in re.findall(r"AMOUNT: +(\d+) ", text)]
check(len(ends) >= 1 and len(ends) == len(starts) == len(amounts), "delivery rows: %d ends, %d starts, %d amounts" % (len(ends), len(starts), len(amounts)))
check(all(e - s == a and a > 0 for e, s, a in zip(ends, starts, amounts)), "a delivery's amount is not its end minus its start")

# 5. Other reports a gauge knows, and what it does not know.
for code, must in (("I20300", "TEST STATUS"), ("I20400", "SHIFT 1 STARTING VALUES"), ("I20500", "STATUS"), ("I60200", "PRODUCT LABEL"), ("I90200", "SOFTWARE REVISION LEVEL")):
    r = g.report(site, code, T0)
    check(r is not None and r[:1] == b"\x01" and r[-1:] == b"\x03" and must.encode() in r, "%s: %r" % (code, r))
check(b"HIGH WATER ALARM" not in g.report(site, "I20500", T0), "a tank is in alarm at an ordinary moment")
for code in ("I30100", "I20199", "I201xx", "XXXXXX", "I99999"):
    check(g.report(site, code, T0) is None, "%s is answered" % code)
check(g.AST_ERROR == b"\x019999FF1B\x03", "the not-understood reply")
check((0x10000 - sum(b"\x019999")) & 0xFFFF == 0xFF1B, "FF1B is not the checksum of SOH 9999")

# 6. The server: commands in one packet, split across packets, the two
# characters ^A, noise, and a label a visitor sets and finds again.
class Sock:
    def __init__(self, chunks): self.chunks, self.sent, self.closed = list(chunks), b"", False
    def settimeout(self, t): pass
    def getsockname(self): return ("192.0.2.1", 10001)
    def recv(self, n):
        if not self.chunks: raise g.socket.timeout()
        return self.chunks.pop(0)
    def sendall(self, data): self.sent += data
    def close(self): self.closed = True

def talk(server, *chunks):
    s = Sock(chunks)
    server.handle(s, ("198.51.100.7", 40000))
    check(s.closed, "the connection was not closed")
    return s.sent

server = g.GuardianASTServer({}, "", None)
out = talk(server, b"\x01I20100\n")
check(out.count(b"\x01") == 1 and out.endswith(b"\x03") and b"IN-TANK INVENTORY" in out, "I20100 over the socket: %r" % out[:60])
out = talk(server, b"\x01I20100\n\x01I20500\n")
check(out.count(b"\x03") == 2 and b"STATUS" in out, "two commands in one packet got %d replies" % out.count(b"\x03"))
out = talk(server, b"\x01I2", b"0100", b"\n")
check(out.count(b"\x03") == 1 and b"IN-TANK INVENTORY" in out, "a command split across packets")
out = talk(server, b"^AI20100\n")
check(b"IN-TANK INVENTORY" in out, "a command typed as ^A")
check(talk(server, b"hello\r\n", b"GET / HTTP/1.0\r\n\r\n") == b"", "noise was answered")
check(talk(server, b"\x01I30100\n") == b"\x019999FF1B\x03", "an unknown command")
check(talk(server, b"\x01" + b"A" * 9000) in (b"", b"\x019999FF1B\x03"), "an overlong request")
out = talk(server, b"\x01S60201UNLEADED PLUS\n")
check(b"PRODUCT LABEL" in out and b"UNLEADED PLUS" in out, "setting a label: %r" % out)
check(b"  1  UNLEADED PLUS " in talk(server, b"\x01I20100\n"), "the label a visitor set is not in the inventory")
again = g.GuardianASTServer({}, "", None)
check(b"  1  UNLEADED PLUS " in talk(again, b"\x01I20100\n"), "the label did not survive a restart")
check(again.site.header == server.site.header, "the site changed across a restart")
check(talk(again, b"\x01S60299X\n") == b"\x019999FF1B\x03" and talk(again, b"\x01S60200X\n") == b"\x019999FF1B\x03", "a label for no tank or all tanks")
out = talk(again, b"\x01S60202" + b"\x00\x1b[2J" + b"B" * 40 + b"\n")
check(b"\x1b" not in out and b"\x00" not in out and b"B" * 21 not in out and b"BBBB" in out, "a label is not cut to twenty characters without control bytes: %r" % out)
# 7. Arbitrary bytes, as scanners and fuzzers send them: the server neither
# fails nor answers with anything but whole framed replies, and never with
# more than the reports of the commands it was sent.
import random
rng = random.Random(20261112)
pieces = [b"\x01", b"^A", b"I20100", b"I201", b"I2", b"S60201", b"S602", b"\n", b"\r\n", b"\x03", b"00", b"99", b"I90200", b"\x00", b"\xff", b"A" * 30]
for _ in range(1500):
    chunks = []
    for _ in range(rng.randint(1, 4)):
        chunk = b"".join(rng.choice(pieces) if rng.random() < 0.8 else bytes([rng.randrange(256)]) for _ in range(rng.randint(1, 12)))
        chunks.append(chunk)
    before = len(failures)
    try:
        out = talk(again, *chunks)
    except Exception as e:
        check(False, "input %r raised %r" % (chunks, e))
        continue
    sent = b"".join(chunks)
    check(out == b"" or (out[:1] == b"\x01" and out[-1:] == b"\x03" and out.count(b"\x01") == out.count(b"\x03")), "input %r got an unframed reply %r" % (chunks, out[:80]))
    check(out.count(b"\x03") <= sent.count(b"\x01") + sent.count(b"^A"), "input %r got more replies than commands" % (chunks,))
    check(len(out) <= 4096 * max(1, out.count(b"\x03")), "input %r got %d bytes" % (chunks, len(out)))
    if len(failures) > before + 3:
        break
# Labels set by the noise above must still be printable and at most twenty long.
for t in again.site.tanks:
    check(len(t.label) <= 20 and all(32 <= ord(c) < 127 for c in t.label), "tank %d label %r" % (t.number, t.label))

kinds = [e.get("event_type") for e in session.events]
check("NEW_CONNECTION" in kinds and "CONNECTION_LOST" in kinds and "AST I20100" in kinds, "session events: %r" % kinds[:6])

print(json.dumps({"failures": failures[:40], "count": len(failures), "sample": reply.decode("ascii", "replace")}))
`

// TestConpotTankGaugeLooksLikeAGauge: the image's tank gauge is the best
// documented honeypot tell there is (no SOH/ETX framing, a numeric date,
// random readings that never change, a TC volume unrelated to temperature).
// The replacement must lay its reports out as a real gauge does and keep the
// relations a real site's numbers keep.
func TestConpotTankGaugeLooksLikeAGauge(t *testing.T) {
	py := python(t)
	dir := t.TempDir()
	module := filepath.Join(dir, "guardian_ast_server.py")
	harness := filepath.Join(dir, "harness.py")
	if err := os.WriteFile(module, conpotGuardianASTPy, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(harness, []byte(tankGaugeHarness), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(py, harness, module, filepath.Join(dir, "state.json")).Output()
	if err != nil {
		t.Fatalf("harness: %v\n%s", err, out)
	}
	var res struct {
		Failures []string `json:"failures"`
		Count    int      `json:"count"`
		Sample   string   `json:"sample"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("harness output: %v\n%s", err, out)
	}
	for _, f := range res.Failures {
		t.Error(f)
	}
	if res.Count > len(res.Failures) {
		t.Errorf("and %d more", res.Count-len(res.Failures))
	}
	t.Logf("an inventory report:\n%s", res.Sample)
}
