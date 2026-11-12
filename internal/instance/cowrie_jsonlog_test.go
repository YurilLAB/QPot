package instance

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
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
