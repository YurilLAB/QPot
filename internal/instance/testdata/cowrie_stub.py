"""Runs the patch layer's Cowrie commands outside Cowrie, for internal/instance's tests.

Twisted, treq and the parts of Cowrie the commands import are stubbed: the filesystem is a tree of
Cowrie's nodes built from the case, the network answers as the case says (and records every lookup
and fetch, so a test can tell what would have reached it), and callLater runs on a virtual clock.

usage: cowrie_stub.py <patch dir> <cases.json>; prints one JSON result per case:
  {"stdout", "stderr", "code", "seconds" (virtual), "events", "lookups", "fetches", "files", "cpu"}

A case: {"argv": [...], "persona": "ubuntu-24.04", "machine": "x86_64", "files": {path: text or
{"b64": .., "mode": .., "uid": .., "mtime": ..} or {"link": target} or {"dir": true}}, "config":
{"section.key": value}, "dns": {name: address or null}, "http": {url: {"code": .., "body": ..}},
"terminal": true, "columns": terminal width, "stdin": text, "lines": [typed lines, with "@SECONDS"
waits], "env": {...}, "installed": epoch, "packages": {name: version}, "plan": {bait plan}, "now": the
wall clock ls compares with, "probe": "bash_variables" (the variables the login shell gets, no command),
"memory": true (report the peak of the bytes the command allocates as "peak")}.
"""

from __future__ import annotations

import base64
import heapq
import importlib.util
import json
import os
import posixpath
import shutil
import stat as stat_mod
import sys
import tempfile
import time
import tracemalloc
import types

PATCH, CASES = sys.argv[1], sys.argv[2]


def module(name: str) -> types.ModuleType:
    mod = sys.modules.get(name)
    if mod is None:
        mod = types.ModuleType(name)
        sys.modules[name] = mod
        parent, _, child = name.rpartition(".")
        if parent:
            setattr(module(parent), child, mod)
    return mod


class Logger:
    def info(self, *a, **k):
        pass

    def warn(self, *a, **k):
        pass

    debug = failure = error = info


module("twisted.logger").Logger = Logger


# --- a virtual clock and the reactor ---------------------------------------------------------
class Clock:
    def __init__(self):
        self.now, self.queue, self.seq = 0.0, [], 0

    def later(self, delay, fn, *args):
        call = DelayedCall(self, self.now + max(float(delay), 0.0), fn, args)
        self.seq += 1
        heapq.heappush(self.queue, (call.when, self.seq, call))
        return call

    def run(self, until=None, limit=100000):
        steps = 0
        while self.queue and steps < limit:
            when, _, call = self.queue[0]
            if until is not None and when > until:
                break
            heapq.heappop(self.queue)
            if call.cancelled:
                continue
            self.now = max(self.now, when)
            call.called = True
            call.fn(*call.args)
            steps += 1
        if until is not None:
            self.now = max(self.now, until)


class DelayedCall:
    def __init__(self, clock, when, fn, args):
        self.clock, self.when, self.fn, self.args = clock, when, fn, args
        self.cancelled = self.called = False

    def active(self):
        return not (self.cancelled or self.called)

    def cancel(self):
        self.cancelled = True


CLOCK = Clock()


class Reactor:
    def callLater(self, delay, fn, *a):
        return CLOCK.later(delay, fn, *a)

    def resolve(self, name):
        return Done(STATE["dns"].get(name))


reactor = Reactor()


class Done:
    """A Deferred that has fired: callbacks run at once."""

    def __init__(self, result=None, failure=None):
        self.result, self.failure = result, failure

    def addCallback(self, fn, *a):
        if self.failure is None:
            try:
                self.result = fn(self.result, *a)
            except Exception as err:  # noqa: BLE001
                self.failure = Failure(err)
        return self

    def addErrback(self, fn, *a):
        if self.failure is not None:
            failure, self.failure = self.failure, None
            self.result = fn(failure, *a)
        return self

    def addCallbacks(self, cb, eb):
        return self.addCallback(cb).addErrback(eb)

    def addBoth(self, fn):
        return self.addCallback(fn).addErrback(fn)


def inlineCallbacks(fn):
    def run(*a, **k):
        gen = fn(*a, **k)
        if not hasattr(gen, "send"):
            return Done(gen)
        value = None
        try:
            while True:
                got = gen.send(value)
                value = got.result if isinstance(got, Done) else got
        except StopIteration as stop:
            return Done(stop.value)
    return run


class Failure:
    def __init__(self, value=None):
        self.value = value if value is not None else sys.exc_info()[1]

    def check(self, *kinds):
        return next((k for k in kinds if isinstance(self.value, k)), None)


class CancelledError(Exception):
    pass


errmod = module("twisted.internet.error")
for _name in ("DNSLookupError", "ConnectingCancelledError", "ConnectionRefusedError", "TCPTimedOutError",
              "ConnectionDone", "ConnectionLost"):
    setattr(errmod, _name, type(_name, (Exception,), {}))
module("twisted.internet").reactor = reactor
module("twisted.internet").error = errmod
defer = module("twisted.internet.defer")
defer.inlineCallbacks, defer.Deferred, defer.CancelledError = inlineCallbacks, Done, CancelledError
defer.succeed = lambda value=None: Done(value)
module("twisted.python.failure").Failure = Failure
module("twisted.python").failure = sys.modules["twisted.python.failure"]
module("twisted.web.iweb").UNKNOWN_LENGTH = object()
module("twisted.internet.protocol").ClientCreator = object
module("twisted.internet.protocol").Protocol = object
module("twisted.protocols.ftp").CommandFailed = type("CommandFailed", (Exception,), {})
module("twisted.protocols.ftp").FTPClient = object

# --- the network: lookups and fetches recorded ------------------------------------------------
STATE: dict = {}


class Response:
    def __init__(self, spec):
        self.code = int(spec.get("code", 200))
        self.phrase = spec.get("phrase", "OK").encode()
        self.version = (b"HTTP", 1, 1)
        self.body = spec.get("body", "").encode()
        self.length = len(self.body)
        self.headers = Headers({"content-type": [spec.get("type", "text/plain")],
                                "content-length": [str(len(self.body))]})


class Headers:
    def __init__(self, raw):
        self.raw = {k.encode(): [v.encode() for v in vs] for k, vs in raw.items()}

    def getRawHeaders(self, name, default=None):
        key = name.encode() if isinstance(name, str) else name
        return self.raw.get(key.lower(), default)

    def getAllRawHeaders(self):
        return list(self.raw.items())


def fetch(_reactor, url, method="get", headers=None, timeout=10, max_redirects=5):
    STATE["fetches"].append({"url": url, "method": method, "headers": {k: list(v) for k, v in (headers or {}).items()},
                             "timeout": timeout, "max_redirects": max_redirects})
    spec = STATE["http"].get(url)
    if spec is None:
        return Done(failure=Failure(errmod.ConnectionRefusedError()))
    return Done(Response(spec))


def resolve_cname(name, visited):
    STATE["lookups"].append(name)
    return Done(STATE["dns"].get(name))


def resolve_allowed(name):
    import ipaddress

    try:
        address = str(ipaddress.ip_address(name))
    except ValueError:
        address = resolve_cname(name, set()).result
    return Done(None if address is None or _is_blocked(ipaddress.ip_address(address)) else address)


def communication_allowed(name):
    return Done(resolve_allowed(name).result is not None)


def _is_blocked(ip):
    return not ip.is_global


network = module("cowrie.core.network")
network.resolve_cname, network.resolve_allowed, network.communication_allowed = (
    resolve_cname, resolve_allowed, communication_allowed)
network._is_blocked = _is_blocked
network.DownloadLimitExceeded = type("DownloadLimitExceeded", (Exception,), {})
network.abort_body = lambda response: None
network.outbound_bind_address = lambda: "0.0.0.0"


def is_ip_address(text):
    import ipaddress

    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


network.is_ip_address = is_ip_address
download = module("cowrie.core.download")
download.BlockedAddress = type("BlockedAddress", (Exception,), {})
download.UnreachableAddress = type("UnreachableAddress", (Exception,), {})
download.fetch = fetch


class Limiter:
    def check(self, host):
        return STATE.get("limit_ok", True)


download.outbound_rate_limiter = lambda name: Limiter()


def capture_download(command, artifact, url, outfile=None, size=0):
    STATE["events"].append({"eventid": "cowrie.session.file_download", "url": url, "outfile": outfile or ""})


download.capture_download = capture_download
download.report_download_failure = lambda command, url: STATE["events"].append(
    {"eventid": "cowrie.session.file_download.failed", "url": url})


class Artifact:
    def __init__(self, name):
        self.data = b""
        self.shasumFilename, self.shasum, self.duplicate = "", "", False

    def write(self, data):
        self.data += data

    def close(self):
        pass


module("cowrie.core.artifact").Artifact = Artifact
module("cowrie.core.artifact").temp_download_path = lambda *a: "/tmp/x"


def collect(response, collector):
    collector(response.body)
    return Done(None)


module("treq").collect = collect


class CowrieConfig:
    @staticmethod
    def get(section, key, fallback=None):
        return STATE["config"].get(f"{section}.{key}", fallback)

    @staticmethod
    def getint(section, key, fallback=0):
        return int(STATE["config"].get(f"{section}.{key}", fallback))

    @staticmethod
    def getboolean(section, key, fallback=False):
        return bool(STATE["config"].get(f"{section}.{key}", fallback))


module("cowrie.core.config").CowrieConfig = CowrieConfig
STATE["config"] = {}

# --- the filesystem -------------------------------------------------------------------------
fsmod = module("cowrie.shell.fs")
(fsmod.A_NAME, fsmod.A_TYPE, fsmod.A_UID, fsmod.A_GID, fsmod.A_SIZE, fsmod.A_MODE, fsmod.A_CTIME, fsmod.A_CONTENTS,
 fsmod.A_TARGET, fsmod.A_REALFILE) = range(10)
fsmod.T_LINK, fsmod.T_DIR, fsmod.T_FILE, fsmod.T_BLK, fsmod.T_CHR, fsmod.T_SOCK, fsmod.T_FIFO = range(7)


class FS:
    def __init__(self, files, mtime):
        self.root = ["", 1, 0, 0, 4096, 0o40755, mtime, [], None, None]
        for path, spec in sorted(files.items()):
            self.add(path, spec, mtime)

    def add(self, path, spec, mtime):
        parts = [p for p in path.split("/") if p]
        node = self.root
        for part in parts[:-1]:
            child = next((c for c in node[7] if c[0] == part), None)
            if child is None:
                child = [part, 1, 0, 0, 4096, 0o40755, mtime, [], None, None]
                node[7].append(child)
            node = child
        if isinstance(spec, str):
            spec = {"text": spec}
        when = spec.get("mtime", mtime)
        if spec.get("dir"):
            new = [parts[-1], 1, spec.get("uid", 0), spec.get("gid", 0), 4096, 0o40000 | spec.get("mode", 0o755), when,
                   [], None, None]
        elif "link" in spec:
            new = [parts[-1], 0, 0, 0, len(spec["link"]), 0o120777, when, [], spec["link"], None]
        else:
            data = base64.b64decode(spec["b64"]) if "b64" in spec else spec.get("text", "").encode()
            mode = spec.get("mode", 0o644)
            new = [parts[-1], 2, spec.get("uid", 0), spec.get("gid", 0), spec.get("size", len(data)),
                   0o100000 | mode, when, data, None, None]
        node[7] = [c for c in node[7] if c[0] != parts[-1]] + [new]

    def resolve_path(self, path, cwd):
        return posixpath.normpath(posixpath.join(cwd, path)) if path else cwd

    def getfile(self, path, follow_symlinks=True, depth=0):
        if depth > 16:
            return None
        if path in ("/", ""):
            return self.root
        node, done = self.root, ""
        pieces = [p for p in path.split("/") if p]
        for i, piece in enumerate(pieces):
            if not isinstance(node[7], list):
                return None
            node = next((c for c in node[7] if c[0] == piece), None)
            if node is None:
                return None
            if node[1] == 0 and (follow_symlinks or i < len(pieces) - 1):
                node = self.getfile(posixpath.normpath(posixpath.join(done or "/", node[8])), True, depth + 1)
                if node is None:
                    return None
            done += "/" + piece
        return node

    def get_path(self, path, follow_symlinks=True):
        node = self.getfile(path, follow_symlinks)
        return node[7]

    def exists(self, path):
        return self.getfile(path) is not None

    def lexists(self, path):
        return self.getfile(path, follow_symlinks=False) is not None

    def isdir(self, path):
        node = self.getfile(path)
        return node is not None and node[1] == 1

    def file_contents(self, path):
        node = self.getfile(path)
        if node is None or node[1] == 1:
            raise OSError(2, "No such file or directory")
        return node[7] if isinstance(node[7], bytes) else b""

    def mkfile(self, path, uid, gid, size, mode, ctime=None):
        parent = self.getfile(posixpath.dirname(path))
        if parent is None or parent[1] != 1:
            raise OSError(2, "No such file or directory")
        name = posixpath.basename(path)
        parent[7] = [c for c in parent[7] if c[0] != name]
        parent[7].append([name, 2, uid, gid, size, mode, ctime if ctime is not None else CLOCK.now, [], None, None])
        return True

    def mkdir(self, path, uid, gid, size, mode):
        parent = self.getfile(posixpath.dirname(path))
        parent[7].append([posixpath.basename(path), 1, uid, gid, size, mode, CLOCK.now, [], None, None])

    def remove(self, path):
        parent = self.getfile(posixpath.dirname(path))
        name = posixpath.basename(path)
        parent[7] = [c for c in parent[7] if c[0] != name]


# --- Cowrie's command base -------------------------------------------------------------------
class PipeProtocol:
    def __init__(self, protocol, cmdclass, args, input_data, targets, cwd=None, user=None):
        self.args, self.targets, self.input_data = args, targets, input_data
        self.stdin_from_pipe = False


module("cowrie.shell.pipe").PipeProtocol = PipeProtocol


class HoneyPotCommand:
    exited = False
    pp = None
    consumes_stdin = False

    def __init__(self, protocol, *args):
        self.protocol = protocol
        self.args = list(args)
        self.exit_code = 0
        self.environ = protocol.environ
        self.exported = set()
        self.fs = protocol.fs
        self.cwd = protocol.cwd
        self.user = {"uid": 0, "gid": 0, "username": "root", "home": "/root"}
        self.input_data = protocol.stdin
        self.shell = protocol
        self.pp = types.SimpleNamespace(targets={1: ("terminal" if protocol.terminal else "pipe", None),
                                                 2: ("terminal", None)}, stdin_from_pipe=False)

    def write(self, data):
        STATE["out"].append(("o", data))

    def writeBytes(self, data):
        STATE["out"].append(("o", data.decode("latin-1")))

    def errorWrite(self, data):
        STATE["out"].append(("e", data))

    def callLater(self, delay, fn, *args):
        return CLOCK.later(delay, fn, *args)

    def start(self):
        self.call()
        self.exit()

    def call(self):
        pass

    def exit(self, code=None):
        if self.exited:
            return
        self.exited = True
        if code is not None:
            self.exit_code = code
        STATE["code"] = self.exit_code

    def lineReceived(self, line):
        STATE["typeahead"].append(line)

    def handle_CTRL_C(self):
        self.write("^C\n")
        self.exit(130)

    def eofReceived(self):
        self.exit()

    def exec_command(self, pp, cmdclass, *args):
        STATE["exec"].append([cmdclass.__name__] + list(args))
        self.exit(0)


module("cowrie.shell.command").HoneyPotCommand = HoneyPotCommand


class Events:
    def dispatch(self, eventid, fmt, **fields):
        STATE["events"].append(dict(fields, eventid=eventid))


# --- the image's modules the patch layer imports ---------------------------------------------
uname = module("cowrie.commands.uname")
uname.hardware_platform = lambda: STATE["machine"]


def tpot_bb_usage_stop(command, name, args):
    """uname.py's: BusyBox's usage for --help, no argument or an unknown option (here: -Z)."""
    if args and "--help" not in args and "-Z" not in args:
        return False
    command.errorWrite(f"BusyBox usage of {name}\n")
    command.exit(1)
    return True


uname.tpot_bb_usage_stop = tpot_bb_usage_stop
module("cowrie.commands.netstat").tpot_net_data = lambda text: {
    "interfaces": [{"name": "lo", "inet": "127.0.0.1"}, {"name": "eth0", "inet": "10.20.0.5", "broadcast": "10.20.0.255"}],
    "gateway": "10.20.0.1"}


class HelpBase(HoneyPotCommand):
    def call(self):
        self.write("stock help\n")


module("cowrie.commands.base").Command_help = HelpBase


class Command_sh(HoneyPotCommand):
    def start(self):
        self.write("nested shell\n")
        self.exit()


class Command_exit(HoneyPotCommand):
    pass


module("cowrie.commands.bash").Command_sh = Command_sh
module("cowrie.commands.bash").Command_exit = Command_exit


class ScpServer(HoneyPotCommand):
    def start(self):
        self.write("\x00")
        STATE["events"].append({"eventid": "scp.server", "args": self.args})
        self.exit()


module("cowrie.commands.scp").Command_scp = ScpServer


class Passwd:
    """cowrie.shell.pwd's: the names of the case's /etc/passwd and /etc/group."""

    path, field = "/etc/passwd", "pw_name"

    def table(self):
        node = STATE["fs"].getfile(self.path)
        text = node[7].decode() if node and isinstance(node[7], bytes) else ""
        return {int(f[2]): f[0] for f in (line.split(":") for line in text.splitlines()) if len(f) > 2 and f[2].isdigit()}

    def getpwuid(self, uid):
        return {self.field: self.table()[uid]}


class Group(Passwd):
    path, field = "/etc/group", "gr_name"

    def getgrgid(self, gid):
        return {self.field: self.table()[gid]}


module("cowrie.shell.pwd").Passwd, module("cowrie.shell.pwd").Group = Passwd, Group
module("cowrie.commands").__path__ = []
module("cowrie.core").__path__ = []


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    parent, _, child = name.rpartition(".")
    setattr(module(parent), child, mod)
    spec.loader.exec_module(mod)
    return mod


TMP = tempfile.mkdtemp()
bait = load("cowrie.core.qpot_bait", os.path.join(PATCH, "qpot_bait.py"))
bait.PLAN_PATH = os.path.join(TMP, "plan.json")
coreutils = load("cowrie.commands.coreutils", os.path.join(PATCH, "coreutils.py"))
# the commands of the patch layer the test gave (coreutils last, as Cowrie loads it)
TABLE = {}
for name in ("curl", "wget", "ssh", "ls"):
    if os.path.exists(os.path.join(PATCH, name + ".py")):
        mod = load("cowrie.commands." + name, os.path.join(PATCH, name + ".py"))
        TABLE.update(mod.commands)
        if name == "ls":
            # ls compares dates with the case's clock
            mod.time = types.SimpleNamespace(time=lambda: STATE["now"], localtime=time.localtime, strftime=time.strftime)
TABLE.update(coreutils.commands)
# cp, which scp runs for a copy between two local paths
TABLE.setdefault("cp", type("Command_cp", (HoneyPotCommand,), {}))

PERSONAS = {"ubuntu-24.04": ("ubuntu", "24.04"), "ubuntu-22.04": ("ubuntu", "22.04"), "debian-13": ("debian", "13"),
            "debian-12": ("debian", "12"), "rhel-9": ("rhel", "9.5"), "centos-7": ("centos", "7"),
            "openwrt": ("openwrt", "21.02.7"), "none": None}


def run(case):
    global CLOCK
    CLOCK = Clock()
    STATE.update(out=[], code=None, events=[], lookups=[], fetches=[], typeahead=[], exec=[],
                 dns=case.get("dns", {}), http=case.get("http", {}), machine=case.get("machine", "x86_64"),
                 config=dict(case.get("config", {})), limit_ok=case.get("limit_ok", True),
                 now=case.get("now", time.time()))
    STATE["config"].setdefault("shell.not_found_style", "bash")
    for cache in (coreutils.qpot_release_seen, coreutils.qpot_packages_seen):
        cache.clear()
    bait.plan.cache_clear()
    bait._hosts.cache_clear()
    with open(bait.PLAN_PATH, "w") as handle:
        json.dump(dict({"version": 1}, **case.get("plan", {})), handle)
    files = dict(case.get("files", {}))
    persona = PERSONAS[case.get("persona", "debian-13")]
    if persona:
        files.setdefault("/etc/os-release", f'ID={persona[0]}\nVERSION_ID="{persona[1]}"\n')
    files.setdefault("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n")
    files.setdefault("/etc/group", "root:x:0:\nbackup:x:34:\n")
    files.setdefault("/root", {"dir": True, "mode": 0o700})
    files.setdefault("/tmp", {"dir": True, "mode": 0o1777})
    mtime = case.get("mtime", 1767225600)
    fs = FS(files, mtime)
    STATE["fs"] = fs
    # the persona's runtime folder: identity.json (when it was installed), apt-packages.json
    ident, packages = case.get("installed"), case.get("packages")
    runtime = os.path.join(TMP, "runtime")
    shutil.rmtree(runtime, ignore_errors=True)
    if ident or packages:
        root = os.path.join(runtime, "honeyfs")
        os.makedirs(root)
        if ident:
            with open(os.path.join(runtime, "identity.json"), "w") as handle:
                json.dump({"installed_at": ident, "booted_at": ident + 86400}, handle)
        if packages:
            with open(os.path.join(runtime, "apt-packages.json"), "w") as handle:
                json.dump({"installed": packages}, handle)
        STATE["config"]["honeypot.contents_path"] = root
    protocol = types.SimpleNamespace(
        fs=fs, environ=dict({"HOME": "/root", "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
                            **(case.get("env") or {})),
        cwd=case.get("cwd", "/root"), hostname=case.get("hostname", "web01"), terminal=case.get("terminal", True),
        stdin=case["stdin"].encode() if "stdin" in case else None, events=Events(), password_input=False,
        user=types.SimpleNamespace(username="root", uid=0, gid=0, windowSize=(24, case.get("columns", 80))))
    protocol.getCommand = lambda name, paths, cwd: TABLE.get(name)
    if case.get("probe") == "bash_variables":
        # what protocol.py sets in the login shell: its environment afterwards, as JSON on stdout
        shell = types.SimpleNamespace(protocol=protocol, environ=dict(protocol.environ))
        coreutils.qpot_bash_variables(shell)
        return {"stdout": json.dumps(shell.environ, sort_keys=True), "stderr": "", "code": 0, "seconds": 0,
                "events": [], "lookups": [], "fetches": [], "files": {}, "cpu": 0, "typeahead": [], "exec": [],
                "exited": True, "password_input": False}
    argv = case["argv"]
    name = case.get("command", argv[0])
    cls = TABLE.get(name) or TABLE.get("/usr/bin/" + name) or TABLE["/bin/" + name]
    cmd = cls(protocol, *argv[1:])
    cmd.qpot_name = getattr(cmd, "qpot_name", argv[0]) if not hasattr(cls, "qpot_name") else cls.qpot_name
    # "memory": the case's peak of allocated bytes (tracemalloc) while the command runs
    if case.get("memory"):
        tracemalloc.start()
    t0 = time.process_time()
    cmd.start()
    for line in case.get("lines", []):
        if line.startswith("@"):
            CLOCK.run(until=CLOCK.now + float(line[1:]))
        elif line == "^C":
            cmd.handle_CTRL_C()
        else:
            cmd.lineReceived(line)
    CLOCK.run()
    cpu = time.process_time() - t0
    peak = 0
    if case.get("memory"):
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
    out = "".join(text for kind, text in STATE["out"] if kind == "o")
    err = "".join(text for kind, text in STATE["out"] if kind == "e")
    listing = {}

    def walk(node, path):
        for child in node[7] if isinstance(node[7], list) else []:
            full = path + "/" + child[0]
            if child[1] == 2:
                listing[full] = {"size": child[4], "mode": child[5], "mtime": child[6],
                                 "b64": base64.b64encode(child[7]).decode() if isinstance(child[7], bytes) else ""}
            elif child[1] == 1:
                walk(child, full)

    walk(fs.root, "")
    return {"stdout": out, "stderr": err, "code": STATE["code"], "seconds": CLOCK.now, "events": STATE["events"],
            "lookups": STATE["lookups"], "fetches": STATE["fetches"], "files": listing, "cpu": cpu,
            "peak": peak, "typeahead": STATE["typeahead"], "exec": STATE["exec"], "exited": cmd.exited,
            "password_input": protocol.password_input}


def main():
    cases = json.load(open(CASES))
    results = []
    for case in cases:
        try:
            results.append(run(case))
        except Exception as err:  # noqa: BLE001 - the test reports it
            import traceback

            results.append({"error": f"{type(err).__name__}: {err}", "trace": traceback.format_exc()})
    print(json.dumps(results))


main()
