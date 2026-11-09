"""Transition/property checks for the finite OpenWrt package adapter.

The separate pinned-image acceptance suite exercises actual opkg metadata,
getCommand, which and filesystem APIs. This fixture keeps transactions fast and
deterministic while checking their independent observable invariants.
"""

import ast
import contextlib
import copy
import importlib.util
import hashlib
import io
import json
from pathlib import Path
import runpy
import sys
import types
import zipfile

patch = Path(sys.argv[1])
sys.argv = [str(Path(__file__).with_name("cowrie_users.py")), str(patch / "adduser.py")]
with contextlib.redirect_stdout(io.StringIO()):
    fixture = runpy.run_path(str(Path(__file__).with_name("cowrie_users.py")))
FS, node, Command = fixture["FS"], fixture["node"], fixture["Command"]
module = fixture["module"]
state = sys.modules["cowrie.core.qpot_state"]


def inline(function):
    def run(*args, **kwargs):
        result = function(*args, **kwargs)
        if isinstance(result, types.GeneratorType):
            for _ in result:
                pass
    return run


module("twisted")
module("twisted.internet")
module("twisted.internet.defer").inlineCallbacks = inline
commands = module("cowrie.commands")
apt = module("cowrie.commands.apt")
commands.apt = apt
branch = "22.03"
versions = {
    "21.02": {"curl": "7.83.1-4.1", "libcurl4": "7.83.1-4.1", "libnghttp2-14": "1.43.0-1"},
    "22.03": {"curl": "8.6.0-1", "libcurl4": "8.6.0-1", "libnghttp2-14": "1.44.0-1", "libmbedtls12": "2.28.8-1"},
}
base = {"libc": "1", "ca-bundle": "20210119-1", "libwolfssl5.5.3.99a5b54a": "5.5.3-stable-1"}
apt.tpot_opkg = lambda key, fallback="": {"opkg_release": branch + ".7", "opkg_arch": "mipsel_24kc"}.get(key, fallback)
apt.tpot_opkg_installed = lambda: dict(base)
apt.tpot_opkg_names = lambda: {name: "packages" for name in list(versions[branch]) + ["tcpdump"]}
apt.tpot_opkg_meta = lambda: {name: (version, "") for name, version in versions[branch].items()}
apt.tpot_opkg_version = lambda name: versions[branch][name]
apt.tpot_upstream = lambda version: version.rpartition("-")[0] or version
apt.tpot_opkg_url = lambda feed: "https://downloads.openwrt.org/releases/" + branch + ".7/packages/mipsel_24kc/" + feed


def mark(protocol, name, version):
    found = getattr(protocol, "tpot_installed", None)
    if found is None:
        protocol.tpot_installed = found = {}
    found[name] = apt.tpot_upstream(version)


apt.tpot_mark_installed = mark


class Upstream(Command):
    def start(self):
        if self.args == ["update"]:
            self.protocol.tpot_opkg_lists = True
        elif self.args == ["list-installed"]:
            self.write("".join(f"{name} - {version}\n" for name, version in sorted({**base, **getattr(self.protocol, "tpot_opkg_added", {})}.items())))
        self.exit(0)

    def tpot_usage(self, text):
        self.errorWrite(text)
        self.exit(1)


apt.Command_opkg = Upstream
spec = importlib.util.spec_from_file_location("cowrie.commands.opkg", patch / "opkg.py")
opkg = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = opkg
spec.loader.exec_module(opkg)


class Protocol:
    tpot_opkg_added = state.SharedAttribute("tpot_opkg_added")
    tpot_opkg_lists = state.SharedAttribute("tpot_opkg_lists")
    tpot_installed = state.SharedAttribute("tpot_installed")

    def __init__(self, fs, avatar=None):
        self.fs, self.hostname = fs, "OpenWrt"
        self.user = avatar or types.SimpleNamespace(server=types.SimpleNamespace(fs=fs, hostname=self.hostname))


def mkdir(self, path, uid, gid, size, mode, ctime=None):
    if self.newcount >= 10000:
        raise OSError("quota")
    self._ensure_private_fs()
    self.add(path, node(Path(path).name, True, uid=uid, gid=gid, mode=mode & 0o7777))
    self.newcount += 1


FS.mkdir = mkdir


def run(protocol, arguments, uid=0):
    result = opkg.Command_opkg.__new__(opkg.Command_opkg)
    result.args, result.protocol, result.fs = arguments, protocol, protocol.fs
    result.user, result.pp = {"uid": uid, "gid": uid, "username": "root" if uid == 0 else "debian"}, None
    result.out, result.err, result.code, result.exited = "", "", None, False
    result.start()
    return result


coreutils = module("cowrie.commands.coreutils")
coreutils.qpot_os_release = lambda fs: ("openwrt", (22, 3))
curl_tree = ast.parse((patch / "curl.py").read_text())
curl = next(item for item in curl_tree.body if isinstance(item, ast.ClassDef) and item.name == "Command_curl")
selected = [item for item in curl.body if isinstance(item, ast.FunctionDef) and item.name in ("qpot_version", "qpot_version_text", "start")]
namespace = {"HoneyPotCommand": Command, "inlineCallbacks": inline, "re": __import__("re")}
for item in curl_tree.body:
    if isinstance(item, ast.Assign):
        for target in item.targets:
            if isinstance(target, ast.Name) and target.id in ("QPOT_CURL_RELEASES", "QPOT_CURL_RECORDED", "QPOT_CURL_BUILDS"):
                namespace[target.id] = ast.literal_eval(item.value)
narrowed = ast.ClassDef(name="Curl", bases=[ast.Name(id="HoneyPotCommand", ctx=ast.Load())], keywords=[], body=selected, decorator_list=[])
exec(compile(ast.fix_missing_locations(ast.Module(body=[narrowed], type_ignores=[])), str(patch / "curl.py"), "exec"), namespace)


checks = []
def check(name, value):
    assert value, name
    checks.append(name)


for branch in ("21.02", "22.03"):
    fs = FS()
    protocol = Protocol(fs)
    before = copy.deepcopy(fs.fs)
    check(branch + " install before update fails atomically", run(protocol, ["install", "curl"]).code == 255 and fs.fs == before)
    check(branch + " update delegated", run(protocol, ["update"]).code == 0 and protocol.tpot_opkg_lists)
    check(branch + " install succeeds", run(protocol, ["install", "curl"]).code == 0)
    check(branch + " actual executable node", fs.getfile("/usr/bin/curl")[5] & 0o111)
    with zipfile.ZipFile(patch / "opkg_assets.zip") as archive:
        package_manifest = json.loads(archive.read("manifest.json"))["packages"][branch]
    for package in package_manifest.values():
        for entry in package["files"]:
            if entry["target"]:
                continue
            content = fs.file_contents(entry["path"])
            check(branch + " authentic bytes/stat " + entry["path"], len(content) == fs.getfile(entry["path"])[4] == entry["size"] and hashlib.sha256(content).hexdigest() == entry["sha256"])
            check(branch + " authentic mode " + entry["path"], fs.getfile(entry["path"])[5] & 0o777 == entry["mode"])
    saved = fs.file_contents("/usr/bin/curl")
    fs.getfile("/usr/bin/curl")[7] = b"local change"
    check(branch + " readonly snapshot unaffected by VFS content changes", opkg.package_assets()[branch]["curl"][1][0][4] == saved)
    fs.getfile("/usr/bin/curl")[7] = saved
    check(branch + " package version matches marker", protocol.tpot_installed["curl"] == apt.tpot_upstream(versions[branch]["curl"]))
    later = Protocol(fs, protocol.user)
    check(branch + " second channel sees metadata", later.tpot_opkg_added is protocol.tpot_opkg_added)
    check(branch + " later package query", versions[branch]["curl"] in run(later, ["list-installed"]).out)
    check(branch + " status has current version", "Version: " + versions[branch]["curl"] in run(later, ["status", "curl"]).out)
    check(branch + " files lists executable", "/usr/bin/curl" in run(later, ["files", "curl"]).out)
    check(branch + " on-disk package list", fs.file_contents("/usr/lib/opkg/info/curl.list") == b"/usr/bin/curl\n")
    check(branch + " on-disk status", ("Package: curl\nVersion: " + versions[branch]["curl"]).encode() in fs.file_contents("/usr/lib/opkg/status"))
    client = namespace["Curl"].__new__(namespace["Curl"])
    client.protocol, client.fs = later, fs
    check(branch + " curl version metadata", client.qpot_version() == tuple(int(n) for n in apt.tpot_upstream(versions[branch]["curl"]).split(".")))
    text = client.qpot_version_text(client.qpot_version())
    check(branch + " curl MIPS musl build", "mipsel-openwrt-linux-musl" in text and "x86_64" not in text)
    check(branch + " curl package identity consistent", text.startswith("curl " + apt.tpot_upstream(versions[branch]["curl"])))
    check(branch + " shared libraries available", opkg.curl_load_error(later, fs) is None)
    before = copy.deepcopy(fs.fs)
    check(branch + " unsupported install not invented", run(later, ["install", "tcpdump"]).code == 255 and fs.fs == before)
    for options in (["--download-only", "install", "curl"], ["-d", "/tmp/target", "install", "curl"], ["install", "curl", "--download-only"]):
        check(branch + " unsupported mutation flags rejected " + options[0], run(later, options).code == 255 and fs.fs == before)
    check(branch + " required library remove blocked", run(later, ["remove", "libcurl4"]).code == 255 and fs.fs == before)
    check(branch + " nonroot install denied", run(later, ["install", "curl"], 1000).code == 255)
    check(branch + " nonroot update denied", run(later, ["update"], 1000).code == 255)
    parent = fs.getfile("/usr/lib")
    parent[7] = [entry for entry in parent[7] if entry[0] != "libcurl.so.4"]
    check(branch + " missing library detected", "libcurl.so.4" in opkg.curl_load_error(later, fs))
    client.out, client.err, client.code, client.exited = "", "", None, False
    client.args = ["--version"]
    client.start()
    check(branch + " actual curl refuses missing loader dependency", client.code == 127)
    check(branch + " reinstall repairs dependency", run(later, ["--force-reinstall", "install", "curl"]).code == 0 and opkg.curl_load_error(later, fs) is None)
    check(branch + " remove succeeds", run(later, ["remove", "curl"]).code == 0)
    check(branch + " executable disappears", not fs.lexists("/usr/bin/curl"))
    check(branch + " marker disappears", "curl" not in later.tpot_installed)
    check(branch + " status disappears", b"Package: curl\n" not in fs.file_contents("/usr/lib/opkg/status"))
    check(branch + " clean connection isolated", not hasattr(Protocol(FS()), "tpot_opkg_added"))

quota = FS()
quota.newcount = 9999
protocol = Protocol(quota)
protocol.tpot_opkg_lists = True
before = copy.deepcopy(quota.fs)
check("quota rejects whole package transaction", run(protocol, ["install", "curl"]).code == 255 and quota.fs == before and not hasattr(protocol, "tpot_opkg_added"))

# Use the actual actor facade: copy.copy(facade) must never proxy staging
# assignments to the live tree. A failed transaction leaves bytes and quota.
spec = importlib.util.spec_from_file_location("cowrie.core.qpot_permissions", patch / "qpot_permissions.py")
permissions = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = permissions
spec.loader.exec_module(permissions)
quota = FS()
quota.newcount = 9999
view = permissions.Filesystem(quota, lambda: {"uid": 0, "gid": 0})
protocol = Protocol(view)
protocol.tpot_opkg_lists = True
before = copy.deepcopy(quota.fs)
check("actor facade failure is atomic", run(protocol, ["install", "curl"]).code == 255 and quota.fs == before and quota.newcount == 9999)
quota.newcount = 0
check("actor facade install commits raw tree", run(protocol, ["install", "curl"]).code == 0 and quota.lexists("/usr/bin/curl"))
check("actor facade remove commits raw tree", run(protocol, ["remove", "curl"]).code == 0 and not quota.lexists("/usr/bin/curl"))
# The trusted operator snapshot must be finite and digest authenticated. A bad
# asset never reaches the live VFS or shared package metadata.
opkg.package_assets.cache_clear()
original_digest = opkg._ASSETS_SHA256
opkg._ASSETS_SHA256 = "0" * 64
fresh = FS()
protocol = Protocol(fresh)
protocol.tpot_opkg_lists = True
before = copy.deepcopy(fresh.fs)
check("corrupt asset rejects atomic install", run(protocol, ["install", "curl"]).code == 255 and fresh.fs == before and not hasattr(protocol, "tpot_opkg_added"))
opkg._ASSETS_SHA256 = original_digest
opkg.package_assets.cache_clear()
original_max = opkg._ASSETS_MAX_COMPRESSED
opkg._ASSETS_MAX_COMPRESSED = 32
check("oversized asset rejects atomic install", run(protocol, ["install", "curl"]).code == 255 and fresh.fs == before and not hasattr(protocol, "tpot_opkg_added"))
opkg._ASSETS_MAX_COMPRESSED = original_max
opkg.package_assets.cache_clear()
original_expanded = opkg._ASSETS_MAX_EXPANDED
opkg._ASSETS_MAX_EXPANDED = 32
check("expanded asset bounds reject atomic install", run(protocol, ["install", "curl"]).code == 255 and fresh.fs == before and not hasattr(protocol, "tpot_opkg_added"))
opkg._ASSETS_MAX_EXPANDED = original_expanded
opkg.package_assets.cache_clear()
check("snapshot loader returns immutable package map", isinstance(opkg.package_assets(), types.MappingProxyType))
print(json.dumps({"count": len(checks), "checks": checks, "result": "PASS"}))
