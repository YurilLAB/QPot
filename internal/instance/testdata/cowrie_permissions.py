"""Bounded actor/DAC unit sequences; real Cowrie integration is a separate test."""
import importlib.util
import posixpath
from pathlib import Path
import stat
import random
import copy
import os
import sys
import types

root = Path(sys.argv[1])
for package in ("cowrie", "cowrie.core"):
    sys.modules.setdefault(package, types.ModuleType(package))
for name in ("qpot_state", "qpot_permissions"):
    spec = importlib.util.spec_from_file_location("cowrie.core." + name, root / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
state = sys.modules["cowrie.core.qpot_state"]
permissions = sys.modules["cowrie.core.qpot_permissions"]

class Tree:
    """Only the raw node primitive; assertions exercise production policy."""
    def __init__(self):
        self.fs = ["/", 1, 0, 0, 4096, 0o40755, 0, [], None, None]
        self.reads = 0
    def _ensure_private_fs(self):
        pass
    def getfile(self, path, follow_symlinks=True):
        node = self.fs
        for part in path.strip("/").split("/") if path != "/" else []:
            node = next((entry for entry in node[7] if entry[0] == part), None)
            if node is None:
                return None
        return node
    def add(self, path, kind=2, uid=0, gid=0, mode=0o100644, contents=b"", target=None):
        parent = self.getfile(posixpath.dirname(path))
        node = [posixpath.basename(path), kind, uid, gid, len(contents), mode, 0, [] if kind == 1 else contents, target, None]
        parent[7].append(node)
        return node
    def file_contents(self, path):
        self.reads += 1
        node = self.getfile(path)
        if node is None:
            raise FileNotFoundError(path)
        return node[7]
    def chmod(self, path, mode):
        node = self.getfile(path)
        node[5] = stat.S_IFMT(node[5]) | mode
    def chown(self, path, uid, gid):
        node = self.getfile(path)
        if uid != -1:
            node[2] = uid
        if gid != -1:
            node[3] = gid
    def remove(self, path):
        self.getfile(posixpath.dirname(path))[7].remove(self.getfile(path))
    def rename(self, old, new):
        node = self.getfile(old)
        self.remove(old)
        node[0] = posixpath.basename(new)
        parent = self.getfile(posixpath.dirname(new))
        parent[7][:] = [child for child in parent[7] if child[0] != node[0]]
        parent[7].append(node)
    def listdir(self, path):
        return [node[0] for node in self.getfile(path)[7]]
    def mkdir(self, path, uid, gid, size, mode, ctime=None):
        return self.add(path, 1, uid, gid, mode)
    def mkfile(self, path, uid, gid, size, mode, ctime=None):
        return self.add(path, 2, uid, gid, mode)
    def update_size(self, path, size):
        self.getfile(path)[4] = size
    def utime(self, path, atime, mtime):
        self.getfile(path)[6] = mtime
    def stat(self, path, follow_symlinks=True):
        return self.getfile(path)

checks = 0
def denied(operation):
    global checks
    try:
        operation()
    except PermissionError:
        checks += 1
    else:
        raise AssertionError("operation should have been denied")

def failure(operation):
    global checks
    try:
        operation()
    except OSError:
        checks += 1
    else:
        raise AssertionError("operation should have failed")

tree = Tree()
tree.add("/etc", 1, mode=0o40755)
tree.add("/etc/group", contents=b"root:x:0:\nusers:x:100:alice\n")
tree.add("/tmp", 1, mode=0o41777)
tree.add("/private", 1, mode=0o40700)
tree.add("/private/public", contents=b"inaccessible ancestor")
tree.add("/root-secret", mode=0o100600, contents=b"secret")
tree.add("/group-secret", gid=100, mode=0o100640, contents=b"group secret")
tree.add("/tmp/own", uid=1000, gid=1000, mode=0o100600, contents=b"mine")
tree.add("/tmp/foreign", uid=2000, gid=2000, mode=0o100644, contents=b"other")
tree.add("/tmp/ancestor-link", 0, mode=0o120777, target="/private/public")
tree.add("/tmp/cycle-a", 0, mode=0o120777, target="cycle-b")
tree.add("/tmp/cycle-b", 0, mode=0o120777, target="cycle-a")
alice = dict(uid=1000, gid=1000, username="alice", groups=[1000])
bob = dict(uid=2000, gid=2000, username="bob", groups=[2000])
a = permissions.Filesystem(tree, lambda: alice)
b = permissions.Filesystem(tree, lambda: bob)
r = permissions.Filesystem(tree, lambda: dict(uid=0, gid=0, username="root", groups=[0]))
denied(lambda: a.file_contents("/root-secret"))
denied(lambda: a.chmod("/root-secret", 0o777))
denied(lambda: a.file_contents("/tmp/ancestor-link"))
denied(lambda: a.listdir("/private"))
denied(lambda: a.remove("/tmp/foreign"))
denied(lambda: a.rename("/tmp/foreign", "/tmp/stolen"))
denied(lambda: a.mkdir2("/private/new"))
denied(lambda: a.file_contents("/group-secret"))
assert tree.getfile("/root-secret")[5] == 0o100600
assert a.file_contents("/tmp/own") == b"mine"
denied(lambda: b.file_contents("/tmp/own"))
a.chmod("/tmp/own", 0o640)
assert tree.getfile("/tmp/own")[5] == 0o100640
assert r.file_contents("/root-secret") == b"secret"
# Active process groups are a snapshot, not a live re-read of /etc/group.
tree.getfile("/etc/group")[7] = b"root:x:0:\nusers:x:100:alice,bob\n"
denied(lambda: a.file_contents("/group-secret"))
alice["groups"].append(100)
assert a.file_contents("/group-secret") == b"group secret"
a.chown("/tmp/own", -1, 100)
assert tree.getfile("/tmp/own")[3] == 100
denied(lambda: a.chown("/tmp/own", 2000, -1))
failure(lambda: r.rename("/tmp/own", "/absent/destination"))
assert tree.getfile("/tmp/own")[7] == b"mine"
failure(lambda: a.file_contents("/tmp/cycle-a"))
node = tree.getfile("/tmp/own")
a.rename("/tmp/own", "/tmp/renamed")
assert tree.getfile("/tmp/renamed") is node
r.mkdir2("/tmp/directory")
failure(lambda: r.rename("/tmp/renamed", "/tmp/directory"))
assert tree.getfile("/tmp/renamed") is node
# Overwriting an existing file retains identity, ownership and mode.
a.mkfile("/tmp/renamed", 1000, 1000, 0, 0o100666)
assert tree.getfile("/tmp/renamed") is node and node[2:4] == [1000, 100] and node[5] == 0o100640
command = types.SimpleNamespace(user=bob, pp=types.SimpleNamespace(tpot_sudo=True))
assert state.effective_user(command)["uid"] == 0 and bob["uid"] == 2000
command.pp.tpot_sudo_user = dict(alice)
assert state.effective_user(command)["uid"] == 1000
# Missing or invalid actor credentials fail closed.
invalid = permissions.Filesystem(tree, lambda: {})
denied(lambda: invalid.file_contents("/root-secret"))
tree.add("/proc", 1, mode=0o40555)
tree.add("/proc/control", mode=0o100644, contents=b"kernel-state\n")
tree.add("/proc/directory", 1, mode=0o40555)
tree.add("/proc-data", mode=0o100600, contents=b"ordinary-file")
tree.add("/tmp/shared-write", mode=0o100666, contents=b"shared")
tree.add("/tmp/proc-link", 0, mode=0o120777, target="/proc/control")
snapshot = copy.deepcopy(tree.fs)
for operation in (
    lambda: r.mkfile("/proc/new", 0, 0, 0, 0o100644),
    lambda: r.mkfile("/proc/control", 0, 0, 0, 0o100644),
    lambda: r.mkdir2("/proc/new-directory"),
    lambda: r.chmod("/proc/control", 0o600),
    lambda: r.chown("/proc/control", 1000, 1000),
    lambda: r.utime("/proc/control", 1, 1),
    lambda: r.touch("/proc/control"),
    lambda: r.remove("/proc/control"),
    lambda: r.rmdir("/proc/directory"),
    lambda: r.rename("/proc/control", "/tmp/from-proc"),
    lambda: r.rename("/tmp/renamed", "/proc/moved"),
    lambda: r.open("/proc/control", os.O_WRONLY, 0o644),
    lambda: r.open("/proc/control", os.O_RDONLY | os.O_TRUNC, 0o644),
    lambda: r.check_write("/tmp/proc-link"),
):
    denied(operation)
    assert tree.fs == snapshot
assert r.file_contents("/proc/control") == b"kernel-state\n"
r.remove("/tmp/proc-link")
assert r.getfile("/tmp/proc-link", False) is None and r.file_contents("/proc/control") == b"kernel-state\n"
r.mkfile("/proc-data", 0, 0, 0, 0o100600)
assert tree.getfile("/proc-data")[4] == 0
tree.getfile("/tmp/renamed")[6] = 100
a.touch("/tmp/renamed")
assert tree.getfile("/tmp/renamed")[6] > 100
tree.getfile("/tmp/shared-write")[6] = 100
a.touch("/tmp/shared-write")
assert tree.getfile("/tmp/shared-write")[6] > 100
denied(lambda: b.touch("/tmp/renamed"))
# Enumerate every permission mode against an independent owner/group/other
# reference, including the owner precedence rule when group bits are broader.
for mode in range(512):
    node = tree.getfile("/root-secret")
    node[5] = stat.S_IFREG | mode
    for uid, gid, groups in ((0, 0, [0]), (1000, 1000, [1000]), (2000, 1000, [1000]), (2000, 2000, [2000])):
        node[2], node[3] = 1000, 1000
        process = dict(uid=uid, gid=gid, username="fixture", groups=groups)
        view = permissions.Filesystem(tree, lambda: process)
        reference = uid == 0 or bool(mode & (0o400 if uid == 1000 else 0o40 if 1000 in groups else 0o4))
        try:
            view.file_contents("/root-secret")
            allowed = True
        except PermissionError:
            allowed = False
        assert allowed == reference, (mode, uid, gid, groups)
# Deterministic malformed-path fuzzing checks bounds, symlink cycles and
# read-only operations preserving the complete tree. This does not claim
# coverage-guided fuzzing of the Twisted transport.
rng = random.Random(0x51504f54)
parts = ["tmp", "private", "ancestor-link", "cycle-a", "cycle-b", "renamed", "missing", ".", "..", "", chr(0), "é"]
baseline = copy.deepcopy(tree.fs)
for _ in range(5000):
    path = "/" + "/".join(rng.choice(parts) for _ in range(rng.randrange(1, 40)))
    try:
        a.getfile(path)
    except OSError:
        pass
assert tree.fs == baseline
failure(lambda: a.getfile("/" + "x" * 4097))
assert checks >= 15
print(f"PASS actor permission sequences ({checks} explicit failure assertions plus state/identity checks, 2048 DAC reference cases and 5000 malformed paths)")
