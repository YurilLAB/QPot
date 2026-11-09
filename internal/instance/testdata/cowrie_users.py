"""Deterministic account-transition checks; the actual-image harness checks VFS integration."""

import copy
import importlib.util
import json
import posixpath
from pathlib import Path
import stat
import sys
import types


def module(name):
    result = types.ModuleType(name)
    sys.modules[name] = result
    return result


for name in ("cowrie", "cowrie.core", "cowrie.shell", "cowrie.shell.command", "cowrie.shell.fs", "cowrie.shell.pwd"):
    module(name)


class Command:
    exited = False

    def write(self, text):
        self.out += text

    def errorWrite(self, text):
        self.err += text

    def exit(self, status=0):
        self.code, self.exited = status, True


sys.modules["cowrie.shell.command"].HoneyPotCommand = Command
names = "A_NAME A_TYPE A_UID A_GID A_SIZE A_MODE A_CTIME A_CONTENTS A_TARGET A_REALFILE".split()
for number, name in enumerate(names):
    setattr(sys.modules["cowrie.shell.fs"], name, number)
sys.modules["cowrie.shell.fs"].T_DIR = 1
sys.modules["cowrie.shell.fs"].T_FILE = 2


class Passwd:
    def getpwnam(self, name):
        for row in self.passwd:
            if row["pw_name"] == name:
                return row
        raise KeyError(name)

    def getpwuid(self, uid):
        for row in self.passwd:
            if row["pw_uid"] == uid:
                return row
        raise KeyError(uid)


sys.modules["cowrie.shell.pwd"].Passwd = Passwd
state_spec = importlib.util.spec_from_file_location("cowrie.core.qpot_state", Path(sys.argv[1]).with_name("qpot_state.py"))
state_module = importlib.util.module_from_spec(state_spec)
sys.modules[state_spec.name] = state_module
state_spec.loader.exec_module(state_module)
spec = importlib.util.spec_from_file_location("cowrie.commands.adduser", sys.argv[1])
users = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = users
spec.loader.exec_module(users)


def node(name, directory=False, contents=b"", uid=0, gid=0, mode=0o644):
    return [name, 1 if directory else 2, uid, gid, 4096 if directory else len(contents),
            (stat.S_IFDIR if directory else stat.S_IFREG) | mode, 1700000000, [] if directory else contents, None, None]


class FS:
    def __init__(self):
        self.fs = node("/", True, mode=0o755)
        self.newcount, self._private_fs = 0, False
        for path in ("/etc", "/etc/skel", "/home", "/root", "/bin"):
            self.add(path, node(posixpath.basename(path), True, mode=0o755))
        files = {
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndebian:x:1000:1000::/home/debian:/bin/bash\n",
            "/etc/group": "root:x:0:\ndebian:x:1000:\nsudo:x:27:\nusers:x:100:\n",
            "/etc/shadow": "root:!:19000:0:99999:7:::\ndebian:!:19000:0:99999:7:::\n",
            "/etc/gshadow": "root:!::\ndebian:!::\nsudo:!::\nusers:!::\n",
            "/etc/skel/.bashrc": "export EDITOR=vi\n",
        }
        for path, text in files.items():
            self.add(path, node(posixpath.basename(path), contents=text.encode(),
                                mode=0o640 if path.endswith(("shadow", "gshadow")) else 0o644))

    def getfile(self, path, follow_symlinks=True):
        current = self.fs
        for part in path.strip("/").split("/") if path.strip("/") else []:
            if current[1] != 1:
                return None
            current = next((item for item in current[7] if item[0] == part), None)
            if current is None:
                return None
        return current

    def add(self, path, entry):
        self.getfile(posixpath.dirname(path))[7].append(entry)

    def file_contents(self, path):
        entry = self.getfile(path)
        if entry is None or entry[1] != 2:
            raise FileNotFoundError(path)
        return entry[7]

    def lexists(self, path):
        return self.getfile(path, False) is not None

    def isdir(self, path):
        entry = self.getfile(path)
        return entry is not None and entry[1] == 1

    def chown(self, path, uid, gid):
        self._ensure_private_fs()
        entry = self.getfile(path)
        if uid != -1:
            entry[2] = uid
        if gid != -1:
            entry[3] = gid

    def _ensure_private_fs(self):
        if not self._private_fs:
            self.fs = copy.deepcopy(self.fs)
            self._private_fs = True


def command(fs, name, args, uid=0, start=True):
    result = users.commands[name].__new__(users.commands[name])
    result.args, result.fs = args, fs
    result.user = {"uid": uid, "gid": uid, "username": "root" if uid == 0 else "debian"}
    result.protocol = types.SimpleNamespace(password_input=False)
    result.input_data = None
    result.cwd = "/"
    result.out, result.err, result.code, result.exited = "", "", None, False
    if start:
        result.start()
    return result


checks = []


def check(name, condition):
    assert condition, name
    checks.append(name)


fs = FS()
baseline = copy.deepcopy(fs.fs)
created = command(fs, "useradd", ["-m", "-u", "1200", "-G", "sudo", "-s", "/bin/bash", "analyst"])
check("finite successful creation", created.code == 0 and created.exited)
check("passwd view", command(fs, "getent", ["passwd", "analyst"]).out == "analyst:x:1200:1200::/home/analyst:/bin/bash\n")
check("id follows creation", command(fs, "id", ["analyst"]).out == "uid=1200(analyst) gid=1200(analyst) groups=1200(analyst),27(sudo)\n")
check("groups follows creation", command(fs, "groups", ["analyst"]).out == "analyst : analyst sudo\n")
check("numeric identity", command(fs, "id", ["-u", "analyst"]).out == "1200\n")
check("group-name identity", command(fs, "id", ["-Gn", "analyst"]).out == "analyst sudo\n")
check("home ownership", fs.getfile("/home/analyst")[2:4] == [1200, 1200])
check("home mode", stat.S_IMODE(fs.getfile("/home/analyst")[5]) == 0o750)
check("skeleton content", fs.file_contents("/home/analyst/.bashrc") == b"export EDITOR=vi\n")
check("skeleton ownership", fs.getfile("/home/analyst/.bashrc")[2:4] == [1200, 1200])
check("base tree isolated", baseline[7] != fs.fs[7] and FS().file_contents("/etc/passwd").count(b"analyst") == 0)
check("private shadow permissions", stat.S_IMODE(fs.getfile("/etc/shadow")[5]) == 0o640)
check("shadow denied unprivileged", command(fs, "getent", ["shadow", "analyst"], 1000).code == 2)

for args, code in [(["analyst"], 9), (["-u", "1200", "duplicate"], 4), (["-g", "missing", "nobody2"], 6),
                   (["-G", "missing", "nobody2"], 6), (["-u", "-1", "nobody2"], 3),
                   (["-d", "relative/path", "nobody2"], 3), (["bad:name"], 3), (["../../root"], 3),
                   (["-c", "bad\nfield", "nobody2"], 3), (["-Z", "nobody2"], 2)]:
    before = copy.deepcopy(fs.fs)
    failed = command(fs, "useradd", args)
    check("invalid operation atomic " + repr(args), failed.code == code and fs.fs == before)
before = copy.deepcopy(fs.fs)
check("nonroot denied", command(fs, "useradd", ["-m", "outsider"], 1000).code == 1 and fs.fs == before)

other = FS()
check("explicit primary group", command(other, "useradd", ["-m", "-g", "users", "helper"]).code == 0)
check("primary group name resolved", command(other, "id", ["helper"]).out == "uid=1001(helper) gid=100(users) groups=100(users)\n")
check("existing primary not duplicated", other.file_contents("/etc/group").count(b"users:") == 1)
nohome = FS()
check("useradd default no home", command(nohome, "useradd", ["serviceuser"]).code == 0 and not nohome.lexists("/home/serviceuser"))
system = FS()
check("system allocation", command(system, "useradd", ["-r", "daemon2"]).code == 0 and b"daemon2:x:999:999:" in system.file_contents("/etc/passwd"))

quota = FS()
quota.newcount = 9999
before = copy.deepcopy(quota.fs)
check("quota refuses entire transaction", command(quota, "useradd", ["-m", "limited"]).code == 10 and quota.fs == before)
broken = FS()
broken.getfile("/etc/group")[7] = b"malformed\n"
before = copy.deepcopy(broken.fs)
check("corrupt group no partial user", command(broken, "useradd", ["broken"]).code == 1 and broken.fs == before)

interactive = FS()
pending = command(interactive, "adduser", ["--gecos", "", "interactive"])
check("password prompt pending", pending.code is None and pending.protocol.password_input)
pending.lineReceived("test-password")
pending.lineReceived("test-password")
check("interactive finite success", pending.code == 0 and not pending.protocol.password_input)
shadow = interactive.file_contents("/etc/shadow").decode()
check("interactive password genuinely hashed", "interactive:$6$" in shadow and "test-password" not in shadow)
check("new account password accepted", users.qpot_new_user_auth(interactive, "interactive", "test-password") is True)
check("new account wrong password rejected", users.qpot_new_user_auth(interactive, "interactive", "different") is False)
check("new locked account rejected", users.qpot_new_user_auth(fs, "analyst", "anything") is False)
check("baseline account policy preserved", users.qpot_new_user_auth(fs, "root", "anything") is None)
check("new user auth isolated to its filesystem", users.qpot_new_user_auth(FS(), "analyst", "anything") is None)
check("known libc SHA512-crypt vector", users.qpot_hash_password("test-password", "salt1234") == "$6$salt1234$JqOdoGwZ6SfV3MgSFFdKrlqZnxH9v9w/gUoO8189UNtme6sWlcvIFwPqr95Z5BKC9OOaiBXZzBYLXnhhHxszM/")
check("UTF8 libc SHA512-crypt vector", users.qpot_hash_password("páss-word", "fixtureSalt") == "$6$fixtureSalt$uSdIgiv1CZKVy8U5EB1iyZwLsK.o5BsKxP.kzgrQL8zbgBC8e9ZQjmaaLMyTU2Jb6vyZpHAZEUwm565jU91DR.")

conflict = FS()
pending = command(conflict, "adduser", ["--gecos", "", "pending"])
pending.lineReceived("test-password")
check("other channel creates user", command(conflict, "useradd", ["arrived"]).code == 0)
before = copy.deepcopy(conflict.fs)
pending.lineReceived("test-password")
check("interactive conflict does not clobber another channel", pending.code == 10 and conflict.fs == before and not conflict.lexists("/home/pending"))
cancelled = FS()
pending = command(cancelled, "adduser", ["cancelled"])
before = copy.deepcopy(cancelled.fs)
pending.eofReceived()
check("EOF cancels atomic creation", pending.code == 1 and cancelled.fs == before and not pending.protocol.password_input)

# Existing directories are not silently re-owned, and existing account nodes
# remain the same objects after later in-place account updates.
existing = FS()
existing.add("/home/already", node("already", True, uid=111, gid=222, mode=0o700))
check("existing home preserved", command(existing, "useradd", ["-m", "already"]).code == 0 and existing.getfile("/home/already")[2:4] == [111, 222])
account_node = existing.getfile("/etc/passwd")
check("later user succeeds", command(existing, "useradd", ["second"]).code == 0)
check("existing account node identity preserved", existing.getfile("/etc/passwd") is account_node)
missing = FS()
missing.getfile("/etc")[7] = [n for n in missing.getfile("/etc")[7] if n[0] not in ("shadow", "gshadow")]
check("missing shadow databases created", command(missing, "useradd", ["shadowuser"]).code == 0)
check("new shadow private", stat.S_IMODE(missing.getfile("/etc/shadow")[5]) == 0o600)
check("new gshadow private", stat.S_IMODE(missing.getfile("/etc/gshadow")[5]) == 0o600)
mismatch = FS()
pending = command(mismatch, "adduser", ["--gecos", "", "wrongpass"])
before = copy.deepcopy(mismatch.fs)
pending.lineReceived("test-password")
pending.lineReceived("different")
check("password mismatch leaves no account", pending.code == 1 and mismatch.fs == before and not pending.protocol.password_input)
full = FS()
pending = command(full, "adduser", ["profile"])
for line in ["test-password", "test-password", "Operator", "", "", "", "", ""]:
    pending.lineReceived(line)
check("finite five-field information prompts", pending.code == 0 and "Favorite movie" not in pending.out)
check("GECOS persisted", ":Operator,,,,:/home/profile:" in full.file_contents("/etc/passwd").decode())
help_fs = FS()
before = copy.deepcopy(help_fs.fs)
check("unprivileged help no mutation", command(help_fs, "useradd", ["--help"], 1000).code == 0 and help_fs.fs == before)
comments = FS()
comments.getfile("/etc/passwd")[7] = b"# local accounts\n\n" + comments.file_contents("/etc/passwd")
comments.getfile("/etc/passwd")[4] = len(comments.getfile("/etc/passwd")[7])
check("comments survive account creation", command(comments, "useradd", ["preserved"]).code == 0 and comments.file_contents("/etc/passwd").startswith(b"# local accounts\n\n"))
longname = "a" * 32
check("32-character username accepted", command(FS(), "useradd", [longname]).code == 0)
check("33-character username rejected", command(FS(), "useradd", [longname + "a"]).code == 3)
check("empty explicit group rejected", command(FS(), "useradd", ["-g", "", "emptygroup"]).code == 6)
passwords = FS()
check("prepare user for chpasswd", command(passwords, "useradd", ["pwuser"]).code == 0)
update = command(passwords, "chpasswd", [], start=False)
update.input_data = b"pwuser:test-password\n"
update.start()
check("chpasswd persists real hash", update.code == 0 and users.qpot_new_user_auth(passwords, "pwuser", "test-password") is True)
check("chpasswd wrong password rejected", users.qpot_new_user_auth(passwords, "pwuser", "different") is False)
before = copy.deepcopy(passwords.fs)
update = command(passwords, "chpasswd", [], start=False)
update.input_data = b"pwuser:changed\nmissing:password\n"
update.start()
check("chpasswd all-or-nothing invalid records", update.code == 1 and passwords.fs == before)
update = command(passwords, "passwd", ["pwuser"])
update.lineReceived("changed-password")
update.lineReceived("changed-password")
check("passwd mutation persists", update.code == 0 and users.qpot_new_user_auth(passwords, "pwuser", "changed-password") is True)
check("old password no longer accepted", users.qpot_new_user_auth(passwords, "pwuser", "test-password") is False)
check("nonroot other-user password denied", command(passwords, "passwd", ["pwuser"], 1000).code == 1)
ownership = FS()
check("ownership target created", command(ownership, "useradd", ["-m", "-u", "1200", "operator"]).code == 0)
ownership.add("/home/payload", node("payload", contents=b"data", mode=0o4755))
check("chown changes named owner and group", command(ownership, "chown", ["operator:operator", "/home/payload"]).code == 0 and ownership.getfile("/home/payload")[2:4] == [1200, 1200])
check("chown clears setuid on ownership change", not (ownership.getfile("/home/payload")[5] & 0o6000))
check("chgrp numeric group", command(ownership, "chgrp", ["100", "/home/payload"]).code == 0 and ownership.getfile("/home/payload")[3] == 100)
before = copy.deepcopy(ownership.fs)
check("unknown owner no mutation", command(ownership, "chown", ["missing", "/home/payload"]).code == 1 and ownership.fs == before)
check("nonroot cannot take ownership", command(ownership, "chown", ["debian", "/home/payload"], 1000).code == 1 and ownership.fs == before)
check("missing path fails", command(ownership, "chown", ["root", "/not-here"]).code == 1)
check("partial group chown", command(ownership, "chown", [":sudo", "/home/payload"]).code == 0 and ownership.getfile("/home/payload")[3] == 27)
check("numeric unknown owner valid", command(ownership, "chown", ["1555", "/home/payload"]).code == 0 and ownership.getfile("/home/payload")[2] == 1555)
check("recursive chown", command(ownership, "chown", ["-R", "operator:operator", "/home/operator"]).code == 0 and ownership.getfile("/home/operator/.bashrc")[2:4] == [1200, 1200])
link = node("escape")
link[1], link[8], link[5] = 0, "/etc/passwd", stat.S_IFLNK | 0o777
ownership.add("/home/operator/escape", link)
check("recursive symlink remains physical", command(ownership, "chown", ["-R", "1555", "/home/operator"]).code == 0 and ownership.getfile("/etc/passwd")[2] == 0 and ownership.getfile("/home/operator/escape")[2] == 1555)
loop = node("loop")
loop[1], loop[8], loop[5] = 0, "/home/loop", stat.S_IFLNK | 0o777
ownership.add("/home/loop", loop)
check("symlink loop bounded", command(ownership, "chown", ["root", "/home/loop"]).code == 1)
unicode_db = FS()
check("Unicode GECOS remains one Unix record", command(unicode_db, "useradd", ["-c", "Operator\u2028HQ", "unicodeuser"]).code == 0 and users.qpot_passwd(unicode_db).getpwnam("unicodeuser")["pw_gecos"] == "Operator\u2028HQ")
check("Unicode record survives later updates", command(unicode_db, "useradd", ["lateruser"]).code == 0 and "Operator\u2028HQ" in unicode_db.file_contents("/etc/passwd").decode())
loop_fs = FS()
loop = node("loop")
loop[1], loop[8], loop[5] = 0, "/home/loop", stat.S_IFLNK | 0o777
loop_fs.add("/home/loop", loop)
before = copy.deepcopy(loop_fs.fs)
check("home-parent symlink loop rejected atomically", command(loop_fs, "useradd", ["-m", "-d", "/home/loop/user", "loopuser"]).code != 0 and loop_fs.fs == before)
huge_ids = FS()
huge_ids.getfile("/etc/passwd")[7] += ("baduid:x:" + "9" * 5000 + ":0::/:/bin/sh\n").encode()
huge_ids.getfile("/etc/passwd")[4] = len(huge_ids.getfile("/etc/passwd")[7])
check("oversized UID rejects safely", command(huge_ids, "id", ["baduid"]).code == 1)
huge_groups = FS()
huge_groups.getfile("/etc/group")[7] += ("badgroup:x:" + "9" * 5000 + ":debian\n").encode()
huge_groups.getfile("/etc/group")[4] = len(huge_groups.getfile("/etc/group")[7])
check("oversized GID rejects safely", command(huge_groups, "groups", ["debian"]).code == 1)
credential = FS()
credential.getfile("/etc/passwd")[7] = credential.file_contents("/etc/passwd").replace(b"debian:x:1000:1000:", b"debian:x:1000:100:")
check("id current primary gid stays credential snapshot", command(credential, "id", [], 1000).out.startswith("uid=1000(debian) gid=1000(debian)"))
check("id named user follows modified database", command(credential, "id", ["debian"], 1000).out.startswith("uid=1000(debian) gid=100(users)"))
check("groups current primary stays credential snapshot", command(credential, "groups", [], 1000).out.startswith("debian"))
malformed = FS()
command(malformed, "useradd", ["brokenhash"])
users.qpot_set_passwords(malformed, [("brokenhash", "$6$salt$é")], True)
check("malformed nonASCII hash rejects safely", users.qpot_new_user_auth(malformed, "brokenhash", "ordinary-local-test") is False)
sudo = FS()
original_user = {"uid": 1000, "gid": 1000, "username": "debian"}
run = command(sudo, "useradd", ["sudoadded"], 1000, start=False)
run.user = original_user
run.pp = types.SimpleNamespace(tpot_sudo=True)
run.start()
check("pinned sudo pipe can create user", run.code == 0 and users.qpot_passwd(sudo).getpwnam("sudoadded")["pw_name"] == "sudoadded")
check("sudo does not alter original shell identity", original_user["uid"] == 1000)
run = command(sudo, "id", [], 1000, start=False)
run.pp = types.SimpleNamespace(tpot_sudo=True)
run.start()
check("sudo id reports root effective credentials", run.code == 0 and run.out.startswith("uid=0(root) gid=0(root)"))
run = command(sudo, "getent", ["shadow", "root"], 1000, start=False)
run.pp = types.SimpleNamespace(tpot_sudo=True)
run.start()
check("sudo privileged account query", run.code == 0 and run.out.startswith("root:"))
boundary = FS()
for database, data in {
    "passwd": "".join(f"u{n}:x:{n}:{n}::/home/u{n}:/bin/sh\n" for n in range(4095)),
    "group": "".join(f"u{n}:x:{n}:\n" for n in range(4095)),
    "shadow": "".join(f"u{n}:!:19000:0:99999:7:::\n" for n in range(4095)),
    "gshadow": "".join(f"u{n}:!::\n" for n in range(4095)),
}.items():
    entry = boundary.getfile("/etc/" + database)
    entry[7], entry[4] = data.encode(), len(data.encode())
check("4096th account creation supported", command(boundary, "useradd", ["-u", "12000", "boundaryuser"]).code == 0)
check("4096-record database remains readable", command(boundary, "getent", ["passwd", "boundaryuser"]).code == 0)
before = copy.deepcopy(boundary.fs)
check("4097th account fails atomically", command(boundary, "useradd", ["-u", "12001", "toomany"]).code != 0 and boundary.fs == before)
# Execute the actual sudo parser with only its framework process adapter
# replaced. User names that are also commands must remain option values.
module("cowrie.core.config").CowrieConfig = types.SimpleNamespace(get=lambda *a, **k: k.get("fallback", ""))
pipe_module = module("cowrie.shell.pipe")
class Pipe:
    def __init__(self, protocol, command, args, data, targets, **kwargs):
        self.user, self.targets, self.args = kwargs["user"], targets, args
        self.stdin_from_pipe = False
pipe_module.PipeProtocol = Pipe
sudo_spec = importlib.util.spec_from_file_location("cowrie.commands.sudo", Path(sys.argv[1]).with_name("sudo.py"))
sudo_module = importlib.util.module_from_spec(sudo_spec)
sys.modules[sudo_spec.name] = sudo_module
sudo_spec.loader.exec_module(sudo_module)
def sudo_command(fs, args):
    result = sudo_module.Command_sudo.__new__(sudo_module.Command_sudo)
    result.args, result.fs, result.cwd, result.input_data = args, fs, "/", None
    result.user = {"uid": 1000, "gid": 1000, "username": "debian"}
    result.environ = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
    result.pp = types.SimpleNamespace(targets={}, stdin_from_pipe=False)
    result.protocol = types.SimpleNamespace(getCommand=lambda name, *rest: users.commands.get(name) or (Command if name == "cat" else None))
    result.out, result.err, result.code, result.exited, result.child = "", "", None, False, None
    def execute(pipe, child, *arguments):
        result.child = (pipe, child, arguments)
        result.code, result.exited = 0, True
    result.exec_command = execute
    result.start()
    return result
sudo_fs = FS()
command(sudo_fs, "useradd", ["-u", "23456", "analyst"])
command(sudo_fs, "useradd", ["-u", "23457", "cat"])
run = sudo_command(sudo_fs, ["-u", "analyst", "id"])
check("sudo target UID resolved from current VFS", run.child[0].tpot_sudo_user["uid"] == 23456)
check("sudo nonroot target is not marked root", run.child[0].tpot_sudo is False)
run = sudo_command(sudo_fs, ["-u", "cat", "id"])
check("sudo username matching command parsed correctly", run.child[1] is users.Command_id and run.child[0].user["username"] == "cat")
run = sudo_command(sudo_fs, ["--user=analyst", "id"])
check("sudo long target option", run.child[0].user["uid"] == 23456)
run = sudo_command(sudo_fs, ["-u#23456", "-g", "users", "id"])
check("sudo numeric target and group", run.child[0].user["uid"] == 23456 and run.child[0].user["gid"] == 100)
run = sudo_command(sudo_fs, ["-u", "missing", "id"])
check("sudo unknown target rejected before child", run.code == 1 and run.child is None)
run = sudo_command(sudo_fs, ["-u", "analyst", "useradd", "forbidden"])
child = command(sudo_fs, "useradd", ["forbidden"], 1000, start=False)
child.pp = run.child[0]
child.start()
check("sudo nonroot target cannot create root accounts", child.code == 1 and "forbidden" not in sudo_fs.file_contents("/etc/passwd").decode())
print(json.dumps({"checks": checks, "count": len(checks), "result": "PASS"}))
