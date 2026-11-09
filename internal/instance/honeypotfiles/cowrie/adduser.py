# SPDX-FileCopyrightText: 2026 QPot contributors
# SPDX-License-Identifier: BSD-3-Clause

"""Account changes and queries over the connection's virtual filesystem.

No command in this module opens a real account database or starts a process.
All validation and home preparation precede the synchronous VFS commit.
"""

from __future__ import annotations

import getopt
import hashlib
import hmac
import posixpath
import re
import secrets
import stat
import time

from cowrie.core.qpot_state import connection_filesystem, effective_user
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import A_CONTENTS, A_CTIME, A_GID, A_MODE, A_NAME, A_REALFILE, A_SIZE, A_TYPE, A_UID, T_DIR, T_FILE

commands = {}
MAX_DATABASE = 262144
MAX_ACCOUNTS = 4096
MAX_ID = 4294967294
USER_NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\$?\Z", re.ASCII)


class AccountError(Exception):
    def __init__(self, message, code=1):
        self.message, self.code = message, code


def qpot_account_bytes(fs, path, required=True):
    # Authentication/account administration is setuid-like internal work. Never
    # extend this bypass to an arbitrary filename supplied by a shell command.
    if path not in ("/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow"):
        raise AccountError("invalid account database")
    fs = connection_filesystem(fs)
    try:
        resolved, node = qpot_ownership_path(fs, path, "/", False, not required)
    except AccountError:
        raise
    except Exception:
        raise AccountError(f"cannot open {path}") from None
    if node is None:
        if required:
            raise AccountError(f"cannot open {path}")
        return None
    if node[A_TYPE] != T_FILE or node[A_SIZE] > MAX_DATABASE:
        raise AccountError(f"invalid account database {path}")
    try:
        data = fs.file_contents(resolved)
    except Exception:
        raise AccountError(f"cannot read {path}") from None
    if len(data) > MAX_DATABASE:
        raise AccountError(f"account database {path} is too large")
    return data


def qpot_rows(fs, path, columns, required=True):
    data = qpot_account_bytes(fs, path, required)
    if data is None:
        return []
    try:
        lines = data.decode("utf-8").replace("\r\n", "\n").split("\n")
    except UnicodeError:
        raise AccountError(f"invalid account database {path}") from None
    rows = []
    for line in lines:
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) != columns or not fields[0] or "\x00" in line:
            raise AccountError(f"invalid account database {path}")
        rows.append(fields)
        if len(rows) > MAX_ACCOUNTS:
            raise AccountError(f"too many entries in {path}")
    return rows


def qpot_passwd(fs):
    """A Passwd-compatible view of the current connection's account files."""
    from cowrie.shell.pwd import Passwd

    view = Passwd.__new__(Passwd)
    view.passwd = []
    for row in qpot_rows(fs, "/etc/passwd", 7):
        uid, gid = qpot_number(row[2], "user ID"), qpot_number(row[3], "group ID")
        view.passwd.append(dict(pw_name=row[0], pw_passwd=row[1], pw_uid=uid, pw_gid=gid,
                                pw_gecos=row[4], pw_dir=row[5], pw_shell=row[6]))
    return view


def qpot_groups(fs):
    result = []
    for row in qpot_rows(fs, "/etc/group", 4):
        result.append(dict(name=row[0], gid=qpot_number(row[2], "group ID"), members=row[3].split(",") if row[3] else []))
    return result


def qpot_group_ids(fs, name, gid, groups=None):
    result = [gid]
    for group in qpot_groups(fs) if groups is None else groups:
        if name in group["members"] and group["gid"] not in result:
            result.append(group["gid"])
    return result


def qpot_group_name(groups, gid):
    return next((g["name"] for g in groups if g["gid"] == gid), str(gid))


def qpot_path(value):
    if not value.startswith("/") or len(value) > 4096 or any(c in value for c in "\x00\n\r:"):
        raise AccountError(f"invalid directory '{value[:128]}'", 3)
    return "/" + posixpath.normpath(value).lstrip("/")


def qpot_number(value, kind):
    if not value.isascii() or not value.isdigit() or len(value) > 10 or int(value) > MAX_ID:
        raise AccountError(f"invalid {kind} '{value[:128]}'", 3)
    return int(value)


def qpot_hash_password(password, salt=None):
    """SHA512-crypt for virtual shadow entries (the glibc/libxcrypt $6$ format)."""
    password = password.encode("utf-8")
    if not password or len(password) > 256 or b"\x00" in password:
        raise AccountError("invalid password")
    salt = (salt or secrets.token_hex(8)).encode("ascii")[:16]
    alternate = hashlib.sha512(password + salt + password).digest()
    block = password + salt + (alternate * ((len(password) + 63) // 64))[:len(password)]
    count = len(password)
    while count:
        block += alternate if count & 1 else password
        count >>= 1
    digest = hashlib.sha512(block).digest()
    p_hash = hashlib.sha512(password * len(password)).digest()
    p_bytes = (p_hash * ((len(password) + 63) // 64))[:len(password)]
    s_hash = hashlib.sha512(salt * (16 + digest[0])).digest()
    s_bytes = (s_hash * ((len(salt) + 63) // 64))[:len(salt)]
    for index in range(5000):
        block = p_bytes if index & 1 else digest
        if index % 3:
            block += s_bytes
        if index % 7:
            block += p_bytes
        block += digest if index & 1 else p_bytes
        digest = hashlib.sha512(block).digest()
    alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    order = [(0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4), (47, 5, 26),
             (6, 27, 48), (28, 49, 7), (50, 8, 29), (9, 30, 51), (31, 52, 10), (53, 11, 32),
             (12, 33, 54), (34, 55, 13), (56, 14, 35), (15, 36, 57), (37, 58, 16), (59, 17, 38),
             (18, 39, 60), (40, 61, 19), (62, 20, 41)]
    encoded = ""
    for a, b, c in order:
        value = (digest[a] << 16) | (digest[b] << 8) | digest[c]
        for _ in range(4):
            encoded += alphabet[value & 63]
            value >>= 6
    value = digest[63]
    for _ in range(2):
        encoded += alphabet[value & 63]
        value >>= 6
    return "$6$" + salt.decode("ascii") + "$" + encoded


def qpot_new_user_auth(fs, name, password):
    """None keeps baseline policy; newly created virtual users honor shadow."""
    fs = connection_filesystem(fs)
    if name not in getattr(fs, "qpot_new_users", set()):
        return None
    try:
        row = next((row for row in qpot_rows(fs, "/etc/shadow", 9) if row[0] == name), None)
        if row is None or row[1].startswith(("!", "*")):
            return False
        if row[1] == "":
            return password == ""
        found = re.fullmatch(r"\$6\$([./0-9A-Za-z]{1,16})\$[./0-9A-Za-z]{86}", row[1])
        if found is None:
            return False
        return hmac.compare_digest(row[1], qpot_hash_password(password, found.group(1)))
    except (AccountError, UnicodeError):
        return False


def qpot_database_bytes(rows, original=None):
    if original is None:
        text = "\n".join(":".join(row) for row in rows) + "\n"
    else:
        remaining = iter(rows)
        parts = []
        for line in re.findall(r"[^\n]*\n|[^\n]+$", original.decode("utf-8")):
            content = line.rstrip("\r\n")
            if not content or content.startswith("#"):
                parts.append(line)
                continue
            row = ":".join(next(remaining))
            ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
            parts.append(row + ending)
        text = "".join(parts)
        for row in remaining:
            if text and not text.endswith("\n"):
                text += "\n"
            text += ":".join(row) + "\n"
    data = text.encode("utf-8")
    if len(rows) > MAX_ACCOUNTS or len(data) > MAX_DATABASE:
        raise AccountError("account database limit exceeded")
    return data


def qpot_prepare_home(fs, home, skel, uid, gid):
    """Prepare a bounded private home subtree after useradd verified root."""
    fs = connection_filesystem(fs)
    if home == "/":
        return None, 0, home
    parent_path, parent = qpot_ownership_path(fs, posixpath.dirname(home), "/")
    if parent is None or parent[A_TYPE] != T_DIR:
        raise AccountError(f"cannot create directory {home}", 12)
    canonical = posixpath.join(parent_path, posixpath.basename(home))
    existing = next((child for child in parent[A_CONTENTS] if child[A_NAME] == posixpath.basename(home)), None)
    if existing is not None:
        _, target = qpot_ownership_path(fs, home, "/")
        if target[A_TYPE] != T_DIR:
            raise AccountError(f"cannot create directory {home}", 12)
        return None, 0, canonical
    if canonical.startswith(("/proc/", "/sys/", "/dev/")) or canonical in ("/proc", "/sys", "/dev"):
        raise AccountError(f"cannot create directory {home}", 12)
    skel_path, source = qpot_ownership_path(fs, skel, "/", True, True)
    if source is not None and source[A_TYPE] != T_DIR:
        raise AccountError(f"invalid skeleton directory {skel}", 12)
    now = time.time()
    result = [posixpath.basename(home), T_DIR, uid, gid, 4096, stat.S_IFDIR | 0o750, now, [], None, None]
    nodes, total = 1, 0
    if source is not None:
        result[A_CONTENTS] = [list(node) for node in source[A_CONTENTS]]
        queue = [(node, 1, skel_path + "/" + node[A_NAME]) for node in result[A_CONTENTS]]
        while queue:
            node, depth, path = queue.pop()
            nodes += 1
            if nodes > 128 or depth > 16:
                raise AccountError("skeleton directory limit exceeded", 12)
            node[A_UID], node[A_GID], node[A_CTIME] = uid, gid, now
            if node[A_TYPE] == T_DIR:
                node[A_CONTENTS] = [list(child) for child in node[A_CONTENTS]]
                queue.extend((child, depth + 1, path + "/" + child[A_NAME]) for child in node[A_CONTENTS])
            elif node[A_TYPE] == T_FILE:
                if node[A_SIZE] > 1048576:
                    raise AccountError("skeleton directory limit exceeded", 12)
                content = fs.file_contents(path)
                total += len(content)
                if total > 1048576:
                    raise AccountError("skeleton directory limit exceeded", 12)
                node[A_CONTENTS], node[A_SIZE], node[A_REALFILE] = content, len(content), None
    return result, nodes, canonical


def qpot_commit(fs, databases, home=None, home_nodes=0):
    """Commit validated account records after the command verified its actor."""
    if not set(databases) <= {"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow"}:
        raise AccountError("invalid account database")
    fs = connection_filesystem(fs)
    new = sum(fs.getfile(path, follow_symlinks=False) is None for path in databases)
    if fs.newcount + new + home_nodes > 10000:
        raise AccountError("cannot update account files: disk quota exceeded", 10)
    for path in databases:
        parent = fs.getfile(posixpath.dirname(path))
        if parent is None or parent[A_TYPE] != T_DIR:
            raise AccountError(f"cannot update {path}", 10)
    fs._ensure_private_fs()
    now = time.time()
    for path, content in databases.items():
        node = fs.getfile(path, follow_symlinks=False)
        if node is None:
            mode = 0o600 if path.endswith(("shadow", "gshadow")) else 0o644
            node = [posixpath.basename(path), T_FILE, 0, 0, len(content), stat.S_IFREG | mode,
                    now, content, None, None]
            fs.getfile(posixpath.dirname(path))[A_CONTENTS].append(node)
        else:
            node[A_CONTENTS], node[A_SIZE], node[A_CTIME], node[A_REALFILE] = content, len(content), now, None
    if home is not None:
        path, node = home
        fs.getfile(posixpath.dirname(path))[A_CONTENTS].append(node)
    fs.newcount += new + home_nodes


def qpot_track_accounts(fs, names):
    fs = connection_filesystem(fs)
    known = getattr(fs, "qpot_new_users", None)
    if known is None:
        fs.qpot_new_users = known = set()
    known.update(names)


def qpot_set_passwords(fs, records, encrypted=False):
    if len(records) > 16:
        raise AccountError("too many password updates")
    accounts = qpot_passwd(fs)
    shadow = qpot_rows(fs, "/etc/shadow", 9, False)
    original = qpot_account_bytes(fs, "/etc/shadow", False)
    changed = set()
    for name, password in records:
        try:
            accounts.getpwnam(name)
        except KeyError:
            raise AccountError(f"user '{name}' does not exist") from None
        if name in changed or len(password) > 1024 or any(c in password for c in "\x00\r\n:"):
            raise AccountError("invalid password update")
        value = password if encrypted else qpot_hash_password(password)
        row = next((row for row in shadow if row[0] == name), None)
        if row is None:
            row = [name, value, str(int(time.time() // 86400)), "0", "99999", "7", "", "", ""]
            shadow.append(row)
        else:
            row[1], row[2] = value, str(int(time.time() // 86400))
        changed.add(name)
    if records:
        qpot_commit(fs, {"/etc/shadow": qpot_database_bytes(shadow, original)})
        qpot_track_accounts(fs, changed)


def qpot_effective_user(command):
    """Use the same process credentials as the connection's filesystem facade."""
    return effective_user(command)


class Command_chpasswd(HoneyPotCommand):
    consumes_stdin = True

    def start(self):
        self.user = qpot_effective_user(self)
        self.lines = []
        self.encrypted = self.args == ["-e"] or self.args == ["--encrypted"]
        if self.args and not self.encrypted:
            if self.args == ["--help"]:
                self.write("Usage: chpasswd [-e|--encrypted]\nRead user:password pairs from standard input.\n")
                self.exit(0)
            else:
                self.errorWrite("chpasswd: unsupported option\n")
                self.exit(2)
            return
        if self.user.get("uid") != 0:
            self.errorWrite("chpasswd: Permission denied.\n")
            self.exit(1)
            return
        if self.input_data is not None:
            if len(self.input_data) > 32768:
                self.errorWrite("chpasswd: input is too large\n")
                self.exit(1)
                return
            try:
                self.lines = self.input_data.decode("utf-8").replace("\r\n", "\n").split("\n")
            except UnicodeError:
                self.errorWrite("chpasswd: invalid input\n")
                self.exit(1)
                return
            self.eofReceived()

    def lineReceived(self, line):
        if self.exited:
            return
        if len(self.lines) >= 16 or len(line.encode("utf-8")) > 2048:
            self.errorWrite("chpasswd: input is too large\n")
            self.exit(1)
            return
        self.lines.append(line)

    def eofReceived(self):
        if self.exited:
            return
        try:
            records = []
            for line in self.lines:
                if not line:
                    continue
                if ":" not in line:
                    raise AccountError("invalid input format")
                records.append(tuple(line.split(":", 1)))
            qpot_set_passwords(self.fs, records, self.encrypted)
            self.exit(0)
        except AccountError as error:
            self.errorWrite(f"chpasswd: {error.message}\n")
            self.exit(1)


class Command_passwd(HoneyPotCommand):
    def start(self):
        self.user = qpot_effective_user(self)
        if len(self.args) > 1 or any(arg.startswith("-") for arg in self.args):
            self.errorWrite("Usage: passwd [LOGIN]\n")
            self.exit(2)
            return
        self.name = self.args[0] if self.args else self.user["username"]
        try:
            user = qpot_passwd(self.fs).getpwnam(self.name)
            if self.user.get("uid") != 0 and user["pw_uid"] != self.user.get("uid"):
                raise AccountError("Permission denied.")
            self.target_uid = user["pw_uid"]
            self.stage = "current" if self.user.get("uid") != 0 else "new"
            self.protocol.password_input = True
            self.write("Current password: " if self.stage == "current" else "New password: ")
        except (AccountError, KeyError):
            self.errorWrite("passwd: Permission denied or unknown user.\n")
            self.exit(1)

    def lineReceived(self, line):
        if self.exited:
            return
        try:
            if len(line.encode("utf-8")) > 256 or "\x00" in line:
                raise AccountError("invalid password")
            if self.stage == "current":
                if qpot_new_user_auth(self.fs, self.name, line) is False:
                    raise AccountError("Authentication failure")
                self.stage = "new"
                self.write("New password: ")
            elif self.stage == "new":
                self.first_password = line
                self.stage = "repeat"
                self.write("Retype new password: ")
            else:
                if line != self.first_password:
                    raise AccountError("passwords do not match")
                if qpot_passwd(self.fs).getpwnam(self.name)["pw_uid"] != self.target_uid:
                    raise AccountError("account changed; try again")
                qpot_set_passwords(self.fs, [(self.name, line)])
                self.first_password = ""
                self.protocol.password_input = False
                self.write("passwd: password updated successfully\n")
                self.exit(0)
        except (AccountError, KeyError) as error:
            self.first_password = ""
            self.protocol.password_input = False
            self.errorWrite("passwd: " + (error.message if isinstance(error, AccountError) else "account changed; try again") + "\n")
            self.exit(1)

    def eofReceived(self):
        self.first_password = ""
        self.protocol.password_input = False
        self.exit(1)

    def handle_CTRL_C(self):
        self.first_password = ""
        self.protocol.password_input = False
        self.exit(130)


class Command_useradd(HoneyPotCommand):
    program = "useradd"
    interactive = False

    def fail(self, error):
        self.protocol.password_input = False
        self.first_password = ""
        self.errorWrite(f"{self.program}: {error.message}\n")
        self.exit(error.code)

    def start(self):
        try:
            self.prepare()
            if self.interactive:
                self.stage = "password"
                self.protocol.password_input = True
                self.write("New password: ")
            else:
                self.finish()
        except (AccountError, OSError, ValueError, KeyError, TypeError) as error:
            self.fail(error if isinstance(error, AccountError) else AccountError("cannot update account files", 10))

    def prepare(self):
        self.user = qpot_effective_user(self)
        if len(self.args) > 64 or sum(len(arg) for arg in self.args) > 16384:
            raise AccountError("too many arguments", 2)
        try:
            opts, names = getopt.gnu_getopt(self.args, "b:c:d:g:G:k:mMp:rs:u:UhnN",
                                           ["base-dir=", "comment=", "home-dir=", "gid=", "groups=", "skel=",
                                            "create-home", "no-create-home", "password=", "system", "shell=", "uid=",
                                            "user-group", "no-user-group", "help", "disabled-password", "disabled-login",
                                            "gecos=", "home=", "ingroup=", "no-create-home"])
        except getopt.GetoptError as error:
            raise AccountError(str(error), 2) from None
        if any(flag in ("-h", "--help") for flag, _ in opts):
            self.write(f"Usage: {self.program} [options] LOGIN\n"
                       "  -m, --create-home     create the home directory\n"
                       "  -d, --home-dir DIR   home directory\n"
                       "  -u, --uid UID        numeric user ID\n"
                       "  -g, --gid GROUP      primary group\n"
                       "  -G, --groups GROUPS  supplementary groups\n"
                       "  -s, --shell SHELL    login shell\n")
            self.exit(0)
            self.exited = True
            return
        if self.user.get("uid", -1) != 0:
            raise AccountError("Permission denied.")
        if len(names) != 1 or len(names[0]) > 32 or not USER_NAME.fullmatch(names[0]):
            raise AccountError("invalid user name or missing login", 3)
        self.name = names[0]
        self.passwd = qpot_rows(self.fs, "/etc/passwd", 7)
        self.groups = qpot_rows(self.fs, "/etc/group", 4)
        self.shadow = qpot_rows(self.fs, "/etc/shadow", 9, False)
        self.gshadow = qpot_rows(self.fs, "/etc/gshadow", 4, False)
        self.account_baseline = {path: qpot_account_bytes(self.fs, path, False)
                                 for path in ("/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow")}
        users = qpot_passwd(self.fs).passwd
        group_view = qpot_groups(self.fs)
        if any(row[0] == self.name for row in self.shadow) or any(row[0] == self.name for row in self.passwd):
            raise AccountError(f"user '{self.name}' already exists", 9)
        values = dict(opts)
        system = any(flag in ("-r", "--system") for flag, _ in opts)
        used_ids = {entry["pw_uid"] for entry in users}
        uid_arg = values.get("-u", values.get("--uid"))
        choices = range(999, 99, -1) if system else range(1000, 60001)
        self.uid = qpot_number(uid_arg, "user ID") if uid_arg is not None else next((n for n in choices if n not in used_ids), -1)
        if self.uid < 0:
            raise AccountError("no available user IDs", 4)
        if self.uid in used_ids:
            raise AccountError(f"UID {self.uid} is not unique", 4)
        gid_arg = values.get("-g", values.get("--gid", values.get("--ingroup")))
        if gid_arg == "":
            raise AccountError("invalid empty group", 6)
        self.new_group = gid_arg is None and not any(flag in ("-N", "--no-user-group", "-n") for flag, _ in opts)
        if self.new_group:
            if any(row[0] == self.name for row in self.gshadow) or any(row[0] == self.name for row in self.groups):
                raise AccountError(f"group '{self.name}' already exists", 9)
            used = {entry["gid"] for entry in group_view}
            self.gid = self.uid if self.uid not in used else next((n for n in choices if n not in used), -1)
            if self.gid < 0:
                raise AccountError("no available group IDs", 4)
        else:
            gid_arg = gid_arg or "100"
            group = next((g for g in group_view if g["name"] == gid_arg or str(g["gid"]) == gid_arg), None)
            if group is None:
                raise AccountError(f"group '{gid_arg}' does not exist", 6)
            self.gid = group["gid"]
        groups_arg = values.get("-G", values.get("--groups", ""))
        self.secondary = []
        for wanted in groups_arg.split(",") if groups_arg else []:
            group = next((g for g in group_view if g["name"] == wanted or str(g["gid"]) == wanted), None)
            if group is None:
                raise AccountError(f"group '{wanted}' does not exist", 6)
            if group["name"] not in self.secondary:
                self.secondary.append(group["name"])
        if len(self.secondary) > 32:
            raise AccountError("too many supplementary groups", 2)
        base = qpot_path(values.get("-b", values.get("--base-dir", "/home")))
        self.home = qpot_path(values.get("-d", values.get("--home-dir", values.get("--home", base + "/" + self.name))))
        self.shell_path = qpot_path(values.get("-s", values.get("--shell", "/bin/bash" if self.program == "adduser" else "/bin/sh")))
        self.comment = values.get("-c", values.get("--comment", values.get("--gecos", "")))
        if len(self.comment) > 1024 or any(c in self.comment for c in "\x00\r\n:"):
            raise AccountError("invalid comment", 3)
        self.password = values.get("-p", values.get("--password", "!"))
        if len(self.password) > 1024 or any(c in self.password for c in "\x00\r\n:"):
            raise AccountError("invalid encrypted password", 3)
        create = self.program == "adduser" and not system
        for flag, _ in opts:
            if flag in ("-m", "--create-home"):
                create = True
            elif flag in ("-M", "--no-create-home"):
                create = False
        skel = qpot_path(values.get("-k", values.get("--skel", "/etc/skel")))
        self.create_home, self.skel = create, skel
        if create:
            qpot_prepare_home(self.fs, self.home, skel, self.uid, self.gid)
        self.interactive = self.program == "adduser" and not system and not any(
            flag in ("--disabled-password", "--disabled-login", "-p", "--password") for flag, _ in opts)
        self.gecos_supplied = any(flag in ("-c", "--comment", "--gecos") for flag, _ in opts)

    def lineReceived(self, line):
        try:
            if len(line.encode("utf-8")) > 1024 or "\x00" in line:
                raise AccountError("invalid input")
            if self.stage == "password":
                self.first_password = line
                self.stage = "repeat"
                self.write("Retype new password: ")
            elif self.stage == "repeat":
                self.protocol.password_input = False
                if line != self.first_password:
                    raise AccountError("passwords do not match")
                self.password = qpot_hash_password(line)
                self.first_password = ""
                if self.gecos_supplied:
                    self.finish()
                else:
                    self.details = []
                    self.stage = "gecos"
                    self.write("Full Name []: ")
            elif self.stage == "gecos":
                if any(c in line for c in ":,\r\n"):
                    raise AccountError("invalid user information")
                self.details.append(line)
                prompts = ["Room Number []: ", "Work Phone []: ", "Home Phone []: ", "Other []: "]
                if len(self.details) <= len(prompts):
                    self.write(prompts[len(self.details) - 1])
                else:
                    self.comment = ",".join(self.details)
                    self.stage = "confirm"
                    self.write("Is the information correct? [Y/n] ")
            elif self.stage == "confirm":
                if line.strip().lower() not in ("", "y", "yes"):
                    raise AccountError("user information not confirmed")
                self.finish()
        except AccountError as error:
            self.fail(error)

    def handle_CTRL_C(self):
        self.protocol.password_input = False
        self.exit(130)

    def eofReceived(self):
        self.protocol.password_input = False
        self.exit(1)

    def finish(self):
        if self.exited:
            return
        for path, original in self.account_baseline.items():
            current = qpot_account_bytes(self.fs, path, False)
            if current != original:
                raise AccountError("account files changed; try again", 10)
        if len(self.comment) > 1024:
            raise AccountError("invalid user information", 3)
        self.home_node, self.home_nodes, self.home_commit_path = qpot_prepare_home(self.fs, self.home, self.skel, self.uid, self.gid) if self.create_home else (None, 0, self.home)
        self.passwd.append([self.name, "x", str(self.uid), str(self.gid), self.comment, self.home, self.shell_path])
        if self.new_group:
            self.groups.append([self.name, "x", str(self.gid), ""])
            self.gshadow.append([self.name, "!", "", ""])
        for row in self.groups:
            if row[0] in self.secondary:
                row[3] = ",".join([member for member in row[3].split(",") if member] + [self.name])
        for row in self.gshadow:
            if row[0] in self.secondary:
                row[3] = ",".join([member for member in row[3].split(",") if member] + [self.name])
        self.shadow.append([self.name, self.password, str(int(time.time() // 86400)), "0", "99999", "7", "", "", ""])
        updates = {path: qpot_database_bytes(rows, self.account_baseline[path])
                   for path, rows in (("/etc/passwd", self.passwd), ("/etc/group", self.groups),
                                      ("/etc/shadow", self.shadow), ("/etc/gshadow", self.gshadow))}
        qpot_commit(self.fs, updates, (self.home_commit_path, self.home_node) if self.home_node is not None else None, self.home_nodes)
        qpot_track_accounts(self.fs, [self.name])
        self.protocol.password_input = False
        self.exit(0)


class Command_adduser(Command_useradd):
    program = "adduser"


class Command_id(HoneyPotCommand):
    def start(self):
        self.user = qpot_effective_user(self)
        try:
            opts, names = getopt.gnu_getopt(self.args, "ugGnrzh", ["user", "group", "groups", "name", "real", "zero", "help", "version"])
            flags = {flag for flag, _ in opts}
            if "--version" in flags:
                from cowrie.commands.coreutils import qpot_coreutils_version_text
                self.write(qpot_coreutils_version_text(self.fs, "id", "Arnold Robbins and David MacKenzie."))
                self.exit(0)
                return
            if flags & {"-h", "--help"}:
                self.write("Usage: id [OPTION]... [USER]\nPrint user and group information.\n")
                self.exit(0)
                return
            modes = [bool(flags & {"-u", "--user"}), bool(flags & {"-g", "--group"}), bool(flags & {"-G", "--groups"})]
            named = bool(flags & {"-n", "--name"})
            if len(names) > 1 or sum(modes) > 1 or ((named or flags & {"-z", "--zero", "-r", "--real"}) and not any(modes)):
                raise AccountError("cannot print multiple identity types", 1)
            view = qpot_passwd(self.fs)
            if names:
                try:
                    user = view.getpwnam(names[0])
                except KeyError:
                    if names[0].isascii() and names[0].isdigit():
                        user = view.getpwuid(int(names[0]))
                    else:
                        raise
            else:
                try:
                    user = view.getpwuid(self.user["uid"])
                except KeyError:
                    user = dict(pw_name=self.user["username"], pw_uid=self.user["uid"], pw_gid=self.user.get("gid", self.user["uid"]))
            uid, gid, name = user["pw_uid"], user["pw_gid"], user["pw_name"]
            groups = qpot_groups(self.fs)
            if not names:
                uid, gid = self.user["uid"], self.user.get("gid", self.user["uid"])
                snapshot = self.user.get("groups")
                gids = [gid] + [n for n in snapshot if isinstance(n, int) and n != gid] if isinstance(snapshot, list) else qpot_group_ids(self.fs, name, gid, groups)
            else:
                gids = qpot_group_ids(self.fs, name, gid, groups)
            end = "\x00" if flags & {"-z", "--zero"} else "\n"
            if modes[0]:
                self.write((name if named else str(uid)) + end)
            elif modes[1]:
                self.write((qpot_group_name(groups, gid) if named else str(gid)) + end)
            elif modes[2]:
                self.write(("\x00" if end == "\x00" else " ").join(qpot_group_name(groups, n) if named else str(n) for n in gids) + end)
            else:
                memberships = ",".join(f"{n}({qpot_group_name(groups, n)})" for n in gids)
                self.write(f"uid={uid}({name}) gid={gid}({qpot_group_name(groups, gid)}) groups={memberships}\n")
            self.exit(0)
        except (getopt.GetoptError, AccountError, KeyError) as error:
            message = error.message if isinstance(error, AccountError) else f"'{self.args[-1] if self.args else ''}': no such user"
            self.errorWrite(f"id: {message}\n")
            self.exit(1)


class Command_groups(HoneyPotCommand):
    def start(self):
        self.user = qpot_effective_user(self)
        if self.args == ["--help"]:
            self.write("Usage: groups [USERNAME]...\nPrint group memberships for each user.\n")
            self.exit(0)
            return
        if self.args == ["--version"]:
            from cowrie.commands.coreutils import qpot_coreutils_version_text
            self.write(qpot_coreutils_version_text(self.fs, "groups", "David MacKenzie and James Youngman."))
            self.exit(0)
            return
        if any(name.startswith("-") for name in self.args):
            self.errorWrite("groups: unrecognized option\n")
            self.exit(1)
            return
        if len(self.args) > 64 or sum(len(arg) for arg in self.args) > 16384:
            self.errorWrite("groups: too many arguments\n")
            self.exit(1)
            return
        try:
            accounts, groups = qpot_passwd(self.fs), qpot_groups(self.fs)
        except AccountError:
            self.errorWrite("groups: cannot read account files\n")
            self.exit(1)
            return
        failed, emitted = False, 0
        for name in self.args or [self.user["username"]]:
            try:
                user = accounts.getpwnam(name) if self.args else accounts.getpwuid(self.user["uid"])
                gid = user["pw_gid"] if self.args else self.user.get("gid", self.user["uid"])
                snapshot = self.user.get("groups") if not self.args else None
                gids = [gid] + [n for n in snapshot if isinstance(n, int) and n != gid] if isinstance(snapshot, list) else qpot_group_ids(self.fs, user["pw_name"], gid, groups)
                text = (name + " : " if self.args else "") + " ".join(qpot_group_name(groups, n) for n in gids) + "\n"
                emitted += len(text.encode("utf-8"))
                if emitted > 1048576:
                    self.errorWrite("groups: output limit exceeded\n")
                    self.exit(1)
                    return
                self.write(text)
            except (AccountError, KeyError):
                self.errorWrite(f"groups: '{name}': no such user\n")
                failed = True
        self.exit(1 if failed else 0)


class Command_getent(HoneyPotCommand):
    def start(self):
        self.user = qpot_effective_user(self)
        if not self.args or self.args[0] not in ("passwd", "group", "shadow", "gshadow") or len(self.args) > 65:
            self.exit(2)
            return
        database = self.args[0]
        if database in ("shadow", "gshadow") and self.user.get("uid") != 0:
            self.exit(2)
            return
        try:
            rows = qpot_rows(self.fs, "/etc/" + database, {"passwd": 7, "group": 4, "shadow": 9, "gshadow": 4}[database])
            keys = self.args[1:]
            failed, emitted = False, 0
            for key in keys or [None]:
                if key is None:
                    found = rows
                else:
                    row = next((row for row in rows if row[0] == key or (database in ("passwd", "group") and row[2] == key)), None)
                    found = [row] if row is not None else []
                if not found:
                    failed = True
                for row in found:
                    text = ":".join(row) + "\n"
                    emitted += len(text.encode("utf-8"))
                    if emitted > 1048576:
                        self.exit(2)
                        return
                    self.write(text)
            self.exit(2 if failed else 0)
        except AccountError:
            self.exit(2)


def qpot_ownership_path(fs, path, cwd, follow=True, missing_ok=False):
    """Resolve only VFS nodes, with a finite symlink budget and no OS lookup."""
    if len(path) > 4096 or any(c in path for c in "\x00\r\n"):
        raise AccountError("invalid file name")
    absolute = posixpath.normpath(path if path.startswith("/") else posixpath.join(cwd, path))
    pending = absolute.strip("/").split("/") if absolute.strip("/") else []
    if len(pending) > 1024:
        raise AccountError("file traversal limit exceeded")
    current, parts, links = fs.fs, [], 0
    if not pending:
        return "/", current
    while pending:
        part = pending.pop(0)
        if current[A_TYPE] != T_DIR:
            raise AccountError(f"cannot access '{path}': Not a directory")
        current = next((child for child in current[A_CONTENTS] if child[A_NAME] == part), None)
        if current is None:
            if missing_ok:
                return absolute, None
            raise AccountError(f"cannot access '{path}': No such file or directory")
        if current[A_TYPE] == 0 and (follow or pending):
            links += 1
            if links > 40:
                raise AccountError(f"cannot access '{path}': Too many levels of symbolic links")
            target = current[8]
            if not target:
                raise AccountError(f"cannot access '{path}': No such file or directory")
            if not isinstance(target, str) or len(target) > 4096:
                raise AccountError("symbolic link target limit exceeded")
            base = "/" + "/".join(parts)
            resolved = posixpath.normpath(target if target.startswith("/") else posixpath.join(base, target))
            pending = [piece for piece in resolved.strip("/").split("/") if piece] + pending
            if len(pending) > 1024:
                raise AccountError("file traversal limit exceeded")
            current, parts = fs.fs, []
        else:
            parts.append(part)
    return "/" + "/".join(parts), current


class Command_chown(HoneyPotCommand):
    program = "chown"

    def ownership(self, value):
        group_view = qpot_groups(self.fs)
        passwd = qpot_passwd(self.fs)
        owner, colon, group = value.partition(":") if self.program == "chown" else ("", ":", value)
        uid, gid, account = -1, -1, None
        if owner:
            if owner.isascii() and owner.isdigit():
                uid = qpot_number(owner, "user ID")
                try:
                    account = passwd.getpwuid(uid)
                except KeyError:
                    pass
            else:
                try:
                    account = passwd.getpwnam(owner)
                    uid = account["pw_uid"]
                except KeyError:
                    raise AccountError(f"invalid user: '{owner}'") from None
        if colon:
            if group:
                if group.isascii() and group.isdigit():
                    gid = qpot_number(group, "group ID")
                else:
                    found = next((row for row in group_view if row["name"] == group), None)
                    if found is None:
                        raise AccountError(f"invalid group: '{group}'")
                    gid = found["gid"]
            elif owner and account is not None:
                gid = account["pw_gid"]
            elif not owner or account is None:
                raise AccountError(f"invalid spec: '{value}'")
        if uid == gid == -1:
            raise AccountError(f"invalid spec: '{value}'")
        return uid, gid

    def change(self, path, uid, gid, nofollow):
        resolved, before = qpot_ownership_path(self.fs, path, self.cwd, not nofollow)
        if resolved == "/proc" or resolved.startswith("/proc/") or resolved == "/sys" or resolved.startswith("/sys/"):
            raise AccountError(f"changing ownership of '{path}': Read-only file system")
        metadata = getattr(self.fs, "lstat", None)
        if callable(metadata):
            try:
                metadata(resolved)
            except Exception:
                raise AccountError(f"cannot access '{path}': Permission denied") from None
        actor = self.user.get("uid", -1)
        if actor != 0:
            if before[A_UID] != actor or (uid != -1 and uid != actor) or (gid != -1 and gid not in self.actor_groups):
                raise AccountError(f"changing ownership of '{path}': Operation not permitted")
        old = before[A_UID], before[A_GID]
        if nofollow and before[A_TYPE] == 0:
            state = getattr(self.fs, "_qpot_file_state", None)
            record = state.record(resolved, before) if state is not None else None
            self.fs._ensure_private_fs()
            _, entry = qpot_ownership_path(self.fs, resolved, "/", False)
            if uid != -1:
                entry[A_UID] = uid
            if gid != -1:
                entry[A_GID] = gid
            if record is not None:
                record["change"] = time.time()
        else:
            self.fs.chown(resolved, uid, gid)
            _, entry = qpot_ownership_path(self.fs, resolved, "/", True)
        if entry[A_TYPE] == T_FILE and old != (entry[A_UID], entry[A_GID]):
            entry[A_MODE] &= ~0o6000
        return old != (entry[A_UID], entry[A_GID])

    def start(self):
        self.user = qpot_effective_user(self)
        try:
            opts, args = getopt.gnu_getopt(self.args, "RfhvcP", ["recursive", "no-dereference", "dereference", "silent", "quiet", "verbose", "changes", "reference=", "help", "version"])
            flags = {flag for flag, _ in opts}
            if "--help" in flags:
                self.write(f"Usage: {self.program} [OPTION]... OWNER[:GROUP] FILE...\n")
                self.exit(0)
                return
            if "--version" in flags:
                from cowrie.commands.coreutils import qpot_coreutils_version_text
                self.write(qpot_coreutils_version_text(self.fs, self.program, "David MacKenzie and Jim Meyering."))
                self.exit(0)
                return
            reference = next((value for flag, value in opts if flag == "--reference"), None)
            if reference is not None:
                _, entry = qpot_ownership_path(self.fs, reference, self.cwd)
                uid, gid = entry[A_UID], entry[A_GID]
            else:
                if len(args) < 2:
                    raise AccountError("missing operand")
                uid, gid = self.ownership(args.pop(0))
            if not args or len(args) > 4096 or sum(len(arg) for arg in args) > 65536:
                raise AccountError("missing operand or too many files")
            recursive = bool(flags & {"-R", "--recursive"})
            nofollow = bool(flags & {"-h", "--no-dereference"})
            quiet = bool(flags & {"-f", "--silent", "--quiet"})
            verbose = bool(flags & {"-v", "--verbose"})
            changed_only = bool(flags & {"-c", "--changes"})
            actor = self.user.get("uid", -1)
            self.actor_groups = qpot_group_ids(self.fs, self.user["username"], self.user.get("gid", actor)) if actor != 0 else []
            failed, total, emitted = False, 0, 0
            for operand in args:
                try:
                    pending, paths = [operand], []
                    while pending:
                        path = pending.pop()
                        resolved, node = qpot_ownership_path(self.fs, path, self.cwd, not (nofollow or recursive))
                        total += 1
                        if total > 4096:
                            raise AccountError("file traversal limit exceeded")
                        # Recursive traversal is physical: symbolic links never
                        # lead outside the requested VFS subtree or into a cycle.
                        paths.append((resolved, nofollow or (recursive and node[A_TYPE] == 0)))
                        if recursive and node[A_TYPE] == T_DIR:
                            pending.extend(posixpath.join(resolved, child[A_NAME]) for child in node[A_CONTENTS])
                    for path, physical in paths:
                        changed = self.change(path, uid, gid, physical)
                        if verbose or (changed_only and changed):
                            text = f"ownership of '{path}' {'changed' if changed else 'retained'}\n"
                            emitted += len(text.encode("utf-8"))
                            if emitted > 1048576:
                                raise AccountError("output limit exceeded")
                            self.write(text)
                except AccountError as error:
                    if not quiet:
                        self.errorWrite(f"{self.program}: {error.message}\n")
                    failed = True
            self.exit(1 if failed else 0)
        except (AccountError, getopt.GetoptError) as error:
            message = error.message if isinstance(error, AccountError) else str(error)
            self.errorWrite(f"{self.program}: {message}\n")
            self.exit(1)


class Command_chgrp(Command_chown):
    program = "chgrp"


for name, command, paths in (
    ("useradd", Command_useradd, ("/usr/sbin/", "/sbin/")),
    ("adduser", Command_adduser, ("/usr/sbin/", "/sbin/")),
    ("id", Command_id, ("/usr/bin/", "/bin/")),
    ("groups", Command_groups, ("/usr/bin/", "/bin/")),
    ("getent", Command_getent, ("/usr/bin/", "/bin/")),
    ("chpasswd", Command_chpasswd, ("/usr/sbin/", "/sbin/")),
    ("passwd", Command_passwd, ("/usr/bin/", "/bin/")),
    ("chown", Command_chown, ("/usr/bin/", "/bin/")),
    ("chgrp", Command_chgrp, ("/usr/bin/", "/bin/")),
):
    commands[name] = command
    for prefix in paths:
        commands[prefix + name] = command
