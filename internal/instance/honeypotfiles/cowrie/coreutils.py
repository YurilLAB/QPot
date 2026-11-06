# SPDX-License-Identifier: BSD-3-Clause

"""Programs of the persona that Cowrie had no command for (QPot).

The persona's tree holds hundreds of programs Cowrie does not emulate; running
one ended in "cannot execute binary file: Exec format error", even for arch on
an x86_64 machine. This module answers the ones scripts use most. Each is
registered under its paths only, so it answers only where the persona has the
program (the shell finds the file on PATH first); hostname and bash keep the
names base and bash registered them under. Texts were recorded with GNU
coreutils 9.7, hostname 3.25, bash 5.2.37 and BusyBox 1.37.0.

It also holds what ping (loaded before it) shares: the persona's release, its
hosts file and its network.
"""

from __future__ import annotations

import getopt
import hashlib
import ipaddress
import math
import posixpath
import random
import re
import string

from cowrie.core.config import CowrieConfig
from cowrie.shell import fs as tree_fs
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.pipe import PipeProtocol

commands: dict = {}

# --- what the persona is -------------------------------------------------------------------

qpot_release_seen: list = []


def qpot_os_release(tree) -> tuple[str, tuple[int, ...]]:
    """(ID, VERSION_ID as numbers) of the persona's /etc/os-release, read once per process."""
    if qpot_release_seen:
        return qpot_release_seen[0]
    found: tuple[str, tuple[int, ...]] = ("", ())
    for name in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            text = tree.file_contents(name).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - missing, a directory, no tree yet
            continue
        values = {}
        for line in text.splitlines():
            key, sep, value = line.partition("=")
            if sep:
                values[key.strip()] = value.strip().strip('"')
        if values:
            numbers = tuple(int(x) for x in re.findall(r"\d+", values.get("VERSION_ID", ""))[:2])
            found = (values.get("ID", "").lower(), numbers)
            break
    if tree is not None:
        qpot_release_seen.append(found)
    return found


def qpot_busybox_applet(tree, name: str) -> bool:
    """Whether the persona's program name is a link to BusyBox."""
    for directory in ("/bin", "/usr/bin", "/sbin", "/usr/sbin"):
        try:
            node = tree.getfile(f"{directory}/{name}", follow_symlinks=False)
        except Exception:  # noqa: BLE001
            node = None
        if node is None:
            continue
        if node[tree_fs.A_TYPE] == tree_fs.T_LINK:
            return posixpath.basename(str(node[tree_fs.A_TARGET] or "")) == "busybox"
        return False
    return False


def qpot_hosts(tree) -> list[tuple[str, list[str]]]:
    """The entries of the persona's /etc/hosts: (address, names)."""
    try:
        text = tree.file_contents("/etc/hosts").decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return []
    entries = []
    for line in text.splitlines():
        words = line.split("#", 1)[0].split()
        if len(words) >= 2:
            entries.append((words[0], words[1:]))
    return entries


def qpot_hosts_lookup(tree, name: str, v6: bool) -> str | None:
    """The address of name in /etc/hosts; an IPv6 one first where the resolver tries it first."""
    wanted = name.lower()
    found = [address for address, names in qpot_hosts(tree) if wanted in (n.lower() for n in names)]
    if v6:
        found.sort(key=lambda address: ":" not in address)
    else:
        found = [address for address in found if ":" not in address]
    return found[0] if found else None


def qpot_hosts_name(tree, address: str) -> str | None:
    """The first name /etc/hosts gives address."""
    for listed, names in qpot_hosts(tree):
        if listed == address:
            return names[0]
    return None


def qpot_net() -> dict:
    """The persona's network ([shell] network, as ip and ss show it)."""
    try:
        from cowrie.commands.netstat import tpot_net_data
    except ImportError:
        return {"interfaces": []}
    return tpot_net_data(CowrieConfig.get("shell", "network", fallback=""))


def qpot_local_addresses() -> tuple[set[str], str, set[str]]:
    """(the machine's own addresses, its gateway, the broadcast addresses of its networks)."""
    net = qpot_net()
    local, broadcasts = set(), set()
    for iface in net.get("interfaces") or []:
        for key in ("inet", "inet6"):
            if iface.get(key):
                local.add(str(iface[key]))
        if iface.get("broadcast"):
            broadcasts.add(str(iface["broadcast"]))
    return local, str(net.get("gateway") or ""), broadcasts


def qpot_interface_addresses() -> list[str]:
    """The IPv4 addresses, then the global IPv6 ones, of the interfaces other than lo (hostname -I)."""
    net = qpot_net()
    v4, v6 = [], []
    for iface in net.get("interfaces") or []:
        if iface.get("name") == "lo":
            continue
        if iface.get("inet") and not str(iface["inet"]).startswith("127."):
            v4.append(str(iface["inet"]))
        inet6 = str(iface.get("inet6") or "")
        if inet6 and not inet6.lower().startswith("fe80"):
            v6.append(inet6)
    return v4 + v6


def qpot_own_address(protocol, name: str) -> str | None:
    """The address the machine's own name resolves to without an /etc/hosts line (nss myhostname)."""
    host = str(getattr(protocol, "hostname", "") or "")
    if host and name.lower() in (host.lower(), host.split(".")[0].lower()):
        addresses = qpot_interface_addresses()
        return addresses[0] if addresses else "127.0.0.1"
    return None


QUOTE_ESCAPES = {"\\": "\\\\", "\a": "\\a", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r",
                 "\t": "\\t", "\v": "\\v"}


def qpot_quote(text: str) -> str:
    """A name in a message of GNU coreutils in a UTF-8 locale (quote(): C escapes inside ‘’)."""
    escaped = "".join(QUOTE_ESCAPES.get(c) or (f"\\{ord(c):03o}" if ord(c) < 32 or ord(c) == 127 else c)
                      for c in text)
    return f"‘{escaped}’"


def qpot_register(cls, *paths: str) -> None:
    for path in paths:
        commands[path] = cls


def qpot_bin(name: str) -> list[str]:
    return [f"/bin/{name}", f"/usr/bin/{name}"]


class QpotCommand(HoneyPotCommand):
    """A command that ends with its exit status and never takes the session down."""

    def start(self) -> None:
        try:
            code = self.run()
        except Exception:  # noqa: BLE001 - a bad argument must not end the session
            code = 1
        if code is not None and not self.exited:
            self.exit(code)

    def run(self) -> int | None:
        return 0

    def busybox(self) -> bool:
        return qpot_busybox_applet(self.fs, posixpath.basename(self.qpot_name))

    def usage_stop(self) -> bool:
        """BusyBox: --help, no argument where needed, an unknown option: its usage, status 1."""
        if not self.busybox():
            return False
        from cowrie.commands.uname import tpot_bb_usage_stop

        return tpot_bb_usage_stop(self, posixpath.basename(self.qpot_name), list(self.args))

    def try_help(self, text: str = "") -> int:
        name = posixpath.basename(self.qpot_name)
        self.errorWrite(f"{text}Try '{name} --help' for more information.\n")
        return 1

    def exec_program(self, words: list[str], failed) -> int | None:
        """Run words in this command's place (exec), as sudo and busybox do."""
        cmdclass = self.protocol.getCommand(words[0], self.environ.get("PATH", "").split(":"), self.cwd)
        if not cmdclass:
            return failed(words[0])
        pp = PipeProtocol(self.protocol, cmdclass, words[1:], self.input_data, self.pp.targets,
                          cwd=self.cwd, user=self.user)
        pp.stdin_from_pipe = self.pp.stdin_from_pipe
        self.exec_command(pp, cmdclass, *words[1:])
        return None


# --- hostname -------------------------------------------------------------------------------

HOSTNAME_USAGE = """Usage: hostname [-b] {hostname|-F file}         set host name (from file)
       hostname [-a|-A|-d|-f|-i|-I|-s|-y]       display formatted name
       hostname                                 display host name

       {yp,nis,}domainname {nisdomain|-F file}  set NIS domain name (from file)
       {yp,nis,}domainname                      display NIS domain name

       dnsdomainname                            display dns domain name

       hostname -V|--version|-h|--help          print info and exit

Program name:
       {yp,nis,}domainname=hostname -y
       dnsdomainname=hostname -d

Program options:
    -a, --alias            alias names
    -A, --all-fqdns        all long host names (FQDNs)
    -b, --boot             set default hostname if none available
    -d, --domain           DNS domain name
    -f, --fqdn, --long     long host name (FQDN)
    -F, --file             read host name or NIS domain name from given file
    -i, --ip-address       addresses for the host name
    -I, --all-ip-addresses all addresses for the host
    -s, --short            short host name
    -y, --yp, --nis        NIS/YP domain name

Description:
   This command can get or set the host name or the NIS domain name. You can
   also get the DNS domain or the FQDN (fully qualified domain name).
   Unless you are using bind or NIS for host lookups you can change the
   FQDN (Fully Qualified Domain Name) and the DNS domain name (which is
   part of the FQDN) in the /etc/hosts file.
"""
HOSTNAME_LONG = {"alias": "a", "all-fqdns": "A", "boot": "b", "domain": "d", "fqdn": "f", "long": "f",
                 "file": "F", "help": "h", "ip-address": "i", "all-ip-addresses": "I", "short": "s",
                 "verbose": "v", "version": "V", "yp": "y", "nis": "y"}


class Command_hostname(QpotCommand):
    """hostname of the hostname package (net-tools on CentOS 7) or BusyBox's applet. Cowrie's set the
    host name to its first argument, so `hostname -f` renamed the host (and the prompt) to -f."""

    qpot_name = "hostname"

    def run(self) -> int | None:
        busybox = self.busybox()
        if busybox and self.usage_stop():
            return self.exit_code
        try:
            if busybox:
                options, rest = getopt.gnu_getopt(self.args, "sidfF:")
            else:
                options, rest = getopt.gnu_getopt(self.args, "aAbdfF:hiIsvVy",
                                                  [k + ("=" if k == "file" else "") for k in HOSTNAME_LONG])
        except getopt.GetoptError as err:
            opt = err.opt or ""
            if len(opt) > 1:
                self.errorWrite(f"hostname: unrecognized option '--{opt}'\n{HOSTNAME_USAGE}")
            elif "requires" in err.msg:
                self.errorWrite(f"hostname: option requires an argument -- '{opt}'\n{HOSTNAME_USAGE}")
            else:
                self.errorWrite(f"hostname: invalid option -- '{opt}'\n{HOSTNAME_USAGE}")
            return 1 if busybox else 255
        show, new_name = "", None
        for opt, value in options:
            key = HOSTNAME_LONG.get(opt.lstrip("-"), opt.lstrip("-")) if opt.startswith("--") else opt[1:]
            if key == "V":
                self.write(f"hostname {self.version()}\n")
                return 0
            if key == "h":
                self.write(HOSTNAME_USAGE)
                return 0
            if key == "F":
                try:
                    new_name = self.fs.file_contents(self.fs.resolve_path(value, self.cwd)).decode(
                        "utf-8", errors="replace").split("\n")[0].strip()
                except Exception:  # noqa: BLE001
                    self.errorWrite(f"hostname: {value}: No such file or directory\n")
                    return 1
            elif key in "aAdfiIsy":
                show = key
        if rest and new_name is None and not show:
            new_name = rest[0]
        if new_name is not None:
            return self.set_name(new_name)
        self.write(self.display(show))
        return 0

    def version(self) -> str:
        os_id, version = qpot_os_release(self.fs)
        major = version[0] if version else 0
        if os_id == "centos" and major <= 7:
            return "3.13"
        if os_id == "debian" and major >= 13:
            return "3.25"
        return "3.23"

    def set_name(self, name: str) -> int:
        if self.user.get("uid") != 0:
            self.errorWrite("hostname: you must be root to change the host name\n")
            return 1
        if not name or len(name) > 64 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", name):
            self.errorWrite("hostname: the specified hostname is invalid\n")
            return 1
        self.protocol.hostname = name
        return 0

    def display(self, show: str) -> str:
        host = str(self.protocol.hostname)
        entry = next(((address, names) for address, names in qpot_hosts(self.fs)
                      if host.lower() in (n.lower() for n in names)), None)
        fqdn = entry[1][0] if entry else host
        if show == "s":
            return host.split(".")[0] + "\n"
        if show == "f":
            return fqdn + "\n"
        if show == "d":
            return fqdn.partition(".")[2] + "\n"
        if show == "a":
            return " ".join(n for n in (entry[1][1:] if entry else [])) + "\n"
        if show == "i":
            listed = [address for address, names in qpot_hosts(self.fs)
                      if host.lower() in (n.lower() for n in names)]
            return " ".join(listed or qpot_interface_addresses()[:1] or ["127.0.0.1"]) + "\n"
        if show == "I":
            return "".join(f"{address} " for address in qpot_interface_addresses()) + "\n"
        if show == "A":
            return f"{fqdn} \n"
        if show == "y":
            return "(none)\n"
        return host + "\n"


commands["/bin/hostname"] = Command_hostname
commands["hostname"] = Command_hostname


# --- arch, sync, tty, printenv --------------------------------------------------------------


class Command_arch(QpotCommand):
    qpot_name = "arch"

    def run(self) -> int | None:
        if self.usage_stop():
            return self.exit_code
        if self.args:
            return self.try_help(f"arch: extra operand {qpot_quote(self.args[0])}\n")
        from cowrie.commands.uname import hardware_platform

        self.write(f"{hardware_platform()}\n")
        return 0


class Command_sync(QpotCommand):
    qpot_name = "sync"


class Command_tty(QpotCommand):
    qpot_name = "tty"

    def run(self) -> int | None:
        if self.usage_stop():
            return self.exit_code
        silent = any(a in ("-s", "--silent", "--quiet") for a in self.args)
        from cowrie.commands.base import tpot_pty

        if tpot_pty(self.protocol):
            if not silent:
                self.write("/dev/pts/0\n")
            return 0
        if not silent:
            self.write("not a tty\n")
        return 1


class Command_printenv(QpotCommand):
    qpot_name = "printenv"

    def run(self) -> int | None:
        names = [a for a in self.args if not a.startswith("-")]
        if not names:
            for name in self.environ:
                if name in self.exported:
                    self.write(f"{name}={self.environ[name]}\n")
            return 0
        code = 0
        for name in names:
            if name in self.environ and name in self.exported:
                self.write(f"{self.environ[name]}\n")
            else:
                code = 1
        return code


# --- basename, dirname ----------------------------------------------------------------------


def gnu_basename(name: str, suffix: str = "") -> str:
    stripped = name.rstrip("/")
    if not stripped:
        return "/" if name else ""
    base = stripped.rsplit("/", 1)[-1]
    if suffix and base != suffix and base.endswith(suffix):
        base = base[: -len(suffix)]
    return base


def gnu_dirname(name: str) -> str:
    stripped = name.rstrip("/")
    if not stripped:
        return "/" if name.startswith("/") else "."
    if "/" not in stripped:
        return "."
    head = stripped.rsplit("/", 1)[0].rstrip("/")
    return head or "/"


class Command_basename(QpotCommand):
    qpot_name = "basename"

    def run(self) -> int | None:
        if self.usage_stop():
            return self.exit_code
        try:
            options, rest = getopt.gnu_getopt(self.args, "as:z", ["multiple", "suffix=", "zero"])
        except getopt.GetoptError as err:
            return self.try_help(f"basename: invalid option -- '{err.opt}'\n")
        multiple = any(o in ("-a", "--multiple", "-s", "--suffix") for o, _ in options)
        suffix = next((v for o, v in options if o in ("-s", "--suffix")), "")
        end = "\0" if any(o in ("-z", "--zero") for o, _ in options) else "\n"
        if not rest:
            return self.try_help("basename: missing operand\n")
        if not multiple:
            if len(rest) > 2:
                return self.try_help(f"basename: extra operand {qpot_quote(rest[2])}\n")
            self.write(gnu_basename(rest[0], rest[1] if len(rest) == 2 else "") + end)
            return 0
        self.write("".join(gnu_basename(name, suffix) + end for name in rest))
        return 0


class Command_dirname(QpotCommand):
    qpot_name = "dirname"

    def run(self) -> int | None:
        if self.usage_stop():
            return self.exit_code
        names = [a for a in self.args if a not in ("-z", "--zero")]
        if not names:
            return self.try_help("dirname: missing operand\n")
        end = "\0" if len(names) != len(self.args) else "\n"
        self.write("".join(gnu_dirname(name) + end for name in names))
        return 0


# --- md5sum and the sha sums ----------------------------------------------------------------


class QpotSum(QpotCommand):
    consumes_stdin = True
    algorithm = "md5"

    def run(self) -> int | None:
        if self.usage_stop():
            return self.exit_code
        name = posixpath.basename(self.qpot_name)
        files, binary = [], False
        for arg in self.args:
            if arg in ("-b", "--binary"):
                binary = True
            elif arg in ("-t", "--text", "--tag", "-z", "--zero", "--"):
                continue
            elif arg.startswith("-") and arg != "-":
                letter = arg.lstrip("-")[:1]
                return self.try_help(f"{name}: invalid option -- '{letter}'\n")
            else:
                files.append(arg)
        code = 0
        for path in files or ["-"]:
            data = self.contents(path, name)
            if data is None:
                code = 1
                continue
            digest = hashlib.new(self.algorithm, data).hexdigest()
            self.write(f"{digest} {'*' if binary else ' '}{path}\n")
        return code

    def contents(self, path: str, name: str) -> bytes | None:
        if path == "-":
            return self.input_data or b""
        full = self.fs.resolve_path(path, self.cwd)
        if not self.fs.exists(full):
            self.errorWrite(f"{name}: {path}: No such file or directory\n")
            return None
        if self.fs.isdir(full):
            self.errorWrite(f"{name}: {path}: Is a directory\n")
            return None
        node = self.fs.getfile(full)
        size = int(node[tree_fs.A_SIZE] or 0) if node else 0
        backed = (node is None or size == 0 or node[tree_fs.A_REALFILE]
                  or isinstance(node[tree_fs.A_CONTENTS], bytes) or full in getattr(self.fs, "generated_files", {}))
        if backed:
            try:
                return self.fs.file_contents(full)
            except Exception:  # noqa: BLE001
                self.errorWrite(f"{name}: {path}: No such file or directory\n")
                return None
        # A program of the tree without contents reads as the same generic header for every file, so
        # two of them would hash alike: hash a few bytes that are its own and stable instead (not
        # bytes of its size: summing a directory of large programs would stall the reactor).
        return hashlib.sha256(f"{self.protocol.hostname}|{full}|{size}".encode()).digest()


def qpot_sum(algorithm: str, name: str):
    return type(f"Command_{name}", (QpotSum,), {"algorithm": algorithm, "qpot_name": name})


# --- mktemp ---------------------------------------------------------------------------------


class Command_mktemp(QpotCommand):
    qpot_name = "mktemp"

    def run(self) -> int | None:
        if self.usage_stop():
            return self.exit_code
        try:
            options, rest = getopt.gnu_getopt(self.args, "dup:qt", ["directory", "dry-run", "quiet",
                                                                    "suffix=", "tmpdir=", "p="])
        except getopt.GetoptError as err:
            return self.try_help(f"mktemp: invalid option -- '{err.opt}'\n")
        keys = {o for o, _ in options}
        directory = bool(keys & {"-d", "--directory"})
        dry = bool(keys & {"-u", "--dry-run"})
        tmpdir = next((v for o, v in options if o in ("-p", "--tmpdir")), None)
        busybox = self.busybox()
        default = "tmp.XXXXXX" if busybox else "tmp.XXXXXXXXXX"
        if len(rest) > 1:
            return self.try_help("mktemp: too many templates\n")
        template = rest[0] if rest else default
        if not rest or "-t" in keys or tmpdir is not None:
            if "/" not in template or tmpdir is not None or not rest:
                template = posixpath.join(tmpdir or self.environ.get("TMPDIR", "/tmp") or "/tmp", template)
        x = len(template) - len(template.rstrip("X"))
        if x < 3:
            self.errorWrite(f"mktemp: too few X's in template {qpot_quote(template)}\n")
            return 1
        alphabet = string.ascii_letters + string.digits
        path = template[: len(template) - x] + "".join(random.choice(alphabet) for _ in range(x))
        if not dry:
            full = self.fs.resolve_path(path, self.cwd)
            parent = posixpath.dirname(full)
            if not self.fs.isdir(parent):
                kind = "directory" if directory else "file"
                self.errorWrite(f"mktemp: failed to create {kind} via template {qpot_quote(template)}: "
                                "No such file or directory\n")
                return 1
            uid, gid = self.user.get("uid", 0), self.user.get("gid", 0)
            try:
                if directory:
                    self.fs.mkdir(full, uid, gid, 4096, 0o40700)
                else:
                    self.fs.mkfile(full, uid, gid, 0, 0o100600)
            except Exception:  # noqa: BLE001 - a read-only place of the tree
                self.errorWrite(f"mktemp: failed to create {'directory' if directory else 'file'} via "
                                f"template {qpot_quote(template)}: Permission denied\n")
                return 1
        self.write(path + "\n")
        return 0


# --- timeout, setsid, nice: run a program in their place ------------------------------------

DURATION = re.compile(r"(\d+(\.\d*)?|\.\d+)([smhd]?)")


class Command_timeout(QpotCommand):
    qpot_name = "timeout"

    def run(self) -> int | None:
        if self.usage_stop():
            return self.exit_code
        args = list(self.args)
        while args and args[0].startswith("-") and args[0] != "-":
            option = args.pop(0)
            if option in ("-s", "--signal", "-k", "--kill-after") and args:
                args.pop(0)
            elif option == "--":
                break
        if len(args) < 2:
            self.errorWrite("Try 'timeout --help' for more information.\n")
            return 125
        if not DURATION.fullmatch(args[0]):
            self.errorWrite(f"timeout: invalid time interval {qpot_quote(args[0])}\n"
                            "Try 'timeout --help' for more information.\n")
            return 125

        def failed(name: str) -> int:
            self.errorWrite(f"timeout: failed to run command {qpot_quote(name)}: No such file or directory\n")
            return 127

        return self.exec_program(args[1:], failed)


class Command_setsid(QpotCommand):
    qpot_name = "setsid"

    def run(self) -> int | None:
        if self.usage_stop():
            return self.exit_code
        args = list(self.args)
        while args and args[0] in ("-c", "--ctty", "-f", "--fork", "-w", "--wait"):
            args.pop(0)
        if not args:
            self.errorWrite("setsid: no command specified\nTry 'setsid --help' for more information.\n")
            return 1

        def failed(name: str) -> int:
            self.errorWrite(f"setsid: failed to execute {name}: No such file or directory\n")
            return 1

        return self.exec_program(args, failed)


class Command_nice(QpotCommand):
    qpot_name = "nice"

    def run(self) -> int | None:
        if self.usage_stop():
            return self.exit_code
        args = list(self.args)
        adjustment = None
        if args and args[0] in ("-n", "--adjustment") and len(args) > 1:
            adjustment = args[1]
            args = args[2:]
        elif args and re.fullmatch(r"-(n)?-?\d+", args[0]):
            adjustment = args.pop(0)
        if not args:
            if adjustment is not None:
                self.errorWrite("nice: a command must be given with an adjustment\n"
                                "Try 'nice --help' for more information.\n")
                return 125
            self.write("0\n")
            return 0

        def failed(name: str) -> int:
            self.errorWrite(f"nice: {qpot_quote(name)}: No such file or directory\n")
            return 127

        return self.exec_program(args, failed)


# --- expr -----------------------------------------------------------------------------------


class ExprError(Exception):
    def __init__(self, text: str, code: int = 2):
        super().__init__(text)
        self.text, self.code = text, code


# expr matches with Python's backtracking matcher, in the reactor: patterns that could take more
# than about this many steps are not run (see Command_expr.match)
EXPR_STEPS = 10_000_000

# a size_t that a position or length of substr does not fit reads as
SIZE_MAX = 2 ** 64 - 1

# the classes of a bracket expression, as Python's
BRE_CLASSES = {"alpha": "a-zA-Z", "digit": "0-9", "alnum": "a-zA-Z0-9", "upper": "A-Z", "lower": "a-z",
               "space": r" \t\n\r\f\v", "blank": r" \t", "xdigit": "0-9A-Fa-f",
               "punct": re.escape(string.punctuation), "cntrl": r"\000-\037\177", "print": " -~",
               "graph": "!-~"}
# GNU regex's own escapes, as Python's; the anchors among them repeat nothing
BRE_ESCAPES = {"w": r"\w", "W": r"\W", "s": r"\s", "S": r"\S"}
BRE_ANCHORS = {"b": r"\b", "B": r"\B", "<": r"\b(?=\w)", ">": r"\b(?<=\w)", "`": r"\A", "'": r"\Z"}
BRE_BAD_BRACKET = "Unmatched [, [^, [:, [., or [="


def bre_bracket(pattern: str, i: int) -> tuple[str, int]:
    """The bracket expression that starts at pattern[i] as Python's, and the index after it."""
    j, parts, negated = i + 1, [], pattern.startswith("^", i + 1)
    j += negated
    first = True
    while j < len(pattern):
        c = pattern[j]
        if c == "]" and not first:
            if not parts:  # only empty ranges: nothing matches, or anything does
                return (r"[\s\S]" if negated else "(?!)"), j + 1
            return "[" + "^" * negated + "".join(parts) + "]", j + 1
        first = False
        end = pattern[j + 2:j + 3]
        if pattern[j + 1:j + 2] == "-" and end not in ("", "]") and c != "[":
            if c <= end:  # a range from high to low is empty, not an error, in GNU expr
                parts.append(re.escape(c) + "-" + re.escape(end))
            j += 3
            continue
        if c == "[" and pattern[j + 1:j + 2] in (":", "=", "."):
            kind = pattern[j + 1]
            end = pattern.find(kind + "]", j + 2)
            if end < 0:
                raise ExprError(BRE_BAD_BRACKET)
            name = pattern[j + 2:end]
            if kind == ":" and name not in BRE_CLASSES:
                raise ExprError("Invalid character class name")
            parts.append(BRE_CLASSES[name] if kind == ":" else re.escape(name))
            j = end + 2
            continue
        parts.append(re.escape(c))
        j += 1
    raise ExprError(BRE_BAD_BRACKET)


def bre(pattern: str) -> tuple[str, int, int, bool, float]:
    """GNU's basic regular expression as Python's: (regex, groups, repetitions, explosive, choices),
    where explosive means a repetition repeats something that repeats or alternates, or a
    back-reference is used (Python's matcher can then take exponential time), and choices is the log
    of the number of ways its alternatives combine (the product of each group's branch count)."""
    out: list[str] = []
    opened: list[tuple[int, int, int]] = []  # each open group: where it starts, repetitions and
    groups = closed = repeats = alternations = 0  # alternations before it
    branches = [1]  # the branches of the expression and of each open group so far
    choices = 0.0
    explosive = False
    atom: tuple[int, bool] | None = None  # the last atom: where it starts, whether it varies inside
    last_op = ""  # the repetition the last atom ends with, if any
    i, n = 0, len(pattern)

    def add(text: str) -> None:
        nonlocal atom, last_op
        atom, last_op = (len(out), False), ""
        out.append(text)

    def repeat(op: str) -> None:
        nonlocal atom, last_op, repeats, explosive
        start, varies = atom
        if last_op == "*" and op == "*":
            return  # a** is a*
        if last_op:
            out.insert(start, "(?:")
            out.append(")")
        repeats += 1
        explosive = explosive or varies or bool(last_op)
        out.append(op)
        atom, last_op = (start, True), op

    while i < n:
        c = pattern[i]
        if c == "\\":
            if i + 1 >= n:
                raise ExprError("Trailing backslash")
            e = pattern[i + 1]
            i += 2
            if e == "(":
                opened.append((len(out), repeats, alternations))
                branches.append(1)
                out.append("(")
                groups += 1
                atom, last_op = None, ""
            elif e == ")":
                if not opened:
                    raise ExprError("Unmatched ) or \\)")
                start, repeats_before, alternations_before = opened.pop()
                choices += math.log(branches.pop())
                out.append(")")
                closed += 1
                atom = (start, repeats > repeats_before or alternations > alternations_before)
                last_op = ""
            elif e == "|":
                out.append("|")
                alternations += 1
                branches[-1] += 1
                atom, last_op = None, ""
            elif e == "{" and atom is None:
                add(re.escape("{"))  # nothing to repeat: a plain brace, as GNU expr reads it
            elif e == "{":
                end = pattern.find("\\}", i)
                if end < 0:
                    raise ExprError("Unmatched \\{")
                bounds = re.fullmatch(r"(\d*)(,?)(\d*)", pattern[i:end])
                i = end + 2
                if not bounds or not (bounds.group(1) or bounds.group(2)) or (
                        bounds.group(3) and not bounds.group(2)):
                    raise ExprError("Invalid content of \\{\\}")
                low = int(bounds.group(1) or 0)
                high = int(bounds.group(3)) if bounds.group(3) else (low if not bounds.group(2) else None)
                if max(low, high or 0) > 32767:
                    raise ExprError("Regular expression too big")
                if high is not None and low > high:
                    raise ExprError("Invalid content of \\{\\}")
                repeat(f"{{{low}}}" if high == low else f"{{{low},{'' if high is None else high}}}")
            elif e in ("+", "?"):
                if atom is None:
                    add(re.escape(e))
                else:
                    repeat(e)
            elif e in "123456789":
                if int(e) > closed:
                    raise ExprError("Invalid back reference")
                explosive = True
                add("\\" + e)
            elif e in BRE_ESCAPES:
                add(BRE_ESCAPES[e])
            elif e in BRE_ANCHORS:
                out.append(BRE_ANCHORS[e])
                atom, last_op = None, ""
            else:
                add(re.escape(e))
        elif c == "[":
            text, i = bre_bracket(pattern, i)
            add(text)
        elif c == "*" and atom is not None:
            repeat("*")
            i += 1
        elif c == "^" and (not out or out[-1] in ("(", "|")):
            out.append("^")
            i += 1
        elif c == "$" and (i + 1 == n or pattern.startswith("\\)", i + 1) or pattern.startswith("\\|", i + 1)):
            out.append(r"\Z")
            atom, last_op = None, ""
            i += 1
        else:
            add("." if c == "." else re.escape(c))
            i += 1
    if opened:
        raise ExprError("Unmatched ( or \\(")
    return "".join(out), groups, repeats, explosive, choices + math.log(branches[0])


class Command_expr(QpotCommand):
    """expr of GNU coreutils: | & comparisons + - * / % : and match substr index length."""

    qpot_name = "expr"

    def run(self) -> int | None:
        if self.usage_stop():
            return self.exit_code
        args = self.args[1:] if self.args[:1] == ["--"] else self.args
        if not args:
            self.errorWrite("expr: missing operand\nTry 'expr --help' for more information.\n")
            return 2
        self.tokens, self.at, self.evaluate = list(args), 0, True
        try:
            value = self.parse_or()
            if self.at < len(self.tokens):
                raise ExprError(f"syntax error: unexpected argument {qpot_quote(self.tokens[self.at])}")
        except ExprError as err:
            self.errorWrite(f"expr: {err.text}\n")
            return err.code
        self.write(f"{value}\n")
        return 1 if self.null(value) else 0

    @staticmethod
    def is_int(value: str) -> bool:
        return bool(re.fullmatch(r"-?\d+", value))

    def need(self, after: str) -> str:
        if self.at >= len(self.tokens):
            raise ExprError(f"syntax error: missing argument after {qpot_quote(after)}")
        token = self.tokens[self.at]
        self.at += 1
        return token

    def peek(self) -> str | None:
        return self.tokens[self.at] if self.at < len(self.tokens) else None

    def number(self, value: str) -> int:
        if not self.is_int(value):
            raise ExprError("non-integer argument")
        return int(value)

    @staticmethod
    def null(value: str) -> bool:
        """GNU's null(): empty, or a zero ("0", "-0", "000")."""
        return value == "" or re.fullmatch(r"-?0+", value) is not None

    def operator(self, names: tuple[str, ...]) -> str | None:
        """The operator at the cursor, taken, when it is one of names."""
        if self.peek() in names:
            self.at += 1
            return self.tokens[self.at - 1]
        return None

    def lazily(self, evaluate: bool, parse):
        """parse(), evaluating only if evaluate (GNU expr parses the operand | or & will not use
        without computing it, so `expr 1 \\| 1 / 0` prints 1)."""
        saved, self.evaluate = self.evaluate, self.evaluate and evaluate
        try:
            return parse()
        finally:
            self.evaluate = saved

    def parse_or(self) -> str:
        left = self.parse_and()
        while self.operator(("|",)):
            right = self.lazily(self.null(left), self.parse_and)
            if self.null(left):
                left = "0" if self.null(right) else right
        return left

    def parse_and(self) -> str:
        left = self.parse_compare()
        while self.operator(("&",)):
            right = self.lazily(not self.null(left), self.parse_compare)
            if self.null(left) or self.null(right):
                left = "0"
        return left

    def parse_compare(self) -> str:
        left = self.parse_add()
        while op := self.operator(("<", "<=", "=", "==", "!=", ">=", ">")):
            right = self.parse_add()
            if self.is_int(left) and self.is_int(right):
                a, b = int(left), int(right)
            else:
                a, b = left, right
            result = {"<": a < b, "<=": a <= b, "=": a == b, "==": a == b, "!=": a != b,
                      ">=": a >= b, ">": a > b}[op]
            left = "1" if result else "0"
        return left

    def parse_add(self) -> str:
        left = self.parse_mul()
        while op := self.operator(("+", "-")):
            right = self.parse_mul()
            if self.evaluate:
                a, b = self.number(left), self.number(right)
                left = str(a + b if op == "+" else a - b)
        return left

    def parse_mul(self) -> str:
        left = self.parse_match()
        while op := self.operator(("*", "/", "%")):
            right = self.parse_match()
            if not self.evaluate:
                continue
            a, b = self.number(left), self.number(right)
            if op != "*" and b == 0:
                raise ExprError("division by zero")
            if op == "*":
                left = str(a * b)
            else:
                quotient = abs(a) // abs(b) * (1 if (a >= 0) == (b >= 0) else -1)
                left = str(quotient if op == "/" else a - b * quotient)
        return left

    def parse_match(self) -> str:
        left = self.parse_unary()
        while self.operator((":",)):
            right = self.parse_unary()
            if self.evaluate:
                left = self.match(left, right)
        return left

    def match(self, text: str, pattern: str) -> str:
        """A basic regular expression anchored at the start: the group, else the length matched."""
        regex, groups, repeats, explosive, choices = bre(pattern)
        # Python's matcher backtracks, and it runs in the reactor every session shares: a pattern
        # that could take it too long reads as one that does not match. It can try about
        # len(text) ** repeats ways for each way its alternatives combine, and 2 ** len(text) times
        # that when a repetition repeats or a back-reference is used.
        size = max(len(text), 1)
        steps = choices + repeats * math.log(size) + (len(text) * math.log(2) if explosive else 0)
        if steps > math.log(EXPR_STEPS):
            found = None
        else:
            try:
                found = re.match(regex, text, re.DOTALL)
            except re.error as err:
                bad_range = "bad character range" in str(err)
                raise ExprError("Invalid range end" if bad_range else "Invalid regular expression") from None
            except (OverflowError, RecursionError):
                raise ExprError("Regular expression too big") from None
        if groups:
            return found.group(1) if found and found.group(1) is not None else ""
        return str(found.end()) if found else "0"

    def parse_unary(self) -> str:
        """+ and the keywords, whose operands are parsed the same way (GNU's eval6)."""
        token = self.peek()
        if token == "+":
            self.at += 1
            return self.need("+")
        if token == "length":
            self.at += 1
            return str(len(self.parse_unary()))
        if token == "match":
            self.at += 1
            text, pattern = self.parse_unary(), self.parse_unary()
            return self.match(text, pattern) if self.evaluate else text
        if token == "index":
            self.at += 1
            text, chars = self.parse_unary(), self.parse_unary()
            positions = [i + 1 for i, c in enumerate(text) if c in chars]
            return str(positions[0]) if positions else "0"
        if token == "substr":
            self.at += 1
            text, start, length = self.parse_unary(), self.parse_unary(), self.parse_unary()
            if not (self.is_int(start) and self.is_int(length)):
                return ""
            # a position or length that does not fit a size_t reads as SIZE_MAX, which gives ""
            first, count = int(start), int(length)
            if not 1 <= first <= len(text) or not 0 < count < SIZE_MAX:
                return ""
            return text[first - 1:first - 1 + count]
        return self.parse_atom()

    def parse_atom(self) -> str:
        """A parenthesised expression or a string (GNU's eval7)."""
        if self.at >= len(self.tokens):
            raise ExprError(f"syntax error: missing argument after {qpot_quote(self.tokens[-1])}")
        token = self.tokens[self.at]
        self.at += 1
        if token == "(":
            value = self.parse_or()
            if self.at >= len(self.tokens):
                raise ExprError(f"syntax error: expecting ')' after {qpot_quote(self.tokens[self.at - 1])}")
            if self.peek() != ")":
                raise ExprError(f"syntax error: expecting ')' instead of {qpot_quote(self.tokens[self.at])}")
            self.at += 1
            return value
        if token == ")":
            raise ExprError("syntax error: unexpected ')'")
        return token


# --- bash --version, exit at the login shell ------------------------------------------------

# bash of each release: (version, copyright year) and the platform it was built for
BASH_RELEASES = {("ubuntu", 24): ("5.2.21(1)-release", 2022), ("ubuntu", 22): ("5.1.16(1)-release", 2020),
                 ("debian", 13): ("5.2.37(1)-release", 2022), ("debian", 12): ("5.2.15(1)-release", 2022),
                 ("debian", 11): ("5.1.4(1)-release", 2020), ("raspbian", 12): ("5.2.15(1)-release", 2022),
                 ("rhel", 9): ("5.1.8(1)-release", 2020), ("centos", 7): ("4.2.46(2)-release", 2011)}


def qpot_bash_version(tree) -> str | None:
    """What `bash --version` prints on the persona, None where it is not known."""
    os_id, version = qpot_os_release(tree)
    release = BASH_RELEASES.get((os_id, version[0] if version else 0))
    if release is None:
        return None
    from cowrie.commands.uname import hardware_platform

    machine = hardware_platform()
    if os_id in ("rhel", "centos"):
        platform = f"{machine}-redhat-linux-gnu"
    elif machine == "x86_64":
        platform = "x86_64-pc-linux-gnu"
    elif machine.startswith("arm"):
        platform = "arm-unknown-linux-gnueabihf"
    else:
        platform = f"{machine}-unknown-linux-gnu"
    return (f"GNU bash, version {release[0]} ({platform})\n"
            f"Copyright (C) {release[1]} Free Software Foundation, Inc.\n"
            "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n\n"
            "This is free software; you are free to change and redistribute it.\n"
            "There is NO WARRANTY, to the extent permitted by law.\n")


try:
    from cowrie.commands.bash import Command_exit, Command_sh
except ImportError:  # pragma: no cover - the image always has them
    Command_exit = Command_sh = None

if Command_sh is not None:

    class Command_bash(Command_sh):
        """bash --version as the persona's bash (Cowrie's ran a nested shell and printed nothing)."""

        def start(self) -> None:
            if self.args[:1] == ["--version"] and not CowrieConfig.get("shell", "bash_version", fallback=""):
                text = qpot_bash_version(self.fs)
                if text is not None:
                    self.write(text)
                    self.exit(0)
                    return
            super().start()

    commands["/bin/bash"] = Command_bash
    commands["bash"] = Command_bash

if Command_exit is not None:

    class Command_logout(Command_exit):
        """exit at the login shell of a terminal: bash says logout as it ends the session."""

        def call(self) -> None:
            stack = self.protocol.cmdstack
            login = (len(stack) == 2 and hasattr(self.protocol, "lineBuffer")
                     and CowrieConfig.get("shell", "not_found_style", fallback="bash") == "bash")
            if login:
                self.write("logout\n")
            super().call()

    commands["exit"] = Command_logout
    commands["logout"] = Command_logout


for qpot_cls, qpot_names in (
    (Command_arch, qpot_bin("arch")),
    (Command_sync, qpot_bin("sync")),
    (Command_tty, qpot_bin("tty")),
    (Command_printenv, qpot_bin("printenv")),
    (Command_basename, qpot_bin("basename")),
    (Command_dirname, qpot_bin("dirname")),
    (Command_mktemp, qpot_bin("mktemp")),
    (Command_timeout, qpot_bin("timeout")),
    (Command_setsid, qpot_bin("setsid")),
    (Command_nice, qpot_bin("nice")),
    (Command_expr, qpot_bin("expr")),
    (qpot_sum("md5", "md5sum"), qpot_bin("md5sum")),
    (qpot_sum("sha1", "sha1sum"), qpot_bin("sha1sum")),
    (qpot_sum("sha256", "sha256sum"), qpot_bin("sha256sum")),
    (qpot_sum("sha512", "sha512sum"), qpot_bin("sha512sum")),
):
    qpot_register(qpot_cls, *qpot_names)
