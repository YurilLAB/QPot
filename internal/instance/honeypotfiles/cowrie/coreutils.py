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
import stat as stat_mod
import string
import time

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


qpot_packages_seen: list = []


def qpot_package_version(name: str) -> str | None:
    """The version the persona's package database (apt-packages.json beside its tree) gives an installed
    package, read once per process; None for a persona without one."""
    if not qpot_packages_seen:
        installed: dict = {}
        try:
            import json
            import os

            from cowrie.core import qpot_bait

            root = qpot_bait._contents_root()
            data = qpot_bait._read_bounded(os.path.join(os.path.dirname(root.rstrip("/")), "apt-packages.json"),
                                           16 << 20) if root else None
            loaded = json.loads(data.decode("utf-8")) if data else {}
            found = loaded.get("installed") if isinstance(loaded, dict) else None
            if isinstance(found, dict):
                installed = {k: v for k, v in found.items() if isinstance(k, str) and isinstance(v, str)}
        except Exception:  # noqa: BLE001 - no database, a broken one: no versions
            installed = {}
        qpot_packages_seen.append(installed)
    return qpot_packages_seen[0].get(name)


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


# addresses the honeypot never contacts beyond Cowrie's blocklist: Azure's WireServer (a public address
#   that answers only the VM itself, with its configuration)
QPOT_BLOCKED_EXTRA = (ipaddress.ip_network("168.63.129.16/32"),)


def qpot_blocked(address: str) -> bool:
    """Whether the honeypot never contacts address (private, loopback, link-local, multicast, CGNAT,
    metadata, IPv6 wrappers of those ...): Cowrie's own blocklist, which its downloads apply
    (resolve_allowed), and QPOT_BLOCKED_EXTRA."""
    try:
        from cowrie.core.network import _is_blocked

        ip = ipaddress.ip_address(address)
        mapped = getattr(ip, "ipv4_mapped", None)
        if any(ip in net or mapped is not None and mapped in net for net in QPOT_BLOCKED_EXTRA
               if ip.version == net.version or mapped is not None):
            return True
        return bool(_is_blocked(ip))
    except Exception:  # noqa: BLE001 - no address: nothing to contact
        return True


def qpot_fetch(url: str, address: str, method: str = "get", headers=None, timeout: int = 10):
    """One request of url (no redirect followed) to address, the very address the caller checked
    (qpot_route, or the one lookup of a name, then qpot_classify): upstream's fetch looks the URL's name
    up again and connects to that answer, so a name /etc/hosts gave a public address reached whatever
    the real DNS said, and a second answer could differ from the first. The name stays the Host header's
    and TLS's (SNI, the certificate check); the outbound address stays [honeypot] out_addr's. Raises
    BlockedAddress for an address that is not "network" (checked again here), UnreachableAddress for IPv6
    (as upstream: the outbound address is an IPv4 one)."""
    import treq
    from twisted.internet import reactor
    from urllib.parse import urlparse

    from cowrie.core.download import BlockedAddress, UnreachableAddress, pinned_agent

    host = urlparse(url).hostname or ""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        raise BlockedAddress(host) from None
    if qpot_classify(str(ip)) != "network":
        raise BlockedAddress(host)
    if ip.version == 6:
        raise UnreachableAddress(host)
    return getattr(treq, method)(url=url, agent=pinned_agent(reactor, str(ip)), allow_redirects=False,
                                 headers=headers, timeout=timeout)


def qpot_route(fs, protocol, host: str) -> tuple[str, str | None]:
    """Where a connection from the persona to host goes, worked out without the network:
    ("refused", address) for the machine itself (loopback, its own addresses, 0.0.0.0), where nothing listens
    on the port a client asks for; ("timeout", address) for an internal host of the bait files and any other
    address the honeypot does not contact (private, link-local ...), which the persona's network drops, as
    ssh's wait on the bait hosts has it; ("network", address) for a public address; ("name", None) for a
    name the resolver has to answer (not in /etc/hosts nor the machine's own)."""
    name = str(host or "").strip().lower().rstrip(".")
    if name.startswith("[") and name.endswith("]"):
        name = name[1:-1]
    if not name or len(name) > 253:
        return "name", None
    try:
        from cowrie.core import qpot_bait

        internal = qpot_bait.internal_host(name)
    except Exception:  # noqa: BLE001 - no bait module: no internal hosts
        internal = None
    if internal is not None:
        return "timeout", internal
    try:
        address = str(ipaddress.ip_address(name))
    except ValueError:
        address = (qpot_hosts_lookup(fs, name, False) or qpot_hosts_lookup(fs, name, True)
                   or qpot_own_address(protocol, name))
        if address is None:
            return "name", None
    return qpot_classify(address), address


def qpot_classify(address: str) -> str:
    """refused, timeout or network for an address (see qpot_route)."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "timeout"
    local, _, _ = qpot_local_addresses()
    if ip.is_loopback or ip.is_unspecified or str(ip) in local:
        return "refused"
    return "timeout" if qpot_blocked(str(ip)) else "network"


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
        if self.user.get("uid") != 0 and not bool(getattr(getattr(self, "pp", None), "tpot_sudo", False)):
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


# --- free: the same KiB counters as /proc/meminfo -------------------------------------------

try:
    from cowrie.commands.free import Command_free as _CowrieFree, FREE_OUTPUT as _FREE_OUTPUT
except ImportError:  # small standalone adapters do not include this image command
    _CowrieFree = None

if _CowrieFree is not None:

    class Command_free(_CowrieFree):
        """Retain the image's formats while scaling -m from KiB in binary units."""

        def busybox_family(self) -> str:
            if not qpot_busybox_applet(self.fs, "free"):
                return ""
            banner = CowrieConfig.get("shell", "text_banner", fallback="")
            match = re.search(r"BusyBox v(\d+)\.(\d+)\.(\d+)", banner)
            version = tuple(int(value) for value in match.groups()) if match else ()
            # These are the actual finite catalog releases, verified against
            # their released free.c. Do not project a modern applet onto old
            # firmware merely because both programs are BusyBox links.
            return {(1, 14, 1): "early", (1, 19, 4): "buffers",
                    (1, 24, 1): "cached", (1, 26, 2): "cached",
                    (1, 35, 0): "modern", (1, 37, 0): "modern"}.get(version, "")

        def busybox_usage(self) -> None:
            from cowrie.commands.uname import tpot_bb_usage_stop

            if not tpot_bb_usage_stop(self, "free", ["--help"]):
                family = self.busybox_family()
                synopsis = "" if family == "early" else (" [-bkmgh]" if family == "modern" else " [-b/k/m/g]")
                description = ("Display free and used memory" if family == "modern" else
                               "Display the amount of free and used system memory")
                banner = CowrieConfig.get("shell", "text_banner", fallback="BusyBox")
                self.errorWrite(f"{banner} multi-call binary.\n\nUsage: free{synopsis}\n\n{description}\n")
            self.exit_code = 1

        def call(self) -> None:
            busybox = qpot_busybox_applet(self.fs, "free")
            if busybox:
                from cowrie.commands.uname import tpot_bb_usage_stop

                family = self.busybox_family()
                if not family:
                    return super().call()
                if family == "early":
                    if self.args and self.args[0].startswith("-"):
                        self.busybox_usage()
                        return
                    return self.do_free()
                # BusyBox free selects the first character of the first
                # argument, rather than GNU's multiple-unit option parser.
                selected = self.args[0][1:2] if self.args and self.args[0].startswith("-") else "k"
                if not selected or selected not in ("bkmgh" if family == "modern" else "bkmg"):
                    self.busybox_usage()
                    return
                if tpot_bb_usage_stop(self, "free", ["-" + selected]):
                    return
                self.do_free({"b": "bytes", "m": "megabytes", "g": "gigabytes", "h": "human"}.get(selected, "kilobytes"))
                return
            try:
                options, operands = getopt.getopt(self.args, "kmh")
            except getopt.GetoptError as error:
                if len(error.opt) > 1:
                    self.errorWrite(f"free: unrecognized option '--{error.opt}'\n")
                else:
                    self.errorWrite(f"free: invalid option -- '{error.opt}'\n")
                self.exit_code = 1
                return
            if operands:
                self.errorWrite("\nUsage:\n free [options]\n")
                self.exit_code = 1
                return
            units = [option for option, _ in options if option in ("-k", "-m")]
            if len(units) > 1:
                self.errorWrite("free: Multiple unit options don't make sense.\n")
                self.exit_code = 1
                return
            selected = "-h" if any(option == "-h" for option, _ in options) else (units[0] if units else "")
            self.do_free({"-m": "megabytes", "-h": "human"}.get(selected, "kilobytes"))

        def do_free(self, fmt: str = "kilobytes") -> None:
            family = self.busybox_family()
            if family in ("early", "buffers", "cached"):
                return self.legacy_free(fmt, family)
            divisors = {"bytes": 1, "megabytes": 1 << 20, "gigabytes": 1 << 30}
            if fmt not in divisors:
                return super().do_free(fmt)
            values = self.get_free_stats()
            if not values:
                return
            values["calc_total_buffers_and_cache"] = values["Buffers"] + values["Cached"]
            values["calc_total_used"] = values["MemTotal"] - values["MemFree"] - values["calc_total_buffers_and_cache"]
            values["calc_swap_used"] = values["SwapTotal"] - values["SwapFree"]
            # Linux /proc reports KiB. GNU truncates MiB; BusyBox's
            # make_human_readable_str rounds to the nearest display unit.
            divisor = divisors[fmt]
            rounding = divisor // 2 if family == "modern" else 0
            self.write(_FREE_OUTPUT.format(**{key: (value * 1024 + rounding) // divisor
                                             for key, value in values.items()}))

        def legacy_free(self, fmt: str, family: str) -> None:
            values = self.get_free_stats()
            if not values:
                return
            divisor = {"bytes": 1, "megabytes": 1 << 20, "gigabytes": 1 << 30}.get(fmt, 1024)
            scale = lambda value: value * 1024 // divisor
            total, unused = values["MemTotal"], values["MemFree"]
            buffers, cached = values["Buffers"], values["Cached"]
            swap, swap_free = values["SwapTotal"], values["SwapFree"]
            fields = [total, total - unused, unused, values["Shmem"], buffers]
            labels = ["total", "used", "free", "shared", "buffers"]
            if family == "cached":
                fields.append(cached)
                labels.append("cached")
            width = 11 if family == "cached" else 13
            prefix = "       " if family == "cached" else ("      " if family == "early" else "     ")
            self.write(prefix + "".join(f"{label:>{width}}" for label in labels) + "\n")
            row = lambda data: "".join(f"{scale(value):>{width}}" for value in data) + "\n"
            self.write(("Mem:   " if family == "cached" else ("  Mem:" if family == "early" else "Mem: ")) + row(fields))
            if family != "early":
                reclaimable = buffers + (cached if family == "cached" else 0)
                self.write(("-/+ buffers/cache:" if family == "cached" else "-/+ buffers:      ") +
                           row([total - unused - reclaimable, unused + reclaimable]))
            self.write(("Swap:  " if family == "cached" else (" Swap:" if family == "early" else "Swap:")) +
                       row([swap, swap - swap_free, swap_free]))
            if family == "early":
                self.write("Total:" + row([total + swap, total - unused + swap - swap_free, unused + swap_free]))

    commands["/usr/bin/free"] = Command_free
    commands["free"] = Command_free


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
        try:
            # The same bytes cat, a pipe and an export read. A pathname or the machine's runtime
            # hostname is not file content: renaming either must not change an unchanged file's hash.
            # Unbacked programs retain the image's bounded generic header, not invented file bytes.
            return self.fs.file_contents(full)
        except Exception:  # noqa: BLE001
            self.errorWrite(f"{name}: {path}: No such file or directory\n")
            return None


def qpot_sum(algorithm: str, name: str):
    return type(f"Command_{name}", (QpotSum,), {"algorithm": algorithm, "qpot_name": name})


# --- zcat -----------------------------------------------------------------------------------


class Command_zcat(QpotSum):
    """zcat of gzip (a script running gzip -cd, so its messages are gzip's) or of BusyBox: the
    database dump of the bait files is read with it. Members are decompressed one after the other
    as gzip does; the output stops at QPOT_ZCAT_MAX bytes and after QPOT_ZCAT_MEMBERS members
    (each member copies the rest of the file), which bounds what a file of the attacker's (a
    bomb, a file of empty members) can make the reactor do."""

    qpot_name = "zcat"
    QPOT_ZCAT_MAX = 8 << 20
    QPOT_ZCAT_MEMBERS = 16

    def run(self) -> int | None:
        import zlib

        busybox = self.busybox()
        applet = posixpath.basename(self.qpot_name)
        # BusyBox names the applet it runs as (gzip -dc: "gzip: invalid magic"); GNU's zcat is gzip -cd
        prog = applet if busybox else "gzip"
        files = []
        for arg in self.args:
            if arg in ("-f", "--force", "-q", "--quiet", "-v", "--verbose", "--"):
                continue
            if arg.startswith("-") and arg != "-":
                letter = arg.lstrip("-")[:1]
                if busybox:
                    return self.try_help(f"zcat: invalid option -- '{letter}'\n")
                self.errorWrite(f"gzip: invalid option -- '{letter}'\n"
                                "Try `gzip --help' for more information.\n")
                return 1
            files.append(arg)  # patterns are the shell's (bashparse.py); a quoted one stays
        code, left = 0, self.QPOT_ZCAT_MAX
        for path in files or ["-"]:
            path = path if busybox else self.qpot_gz_name(path)
            data, status = self.qpot_gz_read(path, prog, busybox)
            if data is None:
                code = qpot_gzip_status(code, status)
                continue
            label = "stdin" if path == "-" else path
            if len(data) < 2 and (not busybox or applet == "zcat"):
                # gzip reads the magic with get_byte, whose end of file is an error; BusyBox's zcat
                # (open_zipped) cannot read two bytes
                self.errorWrite(f"{applet}: short read\n" if busybox else f"\ngzip: {label}: unexpected end of file\n")
                code = 1
                continue
            if data[:2] != b"\x1f\x8b":
                # QPot: gzip starts its error on a line of its own (get_method of gzip.c)
                self.errorWrite(f"{prog}: invalid magic\n" if busybox else f"\ngzip: {label}: not in gzip format\n")
                code = 1
                continue
            out, members = [], 0
            while data and left > 0 and members < self.QPOT_ZCAT_MEMBERS:
                members += 1
                if data[:2] != b"\x1f\x8b":
                    # trailing garbage after a member: gzip warns and ignores it
                    if not busybox:
                        self.errorWrite(f"gzip: {label}: decompression OK, trailing garbage ignored\n")
                        code = code or 2
                    break
                member = zlib.decompressobj(16 + zlib.MAX_WBITS)
                try:
                    chunk = member.decompress(data, left)
                except zlib.error:
                    self.errorWrite(f"{prog}: corrupted data\n" if busybox
                                    else f"\ngzip: {label}: invalid compressed data--format violated\n")
                    code = 1
                    break
                out.append(chunk)
                left -= len(chunk)
                if not member.eof:
                    if left > 0:
                        self.errorWrite(f"{prog}: unexpected end of file\n" if busybox
                                        else f"\ngzip: {label}: unexpected end of file\n")
                        code = 1
                    break
                data = member.unused_data
            self.writeBytes(b"".join(out))
        return code

    @staticmethod
    def qpot_plain_name(name: str) -> str:
        for suffix, plain in ((".tgz", ".tar"), (".taz", ".tar"), (".gz", ""), ("-gz", ""), (".z", ""), ("-z", ""),
                              ("_z", "")):
            if name.lower().endswith(suffix) and len(name) > len(suffix):
                return name[: len(name) - len(suffix)] + plain
        return name

    def qpot_gz_name(self, name: str) -> str:
        """The file GNU gzip decompresses for name (get_istat): name when it is there or has a gzip suffix,
        else the first of name.gz, .z, -z, .Z that is there, else name.gz (the name its message gives)."""
        if name == "-" or self.qpot_plain_name(name) != name or self.fs.exists(self.fs.resolve_path(name, self.cwd)):
            return name
        for suffix in (".gz", ".z", "-z", ".Z"):
            if self.fs.exists(self.fs.resolve_path(name + suffix, self.cwd)):
                return name + suffix
        return name + ".gz"

    def qpot_gz_read(self, path: str, prog: str, busybox: bool) -> tuple[bytes | None, int]:
        """The bytes of path, or None and gzip's status: a directory is skipped with GNU's warning (status
        2); BusyBox reads one as no bytes."""
        if path != "-":
            full = self.fs.resolve_path(path, self.cwd)
            if self.fs.exists(full) and self.fs.isdir(full):
                if busybox:
                    return b"", 0
                self.errorWrite(f"gzip: {path} is a directory -- ignored\n")
                return None, 2
        data = self.contents(path, prog)
        return data, 0 if data is not None else 1


def qpot_gzip_status(code: int, new: int) -> int:
    """gzip's status after another file: an error (1) stays, a warning (2) only replaces success."""
    return 1 if 1 in (code, new) else max(code, new)


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


# --- stat -----------------------------------------------------------------------------------

# coreutils of each release
QPOT_COREUTILS = {("ubuntu", 24): (9, 4), ("ubuntu", 22): (8, 32), ("debian", 13): (9, 7), ("debian", 12): (9, 1),
                  ("rhel", 9): (8, 32), ("centos", 7): (8, 22)}
# the default formats of GNU stat (9.x prints the device as major,minor; 8.x in hex and decimal) and
#   BusyBox's; a device file adds its device type to the Links line
QPOT_STAT_HEAD = "  File: %N\n  Size: %-10s\tBlocks: %-10b IO Block: %-6o %F\n"
QPOT_STAT_TAIL = "Access: (%04a/%10.10A)  Uid: (%5u/%8U)   Gid: (%5g/%8G)\nAccess: %x\nModify: %y\nChange: %z\n"
QPOT_STAT_FILE_TYPES = {stat_mod.S_IFREG: "regular file", stat_mod.S_IFDIR: "directory",
                        stat_mod.S_IFLNK: "symbolic link", stat_mod.S_IFCHR: "character special file",
                        stat_mod.S_IFBLK: "block special file", stat_mod.S_IFIFO: "fifo",
                        stat_mod.S_IFSOCK: "socket"}
QPOT_STAT_NODE_TYPES = {tree_fs.T_LINK: stat_mod.S_IFLNK, tree_fs.T_DIR: stat_mod.S_IFDIR,
                        tree_fs.T_FILE: stat_mod.S_IFREG, tree_fs.T_BLK: stat_mod.S_IFBLK,
                        tree_fs.T_CHR: stat_mod.S_IFCHR, tree_fs.T_SOCK: stat_mod.S_IFSOCK,
                        tree_fs.T_FIFO: stat_mod.S_IFIFO}
# the device numbers of the device files a persona has (major, minor)
QPOT_DEVICES = {"/dev/null": (1, 3), "/dev/zero": (1, 5), "/dev/full": (1, 7), "/dev/random": (1, 8),
                "/dev/urandom": (1, 9), "/dev/kmsg": (1, 11), "/dev/tty": (5, 0), "/dev/console": (5, 1),
                "/dev/ptmx": (5, 2), "/dev/tty0": (4, 0), "/dev/tty1": (4, 1)}
# the file systems that are no disk: their mount point and device
QPOT_VIRTUAL_MOUNTS = (("/proc", (0, 22)), ("/sys", (0, 21)), ("/dev/pts", (0, 24)), ("/dev/shm", (0, 25)),
                       ("/dev", (0, 5)), ("/run", (0, 26)))
QPOT_STAT_DIRECTIVE = re.compile(r"([-#+ 0']*)([0-9]{0,9})(?:\.([0-9]{0,9}))?([HL]?)(.)", re.S)
# operands, output and widths are the attacker's: so much is done at most per stat
QPOT_STAT_MAX_FILES = 4096
QPOT_STAT_MAX_OUTPUT = 1 << 20
# the directives and runs of text one stat may fill in, over all its files (a format of 16384 empty
#   directives given 4096 files held the reactor for minutes); a directive's value is worked out once per
#   file
QPOT_STAT_MAX_STEPS = 1 << 16
QPOT_STAT_TEXT = re.compile(r"[^%]+")
QPOT_STAT_TEXT_ESCAPES = re.compile(r"[^%\\]+")
QPOT_STAT_MAX_WIDTH = 4096


def qpot_coreutils_version(tree) -> tuple[int, int]:
    """(major, minor) of the persona's GNU coreutils: the release the persona engine gives its other
    coreutils ([shell] text_version of a GNU persona: wc, sort, df), else the one of its os-release."""
    if CowrieConfig.get("shell", "text_style", fallback="") == "gnu":
        found = re.fullmatch(r"([0-9]{1,2})\.([0-9]{1,3})", CowrieConfig.get("shell", "text_version", fallback="") or "")
        if found:
            return int(found.group(1)), int(found.group(2))
    os_id, version = qpot_os_release(tree)
    return QPOT_COREUTILS.get((os_id, version[0] if version else 0), (8, 32))


# the copyright year of a coreutils release (as the persona engine's COREUTILS_YEARS)
QPOT_COREUTILS_YEARS = {(8, 22): 2013, (8, 26): 2016, (8, 28): 2017, (8, 30): 2018, (8, 31): 2019, (8, 32): 2020,
                        (9, 1): 2022, (9, 4): 2023, (9, 5): 2024, (9, 7): 2025}


def qpot_coreutils_version_text(tree, program: str, authors: str) -> str:
    """--version of a GNU coreutils program of the persona (as its wc and df print it): Debian's packager
    line where the persona engine gives one, the http licence link before 8.29."""
    version = qpot_coreutils_version(tree)
    year = CowrieConfig.get("shell", "text_year", fallback="") or str(QPOT_COREUTILS_YEARS.get(version, 2022))
    packager = CowrieConfig.get("shell", "text_packager", fallback="") \
        if CowrieConfig.get("shell", "text_style", fallback="") == "gnu" else ""
    scheme = "http" if version < (8, 29) else "https"
    return (f"{program} (GNU coreutils) {version[0]}.{version[1]}\n" + (f"Packaged by {packager}\n" if packager else "")
            + f"Copyright (C) {year} Free Software Foundation, Inc.\n"
            f"License GPLv3+: GNU GPL version 3 or later <{scheme}://gnu.org/licenses/gpl.html>.\n"
            "This is free software: you are free to change and redistribute it.\n"
            "There is NO WARRANTY, to the extent permitted by law.\n\n"
            f"Written by {authors}\n")


def qpot_root_device(tree) -> tuple[int, int]:
    """(major, minor) of the disk the persona's / is on (its /proc/mounts), sda1 where it does not say."""
    for name in ("/proc/mounts", "/etc/mtab", "/etc/fstab"):
        try:
            text = tree.file_contents(name)[:65536].decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - no such file
            continue
        for line in text.splitlines()[:512]:
            words = line.split()
            if len(words) >= 2 and words[1] == "/" and words[0].startswith("/dev/"):
                dev = words[0][5:]
                found = re.fullmatch(r"(sd|xvd|vd)([a-z])(\d*)", dev)
                if found:
                    major = {"sd": 8, "xvd": 202, "vd": 252}[found.group(1)]
                    return major, (ord(found.group(2)) - 97) * 16 + int(found.group(3) or 0)
                found = re.fullmatch(r"nvme\d+n\d+p(\d+)", dev) or re.fullmatch(r"mmcblk\d+p(\d+)", dev)
                if found:
                    return (259 if dev.startswith("nvme") else 179), int(found.group(1))
                if dev.startswith(("mapper/", "dm-")):
                    return 253, 0
    return 8, 1


def qpot_id_names(tree, path: str) -> dict[int, str]:
    """id -> name of the persona's /etc/passwd or /etc/group."""
    try:
        text = tree.file_contents(path)[:1 << 20].decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return {}
    names: dict[int, str] = {}
    for line in text.splitlines()[:8192]:
        parts = line.split(":")
        if (len(parts) >= 3 and parts[0] and not line.lstrip().startswith("#")
                and len(parts[2]) <= 10 and parts[2].isascii() and parts[2].isdigit()):
            number = int(parts[2])
            if number < 0xFFFFFFFF:
                names.setdefault(number, parts[0])
    return names


def qpot_shell_quote(name: str, always: bool) -> str:
    """A name as GNU's shell-escape quoting writes it: in single quotes when it needs them (always)."""
    if not always and name and re.fullmatch(r"[A-Za-z0-9_./:@%+,=^-]+", name):
        return name
    return "'" + name.replace("'", "'\\''") + "'"


def qpot_mode_string(mode: int) -> str:
    kind = {stat_mod.S_IFDIR: "d", stat_mod.S_IFLNK: "l", stat_mod.S_IFCHR: "c", stat_mod.S_IFBLK: "b",
            stat_mod.S_IFIFO: "p", stat_mod.S_IFSOCK: "s"}.get(stat_mod.S_IFMT(mode), "-")
    out = [kind]
    for shift, special, letter in ((6, stat_mod.S_ISUID, "s"), (3, stat_mod.S_ISGID, "s"), (0, stat_mod.S_ISVTX, "t")):
        bits = (mode >> shift) & 7
        out.append("r" if bits & 4 else "-")
        out.append("w" if bits & 2 else "-")
        x = bits & 1
        if mode & special:
            out.append(letter if x else letter.upper())
        else:
            out.append("x" if x else "-")
    return "".join(out)


class QpotFileState:
    """Connection-owned identity and timestamps for the actual nodes of its virtual filesystem.

    Nothing is attached to the shared persona tree. On its first write Cowrie deep-copies that tree;
    remap the records to the copied nodes before the mutation continues. Read-only sessions keep the
    image's copy-on-write behavior. Strong node references prevent a deleted node's id being reused.
    """

    def __init__(self, tree, hostname: str) -> None:
        self.tree, self.hostname = tree, hostname
        self.records: dict[int, dict] = {}
        self.inodes: set[int] = set()
        self.installed: float | None = None
        private = getattr(tree, "_ensure_private_fs", None)
        if callable(private):
            def ensure_private() -> None:
                before = tree.fs
                private()
                if tree.fs is not before:
                    self.replaced(before, tree.fs)

            tree._ensure_private_fs = ensure_private
        tree.qpot_tree_replaced = self.replaced
        for name in ("chmod", "chown", "utime", "rename"):
            original = getattr(tree, name, None)
            if callable(original):
                setattr(tree, name, self.mutation(name, original))

    def replaced(self, before, after, memo=None) -> None:
        """Keep node identities across a copy, including a staged copy with additional entries."""
        if not self.records:
            return
        if memo is not None:
            linked, pending = set(), [after]
            while pending:
                node = pending.pop()
                linked.add(id(node))
                if node[tree_fs.A_TYPE] == tree_fs.T_DIR:
                    pending.extend(node[tree_fs.A_CONTENTS])
            for key, record in list(self.records.items()):
                copied = memo.get(id(record["node"]))
                if isinstance(copied, list) and id(copied) in linked:
                    self.records.pop(key, None)
                    record["node"] = copied
                    self.records[id(copied)] = record
            return
        remapped, pending = dict(self.records), [(before, after)]
        while pending:
            old, new = pending.pop()
            record = self.records.get(id(old))
            if record is not None:
                remapped.pop(id(old), None)
                record["node"] = new
                remapped[id(new)] = record
            if old[tree_fs.A_TYPE] == new[tree_fs.A_TYPE] == tree_fs.T_DIR:
                children = {child[tree_fs.A_NAME]: child for child in new[tree_fs.A_CONTENTS]}
                pending.extend((child, children[child[tree_fs.A_NAME]])
                               for child in old[tree_fs.A_CONTENTS] if child[tree_fs.A_NAME] in children)
        # Retain removed nodes too: an existing reference must never acquire a new node's identity.
        self.records = remapped

    def record(self, path: str, node, installed: float | None = None) -> dict:
        found = self.records.get(id(node))
        if found is not None:
            return found
        if self.installed is None:
            if installed is None:
                from cowrie.core import qpot_bait

                installed = qpot_bait._identity()[0]
            self.installed = float(installed)
        raw = float(node[tree_fs.A_CTIME] or 0)
        seed = int(hashlib.sha256(f"{self.hostname}|{path}".encode()).hexdigest()[:12], 16)
        if raw < self.installed:
            born = self.installed + (seed % 600) + (seed % 999999937) / 1e9
            access, modify = born, raw
        else:
            modify = raw + (seed % 999999937) / 1e9 if raw == int(raw) else raw
            access = born = modify
        inode = 2 if path == "/" else 131072 + int(hashlib.sha256(path.encode()).hexdigest()[:8], 16) % 2000000
        while inode in self.inodes:
            inode += 1
        self.inodes.add(inode)
        found = {"node": node, "raw": raw, "access": access, "modify": modify,
                 "change": born, "birth": born, "inode": inode}
        self.records[id(node)] = found
        return found

    def mutation(self, name: str, original):
        def changed(*args, **kwargs):
            path = args[0] if args else kwargs.get("path", kwargs.get("oldpath", ""))
            node = self.tree.getfile(path, follow_symlinks=name != "rename")
            record = self.record(path, node) if node is not None else None
            result = original(*args, **kwargs)
            if record is not None:
                record["change"] = time.time()
                if name == "utime":
                    record["access"] = float(args[1] if len(args) > 1 else kwargs["_atime"])
                    record["modify"] = float(record["node"][tree_fs.A_CTIME] or 0)
                    record["raw"] = record["modify"]
            return result

        return changed

    def times(self, path: str, node, installed: float) -> tuple[float, float, float, float]:
        record = self.record(path, node, installed)
        raw = float(node[tree_fs.A_CTIME] or 0)
        if raw != record["raw"]:
            # The image's writers put the write time in A_CTIME. Preserve birth and access instead
            # of making the file appear to have been created again whenever its content changes.
            record["raw"] = record["modify"] = raw
            record["change"] = max(record["change"], raw)
        return record["access"], record["modify"], record["change"], record["birth"]


def qpot_track_files(protocol) -> QpotFileState | None:
    """Install once on the connection's filesystem; every SSH channel shares the same records."""
    tree = getattr(protocol, "fs", None)
    if tree is None:
        return None
    state = getattr(tree, "_qpot_file_state", None)
    if state is None:
        state = QpotFileState(tree, str(getattr(protocol, "hostname", "") or ""))
        tree._qpot_file_state = state
    return state


class Command_stat(QpotCommand):
    """stat of GNU coreutils (the release's: 8.22 of CentOS 7 quotes in its locale and has no birth time,
    8.x prints the device in hex, 9.x as major,minor) or of BusyBox: the default, -t, -c/--format and
    --printf, -L. The values are the tree's (the size, owner, mode and time ls shows); the times of a
    package's file are its mtime and the persona's installation, those of a file made later its own."""

    qpot_name = "stat"
    qpot_steps = QPOT_STAT_MAX_STEPS

    def run(self) -> int | None:
        busybox = self.busybox()
        if busybox and self.usage_stop():
            return self.exit_code
        try:
            if busybox:
                options, rest = getopt.getopt(self.args, "c:fLt")
            else:
                options, rest = getopt.gnu_getopt(self.args, "c:Lt", ["dereference", "format=", "printf=",
                                                                      "terse", "cached=", "version"])
        except getopt.GetoptError as err:
            opt = err.opt or ""
            if busybox:
                from cowrie.commands.uname import tpot_bb_usage_stop

                tpot_bb_usage_stop(self, "stat", ["-" + opt[:1]])
                return 1
            if "requires" in err.msg:
                text = (f"option '--{opt}' requires an argument" if len(opt) > 1
                        else f"option requires an argument -- '{opt}'")
            elif len(opt) > 1:
                text = f"unrecognized option '--{opt}'"
            else:
                text = f"invalid option -- '{opt}'"
            return self.try_help(f"stat: {text}\n")
        if not busybox and any(o == "--version" for o, _ in options):
            # QPot: as getopt_long hands it to stat, before any operand is looked at
            self.write(qpot_coreutils_version_text(self.fs, "stat", "Michael Meskes."))
            return 0
        if not rest:
            if busybox:
                from cowrie.commands.uname import tpot_bb_usage_stop

                tpot_bb_usage_stop(self, "stat", [])
                return 1
            return self.try_help("stat: missing operand\n")
        self.qpot_busybox = busybox
        self.qpot_version = qpot_coreutils_version(self.fs)
        follow = any(o in ("-L", "--dereference") for o, _ in options)
        fmt, printf = None, False
        for opt, value in options:
            if opt in ("-c", "--format"):
                fmt, printf = value[:65536], False
            elif opt == "--printf":
                fmt, printf = value[:65536], True
            elif opt in ("-t", "--terse") and fmt is None:
                fmt = "%n %s %b %f %u %g %D %i %h %t %T %X %Y %Z %o\n" if busybox else \
                    "%n %s %b %f %u %g %D %i %h %t %T %X %Y %Z %W %o\n"
                printf = True
        self.qpot_users, self.qpot_groups = qpot_id_names(self.fs, "/etc/passwd"), qpot_id_names(self.fs, "/etc/group")
        self.qpot_root = qpot_root_device(self.fs)
        from cowrie.core import qpot_bait

        self.qpot_installed = qpot_bait._identity()[0]
        code, left = 0, QPOT_STAT_MAX_OUTPUT
        self.qpot_steps = QPOT_STAT_MAX_STEPS
        for name in rest[:QPOT_STAT_MAX_FILES]:
            if left <= 0 or self.qpot_steps <= 0:
                break
            path = self.fs.resolve_path(name, self.cwd)
            node = self.fs.getfile(path, follow_symlinks=follow) if path != "/" else self.fs.getfile("/")
            if node is None:
                self.errorWrite(self.qpot_missing(name))
                code = 1
                continue
            if fmt is None:
                text = self.qpot_format(self.qpot_default(node), name, path, node, True)
            else:
                text = self.qpot_format(fmt, name, path, node, False, printf)
                if not printf:
                    text += "\n"
            text = text[:left]
            left -= len(text)
            self.write(text)
        return code

    def qpot_missing(self, name: str) -> str:
        if self.qpot_busybox:
            return f"stat: can't stat '{name}': No such file or directory\n"
        if self.qpot_version < (8, 31):
            return f"stat: cannot stat {qpot_quote(name)}: No such file or directory\n"
        return f"stat: cannot statx {qpot_shell_quote(name, True)}: No such file or directory\n"

    def qpot_default(self, node) -> str:
        device = stat_mod.S_IFMT(self.qpot_mode(node)) in (stat_mod.S_IFCHR, stat_mod.S_IFBLK)
        if self.qpot_busybox:
            return QPOT_STAT_HEAD + "Device: %Dh/%dd\tInode: %-10i  Links: %h\n" + QPOT_STAT_TAIL
        if self.qpot_version >= (9, 0):
            links = "Device: %Hd,%Ld\tInode: %-11i Links: " + ("%-5h Device type: %Hr,%Lr\n" if device else "%h\n")
        else:
            links = "Device: %Dh/%dd\tInode: %-10i  Links: " + ("%-5h Device type: %t,%T\n" if device else "%h\n")
        return QPOT_STAT_HEAD + links + QPOT_STAT_TAIL + " Birth: %w\n"

    @staticmethod
    def qpot_mode(node) -> int:
        mode = int(node[tree_fs.A_MODE] or 0)
        if not stat_mod.S_IFMT(mode):
            mode |= QPOT_STAT_NODE_TYPES.get(node[tree_fs.A_TYPE], stat_mod.S_IFREG)
        return mode

    def qpot_times(self, path: str, node) -> tuple[float, float, float, float]:
        """(access, modify, change, birth): a file older than the installation came from a package (its
        mtime kept, changed and born when it was unpacked), a later one was written then."""
        return qpot_track_files(self.protocol).times(path, node, self.qpot_installed)

    def qpot_human_time(self, when: float) -> str:
        clock = time.localtime(int(when))
        fraction = int(round((when - int(when)) * 1e9)) % 1000000000
        return time.strftime("%Y-%m-%d %H:%M:%S", clock) + f".{fraction:09d} " + time.strftime("%z", clock)

    def qpot_value(self, letter: str, name: str, path: str, node, default: bool):
        """The value of one directive (an int, a float time, or text), None for no directive of stat."""
        mode = self.qpot_mode(node)
        kind = stat_mod.S_IFMT(mode)
        size = int(node[tree_fs.A_SIZE] or 0)
        if path == "/" and kind == stat_mod.S_IFDIR and not size:
            # the tree's / has no size; ext4's root folder takes a block, as ls shows it
            size = 4096
        major, minor = self.qpot_root
        mount = "/"
        for prefix, numbers in QPOT_VIRTUAL_MOUNTS:
            if path == prefix or path.startswith(prefix + "/"):
                (major, minor), mount = numbers, prefix
                break
        dev_type = QPOT_DEVICES.get(path, (0, 0)) if kind in (stat_mod.S_IFCHR, stat_mod.S_IFBLK) else (0, 0)
        access, modify, change, birth = self.qpot_times(path, node)
        old = self.qpot_version < (8, 31) and not self.qpot_busybox
        if letter == "n":
            return name
        if letter == "N":
            target = f" -> {node[tree_fs.A_TARGET]}" if kind == stat_mod.S_IFLNK else ""
            if self.qpot_busybox:
                # BusyBox's %N quotes a link and its target, nothing else
                return f"'{name}' -> '{node[tree_fs.A_TARGET]}'" if target else name
            if old:
                return qpot_quote(name) + (f" -> {qpot_quote(str(node[tree_fs.A_TARGET]))}" if target else "")
            quoted = qpot_shell_quote(name, not default)
            return quoted + (f" -> {qpot_shell_quote(str(node[tree_fs.A_TARGET]), not default)}" if target else "")
        if letter == "s":
            return size
        if letter == "b":
            if kind == stat_mod.S_IFDIR:
                return max(8, -(-size // 4096) * 8)
            if kind == stat_mod.S_IFREG:
                return -(-size // 4096) * 8
            if kind == stat_mod.S_IFLNK:
                return 0 if size < 60 else 8
            return 0
        if letter == "B":
            return 512
        if letter == "o":
            return 4096
        if letter == "F":
            if kind == stat_mod.S_IFREG and size == 0:
                return "regular empty file"
            return QPOT_STAT_FILE_TYPES.get(kind, "unknown")
        if letter == "f":
            return f"{mode:x}"
        if letter == "a":
            return f"{mode & 0o7777:o}"
        if letter == "A":
            return qpot_mode_string(mode)
        if letter in "uU":
            uid = int(node[tree_fs.A_UID] or 0)
            return uid if letter == "u" else self.qpot_users.get(uid, "UNKNOWN")
        if letter in "gG":
            gid = int(node[tree_fs.A_GID] or 0)
            return gid if letter == "g" else self.qpot_groups.get(gid, "UNKNOWN")
        if letter == "h":
            if kind == stat_mod.S_IFDIR:
                children = node[tree_fs.A_CONTENTS] if isinstance(node[tree_fs.A_CONTENTS], list) else []
                return 2 + sum(1 for child in children if child[tree_fs.A_TYPE] == tree_fs.T_DIR)
            return 1
        if letter == "i":
            return qpot_track_files(self.protocol).record(path, node, self.qpot_installed)["inode"]
        if letter == "d":
            return major * 256 + minor
        if letter == "D":
            return f"{major * 256 + minor:x}"
        if letter in ("Hd", "Ld"):
            return major if letter == "Hd" else minor
        if letter in ("Hr", "Lr"):
            return dev_type[0] if letter == "Hr" else dev_type[1]
        if letter == "m":
            return mount
        if letter == "t":
            return f"{dev_type[0]:x}"
        if letter == "T":
            return f"{dev_type[1]:x}"
        if letter in "xyz":
            return self.qpot_human_time({"x": access, "y": modify, "z": change}[letter])
        if letter in "XYZ":
            return ("time", {"X": access, "Y": modify, "Z": change}[letter])
        if letter == "w":
            return "-" if old or self.qpot_busybox else self.qpot_human_time(birth)
        if letter == "W":
            return 0 if old or self.qpot_busybox else ("time", birth)
        return None

    def qpot_format(self, fmt: str, name: str, path: str, node, default: bool, escapes: bool = False) -> str:
        """fmt with its directives filled in: %[flags][width][.precision]X as stat's printf does (%Hd %Ld
        %Hr %Lr the major and minor numbers); an unknown directive is ?, a % at the end a %. --printf
        also reads the backslash escapes."""
        out: list[str] = []
        i, n, size = 0, len(fmt), 0
        text = QPOT_STAT_TEXT_ESCAPES if escapes else QPOT_STAT_TEXT
        values: dict = {}
        while i < n and size < QPOT_STAT_MAX_OUTPUT and self.qpot_steps > 0:
            self.qpot_steps -= 1
            c = fmt[i]
            if c == "\\" and escapes and i + 1 < n:
                piece, i = self.qpot_escape(fmt, i)
            elif c != "%":
                run = text.match(fmt, i)
                end = run.end() if run else i + 1
                piece, i = fmt[i:end], end
            elif i + 1 >= n:
                piece, i = "%", i + 1
            elif fmt[i + 1] == "%":
                piece, i = "%", i + 2
            else:
                found = QPOT_STAT_DIRECTIVE.match(fmt, i + 1)
                if not found:
                    piece, i = "%", i + 1
                else:
                    spec, i = fmt[i:found.end()], found.end()
                    piece = values.get(spec)
                    if piece is None:
                        flags, width, precision, half, letter = found.groups()
                        key = half + letter if half and letter in "dr" else letter
                        value = None if half and letter not in "dr" else self.qpot_value(key, name, path, node, default)
                        # the same directive again (with its flags, width, precision) is the same text
                        piece = values[spec] = self.qpot_pad(value, flags, width, precision)
            out.append(piece)
            size += len(piece)
        return "".join(out)

    @staticmethod
    def qpot_escape(fmt: str, i: int) -> tuple[str, int]:
        nxt = fmt[i + 1]
        simple = {"n": "\n", "t": "\t", "\\": "\\", "\"": "\"", "a": "\a", "b": "\b", "f": "\f", "r": "\r",
                  "v": "\v", "e": "\x1b"}
        if nxt in simple:
            return simple[nxt], i + 2
        found = re.compile(r"[0-7]{1,3}").match(fmt, i + 1)
        if found:
            return chr(int(found.group(0), 8) & 0xFF), found.end()
        found = re.compile(r"x([0-9A-Fa-f]{1,2})").match(fmt, i + 1)
        if found:
            return chr(int(found.group(1), 16)), found.end()
        return "\\" + nxt, i + 2

    @staticmethod
    def qpot_pad(value, flags: str, width: str, precision: str | None) -> str:
        """A value as stat's printf pads it: numbers (and the digits of %a %D %f) with 0 or blanks, a
        precision their least digits; a time's precision its fraction; text cut to the precision."""
        if value is None:
            return "?"
        width_n = min(int(width), QPOT_STAT_MAX_WIDTH) if width else 0
        left = "-" in flags
        numeric = False
        if isinstance(value, tuple):  # a time in seconds: the precision shows its fraction
            seconds = value[1]
            digits = min(int(precision), 9) if precision else 0
            text = str(int(seconds))
            if digits:
                text += "." + f"{int(round((seconds - int(seconds)) * 1e9)):09d}"[:digits]
            numeric = True
        elif isinstance(value, int):
            text = str(value)
            if precision:
                text = text.zfill(min(int(precision), QPOT_STAT_MAX_WIDTH))
            numeric = True
        else:
            text = str(value)
            numeric = bool(re.fullmatch(r"[0-9a-f]+", text))
            if precision is not None and not numeric:
                text = text[:min(int(precision or 0), QPOT_STAT_MAX_WIDTH)]
        if numeric and "0" in flags and not left:
            return text.zfill(width_n)
        return text.ljust(width_n) if left else text.rjust(width_n)


# --- bash --version, exit at the login shell ------------------------------------------------

# bash of each release: (version, copyright year) and the platform it was built for
BASH_RELEASES = {("ubuntu", 24): ("5.2.21(1)-release", 2022), ("ubuntu", 22): ("5.1.16(1)-release", 2020),
                 ("debian", 13): ("5.2.37(1)-release", 2022), ("debian", 12): ("5.2.15(1)-release", 2022),
                 ("debian", 11): ("5.1.4(1)-release", 2020), ("raspbian", 12): ("5.2.15(1)-release", 2022),
                 ("rhel", 9): ("5.1.8(1)-release", 2020), ("centos", 7): ("4.2.46(2)-release", 2011)}


def qpot_bash_info(tree) -> tuple[str, int, str] | None:
    """(version, copyright year, MACHTYPE) of the persona's bash, None where it is not known: what
    `bash --version`, help, $BASH_VERSION and $MACHTYPE show."""
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
    return release[0], release[1], platform


def qpot_bash_variables(shell) -> None:
    """The variables bash sets in the persona's login shell and does not export: BASH_VERSION,
    BASH_VERSINFO (its first element, what $BASH_VERSINFO reads: the shell keeps no arrays), MACHTYPE,
    HOSTTYPE, OSTYPE, BASH. None on ash, msh, or a bash this does not know."""
    if CowrieConfig.get("shell", "not_found_style", fallback="bash") != "bash":
        return
    info = qpot_bash_info(shell.protocol.fs)
    if info is None:
        return
    version, _, machtype = info
    machine, _, rest = machtype.partition("-")
    values = {"BASH_VERSION": version, "BASH_VERSINFO": version.split(".")[0], "MACHTYPE": machtype,
              "HOSTTYPE": machine, "OSTYPE": rest.split("-", 1)[1] if rest.count("-") else "linux-gnu",
              "BASH": CowrieConfig.get("shell", "login_shell", fallback="") or "/bin/bash"}
    for name, value in values.items():
        shell.environ.setdefault(name, value)


def qpot_bash_version(tree) -> str | None:
    """What `bash --version` prints on the persona, None where it is not known."""
    info = qpot_bash_info(tree)
    if info is None:
        return None
    release, platform = (info[0], info[1]), info[2]
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

    # the option letters a shell takes in one word with -c (set's letters and bash's own)
    QPOT_SH_LETTERS = frozenset("abefhiklmnprstuvxBCEHPTc")

    class Command_bash(Command_sh):
        """bash --version as the persona's bash (Cowrie's ran a nested shell and printed nothing), and
        sh -c as a shell reads it: the command is the one argument after -c, the next is $0 and the
        rest are $1, $2 ... (`sh -c 'wc -l "$1"' _ file`, what find -exec and xargs are given).
        Cowrie's joined every argument into the command and left the parameters unset. -c may share
        its word with other options (bash -lc, sh -ec) or come after them."""

        def start(self) -> None:
            if self.args[:1] == ["--version"] and not CowrieConfig.get("shell", "bash_version", fallback=""):
                text = qpot_bash_version(self.fs)
                if text is not None:
                    self.write(text)
                    self.exit(0)
                    return
            at = self.qpot_command_at()
            if at is None:
                super().start()
                return
            if at >= len(self.args):
                self.errorWrite(f"{self.argv0}: -c: option requires an argument\n")
                self.exit(2)
                return
            self.qpot_run_command(self.args[at], list(self.args[at + 1:]))
            self.exit()

        def qpot_command_at(self) -> int | None:
            """Where the command string of -c stands in the arguments; None without -c."""
            args, index = list(self.args), 0
            while index < len(args):
                arg = args[index]
                if arg in ("--login", "--noprofile", "--norc", "--posix", "--restricted", "--verbose", "--noediting"):
                    index += 1
                elif arg in ("--rcfile", "--init-file", "-o", "+o", "-O", "+O"):
                    index += 2
                elif len(arg) > 1 and arg[0] == "-" and arg[1] != "-" and all(c in QPOT_SH_LETTERS for c in arg[1:]):
                    index += 1
                    if "c" in arg[1:]:
                        # options may still follow -c, before the command (bash -c -x 'id')
                        while index < len(args) and len(args[index]) > 1 and args[index][0] in "-+" and all(
                                c in QPOT_SH_LETTERS for c in args[index][1:]):
                            index += 1
                        return index
                elif len(arg) > 1 and arg[0] == "+" and all(c in QPOT_SH_LETTERS for c in arg[1:]):
                    index += 1
                else:
                    return None
            return None

        def qpot_run_command(self, line: str, rest: list[str]) -> None:
            from cowrie.shell.honeypot import HoneyPotShell

            shell = HoneyPotShell(self.protocol, interactive=False)
            shell.name = rest[0] if rest else self.argv0
            # a new process: its own arguments, never the parameters of what started it
            for key in [k for k in shell.environ if k.isdigit() or k in ("#", "@", "*")]:
                del shell.environ[key]
            if len(rest) > 1:
                shell.set_positional_params(rest[1:])
            self.protocol.cmdstack.append(shell)
            shell.lineReceived(line)
            self.exit_code = shell.last_exit_code

    for _name in ("/bin/bash", "bash", "/bin/sh", "sh", "/usr/bin/bash", "/usr/bin/sh"):
        if _name in ("/bin/bash", "bash") or commands.get(_name) is None:
            commands[_name] = Command_bash

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


# --- gzip, gunzip ---------------------------------------------------------------------------

# gzip of each release
QPOT_GZIP = {("ubuntu", 24): (1, 12), ("ubuntu", 22): (1, 10), ("debian", 13): (1, 13), ("debian", 12): (1, 12),
             ("rhel", 9): (1, 12), ("centos", 7): (1, 5)}
QPOT_GZIP_YEARS = {(1, 13): 2023, (1, 12): 2022, (1, 10): 2018, (1, 5): 2012}
QPOT_GZIP_LONG = ["stdout", "to-stdout", "decompress", "uncompress", "force", "help", "keep", "list", "license",
                  "no-name", "name", "quiet", "recursive", "suffix=", "synchronous", "test", "verbose", "version",
                  "fast", "best", "rsyncable"]
QPOT_GZIP_LIST_HEAD = "         compressed        uncompressed  ratio uncompressed_name\n"
QPOT_GZIP_VERBOSE_HEAD = ("method  crc     date  time           compressed        uncompressed  ratio "
                          "uncompressed_name\n")
# a file larger than this is not compressed in the reactor (gzip of the attacker's 1 GB file)
QPOT_GZIP_MAX_INPUT = 8 << 20
# the bytes one gzip reads and makes over all its files (4096 names of one 8 KiB file of zeros made
#   gzip -t inflate 32 GiB)
QPOT_GZIP_BUDGET = 64 << 20
# the bytes one gzip compresses over all its files (deflate is the slow part: 4 MiB of random bytes take
#   about 0.15 s): one file of the largest size
QPOT_GZIP_DEFLATE = QPOT_GZIP_MAX_INPUT


def qpot_gzip_header(data: bytes) -> int | None:
    """The length of a gzip member's header (with its name, comment, extra field), None when cut short."""
    if len(data) < 10:
        return None
    flags, pos = data[3], 10
    if flags & 4:
        if pos + 2 > len(data):
            return None
        pos += 2 + int.from_bytes(data[pos:pos + 2], "little")
    for bit in (8, 16):
        if flags & bit:
            end = data.find(b"\0", pos)
            if end < 0:
                return None
            pos = end + 1
    if flags & 2:
        pos += 2
    return pos if pos <= len(data) else None


class Command_gzip(Command_zcat):
    """gzip of GNU (or of BusyBox, which has no -l): -l lists the sizes from each file's trailer as gzip
    does (without decompressing it), -t tests, -d and -c decompress (as zcat) or compress, a file in its
    place with its name and time in the header (BusyBox's keeps neither); gunzip is gzip -d."""

    qpot_name = "gzip"
    qpot_budget = QPOT_GZIP_BUDGET
    qpot_bb = False

    def qpot_spend(self, *pieces) -> None:
        self.qpot_budget -= sum(len(piece) for piece in pieces if piece)

    def run(self) -> int | None:
        self.qpot_budget = QPOT_GZIP_BUDGET
        self.qpot_deflate_left = QPOT_GZIP_DEFLATE
        busybox = self.qpot_bb = self.busybox()
        decompress = posixpath.basename(self.qpot_name) == "gunzip"
        if busybox and self.usage_stop():
            return self.exit_code
        try:
            if busybox:
                options, files = getopt.gnu_getopt(self.args, "cdfkt123456789")
            else:
                options, files = getopt.gnu_getopt(self.args, "cdfhklLnNqrS:tvV123456789", QPOT_GZIP_LONG)
        except getopt.GetoptError as err:
            opt = err.opt or ""
            if busybox:
                from cowrie.commands.uname import tpot_bb_usage_stop

                tpot_bb_usage_stop(self, posixpath.basename(self.qpot_name), ["-" + opt[:1]])
                return 1
            text = f"unrecognized option '--{opt}'" if len(opt) > 1 else f"invalid option -- '{opt}'"
            self.errorWrite(f"gzip: {text}\nTry `gzip --help' for more information.\n")
            return 1
        keys = {o for o, _ in options}
        if keys & {"-V", "--version"}:
            self.write(self.qpot_version_text())
            return 0
        if keys & {"-d", "--decompress", "--uncompress"}:
            decompress = True
        to_stdout = bool(keys & {"-c", "--stdout", "--to-stdout"})
        force = bool(keys & {"-f", "--force"})
        keep = bool(keys & {"-k", "--keep"})
        self.qpot_verbose = bool(keys & {"-v", "--verbose"})
        files = files[:QPOT_STAT_MAX_FILES]
        if keys & {"-l", "--list"}:
            return self.qpot_list(files, bool(keys & {"-q", "--quiet"}), bool(keys & {"-N", "--name"}))
        if keys & {"-t", "--test"}:
            return self.qpot_test(files, busybox)
        if decompress and (to_stdout or not files or files == ["-"]):
            self.args = files
            return Command_zcat.run(self)
        code = 0
        for name in files or ["-"]:
            if self.qpot_budget <= 0:
                break
            if name == "-":
                code = qpot_gzip_status(code, self.qpot_to_stdout(self.input_data or b"", "", 0, force))
            elif decompress:
                code = qpot_gzip_status(code, self.qpot_gunzip(name, keep, force))
            else:
                code = qpot_gzip_status(code, self.qpot_compress(name, to_stdout, keep, force))
        return code

    def qpot_version_text(self) -> str:
        os_id, version = qpot_os_release(self.fs)
        release = QPOT_GZIP.get((os_id, version[0] if version else 0), (1, 13))
        scheme = "https" if release >= (1, 6) else "http"
        return (f"gzip {release[0]}.{release[1]}\nCopyright (C) {QPOT_GZIP_YEARS[release]} Free Software Foundation, "
                "Inc.\nCopyright (C) 1993 Jean-loup Gailly.\nThis is free software.  You may redistribute copies of "
                f"it under the terms of\nthe GNU General Public License <{scheme}://www.gnu.org/licenses/gpl.html>.\n"
                "There is NO WARRANTY, to the extent permitted by law.\n\nWritten by Jean-loup Gailly.\n")

    def qpot_prog(self) -> str:
        """The name gzip's messages start with: BusyBox's applet, else gzip (GNU's gunzip is a script)."""
        return posixpath.basename(self.qpot_name) if self.qpot_bb else "gzip"

    def qpot_list(self, files: list[str], quiet: bool = False, stored: bool = False) -> int:
        """gzip -l: per file its size, the size its trailer gives, the ratio gzip computes (from the
        compressed size less the header and trailer), the name without its suffix (-N: the one the header
        keeps); totals for more than one file (whose ratio takes the last file's header, as gzip's does).
        -q leaves out the heading and the totals."""
        code, listed, total_in, total_out, header = 0, 0, 0, 0, 0
        head = QPOT_GZIP_VERBOSE_HEAD if self.qpot_verbose else QPOT_GZIP_LIST_HEAD
        for name in files or ["-"]:
            if self.qpot_budget <= 0:
                break
            name = self.qpot_gz_name(name)
            data, status = self.qpot_gz_read(name, "gzip", False)
            if data is None:
                code = qpot_gzip_status(code, status)
                continue
            self.qpot_spend(data)
            label = "stdin" if name == "-" else name
            if data[:2] != b"\x1f\x8b" and len(data) >= 2:
                self.errorWrite(f"\ngzip: {label}: not in gzip format\n")
                code = 1
                continue
            size = qpot_gzip_header(data)
            if size is None or len(data) < size + 8:
                self.errorWrite(f"\ngzip: {label}: unexpected end of file\n")
                code = 1
                continue
            if not listed and (self.qpot_verbose or not quiet):
                self.write(head)
            header = size + 8
            out = int.from_bytes(data[-4:], "little")
            crc = int.from_bytes(data[-8:-4], "little")
            ratio = 100.0 * (out - (len(data) - header)) / out if out else 0.0
            plain = "stdout" if name == "-" else self.qpot_plain_name(name)
            if stored and data[3] & 8:
                kept = data[10 + (2 + int.from_bytes(data[10:12], "little") if data[3] & 4 else 0):size].split(b"\0")[0]
                plain = kept.decode("latin-1") or plain
            line = f"{len(data):19d} {out:19d} {ratio:5.1f}% {plain}\n"
            if self.qpot_verbose:
                stamp = int.from_bytes(data[4:8], "little")
                if not stamp and name != "-":
                    node = self.fs.getfile(self.fs.resolve_path(name, self.cwd))
                    stamp = int(node[tree_fs.A_CTIME] or 0) if node else 0
                when = time.strftime("%b %e %H:%M", time.localtime(stamp))
                line = f"defla {crc:08x} {when} {line}"
            self.write(line)
            listed += 1
            total_in += len(data)
            total_out += out
        if listed > 1 and (self.qpot_verbose or not quiet):
            ratio = 100.0 * (total_out - (total_in - header)) / total_out if total_out else 0.0
            line = f"{total_in:19d} {total_out:19d} {ratio:5.1f}% (totals)\n"
            self.write((" " * 28 if self.qpot_verbose else "") + line)
        return code

    def qpot_inflate(self, data: bytes, label: str, busybox: bool) -> tuple[bytes | None, str | None]:
        """data decompressed (bounded as zcat is), or the message gzip gives for it."""
        import zlib

        # BusyBox names the applet it runs as (gzip -t, gunzip: "gunzip: invalid magic", recorded from 1.37)
        applet = posixpath.basename(self.qpot_name)
        if len(data) < 2 and not busybox:
            return None, f"\ngzip: {label}: unexpected end of file\n"
        if data[:2] != b"\x1f\x8b":
            return None, f"{applet}: invalid magic\n" if busybox else f"\ngzip: {label}: not in gzip format\n"
        member = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            out = member.decompress(data, self.QPOT_ZCAT_MAX)
        except zlib.error:
            return None, f"{applet}: corrupted data\n" if busybox else \
                f"\ngzip: {label}: invalid compressed data--format violated\n"
        if not member.eof and len(out) < self.QPOT_ZCAT_MAX:
            return None, f"{applet}: unexpected end of file\n" if busybox else \
                f"\ngzip: {label}: unexpected end of file\n"
        return out, None

    def qpot_test(self, files: list[str], busybox: bool) -> int:
        code = 0
        for name in files or ["-"]:
            if self.qpot_budget <= 0:
                break
            name = name if busybox else self.qpot_gz_name(name)
            data, status = self.qpot_gz_read(name, self.qpot_prog(), busybox)
            if data is None:
                code = qpot_gzip_status(code, status)
                continue
            out, problem = self.qpot_inflate(data, "stdin" if name == "-" else name, busybox)
            self.qpot_spend(data, out)
            if problem:
                self.errorWrite(problem)
                code = 1
            elif self.qpot_verbose:
                self.errorWrite(f"{name}:\t OK\n")
        return code

    def qpot_to_stdout(self, data: bytes, name: str, stamp: int, force: bool) -> int:
        targets = getattr(self.pp, "targets", None) or {}
        # BusyBox writes to a terminal as well
        if (targets.get(1) or ("terminal",))[0] == "terminal" and not force and not self.qpot_bb:
            self.errorWrite("gzip: compressed data not written to a terminal. Use -f to force compression.\n"
                            "For help, type: gzip -h\n")
            return 1
        data = data[:QPOT_GZIP_MAX_INPUT]
        if not self.qpot_may_deflate(data):
            return 0
        packed = self.qpot_deflate(data, name, stamp)
        self.qpot_spend(data, packed)
        self.writeBytes(packed)
        return 0

    def qpot_may_deflate(self, data: bytes) -> bool:
        """Whether data fits what this gzip may still compress (QPOT_GZIP_DEFLATE); when it does not, the
        rest of the files are left alone."""
        if len(data) > self.qpot_deflate_left:
            self.qpot_budget = 0
            return False
        self.qpot_deflate_left -= len(data)
        return True

    @staticmethod
    def qpot_deflate(data: bytes, name: str, stamp: int) -> bytes:
        """data as GNU gzip writes it at its default level: the name and time of a file in the header."""
        import struct
        import zlib

        compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
        body = compressor.compress(data) + compressor.flush()
        flags = 8 if name else 0
        head = b"\x1f\x8b\x08" + bytes([flags]) + struct.pack("<I", stamp & 0xFFFFFFFF) + b"\x00\x03"
        if name:
            head += name.encode("utf-8", "replace") + b"\x00"
        return head + body + struct.pack("<II", zlib.crc32(data) & 0xFFFFFFFF, len(data) & 0xFFFFFFFF)

    def qpot_node(self, name: str):
        """(path, node, status) of name: no node after gzip's message when it is not there (status 1) or
        is a directory (GNU skips one with a warning, status 2; BusyBox reads one as no bytes)."""
        path = self.fs.resolve_path(name, self.cwd)
        node = self.fs.getfile(path)
        if node is None:
            self.errorWrite(f"{self.qpot_prog()}: {name}: No such file or directory\n")
            return path, None, 1
        if node[tree_fs.A_TYPE] == tree_fs.T_DIR and not self.qpot_bb:
            self.errorWrite(f"gzip: {name} is a directory -- ignored\n")
            return path, None, 2
        return path, node, 0

    def qpot_place(self, path: str, node, data: bytes, stamp) -> bool:
        """A new file at path with data and the permissions of node, made at stamp (None: now). GNU gzip
        gives it node's owner too; BusyBox's is the user's."""
        uid, gid = node[tree_fs.A_UID], node[tree_fs.A_GID]
        if self.qpot_bb:
            user = getattr(self.protocol, "user", None)
            uid, gid = getattr(user, "uid", uid), getattr(user, "gid", gid)
        mode = stat_mod.S_IFREG | (int(node[tree_fs.A_MODE] or 0) & 0o7777)
        try:
            self.fs.mkfile(path, uid, gid, len(data), mode, stamp)
            made = self.fs.getfile(path)
            made[tree_fs.A_CONTENTS] = data
            return True
        except Exception:  # noqa: BLE001 - a read-only place of the tree
            return False

    def qpot_compress(self, name: str, to_stdout: bool, keep: bool, force: bool) -> int:
        path, node, status = self.qpot_node(name)
        if node is None:
            return status
        bb, prog = self.qpot_bb, self.qpot_prog()
        # GNU's make_ofname, which -c skips, leaves a .gz alone (without a warning status); BusyBox makes
        # x.gz.gz
        if not bb and not to_stdout and self.qpot_plain_name(name) != name and not force:
            self.errorWrite(f"gzip: {name} already has .gz suffix -- unchanged\n")
            return 0
        size = int(node[tree_fs.A_SIZE] or 0)
        if size > QPOT_GZIP_MAX_INPUT:
            self.errorWrite(f"{prog}: {name}: File too large\n")
            return 1
        folder = node[tree_fs.A_TYPE] == tree_fs.T_DIR
        data = b"" if folder else self.contents(name, prog)
        if data is None:
            return 1
        # BusyBox keeps neither the name nor the time in the header
        title, stamp = ("", 0) if bb else (posixpath.basename(path), int(node[tree_fs.A_CTIME] or 0))
        if to_stdout:
            return self.qpot_to_stdout(data, title, stamp, True)
        target = path + ".gz"
        if self.fs.exists(target) and not force:
            if bb:
                # BusyBox opens the new file O_EXCL
                self.errorWrite(f"{prog}: can't open '{name}.gz': File exists\n")
                return 1
            self.errorWrite(f"gzip: {name}.gz already exists;\tnot overwritten\n")
            return 2
        if not self.qpot_may_deflate(data):
            return 0
        packed = self.qpot_deflate(data, title, stamp)
        self.qpot_spend(data, packed)
        # GNU gzip gives the new file the time of the old one; BusyBox's is made now
        if not self.qpot_place(target, node, packed, None if bb else node[tree_fs.A_CTIME]):
            self.errorWrite(f"{prog}: can't open '{name}.gz': Permission denied\n" if bb
                            else f"gzip: {name}.gz: Permission denied\n")
            return 1
        if keep:
            return 0
        if folder:
            # BusyBox read the directory as nothing, and dies when it cannot remove it
            self.errorWrite(f"{prog}: can't remove file '{name}': Is a directory\n")
            self.qpot_budget = 0
            return 1
        self.fs.remove(path)
        return 0

    def qpot_gunzip(self, name: str, keep: bool, force: bool) -> int:
        bb, prog = self.qpot_bb, self.qpot_prog()
        name = name if bb else self.qpot_gz_name(name)
        path, node, status = self.qpot_node(name)
        if node is None:
            return status
        if bb:
            # BusyBox knows .gz, and .tgz for .tar, as written (make_new_name_gunzip); it opens the new
            # file (O_EXCL) before it reads a byte
            if name.endswith(".gz") and len(posixpath.basename(path)) > 3:
                plain, shown = path[:-3], name[:-3]
            elif name.endswith(".tgz") and len(posixpath.basename(path)) > 4:
                plain, shown = path[:-4] + ".tar", name[:-4] + ".tar"
            else:
                self.errorWrite(f"{prog}: {name}: unknown suffix - ignored\n")
                return 1
            if self.fs.exists(plain) and not force:
                self.errorWrite(f"{prog}: can't open '{shown}': File exists\n")
                return 1
        else:
            plain, shown = self.qpot_plain_name(path), self.qpot_plain_name(name)
            if plain == path:
                self.errorWrite(f"gzip: {name}: unknown suffix -- ignored\n")
                return 2
        data = b"" if node[tree_fs.A_TYPE] == tree_fs.T_DIR else self.contents(name, prog)
        if data is None:
            return 1
        out, problem = self.qpot_inflate(data, name, bb)
        self.qpot_spend(data, out)
        if problem:
            self.errorWrite(problem)
            return 1
        if not bb and self.fs.exists(plain) and not force:
            self.errorWrite(f"gzip: {shown} already exists;\tnot overwritten\n")
            return 2
        # GNU gzip gives the file the time of the .gz (the header's only with -N); BusyBox the header's
        # when it has one, else now
        stamp = (int.from_bytes(data[4:8], "little") or None) if bb else node[tree_fs.A_CTIME]
        if not self.qpot_place(plain, node, out, stamp):
            self.errorWrite(f"{prog}: can't open '{shown}': Permission denied\n" if bb
                            else f"gzip: {shown}: Permission denied\n")
            return 1
        if not keep:
            self.fs.remove(path)
        return 0


# --- help: bash's builtins (BusyBox ash's on its personas) ---------------------------------

# the short docs of bash's builtins in the order help shows them: bash 5.1 and 5.2 (recorded from 5.2.37
#   with COLUMNS=512; a doc ending in > is longer than the 125 characters help ever shows) and 4.2 (the
#   4.2.37 list Cowrie printed at 190 columns, the three docs it cut completed from bash 4.2's builtins)
QPOT_HELP_BASH5 = (
    "job_spec [&]",
    "(( expression ))",
    ". filename [arguments]",
    ":",
    "[ arg... ]",
    "[[ expression ]]",
    "alias [-p] [name[=value] ... ]",
    "bg [job_spec ...]",
    "bind [-lpsvPSVX] [-m keymap] [-f filename] [-q name] [-u name] [-r keyseq] [-x keyseq:shell-command] [keyseq:readline-functio>",
    "break [n]",
    "builtin [shell-builtin [arg ...]]",
    "caller [expr]",
    "case WORD in [PATTERN [| PATTERN]...) COMMANDS ;;]... esac",
    "cd [-L|[-P [-e]] [-@]] [dir]",
    "command [-pVv] command [arg ...]",
    "compgen [-abcdefgjksuv] [-o option] [-A action] [-G globpat] [-W wordlist] [-F function] [-C command] [-X filterpat] [-P pref>",
    "complete [-abcdefgjksuv] [-pr] [-DEI] [-o option] [-A action] [-G globpat] [-W wordlist] [-F function] [-C command] [-X filte>",
    "compopt [-o|+o option] [-DEI] [name ...]",
    "continue [n]",
    "coproc [NAME] command [redirections]",
    "declare [-aAfFgiIlnrtux] [name[=value] ...] or declare -p [-aAfFilnrtux] [name ...]",
    "dirs [-clpv] [+N] [-N]",
    "disown [-h] [-ar] [jobspec ... | pid ...]",
    "echo [-neE] [arg ...]",
    "enable [-a] [-dnps] [-f filename] [name ...]",
    "eval [arg ...]",
    "exec [-cl] [-a name] [command [argument ...]] [redirection ...]",
    "exit [n]",
    "export [-fn] [name[=value] ...] or export -p",
    "false",
    "fc [-e ename] [-lnr] [first] [last] or fc -s [pat=rep] [command]",
    "fg [job_spec]",
    "for NAME [in WORDS ... ] ; do COMMANDS; done",
    "for (( exp1; exp2; exp3 )); do COMMANDS; done",
    "function name { COMMANDS ; } or name () { COMMANDS ; }",
    "getopts optstring name [arg ...]",
    "hash [-lr] [-p pathname] [-dt] [name ...]",
    "help [-dms] [pattern ...]",
    "history [-c] [-d offset] [n] or history -anrw [filename] or history -ps arg [arg...]",
    "if COMMANDS; then COMMANDS; [ elif COMMANDS; then COMMANDS; ]... [ else COMMANDS; ] fi",
    "jobs [-lnprs] [jobspec ...] or jobs -x command [args]",
    "kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]",
    "let arg [arg ...]",
    "local [option] name[=value] ...",
    "logout [n]",
    "mapfile [-d delim] [-n count] [-O origin] [-s count] [-t] [-u fd] [-C callback] [-c quantum] [array]",
    "popd [-n] [+N | -N]",
    "printf [-v var] format [arguments]",
    "pushd [-n] [+N | -N | dir]",
    "pwd [-LP]",
    "read [-ers] [-a array] [-d delim] [-i text] [-n nchars] [-N nchars] [-p prompt] [-t timeout] [-u fd] [name ...]",
    "readarray [-d delim] [-n count] [-O origin] [-s count] [-t] [-u fd] [-C callback] [-c quantum] [array]",
    "readonly [-aAf] [name[=value] ...] or readonly -p",
    "return [n]",
    "select NAME [in WORDS ... ;] do COMMANDS; done",
    "set [-abefhkmnptuvxBCEHPT] [-o option-name] [--] [-] [arg ...]",
    "shift [n]",
    "shopt [-pqsu] [-o] [optname ...]",
    "source filename [arguments]",
    "suspend [-f]",
    "test [expr]",
    "time [-p] pipeline",
    "times",
    "trap [-lp] [[arg] signal_spec ...]",
    "true",
    "type [-afptP] name [name ...]",
    "typeset [-aAfFgiIlnrtux] name[=value] ... or typeset -p [-aAfFilnrtux] [name ...]",
    "ulimit [-SHabcdefiklmnpqrstuvxPRT] [limit]",
    "umask [-p] [-S] [mode]",
    "unalias [-a] name [name ...]",
    "unset [-f] [-v] [-n] [name ...]",
    "until COMMANDS; do COMMANDS-2; done",
    "variables - Names and meanings of some shell variables",
    "wait [-fn] [-p var] [id ...]",
    "while COMMANDS; do COMMANDS-2; done",
    "{ COMMANDS ; }",
)
QPOT_HELP_BASH4 = (
    "job_spec [&]",
    "(( expression ))",
    ". filename [arguments]",
    ":",
    "[ arg... ]",
    "[[ expression ]]",
    "alias [-p] [name[=value] ... ]",
    "bg [job_spec ...]",
    "bind [-lpvsPVS] [-m keymap] [-f filename] [-q name] [-u name] [-r keyseq] [-x keyseq:shell-command] [keyseq:readline-function or readline-command]",
    "break [n]",
    "builtin [shell-builtin [arg ...]]",
    "caller [expr]",
    "case WORD in [PATTERN [| PATTERN]...) COMMANDS ;;]... esac",
    "cd [-L|[-P [-e]]] [dir]",
    "command [-pVv] command [arg ...]",
    "compgen [-abcdefgjksuv] [-o option]  [-A action] [-G globpat] [-W wordlist]  [-F function] [-C command] [-X filterpat] [-P prefix] [-S suffix] [word]",
    "complete [-abcdefgjksuv] [-pr] [-DE] [-o option] [-A action] [-G globpat] [-W wordlist]  [-F function] [-C command] [-X filterpat] [-P prefix] [-S suffix] [name ...]",
    "compopt [-o|+o option] [-DE] [name ...]",
    "continue [n]",
    "coproc [NAME] command [redirections]",
    "declare [-aAfFgilrtux] [-p] [name[=value] ...]",
    "dirs [-clpv] [+N] [-N]",
    "disown [-h] [-ar] [jobspec ...]",
    "echo [-neE] [arg ...]",
    "enable [-a] [-dnps] [-f filename] [name ...]",
    "eval [arg ...]",
    "exec [-cl] [-a name] [command [arguments ...]] [redirection ...]",
    "exit [n]",
    "export [-fn] [name[=value] ...] or export -p",
    "false",
    "fc [-e ename] [-lnr] [first] [last] or fc -s [pat=rep] [command]",
    "fg [job_spec]",
    "for NAME [in WORDS ... ] ; do COMMANDS; done",
    "for (( exp1; exp2; exp3 )); do COMMANDS; done",
    "function name { COMMANDS ; } or name () { COMMANDS ; }",
    "getopts optstring name [arg]",
    "hash [-lr] [-p pathname] [-dt] [name ...]",
    "help [-dms] [pattern ...]",
    "history [-c] [-d offset] [n] or history -anrw [filename] or history -ps arg [arg...]",
    "if COMMANDS; then COMMANDS; [ elif COMMANDS; then COMMANDS; ]... [ else COMMANDS; ] fi",
    "jobs [-lnprs] [jobspec ...] or jobs -x command [args]",
    "kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]",
    "let arg [arg ...]",
    "local [option] name[=value] ...",
    "logout [n]",
    "mapfile [-n count] [-O origin] [-s count] [-t] [-u fd] [-C callback] [-c quantum] [array]",
    "popd [-n] [+N | -N]",
    "printf [-v var] format [arguments]",
    "pushd [-n] [+N | -N | dir]",
    "pwd [-LP]",
    "read [-ers] [-a array] [-d delim] [-i text] [-n nchars] [-N nchars] [-p prompt] [-t timeout] [-u fd] [name ...]",
    "readarray [-n count] [-O origin] [-s count] [-t] [-u fd] [-C callback] [-c quantum] [array]",
    "readonly [-aAf] [name[=value] ...] or readonly -p",
    "return [n]",
    "select NAME [in WORDS ... ;] do COMMANDS; done",
    "set [-abefhkmnptuvxBCHP] [-o option-name] [--] [arg ...]",
    "shift [n]",
    "shopt [-pqsu] [-o] [optname ...]",
    "source filename [arguments]",
    "suspend [-f]",
    "test [expr]",
    "time [-p] pipeline",
    "times",
    "trap [-lp] [[arg] signal_spec ...]",
    "true",
    "type [-afptP] name [name ...]",
    "typeset [-aAfFgilrtux] [-p] name[=value] ...",
    "ulimit [-SHacdefilmnpqrstuvx] [limit]",
    "umask [-p] [-S] [mode]",
    "unalias [-a] name [name ...]",
    "unset [-f] [-v] [name ...]",
    "until COMMANDS; do COMMANDS; done",
    "variables - Names and meanings of some shell variables",
    "wait [id]",
    "while COMMANDS; do COMMANDS; done",
    "{ COMMANDS ; }",
)
QPOT_HELP_HEAD = (
    "These shell commands are defined internally.  Type `help' to see this list.\n"
    "Type `help name' to find out more about the function `name'.\n"
    "Use `info bash' to find out more about the shell in general.\n"
    "Use `man -k' or `info' to find out more about commands not in this list.\n"
    "\n"
    "A star (*) next to a name means that the command is disabled.\n"
    "\n"
)
# the builtins of BusyBox ash: 1.19 (recorded from the Archer C7 v5, the persona engine's table) and
#   1.37 (recorded from Debian's 1.37.0)
QPOT_ASH_BUILTINS_OLD = (".", ":", "[", "[[", "alias", "bg", "break", "cd", "chdir", "command", "continue", "echo",
                         "eval", "exec", "exit", "export", "false", "fg", "getopts", "hash", "help", "jobs", "kill",
                         "let", "local", "printf", "pwd", "read", "readonly", "return", "set", "shift", "source",
                         "test", "times", "trap", "true", "type", "ulimit", "umask", "unalias", "unset", "wait")
QPOT_ASH_BUILTINS_NEW = (".", ":", "[", "[[", "alias", "bg", "break", "cd", "chdir", "command", "continue", "echo",
                         "eval", "exec", "exit", "export", "false", "fg", "getopts", "hash", "help", "history",
                         "jobs", "kill", "let", "local", "printf", "pwd", "read", "readonly", "return", "set",
                         "shift", "source", "test", "times", "trap", "true", "type", "ulimit", "umask", "unalias",
                         "unset", "wait")


def qpot_help_columns(docs: tuple[str, ...], columns: int) -> str:
    """The two columns of bash's help (help.def: dispcolumn): half the terminal's width per column, at most
    128; a doc that does not fit is cut and ends in >."""
    width = columns // 2
    if width > 128:
        width = 128
    if width <= 3:
        width = 40
    count = len(docs)
    height = (count + 1) // 2

    def cell(doc: str, room: int) -> str:
        longer = doc.endswith(">")
        text = doc[:-1] if longer else doc
        if longer or len(text) >= room:
            return " " + text[:room] + ">"
        return " " + text

    out = []
    for i in range(height):
        first = cell(docs[i], width - 3)
        if 2 * i >= count or i + height >= count:
            out.append(first + "\n")
            continue
        out.append(first.ljust(width) + cell(docs[i + height], width - 4) + "\n")
    return "".join(out)


def qpot_ash_help(builtins: tuple[str, ...], old: bool) -> str:
    """help of BusyBox ash (helpcmd of shell/ash.c): the names after a tab or a blank, a new line once the
    column passes 60; 1.19 ends with a blank line, later releases with the line's end."""
    out, col = "Built-in commands:\n------------------\n", 0
    for name in builtins:
        piece = ("\t" if col == 0 else " ") + name
        out += piece
        col += len(piece)
        if col > 60:
            out += "\n"
            col = 0
    if old:
        return out + ("\n" if col else "") + "\n"
    return out + ("\n" if col else "")


try:
    from cowrie.commands.base import Command_help as QpotHelpBase
except ImportError:  # pragma: no cover - the image always has it
    QpotHelpBase = None

if QpotHelpBase is not None:

    class Command_help(QpotHelpBase):
        """help as the persona's shell prints it: bash's banner and builtins of its release, laid out for the
        terminal's width (Cowrie printed bash 4.2.37's at 190 columns everywhere), BusyBox ash's builtins on
        an ash persona; msh's and an unknown bash stay as before."""

        def call(self) -> None:
            style = CowrieConfig.get("shell", "not_found_style", fallback="bash")
            if style == "ash":
                found = re.match(r"(\d+)\.(\d+)", CowrieConfig.get("shell", "text_version", fallback="") or "")
                old = not found or (int(found.group(1)), int(found.group(2))) < (1, 30)
                self.write(qpot_ash_help(QPOT_ASH_BUILTINS_OLD if old else QPOT_ASH_BUILTINS_NEW, old))
                return
            info = qpot_bash_info(self.fs) if style == "bash" else None
            if info is None:
                super().call()
                return
            # help lays itself out for the terminal it writes to (bash keeps COLUMNS at its width); piped or
            #   redirected, for 80 columns whatever COLUMNS says (recorded from 5.2.37)
            targets = getattr(getattr(self, "pp", None), "targets", None) or {}
            width = 0
            if (targets.get(1) or ("",))[0] == "terminal" and not hasattr(self.protocol, "execcmd"):
                columns = self.environ.get("COLUMNS", "")
                width = int(columns) if columns.isdigit() and len(columns) <= 5 else 0
                if not width:
                    try:
                        width = int(self.protocol.user.windowSize[1])
                    except (AttributeError, TypeError, ValueError, IndexError):
                        width = 0
            docs = QPOT_HELP_BASH4 if info[0].startswith("4.") else QPOT_HELP_BASH5
            self.write(f"GNU bash, version {info[0]} ({info[2]})\n" + QPOT_HELP_HEAD
                       + qpot_help_columns(docs, width or 80))

    commands["help"] = Command_help


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
    (Command_zcat, qpot_bin("zcat")),
    (Command_stat, qpot_bin("stat")),
    (Command_gzip, qpot_bin("gzip")),
    (type("Command_gunzip", (Command_gzip,), {"qpot_name": "gunzip"}), qpot_bin("gunzip")),
):
    qpot_register(qpot_cls, *qpot_names)
