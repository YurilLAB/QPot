# SPDX-FileCopyrightText: 2009-2010 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2025 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""ping as the persona's own: iputils of its release, or BusyBox's applet.

QPot replaced Cowrie's ping. That one took no argument for -c (so `ping -c 4
host` ended in "bad number of packets to transmit"), refused -q, -W, -w and -n,
printed the same statistics whatever the replies were and made an address up
for every name. Texts were recorded with iputils 20240905 and BusyBox 1.37.0;
those of iputils s20160308 (CentOS 7) are derived from its source.
"""

from __future__ import annotations

import getopt
import hashlib
import ipaddress
import math
import random
import re
import socket
import threading
import time
from typing import Any

from twisted.internet import defer, reactor, threads
from twisted.python import failure

from cowrie.core.config import CowrieConfig
from cowrie.shell.command import HoneyPotCommand

commands = {}

# iputils 20240905 (recorded); the releases of the personas list a few options fewer
USAGE_MODERN = """
Usage
  ping [options] <destination>

Options:
  <destination>      DNS name or IP address
  -3                 RTT precision (do not round up the result time)
  -a                 use audible ping
  -A                 use adaptive ping
  -B                 sticky source address
  -c <count>         stop after <count> replies
  -C                 call connect() syscall on socket creation
  -D                 print timestamps
  -d                 use SO_DEBUG socket option
  -e <identifier>    define identifier for ping session, default is random for
                     SOCK_RAW and kernel defined for SOCK_DGRAM
                     Imply using SOCK_RAW (for IPv4 only for identifier 0)
  -f                 flood ping
  -h                 print help and exit
  -H                 force reverse DNS name resolution (useful for numeric
                     destinations or for -f), override -n
  -I <interface>     either interface name or address
  -i <interval>      seconds between sending each packet
  -L                 suppress loopback of multicast packets
  -l <preload>       send <preload> number of packages while waiting replies
  -m <mark>          tag the packets going out
  -M <pmtud opt>     define path MTU discovery, can be one of <do|dont|want|probe>
  -n                 no reverse DNS name resolution, override -H
  -O                 report outstanding replies
  -p <pattern>       contents of padding byte
  -q                 quiet output
  -Q <tclass>        use quality of service <tclass> bits
  -s <size>          use <size> as number of data bytes to be sent
  -S <size>          use <size> as SO_SNDBUF socket option value
  -t <ttl>           define time to live
  -U                 print user-to-user latency
  -v                 verbose output
  -V                 print version and exit
  -w <deadline>      reply wait <deadline> in seconds
  -W <timeout>       time to wait for response

IPv4 options:
  -4                 use IPv4
  -b                 allow pinging broadcast
  -R                 record route
  -T <timestamp>     define timestamp, can be one of <tsonly|tsandaddr|tsprespec>

IPv6 options:
  -6                 use IPv6
  -F <flowlabel>     define flow label, default is random
  -N <nodeinfo opt>  use IPv6 node info query, try <help> as argument

For more details see ping(8).
"""
USAGE_LEGACY = (
    "Usage: ping [-aAbBdDfhLnOqrRUvV] [-c count] [-i interval] [-I interface]\n"
    "            [-m mark] [-M pmtudisc_option] [-l preload] [-p pattern] [-Q tos]\n"
    "            [-s packetsize] [-S sndbuf] [-t ttl] [-T timestamp_option]\n"
    "            [-w deadline] [-W timeout] [hop1 ...] destination\n"
)
# BusyBox 1.37.0 (recorded), shown after the persona's banner where its usage table has no ping
USAGE_BUSYBOX = """Usage: ping [OPTIONS] HOST

Send ICMP ECHO_REQUESTs to HOST

\t-4,-6\t\tForce IP or IPv6 name resolution
\t-c CNT\t\tSend only CNT pings
\t-s SIZE\t\tSend SIZE data bytes in packets (default 56)
\t-i SECS\t\tInterval
\t-A\t\tPing as soon as reply is received
\t-t TTL\t\tSet TTL
\t-I IFACE/IP\tSource interface or IP address
\t-W SEC\t\tSeconds to wait for the first response (default 10)
\t\t\t(after all -c CNT packets are sent)
\t-w SEC\t\tSeconds until ping exits (default:infinite)
\t\t\t(can exit earlier with -c CNT)
\t-q\t\tQuiet, only display output at start/finish
\t-p HEXBYTE\tPayload pattern
"""
OPTIONS_MODERN ="346aAbBc:CdDe:fF:hHi:I:l:Lm:M:nN:Op:qQ:rRs:S:t:T:UvVw:W:"
OPTIONS_LEGACY = "aAbBc:dDfF:hi:I:l:Lm:M:nOp:qQ:rRs:S:t:T:UvVw:W:"
OPTIONS_BUSYBOX = "46c:s:t:I:W:w:i:qAp:"
LONG_MAX = 9223372036854775807
# iputils of each release the personas run ((ID, major) of os-release)
IPUTILS = {("ubuntu", 24): "20240117", ("ubuntu", 22): "20211215", ("debian", 13): "20250605",
           ("debian", 12): "20221126", ("debian", 11): "20210202", ("raspbian", 12): "20221126",
           ("raspbian", 11): "20210202", ("rhel", 9): "20210202", ("rocky", 9): "20210202",
           ("almalinux", 9): "20210202", ("centos", 9): "20210202"}
# where the resolvers answer from in most networks: (initial TTL, hops, base RTT in ms)
WELL_KNOWN = {"8.8.8.8": (128, 12, 9.0), "8.8.4.4": (128, 12, 9.5), "1.1.1.1": (64, 7, 6.0),
              "1.0.0.1": (64, 7, 6.5), "9.9.9.9": (64, 9, 11.0)}
NO_REPLY = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")]


LABEL = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?")


def host_name(name: str) -> bool:
    """Whether the C library's resolver would look name up: at most 253 characters, labels of 63."""
    name = name[:-1] if name.endswith(".") else name
    return 0 < len(name) <= 253 and all(LABEL.fullmatch(label) for label in name.split("."))


# Lookups run in Twisted's thread pool, which the whole honeypot shares, and a lookup that times out
# keeps its thread until the C library gives up: at most LOOKUP_THREADS run at once, whatever the
# sessions ask (more read as an unreachable resolver), and each answer is kept LOOKUP_TTL seconds,
# as a caching resolver would.
LOOKUP_THREADS = 4
LOOKUP_TTL = 300
LOOKUP_CACHE = 512
lookup_lock = threading.Lock()
lookup_busy = [0]
lookup_cache: dict[tuple[str, str], tuple[float, Any]] = {}


def qpot_lookup(kind: str, key: str, resolver, *args) -> defer.Deferred:
    """A Deferred of resolver(*args), run in the thread pool within the limits above."""
    kept = lookup_cache.get((kind, key))
    if kept and time.monotonic() - kept[0] < LOOKUP_TTL:
        return defer.fail(kept[1]) if isinstance(kept[1], Exception) else defer.succeed(kept[1])
    with lookup_lock:
        if lookup_busy[0] >= LOOKUP_THREADS:
            return defer.fail(socket.gaierror(getattr(socket, "EAI_AGAIN", -3), "busy"))
        lookup_busy[0] += 1

    def run():
        try:
            return resolver(*args)
        finally:
            with lookup_lock:
                lookup_busy[0] -= 1

    def keep(result):
        value = result.value if isinstance(result, failure.Failure) else result
        if isinstance(value, Exception) and not isinstance(value, (socket.gaierror, socket.herror)):
            return result  # a lookup that timed out or broke is asked again next time
        if len(lookup_cache) >= LOOKUP_CACHE:
            lookup_cache.pop(next(iter(lookup_cache)))
        lookup_cache[(kind, key)] = (time.monotonic(), value)
        return result

    d = threads.deferToThread(run)
    d.addBoth(keep)
    return d


def ping_style(tree) -> tuple[str, str]:
    """("busybox" | "modern" | "legacy", version) of the persona's ping."""
    from cowrie.commands import coreutils

    if coreutils.qpot_busybox_applet(tree, "ping"):
        return "busybox", ""
    os_id, version = coreutils.qpot_os_release(tree)
    major = version[0] if version else 0
    if (os_id, major) in IPUTILS:
        return "modern", IPUTILS[(os_id, major)]
    if (os_id == "ubuntu" and major >= 21) or (os_id in ("debian", "raspbian") and major >= 11):
        return "modern", "20211215"
    return "legacy", "s20160308"


def iputils_ms(us: int) -> str:
    """A time as iputils prints it: fewer decimals the longer it is."""
    if us >= 100000 - 50:
        return "%d" % ((us + 500) // 1000)
    if us >= 10000 - 5:
        return "%d.%01d" % ((us + 50) // 1000, ((us + 50) % 1000) // 100)
    if us >= 1000:
        return "%d.%02d" % ((us + 5) // 1000, ((us + 5) % 1000) // 10)
    return "%d.%03d" % (us // 1000, us % 1000)


class Command_ping(HoneyPotCommand):
    """ping"""

    def start(self) -> None:
        self.calls: list[Any] = []
        self.finished = False
        self.begun = False
        self.style, self.version = ping_style(self.fs)
        try:
            go = self.parse()
        except Exception:  # noqa: BLE001 - a bad argument must not end the session
            go = False
            self.exit_code = 2
        if not go:
            self.exit()
            return
        self.resolve()

    # --- options ---------------------------------------------------------------------------

    def fail(self, text: str, code: int) -> bool:
        self.errorWrite(text)
        self.exit_code = code
        return False

    def usage_error(self, text: str) -> bool:
        if self.style == "modern":
            return self.fail(f"ping: {text}\n{USAGE_MODERN}", 2)
        if self.style == "legacy":
            return self.fail(f"ping: {text}\n{USAGE_LEGACY}", 2)
        banner = CowrieConfig.get("shell", "text_banner", fallback="BusyBox v1.36.1")
        line = f"ping: {text}\n" if text else ""
        return self.fail(f"{line}{banner} multi-call binary.\n\n{USAGE_BUSYBOX}", 1)

    def number(self, option: str, text: str, low: int, high: int) -> int | None:
        """An integer option as each ping reads it; None after its message."""
        value = text.strip()
        ok = value.lstrip("+-").isdigit()
        if self.style == "busybox":
            if not value.isdigit():
                self.fail(f"ping: invalid number '{text}'\n", 1)
                return None
            return int(value)
        if self.style == "legacy":
            if not ok or not low <= int(value) <= high:
                legacy = {"c": "bad number of packets to transmit.", "s": "illegal packet size.",
                          "w": "bad wait time.", "t": "ttl out of range"}.get(option, "invalid argument")
                self.fail(f"ping: {legacy}\n", 2)
                return None
            return int(value)
        if not ok:
            self.fail(f"ping: invalid argument: '{text}'\n", 1)
            return None
        if not low <= int(value) <= high:
            self.fail(f"ping: invalid argument: '{text}': out of range: {low} <= value <= {high}\n", 1)
            return None
        return int(value)

    def seconds(self, option: str, text: str) -> float | None:
        try:
            value = float(text)
            if value < 0 or math.isnan(value) or math.isinf(value):
                raise ValueError
            return value
        except ValueError:
            if self.style == "busybox":
                self.fail(f"ping: invalid number '{text}'\n", 1)
            elif option == "i":
                self.fail(f"ping: bad timing interval: {text}\n" if self.style == "modern"
                          else "ping: bad timing interval\n", 1 if self.style == "modern" else 2)
            else:
                self.fail(f"ping: bad linger time: {text}\n" if self.style == "modern"
                          else "ping: bad linger time\n", 1 if self.style == "modern" else 2)
            return None

    def parse(self) -> bool:
        args = list(self.args)
        if self.style == "busybox":
            from cowrie.commands.uname import tpot_bb_usage_stop

            if tpot_bb_usage_stop(self, "ping", args):
                return False
        spec = {"modern": OPTIONS_MODERN, "legacy": OPTIONS_LEGACY}.get(self.style, OPTIONS_BUSYBOX)
        try:
            options, rest = getopt.gnu_getopt(args, spec)
        except getopt.GetoptError as err:
            opt = err.opt or ""
            if len(opt) > 1:
                return self.usage_error(f"unrecognized option '--{opt}'")
            if "requires" in err.msg:
                return self.usage_error(f"option requires an argument -- '{opt}'")
            return self.usage_error(f"invalid option -- '{opt}'")
        self.count: int | None = None
        self.interval, self.linger, self.deadline = 1.0, 10.0, None
        self.size, self.quiet, self.numeric, self.v6, self.broadcast = 56, False, False, False, False
        for opt, value in options:
            key = opt[1:]
            if key == "c":
                count = self.number("c", value, 1, LONG_MAX)
                if count is None:
                    return False
                self.count = count or None  # BusyBox: -c 0 pings on
            elif key == "s":
                size = self.number("s", value, 0, 65507)
                if size is None:
                    return False
                self.size = size
            elif key == "w":
                deadline = self.number("w", value, 0, 2147483647)
                if deadline is None:
                    return False
                self.deadline = deadline or None
            elif key in ("i", "W"):
                seconds = self.seconds(key, value)
                if seconds is None:
                    return False
                if key == "i":
                    self.interval = max(seconds, 0.05)
                else:
                    self.linger = seconds
            elif key == "t" and self.style != "busybox":
                if self.number("t", value, 0, 255) is None:
                    return False
            elif key == "q":
                self.quiet = True
            elif key == "n":
                self.numeric = True
            elif key == "6":
                self.v6 = True
            elif key == "b":
                self.broadcast = True
            elif key == "V" and self.style != "busybox":
                if self.style == "modern":
                    self.write(f"ping from iputils {self.version}\nlibcap: yes, IDN: yes, NLS: no, "
                               "error.h: yes, getrandom(): yes, __fpending(): yes\n")
                else:
                    self.write(f"ping utility, iputils-{self.version}\n")
                self.exit_code = 0
                return False
            elif key == "h" and self.style != "busybox":
                self.write(USAGE_MODERN if self.style == "modern" else USAGE_LEGACY)
                self.exit_code = 2
                return False
        if not rest:
            if self.style == "modern":
                return self.fail("ping: usage error: Destination address required\n", 2)
            if self.style == "legacy":
                return self.fail(USAGE_LEGACY, 2)
            return self.usage_error("")
        self.host = rest[-1]
        return True

    # --- the destination -------------------------------------------------------------------

    def not_found(self, reason: str = "Name or service not known") -> None:
        if self.exited:
            return
        if self.style == "modern":
            self.fail(f"ping: {self.host}: {reason}\n", 2)
        elif self.style == "legacy":
            self.fail(f"ping: unknown host {self.host}\n", 2)
        else:
            self.fail(f"ping: bad address '{self.host}'\n", 1)
        self.exit()

    def resolve(self) -> None:
        from cowrie.commands import coreutils

        host = self.host
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            if literal.version == 6 and literal != ipaddress.ip_address("::1"):
                if self.style == "legacy":
                    self.not_found()
                    return
                self.fail("ping: connect: Network is unreachable\n", 2)
                self.exit()
                return
            if literal.version == 4 and self.v6:
                self.fail(f"ping: {host}: Address family for hostname not supported\n", 2)
                self.exit()
                return
            self.found(str(literal), host, numeric=True)
            return
        if self.v6 and self.style == "modern" and host.lower() not in ("localhost", "ip6-localhost"):
            self.fail(f"ping: {host}: Address family for hostname not supported\n", 2)
            self.exit()
            return
        listed = coreutils.qpot_hosts_lookup(self.fs, host, v6=self.style == "modern")
        if listed:
            self.found(listed, host, numeric=False)
            return
        own = coreutils.qpot_own_address(self.protocol, host)
        if own:
            self.found(own, host, numeric=False)
            return
        # a name the resolver would refuse is not asked for
        try:
            name = host.encode("idna").decode("ascii")
        except UnicodeError:
            name = ""
        if not host_name(name):
            self.not_found()
            return
        # the C library's resolver, as ping's: its message tells a name that does not exist from a
        # resolver that cannot be reached ("Temporary failure in name resolution")
        d = qpot_lookup("name", name.lower(), socket.getaddrinfo, name, None, socket.AF_INET, socket.SOCK_RAW)
        d.addTimeout(12, reactor)
        d.addCallbacks(lambda found: self.found(str(found[0][4][0]), host, numeric=False), self.lookup_failed)

    def lookup_failed(self, failure) -> None:
        # glibc's texts (the personas' C library), not those of the image's own C library
        error = failure.value
        code = error.args[0] if isinstance(error, socket.gaierror) and error.args else None
        texts = {getattr(socket, "EAI_AGAIN", -3): "Temporary failure in name resolution",
                 getattr(socket, "EAI_FAIL", -4): "Non-recoverable failure in name resolution",
                 getattr(socket, "EAI_NODATA", -5): "No address associated with hostname",
                 getattr(socket, "EAI_ADDRFAMILY", -9): "Address family for hostname not supported"}
        if code is None and not isinstance(error, (UnicodeError, ValueError)):
            self.not_found("Temporary failure in name resolution")
        else:
            self.not_found(texts.get(code, "Name or service not known"))

    def found(self, ip: str, host: str, numeric: bool) -> None:
        if self.exited:
            return
        self.ip = ip
        if self.style == "busybox" or numeric or self.numeric:
            self.label = None
            self.begin()
            return
        from cowrie.commands import coreutils

        name = coreutils.qpot_hosts_name(self.fs, ip)
        if name or ipaddress.ip_address(ip).is_loopback:
            self.label = name or self.protocol.hostname
            self.begin()
            return
        d = qpot_lookup("address", ip, socket.gethostbyaddr, ip)
        d.addTimeout(2, reactor)
        d.addCallbacks(lambda result: self.named(result[0]), lambda _failure: self.named(None))

    def named(self, name: str | None) -> None:
        if self.exited:
            return
        self.label = name
        self.begin()

    # --- the replies -----------------------------------------------------------------------

    def reply_profile(self) -> tuple[int, float, float] | None:
        """(TTL, base RTT ms, jitter share) of the destination, None for one that never answers."""
        from cowrie.commands import coreutils

        address = ipaddress.ip_address(self.ip)
        local, gateway, broadcasts = coreutils.qpot_local_addresses()
        if address.is_loopback or address.is_unspecified or self.ip in local:
            return 64, 0.03, 0.4
        if self.ip == gateway:
            return 64, 0.4, 0.3
        if self.ip in broadcasts or self.ip == "255.255.255.255":
            return None
        if any(address in net for net in NO_REPLY if net.version == address.version):
            return None
        if self.ip in WELL_KNOWN:
            initial, hops, base = WELL_KNOWN[self.ip]
        else:
            seed = hashlib.sha256(f"{self.protocol.hostname}|{self.ip}".encode()).digest()
            initial = (64, 64, 64, 128, 128, 255)[seed[0] % 6]
            hops = 6 + seed[1] % 14
            base = 5.0 + ((seed[2] << 8) | seed[3]) % 16000 / 100.0
        return initial - hops, base, 0.03

    def begin(self) -> None:
        if self.exited:
            return
        from cowrie.commands import coreutils

        address = ipaddress.ip_address(self.ip)
        broadcasts = coreutils.qpot_local_addresses()[2]
        if (self.ip == "255.255.255.255" or self.ip in broadcasts) and self.style != "busybox" and not self.broadcast:
            self.fail("ping: Do you want to ping broadcast? Then -b. If not, check your local firewall rules\n", 2)
            self.exit()
            return
        self.begun = True
        self.profile = self.reply_profile()
        if self.style == "busybox":
            self.write(f"PING {self.host} ({self.ip}): {self.size} data bytes\n")
        elif address.version == 6:
            self.write(f"PING {self.host} ({self.ip}) {self.size} data bytes\n")
        else:
            self.write(f"PING {self.host} ({self.ip}) {self.size}({self.size + 28}) bytes of data.\n")
        self.sent = self.received = self.pending = 0
        self.rtts: list[int] = []
        self.started = time.time()
        if self.deadline:
            self.calls.append(self.callLater(self.deadline, self.finish, True))
        self.send()

    def rtt_us(self) -> int:
        ttl, base, share = self.profile
        rtt = base * (1 + random.gauss(0, share)) + abs(random.gauss(0, base * 0.01 + 0.002))
        if base > 1 and random.random() < 0.02:
            rtt += base * random.uniform(0.2, 1.0)
        return max(int(rtt * 1000), 8)

    def send(self) -> None:
        if self.finished:
            return
        self.sent += 1
        if self.profile is not None:
            self.pending += 1
            rtt = self.rtt_us()
            self.calls.append(self.callLater(rtt / 1e6, self.reply, self.sent, rtt))
        if self.count is None or self.sent < self.count:
            self.calls.append(self.callLater(self.interval, self.send))
        elif self.profile is None:
            self.calls.append(self.callLater(self.linger, self.finish, False))

    def reply(self, seq: int, rtt: int) -> None:
        if self.finished:
            return
        self.pending -= 1
        self.received += 1
        self.rtts.append(rtt)
        if not self.quiet:
            source = f"{self.label} ({self.ip})" if self.label else self.ip
            ttl = self.profile[0]
            if self.style == "busybox":
                self.write(f"{self.size + 8} bytes from {self.ip}: seq={seq - 1} ttl={ttl} "
                           f"time={rtt // 1000}.{rtt % 1000:03d} ms\n")
            else:
                self.write(f"{self.size + 8} bytes from {source}: icmp_seq={seq} ttl={ttl} time={iputils_ms(rtt)} ms\n")
        if self.count is not None and self.sent >= self.count and self.pending == 0:
            self.finish(False)

    def finish(self, measured: bool) -> None:
        if self.finished:
            return
        self.finished = True
        for call in self.calls:
            if call.active():
                call.cancel()
        if measured or self.sent < 2:
            elapsed = int((time.time() - self.started) * 1000) if measured else 0
        else:
            elapsed = int((self.sent - 1) * self.interval * 1000) + random.randint(0, 6)
        loss = (self.sent - self.received) * 100 // self.sent if self.sent else 0
        lines = [f"\n--- {self.host} ping statistics ---\n"]
        if self.style == "busybox":
            lines.append(f"{self.sent} packets transmitted, {self.received} packets received, {loss}% packet loss\n")
            if self.rtts:
                low, high, avg = min(self.rtts), max(self.rtts), sum(self.rtts) // len(self.rtts)
                lines.append(f"round-trip min/avg/max = {low // 1000}.{low % 1000:03d}/"
                             f"{avg // 1000}.{avg % 1000:03d}/{high // 1000}.{high % 1000:03d} ms\n")
        else:
            lines.append(f"{self.sent} packets transmitted, {self.received} received, {loss}% packet loss, "
                         f"time {elapsed}ms\n")
            if self.rtts:
                n = len(self.rtts)
                avg = sum(self.rtts) / n
                mdev = math.sqrt(max(sum(r * r for r in self.rtts) / n - avg * avg, 0.0))
                lines.append(f"rtt min/avg/max/mdev = {min(self.rtts) / 1000:.3f}/{avg / 1000:.3f}/"
                             f"{max(self.rtts) / 1000:.3f}/{mdev / 1000:.3f} ms\n")
            else:
                lines.append("\n")
        self.write("".join(lines))
        self.exit(0 if self.received else 1)

    def handle_CTRL_C(self) -> None:
        if not self.begun or self.finished:
            HoneyPotCommand.handle_CTRL_C(self)
            return
        self.write("^C")
        self.finish(True)


commands["/bin/ping"] = Command_ping
commands["ping"] = Command_ping
