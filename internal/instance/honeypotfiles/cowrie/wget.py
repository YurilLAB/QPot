# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import getopt
import posixpath
import re
import time
from typing import Any
from urllib import parse

import treq
from twisted.internet import defer, error, reactor
from twisted.internet.defer import CancelledError, inlineCallbacks
from twisted.internet.protocol import ClientCreator, Protocol
from twisted.logger import Logger
from twisted.protocols.ftp import CommandFailed, FTPClient
from twisted.python import failure
from twisted.web.iweb import UNKNOWN_LENGTH

from cowrie.core.artifact import Artifact
from cowrie.core.config import CowrieConfig
from cowrie.core.download import (
    BlockedAddress,
    UnreachableAddress,
    capture_download,
    fetch,
    outbound_rate_limiter,
    report_download_failure,
)
from cowrie.core.network import (
    DownloadLimitExceeded,
    abort_body,
    communication_allowed,
    is_ip_address,
    resolve_allowed,
    outbound_bind_address,
)
from cowrie.shell.command import HoneyPotCommand

commands = {}

wget_rate_limiter = outbound_rate_limiter("wget")


def tdiff(seconds: int) -> str:
    days, remainder = divmod(seconds, 86400)  # 86400 = 24*60*60
    hours, remainder = divmod(remainder, 3600)  # 3600 = 60*60
    minutes, secs = divmod(remainder, 60)

    parts = []
    if days >= 1:
        parts.append(f"{days}d")
    if hours >= 1:
        parts.append(f"{hours}h")
    if minutes >= 1:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")

    return " ".join(parts)


def sizeof_fmt(num: float) -> str:
    for x in ["bytes", "K", "M", "G", "T"]:
        if num < 1024.0:
            return f"{num}{x}"
        num /= 1024.0
    raise ValueError


# Luciano Ramalho @ http://code.activestate.com/recipes/498181/
def splitthousands(s: str, sep: str = ",") -> str:
    if len(s) <= 3:
        return s
    return splitthousands(s[:-3], sep) + sep + s[-3:]


class _FTPWgetReceiver(Protocol):
    """
    Receive FTP data and forward to wget collector
    """

    def __init__(self, command: Command_wget) -> None:
        self.command = command

    def dataReceived(self, data: bytes) -> None:
        self.command.collect(data)

    def connectionLost(self, reason=None):
        # Download completion handled by command callbacks
        return None


# QPot: the options of GNU wget (src/main.c option_data), taken; the download stays Cowrie's
QPOT_WGET_SHORT = "hVbe:o:a:dqvi:FB:t:O:n:cNST:w:Q:46rl:kKEpA:R:D:I:X:HLP:U:x"
QPOT_WGET_LONG = [
    "help", "version", "background", "execute=", "output-file=", "append-output=", "debug", "quiet",
    "verbose", "no-verbose", "report-speed=", "input-file=", "force-html", "base=", "config=", "rejected-log=",
    "tries=", "retry-connrefused", "retry-on-host-error", "retry-on-http-error=", "output-document=",
    "no-clobber", "backups=", "continue", "start-pos=", "progress=", "show-progress", "timestamping",
    "no-if-modified-since", "no-use-server-timestamps", "server-response", "spider", "timeout=",
    "dns-timeout=", "connect-timeout=", "read-timeout=", "wait=", "waitretry=", "random-wait", "no-proxy",
    "quota=", "bind-address=", "limit-rate=", "no-dns-cache", "restrict-file-names=", "inet4-only",
    "inet6-only", "prefer-family=", "user=", "password=", "ask-password", "use-askpass=", "no-iri",
    "local-encoding=", "remote-encoding=", "unlink", "xattr", "no-directories", "force-directories",
    "no-host-directories", "protocol-directories", "cut-dirs=", "directory-prefix=", "default-page=",
    "adjust-extension", "http-user=", "http-password=", "no-http-keep-alive", "no-cache", "no-cookies",
    "load-cookies=", "save-cookies=", "keep-session-cookies", "ignore-length", "header=", "compression=",
    "max-redirect=", "proxy-user=", "proxy-password=", "referer=", "save-headers", "user-agent=",
    "post-data=", "post-file=", "method=", "body-data=", "body-file=", "content-disposition",
    "content-on-error", "auth-no-challenge", "secure-protocol=", "https-only", "no-check-certificate",
    "certificate=", "certificate-type=", "private-key=", "private-key-type=", "ca-certificate=",
    "ca-directory=", "crl-file=", "pinnedpubkey=", "random-file=", "egd-file=", "ciphers=", "no-hsts",
    "hsts-file=", "ftp-user=", "ftp-password=", "no-remove-listing", "no-glob", "no-passive-ftp",
    "preserve-permissions", "retr-symlinks", "recursive", "level=", "delete-after", "convert-links",
    "convert-file-only", "backup-converted", "mirror", "page-requisites", "strict-comments", "accept=",
    "reject=", "accept-regex=", "reject-regex=", "regex-type=", "domains=", "exclude-domains=",
    "follow-ftp", "follow-tags=", "ignore-tags=", "ignore-case", "span-hosts", "relative",
    "include-directories=", "exclude-directories=", "no-parent", "https-proxy=", "http-proxy=",
]
# a try is at most so many (-t 0 or inf: until ^C, as long as a session lasts)
QPOT_WGET_MAX_TRIES = 1000
# the options wget reads as a time period, by their long names
QPOT_WGET_TIMES = {"-T": "timeout", "-w": "wait", "--timeout": "timeout", "--connect-timeout": "connect-timeout",
                   "--dns-timeout": "dns-timeout", "--read-timeout": "read-timeout", "--wait": "wait",
                   "--waitretry": "waitretry"}
QPOT_WGET_TIME = re.compile(r"\s*([+-]?)([0-9]*(?:\.[0-9]*)?)\s*([smhdw]?)\s*", re.IGNORECASE)
QPOT_WGET_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def qpot_wget_time(text: str) -> float | None:
    """A time period as wget reads one: a decimal number, then s, m, h, d or w; None if it is none."""
    found = QPOT_WGET_TIME.fullmatch(text[:64]) if len(text) <= 64 else None
    if found is None or not found.group(2) or found.group(2) == ".":
        return None
    value = float(found.group(2)) * QPOT_WGET_UNITS[found.group(3).lower()]
    return -value if found.group(1) == "-" else value
# the kernel's SYN retries (net.ipv4.tcp_syn_retries 6) give up after 127 s, as for ssh
QPOT_KERNEL_TIMEOUT = 127


class Command_wget(HoneyPotCommand):
    """
    wget command
    """

    _log = Logger()

    limit_size: int = CowrieConfig.getint("honeypot", "download_limit_size", fallback=0)
    quiet: bool = False

    outfile: str | None = None  # outfile is the file saved inside the honeypot
    artifact: (
        Artifact  # artifact is the file saved for forensics in the real file system
    )
    currentlength: int = 0  # partial size during download
    totallength: int = 0  # total length
    proglen: int = 0
    wget_version: str = (
        "1.25.0"  # GNU wget version used in --help and User-Agent header
    )
    url: bytes
    host: str
    scheme: str
    port: int = 80
    ftp_client: FTPClient | None = None
    ftp_remote_dir: str | None = None
    ftp_remote_file: str | None = None
    started: float

    def print_usage_error(self, error_msg: str = "") -> None:
        """Print usage error message"""
        self.exit_code = 1
        if error_msg:
            self.errorWrite(f"wget: {error_msg}\n")
        self.errorWrite("Usage: wget [OPTION]... [URL]...\n\n")
        self.errorWrite("Try `wget --help' for more options.\n")

    def print_help_message(self) -> None:
        """
        Print GNU-style wget help message.

        Lists both implemented options (that actually work) and recognized options
        (that are silently ignored for compatibility).
        """

        self.write(
            f"GNU Wget {self.wget_version}, a non-interactive network retriever.\n"
        )
        self.write("Usage: wget [OPTION]... [URL]...\n\n")
        self.write("Startup:\n")
        self.write("  -h,  --help              print this help\n\n")
        self.write("Download:\n")
        self.write(
            "  -c,  --continue          resume getting a partially-downloaded file\n"
        )
        self.write("  -O                       write documents to FILE\n")
        self.write("  -q,  --quiet             quiet (no output)\n")
        self.write("  -T,  --timeout=SECONDS   set all timeout values to SECONDS\n")
        self.write("       --tries=NUMBER      set number of retries to NUMBER\n\n")
        self.write("HTTP options:\n")
        self.write("       --header=STRING     insert STRING among the headers\n")
        self.write(
            "       --post-data=STRING  use the POST method; send STRING as the data\n"
        )
        self.write(
            "       --max-redirect=NUM  maximum redirections allowed per page\n\n"
        )
        self.write("Directories:\n")
        self.write("  -P,  --directory-prefix=PREFIX  save files to PREFIX/..\n\n")
        self.write("Email bug reports, questions, discussions to <bug-wget@gnu.org>\n")
        self.write(
            "and/or open issues at https://savannah.gnu.org/bugs/?func=additem&group=wget.\n"
        )

    @inlineCallbacks
    def start(self):
        url: str
        try:
            # QPot: GNU wget's options (getopt_long, so abbreviations and --opt=value or --opt value);
            #   Cowrie's took -T without its value and refused -t, --no-check-certificate, -U ...
            optlist, args = getopt.gnu_getopt(self.args, QPOT_WGET_SHORT, QPOT_WGET_LONG)
        except getopt.GetoptError as err:
            # QPot: glibc getopt's messages, wget's status 2
            opt = err.opt or ""
            if "requires" in err.msg:
                text = f"option '--{opt}' requires an argument" if len(opt) > 1 else \
                    f"option requires an argument -- '{opt}'"
            elif "must not have" in err.msg:
                text = f"option '--{opt}' doesn't allow an argument"
            elif "not a unique prefix" in err.msg:
                text = f"option '--{opt}' is ambiguous"
            elif len(opt) > 1:
                text = f"unrecognized option '--{opt}'"
            else:
                text = f"invalid option -- '{opt}'"
            self.print_usage_error(text)
            self.exit(2)
            return

        # QPot: a time option wget cannot read stops it (cmd_time of init.c), status 2
        for opt, arg in optlist:
            name = QPOT_WGET_TIMES.get(opt, opt[2:] if opt.startswith("--") else "")
            if name in QPOT_WGET_TIMES.values() and qpot_wget_time(arg) is None:
                self.errorWrite(f"wget: --{name}: Invalid time period \u2018{arg}\u2019\n")
                self.exit(2)
                return

        # Handle help option first - print help and exit immediately
        for opt in optlist:
            if opt[0] in ["-h", "--help"]:
                self.print_help_message()
                self.exit()
                return

        if len(args):
            url = args[0].strip()
        else:
            self.print_usage_error("missing URL")
            self.exit()
            return

        self.outfile = None
        self.quiet = False
        for opt in optlist:
            if opt[0] in ("-O", "--output-document"):
                self.outfile = opt[1]
            elif opt[0] in ["-q", "--quiet", "-o", "--output-file", "-a", "--append-output"]:
                # QPot: -o and -a send the messages to the log file
                self.quiet = True
        self.qpot_optlist = optlist

        # for some reason getopt doesn't recognize "-O -"
        # use try..except for the case if passed command is malformed
        try:
            if not self.outfile:
                if "-O" in args:
                    self.outfile = args[args.index("-O") + 1]
        except Exception:
            pass

        if "://" not in url:
            url = f"http://{url}"

        # urlparse() raises on malformed IPv6 brackets, and .port and .hostname
        # are parsed lazily and raise rather than returning None for a port
        # that is not a decimal 0-65535. The URL is attacker input.
        try:
            urldata = parse.urlparse(url)
            hostname = urldata.hostname
            port = urldata.port
        except ValueError:
            self.print_usage_error("invalid URL")
            self.exit()
            return

        self.scheme = (urldata.scheme or "http").lower()

        # self.host is required as it will be used as key in rate limiter from this point forward
        if hostname:
            self.host = hostname
        else:
            self.print_usage_error("invalid URL")
            self.exit()
            return

        # Determine self.port: use explicit port from URL, otherwise use scheme default
        if port is not None:
            self.port = port
        elif self.scheme == "https":
            self.port = 443
        elif self.scheme == "ftp":
            self.port = 21
        else:
            self.port = 80

        # Check rate limit before proceeding
        if not wget_rate_limiter.check(self.host):
            self._log.info(
                "wget: rate limit exceeded for host: {host}. Simulating connection timeout",
                host=self.host,
            )

            # Simulate connection timeout
            # QPot: as GNU wget times out: its tries, then "Giving up" and status 4
            if not self.qpot_busybox():
                self.qpot_unreachable(url, "timeout", None)
                return
            self.errorWrite(f"Connecting to {self.host}:{self.port}... ")
            self.errorWrite("failed: Connection timed out.\n")
            self.errorWrite("Retrying.\n\n")

            self.exit(1)
            return

        # QPot: GNU wget connects to an address the honeypot does not contact: the machine itself refuses,
        #   the bait's internal hosts and the private networks time out (no "unable to resolve" for an
        #   address); a name is looked up once, as before, and the download (or not) is upstream's
        if self.qpot_busybox():
            allowed = yield communication_allowed(self.host)
        else:
            from cowrie.commands.coreutils import qpot_classify, qpot_route
            from cowrie.core.network import resolve_cname

            kind, address = qpot_route(self.fs, self.protocol, self.host)
            named = False
            if kind == "name":
                resolved = yield resolve_cname(self.host, set())
                if self.exited:
                    return
                if resolved is not None:
                    kind, address, named = qpot_classify(str(resolved)), str(resolved), True
            if kind in ("refused", "timeout"):
                self.qpot_unreachable(url, kind, address if named else None)
                return
            allowed = kind == "network"
        if not allowed:
            self._log.info("Attempt to access blocked network address")
            if not self.quiet:
                tm = time.strftime("%Y-%m-%d %H:%M:%S")
                self.errorWrite(f"--{tm}--  {url}\n")
                # QPot: a name the resolver does not know is glibc's EAI_NONAME (the persona's DNS works)
                reason = "Temporary failure in name resolution" if self.qpot_busybox() else "Name or service not known"
                self.errorWrite(f"Resolving {self.host} ({self.host})... failed: {reason}.\n")
            self.errorWrite(f"wget: unable to resolve host address ‘{self.host}’\n")
            # QPot: GNU wget's status for a network failure
            self.exit(1 if self.qpot_busybox() else 4)
            return None

        self.url = url.encode("utf8")

        if self.outfile is None:
            self.outfile = urldata.path.split("/")[-1]
            if not len(self.outfile.strip()) or not urldata.path.count("/"):
                self.outfile = "index.html"
            self.outfile = self.fs.resolve_path(self.outfile, self.cwd)

        elif self.outfile != "-":
            self.outfile = self.fs.resolve_path(self.outfile, self.cwd)
            path = posixpath.dirname(self.outfile)
            if not path or not self.fs.exists(path) or not self.fs.isdir(path):
                self.errorWrite(
                    f"wget: {self.outfile}: Cannot open: No such file or directory\n"
                )
                self.exit(1)
                return

        self.artifact = Artifact("wget-download")

        if not self.quiet:
            tm = time.strftime("%Y-%m-%d %H:%M:%S")
            self.errorWrite(f"--{tm}--  {url}\n")
            self.errorWrite(f"Connecting to {self.host}:{self.port}... connected.\n")
            proto_label = (
                "HTTP" if self.scheme in ("http", "https") else self.scheme.upper()
            )
            self.errorWrite(f"{proto_label} request sent, awaiting response... ")

        # Starting the transfer can raise synchronously before any Deferred
        # exists: connectTCP rejects an FTP host it cannot build a connection
        # for. Route that raise through error() so the command exits instead of
        # being orphaned on the cmdstack until session timeout.
        try:
            if self.scheme == "ftp":
                self.deferred = self.ftpDownload(urldata)
                if self.deferred:
                    self.deferred.addErrback(self.error)
            else:
                self.deferred = self.httpDownload(url)
                if self.deferred:
                    self.deferred.addCallback(self.success)
                    self.deferred.addErrback(self.error)
        except Exception:
            self.error(failure.Failure())
            return

    def qpot_busybox(self) -> bool:
        """Whether this is BusyBox's wget (Command_tpot_wget on a persona with BusyBox's)."""
        return isinstance(self, Command_tpot_wget) and tpot_bb_wget_version() is not None

    def qpot_number(self, names: tuple[str, ...], default: float) -> float:
        """The last of the options names as a number of seconds (with wget's s, m, h, d, w) or tries, else
        default."""
        value = default
        for opt, arg in self.qpot_optlist:
            if opt in names:
                if arg.strip().lower() in ("inf", "infinite"):
                    value = 0
                    continue
                found = qpot_wget_time(arg)
                if found is not None:
                    value = found
        return value

    def qpot_unreachable(self, url: str, kind: str, address: str | None) -> None:
        """GNU wget's tries at an address that refuses (no retry, as wget has it without
        --retry-connrefused) or never answers (each try waits -T or --connect-timeout, else the kernel's
        127 s, then --waitretry's growing pause): "Giving up." and status 4."""
        self.qpot_url, self.qpot_kind, self.qpot_address = url, kind, address
        tries = int(self.qpot_number(("-t", "--tries"), 20))
        self.qpot_tries = QPOT_WGET_MAX_TRIES if tries <= 0 else min(tries, QPOT_WGET_MAX_TRIES)
        timeout = self.qpot_number(("-T", "--timeout", "--connect-timeout"), 0)
        self.qpot_wait = timeout if 0 < timeout < QPOT_KERNEL_TIMEOUT else QPOT_KERNEL_TIMEOUT
        self.qpot_waitretry = max(self.qpot_number(("--waitretry",), 10), 0)
        self.qpot_try = 0
        self.qpot_next_try()

    def qpot_next_try(self) -> None:
        self.qpot_timer = None
        self.qpot_try += 1
        if not self.quiet:
            tm = time.strftime("%Y-%m-%d %H:%M:%S")
            again = f"(try:{self.qpot_try:2d})  " if self.qpot_try > 1 else ""
            self.errorWrite(f"--{tm}--  {again}{self.qpot_url}\n")
            if self.qpot_address is not None:
                if self.qpot_try == 1:
                    self.errorWrite(f"Resolving {self.host} ({self.host})... {self.qpot_address}\n")
                where = f"{self.host} ({self.host})|{self.qpot_address}|:{self.port}"
            else:
                where = f"{self.host}:{self.port}"
            self.errorWrite(f"Connecting to {where}... ")
        if self.qpot_kind == "refused":
            self.qpot_try_failed("Connection refused")
            return
        self.qpot_timer = self.callLater(self.qpot_wait, self.qpot_try_failed, "Connection timed out")

    def qpot_try_failed(self, reason: str) -> None:
        self.qpot_timer = None
        if not self.quiet:
            self.errorWrite(f"failed: {reason}.\n")
        if self.qpot_kind == "refused":
            self.exit(4)
            return
        if self.qpot_try < self.qpot_tries:
            if not self.quiet:
                self.errorWrite("Retrying.\n\n")
            self.qpot_timer = self.callLater(min(self.qpot_try, self.qpot_waitretry) or 0.05, self.qpot_next_try)
            return
        if not self.quiet:
            self.errorWrite("Giving up.\n\n")
        self.exit(4)

    def httpDownload(self, url: str) -> Any:
        """
        Download `url`
        """
        headers: dict[bytes | str, list[bytes | str]] = {
            "User-Agent": [f"Wget/{self.wget_version} (linux-gnu)"]
        }

        return fetch(reactor, url, headers=headers, timeout=10)

    def ftpDownload(self, urldata: parse.ParseResult) -> Any:
        """
        Download `url` via FTP
        """
        username = parse.unquote(urldata.username) if urldata.username else "anonymous"
        password = parse.unquote(urldata.password) if urldata.password else "busybox@"

        raw_path = urldata.path or ""
        if urldata.params:
            raw_path = f"{raw_path};{urldata.params}"
        remote_path = parse.unquote(raw_path)

        if not remote_path or remote_path.endswith("/"):
            self.errorWrite("wget: unsupported directory target in FTP URL\n")
            self.exit(1)
            return None

        self.ftp_remote_dir = posixpath.dirname(remote_path)
        self.ftp_remote_file = posixpath.basename(remote_path)

        if not self.ftp_remote_file:
            self.errorWrite("wget: missing remote filename in FTP URL\n")
            self.exit(1)
            return None

        ip = is_ip_address(self.host)
        if ip is not None and ip.version == 6:
            # The outbound source address is an IPv4 one, so an IPv6 server is
            # as unreachable here as it is on the HTTP path.
            self.errorWrite("failed: Network is unreachable.\n")
            self.exit(1)
            return None

        self.ftp_client = None

        creator = ClientCreator(reactor, FTPClient, username, password, passive=True)
        deferred = creator.connectTCP(
            self.host,
            self.port,
            timeout=30,
            bindAddress=(outbound_bind_address(), 0),
        )
        deferred.addCallback(self._ftp_connected)
        return deferred

    def _ftp_connected(self, client: FTPClient) -> defer.Deferred[Any]:
        """
        Handle established FTP connection
        """
        self.ftp_client = client

        if self.ftp_remote_dir and self.ftp_remote_dir not in (".", "./"):
            d: defer.Deferred[Any] = client.cwd(self.ftp_remote_dir)
        else:
            d = defer.succeed(None)

        d.addCallback(lambda _: self._ftp_start_retrieve())
        return d

    def _ftp_start_retrieve(self) -> defer.Deferred[Any]:
        """
        Start retrieving file over FTP
        """
        if not self._begin_download(None, "application/octet-stream", "200 OK"):
            if self.ftp_client:
                try:
                    quit_deferred = self.ftp_client.quit()
                    quit_deferred.addErrback(
                        lambda f: self._log.info(
                            "FTP quit failed during abort: {error}",
                            error=f.getErrorMessage(),
                        )
                    )
                except Exception as e:  # pragma: no cover - defensive
                    self._log.info(
                        "FTP quit raised exception during abort: {error}", error=e
                    )
                finally:
                    self.ftp_client = None
            return defer.succeed(None)

        if not self.ftp_client or not self.ftp_remote_file:
            return defer.fail(Exception("FTP client not connected"))

        receiver = _FTPWgetReceiver(self)
        deferred = self.ftp_client.retrieveFile(self.ftp_remote_file, receiver)
        deferred.addCallback(self._ftp_after_retrieve)
        return deferred  # type: ignore[no-any-return]

    def _ftp_after_retrieve(self, result: Any) -> Any:
        """
        Cleanup after FTP retrieval completes
        """
        if self.ftp_client:
            try:
                quit_deferred = self.ftp_client.quit()
                quit_deferred.addErrback(
                    lambda f: self._log.info(
                        "FTP quit failed: {error}", error=f.getErrorMessage()
                    )
                )
            except Exception as e:  # pragma: no cover - defensive
                self._log.info("FTP quit raised exception: {error}", error=e)
            finally:
                self.ftp_client = None

        self.collectioncomplete(None)
        return result

    def _begin_download(
        self, total_length: int | None, contenttype: str, status_line: str = "200 OK"
    ) -> bool:
        """
        Prepare transfer bookkeeping and display status
        """
        if total_length is not None:
            self.totallength = total_length
        else:
            self.totallength = 0

        if (
            total_length is not None
            and self.limit_size > 0
            and self.totallength > self.limit_size
        ):
            self._log.info(
                "Not saving URL ({url}) (size: {size}) exceeds file size limit ({limit})",
                url=self.url.decode(),
                size=self.totallength,
                limit=self.limit_size,
            )
            self.exit()
            return False

        self.currentlength = 0
        self.proglen = 0
        self.contenttype = contenttype
        self.speed = 0.0
        self.started = time.time()

        if not self.quiet:
            self.errorWrite(f"{status_line}\n")
            if total_length is not None:
                self.errorWrite(
                    f"Length: {self.totallength} ({sizeof_fmt(self.totallength)}) [{self.contenttype}]\n"
                )
            else:
                self.errorWrite(f"Length: unspecified [{self.contenttype}]\n")

            dest = (
                "STDOUT"
                if self.outfile is None or self.outfile == "-"
                else self.outfile
            )
            self.errorWrite(f"Saving to: `{dest}'\n\n")

        return True

    def handle_CTRL_C(self) -> None:
        # QPot: ^C during a try or between tries stops it
        timer = getattr(self, "qpot_timer", None)
        if timer is not None and timer.active():
            timer.cancel()
        self.qpot_timer = None
        self.write("^C\n")
        self.exit(130)  # 128 + SIGINT

    def exit(self, code: int | None = None) -> None:
        # Close the download artifact on every exit path so an aborted download
        # (CTRL-C, size limit, ...) does not leave its empty temp file behind in
        # the download directory. close() is idempotent and removes an empty
        # artifact, so the normal success/error paths are unaffected.
        artifact = getattr(self, "artifact", None)
        if artifact is not None:
            artifact.close()
        HoneyPotCommand.exit(self, code)

    def success(self, response):
        """
        successful treq get
        """
        # Response metadata comes from an attacker-directed server and need
        # not be valid UTF-8.
        if response.headers.hasHeader(b"content-type"):
            contenttype = response.headers.getRawHeaders(b"content-type")[0].decode(
                errors="replace"
            )
        else:
            contenttype = "text/whatever"

        status_line = "200 OK"
        code = getattr(response, "code", None)
        phrase = getattr(response, "phrase", None)
        if code is not None:
            if phrase:
                if isinstance(phrase, bytes):
                    phrase = phrase.decode(errors="replace")
                status_line = f"{code} {phrase}"
            else:
                status_line = str(code)

        total_length: int | None
        if response.length != UNKNOWN_LENGTH:
            total_length = response.length
        else:
            total_length = None

        if not self._begin_download(total_length, contenttype, status_line):
            # Stop the transfer; an undelivered body would otherwise keep
            # downloading and buffering in memory.
            abort_body(response)
            return None

        deferred = treq.collect(response, self.collect)
        deferred.addCallback(self.collectioncomplete)
        return deferred

    def collect(self, data: bytes) -> None:
        """
        partial collect
        """
        if self.exited:
            # The command exited while the transfer was still in flight (size
            # limit, CTRL-C); drop late chunks instead of writing to the
            # closed artifact.
            return
        eta: float
        self.currentlength += len(data)
        if self.limit_size > 0 and self.currentlength > self.limit_size:
            self._log.info(
                "Not saving URL ({url}) (size: {size}) exceeds file size limit ({limit})",
                url=self.url.decode(),
                size=self.currentlength,
                limit=self.limit_size,
            )
            self.exit()
            # treq closes the connection when the collector raises, aborting
            # the transfer instead of draining the rest of the body. The
            # errback this triggers is inert because the command has exited.
            raise DownloadLimitExceeded

        self.artifact.write(data)

        # Clamp elapsed to 1 microsecond: on a localhost transfer the first
        # chunk can arrive within the same time.time() tick as self.started,
        # which would divide by zero. 1e-6 is below any real network RTT, so it
        # does not distort the reported speed on genuine connections.
        elapsed = max(time.time() - self.started, 1e-6)
        self.speed = self.currentlength / elapsed
        if self.totallength != 0:
            percent = int(self.currentlength / self.totallength * 100)
            spercent = f"{percent}%"
            eta = (self.totallength - self.currentlength) / self.speed
        else:
            spercent = f"{self.currentlength / 1000:3.0f}K"
            percent = 0
            eta = 0.0

        s = "\r{} [{}] {} {:3.1f}K/s  eta {}".format(
            spercent.rjust(3),
            ("%s>" % (int(39.0 / 100.0 * percent) * "=")).ljust(39),
            splitthousands(str(int(self.currentlength))).ljust(12),
            self.speed / 1000,
            tdiff(int(eta)),
        )
        if not self.quiet:
            self.errorWrite(s.ljust(self.proglen))
        self.proglen = len(s)
        self.lastupdate = time.time()

        if not self.outfile or self.outfile == "-":
            self.writeBytes(data)

    def collectioncomplete(self, data: None) -> None:
        """
        this gets called once collection is complete
        """
        if self.exited:
            # The command exited while the transfer was still in flight; the
            # partial artifact was already handled by exit(), so don't report
            # a download for a dead command or exit again.
            return
        self.artifact.close()

        self.totallength = self.currentlength

        if not self.quiet:
            self.errorWrite(
                "\r100% [{}] {} {:3.1f}K/s".format(
                    "%s>" % (38 * "="),
                    splitthousands(str(int(self.totallength))).ljust(12),
                    self.speed / 1000,
                )
            )
            self.errorWrite("\n\n")
            dest = (
                "stdout"
                if self.outfile is None or self.outfile == "-"
                else self.outfile
            )
            self.errorWrite(
                "{} ({:3.2f} KB/s) - `{}' saved [{}/{}]\n\n".format(
                    time.strftime("%Y-%m-%d %H:%M:%S"),
                    self.speed / 1000,
                    dest,
                    self.currentlength,
                    self.totallength,
                )
            )

        capture_download(
            self,
            self.artifact,
            self.url.decode(),
            outfile=None if self.outfile == "-" else self.outfile,
            size=self.currentlength,
        )
        self.exit()

    def error(self, response):
        """
        handle errors
        """
        if self.exited:
            # The command exited while the transfer was still in flight; a
            # late failure of that transfer is not this command's outcome.
            return
        self.exit_code = 1
        report_download_failure(self, self.url.decode())

        if response.check(BlockedAddress) is not None:
            # A redirect reached a host the honeypot must not contact.
            self.errorWrite(
                f"wget: unable to resolve host address ‘{response.value.host}’\n"
            )
            self.exit()
            return

        if response.check(UnreachableAddress) is not None:
            self.errorWrite("failed: Network is unreachable.\n")
            self.exit()
            return

        if response.check(error.DNSLookupError) is not None:
            # QPot: the host's name (Cowrie wrote "no.such")
            self.errorWrite(
                f"Resolving {self.host} ({self.host})... failed: Temporary failure in name resolution.\n"
            )
            self.errorWrite(f"wget: unable to resolve host address ‘{self.host}’\n")
            self.exit()
            return

        if response.check(CancelledError) is not None:
            self.errorWrite("failed: Operation timed out.\n")
            self.exit()
            return

        if response.check(CommandFailed) is not None:
            details = ""
            value = getattr(response, "value", None)
            if value and getattr(value, "args", None):
                details = value.args[0]
            self.errorWrite(f"wget: FTP error: {details}\n")
            self.exit()
            return

        if response.check(error.ConnectingCancelledError) is not None:
            self.errorWrite("cancel failed: Operation timed out.\n")
            self.exit()
            return

        if response.check(error.ConnectionDone) is not None:
            self.errorWrite("No data received.\n")
            self.exit()
            return

        if response.check(error.TCPTimedOutError) is not None:
            self.errorWrite("failed: Connection timed out.\n")
            self.exit()
            return

        self._log.failure("Unhandled wget error", failure=response)
        self.errorWrite("\n")
        self.exit()


commands["/usr/bin/wget"] = Command_wget
commands["wget"] = Command_wget
commands["/usr/bin/dget"] = Command_wget
commands["dget"] = Command_wget



# T-Pot: wget of a BusyBox firmware ([shell] wget_style = busybox, text_banner / text_version)
import re as tpot_re  # noqa: E402

# the usage of BusyBox wget per release (the //usage of networking/wget.c, include/usage.h of 1.14;
#   FEATURE_WGET_LONG_OPTIONS and FEATURE_WGET_TIMEOUT on as in the default configuration, HTTPS from
#   1.32 as there); recorded with busybox:1.25.1 to 1.36.1 and BusyBox 1.24.1 built from its release
#   tarball (refs t9.json bb*-wget-help), 1.14 and 1.19 from the sources
TPOT_BB_WGET_USAGE = (
    # 1.35.0 and 1.36.1: --post-file and the short --header
    ((1, 35), "[-cqS] [--spider] [-O FILE] [-o LOGFILE] [--header STR]\n"
              "\t[--post-data STR | --post-file FILE] [-Y on/off]\n"
              "\t[--no-check-certificate] [-P DIR] [-U AGENT] [-T SEC] URL...\n\n"
              "Retrieve files via HTTP or FTP\n\n"
              "\t--spider\tOnly check URL existence: $? is 0 if exists\n"
              "\t--header STR\tAdd STR (of form 'header: value') to headers\n"
              "\t--post-data STR\tSend STR using POST method\n\t--post-file FILE\tSend FILE using POST method\n"
              "\t--no-check-certificate\tDon't validate the server's certificate\n"
              "\t-c\t\tContinue retrieval of aborted transfer\n\t-q\t\tQuiet\n\t-P DIR\t\tSave to DIR (default .)\n"
              "\t-S    \t\tShow server response\n\t-T SEC\t\tNetwork read timeout is SEC seconds\n"
              "\t-O FILE\t\tSave to FILE ('-' for stdout)\n\t-o LOGFILE\tLog messages to FILE\n"
              "\t-U STR\t\tUse STR for User-Agent header\n\t-Y on/off\tUse proxy\n"),
    # 1.33.1 and 1.34.1: the short form
    ((1, 33), "[-cqS] [--spider] [-O FILE] [-o LOGFILE] [--header 'HEADER: VALUE'] [-Y on/off]\n"
              "\t[--no-check-certificate] [-P DIR] [-U AGENT] [-T SEC] URL...\n\n"
              "Retrieve files via HTTP or FTP\n\n"
              "\t--spider\tOnly check URL existence: $? is 0 if exists\n"
              "\t--no-check-certificate\tDon't validate the server's certificate\n"
              "\t-c\t\tContinue retrieval of aborted transfer\n\t-q\t\tQuiet\n\t-P DIR\t\tSave to DIR (default .)\n"
              "\t-S    \t\tShow server response\n\t-T SEC\t\tNetwork read timeout is SEC seconds\n"
              "\t-O FILE\t\tSave to FILE ('-' for stdout)\n\t-o LOGFILE\tLog messages to FILE\n"
              "\t-U STR\t\tUse STR for User-Agent header\n\t-Y on/off\tUse proxy\n"),
    # 1.32.1: the form of 1.31 with HTTPS
    ((1, 32), "[-c|--continue] [--spider] [-q|--quiet] [-O|--output-document FILE]\n"
              "\t[-o|--output-file FILE] [--header 'header: value'] [-Y|--proxy on/off]\n"
              "\t[--no-check-certificate]\n"
              "\t[-P DIR] [-S|--server-response] [-U|--user-agent AGENT] [-T SEC] URL...\n\n"
              "Retrieve files via HTTP or FTP\n\n"
              "\t--spider\tOnly check URL existence: $? is 0 if exists\n"
              "\t--no-check-certificate\tDon't validate the server's certificate\n"
              "\t-c\t\tContinue retrieval of aborted transfer\n\t-q\t\tQuiet\n\t-P DIR\t\tSave to DIR (default .)\n"
              "\t-S    \t\tShow server response\n\t-T SEC\t\tNetwork read timeout is SEC seconds\n"
              "\t-O FILE\t\tSave to FILE ('-' for stdout)\n\t-o FILE\t\tLog messages to FILE\n"
              "\t-U STR\t\tUse STR for User-Agent header\n\t-Y on/off\tUse proxy\n"),
    # 1.31.1: -o
    ((1, 31), "[-c|--continue] [--spider] [-q|--quiet] [-O|--output-document FILE]\n"
              "\t[-o|--output-file FILE] [--header 'header: value'] [-Y|--proxy on/off]\n"
              "\t[-P DIR] [-S|--server-response] [-U|--user-agent AGENT] [-T SEC] URL...\n\n"
              "Retrieve files via HTTP or FTP\n\n"
              "\t--spider\tOnly check URL existence: $? is 0 if exists\n\t-c\t\tContinue retrieval of aborted transfer\n"
              "\t-q\t\tQuiet\n\t-P DIR\t\tSave to DIR (default .)\n\t-S    \t\tShow server response\n"
              "\t-T SEC\t\tNetwork read timeout is SEC seconds\n\t-O FILE\t\tSave to FILE ('-' for stdout)\n"
              "\t-o FILE\t\tLog messages to FILE\n\t-U STR\t\tUse STR for User-Agent header\n\t-Y on/off\tUse proxy\n"),
    ((1, 27), "[-c|--continue] [--spider] [-q|--quiet] [-O|--output-document FILE]\n"
              "\t[--header 'header: value'] [-Y|--proxy on/off] [-P DIR]\n"
              "\t[-S|--server-response] [-U|--user-agent AGENT] [-T SEC] URL...\n\n"
              "Retrieve files via HTTP or FTP\n\n"
              "\t--spider\tOnly check URL existence: $? is 0 if exists\n\t-c\t\tContinue retrieval of aborted transfer\n"
              "\t-q\t\tQuiet\n\t-P DIR\t\tSave to DIR (default .)\n\t-S    \t\tShow server response\n"
              "\t-T SEC\t\tNetwork read timeout is SEC seconds\n\t-O FILE\t\tSave to FILE ('-' for stdout)\n"
              "\t-U STR\t\tUse STR for User-Agent header\n\t-Y on/off\tUse proxy\n"),
    ((1, 26), "[-c|--continue] [--spider] [-q|--quiet] [-O|--output-document FILE]\n"
              "\t[--header 'header: value'] [-Y|--proxy on/off] [-P DIR]\n"
              "\t[-U|--user-agent AGENT] [-T SEC] URL...\n\n"
              "Retrieve files via HTTP or FTP\n\n"
              "\t--spider\tSpider mode - only check file existence\n\t-c\t\tContinue retrieval of aborted transfer\n"
              "\t-q\t\tQuiet\n\t-P DIR\t\tSave to DIR (default .)\n\t-T SEC\t\tNetwork read timeout is SEC seconds\n"
              "\t-O FILE\t\tSave to FILE ('-' for stdout)\n\t-U STR\t\tUse STR for User-Agent header\n"
              "\t-Y on/off\tUse proxy\n"),
    ((1, 20), "[-c|--continue] [-s|--spider] [-q|--quiet] [-O|--output-document FILE]\n"
              "\t[--header 'header: value'] [-Y|--proxy on/off] [-P DIR]\n"
              "\t[-U|--user-agent AGENT] [-T SEC] URL...\n\n"
              "Retrieve files via HTTP or FTP\n\n"
              "\t-s\tSpider mode - only check file existence\n\t-c\tContinue retrieval of aborted transfer\n"
              "\t-q\tQuiet\n\t-P DIR\tSave to DIR (default .)\n\t-T SEC\tNetwork read timeout is SEC seconds\n"
              "\t-O FILE\tSave to FILE ('-' for stdout)\n\t-U STR\tUse STR for User-Agent header\n"
              "\t-Y\tUse proxy ('on' or 'off')\n"),
    ((1, 15), "[-c|--continue] [-s|--spider] [-q|--quiet] [-O|--output-document FILE]\n"
              "\t[--header 'header: value'] [-Y|--proxy on/off] [-P DIR]\n"
              "\t[--no-check-certificate] [-U|--user-agent AGENT] [-T SEC] URL...\n\n"
              "Retrieve files via HTTP or FTP\n\n"
              "\t-s\tSpider mode - only check file existence\n\t-c\tContinue retrieval of aborted transfer\n"
              "\t-q\tQuiet\n\t-P DIR\tSave to DIR (default .)\n\t-T SEC\tNetwork read timeout is SEC seconds\n"
              "\t-O FILE\tSave to FILE ('-' for stdout)\n\t-U STR\tUse STR for User-Agent header\n"
              "\t-Y\tUse proxy ('on' or 'off')\n"),
    ((0, 0), "[-c|--continue] [-s|--spider] [-q|--quiet] [-O|--output-document file]\n"
             "\t[--header 'header: value'] [-Y|--proxy on/off] [-P DIR]\n"
             "\t[-U|--user-agent agent] url\n\n"
             "Retrieve files via HTTP or FTP\n\nOptions:\n"
             "\t-s\tSpider mode - only check file existence\n\t-c\tContinue retrieval of aborted transfer\n"
             "\t-q\tQuiet\n\t-P\tSet directory prefix to DIR\n\t-O\tSave to filename ('-' for stdout)\n"
             "\t-U\tAdjust 'User-Agent' field\n\t-Y\tUse proxy ('on' or 'off')\n"),
)


# the options getopt32 of BusyBox wget takes, per release: (since, flags, with a value, with an optional
#   value, long flags, long options with a value); from the getopt32 strings and wget_longopts of
#   networking/wget.c 1.14.1 / 1.19.4 / 1.24.1 / 1.26.2 / 1.27.2 and recorded with busybox:1.27.2 /
#   1.31.1 / 1.36.1 and the BusyBox v1.19.4 of the Archer C7 v5 (qemu-mips-static): -T and -t are taken
#   and ignored by every release (a build without FEATURE_WGET_TIMEOUT has no --timeout), -s goes with
#   1.26 (busybox:1.25.1 takes it, 1.26.2 not), -S comes with 1.27, -o / --output-file with 1.31
#   (busybox:1.30.1 refuses it), --post-file with 1.35 (busybox:1.34.1 refuses it, 1.35.0 takes it)
_TPOT_BB_WGET_LONG_114 = frozenset({"output-document", "directory-prefix", "proxy", "user-agent", "header",
                                    "post-data"})
_TPOT_BB_WGET_FLAGS_126 = frozenset({"continue", "quiet", "spider", "passive-ftp", "no-check-certificate",
                                     "no-cache", "no-verbose", "no-clobber", "no-host-directories", "no-parent"})
TPOT_BB_WGET_OPTIONS = (
    ((1, 35), "cqS", "OoPYUTt", "n", _TPOT_BB_WGET_FLAGS_126 | {"server-response"},
     _TPOT_BB_WGET_LONG_114 | {"tries", "output-file", "post-file"}),
    ((1, 31), "cqS", "OoPYUTt", "n", _TPOT_BB_WGET_FLAGS_126 | {"server-response"},
     _TPOT_BB_WGET_LONG_114 | {"tries", "output-file"}),
    ((1, 27), "cqS", "OPYUTt", "n", _TPOT_BB_WGET_FLAGS_126 | {"server-response"}, _TPOT_BB_WGET_LONG_114 | {"tries"}),
    ((1, 26), "cq", "OPYUTt", "n", _TPOT_BB_WGET_FLAGS_126, _TPOT_BB_WGET_LONG_114 | {"tries"}),
    ((1, 24), "csq", "OPYUTt", "", frozenset({"continue", "spider", "quiet", "passive-ftp", "no-check-certificate",
                                              "no-cache"}), _TPOT_BB_WGET_LONG_114),
    ((1, 15), "csq", "OPYUTt", "", frozenset({"continue", "spider", "quiet", "passive-ftp", "no-check-certificate"}),
     _TPOT_BB_WGET_LONG_114),
    ((0, 0), "csq", "OPYUtT", "", frozenset({"continue", "spider", "quiet", "passive-ftp"}), _TPOT_BB_WGET_LONG_114),
)


def tpot_bb_wget_version() -> tuple[int, int] | None:
    """T-Pot: (major, minor) of the BusyBox whose wget this is, None for GNU wget."""
    if CowrieConfig.get("shell", "wget_style", fallback="gnu") != "busybox":
        return None
    found = tpot_re.match(r"(\d+)\.(\d+)", CowrieConfig.get("shell", "text_version", fallback="1.24.1"))
    return (int(found.group(1)), int(found.group(2))) if found else (1, 24)


# T-Pot: the address BusyBox wget names ("Connecting to HOST (IP:PORT)") is the one of upstream's address check, which
#   upstream's start makes after its rate limit: the command that asks is the one start() runs (it calls the check
#   before it yields anything)
tpot_upstream_allowed = communication_allowed
tpot_wget_asking: list = []


@inlineCallbacks
def communication_allowed(address: str):
    command = tpot_wget_asking.pop() if tpot_wget_asking else None
    if command is None:
        allowed = yield tpot_upstream_allowed(address)
        return allowed
    resolved = yield resolve_allowed(address)
    if resolved is not None:
        command.tpot_ip = command.tpot_ip or str(resolved)
        return True
    if command.tpot_ip is None:
        # an address the honeypot does not contact: the one BusyBox connects to (refused), else "bad address"
        try:
            command.tpot_ip = yield reactor.resolve(address)
        except Exception:  # noqa: BLE001 - a name that does not resolve
            command.tpot_ip = None
    return False


class Command_tpot_wget(Command_wget):
    """wget as BusyBox writes it (tpot_bb_wget_version): the download stays upstream's, the texts
    are BusyBox's: "Connecting to HOST (IP:PORT)", its progress line at the end, "bad address",
    "can't connect to remote host", "server returned error" (busybox:1.27.2 / 1.36.1, the sources of
    the older releases); without BusyBox upstream's GNU wget."""

    tpot_ip: str | None = None

    @inlineCallbacks
    def start(self):
        version = tpot_bb_wget_version()
        if version is not None:
            args = self.tpot_bb_args()
            if args is None:
                self.exit()
                return
            self.args = args
            # the address of "Connecting to": as BusyBox resolves the host before it connects
            words, index = [], 0
            while index < len(args):
                arg = args[index]
                index += 1
                if arg in ("-O", "-P", "--header"):
                    index += 1  # its value
                elif not arg.startswith("-"):
                    words.append(arg)
            if words:
                url = words[0] if "://" in words[0] else f"http://{words[0]}"
                self.tpot_url = url
                try:
                    host = parse.urlparse(url).hostname or ""
                except ValueError:
                    host = ""
                if host and is_ip_address(host):
                    self.tpot_ip = host
            # a name: its address comes from upstream's address check, after its rate limit (communication_allowed)
            tpot_wget_asking.append(self)
        try:
            yield Command_wget.start(self)
        finally:
            if self in tpot_wget_asking:
                tpot_wget_asking.remove(self)

    def tpot_bb_usage(self) -> str:
        """The usage of BusyBox wget under its banner."""
        version = tpot_bb_wget_version()
        usage = next(text for since, text in TPOT_BB_WGET_USAGE if version >= since)
        if CowrieConfig.get("shell", "wget_timeout", fallback="yes") == "no":
            # a build without FEATURE_WGET_TIMEOUT (the Archer C7 v5): no -T in the usage
            usage = usage.replace(" [-T SEC]", "").replace("\t-T SEC\tNetwork read timeout is SEC seconds\n", "")
        if version < (1, 21):
            # bb_show_usage before 1.21 ends with a blank line (recorded for 1.19.4)
            usage += "\n"
        banner = CowrieConfig.get("shell", "text_banner", fallback="BusyBox")
        return f"{banner} multi-call binary.\n\nUsage: wget {usage}"

    def tpot_bb_option_error(self, kind: str, option: str) -> None:
        """getopt32 of BusyBox: the message of the firmware's C library, then the usage."""
        libc = CowrieConfig.get("shell", "text_libc", fallback="glibc")
        if kind == "long":
            text = {"musl": f"unrecognized option: {option[2:].partition('=')[0]}",
                    "uclibc": f"unrecognized option `{option}'"}.get(libc, f"unrecognized option '{option}'")
        elif kind == "long-argument":
            text = {"musl": f"option requires an argument: {option[2:]}",
                    "uclibc": f"option `{option}' requires an argument"}.get(
                libc, f"option '{option}' requires an argument")
        elif kind == "argument":
            text = {"musl": f"option requires an argument: {option}",
                    "uclibc": f"option requires an argument -- {option}"}.get(
                libc, f"option requires an argument -- '{option}'")
        else:
            text = {"musl": f"unrecognized option: {option}", "uclibc": f"invalid option -- {option}"}.get(
                libc, f"invalid option -- '{option}'")
        self.exit_code = 1
        self.errorWrite(f"wget: {text}\n" + self.tpot_bb_usage())

    def tpot_bb_args(self) -> list[str] | None:
        """The arguments of BusyBox wget for upstream's getopt ("hcqO:TP:"): what getopt32 of the
        persona's BusyBox takes (TPOT_BB_WGET_OPTIONS); the options that do not change the download go
        with their values, -q and -o LOGFILE are kept as tpot_quiet / tpot_silent. None after an option
        that BusyBox has not (its message and usage written)."""
        version = tpot_bb_wget_version()
        flags, with_value, optional, long_flags, long_value = next(
            row[1:] for row in TPOT_BB_WGET_OPTIONS if version >= row[0])
        # FEATURE_WGET_TIMEOUT (from 1.18) brings --timeout and makes the value of -T a number;
        #   -T is in the getopt string of every build
        timeout = CowrieConfig.get("shell", "wget_timeout", fallback="yes") != "no" and version >= (1, 18)
        if timeout:
            long_value = long_value | {"timeout"}
        args, out, index = list(self.args), [], 0
        quiet = silent = False
        while index < len(args):
            arg = args[index]
            index += 1
            if arg == "--":
                out += args[index - 1:]
                break
            if arg.startswith("--"):
                name, eq, value = arg[2:].partition("=")
                if name not in long_value and (name not in long_flags or eq):
                    self.tpot_bb_option_error("long", arg)
                    return None
                if name in long_value and not eq:
                    if index >= len(args):
                        self.tpot_bb_option_error("long-argument", arg)
                        return None
                    value, index = args[index], index + 1
                if name == "timeout" and not self.tpot_bb_seconds(value):
                    return None
                if name == "output-document":
                    out += ["-O", value]
                elif name == "directory-prefix":
                    out += ["-P", value]
                elif name == "header":
                    out.append(f"--header={value}")
                elif name == "continue":
                    out.append("-c")
                elif name == "quiet":
                    out.append("--quiet")
                    quiet = True
                elif name == "output-file":
                    silent = True
                continue
            if not arg.startswith("-") or arg == "-":
                out.append(arg)
                continue
            position = 1
            while position < len(arg):
                letter = arg[position]
                position += 1
                if letter in optional:
                    break  # -n[ARG]: the rest of the word is its argument
                if letter in with_value:
                    value = arg[position:]
                    if not value:
                        if index >= len(args):
                            self.tpot_bb_option_error("argument", letter)
                            return None
                        value, index = args[index], index + 1
                    if letter == "T" and timeout and not self.tpot_bb_seconds(value):
                        return None
                    if letter in "OP":
                        out += [f"-{letter}", value]
                    elif letter == "o":
                        silent = True
                    break
                if letter not in flags:
                    self.tpot_bb_option_error("invalid", letter)
                    return None
                if letter == "c":
                    out.append("-c")
                elif letter == "q":
                    out.append("-q")
                    quiet = True
        self.tpot_quiet, self.tpot_silent = quiet, silent
        return out

    def tpot_bb_seconds(self, value: str) -> bool:
        """-T SEC of a build with FEATURE_WGET_TIMEOUT: getopt32 converts it with xatoi_positive, which
        stops BusyBox on anything but digits ("invalid number", a value past an unsigned int too) and on a
        value past an int (its range); status 1, no usage (busybox:1.26.2 / 1.36.1)."""
        if tpot_re.fullmatch(r"[0-9]+", value) and int(value) <= 4294967295:
            if int(value) <= 2147483647:
                return True
            self.errorWrite(f"wget: number {value} is not in 0..2147483647 range\n")
        else:
            self.errorWrite(f"wget: invalid number '{value}'\n")
        self.exit_code = 1
        return False

    def print_usage_error(self, error_msg: str = "") -> None:
        version = tpot_bb_wget_version()
        if version is None or error_msg != "missing URL":
            Command_wget.print_usage_error(self, error_msg)
            return
        self.exit_code = 1
        self.errorWrite(self.tpot_bb_usage())

    def tpot_hostport(self) -> str:
        """HOST, or HOST:PORT when the URL names its port (as BusyBox prints what it was given)."""
        url = getattr(self, "tpot_url", None) or (self.url.decode(errors="replace") if hasattr(self, "url") else "")
        explicit = tpot_re.search(r"//[^/]*:(\d+)", url)
        return f"{self.host}:{self.port}" if explicit else self.host

    def tpot_cannot(self, reason: str) -> str:
        version = tpot_bb_wget_version()
        word = "cannot" if version < (1, 15) else "can't"
        return f"wget: {word} connect to remote host ({self.tpot_ip or self.host}): {reason}\n"

    def errorWrite(self, data: str) -> None:
        version = tpot_bb_wget_version()
        if version is None:
            Command_wget.errorWrite(self, data)
            return
        if data.startswith(("--", "Resolving ", "HTTP request sent", "FTP request sent", "Length: ", "Saving to: ",
                            "\r", "Retrying.")) or data == "\n\n" or tpot_re.fullmatch(r"\d{3}( .*)?\n", data):
            return
        if data.startswith("Connecting to ") and data.endswith("... connected.\n"):
            data = f"Connecting to {self.tpot_hostport()} ({self.tpot_ip or self.host}:{self.port})\n"
            if version >= (1, 30):
                dest = "stdout" if self.outfile in (None, "-") else self.outfile
                data += "writing to stdout\n" if dest == "stdout" else f"saving to '{dest}'\n"
        elif data.startswith("Connecting to ") and (data.endswith("... ") or "failed:" in data):
            # (the rate limit of upstream writes "Connecting to H:P... " and its failure apart)
            data = f"Connecting to {self.tpot_hostport()} ({self.tpot_ip or self.host}:{self.port})\n"
        elif data.startswith("failed: Connection timed out"):
            data = self.tpot_cannot("Connection timed out")
        elif data.startswith("failed: Network is unreachable"):
            data = self.tpot_cannot("Network is unreachable")
        elif data.startswith("wget: unable to resolve host address"):
            if self.tpot_ip is not None:
                # an address the honeypot does not contact: refused, as a closed port of a real host
                data = (f"Connecting to {self.tpot_hostport()} ({self.tpot_ip}:{self.port})\n"
                        + self.tpot_cannot("Connection refused"))
            else:
                data = f"wget: bad address '{self.host}'\n"
        elif " saved [" in data:
            data = self.tpot_progress(version)
        if getattr(self, "tpot_silent", False):
            return  # -o LOGFILE: the messages go to that file
        if getattr(self, "tpot_quiet", False):
            # -q: no Connecting line, no progress, the errors stay
            data = "".join(line for line in data.splitlines(keepends=True)
                           if line.startswith("wget: "))
            if not data:
                return
        Command_wget.errorWrite(self, data)

    def tpot_progress(self, version) -> str:
        """The last line of BusyBox's progress meter (80 columns) and what follows it."""
        name = (self.outfile or "-").rsplit("/", 1)[-1] if self.outfile not in (None, "-") else "-"
        size, unit = self.currentlength, " "
        if size >= 100000:
            size, unit = size >> 10, "k"
            while size >= 100000:
                size, unit = size >> 10, "MGTP"["kMGT".index(unit)]
        if version >= (1, 30):
            amount = f"{size:6d}" if unit == " " else f"{size:5d}{unit}"
            line = f"{name:<20.20} 100% |{'*' * 32}|{amount}  0:00:00 ETA\n"
            dest = "stdout" if self.outfile in (None, "-") else self.outfile
            return line + ("written to stdout\n" if dest == "stdout" else f"'{dest}' saved\n")
        return f"{name:<20.20} 100% |{'*' * 31}|{size:6d}{unit}  0:00:00 ETA\n\n"

    def success(self, response):
        if tpot_bb_wget_version() is not None:
            code = getattr(response, "code", 200) or 200
            if code >= 400:
                phrase = getattr(response, "phrase", b"") or b""
                phrase = phrase.decode(errors="replace") if isinstance(phrase, bytes) else str(phrase)
                version = getattr(response, "version", (b"HTTP", 1, 1))
                proto = f"{version[0].decode(errors='replace')}/{version[1]}.{version[2]}"
                Command_wget.errorWrite(self, f"wget: server returned error: {proto} {code} {phrase}\n")
                abort_body(response)
                self.exit(1)
                return None
        return Command_wget.success(self, response)

    def error(self, response):
        if tpot_bb_wget_version() is not None and response.check(error.ConnectionRefusedError) is not None \
                and not self.exited:
            self.exit_code = 1
            report_download_failure(self, self.url.decode())
            Command_wget.errorWrite(self, self.tpot_cannot("Connection refused"))
            self.exit()
            return
        Command_wget.error(self, response)


commands["/usr/bin/wget"] = Command_tpot_wget
commands["wget"] = Command_tpot_wget
