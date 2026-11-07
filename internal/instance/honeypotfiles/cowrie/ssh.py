# SPDX-FileCopyrightText: 2009-2012 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause


from __future__ import annotations

import base64
import fnmatch
import getopt
import hashlib
import re
import socket
import time
from typing import TYPE_CHECKING

from twisted.logger import Logger

from cowrie.core import qpot_bait
from cowrie.core.config import CowrieConfig
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import A_SIZE

if TYPE_CHECKING:
    from collections.abc import Callable

commands = {}


OUTPUT = [
    "usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface]",
    "           [-b bind_address] [-c cipher_spec] [-D [bind_address:]port]",
    "           [-E log_file] [-e escape_char] [-F configfile] [-I pkcs11]",
    "           [-i identity_file] [-J [user@]host[:port]] [-L address]",
    "           [-l login_name] [-m mac_spec] [-O ctl_cmd] [-o option] [-p port]",
    "           [-Q query_option] [-R address] [-S ctl_path] [-W host:port]",
    "           [-w local_tun[:remote_tun]] destination [command]",
]


class QpotSSHClient(HoneyPotCommand):
    """QPot: what ssh, scp and sftp of OpenSSH share: the identity files they would offer (logged so that
    a stolen key used from here trips its canary), the config they read, and the wait on a host that
    never answers."""

    # the program the logged command line starts with
    qpot_program = "ssh"

    # QPot: the kernel's SYN retries (net.ipv4.tcp_syn_retries 6) give up after 127 s
    QPOT_KERNEL_TIMEOUT = 127
    # QPot: OpenSSH's default identity files, tried when none is given
    QPOT_DEFAULT_IDS = ("id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk", "id_dsa")
    # QPot: at most so many identity files are read per ssh (an attacker can name any number)
    QPOT_MAX_IDS = 8

    def qpot_home(self) -> str:
        home = str((getattr(self, "environ", None) or {}).get("HOME", "") or "")
        return home.rstrip("/") if home.startswith("/") else ""

    def qpot_read_small(self, path: str) -> bytes | None:
        """The contents of a regular file of at most MAX_KEY_FILE bytes, None for anything else."""
        try:
            if not self.fs.exists(path) or self.fs.isdir(path):
                return None
            node = self.fs.getfile(path)
            if node is None or int(node[A_SIZE] or 0) > qpot_bait.MAX_KEY_FILE:
                return None
            return self.fs.file_contents(path)[: qpot_bait.MAX_KEY_FILE]
        except Exception:  # noqa: BLE001 - a broken link, a folder: no file
            return None

    def qpot_config_identities(self, data: bytes, host: str) -> list[str]:
        """IdentityFile of the Host blocks of an ssh_config that match host (Match blocks are skipped)."""
        found, active = [], True
        for raw in data[:65536].decode("utf-8", "replace").splitlines()[:2048]:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = re.split(r"[ \t]*=[ \t]*|[ \t]+", line, maxsplit=1)
            key, value = parts[0].lower(), (parts[1] if len(parts) > 1 else "").strip()
            if key == "host":
                pats = value.lower().split()[:64]
                name = host.lower()
                active = (any(fnmatch.fnmatchcase(name, p) for p in pats if not p.startswith("!"))
                          and not any(fnmatch.fnmatchcase(name, p[1:]) for p in pats if p.startswith("!")))
            elif key == "match":
                active = False
            elif key == "identityfile" and active and value:
                found.append(value.strip('"'))
        return found

    def qpot_identities(self, optlist: list[tuple[str, str]], user: str, host: str) -> list[str]:
        """The identity files ssh would try for user@host, as paths of the fake filesystem: -i and
        -o IdentityFile, then the IdentityFile of the config (-F, else ~/.ssh/config), else the
        default files of ~/.ssh that exist."""
        home = self.qpot_home()
        given, config = [], home + "/.ssh/config" if home else ""
        for opt, value in optlist:
            if opt == "-i":
                given.append(value)
            elif opt == "-F":
                config = value
            elif opt == "-o":
                found = re.fullmatch(r"(?i)\s*identityfile(?:\s*=|[^\S ]* )\s*(\S.{0,1023})", value)
                if found:
                    given.append(found.group(1).strip().strip('"'))
        if config:
            data = self.qpot_read_small(self.fs.resolve_path(config.replace("~", home, 1) if config.startswith("~")
                                                             else config, self.cwd))
            if data:
                given += self.qpot_config_identities(data, host)
        if not given and home:
            given = [home + "/.ssh/" + name for name in self.QPOT_DEFAULT_IDS]

        def expand(path: str) -> str:
            local = str(getattr(getattr(self.protocol, "user", None), "username", "") or "")
            path = (path.replace("%d", home).replace("%u", local).replace("%r", user).replace("%h", host)
                    .replace("%%", "%"))
            if path == "~" or path.startswith("~/"):
                path = home + path[1:]
            return self.fs.resolve_path(path, self.cwd)

        paths: list[str] = []
        for path in given[: self.QPOT_MAX_IDS * 4]:
            full = expand(path[:1024])
            if full and full not in paths:
                paths.append(full)
        return paths[: self.QPOT_MAX_IDS]

    def qpot_log_identities(self, optlist: list[tuple[str, str]], user: str, host: str) -> None:
        """Log each public key ssh would offer for user@host (read from the identity file, else its
        .pub) as a cowrie.credentials.use event with its fingerprint, as Cowrie logs a login's key."""
        seen = set()
        for path in self.qpot_identities(optlist, user, host):
            blob = None
            for candidate in (path, path + ".pub"):
                data = self.qpot_read_small(candidate)
                blob = qpot_bait.public_key(data) if data else None
                if blob:
                    break
            if not blob or blob in seen:
                continue
            seen.add(blob)
            key_type = qpot_bait.key_type(blob) or ""
            self.protocol.events.dispatch(
                "cowrie.credentials.use",
                "SSH key %(fingerprint)s used for %(username)s@%(host)s",
                realm="ssh",
                username=user[:256],
                host=host[:256],
                identity=path,
                fingerprint=qpot_bait.key_fingerprint(blob),
                key=key_type + " " + base64.b64encode(blob).decode(),
                type=key_type,
                input=" ".join([self.qpot_program] + list(self.args))[:4096],
            )

    def qpot_unreachable(self, address: str, optlist: list[tuple[str, str]]) -> None:
        """Connect to an address that never answers: ConnectTimeout of -o, else of the user's
        ~/.ssh/config, else the kernel's; then ssh's message and its status 255."""
        port, timeout = "22", None
        for opt, value in optlist:
            if opt == "-p" and value.isdigit() and len(value) <= 5:
                port = value
            elif opt == "-o":
                # one way to match the separator (here and for IdentityFile): \s*[ =]\s* tried
                # every split of a run of blanks, and 62 000 of them held the reactor 56 s
                found = re.fullmatch(r"(?i)\s*connecttimeout(?:\s*=|[^\S ]* )\s*([0-9]{1,4})\s*", value)
                if found:
                    timeout = int(found.group(1))
        if timeout is None:
            config = next((value for opt, value in optlist if opt == "-F"), None)
            timeout = self.qpot_config_timeout(config)
        if not timeout or timeout > self.QPOT_KERNEL_TIMEOUT:
            timeout = self.QPOT_KERNEL_TIMEOUT
        self.qpot_timer = self.callLater(timeout, self.qpot_timed_out, address, port)

    def qpot_config_timeout(self, config: str | None = None) -> int | None:
        """ConnectTimeout of the config ssh reads (-F's, else the session user's ~/.ssh/config; its first
        one), None without one."""
        home = str((getattr(self, "environ", None) or {}).get("HOME", "") or "")
        if config is not None:
            path = self.fs.resolve_path(home + config[1:] if config.startswith("~/") else config,
                                        getattr(self, "cwd", "/"))
        elif home.startswith("/"):
            path = home.rstrip("/") + "/.ssh/config"
        else:
            return None
        try:
            data = self.fs.file_contents(path)[:65536]
        except Exception:  # noqa: BLE001 - no config, a folder, a broken link: no timeout of its own
            return None
        # one way to match the separator, as for -o: the config is the attacker's to write
        found = re.search(rb"(?im)^[ \t]*ConnectTimeout(?:[ \t]*=[ \t]*|[ \t]+)([0-9]{1,4})[ \t]*$", data)
        return int(found.group(1)) if found else None

    def qpot_timed_out(self, address: str, port: str) -> None:
        self.qpot_timer = None
        # QPot: ssh's log line ends in CRLF (log.c), as a terminal shows it
        self.errorWrite(f"ssh: connect to host {address} port {port}: Connection timed out\r\n")
        self.exit(255)



class Command_ssh(QpotSSHClient):
    """
    ssh
    """

    _log = Logger()

    host: str
    callbacks: list[Callable]

    def valid_ip(self, address: str) -> bool:
        try:
            socket.inet_aton(address)
        except Exception:
            return False
        else:
            return True

    def start(self) -> None:
        try:
            options = "-1246AaCfgKkMNnqsTtVvXxYb:c:D:e:F:i:L:l:m:O:o:p:R:S:w:"
            optlist, args = getopt.getopt(self.args, options)
        except getopt.GetoptError:
            self.write("Unrecognized option\n")
            self.exit()
            return

        for opt in optlist:
            if opt[0] == "-V":
                self.write(
                    CowrieConfig.get(
                        "shell",
                        "ssh_version",
                        fallback="OpenSSH_7.9p1, OpenSSL 1.1.1a  20 Nov 2018",
                    )
                    + "\n"
                )
                self.exit()
                return
        if not len(args):
            for line in OUTPUT:
                self.write(f"{line}\n")
            self.exit()
            return
        user, host = "root", args[0]
        for opt in optlist:
            if opt[0] == "-l":
                user = opt[1]
        if args[0].count("@"):
            user, host = args[0].split("@", 1)

        # QPot: the keys ssh would offer (-i, IdentityFile, its defaults) are logged as used: a stolen
        #   key used from here (ssh -i ~/.ssh/id_ed25519 backup@db01) trips as one offered in a login
        self.qpot_log_identities(optlist, user, host)

        # QPot: an internal host the bait files name (qpot_bait.py) is out of reach from here, as is
        #   the network behind the persona: ssh waits out its connect timeout and gives up
        address = qpot_bait.internal_host(host)
        if address is not None:
            self.qpot_unreachable(address, optlist)
            return

        if re.match("^[0-9.]+$", host):
            if self.valid_ip(host):
                self.ip = host
            else:
                self.write(
                    f"ssh: Could not resolve hostname {host}: \
                    Name or service not known\n"
                )
                self.exit()
        else:
            s = hashlib.md5(host.encode()).hexdigest()
            self.ip = ".".join(
                [str(int(x, 16)) for x in (s[0:2], s[2:4], s[4:6], s[6:8])]
            )

        self.host = host
        self.remote_user = user

        self.write(
            f"The authenticity of host '{self.host} ({self.ip})' \
            can't be established.\n"
        )
        self.write(
            "RSA key fingerprint is \
            9d:30:97:8a:9e:48:0d:de:04:8d:76:3a:7b:4b:30:f8.\n"
        )
        self.write("Are you sure you want to continue connecting (yes/no)? ")
        self.callbacks = [self.yesno, self.wait]

    def yesno(self, line: str) -> None:
        self.write(
            f"Warning: Permanently added '{self.host}' (RSA) to the \
            list of known hosts.\n"
        )
        self.write(f"{self.remote_user}@{self.host}'s password: ")
        self.protocol.password_input = True

    def wait(self, line: str) -> None:
        self.callLater(2, self.finish, line)

    def finish(self, line: str) -> None:
        self.pause = False
        rests = self.host.strip().split(".")
        if len(rests) and rests[0].isalpha():
            host = rests[0]
        else:
            host = "localhost"
        self.protocol.hostname = host
        # The fake remote login lands the running shell in root's home there.
        self.shell.cwd = "/root" if self.fs.exists("/root") else "/"
        self.protocol.password_input = False
        kernel_version = CowrieConfig.get("shell", "kernel_version", fallback="5.10.0")
        kernel_build = CowrieConfig.get("shell", "kernel_build_string", fallback="#1 SMP")
        hardware = CowrieConfig.get("shell", "hardware_platform", fallback="x86_64")
        operating_system = CowrieConfig.get("shell", "operating_system", fallback="GNU/Linux")
        self.write(
            f"Linux {self.protocol.hostname} {kernel_version} {kernel_build} "
            f"{hardware} {operating_system}\n"
        )
        self.write(f"Last login: {time.ctime(time.time() - 123123)} from 192.168.9.4\n")
        self.exit()

    def handle_CTRL_C(self) -> None:
        # QPot: ^C while connecting stops the wait as well
        timer = getattr(self, "qpot_timer", None)
        if timer is not None and timer.active():
            timer.cancel()
        self.qpot_timer = None
        HoneyPotCommand.handle_CTRL_C(self)

    def lineReceived(self, line: str) -> None:
        if getattr(self, "qpot_timer", None) is not None:
            # QPot: typed while ssh connects: the shell reads it after ssh gave up
            HoneyPotCommand.lineReceived(self, line)
            return
        self._log.info("INPUT (ssh): {line}", line=line)
        # QPot: the answer and the password typed at ssh's prompts are the attacker's input, logged
        #   as such: a stolen password typed here is seen as one typed at the shell
        self.protocol.events.dispatch(
            "cowrie.command.input",
            "INPUT (%(realm)s): %(input)s",
            realm="ssh",
            input=line,
        )
        if len(self.callbacks):
            self.callbacks.pop(0)(line)


commands["/usr/bin/ssh"] = Command_ssh
commands["ssh"] = Command_ssh


# QPot: scp and sftp of OpenSSH's client. Cowrie had only the server side of scp (scp -t / -f, what an
#   upload into the honeypot runs), so `scp -i key file user@host:` waited for scp's protocol on the
#   terminal, and sftp was "Exec format error". Their options are read as OpenSSH's getopt reads them,
#   the keys they would offer are logged as ssh's are, and the connection ends as the persona's network
#   has it (the bait's internal hosts and private networks time out, the machine itself refuses other
#   ports than its sshd's): OpenSSH's messages and exit status. A host that answers asks for its host key
#   and a password, and refuses the password: nothing is transferred, nothing reaches the network.
try:
    from cowrie.commands.scp import Command_scp as QpotScpServer
except ImportError:  # outside Cowrie (the tests' harness)
    QpotScpServer = HoneyPotCommand

QPOT_SCP_OPTIONS = {(9, 0): "12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:X:",
                    (8, 0): "12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:",
                    (0, 0): "dfl:prtvBCc:i:P:q12346S:o:F:"}
QPOT_SFTP_OPTIONS = {(9, 0): "1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:X:",
                     (8, 0): "1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:",
                     (0, 0): "1246afhpqrvCc:D:i:l:o:s:S:b:B:F:P:R:"}
QPOT_SCP_USAGE = {
    (9, 0): ("usage: scp [-346ABCOpqRrsTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n"
             "           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n"
             "           [-P port] [-S program] [-X sftp_option] source ... target\n"),
    (8, 0): ("usage: scp [-346ABCOpqRrsTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n"
             "           [-i identity_file] [-J destination] [-l limit]\n"
             "           [-o ssh_option] [-P port] [-S program] source ... target\n"),
    (0, 0): ("usage: scp [-12346BCpqrv] [-c cipher] [-F ssh_config] [-i identity_file]\n"
             "           [-l limit] [-o ssh_option] [-P port] [-S program]\n"
             "           [[user@]host1:]file1 ... [[user@]host2:]file2\n"),
}
QPOT_SFTP_USAGE = {
    (9, 0): ("usage: sftp [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n"
             "          [-D sftp_server_command] [-F ssh_config] [-i identity_file]\n"
             "          [-J destination] [-l limit] [-o ssh_option] [-P port]\n"
             "          [-R num_requests] [-S program] [-s subsystem | sftp_server]\n"
             "          [-X sftp_option] destination\n"),
    (8, 0): ("usage: sftp [-46aCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n"
             "          [-D sftp_server_path] [-F ssh_config] [-i identity_file]\n"
             "          [-J destination] [-l limit] [-o ssh_option] [-P port]\n"
             "          [-R num_requests] [-S program] [-s subsystem | sftp_server]\n"
             "          destination\n"),
    (0, 0): ("usage: sftp [-1246aCfpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n"
             "          [-D sftp_server_path] [-F ssh_config] [-i identity_file] [-l limit]\n"
             "          [-o ssh_option] [-P port] [-R num_requests] [-S program]\n"
             "          [-s subsystem | sftp_server] host\n"
             "       sftp [user@]host[:file ...]\n"
             "       sftp [user@]host[:dir[/]]\n"
             "       sftp -b batchfile [user@]host\n"),
}
# an -o value or a config line longer than this is no option ssh takes
QPOT_MAX_OPTION = 4096


def qpot_openssh_version() -> tuple[int, int]:
    """(major, minor) of the persona's OpenSSH ([shell] ssh_version), (7, 4) for any other client."""
    found = re.match(r"OpenSSH_(\d{1,2})\.(\d{1,2})", CowrieConfig.get("shell", "ssh_version", fallback="") or "")
    return (int(found.group(1)), int(found.group(2))) if found else (7, 4)


def qpot_by_version(table: dict, version: tuple[int, int]):
    return next(table[since] for since in sorted(table, reverse=True) if version >= since)


def qpot_x_option(value: str) -> str | None:
    """The fatal error -X value gets from scp and sftp (9.2 to 10.0: buffer= takes scan_scaled's 1 to
    256 KiB, nrequests= strtonum's 1 to 262144), None for a value they take."""
    if value.startswith("buffer="):
        text = value[7:]
        found = re.fullmatch(r"([0-9]{1,30})(?:\.([0-9]{1,30}))?([BKMGTPEbkmgtpe]?)", text)
        if found is None:
            return f'Invalid buffer size "{text[:256]}": Invalid argument'
        scale = 1024 ** "BKMGTPE".index(found.group(3).upper()) if found.group(3) else 1
        number = int(found.group(1)) * scale + (int(found.group(2)) * scale // 10 ** len(found.group(2))
                                                if found.group(2) else 0)
        if number > 2 ** 63 - 1:
            return f'Invalid buffer size "{text}": Numerical result out of range'
        if number <= 0 or number > 256 * 1024:
            return f'Invalid buffer size "{text}": Invalid argument'
        return None
    if value.startswith("nrequests="):
        text = value[10:]
        if not re.fullmatch(r"[+-]?[0-9]{1,30}", text):
            return f'Invalid number of requests "{text[:256]}": invalid'
        number = int(text)
        if number < 1:
            return f'Invalid number of requests "{text}": too small'
        if number > 256 * 1024:
            return f'Invalid number of requests "{text}": too large'
        return None
    return "Invalid -X option"


def qpot_split_option(text: str) -> tuple[str, str]:
    """(keyword in lower case, value) of an -o option or a config line: the keyword ends at a blank or
    '=', then blanks, at most one '=', blanks (linear: no regex tries the splits of a run of blanks)."""
    text = text[:QPOT_MAX_OPTION].strip()
    i = 0
    while i < len(text) and text[i] not in " \t=":
        i += 1
    key, rest = text[:i], text[i:].lstrip(" \t")
    if rest.startswith("="):
        rest = rest[1:].lstrip(" \t")
    return key.lower(), rest.strip().strip('"')


def qpot_host_matches(patterns: str, host: str) -> bool:
    pats = patterns.lower().split()[:64]
    name = host.lower()
    return (any(fnmatch.fnmatchcase(name, p) for p in pats if not p.startswith("!"))
            and not any(fnmatch.fnmatchcase(name, p[1:]) for p in pats if p.startswith("!")))


class QpotSSHTransfer(QpotSSHClient):
    """scp and sftp: the connection to the remote host, as OpenSSH's client makes it."""

    qpot_port_opt = "-P"
    qpot_timer = None
    qpot_options: dict = {}
    qpot_answer = None

    def qpot_version(self) -> tuple[int, int]:
        return qpot_openssh_version()

    def qpot_usage_error(self, text: str) -> None:
        if text:
            self.errorWrite(text + "\r\n")
        table = QPOT_SCP_USAGE if self.qpot_program == "scp" else QPOT_SFTP_USAGE
        self.errorWrite(qpot_by_version(table, self.qpot_version()))
        self.exit(1)

    def qpot_getopt(self) -> tuple[list, list] | None:
        table = QPOT_SCP_OPTIONS if self.qpot_program == "scp" else QPOT_SFTP_OPTIONS
        prefix = "scp: " if self.qpot_program == "scp" else ""
        try:
            parsed = getopt.getopt(self.args, qpot_by_version(table, self.qpot_version()))
        except getopt.GetoptError as err:
            if "requires argument" in err.msg:
                self.qpot_usage_error(f"{prefix}option requires an argument -- {err.opt}")
            else:
                self.qpot_usage_error(f"{prefix}unknown option -- {err.opt}")
            return None
        for opt, value in parsed[0]:
            problem = qpot_x_option(value) if opt == "-X" else None
            if problem:
                # fatal() of scp.c and sftp.c (9.2 to 10.0): its message, status 255
                self.errorWrite(f"{prefix}{problem}\r\n")
                self.exit(255)
                return None
        return parsed

    def qpot_config_values(self, optlist: list, host: str) -> dict:
        """The options ssh would use for host: -o first, then the matching Host blocks of the config (-F,
        else ~/.ssh/config); the first value of a keyword wins, as in ssh_config."""
        values: dict = {}
        for opt, value in optlist:
            if opt == "-o":
                key, val = qpot_split_option(value)
                if key and val:
                    values.setdefault(key, val)
        home = self.qpot_home()
        config = next((value for opt, value in optlist if opt == "-F"), None)
        path = config if config is not None else (home + "/.ssh/config" if home else "")
        if path:
            if path.startswith("~/"):
                path = home + path[1:]
            data = self.qpot_read_small(self.fs.resolve_path(path, self.cwd))
            active = True
            for raw in (data or b"")[:65536].decode("utf-8", "replace").splitlines()[:2048]:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                key, val = qpot_split_option(line)
                if key == "host":
                    active = qpot_host_matches(val, host)
                elif key == "match":
                    active = False
                elif active and val:
                    values.setdefault(key, val)
        return values

    def qpot_connect(self, optlist: list, user: str | None, host: str) -> None:
        """Log the keys, then connect to host (an alias of the config, a name or an address)."""
        options = self.qpot_config_values(optlist, host)
        self.qpot_options = options
        self.qpot_quiet = any(opt == "-q" for opt, _ in optlist) or \
            options.get("loglevel", "").lower() in ("quiet", "fatal", "error")
        login = str(getattr(getattr(self.protocol, "user", None), "username", "") or "root")
        self.qpot_user = (user or options.get("user") or login)[:256]
        self.qpot_host = host[:256]
        port = next((value for opt, value in optlist if opt == "-P"), None) or options.get("port") or "22"
        self.qpot_port = port if port.isdigit() and len(port) <= 5 else "22"
        # HostName's %h is the host typed: both are cut first (a HostName of 2000 %h and a host of 100 KB
        #   made a 200 MB string)
        target = options.get("hostname", host)[:256].replace("%h", host[:256])[:256]
        self.qpot_log_identities(optlist, self.qpot_user, host)
        from cowrie.commands.coreutils import qpot_route

        kind, address = qpot_route(self.fs, self.protocol, target)
        if kind == "timeout":
            connect = [(opt, value) for opt, value in optlist if opt != "-P"] + [("-p", self.qpot_port)]
            timeout = options.get("connecttimeout")
            if timeout and timeout.isdigit() and not any(
                    opt == "-o" and qpot_split_option(value)[0] == "connecttimeout" for opt, value in optlist):
                connect.append(("-o", f"ConnectTimeout={timeout}"))
            self.qpot_unreachable(address, connect)
            return
        if kind == "refused" and self.qpot_port != "22":
            if not self.qpot_quiet:
                self.errorWrite(f"ssh: connect to host {address} port {self.qpot_port}: Connection refused\r\n")
            self.qpot_closed()
            return
        if address is None:
            # a name: the address ssh shows for it, as Cowrie's ssh makes one up
            digest = hashlib.md5(target.encode()).hexdigest()  # noqa: S324 - not a security use
            address = ".".join(str(int(digest[i:i + 2], 16)) for i in range(0, 8, 2))
        self.qpot_address = address
        self.qpot_target = target
        self.qpot_host_key()

    def qpot_timed_out(self, address: str, port: str) -> None:
        self.qpot_timer = None
        if not self.qpot_quiet:
            self.errorWrite(f"ssh: connect to host {address} port {port}: Connection timed out\r\n")
        self.qpot_closed()

    def qpot_yes(self, key: str) -> bool:
        return self.qpot_options.get(key, "").lower() in ("yes", "true")

    def qpot_host_key(self) -> None:
        """The remote's host key: added without a word with StrictHostKeyChecking no, refused in batch
        mode, else asked about."""
        strict = self.qpot_options.get("stricthostkeychecking", "ask").lower()
        if strict in ("no", "off", "accept-new"):
            self.qpot_added()
            return
        if self.qpot_yes("batchmode") or strict in ("yes", "true"):
            self.errorWrite("Host key verification failed.\r\n")
            self.qpot_closed()
            return
        version = self.qpot_version()
        blob = hashlib.sha256(f"qpot-host-key|{self.qpot_target}".encode()).digest()
        sha = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        kind = "ED25519" if version >= (8, 5) else "ECDSA"
        text = f"The authenticity of host '{self.qpot_host} ({self.qpot_address})' can't be established.\r\n"
        text += f"{kind} key fingerprint is SHA256:{sha}.\r\n"
        if version < (7, 5):
            md5 = ":".join(f"{b:02x}" for b in hashlib.md5(blob).digest())  # noqa: S324 - the format shown
            text += f"{kind} key fingerprint is MD5:{md5}.\r\n"
        if version >= (8, 6):
            text += "This key is not known by any other names.\r\n"
        text += "Are you sure you want to continue connecting (yes/no" + (
            "/[fingerprint])? " if version >= (8, 0) else ")? ")
        self.errorWrite(text)
        self.qpot_answer = self.qpot_host_answer
        self.qpot_fingerprint = f"SHA256:{sha}"

    def qpot_host_answer(self, line: str) -> None:
        answer = line.strip().lower()
        if answer in ("yes", self.qpot_fingerprint.lower()):
            self.qpot_added()
        elif answer == "no":
            self.errorWrite("Host key verification failed.\r\n")
            self.qpot_closed()
        else:
            self.errorWrite("Please type 'yes', 'no' or the fingerprint: " if self.qpot_version() >= (8, 0)
                            else "Please type 'yes' or 'no': ")

    def qpot_added(self) -> None:
        if not self.qpot_quiet:
            kind = "ED25519" if self.qpot_version() >= (8, 5) else "ECDSA"
            name = self.qpot_host if self.qpot_version() >= (8, 5) or self.qpot_host == self.qpot_address \
                else f"{self.qpot_host},{self.qpot_address}"
            self.errorWrite(f"Warning: Permanently added '{name}' ({kind}) to the list of known hosts.\r\n")
        self.qpot_attempts = 0
        self.qpot_password()

    def qpot_password(self) -> None:
        """The password prompt (NumberOfPasswordPrompts tries, 3), none in batch mode; every password is
        refused."""
        prompts = self.qpot_options.get("numberofpasswordprompts", "3")
        limit = int(prompts) if prompts.isdigit() and len(prompts) <= 2 else 3
        if self.qpot_yes("batchmode") or self.qpot_attempts >= limit:
            self.protocol.password_input = False
            self.errorWrite(f"{self.qpot_user}@{self.qpot_host}: Permission denied (publickey,password).\r\n")
            self.qpot_closed()
            return
        if self.qpot_attempts:
            self.errorWrite("Permission denied, please try again.\r\n")
        self.errorWrite(f"{self.qpot_user}@{self.qpot_host}'s password: ")
        self.protocol.password_input = True
        self.qpot_answer = self.qpot_password_typed

    def qpot_password_typed(self, line: str) -> None:
        self.qpot_attempts += 1
        # the Enter's new line is the terminal's (the protocol writes it), as readpassphrase writes one;
        #   as a wrong password takes its time on the server
        self.qpot_timer = self.callLater(2, self.qpot_password_refused)

    def qpot_password_refused(self) -> None:
        self.qpot_timer = None
        self.qpot_password()

    def qpot_closed(self) -> None:  # pragma: no cover - each program has its own
        self.exit(255)

    def lineReceived(self, line: str) -> None:
        answer = self.qpot_answer
        if answer is None or getattr(self, "qpot_timer", None) is not None:
            # typed while connecting: the shell reads it afterwards
            HoneyPotCommand.lineReceived(self, line)
            return
        self.qpot_answer = None
        # the answers and passwords typed at the prompts are the attacker's input, logged as ssh's are
        self.protocol.events.dispatch(
            "cowrie.command.input",
            "INPUT (%(realm)s): %(input)s",
            realm=self.qpot_program,
            input=line,
        )
        answer(line)

    def handle_CTRL_C(self) -> None:
        timer = getattr(self, "qpot_timer", None)
        if timer is not None and timer.active():
            timer.cancel()
        self.qpot_timer = None
        self.protocol.password_input = False
        HoneyPotCommand.handle_CTRL_C(self)


def qpot_remote(operand: str) -> tuple[str | None, str, str] | None:
    """(user, host, path) of a remote operand of scp ([user@]host:path, [user@][v6]:path, scp://...),
    None for a local one (no colon before the first slash)."""
    if operand.startswith("scp://"):
        rest = operand[6:]
        authority, _, path = rest.partition("/")
        user, at, hostport = authority.rpartition("@")
        host = hostport.rsplit(":", 1)[0] if hostport.count(":") == 1 else hostport
        return (user if at else None), host.strip("[]"), "/" + path
    if operand.startswith("["):
        end = operand.find("]:")
        return (None, operand[1:end], operand[end + 2:]) if end > 0 else None
    colon = operand.find(":")
    slash = operand.find("/")
    if colon <= 0 or (0 <= slash < colon):
        return None
    login, path = operand[:colon], operand[colon + 1:]
    user, at, host = login.rpartition("@")
    if not host:
        return None
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return (user if at else None), host, path


class Command_scp(QpotSSHTransfer, QpotScpServer):
    """scp: OpenSSH's client; scp -t / -f (the remote end of a transfer into the honeypot) stays
    Cowrie's."""

    qpot_program = "scp"
    qpot_server = False

    def start(self) -> None:
        parsed = self.qpot_getopt()
        if parsed is None:
            return
        optlist, operands = parsed
        if any(opt in ("-t", "-f") for opt, _ in optlist):
            self.qpot_server = True
            QpotScpServer.start(self)
            return
        if len(operands) < 2:
            self.qpot_usage_error("")
            return
        self.qpot_legacy = self.qpot_version() < (9, 0) or any(opt == "-O" for opt, _ in optlist)
        remotes = [(operand, qpot_remote(operand)) for operand in operands[:1024]]
        remote = next((found for _, found in remotes if found is not None), None)
        if remote is None:
            self.qpot_local_copy(optlist, operands)
            return
        if not self.qpot_legacy and remotes[-1][1] is not None:
            # an upload in SFTP mode: the local files are looked at before the connection
            recursive = any(opt == "-r" for opt, _ in optlist)
            for operand, found in remotes[:-1]:
                if found is not None:
                    continue
                path = self.fs.resolve_path(operand, self.cwd)
                if not self.fs.exists(path):
                    self.errorWrite(f'scp: stat local "{operand}": No such file or directory\r\n')
                    self.exit(255)
                    return
                if self.fs.isdir(path) and not recursive:
                    self.errorWrite(f'scp: omitting directory "{operand}"\r\n')
        self.qpot_connect(optlist, remote[0], remote[1])

    def qpot_local_copy(self, optlist: list, operands: list[str]) -> None:
        """Both ends local: scp runs cp (cp -r, cp -p for -r, -p)."""
        words = ["cp"] + [f"-{opt[1]}" for opt, _ in optlist if opt in ("-r", "-p")] + ["--"] + operands
        cmdclass = self.protocol.getCommand("cp", self.environ.get("PATH", "").split(":"), self.cwd)
        if not cmdclass:
            self.exit(1)
            return
        from cowrie.shell.pipe import PipeProtocol

        pp = PipeProtocol(self.protocol, cmdclass, words[1:], self.input_data, self.pp.targets,
                          cwd=self.cwd, user=self.user)
        pp.stdin_from_pipe = self.pp.stdin_from_pipe
        self.exec_command(pp, cmdclass, *words[1:])

    def qpot_closed(self) -> None:
        if self.qpot_legacy:
            self.errorWrite("lost connection\n")
            self.exit(1)
            return
        self.errorWrite("scp: Connection closed\r\n")
        self.exit(255)

    def lineReceived(self, line: str) -> None:
        if self.qpot_server:
            QpotScpServer.lineReceived(self, line)
            return
        QpotSSHTransfer.lineReceived(self, line)

    def eofReceived(self) -> None:
        if self.qpot_server:
            QpotScpServer.eofReceived(self)
            return
        HoneyPotCommand.eofReceived(self)

    def handle_CTRL_C(self) -> None:
        if self.qpot_server:
            QpotScpServer.handle_CTRL_C(self)
            return
        QpotSSHTransfer.handle_CTRL_C(self)


class Command_sftp(QpotSSHTransfer):
    """sftp: OpenSSH's client."""

    qpot_program = "sftp"
    qpot_batch = False
    qpot_optlist: list = []

    def start(self) -> None:
        parsed = self.qpot_getopt()
        if parsed is None:
            return
        optlist, operands = parsed
        if len(operands) != 1:
            self.qpot_usage_error("")
            return
        self.qpot_batch = any(opt == "-b" for opt, _ in optlist)
        self.qpot_optlist = optlist
        destination = operands[0]
        if destination.startswith("sftp://"):
            found = qpot_remote("scp://" + destination[7:])
            user, host = (found[0], found[1]) if found else (None, destination)
        else:
            user, at, host = destination.rpartition("@")
            user = user if at else None
            if host.startswith("["):
                host = host[1:host.find("]")] if "]" in host else host[1:]
            else:
                host = host.split(":", 1)[0]
        self.qpot_connect(optlist, user, host)

    def qpot_closed(self) -> None:
        # sftp.c's sigchld_handler (from 8.x; from 9.x not with -q or -b) when ssh dies, then get_msg of
        #   sftp-client.c reading the end of the pipe; 7.4 has no handler
        version = self.qpot_version()
        quiet = self.qpot_batch or any(opt == "-q" for opt, _ in self.qpot_optlist)
        if version >= (8, 0) and (version < (9, 0) or not quiet):
            self.errorWrite("\rConnection closed.  \n")
        self.errorWrite("Connection closed\r\n")
        self.exit(255)


commands["/usr/bin/scp"] = Command_scp
commands["scp"] = Command_scp
commands["/usr/bin/sftp"] = Command_sftp
