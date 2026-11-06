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


class Command_ssh(HoneyPotCommand):
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
                input=" ".join(["ssh"] + list(self.args))[:4096],
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
            timeout = self.qpot_config_timeout()
        if not timeout or timeout > self.QPOT_KERNEL_TIMEOUT:
            timeout = self.QPOT_KERNEL_TIMEOUT
        self.qpot_timer = self.callLater(timeout, self.qpot_timed_out, address, port)

    def qpot_config_timeout(self) -> int | None:
        """ConnectTimeout of the session user's ~/.ssh/config (its first one), None without one."""
        home = str((getattr(self, "environ", None) or {}).get("HOME", "") or "")
        if not home.startswith("/"):
            return None
        try:
            data = self.fs.file_contents(home.rstrip("/") + "/.ssh/config")[:65536]
        except Exception:  # noqa: BLE001 - no config, a folder, a broken link: no timeout of its own
            return None
        # one way to match the separator, as for -o: the config is the attacker's to write
        found = re.search(rb"(?im)^[ \t]*ConnectTimeout(?:[ \t]*=[ \t]*|[ \t]+)([0-9]{1,4})[ \t]*$", data)
        return int(found.group(1)) if found else None

    def qpot_timed_out(self, address: str, port: str) -> None:
        self.qpot_timer = None
        self.errorWrite(f"ssh: connect to host {address} port {port}: Connection timed out\n")
        self.exit(255)

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
