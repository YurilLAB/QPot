# SPDX-FileCopyrightText: 2009-2012 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause


from __future__ import annotations

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

    def qpot_unreachable(self, address: str, optlist: list[tuple[str, str]]) -> None:
        """Connect to an address that never answers: ConnectTimeout of -o, else of the user's
        ~/.ssh/config, else the kernel's; then ssh's message and its status 255."""
        port, timeout = "22", None
        for opt, value in optlist:
            if opt == "-p" and value.isdigit() and len(value) <= 5:
                port = value
            elif opt == "-o":
                found = re.fullmatch(r"(?i)\s*connecttimeout\s*[ =]\s*([0-9]{1,4})\s*", value)
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
        found = re.search(rb"(?im)^[ \t]*ConnectTimeout[ \t]*[ \t=][ \t]*([0-9]{1,4})[ \t]*$", data)
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
