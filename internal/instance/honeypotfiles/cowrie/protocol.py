# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import functools
import hashlib
import math
import random
import re
import socket
import time
from importlib import import_module
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from twisted.conch import recvline
from twisted.conch.insults import insults
from twisted.internet.protocol import connectionDone
from twisted.logger import Logger
from twisted.protocols.policies import TimeoutMixin

import cowrie.commands
from cowrie.core.config import CowrieConfig
from cowrie.core.resources import read_data_bytes
from cowrie.shell import command, fs, honeypot


@functools.cache
def tpot_skip_python_commands() -> frozenset[str]:
    """T-Pot: the commands of [shell] skip_python_commands, parsed once (the
    config does not change while Cowrie runs, getCommand runs for every word)."""
    return frozenset(
        name.strip()
        for name in CowrieConfig.get("shell", "skip_python_commands", fallback="").split(",")
        if name.strip()
    )


@functools.cache
def tpot_builtins() -> frozenset[str] | None:
    """T-Pot: the builtins of the persona's shell ([shell] builtins) on a firmware whose programs
    are only those of its image: a Python command answers a bare name only as one of them or as a
    program found on PATH. None without the key (upstream: every Python command answers)."""
    value = CowrieConfig.get("shell", "builtins", fallback=None)
    if value is None:
        return None
    return frozenset(name.strip() for name in value.split(",") if name.strip())
from cowrie.shell.script import run_script_file

if TYPE_CHECKING:
    from twisted.python import failure

    from cowrie.core.events import EventLog


@functools.cache
def boot_offset() -> float:
    """Seconds between the emulated machine's boot and cowrie's start, from
    [honeypot] boot_offset. Unset, it is chosen once per process between one
    and ninety days, so a restarted honeypot does not report seconds of
    uptime and installs do not share one value."""
    configured = CowrieConfig.getint("honeypot", "boot_offset", fallback=-1)
    if configured >= 0:
        return float(configured)
    return float(random.randint(86400, 90 * 86400))


def tpot_exec_denied(prefix: str, name: str) -> tuple[str, int]:
    """T-Pot: the error and status of a file without an x bit: "x: can't execute" of BusyBox msh, else
    bash's "Permission denied" (both 126)."""
    if CowrieConfig.get("shell", "not_found_style", fallback="bash") == "msh":
        return f"{name}: can't execute\n", 126
    return f"{prefix}{name}: Permission denied\n", 126


import collections.abc


class TpotCommands(collections.abc.MutableMapping):
    """T-Pot: the commands of one connection. Cowrie's commands (the dict every session reads) stay as they are;
    what the connection's package installs add is in added, what its removals take away in removed. Every
    protocol of a connection (its channels) has its view on the same added and removed (tpot_commands)."""

    def __init__(self, shared, added=None, removed=None) -> None:
        self.tpot_shared = shared
        self.tpot_added = {} if added is None else added
        self.tpot_removed = set() if removed is None else removed

    def __getitem__(self, key):
        if key in self.tpot_added:
            return self.tpot_added[key]
        if key in self.tpot_removed:
            raise KeyError(key)
        return self.tpot_shared[key]

    def __contains__(self, key) -> bool:
        return key in self.tpot_added or (key not in self.tpot_removed and key in self.tpot_shared)

    def __setitem__(self, key, value) -> None:
        self.tpot_removed.discard(key)
        if key in self.tpot_shared and self.tpot_shared[key] is value:
            self.tpot_added.pop(key, None)   # Cowrie's own command again
        else:
            self.tpot_added[key] = value

    def __delitem__(self, key) -> None:
        if key not in self:
            raise KeyError(key)
        self.tpot_added.pop(key, None)
        if key in self.tpot_shared:
            self.tpot_removed.add(key)

    def __iter__(self):
        yield from list(self.tpot_added)
        for key in list(self.tpot_shared):
            if key not in self.tpot_added and key not in self.tpot_removed:
                yield key

    def __len__(self) -> int:
        return sum(1 for _ in self)

    def tpot_restore(self, program: str) -> bool:
        """Cowrie's own commands of the name of program that a removal took away answer again (a reinstall);
        True if Cowrie has one of them."""
        name = program.rsplit("/", 1)[-1]
        back = {key for key in self.tpot_removed if key.rsplit("/", 1)[-1] == name}
        self.tpot_removed.difference_update(back)
        return any(key in self.tpot_shared and key not in self.tpot_added for key in back)


def tpot_commands(avatar, shared) -> TpotCommands:
    """The commands of the connection of avatar (protocol.user, which every channel of the connection shares, as
    the time budget of shell/command.py): its own added and removed on Cowrie's commands."""
    overlay = getattr(avatar, "tpot_commands", None)
    if not (isinstance(overlay, tuple) and len(overlay) == 2):
        overlay = ({}, set())
        try:
            avatar.tpot_commands = overlay
        except (AttributeError, TypeError):
            pass
    return TpotCommands(shared, *overlay)


class HoneyPotBaseProtocol(insults.TerminalProtocol, TimeoutMixin):
    """
    Base protocol for interactive and non-interactive use
    """

    _log = Logger()

    # The session's event emitter, set from the transport in connectionMade.
    events: EventLog

    # True once end_process() has run. Class-level so it holds even for
    # instances created without __init__ (tests).
    _process_ended: bool = False

    commands: ClassVar[dict] = {}
    for c in cowrie.commands.command_modules:
        try:
            module = import_module(f"cowrie.commands.{c}")
            commands.update(module.commands)
        except ImportError:
            _log.failure("Failed to import command {cmd}", cmd=c)

    def __init__(self, avatar):
        self.user = avatar
        # T-Pot: the commands of this connection on Cowrie's (TpotCommands)
        self.commands = tpot_commands(avatar, HoneyPotBaseProtocol.commands)
        self.environ = avatar.environ
        self.hostname: str = self.user.server.hostname
        self.fs = self.user.server.fs
        # The stdio wiring being handed to the command now starting, which the
        # command keeps as its own (HoneyPotCommand.pp). It stays set to the
        # most recently started command's afterwards, which is what a capture
        # shell reads to collect a command's captured output. Only ever one at
        # a time: commands run strictly in sequence.
        self.pp = None
        self.logintime: float
        self.realClientIP: str
        self.realClientPort: int
        self.kippoIP: str
        self.kippoIPv6: str = ""
        self.clientIP: str
        self.sessionno: int
        self.factory = None

        self.data = None
        self.password_input = False
        self.cmdstack = []

    def getProtoTransport(self):
        """
        Due to protocol nesting differences, we need provide how we grab
        the proper transport to access underlying SSH information. Meant to be
        overridden for other protocols.
        """
        return self.terminal.transport.session.conn.transport

    def connectionMade(self) -> None:
        pt = self.getProtoTransport()

        self.factory = pt.factory
        # The session's event emitter, owned by the transport. Kept across
        # connectionLost so a command's deferred callback that outlives the
        # session (a download completing after disconnect) can still emit an
        # attributed, late-flagged event.
        self.events = pt.events
        self.sessionno = pt.transport.sessionno
        self.realClientIP = pt.transport.getPeer().host
        self.realClientPort = pt.transport.getPeer().port
        self.logintime = time.time()

        self.events.dispatch("cowrie.session.params", "", arch=self.user.server.arch)
        self.fs.generated_files["/proc/uptime"] = self.proc_uptime
        self.fs.generated_files["/proc/loadavg"] = self.proc_loadavg
        # T-Pot: the PIDs of the session (one counter for all sessions) and its processes in /proc
        try:
            from cowrie.commands.base import tpot_proc_session

            tpot_proc_session(self)
        except Exception:  # noqa: BLE001 - the session goes on with the /proc of the persona's tree
            self._log.failure("T-Pot: /proc of the session")

        idle_timeout = CowrieConfig.getint("honeypot", "idle_timeout", fallback=180)
        self.setTimeout(idle_timeout)

        # Source IP of client in user visible reports (can be fake or real)
        self.clientIP = CowrieConfig.get(
            "honeypot", "fake_addr", fallback=self.realClientIP
        )

        # Source IP of server in user visible reports (can be fake or real)
        if CowrieConfig.has_option("honeypot", "internet_facing_ip"):
            self.kippoIP = CowrieConfig.get("honeypot", "internet_facing_ip")
        else:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect(("8.8.8.8", 80))
                    self.kippoIP = s.getsockname()[0]
            except Exception:
                self.kippoIP = "192.168.0.1"

        # IPv6 GUA of server in user visible reports (can be fake or real)
        if CowrieConfig.has_option("honeypot", "internet_facing_ipv6"):
            self.kippoIPv6 = CowrieConfig.get("honeypot", "internet_facing_ipv6")
        else:
            try:
                with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
                    s.connect(
                        ("2001:4860:4860::8888", 80)
                    )  # NOSONAR - probe target to detect host GUA, not a secret
                    addr = s.getsockname()[0]
                    # Only use GUA, not link-local
                    self.kippoIPv6 = addr if not addr.lower().startswith("fe80") else ""
            except Exception:
                self.kippoIPv6 = ""

    def end_process(self, code: int) -> None:
        """
        End the session's process with exit status ``code``, once.

        Every path that ends the process comes through here: the exec queue
        draining, ``exit``, ``exec``, EOF, a command finishing with no shell
        left, and the idle timeout. Only the first call reaches the channel.
        A later one would report a second, possibly different, exit status:
        a channel EOF that arrives after an exec command already finished
        reaches the finished shell still on the cmdstack, and input queued
        behind ``exit`` is still read before a telnet connection closes.
        """
        if self._process_ended:
            return
        self._process_ended = True
        terminal = self.terminal
        if terminal is None or terminal.transport is None:
            # The client already disconnected: there is no channel to tell.
            return
        terminal.transport.processEnded(command.process_status(code))

    def timeoutConnection(self) -> None:
        """
        this logs out when connection times out
        """
        self.end_process(1)

    def connectionLost(self, reason: failure.Failure = connectionDone) -> None:
        """
        Called when the connection is shut down.
        Clear any circular references here, and any external references to
        this Protocol. The connection has been closed.
        """
        self.setTimeout(None)
        insults.TerminalProtocol.connectionLost(self, reason)
        self.terminal = None  # (this should be done by super above)
        for cmd in self.cmdstack:
            if isinstance(cmd, command.HoneyPotCommand):
                cmd.connectionLost()
        self.cmdstack = []
        self.fs = None
        self.pp = None
        self.user = None
        self.environ = None

    def txtcmd(self, txt: bytes) -> object:
        class Command_txtcmd(command.HoneyPotCommand):
            def call(self):
                self.writeBytes(txt)

        return Command_txtcmd

    def scriptcmd(self, path: str, name: str) -> object:
        """Return a command class that executes a shell script from the virtual filesystem."""

        class Command_scriptcmd(command.HoneyPotCommand):
            def call(self):
                # Running ./file or /path/file: the kernel rejects a binary with
                # ENOEXEC ("cannot execute binary file"); a shell script is run
                # through the parser (the shebang is parsed as a comment).
                prefix = self.shell.error_prefix()
                # exec() refuses a file without an applicable execute bit
                # (EACCES) before it looks at the contents.
                if not self.fs.is_executable(path, self.user["uid"], self.user["gid"]):
                    # T-Pot: BusyBox msh says "can't execute" (tpot_exec_denied)
                    message, self.exit_code = tpot_exec_denied(prefix, name)
                    self.errorWrite(message)
                    return
                run_script_file(
                    self,
                    path,
                    name=name,
                    args=self.args,
                    not_found_message=f"{prefix}{name}: No such file or directory\n",
                    binary_message=(
                        f"{prefix}{name}: cannot execute binary file: "
                        "Exec format error\n"
                    ),
                )

        return Command_scriptcmd

    def isCommand(self, cmd):
        """
        Check if cmd (the argument of a command) is a command, too.
        """
        return True if cmd in self.commands else False

    def getCommand(self, cmd, paths, cwd):
        if not cmd.strip():
            return None
        path = None
        skip_python_commands = tpot_skip_python_commands()
        # the programs apt / dnf installed in this session ({name: version}) answer
        installed = getattr(self, "tpot_installed", None) or {}

        def skip_python_command(name):
            if Path(name).name in installed:
                return False
            return name in skip_python_commands or Path(name).name in skip_python_commands

        builtins = tpot_builtins()
        if cmd in self.commands and not skip_python_command(cmd) and (builtins is None or cmd in builtins):
            return self.commands[cmd]
        # T-Pot: a builtin of the firmware's shell that Cowrie has no command of answers with the
        # txtcmd of its name (bin/<name>), without a program on PATH
        if builtins is not None and cmd in builtins and "/" not in cmd:
            txtcmds_dir = CowrieConfig.get("honeypot", "txtcmds_path", fallback="")
            builtin_path = Path(txtcmds_dir) / "bin" / cmd if txtcmds_dir else None
            if builtin_path is not None and builtin_path.is_file():
                return self.txtcmd(builtin_path.read_bytes())
        if cmd[0] in (".", "/"):
            path = self.fs.resolve_path(cmd, cwd)
            if not self.fs.exists(path):
                return None
        else:
            for i in [f"{self.fs.resolve_path(x, cwd)}/{cmd}" for x in paths if x]:
                if self.fs.exists(i):
                    path = i
                    break

        if path is None:
            return None

        # T-Pot: the spellings of path through the directory links of the tree
        # (/bin -> usr/bin): `df` finds /usr/bin/df on PATH, the txtcmd is bin/df.
        import posixpath

        def tpot_real(name):
            parts = [part for part in name.split("/") if part]
            real = []
            for part in parts[:-1]:
                node = self.fs.getfile("/" + "/".join(real + [part]), follow_symlinks=False)
                if node is not None and node[fs.A_TYPE] == fs.T_LINK and node[fs.A_TARGET]:
                    target = node[fs.A_TARGET]
                    base = "" if target.startswith("/") else "/".join(real)
                    real = [x for x in posixpath.normpath(f"/{base}/{target}").split("/") if x]
                else:
                    real.append(part)
            return "/" + "/".join(real + parts[-1:])

        real = tpot_real(path)
        spellings = [path, real]
        for link in self.fs.fs[fs.A_CONTENTS]:
            target = "/" + "/".join(x for x in (link[fs.A_TARGET] or "").split("/") if x)
            if link[fs.A_TYPE] == fs.T_LINK and target != "/" and real.startswith(target + "/"):
                spellings.append("/" + link[fs.A_NAME] + real[len(target):])
        spellings = list(dict.fromkeys(spellings))
        # a program apt installed in this session that neither a txtcmd of the persona nor Cowrie's
        # command of its name answers (the persona does not have it)
        faked = getattr(self, "tpot_faked", None) or {}
        for spelling in spellings:
            if spelling in faked:
                return faked[spelling]

        relpath = path.lstrip("/")
        txtcmds_path = CowrieConfig.get("honeypot", "txtcmds_path", fallback="")
        if txtcmds_path:
            operator_path = Path(txtcmds_path) / relpath
            if operator_path.is_file():
                return self.txtcmd(operator_path.read_bytes())
        if txtcmds_path:
            for spelling in spellings[1:]:
                operator_path = Path(txtcmds_path) / spelling.lstrip("/")
                if operator_path.is_file():
                    return self.txtcmd(operator_path.read_bytes())
        # a Python command of one of the spellings answers before the txtcmds Cowrie ships
        # (data/txtcmds/bin/df, usr/bin/top), as it answers the bare name
        for spelling in spellings:
            if spelling in self.commands and not skip_python_command(spelling):
                return self.commands[spelling]
        # T-Pot: a program of the firmware's PATH that Cowrie's Python answers by its name
        name = posixpath.basename(path)
        if builtins is not None and name in self.commands and not skip_python_command(name):
            return self.commands[name]

        try:
            binary_data = read_data_bytes("txtcmds", *relpath.split("/"))
            return self.txtcmd(binary_data)
        except FileNotFoundError:
            # No txtcmd file at this path -- including when the command resolves
            # to a directory (e.g. `/` -> empty relpath -> the txtcmds directory
            # itself), which read_data_bytes reports as FileNotFoundError on
            # every platform. Fall through so the caller reports "Is a
            # directory" instead of crashing the session.
            pass

        # (the Python commands of the spellings answered before Cowrie's txtcmds)

        if self.fs.isfile(path):
            # bash names a command typed with a slash as typed, and one found
            # through PATH by its full path.
            return self.scriptcmd(path, cmd if "/" in cmd else path)

        self._log.info("Can't find command {cmd}", cmd=cmd)
        return None

    def lineReceived(self, line: bytes) -> None:
        """
        IMPORTANT
        Before this, all data is 'bytes'. Here it converts to 'string' and
        commands work with string rather than bytes.

        Invalid UTF-8 (binary piped or pasted into the shell) becomes
        replacement characters: the line must not raise out of the protocol
        and kill the session.
        """
        string = line.decode("utf8", errors="replace")

        if self.cmdstack:
            self.cmdstack[-1].lineReceived(string)
        else:
            self._log.info("discarding input {input}", input=string)
            self.end_process(0)

    def call_command(self, pp, cmd, *args):
        """Run a command with the stdio wiring ``pp``. A command that runs
        another synchronously during ``start()`` (``su -c``, ``sh -c``, a
        nested shell, busybox) reaches back here and executes it inline."""
        self.pp = pp
        obj = cmd(self, *args)
        obj.set_input_data(pp.input_data)
        self.cmdstack.append(obj)
        obj.start()

        # Mirror ProcessProtocol.transport.closeStdin(): if the command parked
        # waiting for stdin but nothing will ever write to it, signal EOF so it
        # terminates instead of leaking on the cmdstack. Stdin is left open when
        # a live source will deliver its own EOF later: an interactive terminal,
        # or the SSH exec channel feeding the top-level command (e.g. `scp -t`,
        # whose pushed bytes arrive after the command has started). A piped
        # command reads buffered output, so it gets EOF here.
        if self.cmdstack and self.cmdstack[-1] is obj:
            parent = self.cmdstack[-2] if len(self.cmdstack) >= 2 else None
            # A child shell that inherits its parent's stdin (a pipeline's
            # first stage, a "(...)" group) is looked through to the shell
            # that owns the stdin.
            while parent is not None and getattr(parent, "inherits_stdin", False):
                index = self.cmdstack.index(parent)
                parent = self.cmdstack[index - 1] if index > 0 else None
            live_stdin = (
                not getattr(pp, "stdin_from_pipe", False)
                and parent is not None
                and (
                    getattr(parent, "interactive", False)
                    or (
                        isinstance(self, HoneyPotExecProtocol)
                        and parent is self.cmdstack[0]
                    )
                )
            )
            if not live_stdin:
                obj.eofReceived()

    def boot_time(self) -> float:
        """When the emulated machine booted: boot_offset before cowrie
        started."""
        return float(self.getProtoTransport().factory.starttime) - boot_offset()

    def uptime(self):
        """
        Uptime
        """
        return time.time() - self.boot_time()

    # T-Pot: the load of the emulated system, shared by top, uptime, w and /proc/loadavg
    TPOT_LOAD_WAVES = ((0.5, 1740.0), (0.3, 410.0), (0.15, 97.0))
    # T-Pot: the PIDs of every session of this Cowrie process, one counter on the class (it outlives a session, not
    #   a restart): the newest PID any session took and when (tpot_claim_pids, tpot_new_pid)
    TPOT_PIDS: ClassVar[dict] = {"last": 0, "at": 0.0}
    # where the kernel starts again past pid_max ([shell] pid_max; RESERVED_PIDS of kernel/pid.c)
    TPOT_PID_WRAP = 300

    def tpot_load_average(self, now: float | None = None) -> tuple[float, float, float]:
        """T-Pot: the 1, 5 and 15 minute load average. A base load ([shell] load_base) drifts in
        three slow waves (phases from the host name); the kernel's three exponential averages
        (time constants 1, 5 and 15 minutes, in closed form for a wave) smooth it, so the values
        move slowly, the 15 minute one least, and stay above zero."""
        now = time.time() if now is None else now
        try:
            base = max(0.0, float(CowrieConfig.get("shell", "load_base", fallback="0.05")))
        except ValueError:
            base = 0.05
        seed = hashlib.sha256(str(self.hostname).encode("utf-8")).digest()
        values = []
        for tau in (60.0, 300.0, 900.0):
            value = base
            for index, (share, period) in enumerate(self.TPOT_LOAD_WAVES):
                omega = 2 * math.pi / period
                phase = seed[index] / 256 * 2 * math.pi
                value += (base * share / math.hypot(1.0, omega * tau)
                          * math.sin(omega * now + phase - math.atan(omega * tau)))
            values.append(max(0.0, value))
        return values[0], values[1], values[2]

    def tpot_processes(self) -> list:
        """T-Pot: the ps list of the persona ([shell] processes); its login shell has the PID of this session's
        (tpot_login_pid, from tpot_session), the list itself stays as it is."""
        server = getattr(self.user, "server", None)
        listed = [p for p in (getattr(server, "process", None) or []) if isinstance(p, dict)]
        shell = getattr(self, "tpot_login_pid", None)
        logins = [p for p in listed if str(p.get("TTY") or "").startswith(("pts/", "tty"))
                  and "getty" not in str(p.get("COMMAND") or "")]
        if not isinstance(shell, int) or not logins or logins[-1].get("PID") == shell:
            return listed
        return [dict(p, PID=shell) if p is logins[-1] else p for p in listed]

    def tpot_pid_max(self) -> int:
        try:
            return max(1000, min(1 << 22, int(CowrieConfig.get("shell", "pid_max", fallback="4194304"))))
        except (TypeError, ValueError):
            return 1 << 22

    def tpot_claim_pids(self, wanted: int, span: int, taken=frozenset(), now: float | None = None) -> int:
        """T-Pot: the PID of the login shell of a new session, with span PIDs before it for the session's processes
        (its sshd and monitor, in.telnetd and login). The first session of this Cowrie process takes wanted (the shell
        of the ps list); a later one the PIDs after the newest any session took (TPOT_PIDS: no two sessions show one
        PID), a few more for what the system started meanwhile (one per 7 seconds, as tpot_last_pid), none of the
        list's (taken); past pid_max the count starts again above TPOT_PID_WRAP, as the kernel's."""
        now = time.time() if now is None else now
        state, span, limit = self.TPOT_PIDS, max(0, int(span)), self.tpot_pid_max()
        if not state["last"]:
            shell = int(wanted)
        else:
            gap = 2 + random.randint(0, 24) + int(max(0.0, now - state["at"]) // 7)
            shell = max(int(wanted), state["last"] + 1 + span + gap)
        for _ in range(4096):
            if shell >= limit:
                shell = self.TPOT_PID_WRAP + span + 1
            if not any(p in taken for p in range(shell - span, shell + 1)):
                break
            shell += 1
        state["last"], state["at"] = shell, now
        return shell

    def tpot_tasks(self, session: int | None = None) -> int:
        """T-Pot: the tasks of the system: the ps list, the session's processes up to the shell
        (session: sshd and its monitor, in.telnetd and login; by default those of tpot_session), the
        running command and the kernel threads ([shell] kernel_threads), as ps -e and top count them."""
        try:
            threads = max(0, CowrieConfig.getint("shell", "kernel_threads", fallback=0))
        except ValueError:
            threads = 0
        if session is None:
            session = getattr(self, "tpot_session_size", None)
        if not isinstance(session, int):
            try:
                from cowrie.commands.base import tpot_session
                session = len(tpot_session(self, str(getattr(getattr(self, "user", None), "username", "root")))["chain"])
            except Exception:  # noqa: BLE001 - without the session's processes one
                session = 1
        return len(self.tpot_processes()) + max(0, session) + 1 + threads

    def tpot_new_pid(self, count: int = 1, now: float | None = None) -> int:
        """T-Pot: the first of count new PIDs (ps, top and the commands of their pipeline): after the
        newest process, never one of an earlier command or of another session again (TPOT_PIDS)."""
        first = max(self.tpot_last_pid(now), getattr(self, "tpot_pid_used", 0) + 1, self.TPOT_PIDS["last"] + 1)
        self.tpot_pid_used = first + max(1, count) - 1
        self.TPOT_PIDS["last"] = max(self.TPOT_PIDS["last"], self.tpot_pid_used)
        return first

    def tpot_last_pid(self, now: float | None = None) -> int:
        """T-Pot: the newest PID: a few after the newest process of the ps list, more the longer
        the session runs."""
        now = time.time() if now is None else now
        pids = [p["PID"] for p in self.tpot_processes() if isinstance(p.get("PID"), int)]
        since = max(0.0, now - getattr(self, "logintime", now))
        session = getattr(self, "tpot_session_pid", None)
        newest = max(pids + ([session + 1] if isinstance(session, int) else []) or [1000])
        return max(newest + 9 + int(since // 7), getattr(self, "tpot_pid_used", 0), self.TPOT_PIDS["last"])

    def tpot_uptime_line(self, now: float | None = None) -> str:
        """T-Pot: the line of uptime and w, and of top after "top -": procps sprint_uptime
        (" 12:57:13 up 11 days,  4:22,  1 user,  load average: 0.06, 0.04, 0.01"); BusyBox
        ([shell] top_style busybox) names no users."""
        now = time.time() if now is None else now
        up = max(0, int(now - self.boot_time()))
        days, rest = divmod(up, 86400)
        hours, minutes = rest // 3600, rest % 3600 // 60
        text = f"{days} day{'s' if days != 1 else ''}, " if days else ""
        text += f"{hours:2d}:{minutes:02d}" if hours else f"{minutes} min"
        load = ", ".join(f"{value:.2f}" for value in self.tpot_load_average(now))
        clock = time.strftime("%H:%M:%S", time.localtime(now))
        if CowrieConfig.get("shell", "top_style", fallback="procps") == "busybox":
            return f" {clock} up {text},  load average: {load}"
        # an exec channel without a pty has no utmp entry: no user (procps: "%2d user%s")
        users = 0 if hasattr(self, "execcmd") and not getattr(getattr(self, "user", None), "windowSize", None) else 1
        return f" {clock} up {text},  {users} user{'' if users == 1 else 's'},  load average: {load}"

    def proc_loadavg(self) -> bytes:
        """T-Pot: /proc/loadavg: the load average of top and uptime, runnable / all tasks and the
        newest PID."""
        now = time.time()
        load = " ".join(f"{value:.2f}" for value in self.tpot_load_average(now))
        return f"{load} 1/{self.tpot_tasks()} {self.tpot_last_pid(now)}\n".encode()

    def proc_uptime(self) -> bytes:
        """/proc/uptime: seconds since boot, and idle seconds summed over the
        CPUs listed in /proc/cpuinfo, as a lightly loaded machine reports."""
        uptime = self.uptime()
        try:
            cpuinfo = self.fs.file_contents("/proc/cpuinfo")
        except (fs.FileNotFound, IsADirectoryError):
            cpuinfo = b""
        processors = [x for x in cpuinfo.splitlines() if x.startswith(b"processor")]
        cpus = max(1, len(processors))
        return f"{uptime:.2f} {uptime * cpus * 0.97:.2f}\n".encode()

    def eofReceived(self) -> None:
        """
        EOF on stdin, from a terminal CTRL-D or a closed SSH channel. Deliver it
        to the command currently reading stdin; with no command running the
        shell handles it (logout). If the cmdstack is gone, end the session.
        """
        if self.cmdstack:
            self.cmdstack[-1].eofReceived()
        else:
            self.end_process(0)


def qpot_shell_variables(shell) -> None:
    """QPot: the shell variables of the persona's bash (coreutils.qpot_bash_variables); a missing module
    or an unknown persona leaves the shell as Cowrie made it."""
    try:
        from cowrie.commands.coreutils import qpot_bash_variables

        qpot_bash_variables(shell)
    except Exception:  # noqa: BLE001 - never stop a login over it
        pass


class HoneyPotExecProtocol(HoneyPotBaseProtocol):
    _log = Logger()

    # input_data is static buffer for stdin received from remote client
    input_data = b""

    # Longest accepted stdin line in line mode, bash's per-argument limit
    # (MAX_ARG_STRLEN). Bytes beyond it are dropped so an endless
    # unterminated stream cannot grow memory without bound.
    STDIN_LINE_MAX = 131072

    def __init__(self, avatar, execcmd):
        """
        IMPORTANT
        Before this, execcmd is 'bytes'. Here it converts to 'string' and
        commands work with string rather than bytes.
        """
        # The exec command is attacker input and need not be valid UTF-8.
        # Every caller reads execcmd right after construction, so it must
        # always be set.
        self.execcmd = execcmd.decode("utf8", errors="replace")

        # When the exec'd command is a shell reading commands from the channel
        # (`ssh host bash`), stdin is delivered to the cmdstack line by line
        # instead of being buffered raw in input_data.
        self.stdin_line_mode: bool = False
        self._stdin_line = bytearray()
        self._stdin_last_cr: bool = False

        HoneyPotBaseProtocol.__init__(self, avatar)

    def connectionMade(self) -> None:
        HoneyPotBaseProtocol.connectionMade(self)
        self.setTimeout(60)
        self.cmdstack = [honeypot.HoneyPotShell(self, interactive=False)]
        # QPot: the variables bash sets for the command it runs (BASH_VERSION ...)
        qpot_shell_variables(self.cmdstack[0])
        # The parser treats newlines as statement separators, so a multi-line
        # exec payload (including loops/conditionals) is run as written.
        self.cmdstack[0].lineReceived(self.execcmd)

    def keystrokeReceived(self, keyID, modifier):
        # T-Pot: a full screen command (top, ssh -t) takes the keys of the pty
        key = getattr(self.cmdstack[-1], "tpot_key", None) if self.cmdstack else None
        if key is not None and isinstance(keyID, bytes) and key(keyID):
            return
        if not self.stdin_line_mode:
            self.input_data += keyID
            return
        if not isinstance(keyID, bytes):
            # A function key parsed from an escape sequence has no place in a
            # line-based stdin stream.
            return
        last_cr = self._stdin_last_cr
        self._stdin_last_cr = keyID == b"\r"
        if keyID == b"\n" and last_cr:
            # The \n of a \r\n pair; the \r already dispatched the line.
            return
        # Control bytes are handled as a tty would, which is only strictly
        # right when the client requested a pty; in a plain pipe they are
        # rare enough that the difference does not matter.
        if keyID in (b"\r", b"\n"):
            self._dispatch_stdin_line()
        elif keyID == b"\x04" and not self._stdin_line:
            # CTRL-D on an empty line is EOF for the shell reading stdin.
            HoneyPotBaseProtocol.eofReceived(self)
        elif keyID in (b"\x08", b"\x7f"):
            # Backspace / delete: drop the last byte of the pending line.
            del self._stdin_line[-1:]
        elif keyID == b"\x03":
            # CTRL-C: discard the pending line.
            self._stdin_line.clear()
        elif len(self._stdin_line) < self.STDIN_LINE_MAX:
            self._stdin_line += keyID

    def _dispatch_stdin_line(self) -> None:
        """Run the accumulated stdin line through the command stack."""
        line = bytes(self._stdin_line)
        self._stdin_line.clear()
        self.lineReceived(line)

    def setInsertMode(self) -> None:
        """Insert-mode toggle requested when an interactive shell resumes; an
        exec channel has no recvline editor, so there is no mode to switch."""

    def eofReceived(self) -> None:
        if self.stdin_line_mode:
            if self._stdin_line:
                # A final line without a terminator still runs, as bash does
                # when its stdin ends without a newline.
                self._dispatch_stdin_line()
            readers = [
                item for item in self.cmdstack if getattr(item, "reads_stdin", False)
            ]
            if not readers:
                # The stdin-reading shell already exited (e.g. `exit`) and
                # ended the process; nothing is left to deliver EOF to.
                return
            # The shell learns of the EOF now even when a running command
            # receives it: once that command exits, the shell has nothing
            # more to read and must finish its buffered lines, then end.
            for shell in readers:
                shell.stdin_eof = True
        HoneyPotBaseProtocol.eofReceived(self)


qpot_release_seen: list = []


def qpot_os_release(tree) -> tuple[str, tuple[int, ...]]:
    """QPot: (ID, VERSION_ID as numbers) of the persona's /etc/os-release in the emulated tree, read
    once per process (the persona does not change while it runs), ("", ()) without one."""
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


def qpot_editor() -> str:
    """QPot: the line editor of the persona's login shell: "ash" (BusyBox lineedit) or "readline" (bash)."""
    style = CowrieConfig.get("shell", "not_found_style", fallback="bash")
    return "ash" if style in ("ash", "msh") else "readline"


def qpot_bracketed_paste(tree) -> bool:
    """QPot: whether the persona's bash (5.1 and later: Ubuntu 21.04, Debian 11, RHEL 9 on) turns on
    bracketed paste around each line it reads: ESC[?2004h before the prompt, ESC[?2004l after the line
    (recorded with bash 5.2.37). CentOS 7's 4.2 and the firmware shells do not."""
    if qpot_editor() != "readline":
        return False
    os_id, version = qpot_os_release(tree)
    first = {"ubuntu": (21, 4), "debian": (11,), "raspbian": (11,), "rhel": (9,), "centos": (9,),
             "rocky": (9,), "almalinux": (9,), "fedora": (34,)}.get(os_id)
    return bool(first and version and version >= first)


@functools.cache
def tpot_history_size(root: bool) -> int:
    """T-Pot: the lines the shell's history keeps ([shell] history_size, history_size_root for
    root; parsed once), 0 for no limit. It holds at most 1000 lines whatever HISTSIZE says (EdgeOS:
    10000), which bounds the memory of a session's history."""
    value = CowrieConfig.get("shell", "history_size_root" if root else "history_size", fallback="")
    try:
        size = max(int(value), 0)
    except (TypeError, ValueError):
        return 0
    return min(size, 1000) if size else 0


@functools.cache
def tpot_history_control(root: bool) -> frozenset[str]:
    """T-Pot: what the shell's history leaves out ([shell] history_control, history_control_root
    for root; HISTCONTROL of bash, colon separated, ignoreboth for both; parsed once): ignoredups (a
    line as the one before), ignorespace (a line that starts with a space)."""
    value = CowrieConfig.get("shell", "history_control_root" if root else "history_control", fallback="")
    words = {word.strip() for word in (value or "").split(":")}
    if "ignoreboth" in words:
        words |= {"ignoredups", "ignorespace"}
    return frozenset(words & {"ignoredups", "ignorespace"})


class HoneyPotInteractiveProtocol(HoneyPotBaseProtocol, recvline.HistoricRecvLine):
    # T-Pot: the longest line the line editor keeps (bytes)
    TPOT_LINE_MAX = 65536

    def __init__(self, avatar):
        recvline.HistoricRecvLine.__init__(self)
        HoneyPotBaseProtocol.__init__(self, avatar)

    def connectionMade(self) -> None:
        self.displayMOTD()

        HoneyPotBaseProtocol.connectionMade(self)
        recvline.HistoricRecvLine.connectionMade(self)
        self.qpot_read_history()

        self.cmdstack = [honeypot.HoneyPotShell(self)]
        # QPot: the variables bash sets in the login shell (BASH_VERSION ...)
        qpot_shell_variables(self.cmdstack[0])
        # Show the first prompt now that the interactive shell is on the stack.
        self.cmdstack[0].showPrompt()

        self.keyHandlers.update(
            {
                b"\x00": self.handle_NUL,  # NUL (NVT line ending, keepalive padding)
                b"\x01": self.handle_HOME,  # CTRL-A
                b"\x02": self.handle_LEFT,  # CTRL-B
                b"\x03": self.handle_CTRL_C,  # CTRL-C
                b"\x04": self.handle_CTRL_D,  # CTRL-D
                b"\x05": self.handle_END,  # CTRL-E
                b"\x06": self.handle_RIGHT,  # CTRL-F
                b"\x08": self.handle_BACKSPACE,  # CTRL-H
                b"\x09": self.handle_TAB,
                b"\x0b": self.handle_CTRL_K,  # CTRL-K
                b"\x0c": self.handle_CTRL_L,  # CTRL-L
                b"\x0e": self.handle_DOWN,  # CTRL-N
                b"\x10": self.handle_UP,  # CTRL-P
                b"\x15": self.handle_CTRL_U,  # CTRL-U
                b"\x16": self.handle_CTRL_V,  # CTRL-V
                b"\x1b": self.handle_ESC,  # ESC
            }
        )

    # QPot: the most of the history file a login reads (bytes, from its end)
    QPOT_HISTFILE_MAX = 65536

    def qpot_read_history(self) -> None:
        """QPot: an interactive bash reads its history file at the start, so `history` and the up
        arrow show the lines of ~/.bash_history before the session's own. Only the last HISTSIZE
        lines are kept, numbered on from those dropped, as bash's stifle_history does; a line read
        from the file has no time (HISTTIMEFORMAT shows "??" for it, as bash 4.4 and later)."""
        path = str((self.environ or {}).get("HISTFILE", "") or "")
        if not path.startswith("/"):
            return
        try:
            data = self.fs.file_contents(path)
        except Exception:  # noqa: BLE001 - no history file, a folder, a broken link: an empty history
            return
        if not isinstance(data, bytes) or not data:
            return
        if len(data) > self.QPOT_HISTFILE_MAX:
            data = data[-self.QPOT_HISTFILE_MAX:]
            data = data[data.find(b"\n") + 1:]
        lines = [line for line in data.split(b"\n") if line]
        size = tpot_history_size(getattr(self.user, "uid", None) == 0)
        dropped = max(len(lines) - size, 0) if size else 0
        lines = lines[dropped:]
        self.historyLines = lines
        self.tpot_history_times = [None] * len(lines)
        self.tpot_history_base = dropped
        self.historyPosition = len(lines)

    def displayMOTD(self) -> None:
        try:
            self.terminal.write(self.fs.file_contents("/etc/motd"))
        except Exception:
            pass
        # T-Pot: BusyBox msh on a terminal: two empty lines, its banner, the line about help, an empty line
        tpot_banner = CowrieConfig.get("shell", "text_banner", fallback="")
        if CowrieConfig.get("shell", "not_found_style", fallback="bash") == "msh" and tpot_banner:
            self.terminal.write(
                f"\n\n{tpot_banner} built-in shell (msh)\n"
                "Enter 'help' for a list of built-in commands.\n\n".encode()
            )

    def timeoutConnection(self) -> None:
        """
        this logs out when connection times out
        """
        assert self.terminal is not None
        # T-Pot: a full screen command (top) gives the cursor back first
        restore = getattr(self.cmdstack[-1], "tpot_restore", None) if self.cmdstack else None
        if restore is not None:
            restore()
        self.terminal.write(b"timed out waiting for input: auto-logout\n")
        HoneyPotBaseProtocol.timeoutConnection(self)

    def connectionLost(self, reason: failure.Failure = connectionDone) -> None:
        HoneyPotBaseProtocol.connectionLost(self, reason)
        recvline.HistoricRecvLine.connectionLost(self, reason)
        self.keyHandlers = {}

    def initializeScreen(self) -> None:
        """
        Overriding super to prevent terminal.reset()
        """
        self.setInsertMode()

    # QPot: the line editor writes what the persona's shell writes on an xterm, recorded with
    # bash 5.2.37 (readline 8.2) and BusyBox 1.37.0 ash. Twisted's RecvLine put the terminal in
    # insert mode (ESC[4h before every prompt, ESC[4l after every line), which no shell does, moved
    # with ESC[1D where both write a backspace, and erased with ESC[1D ESC[1P one byte at a time.
    # Twisted's terminal turns every \n into \r\n, so a newline is written as \n here.

    def setInsertMode(self) -> None:
        self.mode = "insert"

    def setTypeoverMode(self) -> None:
        self.mode = "typeover"

    @property
    def ps(self):
        """The prompts as written: bash 5.1 and later turn on bracketed paste before each."""
        return getattr(self, "_qpot_ps_written", recvline.RecvLine.ps)

    @ps.setter
    def ps(self, value) -> None:
        self._qpot_ps_raw = value
        tree = getattr(self, "fs", None)
        mark = b"\x1b[?2004h" if tree is not None and qpot_bracketed_paste(tree) and self.qpot_term() else b""
        self._qpot_ps_written = tuple(mark + p for p in value)

    def qpot_term(self) -> bool:
        """A terminal that is not dumb: readline brackets pastes on any other."""
        term = str((getattr(self, "environ", None) or {}).get("TERM", "xterm"))
        return term not in ("", "dumb")

    def qpot_bracketing(self) -> bool:
        """Whether the prompt now on screen turned bracketed paste on."""
        return getattr(self, "_qpot_ps_written", (b"",))[0].startswith(b"\x1b[?2004h")

    def qpot_prompt(self) -> bytes:
        """The prompt as the line editor redraws it (without the bracketed paste switch)."""
        raw = getattr(self, "_qpot_ps_raw", recvline.RecvLine.ps)
        return raw[self.pn] if self.pn < len(raw) else raw[0]

    def qpot_write(self, data: bytes) -> None:
        """Echo of the line editor; nothing while a password is read (the tty does not echo)."""
        if data and self.terminal is not None and not self.password_input:
            self.terminal.write(data)

    def drawInputLine(self) -> None:
        assert self.terminal is not None
        self.terminal.write(self.qpot_prompt() + b"".join(self.lineBuffer))

    def qpot_line_change(self, old: bytes, index: int, new: bytes, new_index: int) -> bytes:
        """The bytes that turn the line old (cursor at index) into new (cursor at new_index)."""
        if qpot_editor() == "ash":
            # BusyBox redraws the line: CR, the prompt, the line, erase below
            out = b"\r" + self.qpot_prompt() + new + b"\x1b[J"
        else:
            # readline rewrites from the first byte that differs and erases what is left over
            same = 0
            while same < min(len(old), len(new)) and old[same] == new[same]:
                same += 1
            out = b"\x08" * (index - same) if index > same else old[index:same]
            out += new[same:]
            if len(old) > len(new):
                out += b"\x1b[K"
        return out + b"\x08" * (len(new) - new_index)

    def qpot_redraw(self, function, *args):
        """Run an editing function of Twisted's or the shell's for its bookkeeping and write the change
        of the line as the persona's editor writes it. Output with a line break (a TAB listing) passes
        as it was written."""
        terminal = self.terminal
        self._qpot_last_written = b""
        if terminal is None or "write" in vars(terminal):
            return function(*args)
        old, index = b"".join(self.lineBuffer), self.lineBufferIndex
        parts: list[bytes] = []
        terminal.write = parts.append
        try:
            result = function(*args)
        finally:
            del terminal.write
        written = b"".join(parts)
        self._qpot_last_written = written
        if b"\n" in written:
            terminal.write(written)
        else:
            self.qpot_write(self.qpot_line_change(old, index, b"".join(self.lineBuffer), self.lineBufferIndex))
        return result

    def handle_LEFT(self) -> None:
        if self.lineBufferIndex > 0:
            self.lineBufferIndex -= 1
            self.qpot_write(b"\x08")

    def handle_RIGHT(self) -> None:
        if self.lineBufferIndex < len(self.lineBuffer):
            # both editors move right by writing the character under the cursor again
            self.qpot_write(self.lineBuffer[self.lineBufferIndex])
            self.lineBufferIndex += 1

    def handle_HOME(self) -> None:
        if self.lineBufferIndex:
            self.qpot_write(b"\x08" * self.lineBufferIndex)
            self.lineBufferIndex = 0

    def handle_END(self) -> None:
        if self.lineBufferIndex < len(self.lineBuffer):
            self.qpot_write(b"".join(self.lineBuffer[self.lineBufferIndex :]))
            self.lineBufferIndex = len(self.lineBuffer)

    def handle_BACKSPACE(self) -> None:
        if self.lineBufferIndex <= 0:
            return
        self.lineBufferIndex -= 1
        del self.lineBuffer[self.lineBufferIndex]
        tail = b"".join(self.lineBuffer[self.lineBufferIndex :])
        if qpot_editor() == "ash":
            self.qpot_write(b"\x08" + tail + b"\x1b[J" + b"\x08" * len(tail))
        elif tail:
            self.qpot_write(b"\x08\x1b[1P")
        else:
            self.qpot_write(b"\x08 \x08")

    def handle_DELETE(self) -> None:
        if self.lineBufferIndex >= len(self.lineBuffer):
            return
        del self.lineBuffer[self.lineBufferIndex]
        tail = b"".join(self.lineBuffer[self.lineBufferIndex :])
        if qpot_editor() == "ash":
            self.qpot_write(tail + b"\x1b[J" + b"\x08" * len(tail))
        else:
            self.qpot_write(b"\x1b[1P")

    def handle_RETURN(self) -> None:
        self.qpot_history_add()
        line = b"".join(self.lineBuffer)
        self.lineBuffer = []
        self.lineBufferIndex = 0
        self.terminal.nextLine()
        # the shell reading its own line turns bracketed paste off again before it runs it
        if len(self.cmdstack) == 1 and self.qpot_bracketing():
            self.terminal.write(b"\x1b[?2004l\r")
        self.lineReceived(line)

    def call_command(self, pp, cmd, *args):
        self.pp = pp
        self.setTypeoverMode()
        HoneyPotBaseProtocol.call_command(self, pp, cmd, *args)

    def characterReceived(self, ch, moreCharactersComing):
        """
        Easier way to implement password input?
        """
        self.resetTimeout()  # Reset the idle timeout
        # T-Pot: a full screen command (top) takes the keys one by one, without echo
        key = getattr(self.cmdstack[-1], "tpot_key", None) if self.cmdstack else None
        if key is not None and key(ch):
            return
        # T-Pot: a line holds at most TPOT_LINE_MAX bytes; a key beyond it is echoed as bash
        # echoes it, but not kept (the line runs and is logged cut to the bound)
        if len(self.lineBuffer) < self.TPOT_LINE_MAX or (
            self.mode != "insert" and self.lineBufferIndex < len(self.lineBuffer)
        ):
            if self.mode == "insert":
                self.lineBuffer.insert(self.lineBufferIndex, ch)
            else:
                self.lineBuffer[self.lineBufferIndex : self.lineBufferIndex + 1] = [ch]
            self.lineBufferIndex += 1
        if not self.password_input:
            assert self.terminal is not None
            tail = b"".join(self.lineBuffer[self.lineBufferIndex :])
            if self.mode != "insert" or not tail:
                self.terminal.write(ch)
            elif qpot_editor() == "ash":
                self.terminal.write(ch + tail + b"\x08" * len(tail))
            else:
                self.terminal.write(b"\x1b[1@" + ch)

    def qpot_history_add(self) -> None:
        if len(self.cmdstack) == 1:
            if self.lineBuffer:
                # T-Pot: HISTCONTROL of the persona's shell leaves out a repeated line or one that
                # starts with a space; the history keeps the last HISTSIZE lines, `history` numbers
                # them on from those it dropped (tpot_history_base)
                root = getattr(self.user, "uid", None) == 0
                line = b"".join(self.lineBuffer)
                control = tpot_history_control(root)
                if not (
                    ("ignorespace" in control and line[:1] == b" ")
                    or ("ignoredups" in control and self.historyLines and self.historyLines[-1] == line)
                ):
                    self.historyLines.append(line)
                    # the time of the line, for HISTTIMEFORMAT (patch_history)
                    times = getattr(self, "tpot_history_times", None)
                    if times is None:
                        times = self.tpot_history_times = []
                    times.append(time.time())
                size = tpot_history_size(root)
                if size and len(self.historyLines) > size:
                    dropped = len(self.historyLines) - size
                    del self.historyLines[:dropped]
                    del getattr(self, "tpot_history_times", [])[:dropped]
                    self.tpot_history_base = getattr(self, "tpot_history_base", 0) + dropped
            self.historyPosition = len(self.historyLines)

    def handle_NUL(self) -> None:
        """
        Ignore NUL bytes. They are routine NVT traffic: telnet clients send
        CR NUL as the line ending per RFC 854, and some clients send stray NUL
        bytes as keepalive padding.
        """

    def handle_CTRL_C(self) -> None:
        if len(self.cmdstack) == 1 and self.terminal is not None:
            # the shell's own newline follows (handle_CTRL_C of the shell)
            if qpot_editor() == "ash":
                self.terminal.write(b"^C\n")
            elif self.qpot_bracketing():
                self.terminal.write(b"^C\x1b[?2004l\r\x1b[?2004h\x1b[?2004l\r")
            else:
                self.terminal.write(b"^C")
        if self.cmdstack:
            self.cmdstack[-1].handle_CTRL_C()

    def handle_CTRL_D(self) -> None:
        # CTRL-D at the terminal signals end-of-file on stdin.
        self.eofReceived()

    def handle_TAB(self) -> None:
        if self.cmdstack:
            before = (b"".join(self.lineBuffer), self.lineBufferIndex)
            self.qpot_redraw(self.cmdstack[-1].handle_TAB)
            if not self._qpot_last_written and before == (b"".join(self.lineBuffer), self.lineBufferIndex):
                self.qpot_write(b"\x07")

    def handle_CTRL_K(self) -> None:
        assert self.terminal is not None
        if self.lineBufferIndex < len(self.lineBuffer):
            self.qpot_write(b"\x1b[J" if qpot_editor() == "ash" else b"\x1b[K")
        self.lineBuffer = self.lineBuffer[0 : self.lineBufferIndex]

    def handle_CTRL_L(self) -> None:
        """
        Handle a 'form feed' byte - generally used to request a screen
        refresh/redraw.
        """
        assert self.terminal is not None
        # the clear capability of xterm (home, erase the screen), then the prompt and the line
        line = b"".join(self.lineBuffer)
        self.terminal.write(b"\x1b[H\x1b[2J" + self.qpot_prompt() + line
                            + b"\x08" * (len(line) - self.lineBufferIndex))

    def tpot_one_write(self, function, *args):
        """T-Pot: run function with the terminal's writes taken together into one write."""
        terminal = self.terminal
        if terminal is None or "write" in vars(terminal):
            return function(*args)
        parts: list[bytes] = []
        terminal.write = parts.append
        try:
            return function(*args)
        finally:
            del terminal.write
            if parts:
                terminal.write(b"".join(parts))

    def _deliverBuffer(self, buf):
        # T-Pot: a line of the history in one write
        self.tpot_one_write(recvline.HistoricRecvLine._deliverBuffer, self, buf)

    def handle_UP(self):
        # T-Pot: the move to the line before in one write; QPot: the bytes of the persona's editor
        self.qpot_redraw(recvline.HistoricRecvLine.handle_UP, self)

    def handle_DOWN(self):
        # T-Pot: the move to the line after in one write; QPot: the bytes of the persona's editor
        self.qpot_redraw(recvline.HistoricRecvLine.handle_DOWN, self)

    def handle_CTRL_U(self) -> None:
        assert self.terminal is not None
        index = self.lineBufferIndex
        rest = b"".join(self.lineBuffer[index:])
        if index:
            if qpot_editor() == "ash":
                # BusyBox redraws: CR, the prompt, what is left, erase below
                self.qpot_write(b"\r" + self.qpot_prompt() + rest + b"\x1b[J" + b"\x08" * len(rest))
            elif rest:
                self.qpot_write(b"\x08" * index + b"\x1b[%dP" % index)
            else:
                self.qpot_write(b"\x08" * index + b"\x1b[K")
        self.lineBuffer = self.lineBuffer[index:]
        self.lineBufferIndex = 0

    def handle_CTRL_V(self) -> None:
        pass

    def handle_ESC(self) -> None:
        pass


class HoneyPotInteractiveTelnetProtocol(HoneyPotInteractiveProtocol):
    """
    Specialized HoneyPotInteractiveProtocol that provides Telnet specific
    overrides.
    """

    def __init__(self, avatar):
        HoneyPotInteractiveProtocol.__init__(self, avatar)

    def getProtoTransport(self):
        """
        Due to protocol nesting differences, we need to override how we grab
        the proper transport to access underlying Telnet information.
        """
        return self.terminal.transport.session.transport
