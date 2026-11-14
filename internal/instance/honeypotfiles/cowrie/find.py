# SPDX-FileCopyrightText: 2025 Onder7994
# SPDX-FileCopyrightText: 2025-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""
find command
"""

from __future__ import annotations

import fnmatch
import hashlib
import posixpath
import re
import time

from cowrie.shell import fs as tree_fs
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import A_CONTENTS, A_MODE, A_NAME, A_TYPE, T_DIR, T_FILE, T_LINK

commands = {}

# QPot: the fields of a node the expression reads beside those above
A_UID, A_GID, A_SIZE, A_CTIME, A_TARGET = (tree_fs.A_UID, tree_fs.A_GID, tree_fs.A_SIZE, tree_fs.A_CTIME,
                                           tree_fs.A_TARGET)

QPOT_HELP = """Usage: find [-H] [-L] [-P] [-Olevel] [-D debugopts] [path...] [expression]

Default path is the current directory; default expression is -print.
Expression may consist of: operators, options, tests, and actions.

Operators (decreasing precedence; -and is implicit where no others are given):
      ( EXPR )   ! EXPR   -not EXPR   EXPR1 -a EXPR2   EXPR1 -and EXPR2
      EXPR1 -o EXPR2   EXPR1 -or EXPR2   EXPR1 , EXPR2

Positional options (always true):
      -daystart -follow -nowarn -regextype -warn

Normal options (always true, specified before other expressions):
      -depth -files0-from FILE -maxdepth LEVELS -mindepth LEVELS
      -mount -noleaf -xdev -ignore_readdir_race -noignore_readdir_race

Tests (N can be +N or -N or N):
      -amin N -anewer FILE -atime N -cmin N -cnewer FILE -context CONTEXT
      -ctime N -empty -false -fstype TYPE -gid N -group NAME -ilname PATTERN
      -iname PATTERN -inum N -iwholename PATTERN -iregex PATTERN
      -links N -lname PATTERN -mmin N -mtime N -name PATTERN -newer FILE
      -nouser -nogroup -path PATTERN -perm [-/]MODE -regex PATTERN
      -readable -writable -executable
      -wholename PATTERN -size N[bcwkMG] -true -type [bcdpflsD] -uid N
      -used N -user NAME -xtype [bcdpfls]

Actions:
      -delete -print0 -printf FORMAT -fprintf FILE FORMAT -print
      -fprint0 FILE -fprint FILE -ls -fls FILE -prune -quit
      -exec COMMAND ; -exec COMMAND {} + -ok COMMAND ;
      -execdir COMMAND ; -execdir COMMAND {} + -okdir COMMAND ;

Other common options:
      --help                   display this help and exit
      --version                output version information and exit

Valid arguments for -D:
exec, opt, rates, search, stat, time, tree, all, help
Use '-D help' for a description of the options, or see find(1)

Please see also the documentation at https://www.gnu.org/software/findutils/.
You can report (and track progress on fixing) bugs in the "find"
program via the GNU findutils bug-reporting page at
https://savannah.gnu.org/bugs/?group=findutils or, if
you have no web access, by sending email to <bug-findutils@gnu.org>.
"""

QPOT_REGEX_TYPES = ("findutils-default", "ed", "emacs", "gnu-awk", "grep", "posix-awk", "awk", "posix-basic",
                    "posix-egrep", "egrep", "posix-extended", "posix-minimal-basic", "sed")
QPOT_REGEX_EXTENDED = ("gnu-awk", "posix-awk", "awk", "posix-egrep", "egrep", "posix-extended")
# what BusyBox's find knows: anything else is "unrecognized" there
QPOT_BUSYBOX_WORDS = frozenset((
    "-name", "-iname", "-path", "-ipath", "-regex", "-type", "-executable", "-perm", "-mtime", "-atime", "-ctime",
    "-mmin", "-amin", "-cmin", "-newer", "-inum", "-samefile", "-user", "-group", "-size", "-links", "-empty",
    "-print", "-print0", "-exec", "-ok", "-delete", "-quit", "-prune", "-maxdepth", "-mindepth", "-depth", "-xdev",
    "-mount", "-follow", "-o", "-or", "-a", "-and", "-not"))
QPOT_HALF_YEAR = 31556952 // 2


class QpotFindStop(Exception):
    """The expression cannot be read: find's message, and status 1 (out: --help and --version,
    which go to the output and end with status 0)."""

    def __init__(self, text: str, out: bool = False) -> None:
        super().__init__(text)
        self.text, self.out = text, out


class QpotFindQuit(Exception):
    """-quit."""


class QpotEntry:
    """One file of the walk: its node, the path find prints, its path from the root, its name and depth."""

    __slots__ = ("depth", "full", "name", "node", "path", "start")

    def __init__(self, node, path: str, full: str, name: str, depth: int, start: str) -> None:
        self.node, self.path, self.full, self.name, self.depth, self.start = node, path, full, name, depth, start


def qpot_regex(pattern: str, kind: str, fold: bool):
    """-regex's pattern for Python's re, or None for one that is not matched here. The default syntax
    is Emacs's, where \\( \\) \\| group and ( ) | { } are themselves; the extended ones are ERE. A pattern
    that could take long on a path (several repeats, a repeated group, a back-reference) matches
    nothing: every path of the walk is tried against it on the one thread all sessions share."""
    if len(pattern) > 200:
        return None
    extended = kind in QPOT_REGEX_EXTENDED
    out, i, repeats, last_group = [], 0, 0, False
    while i < len(pattern):
        char = pattern[i]
        if char == "\\" and i + 1 < len(pattern):
            nxt = pattern[i + 1]
            i += 2
            if nxt.isdigit():
                return None
            if not extended and nxt in "()|":
                out.append(nxt)
                last_group = nxt == ")"
                continue
            if nxt in "wWsSbB<>`'":
                out.append({"<": r"\b", ">": r"\b", "`": r"\A", "'": r"\Z"}.get(nxt, "\\" + nxt))
            else:
                out.append(re.escape(nxt))
            last_group = False
            continue
        i += 1
        if char == "[":
            end = pattern.find("]", i + 1 if pattern[i:i + 1] in ("]", "^") else i)
            if pattern[i:i + 2] == "^]":
                end = pattern.find("]", i + 2)
            if end < 0:
                return None
            body = pattern[i:end]
            if "[:" in body or "[." in body or "[=" in body:
                return None
            out.append("[" + body.replace("\\", "\\\\") + "]")
            i = end + 1
            last_group = False
            continue
        if char in "*+?":
            if char in "+?" and kind in ("posix-basic", "posix-minimal-basic", "ed", "sed", "grep"):
                out.append(re.escape(char))
                continue
            if last_group and char != "?":
                return None
            repeats += char != "?"
            out.append(char)
            last_group = False
            continue
        if char in "(|)":
            if extended:
                if pattern[i:i + 1] == "?" and char == "(":
                    return None
                out.append(char)
                last_group = char == ")"
            else:
                out.append("\\" + char)
                last_group = False
            continue
        if char in "{}":
            if extended:
                return None  # an interval: a repeat of unknown size
            out.append("\\" + char)
            last_group = False
            continue
        out.append(char if char in ".^$" else re.escape(char))
        last_group = False
    if repeats > 3:
        return None
    try:
        return re.compile("".join(out), re.IGNORECASE if fold else 0)
    except re.error:
        return None


class Command_find(HoneyPotCommand):
    """
    find command
    """

    # QPot: GNU find does not follow symbolic links (-P, its default), so its walk ends. The image's
    #   find descended into every link to a directory (/usr/bin/X11 -> ., /proc/self/root -> /) down
    #   to depth 20, resolving each path from the root: `find / -name id_rsa`, the first thing a
    #   credential harvester runs, held Cowrie's reactor and with it every session for many minutes.
    #   The walk now goes over the tree's nodes, enters no link and stops after QPOT_FIND_MAX entries
    #   or QPOT_FIND_SECONDS, whichever comes first.
    # QPot: the expression is GNU find's: its operators (! -a -o , and parentheses), tests (-name,
    #   -path, -regex, -type, -perm, -size, -empty, -user, -mtime, -newer ...), options (-maxdepth,
    #   -mindepth, -depth ...) and actions (-print, -print0, -printf, -ls, -fprint, -prune, -quit,
    #   -delete, -exec and -execdir with ; and +). The image's knew -name, -type and -maxdepth and
    #   answered "unknown predicate" to the rest, so `find / -name id_rsa -o -name '*.pem'` and
    #   `find /root -type f -exec cat {} \;` showed nothing. A command -exec starts is one of the
    #   honeypot's own, started and logged as the shell starts it; its status decides the test, as
    #   in find. Texts recorded from findutils 4.10.0.
    QPOT_FIND_MAX = 200000
    QPOT_FIND_SECONDS = 2.0
    QPOT_FIND_EXECS = 1000
    QPOT_FIND_ARGS = 128 * 1024
    QPOT_TYPES = {"f": T_FILE, "d": T_DIR, "l": T_LINK, "b": tree_fs.T_BLK, "c": tree_fs.T_CHR,
                  "s": tree_fs.T_SOCK, "p": tree_fs.T_FIFO}

    def start(self) -> None:
        self.maxdepth: int = 1 << 30
        self.qpot_mindepth = 0
        self.qpot_depth_first = False
        self.qpot_status = 0
        self.qpot_buffer: list[str] = []
        self.qpot_files: dict[str, list[str]] = {}
        self.qpot_plus: list[dict] = []
        self.qpot_execs = 0
        self.qpot_state = "idle"
        self.qpot_interrupted = False
        self.qpot_pruned = False
        self.qpot_check = 1024
        self.qpot_regex_kind = "emacs"
        self.qpot_now = time.time()
        self.qpot_origin = self.qpot_now
        self.qpot_tables: dict | None = None
        self.qpot_state_seen: list = []
        self.qpot_warnings: list[str] = []
        self.qpot_first_test = ""
        self.qpot_warn = self.qpot_at_terminal()
        self.qpot_busybox = self.qpot_is_busybox()
        self.qpot_root = int((getattr(self, "user", None) or {}).get("uid", 0) or 0) == 0
        try:
            paths, words = self.qpot_split(list(self.args))
            expr = self.qpot_compile(words)
        except QpotFindStop as stop:
            if stop.out:
                self.write(stop.text)
            else:
                self.errorWrite(stop.text)
            self.exit(0 if stop.out else 1)
            return
        for text in self.qpot_warnings:
            self.errorWrite(text)
        self.qpot_left = self.QPOT_FIND_MAX
        self.qpot_deadline = time.monotonic() + self.QPOT_FIND_SECONDS
        self.qpot_gen = self.qpot_run(paths or ["."], expr)
        self.qpot_step(None)

    # --- the walk ---

    def qpot_run(self, paths: list[str], expr):
        """The whole call (a generator): it hands out each command -exec starts and takes its status."""
        try:
            for arg in paths:
                full = self.fs.resolve_path(arg, self.cwd)
                node = self.fs.getfile(full, follow_symlinks=False)
                if node is None:
                    self.qpot_error(f"find: ‘{arg}’: No such file or directory\n")
                    continue
                self.start_path = full
                entry = QpotEntry(node, arg, full, posixpath.basename(arg.rstrip("/")) or "/", 0, arg)
                yield from self.qpot_walk(entry, expr)
                if self.qpot_left < 0:
                    break
        except QpotFindQuit:
            pass
        for action in self.qpot_plus:
            yield from self.qpot_exec_batches(action)
        self.qpot_flush()
        for path, parts in self.qpot_files.items():
            self.qpot_save(path, "".join(parts))
        return self.qpot_status

    def qpot_walk(self, entry: QpotEntry, expr):
        """Visit an entry and what is below it."""
        self.qpot_left -= 1
        if self.qpot_left < 0 or (self.qpot_left % self.qpot_check == 0 and time.monotonic() > self.qpot_deadline):
            self.qpot_left = -1
            return
        fn, suspends = expr
        node = entry.node
        wanted = entry.depth >= self.qpot_mindepth
        self.qpot_pruned = False
        if wanted and not self.qpot_depth_first:
            if suspends:
                yield from fn(entry)
            else:
                fn(entry)
        pruned, self.qpot_pruned = self.qpot_pruned, False
        if (not pruned and entry.depth < self.maxdepth and node[A_TYPE] == T_DIR
                and isinstance(node[A_CONTENTS], list)):
            if not self.qpot_root and not self.qpot_may_list(entry):
                self.qpot_error(f"find: ‘{entry.path}’: Permission denied\n")
            else:
                prefix = entry.path if entry.path.endswith("/") else entry.path + "/"
                base = entry.full if entry.full.endswith("/") else entry.full + "/"
                for child in list(node[A_CONTENTS]):
                    if self.qpot_left < 0:
                        return
                    name = str(child[A_NAME])
                    if name in (".", ".."):
                        continue
                    yield from self.qpot_walk(
                        QpotEntry(child, prefix + name, base + name, name, entry.depth + 1, entry.start), expr)
        if wanted and self.qpot_depth_first and self.qpot_left >= 0:
            if suspends:
                yield from fn(entry)
            else:
                fn(entry)

    def qpot_may_list(self, entry: QpotEntry) -> bool:
        try:
            self.fs.get_path(entry.full)
        except PermissionError:
            return False
        except Exception:  # noqa: BLE001 - a folder the tree cannot list is an empty one
            return True
        return True

    def qpot_error(self, text: str) -> None:
        self.qpot_flush()
        self.errorWrite(text)
        self.qpot_status = 1

    def qpot_emit(self, text: str) -> None:
        self.qpot_buffer.append(text)
        if len(self.qpot_buffer) >= 512:
            self.qpot_flush()

    def qpot_flush(self) -> None:
        if self.qpot_buffer:
            text, self.qpot_buffer = "".join(self.qpot_buffer), []
            self.write(text)

    # --- commands started by -exec ---

    def qpot_step(self, reply) -> None:
        """Run the call up to the next command it starts; resume() goes on when that one has ended."""
        while True:
            try:
                argv, cwd = self.qpot_gen.send(reply)
            except StopIteration as done:
                if not self.exited:
                    self.exit(done.value or 0)
                return
            except Exception:  # noqa: BLE001 - a bad argument must not end the session
                self.qpot_flush()
                if not self.exited:
                    self.exit(1)
                return
            reply = self.qpot_launch(argv, cwd)
            if reply is None:
                return

    def qpot_launch(self, argv: list[str], cwd: str):
        """Start a command: its status once it has ended, None while it runs."""
        from cowrie.shell.pipe import PipeProtocol

        protocol, name = self.protocol, argv[0]
        self.qpot_flush()
        cmdclass = protocol.getCommand(name, self.environ.get("PATH", "").split(":"), cwd)
        if cmdclass is not None:
            try:
                from cowrie.commands.wc import TPOT_XARGS_BUILTINS as builtins
            except Exception:  # noqa: BLE001
                builtins = ()
            if name in builtins:
                cmdclass = None  # a builtin of the shell is no file find could run
        if cmdclass is None:
            self.errorWrite(f"find: ‘{name}’: No such file or directory\n" if not self.qpot_busybox
                            else f"find: can't execute '{name}': No such file or directory\n")
            return 127
        try:
            protocol.events.dispatch("cowrie.command.success", "Command found: %(input)s", input=" ".join(argv))
        except Exception:  # noqa: BLE001
            pass
        pp = PipeProtocol(protocol, cmdclass, argv[1:], b"", self.pp.targets, cwd=cwd, user=self.user)
        pp.stdin_from_pipe = True
        self.qpot_state, self.qpot_done = "starting", False
        protocol.call_command(pp, cmdclass, *argv[1:])
        if self.qpot_done:
            self.qpot_state = "idle"
            return int(getattr(self, "last_exit_code", 0) or 0)
        self.qpot_state = "waiting"
        child = protocol.cmdstack[-1] if protocol.cmdstack else None
        if child is not None and child is not self:
            handle = child.handle_CTRL_C

            def interrupted():
                self.qpot_interrupted = True  # the signal goes to the whole foreground group
                handle()

            child.handle_CTRL_C = interrupted
        return None

    def resume(self) -> None:
        state = getattr(self, "qpot_state", "idle")
        if state == "starting":
            self.qpot_done = True
        elif state == "waiting":
            self.qpot_state = "idle"
            if self.qpot_interrupted:
                self.qpot_gen.close()
                if not self.exited:
                    self.exit(130)
                return
            self.qpot_deadline = time.monotonic() + self.QPOT_FIND_SECONDS
            self.qpot_step(int(getattr(self, "last_exit_code", 0) or 0))

    def qpot_exec_batches(self, action: dict):
        """-exec COMMAND {} +: the paths it gathered, as many to a command line as fit."""
        paths, action["paths"] = action["paths"], []
        while paths:
            batch, size = [], sum(len(word) + 1 for word in action["argv"])
            while paths and (not batch or size + len(paths[0]) + 1 <= self.QPOT_FIND_ARGS):
                size += len(paths[0]) + 1
                batch.append(paths.pop(0))
            if self.qpot_execs >= self.QPOT_FIND_EXECS:
                return
            self.qpot_execs += 1
            status = yield (action["argv"] + batch, action["cwd"] or self.cwd)
            if status:
                self.qpot_status = 1

    # --- reading the command line ---

    def qpot_at_terminal(self) -> bool:
        """Whether find's input is a terminal, where it warns (-warn is its default there)."""
        try:
            from cowrie.commands.base import tpot_pty

            return bool(tpot_pty(self.protocol)) and not getattr(self.pp, "stdin_from_pipe", False)
        except Exception:  # noqa: BLE001
            return False

    def qpot_is_busybox(self) -> bool:
        try:
            from cowrie.commands.coreutils import qpot_busybox_applet

            return bool(qpot_busybox_applet(self.fs, "find"))
        except Exception:  # noqa: BLE001
            return False

    def qpot_version(self) -> tuple:
        try:
            from cowrie.commands.coreutils import qpot_package_version

            found = re.match(r"(?:\d+:)?(\d+)\.(\d+)(?:\.(\d+))?", qpot_package_version("findutils") or "")
        except Exception:  # noqa: BLE001
            found = None
        return (int(found[1]), int(found[2]), int(found[3] or 0)) if found else (4, 10, 0)

    def qpot_split(self, args: list[str]):
        """(starting points, expression): the points come first, after -H, -L, -P, -D and -O."""
        i = 0
        while i < len(args):
            if args[i] in ("-H", "-L", "-P") or (args[i].startswith("-O") and args[i][2:].isdigit()):
                i += 1
            elif args[i] == "-D" and i + 1 < len(args):
                i += 2
            else:
                break
        paths = []
        while i < len(args):
            arg = args[i]
            if arg in ("(", ")", "!") or (arg.startswith("-") and len(arg) > 1):
                break
            paths.append(arg)
            i += 1
        return paths, args[i:]

    def qpot_compile(self, words: list[str]):
        self.qpot_words, self.qpot_at, self.qpot_acts = words, 0, False
        if not words:
            expr = ((lambda entry: True), False)
        else:
            expr = self.qpot_comma()
            if self.qpot_at < len(words):
                raise QpotFindStop("find: you have too many ')'\n")
        if not self.qpot_acts:
            expr = self.qpot_both(expr, (self.qpot_printer("\n"), False))
        return expr

    def qpot_peek(self):
        return self.qpot_words[self.qpot_at] if self.qpot_at < len(self.qpot_words) else None

    def qpot_need(self, op: str) -> None:
        word = self.qpot_peek()
        if word is None:
            raise QpotFindStop(f"find: expected an expression after '{op}'\n")
        if word == ")":
            raise QpotFindStop(f"find: expected an expression between '{op}' and ')'\n")

    @staticmethod
    def qpot_both(left, right):
        fa, sa = left
        fb, sb = right
        if not sa and not sb:
            return (lambda entry: fa(entry) and fb(entry)), False

        def both(entry):
            if not ((yield from fa(entry)) if sa else fa(entry)):
                return False
            return (yield from fb(entry)) if sb else fb(entry)

        return both, True

    @staticmethod
    def qpot_either(left, right):
        fa, sa = left
        fb, sb = right
        if not sa and not sb:
            return (lambda entry: fa(entry) or fb(entry)), False

        def either(entry):
            if (yield from fa(entry)) if sa else fa(entry):
                return True
            return (yield from fb(entry)) if sb else fb(entry)

        return either, True

    @staticmethod
    def qpot_list(left, right):
        fa, sa = left
        fb, sb = right
        if not sa and not sb:
            return (lambda entry: (fa(entry), fb(entry))[1]), False

        def listed(entry):
            if sa:
                yield from fa(entry)
            else:
                fa(entry)
            return (yield from fb(entry)) if sb else fb(entry)

        return listed, True

    @staticmethod
    def qpot_negate(inner):
        fn, suspends = inner
        if not suspends:
            return (lambda entry: not fn(entry)), False

        def negated(entry):
            return not (yield from fn(entry))

        return negated, True

    def qpot_comma(self):
        left = self.qpot_or()
        while self.qpot_peek() == ",":
            self.qpot_at += 1
            self.qpot_need(",")
            left = self.qpot_list(left, self.qpot_or())
        return left

    def qpot_or(self):
        left = self.qpot_and()
        while self.qpot_peek() in ("-o", "-or"):
            op = self.qpot_words[self.qpot_at]
            self.qpot_at += 1
            self.qpot_need(op)
            left = self.qpot_either(left, self.qpot_and())
        return left

    def qpot_and(self):
        left = self.qpot_not()
        while True:
            word = self.qpot_peek()
            if word is None or word in (")", ",", "-o", "-or"):
                return left
            if word in ("-a", "-and"):
                self.qpot_at += 1
                self.qpot_need(word)
            left = self.qpot_both(left, self.qpot_not())

    def qpot_not(self):
        word = self.qpot_peek()
        if word in ("!", "-not"):
            self.qpot_at += 1
            self.qpot_need(word)
            return self.qpot_negate(self.qpot_not())
        return self.qpot_primary()

    def qpot_primary(self):
        word = self.qpot_peek()
        if word == "(":
            self.qpot_at += 1
            if self.qpot_peek() == ")":
                raise QpotFindStop("find: invalid expression; empty parentheses are not allowed.\n")
            if self.qpot_peek() is None:
                raise QpotFindStop("find: invalid expression; I was expecting to find a ')' somewhere "
                                   "but did not see one.\n")
            inner = self.qpot_comma()
            if self.qpot_peek() != ")":
                raise QpotFindStop("find: invalid expression; I was expecting to find a ')' somewhere "
                                   "but did not see one.\n")
            self.qpot_at += 1
            return inner
        if word == ")":
            raise QpotFindStop("find: you have too many ')'\n")
        if word in ("-o", "-or", "-a", "-and", ","):
            raise QpotFindStop(f"find: invalid expression; you have used a binary operator '{word}' "
                               "with nothing before it.\n")
        self.qpot_at += 1
        return self.qpot_predicate(str(word))

    def qpot_arg(self, word: str) -> str:
        if self.qpot_at >= len(self.qpot_words):
            raise QpotFindStop(f"find: missing argument to `{word}'\n" if not self.qpot_busybox
                               else f"find: {word} requires an argument\n")
        self.qpot_at += 1
        return self.qpot_words[self.qpot_at - 1]

    def qpot_number(self, text: str, word: str):
        """[+-]N as (sign, N)."""
        sign, digits = (text[0], text[1:]) if text[:1] in ("+", "-") else ("", text)
        if not digits.isdigit() or len(digits) > 18:
            raise QpotFindStop(f"find: invalid argument `{text}' to `{word}'\n")
        return sign, int(digits)

    @staticmethod
    def qpot_compare(sign: str, value: float, wanted: int) -> bool:
        return value > wanted if sign == "+" else value < wanted if sign == "-" else value == wanted

    def qpot_predicate(self, word: str):
        """The test, option or action a word names, as (function of an entry, whether it starts commands)."""
        if not word.startswith("-"):
            raise QpotFindStop(f"find: paths must precede expression: `{word}'\n")
        name = word[1:] if word.startswith("--") else word
        if self.qpot_busybox and name not in QPOT_BUSYBOX_WORDS:
            raise QpotFindStop(f"find: unrecognized: {word}\n" + self.qpot_busybox_usage())
        test = self.qpot_test(name)
        if test is not None:
            if name in ("-maxdepth", "-mindepth", "-depth", "-d", "-xdev", "-mount", "-noleaf"):
                if self.qpot_first_test and self.qpot_warn and not self.qpot_busybox:
                    self.qpot_warnings.append(
                        f"find: warning: you have specified the global option {name} after the argument "
                        f"{self.qpot_first_test}, but global options are not positional, i.e., {name} affects "
                        "tests specified before it as well as those specified after it.  Please specify global "
                        "options before other arguments.\n")
            elif name not in ("-daystart", "-follow", "-warn", "-nowarn", "-regextype"):
                self.qpot_first_test = self.qpot_first_test or name
            return test, False
        action = self.qpot_action(name)
        if action is not None:
            self.qpot_acts = self.qpot_acts or name not in ("-prune", "-quit")
            self.qpot_first_test = self.qpot_first_test or name
            return action
        if name.startswith("-newer") and len(name) == 8:
            raise QpotFindStop(f"find: invalid predicate `{word}'\n")
        raise QpotFindStop(f"find: unknown predicate `{word}'\n")

    def qpot_busybox_usage(self) -> str:
        try:
            from cowrie.commands.uname import tpot_bb_usage_table
            from cowrie.core.config import CowrieConfig

            path = CowrieConfig.get("shell", "busybox_usage", fallback="")
            entry = tpot_bb_usage_table(path).get("find") if path else None
            if not entry:
                return ""
            banner = CowrieConfig.get("shell", "text_banner", fallback="BusyBox")
            return f"{banner} multi-call binary.\n\nUsage: find {entry['usage']}"
        except Exception:  # noqa: BLE001
            return ""

    def qpot_test(self, name: str):
        """A test or an option; None for what is neither."""
        always = lambda entry: True  # noqa: E731
        if name in ("-name", "-iname", "-lname", "-ilname"):
            pattern, fold = self.qpot_arg(name), name.startswith("-i")
            if fold:
                pattern = pattern.lower()
            match = fnmatch.fnmatchcase
            if name in ("-name", "-iname") and "/" in pattern and self.qpot_warn and not self.qpot_busybox:
                self.qpot_warnings.append(
                    f"find: warning: ‘{name}’ matches against basenames only, but the given pattern contains a "
                    "directory separator (‘/’), thus the expression will evaluate to false all the time.  "
                    "Did you mean ‘-wholename’?\n")
            if name in ("-lname", "-ilname"):
                def link_named(entry):
                    if entry.node[A_TYPE] != T_LINK:
                        return False
                    target = str(entry.node[A_TARGET] or "")
                    return match(target.lower() if fold else target, pattern)
                return link_named
            return lambda entry: match(entry.name.lower() if fold else entry.name, pattern)
        if name in ("-path", "-ipath", "-wholename", "-iwholename"):
            pattern, fold = self.qpot_arg(name), name.startswith("-i")
            if fold:
                pattern = pattern.lower()
            return lambda entry: fnmatch.fnmatchcase(entry.path.lower() if fold else entry.path, pattern)
        if name in ("-regex", "-iregex"):
            compiled = qpot_regex(self.qpot_arg(name), self.qpot_regex_kind, name == "-iregex")
            self.qpot_check = 64
            if compiled is None:
                return lambda entry: False
            return lambda entry: compiled.fullmatch(entry.path) is not None
        if name == "-regextype":
            kind = self.qpot_arg(name)
            if kind not in QPOT_REGEX_TYPES:
                raise QpotFindStop(f"find: Unknown regular expression type ‘{kind}’; valid types are "
                                   + ", ".join(f"‘{known}’" for known in QPOT_REGEX_TYPES) + ".\n")
            self.qpot_regex_kind = kind
            return always
        if name in ("-type", "-xtype"):
            value = self.qpot_arg(name)
            letters = value.split(",")
            if self.qpot_busybox and value not in self.QPOT_TYPES:
                raise QpotFindStop(f"find: invalid argument '{value}' to '{name}'\n")
            if not value:
                raise QpotFindStop(f"find: Arguments to {name} should contain at least one letter\n")
            if value.endswith(","):
                raise QpotFindStop(f"find: Last file type in list argument to {name} is missing, i.e., list is "
                                   "ending on: ','\n")
            for letter in letters:
                if letter[:1] not in self.QPOT_TYPES:
                    raise QpotFindStop(f"find: Unknown argument to {name}: {letter[:1]}\n")
                if len(letter) > 1:
                    raise QpotFindStop(f"find: Must separate multiple arguments to {name} using: ','\n")
            kinds = frozenset(self.QPOT_TYPES[letter] for letter in letters)
            if name == "-type":
                # a link is of type l, neither f nor d, whatever it points to (GNU find -P)
                return lambda entry: entry.node[A_TYPE] in kinds

            def pointed(entry):
                node = entry.node
                if node[A_TYPE] == T_LINK:
                    node = self.fs.getfile(entry.full) or node
                return node[A_TYPE] in kinds
            return pointed
        if name == "-perm":
            spec = self.qpot_arg(name)
            perm = self.qpot_perm(spec)
            if perm is None:
                raise QpotFindStop(f"find: invalid mode ‘{spec}’\n")
            how, bits = perm

            def permitted(entry):
                mode = int(entry.node[A_MODE] or 0) & 0o7777
                return (mode & bits == bits if how == "-" else (not bits or bool(mode & bits)) if how == "/"
                        else mode == bits)
            return permitted
        if name == "-size":
            spec = self.qpot_arg(name)
            body = spec[1:] if spec[:1] in ("+", "-") else spec
            unit = body[-1:] if body[-1:] and not body[-1:].isdigit() else "b"
            digits = body[:-1] if body[-1:] and not body[-1:].isdigit() else body
            sizes = {"c": 1, "w": 2, "b": 512, "k": 1024, "M": 1 << 20, "G": 1 << 30}
            if unit not in sizes:
                raise QpotFindStop(f"find: invalid -size type `{unit}'\n")
            if not digits.isdigit() or len(digits) > 18:
                raise QpotFindStop(f"find: invalid argument `{spec}' to `-size'\n")
            sign, wanted, per = spec[0] if spec[:1] in ("+", "-") else "", int(digits), sizes[unit]
            return lambda entry: self.qpot_compare(sign, -(-self.qpot_size(entry.node) // per), wanted)
        if name == "-empty":
            def empty(entry):
                node = entry.node
                if node[A_TYPE] == T_DIR:
                    return not node[A_CONTENTS]
                return node[A_TYPE] == T_FILE and self.qpot_size(node) == 0
            return empty
        if name in ("-user", "-group"):
            value, key, field = self.qpot_arg(name), name[1], A_UID if name == "-user" else A_GID
            number = self.qpot_ids()[key + "names"].get(value)
            if number is None:
                if not value.isdigit():
                    new = self.qpot_version() >= (4, 10, 0)
                    if name == "-user":
                        raise QpotFindStop(f"find: invalid user name or UID argument to -user: ‘{value}’\n" if new
                                           else f"find: ‘{value}’ is not the name of a known user\n")
                    raise QpotFindStop(f"find: invalid group name or GID argument to -group: ‘{value}’\n" if new
                                       else f"find: ‘{value}’ is not the name of an existing group\n")
                number = int(value)
            return lambda entry: int(entry.node[field] or 0) == number
        if name in ("-uid", "-gid"):
            sign, wanted = self.qpot_number(self.qpot_arg(name), name)
            field = A_UID if name == "-uid" else A_GID
            return lambda entry: self.qpot_compare(sign, int(entry.node[field] or 0), wanted)
        if name in ("-nouser", "-nogroup"):
            key, field = name[3], A_UID if name == "-nouser" else A_GID
            return lambda entry: int(entry.node[field] or 0) not in self.qpot_ids()[key]
        if name in ("-mtime", "-atime", "-ctime", "-mmin", "-amin", "-cmin"):
            sign, wanted = self.qpot_number(self.qpot_arg(name), name)
            which, per = name[1], 86400 if name.endswith("time") else 60
            origin = self.qpot_origin
            return lambda entry: self.qpot_compare(sign, (origin - self.qpot_time(entry, which)) // per, wanted)
        if name in ("-newer", "-anewer", "-cnewer") or (
                len(name) == 8 and name.startswith("-newer") and name[6] in "acm" and name[7] in "acmt"):
            value = self.qpot_arg(name)
            which = "m" if name == "-newer" else name[1] if len(name) == 7 else name[6]
            if len(name) == 8 and name[7] == "t":
                limit = self.qpot_date(value)
            else:
                full = self.fs.resolve_path(value, self.cwd)
                node = self.fs.getfile(full)
                if node is None:
                    raise QpotFindStop(f"find: ‘{value}’: No such file or directory\n")
                limit = self.qpot_time(QpotEntry(node, value, full, posixpath.basename(full), 0, value),
                                       "m" if len(name) != 8 else name[7])
            return lambda entry: self.qpot_time(entry, which) > limit
        if name in ("-readable", "-writable", "-executable"):
            bit = {"-readable": 4, "-writable": 2, "-executable": 1}[name]
            return lambda entry: self.qpot_access(entry.node, bit)
        if name == "-links":
            sign, wanted = self.qpot_number(self.qpot_arg(name), name)
            return lambda entry: self.qpot_compare(sign, self.qpot_links(entry.node), wanted)
        if name == "-inum":
            sign, wanted = self.qpot_number(self.qpot_arg(name), name)
            return lambda entry: self.qpot_compare(sign, self.qpot_inode(entry), wanted)
        if name == "-samefile":
            value = self.qpot_arg(name)
            node = self.fs.getfile(self.fs.resolve_path(value, self.cwd))
            if node is None:
                raise QpotFindStop(f"find: ‘{value}’: No such file or directory\n")
            return lambda entry: entry.node is node
        if name in ("-fstype", "-context", "-used"):
            self.qpot_arg(name)
            return (lambda entry: False) if name != "-fstype" else always
        if name == "-true":
            return always
        if name == "-false":
            return lambda entry: False
        if name in ("-maxdepth", "-mindepth"):
            value = self.qpot_arg(name)
            if not value.isdigit() or len(value) > 9:
                raise QpotFindStop(f"find: Expected a positive decimal integer argument to {name}, "
                                   f"but got ‘{value}’\n" if not self.qpot_busybox
                                   else f"find: invalid number '{value}'\n")
            if name == "-maxdepth":
                self.maxdepth = int(value)
            else:
                self.qpot_mindepth = int(value)
            return always
        if name in ("-depth", "-d"):
            self.qpot_depth_first = True
            return always
        if name == "-daystart":
            clock = time.localtime(self.qpot_now)
            self.qpot_origin = self.qpot_now - (clock.tm_hour * 3600 + clock.tm_min * 60 + clock.tm_sec) + 86400
            return always
        if name in ("-xdev", "-mount", "-noleaf", "-follow", "-warn", "-nowarn", "-ignore_readdir_race",
                    "-noignore_readdir_race"):
            return always
        return None

    def qpot_action(self, name: str):
        """An action, as (function of an entry, whether it starts commands); None for what is none."""
        if name == "-print":
            return self.qpot_printer("\n"), False
        if name == "-print0":
            return self.qpot_printer("\0"), False
        if name == "-ls":
            return (lambda entry: self.qpot_emit(self.qpot_ls_line(entry)) or True), False
        if name == "-printf":
            parts = self.qpot_format(self.qpot_arg(name))
            return (lambda entry: self.qpot_emit(self.qpot_formatted(parts, entry)) or True), False
        if name in ("-fprint", "-fprint0", "-fls", "-fprintf"):
            target = self.qpot_arg(name)
            path = self.fs.resolve_path(target, self.cwd)
            if not self.fs.isdir(posixpath.dirname(path) or "/") or self.fs.isdir(path):
                raise QpotFindStop(f"find: ‘{target}’: "
                                   f"{'Is a directory' if self.fs.isdir(path) else 'No such file or directory'}\n")
            out = self.qpot_files.setdefault(path, [])
            if name == "-fprintf":
                parts = self.qpot_format(self.qpot_arg(name))
                return (lambda entry: out.append(self.qpot_formatted(parts, entry)) or True), False
            if name == "-fls":
                return (lambda entry: out.append(self.qpot_ls_line(entry)) or True), False
            end = "\n" if name == "-fprint" else "\0"
            return (lambda entry: out.append(entry.path + end) or True), False
        if name == "-prune":
            def prune(entry):
                self.qpot_pruned = True
                return True
            return prune, False
        if name == "-quit":
            def quit_now(entry):
                raise QpotFindQuit
            return quit_now, False
        if name == "-delete":
            self.qpot_depth_first = True
            return self.qpot_delete, False
        if name in ("-exec", "-execdir", "-ok", "-okdir"):
            return self.qpot_exec_action(name)
        if name == "-help":
            raise QpotFindStop(QPOT_HELP, out=True)
        if name == "-version":
            version = self.qpot_version()
            year = {(4, 7): 2019, (4, 8): 2021, (4, 9): 2022}.get(version[:2], 2024)
            raise QpotFindStop(
                f"find (GNU findutils) {'.'.join(map(str, version))}\n"
                f"Copyright (C) {year} Free Software Foundation, Inc.\n"
                "License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.\n"
                "This is free software: you are free to change and redistribute it.\n"
                "There is NO WARRANTY, to the extent permitted by law.\n\n"
                "Written by Eric B. Decker, James Youngman, and Kevin Dalley.\n"
                "Features enabled: D_TYPE O_NOFOLLOW(enabled) LEAF_OPTIMISATION FTS(FTS_CWDFD) "
                f"CBO(level={1 if version >= (4, 10, 0) else 2}) \n", out=True)
        return None

    def qpot_printer(self, end: str):
        return lambda entry: self.qpot_emit(entry.path + end) or True

    def qpot_exec_action(self, name: str):
        words = self.qpot_words
        begin, end = self.qpot_at, self.qpot_at
        while end < len(words) and words[end] != ";" and not (
                words[end] == "+" and end > begin and words[end - 1] == "{}"):
            end += 1
        if end >= len(words) or end == begin:
            raise QpotFindStop(f"find: missing argument to `{name}'\n")
        plus = words[end] == "+"
        argv = list(words[begin:end])
        self.qpot_at = end + 1
        there = name in ("-execdir", "-okdir")
        if name in ("-ok", "-okdir"):
            def asked(entry):
                # the question goes to the terminal and no answer is read here: as one that is not "y"
                self.qpot_flush()
                self.errorWrite(f"< {argv[0]} ... {'./' + entry.name if there else entry.path} > ? ")
                return False
            return asked, False
        if plus:
            if any("{}" in arg for arg in argv[:-1]):
                raise QpotFindStop(f"find: Only one instance of {{}} is supported with {name} ... +\n")
            action = {"argv": argv[:-1], "paths": [], "cwd": None}
            self.qpot_plus.append(action)

            def gathered(entry):
                if there:
                    # one command line per folder
                    folder = posixpath.dirname(entry.full.rstrip("/")) or "/"
                    if action["cwd"] not in (None, folder):
                        yield from self.qpot_exec_batches(action)
                    action["cwd"] = folder
                    action["paths"].append("./" + entry.name)
                else:
                    action["paths"].append(entry.path)
                return True
            return gathered, True

        def ran(entry):
            if self.qpot_execs >= self.QPOT_FIND_EXECS:
                raise QpotFindQuit  # a departure: real find has no cap on the commands it starts
            self.qpot_execs += 1
            shown = "./" + entry.name if there else entry.path
            cwd = (posixpath.dirname(entry.full.rstrip("/")) or "/") if there else self.cwd
            status = yield ([arg.replace("{}", shown) for arg in argv], cwd)
            return status == 0
        return ran, True

    # --- what a test reads of a file ---

    @staticmethod
    def qpot_size(node) -> int:
        if node[A_TYPE] == T_LINK:
            return len(str(node[A_TARGET] or ""))
        if node[A_TYPE] == T_DIR:
            return int(node[A_SIZE] or 0) or 4096
        return int(node[A_SIZE] or 0)

    @staticmethod
    def qpot_links(node) -> int:
        if node[A_TYPE] != T_DIR or not isinstance(node[A_CONTENTS], list):
            return 1
        return 2 + sum(1 for child in node[A_CONTENTS] if child[A_TYPE] == T_DIR)

    def qpot_file_state(self):
        """Where the connection keeps the times and inodes stat has shown (coreutils.py), or None."""
        if not self.qpot_state_seen:
            state = None
            try:
                from cowrie.commands.coreutils import qpot_track_files

                state = qpot_track_files(self.protocol)
                if state is not None and state.installed is None:
                    state.record("/", self.fs.getfile("/"))
            except Exception:  # noqa: BLE001
                state = None
            self.qpot_state_seen.append(state)
        return self.qpot_state_seen[0]

    def qpot_time(self, entry: QpotEntry, which: str = "m", exact: bool = False) -> float:
        """The file's time as stat shows it. No record is kept for a file only find has looked at: a
        walk of the whole tree would keep one for each of its files."""
        raw = float(entry.node[A_CTIME] or 0)
        state = self.qpot_file_state()
        if state is None:
            return raw
        found = state.records.get(id(entry.node))
        if found is not None:
            return float(found[{"m": "modify", "a": "access", "c": "change"}.get(which, "modify")])
        installed = float(state.installed or 0)
        if which == "m" and (not exact or raw < installed):
            return raw
        seed = int(hashlib.sha256(f"{state.hostname}|{entry.full}".encode()).hexdigest()[:12], 16)
        if raw < installed:
            return installed + (seed % 600) + (seed % 999999937) / 1e9
        return raw + (seed % 999999937) / 1e9 if raw == int(raw) else raw

    def qpot_inode(self, entry: QpotEntry) -> int:
        state = self.qpot_file_state()
        found = state.records.get(id(entry.node)) if state is not None else None
        if found is not None:
            return int(found["inode"])
        if entry.full == "/":
            return 2
        return 131072 + int(hashlib.sha256(entry.full.encode()).hexdigest()[:8], 16) % 2000000

    def qpot_date(self, text: str) -> float:
        value = text.strip()
        if value.startswith("@") and value[1:].replace(".", "", 1).isdigit():
            return float(value[1:])
        for form in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d", "%Y/%m/%d",
                     "%Y%m%d", "%d %b %Y", "%b %d %Y", "%b %d, %Y"):
            try:
                return time.mktime(time.strptime(value, form))
            except (ValueError, OverflowError):
                continue
        words = value.lower().split()
        steps = {"second": 1, "minute": 60, "hour": 3600, "day": 86400, "week": 604800, "month": 2629746,
                 "year": 31556952}
        if value.lower() in ("now", "today"):
            return self.qpot_now
        if value.lower() == "yesterday":
            return self.qpot_now - 86400
        if len(words) == 3 and words[0].isdigit() and words[1].rstrip("s") in steps and words[2] == "ago":
            return self.qpot_now - int(words[0]) * steps[words[1].rstrip("s")]
        raise QpotFindStop(f"find: I cannot figure out how to interpret ‘{text}’ as a date or time\n")

    def qpot_ids(self) -> dict:
        """The persona's users and groups: {"u": ids, "g": ids, "unames": name to id, "gnames": ...}."""
        if self.qpot_tables is None:
            tables: dict = {"u": {}, "g": {}, "unames": {}, "gnames": {}}
            for key, name in (("u", "/etc/passwd"), ("g", "/etc/group")):
                try:
                    text = self.fs.file_contents(name)[:1 << 20].decode("utf-8", "replace")
                except Exception:  # noqa: BLE001 - a tree without the file: only numbers are known
                    continue
                for line in text.splitlines():
                    fields = line.split(":")
                    if len(fields) > 2 and fields[2].isdigit():
                        tables[key].setdefault(int(fields[2]), fields[0])
                        tables[key + "names"].setdefault(fields[0], int(fields[2]))
            for key in ("u", "g"):
                tables[key].setdefault(0, "root")
                tables[key + "names"].setdefault("root", 0)
            self.qpot_tables = tables
        return self.qpot_tables

    def qpot_access(self, node, bit: int) -> bool:
        mode = int(node[A_MODE] or 0)
        user = getattr(self, "user", None) or {}
        uid = int(user.get("uid", 0) or 0)
        if uid == 0:
            return bit != 1 or node[A_TYPE] == T_DIR or bool(mode & 0o111)
        if int(node[A_UID] or 0) == uid:
            return bool(mode & (bit << 6))
        if int(node[A_GID] or 0) == int(user.get("gid", -1) or 0):
            return bool(mode & (bit << 3))
        return bool(mode & bit)

    # --- -ls and -printf ---

    def qpot_mode_text(self, node) -> str:
        mode = int(node[A_MODE] or 0)
        text = {T_DIR: "d", T_LINK: "l", tree_fs.T_BLK: "b", tree_fs.T_CHR: "c", tree_fs.T_SOCK: "s",
                tree_fs.T_FIFO: "p"}.get(node[A_TYPE], "-")
        for shift, special, low, high in ((6, 0o4000, "s", "S"), (3, 0o2000, "s", "S"), (0, 0o1000, "t", "T")):
            bits = mode >> shift & 7
            execute = "x" if bits & 1 else "-"
            if mode & special:
                execute = low if bits & 1 else high
            text += ("r" if bits & 4 else "-") + ("w" if bits & 2 else "-") + execute
        return text

    def qpot_blocks(self, node) -> int:
        """The file's size on disk in 1K blocks, as ext4 gives it."""
        if node[A_TYPE] == T_LINK:
            return 0 if len(str(node[A_TARGET] or "")) < 60 else 4
        return -(-self.qpot_size(node) // 4096) * 4

    def qpot_owner(self, node, key: str) -> str:
        number = int(node[A_UID if key == "u" else A_GID] or 0)
        return self.qpot_ids()[key].get(number, str(number))

    def qpot_ls_line(self, entry: QpotEntry) -> str:
        node = entry.node
        stamp = self.qpot_time(entry, exact=True)
        clock = time.localtime(stamp)
        when = (time.strftime("%b %e %H:%M", clock) if self.qpot_now - QPOT_HALF_YEAR < stamp < self.qpot_now + 3600
                else time.strftime("%b %e  %Y", clock))
        link = f" -> {node[A_TARGET]}" if node[A_TYPE] == T_LINK else ""
        return (f"{self.qpot_inode(entry):9d} {self.qpot_blocks(node):6d} {self.qpot_mode_text(node)} "
                f"{self.qpot_links(node):3d} {self.qpot_owner(node, 'u'):<8} {self.qpot_owner(node, 'g'):<8} "
                f"{self.qpot_size(node):8d} {when} {entry.path}{link}\n")

    def qpot_format(self, text: str) -> list:
        """-printf's format as a list of strings and (directive, letter) pairs; the list ends at \\c."""
        parts: list = []
        escapes = {"n": "\n", "t": "\t", "\\": "\\", "a": "\a", "b": "\b", "f": "\f", "r": "\r", "v": "\v"}
        i, plain = 0, []

        def literal():
            if plain:
                parts.append("".join(plain))
                plain.clear()

        while i < len(text):
            char = text[i]
            i += 1
            if char == "\\" and i < len(text):
                nxt = text[i]
                if nxt == "c":
                    literal()
                    parts.append(None)
                    return parts
                if nxt in "01234567":
                    digits = re.match(r"[0-7]{1,3}", text[i:])[0]
                    plain.append(chr(int(digits, 8)))
                    i += len(digits)
                    continue
                i += 1
                if nxt in escapes:
                    plain.append(escapes[nxt])
                else:
                    self.errorWrite(f"find: warning: unrecognized escape `\\{nxt}'\n")
                    plain.append("\\" + nxt)
                continue
            if char != "%" or i >= len(text):
                plain.append(char)
                continue
            found = re.match(r"([-+ #0]*\d*(?:\.\d+)?)([A-Za-z%])", text[i:])
            if not found:
                plain.append(char)
                continue
            flags, letter = found[1], found[2]
            i += len(found[0])
            if letter == "%":
                plain.append("%")
                continue
            sub = ""
            if letter in "ACT" and i < len(text):
                sub = text[i]
                i += 1
            if letter not in "abcdfgGhHiklmMnpPsStuUyYACT":
                self.errorWrite(f"find: warning: unrecognized format directive `%{letter}'\n")
                plain.append("%" + flags + letter)
                continue
            literal()
            parts.append((flags, letter, sub))
        literal()
        return parts

    def qpot_stamp(self, stamp: float, sub: str) -> str:
        clock = time.localtime(stamp)
        fraction = f"{stamp - int(stamp):.10f}"[1:]
        if sub == "@":
            return f"{int(stamp)}{fraction}"
        if sub == "+":
            return time.strftime("%Y-%m-%d+%H:%M:%S", clock) + fraction
        if sub == "full":
            return time.strftime("%a %b %e %H:%M:%S", clock) + fraction + time.strftime(" %Y", clock)
        if sub == "c":
            return time.strftime("%a %b %e %H:%M:%S %Y", clock)
        if sub == "S":
            return time.strftime("%S", clock) + fraction
        if sub == "T":
            return time.strftime("%H:%M:%S", clock) + fraction
        if sub in "aAbBdDeFhHIjklmMprRuUVwWxXyYZ":
            return time.strftime("%" + sub, clock)
        return ""

    def qpot_formatted(self, parts: list, entry: QpotEntry) -> str:
        node, out = entry.node, []
        for part in parts:
            if part is None:
                break
            if isinstance(part, str):
                out.append(part)
                continue
            flags, letter, sub = part
            if letter == "p":
                value = entry.path
            elif letter == "f":
                value = entry.name
            elif letter == "h":
                value = "" if entry.path == "/" else posixpath.dirname(entry.path.rstrip("/")) or "."
            elif letter == "H":
                value = entry.start
            elif letter == "P":
                value = entry.path[len(entry.start):].lstrip("/")
            elif letter == "s":
                value = self.qpot_size(node)
            elif letter == "k":
                value = self.qpot_blocks(node)
            elif letter == "b":
                value = self.qpot_blocks(node) * 2
            elif letter == "S":
                value = "1"
            elif letter == "u":
                value = self.qpot_owner(node, "u")
            elif letter == "g":
                value = self.qpot_owner(node, "g")
            elif letter == "U":
                value = int(node[A_UID] or 0)
            elif letter == "G":
                value = int(node[A_GID] or 0)
            elif letter == "m":
                value = f"{int(node[A_MODE] or 0) & 0o7777:o}"
            elif letter == "M":
                value = self.qpot_mode_text(node)
            elif letter in "yY":
                kind = node
                if letter == "Y" and node[A_TYPE] == T_LINK:
                    kind = self.fs.getfile(entry.full)
                value = "N" if kind is None else next(
                    (key for key, code in self.QPOT_TYPES.items() if code == kind[A_TYPE]), "U")
            elif letter == "d":
                value = entry.depth
            elif letter == "n":
                value = self.qpot_links(node)
            elif letter == "i":
                value = self.qpot_inode(entry)
            elif letter == "l":
                value = str(node[A_TARGET] or "") if node[A_TYPE] == T_LINK else ""
            elif letter in "act":
                value = self.qpot_stamp(self.qpot_time(entry, {"t": "m"}.get(letter, letter), True), "full")
            else:
                value = self.qpot_stamp(self.qpot_time(entry, {"T": "m", "A": "a", "C": "c"}[letter], True), sub)
            text = str(value)
            if flags:
                width = re.search(r"\d+", flags)
                if width and len(width[0]) < 5:
                    text = text.ljust(int(width[0])) if "-" in flags else text.rjust(int(width[0]))
            out.append(text)
        return "".join(out)

    # --- actions that change the tree ---

    def qpot_delete(self, entry: QpotEntry) -> bool:
        node = entry.node
        why = ""
        if entry.depth == 0 and entry.path in (".", "/"):
            return True
        if node[A_TYPE] == T_DIR and node[A_CONTENTS]:
            why = "Directory not empty"
        else:
            try:
                if node[A_TYPE] == T_DIR:
                    self.fs.rmdir(entry.full)
                else:
                    self.fs.remove(entry.full)
            except PermissionError:
                why = "Permission denied"
            except Exception:  # noqa: BLE001 - a tree that cannot be written to
                why = "Read-only file system"
        if why:
            self.qpot_error(f"find: cannot delete ‘{entry.path}’: {why}\n")
            return False
        return True

    def qpot_save(self, path: str, text: str) -> None:
        """What -fprint and its kin wrote, as a file of the tree."""
        import stat as stat_mod

        data = text.encode("utf-8", "surrogateescape")
        user = getattr(self, "user", None) or {}
        try:
            if self.fs.exists(path):
                self.fs.remove(path)
            self.fs.mkfile(path, int(user.get("uid", 0) or 0), int(user.get("gid", 0) or 0), len(data),
                           stat_mod.S_IFREG | 0o644, time.time())
            self.fs.getfile(path)[A_CONTENTS] = data
        except Exception:  # noqa: BLE001 - a place nothing can be written to
            self.qpot_status = 1

    @staticmethod
    def qpot_perm(spec: str) -> tuple[str, int] | None:
        """-perm's mode: ("-", bits) all of them set, ("/", bits) any, ("=", bits) exactly; octal or
        symbolic (u=s, -g=s, /u=s,g=s, u=rwx,go=rx) as GNU find reads it; None for no mode."""
        how, body = ("-", spec[1:]) if spec.startswith("-") else ("/", spec[1:]) if spec.startswith("/") else ("=", spec)
        if not body or len(body) > 64:
            return None
        if body.isdigit():
            return (how, int(body, 8)) if all(c in "01234567" for c in body) and len(body) <= 4 else None
        bits = 0
        for clause in body.split(","):
            who, i = "", 0
            while i < len(clause) and clause[i] in "ugoa":
                who, i = who + clause[i], i + 1
            if i >= len(clause) or clause[i] not in "=+-":
                return None
            who = who or "a"
            if "a" in who:
                who = "ugo"
            while i < len(clause) and clause[i] in "=+-":
                op, i = clause[i], i + 1
                perms = ""
                while i < len(clause) and clause[i] in "rwxXst":
                    perms, i = perms + clause[i], i + 1
                value = 0
                for w in who:
                    shift = {"u": 6, "g": 3, "o": 0}[w]
                    mask = 0o7 << shift | {"u": 0o4000, "g": 0o2000, "o": 0o1000}[w]
                    part = 0
                    for p in perms:
                        part |= {"r": 4 << shift, "w": 2 << shift, "x": 1 << shift, "X": 1 << shift,
                                 "s": {"u": 0o4000, "g": 0o2000, "o": 0}[w], "t": 0o1000 if w == "o" else 0}[p]
                    if op == "=":
                        bits &= ~mask
                    value |= part
                bits = bits & ~value if op == "-" else bits | value
            if i != len(clause):
                return None
        return how, bits


commands["find"] = Command_find
commands["/bin/find"] = Command_find
commands["/usr/bin/find"] = Command_find
