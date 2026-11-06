# SPDX-FileCopyrightText: 2025 Onder7994
# SPDX-FileCopyrightText: 2025-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""
find command
"""

from __future__ import annotations

import fnmatch
import posixpath
import time

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import A_CONTENTS, A_MODE, A_NAME, A_TYPE, T_DIR, T_FILE, T_LINK

commands = {}


class Command_find(HoneyPotCommand):
    """
    find command
    """

    # QPot: GNU find does not follow symbolic links (-P, its default), so its walk ends. The image's
    #   find descended into every link to a directory (/usr/bin/X11 -> ., /proc/self/root -> /) down
    #   to depth 20, resolving each path from the root: `find / -name id_rsa`, the first thing a
    #   credential harvester runs, held Cowrie's reactor and with it every session for many minutes.
    #   The walk now goes over the tree's nodes, enters no link and stops after QPOT_FIND_MAX entries
    #   or QPOT_FIND_SECONDS, whichever comes first. Several starting points (find /root /home ...),
    #   -iname, -type l and -print are taken as GNU find takes them.
    QPOT_FIND_MAX = 200000
    QPOT_FIND_SECONDS = 2.0
    QPOT_TYPES = {"f": T_FILE, "d": T_DIR, "l": T_LINK}

    def start(self) -> None:
        self.maxdepth: int = 20
        self.name_pattern = None
        self.type_filter = None
        self.qpot_names: list[tuple[str, bool]] = []
        self.qpot_perms: list[tuple[str, int]] = []

        self.start_path = self.cwd
        qpot_paths: list[str] = []

        idx = 0
        while idx < len(self.args):
            arg = self.args[idx]

            if arg in ("-name", "-iname"):
                idx += 1
                if idx >= len(self.args):
                    self.errorWrite(f"find: missing argument to `{arg}'\n")
                    self.exit()
                    return
                self.name_pattern = self.args[idx]
                self.qpot_names.append((self.args[idx], arg == "-iname"))

            elif arg == "-type":
                idx += 1
                if idx >= len(self.args):
                    self.errorWrite("find: missing argument to `-type'\n")
                    self.exit()
                    return
                val = self.args[idx]
                if val in self.QPOT_TYPES:
                    self.type_filter = val
                else:
                    self.errorWrite(f"find: Unknown argument to -type: {val}\n")
                    self.exit()
                    return

            elif arg == "-maxdepth":
                idx += 1
                if idx >= len(self.args):
                    self.errorWrite("find: missing argument to `-maxdepth'\n")
                    self.exit()
                    return
                try:
                    self.maxdepth = int(self.args[idx])
                except ValueError:
                    self.errorWrite("find: maxdepth must be an integer\n")
                    self.exit()
                    return

            elif arg == "-print":
                pass

            elif arg == "-perm":
                idx += 1
                if idx >= len(self.args):
                    self.errorWrite("find: missing argument to `-perm'\n")
                    self.exit()
                    return
                perm = self.qpot_perm(self.args[idx])
                if perm is None:
                    self.errorWrite(f"find: invalid mode ‘{self.args[idx]}’\n")
                    self.exit()
                    return
                self.qpot_perms.append(perm)

            elif ((arg == "-" or not arg.startswith("-")) and not self.qpot_names and not self.qpot_perms
                  and self.type_filter is None):
                # the starting points come before the expression
                qpot_paths.append(arg)

            else:
                self.errorWrite(f"find: unknown predicate `{arg}'\n")
                self.exit()
                return

            idx += 1

        self.qpot_left = self.QPOT_FIND_MAX
        self.qpot_deadline = time.monotonic() + self.QPOT_FIND_SECONDS
        for arg in qpot_paths or ["."]:
            self.start_path = self.fs.resolve_path(arg, self.cwd)
            node = self.fs.getfile(self.start_path, follow_symlinks=False)
            if node is None:
                self.errorWrite(f"find: ‘{arg}’: No such file or directory\n")
                continue
            self.qpot_walk(node, arg, 0, posixpath.basename(arg.rstrip("/")) or "/")
            if self.qpot_left < 0:
                break
        self.exit()

    def qpot_walk(self, node: list, path: str, depth: int, name: str) -> None:
        """Visit node (at path, named name, depth levels below a starting point) and what is below it."""
        self.qpot_left -= 1
        if self.qpot_left < 0 or (self.qpot_left % 1024 == 0 and time.monotonic() > self.qpot_deadline):
            self.qpot_left = -1
            return
        if self.qpot_match(node, name):
            self.write(f"{path}\n")
        if depth >= self.maxdepth or node[A_TYPE] != T_DIR or not isinstance(node[A_CONTENTS], list):
            return
        prefix = path if path.endswith("/") else path + "/"
        for child in list(node[A_CONTENTS]):
            if self.qpot_left < 0:
                return
            name = str(child[A_NAME])
            if name in (".", ".."):
                continue
            self.qpot_walk(child, prefix + name, depth + 1, name)

    def qpot_match(self, node: list, basename: str) -> bool:
        for pattern, fold in self.qpot_names:
            if fold:
                if not fnmatch.fnmatchcase(basename.lower(), pattern.lower()):
                    return False
            elif not fnmatch.fnmatchcase(basename, pattern):
                return False
        # a link is of type l, neither f nor d, whatever it points to (GNU find -P)
        if self.type_filter is not None and node[A_TYPE] != self.QPOT_TYPES[self.type_filter]:
            return False
        mode = int(node[A_MODE] or 0) & 0o7777
        for how, bits in self.qpot_perms:
            if how == "-" and mode & bits != bits or how == "/" and bits and not mode & bits or how == "=" and mode != bits:
                return False
        return True

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

    def _match(self, path: str) -> bool:
        node = self.fs.getfile(path, follow_symlinks=False)
        return node is not None and self.qpot_match(node, posixpath.basename(path.rstrip("/")) or "/")


commands["find"] = Command_find
commands["/bin/find"] = Command_find
