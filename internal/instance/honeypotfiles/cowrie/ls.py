# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2015-2025 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import getopt
import posixpath
import re
import stat
import time

from cowrie.core.config import CowrieConfig
from cowrie.shell import fs
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.pwd import Group, Passwd

commands = {}

# QPot: GNU ls's half year (ls.c: a timestamp older than this, or in the future, shows its year)
QPOT_HALF_YEAR = 31556952 // 2


def qpot_ls_time(stamp: float, now: float) -> str:
    """The time column of GNU ls -l in the C and English locales: month, day and time for the last half
    year, month, day and year otherwise (ISO dates are --time-style=long-iso's, not the default)."""
    clock = time.localtime(stamp)
    if now - QPOT_HALF_YEAR < stamp < now:
        return time.strftime("%b %e %H:%M", clock)
    return time.strftime("%b %e  %Y", clock)


def qpot_root_size(node: list, path: str) -> list:
    """A copy of a node to list: the tree's / has no size in Cowrie's trees, where ext4's root folder
    takes a block (4096), as stat shows it."""
    if path == "/" and node[fs.A_TYPE] == fs.T_DIR and not node[fs.A_SIZE]:
        node[fs.A_SIZE] = 4096
    return node


def qpot_human(size: int) -> str:
    """-h of GNU ls (human_readable of gnulib's human.c, rounding up): powers of 1024, one decimal below
    10, 1023.9K shown as 1.0M."""
    amount, tenths, rounding, exponent = max(int(size), 0), 0, 0, 0
    if amount < 1024:
        return str(amount)
    while True:
        r10 = (amount % 1024) * 10 + tenths
        r2 = (r10 % 1024) * 2 + (rounding >> 1)
        amount //= 1024
        tenths = r10 // 1024
        rounding = int(r2 + rounding != 0) if r2 < 1024 else 2 + int(1024 < r2 + rounding)
        exponent += 1
        if amount < 1024 or exponent >= 8:
            break
    point = ""
    if amount < 10:
        if rounding:
            tenths, rounding = tenths + 1, 0
            if tenths == 10:
                amount, tenths = amount + 1, 0
        if amount < 10:
            point, tenths, rounding = f".{tenths}", 0, 0
    if tenths + rounding:
        amount += 1
        if amount == 1024 and exponent < 8:
            amount, exponent, point = 1, exponent + 1, ".0"
    return f"{amount}{point}{'KMGTPEZY'[exponent - 1]}"


# the work one ls -C or -x may spend choosing its columns (names measured and columns summed, the columns
#   tried from the most down): a terminal of any width over the largest folder of a persona stays far
#   below it; past it the names are listed one per line
QPOT_COLUMNS_BUDGET = 1 << 21
# the quotes of GNU ls's quote() in the persona's UTF-8 locale
QPOT_LQ, QPOT_RQ = chr(0x2018), chr(0x2019)


def qpot_indent(start: int, end: int, tabsize: int) -> str:
    """indent() of ls.c: from column start to end, a tab while a tab stop is passed, then blanks."""
    tabs = []
    while tabsize and end // tabsize > (start + 1) // tabsize:
        tabs.append("\t")
        start += tabsize - start % tabsize
    return "".join(tabs) + " " * (end - start)


def qpot_columns(names: list[str], width: int, across: bool = False, tabsize: int = 8) -> str:
    """GNU ls -C (print_many_per_line) or -x (print_horizontal): the most columns that fit the line (width
    0: no limit), filled top to bottom (-x: across), each as wide as its longest name and two blanks (none
    after the last), the gaps filled by indent(). The column counts are tried from the most down and each
    stops once its line is too long (-C needs only the counts whose rows leave no column empty: an empty
    one only widens the line); past QPOT_COLUMNS_BUDGET of work the names go one per line."""
    count = len(names)
    if not count:
        return ""
    lengths = [len(name) for name in names]
    # no limit: one line, and blanks only (recorded from 9.7: -w 0, COLUMNS=0, a width too large)
    limit = width if width > 0 else sum(lengths) + 2 * count + 1
    tabsize = tabsize if width > 0 else 0
    budget, cols, widths = QPOT_COLUMNS_BUDGET, 1, [max(lengths)]
    longest, shortest, before = max(lengths), min(lengths), [0]
    for size in lengths:
        before.append(before[-1] + size)
    for tried in range(min(count, max(limit // 3, 1)), 1, -1):
        rows = -(-count // tried)
        if not across and -(-count // rows) != tried:
            budget -= 1
            continue
        if across:
            # -x: what the line needs at least (each row's names stand in columns of their own, the
            #   longest name's column beside the rest): a count past the line is passed over at once
            budget -= rows
            least = longest + (tried - 1) * (shortest + 2)
            for row in range(rows):
                start, end = row * tried, min(row * tried + tried, count)
                least = max(least, before[end] - before[start] + (tried - end + start) * shortest + 2 * tried - 2)
            if least >= limit:
                if budget < 0:
                    break
                continue
        sizes, line = [], -2
        for col in range(tried):
            piece = lengths[col::tried] if across else lengths[col * rows:(col + 1) * rows]
            budget -= len(piece) + 1
            longest = max(piece)
            sizes.append(longest + (0 if col == tried - 1 else 2))
            line += longest + 2
            if line >= limit:
                break
        if line < limit and len(sizes) == tried:
            cols, widths = tried, sizes
            break
        if budget < 0:
            break
    rows = -(-count // cols)
    out = []
    for row in range(rows):
        line, pos = [], 0
        for col in range(cols):
            index = row * cols + col if across else col * rows + row
            if index >= count:
                break
            line.append(names[index])
            following = index + 1 if across else index + rows
            if col == cols - 1 or following >= count:
                break
            line.append(qpot_indent(pos + lengths[index], pos + widths[col], tabsize))
            pos += widths[col]
        out.append("".join(line) + "\n")
    return "".join(out)


def qpot_size_arg(text: str, overflow: int | None = 0) -> int | None:
    """A width (decode_line_length of ls.c) or tab size as GNU ls reads it: blanks and a + first, then a
    number in base 0 (0x hex, 0 octal, else decimal); one too large for ptrdiff_t gives overflow (a width:
    0, no limit); None for anything else."""
    text = text.lstrip(" \t\n\v\f\r")
    text = text[1:] if text[:1] == "+" else text
    digits, base = text, 10
    if text[:2] in ("0x", "0X"):
        digits, base = text[2:], 16
    elif text[:1] == "0" and len(text) > 1:
        digits, base = text[1:], 8
    allowed = "0123456789abcdefABCDEF"[: base if base < 16 else 22]
    if not digits or any(c not in allowed for c in digits):
        return None
    significant = digits.lstrip("0") or "0"
    if len(significant) > 64:
        return overflow
    value = int(significant, base)
    return value if value < 1 << 63 else overflow


def qpot_bb_columns(names: list[str], width: int, across: bool) -> str:
    """BusyBox ls -C (display_files of coreutils/ls.c, recorded from 1.37): columns two blanks wider than
    the longest name, as many as the width holds (at least one), filled top to bottom (-x: across); a name
    is padded to its column only when another follows it on the line."""
    count = len(names)
    if not count:
        return ""
    column = max(len(name) for name in names) + 2
    cols = max(1, min(width // column, count))
    rows = -(-count // cols)
    out = []
    for row in range(rows):
        picked = [names[i] for i in ((row * cols + col if across else col * rows + row) for col in range(cols))
                  if i < count]
        out.append("".join(name.ljust(column) for name in picked[:-1]) + picked[-1] + "\n")
    return "".join(out)


QPOT_ATOI = re.compile(r"[ \t\n\v\f\r]*([+-]?)([0-9]*)")


def qpot_atoi(text: str) -> int:
    """atoi as glibc gives it (strtol, cut to an int): blanks, a sign and decimal digits, the rest ignored
    (recorded from BusyBox 1.37 on COLUMNS: " 37", "37x", "+37" and 2**32+37 read as 37)."""
    match = QPOT_ATOI.match(text[:4096])
    digits = match.group(2).lstrip("0")
    value = int(digits or "0") if len(digits) <= 19 else 1 << 63
    value = -value if match.group(1) == "-" else value
    value = max(min(value, (1 << 63) - 1), -(1 << 63)) & 0xFFFFFFFF
    return value - (1 << 32) if value >= 1 << 31 else value


# QPot: the long options of GNU ls that name a short one this ls has (and those it reads)
QPOT_LS_LONG = {"--all": "-a", "--almost-all": "-A", "--directory": "-d", "--human-readable": "-h",
                "--inode": "-i", "--reverse": "-r", "--recursive": "-R", "--size": "-s",
                "--numeric-uid-gid": "-n", "--dereference": "-L", "--ignore-backups": "-B", "--no-group": "-G",
                "--literal": "-N", "--hide-control-chars": "-q", "--quote-name": "-Q", "--width": "-w",
                "--tabsize": "-T"}


class Command_ls(HoneyPotCommand):
    def uid2name(self, uid: int) -> str:
        try:
            name: str = Passwd().getpwuid(uid)["pw_name"]
        except Exception:
            return str(uid)
        else:
            return name

    def gid2name(self, gid: int) -> str:
        try:
            group: str = Group().getgrgid(gid)["gr_name"]
        except Exception:
            return str(gid)
        else:
            return group

    def call(self) -> None:
        path = self.cwd
        paths = []
        self.showHidden = False
        self.showDirectories = False
        self.showHumanReadable = False
        func = self.do_ls_normal

        # Parse options or display no files
        # QPot: the format the last of -l, -1, -C, -x asks for (-1 has no effect after -l), the width of -w
        #   (0: no limit) and the tab size of -T, as GNU ls decodes them
        self.qpot_format, self.qpot_width, self.qpot_tabsize = None, None, 8
        try:
            opts, args = getopt.gnu_getopt(
                self.args,
                "1@ABCFGHLOPRST:UWabcdefghiklmnopqrstuvw:x",
                ["help", "version", "param"] + [name[2:] + ("=" if name in ("--width", "--tabsize") else "")
                                                for name in QPOT_LS_LONG],
            )
        except getopt.GetoptError as err:
            self.qpot_bad_option(err)
            return
        for x, a in opts:
            x = QPOT_LS_LONG.get(x, x)
            if x == "-l":
                self.qpot_format = "long"
            elif x == "-1" and self.qpot_format != "long":
                self.qpot_format = "one"
            elif x in ("-C", "-x"):
                self.qpot_format = "columns" if x == "-C" else "across"
            elif x in ("-w", "-T") and CowrieConfig.get("shell", "ls_style", fallback="gnu") == "busybox":
                # BusyBox: -w a decimal number up to INT_MAX (xatoi_positive), -T taken and ignored
                if x == "-w":
                    digits = a.lstrip("0") or "0"
                    if not (a.isascii() and a.isdigit()) or len(digits) > 10 or int(digits) > 0xFFFFFFFF:
                        self.errorWrite(f"ls: invalid number '{a}'\n")
                        self.exit_code = 1
                        return
                    if int(digits) > 0x7FFFFFFF:
                        self.errorWrite(f"ls: number {a} is not in 0..2147483647 range\n")
                        self.exit_code = 1
                        return
                    self.qpot_width = int(digits)
            elif x in ("-w", "-T"):
                number = qpot_size_arg(a, 0 if x == "-w" else None)
                if number is None:
                    what = "line width" if x == "-w" else "tab size"
                    self.errorWrite(f"ls: invalid {what}: {QPOT_LQ}{a}{QPOT_RQ}\n")
                    self.exit_code = 2
                    return
                if x == "-w":
                    self.qpot_width = number
                else:
                    self.qpot_tabsize = number
            if x == "-h":
                self.showHumanReadable = True

            if x == "-a":
                self.showHidden = True
            if x == "-d":
                self.showDirectories = True
        if self.qpot_format == "long":
            func = self.do_ls_l
        if CowrieConfig.get("shell", "ls_style", fallback="gnu") != "busybox":
            self.qpot_gnu_width()

        # T-Pot: -l lists a link of the command line itself
        self.tpot_long = func == self.do_ls_l
        for arg in args:
            resolved = self.protocol.fs.resolve_path(arg, self.cwd)
            # bash expands ~ before ls runs, so ls names it by the expanded path
            paths.append((resolved, resolved if arg.startswith("~") else arg))

        if not paths:
            func(path, path)
        elif len(paths) == 1:
            func(*paths[0])
        else:
            self.qpot_operands(func, paths)

    def qpot_bad_option(self, err) -> None:
        """getopt_long's message for an option ls has not (or one missing its value), then ls's hint;
        status 2. BusyBox's ls gives its usage where the persona's table has it."""
        opt = err.opt or ""
        if CowrieConfig.get("shell", "ls_style", fallback="gnu") == "busybox":
            from cowrie.commands.uname import tpot_bb_usage_stop

            if tpot_bb_usage_stop(self, "ls", list(self.args)):
                return
        long = err.msg.startswith("option --")
        if "requires argument" in err.msg:
            text = f"option '--{opt}' requires an argument" if long else f"option requires an argument -- '{opt}'"
        elif "must not have an argument" in err.msg:
            text = f"option '--{opt}' doesn't allow an argument"
        else:
            text = f"unrecognized option '--{opt}'" if long else f"invalid option -- '{opt}'"
        self.errorWrite(f"ls: {text}\nTry 'ls --help' for more information.\n")
        self.exit_code = 2

    def qpot_operands(self, func, paths) -> None:
        """QPot: several operands as GNU ls lists them: the missing ones reported, the files (a link with
        -l, a folder with -d) together, then each folder under its "name:" heading, a blank line before."""
        files, dirs = [], []
        fsys = self.protocol.fs
        for path, name in paths:
            link = fsys.getfile(path, follow_symlinks=False)
            node = fsys.getfile(path)
            if node is None and link is None:
                self.errorWrite(f"ls: cannot access '{name}': No such file or directory\n")
                self.exit_code = 2
                continue
            linked = link is not None and link[fs.A_TYPE] == fs.T_LINK and getattr(self, "tpot_long", False)
            if node is not None and node[fs.A_TYPE] == fs.T_DIR and not self.showDirectories and not linked:
                dirs.append((path, name))
            else:
                node = qpot_root_size((link if linked or node is None else node)[:], path)
                node[fs.A_NAME] = name
                files.append(node)
        files.sort(key=lambda node: node[fs.A_NAME])
        dirs.sort(key=lambda item: item[1])
        if files:
            if func == self.do_ls_l:
                self.qpot_long(files)
            else:
                self.qpot_names([node[fs.A_NAME] for node in files])
        for index, (path, name) in enumerate(dirs):
            if files or index:
                self.write("\n")
            self.write(f"{name}:\n")
            func(path, name)

    def get_dir_files(self, path, name):
        try:
            link = None
            if getattr(self, "tpot_long", False):
                link = self.protocol.fs.getfile(path, follow_symlinks=False)
                if link is not None and link[fs.A_TYPE] != fs.T_LINK:
                    link = None
            if self.protocol.fs.isdir(path) and not self.showDirectories and link is None:
                files = self.protocol.fs.get_path(path)[:]
                if self.showHidden:
                    dot = qpot_root_size(self.protocol.fs.getfile(path)[:], path)
                    dot[fs.A_NAME] = "."
                    files.append(dot)
                    dotdot = qpot_root_size(self.protocol.fs.getfile(posixpath.split(path)[0])[:],
                                            posixpath.split(path)[0])
                    if not dotdot:
                        dotdot = self.protocol.fs.getfile(path)[:]
                    dotdot[fs.A_NAME] = ".."
                    files.append(dotdot)
                else:
                    files = [x for x in files if not x[fs.A_NAME].startswith(".")]
                files.sort()
            else:
                file = qpot_root_size((link or self.protocol.fs.getfile(path))[:], path)
                file[fs.A_NAME] = name
                files = [file]
        except Exception:
            self.errorWrite(f"ls: cannot access '{name}': No such file or directory\n")
            self.exit_code = 2
            return
        return files

    def do_ls_normal(self, path: str, name: str) -> None:
        files = self.get_dir_files(path, name)
        if not files:
            return

        line = [x[fs.A_NAME] for x in files]
        if not line:
            return
        self.qpot_names(line)

    def qpot_getenv(self, name: str) -> str | None:
        """A variable of the environment ls gets: one the shell exported (a plain shell variable stays in
        the shell)."""
        environ = getattr(self, "environ", None) or {}
        exported = getattr(self, "exported", None)
        if name in environ and (exported is None or name in exported):
            return str(environ[name])
        return None

    def qpot_terminal(self) -> bool:
        """stdout is the session's terminal (not a pipe, a file or an exec session's channel)."""
        targets = getattr(getattr(self, "pp", None), "targets", None) or {}
        return (targets.get(1) or ("",))[0] == "terminal" and not hasattr(self.protocol, "execcmd")

    def qpot_gnu_width(self) -> None:
        """GNU ls's line width, decided once before it lists (ls.c decode_switches), only for -C and -x:
        -w's, else the terminal's it writes to, else an exported COLUMNS (one it cannot read warned of and
        ignored), else 80 (recorded from 9.7)."""
        style = self.qpot_format or ("columns" if self.qpot_terminal() else "one")
        if style not in ("columns", "across") or self.qpot_width is not None:
            return
        if self.qpot_terminal():
            try:
                self.qpot_width = int(self.protocol.user.windowSize[1]) or None
            except (AttributeError, TypeError, ValueError, IndexError):
                self.qpot_width = None
        text = self.qpot_getenv("COLUMNS") or ""
        if self.qpot_width is None and text:
            self.qpot_width = qpot_size_arg(text)
            if self.qpot_width is None:
                self.errorWrite("ls: ignoring invalid width in environment variable COLUMNS: "
                                f"{QPOT_LQ}{text}{QPOT_RQ}\n")

    def qpot_bb_width(self) -> int:
        """BusyBox's width without -w (get_terminal_width of stdin, less one): an exported COLUMNS as atoi
        reads it, else the terminal's columns when stdin is the terminal; a value below 2 or from 30000 up
        counts as 80 (recorded from 1.37)."""
        text = self.qpot_getenv("COLUMNS")
        value = 0
        if text is not None:
            value = qpot_atoi(text)
        else:
            from cowrie.commands.base import tpot_pty

            if tpot_pty(self.protocol) and not getattr(getattr(self, "pp", None), "stdin_from_pipe", False):
                try:
                    value = int(self.protocol.user.windowSize[1])
                except (AttributeError, TypeError, ValueError, IndexError):
                    value = 0
        if value <= 1 or value >= 30000:
            value = 80
        return value - 1

    def qpot_names(self, line: list[str]) -> None:
        # T-Pot: no terminal (a pipe, a file, an exec session): one name per line; QPot: unless -C or -x
        #   asks for columns
        style = getattr(self, "qpot_format", None) or ("columns" if self.qpot_terminal() else "one")
        if style == "one":
            for f in line:
                self.write(f"{f}\n")
            return
        wincols = getattr(self, "qpot_width", None)
        if CowrieConfig.get("shell", "ls_style", fallback="gnu") == "busybox":
            # QPot: BusyBox lays its columns out as its display_files does
            wincols = self.qpot_bb_width() if wincols is None else wincols
            self.write(qpot_bb_columns(line, wincols, style == "across"))
            return
        # QPot: GNU ls fills its columns top to bottom, as wide as qpot_gnu_width found (else 80)
        wincols = 80 if wincols is None else wincols
        self.write(qpot_columns(line, wincols, style == "across", getattr(self, "qpot_tabsize", 8)))

    def tpot_bb_long(self, permstr, file, size, linktarget):
        """T-Pot: a line of BusyBox ls -l (list_single of coreutils/ls.c; recorded with BusyBox v1.19.4 of
        the Archer C7 v5): "%-10s %4u %-8.8s %-8.8s %9s", the month and day, then the time for a file of the
        last half year (up to 15 minutes ahead) or the year. A folder counts its subfolders and . and .."""
        links = 1
        if file[fs.A_TYPE] == fs.T_DIR:
            links = 2 + sum(1 for child in (file[fs.A_CONTENTS] or []) if child[fs.A_TYPE] == fs.T_DIR)
        stamp = file[fs.A_CTIME]
        age = time.time() - stamp
        clock = time.localtime(stamp)
        when = time.strftime("%b %e", clock) + (time.strftime(" %H:%M", clock) if -15 * 60 < age < 3600 * 24 * 365 / 2
                                               else time.strftime("  %Y", clock))
        user, group = self.uid2name(file[fs.A_UID]), self.gid2name(file[fs.A_GID])
        return f"{permstr} {links:4d} {user[:8]:<8} {group[:8]:<8} {size:>9} {when} {file[fs.A_NAME]}{linktarget}"

    def do_ls_l(self, path: str, name: str) -> None:
        """
        Display detailed information about files
        Mimics the output of GNU ls -l and supports the following options:
        -a, -h

        :param path: The path to list
        :param name: The path as the command line named it
        """
        files = self.get_dir_files(path, name)
        # QPot: GNU's total line for a listed folder: the 1 KiB blocks of what it lists
        gnu = CowrieConfig.get("shell", "ls_style", fallback="gnu") != "busybox"
        if files is not None and gnu and not self.showDirectories and self.protocol.fs.isdir(path):
            node = self.protocol.fs.getfile(path, follow_symlinks=False)
            if node is not None and node[fs.A_TYPE] != fs.T_LINK:
                blocks = sum(self.qpot_blocks(f) for f in files)
                self.write(f"total {qpot_human(blocks * 1024) if self.showHumanReadable else blocks}\n")
        self.qpot_long(files, path)

    @staticmethod
    def qpot_blocks(node) -> int:
        """The 1 KiB blocks a file takes, as stat's %b counts them in 4 KiB ones: a folder at least one, a
        link one when its target does not fit the inode (60 bytes), a device none."""
        size = int(node[fs.A_SIZE] or 0)
        if node[fs.A_TYPE] == fs.T_DIR:
            return max(4, -(-size // 4096) * 4)
        if node[fs.A_TYPE] == fs.T_FILE:
            return -(-size // 4096) * 4
        if node[fs.A_TYPE] == fs.T_LINK:
            return 0 if size < 60 else 4
        return 0

    @staticmethod
    def qpot_links(node) -> int:
        """The link count: a folder has . and the .. of each folder in it."""
        if node[fs.A_TYPE] == fs.T_DIR:
            children = node[fs.A_CONTENTS] if isinstance(node[fs.A_CONTENTS], list) else []
            return 2 + sum(1 for child in children if child[fs.A_TYPE] == fs.T_DIR)
        return 1

    def qpot_long(self, files, path=None) -> None:
        # T-Pot: the total line of BusyBox from 1.16 with CONFIG_DESKTOP ([shell] ls_total) for a listed folder:
        #   (1 + its 512 byte blocks) / 2, a folder and a file in 4 KiB blocks, a link none
        if (path is not None and files is not None
                and CowrieConfig.get("shell", "ls_style", fallback="gnu") == "busybox"
                and CowrieConfig.get("shell", "ls_total", fallback="no") == "yes" and not self.showDirectories
                and self.protocol.fs.isdir(path)):
            node = self.protocol.fs.getfile(path, follow_symlinks=False)
            if node is not None and node[fs.A_TYPE] != fs.T_LINK:
                blocks = 1 + sum(8 if f[fs.A_TYPE] == fs.T_DIR else -(-f[fs.A_SIZE] // 4096) * 8
                                 for f in files if f[fs.A_TYPE] in (fs.T_DIR, fs.T_FILE))
                self.write(f"total {blocks // 2}\n")
        if not files:
            return
        # Create a list to hold formatted sizes for display
        formatted_sizes = []
        filesize_str_extent = 0
        if len(files):
            filesize_str_extent = max(len(str(x[fs.A_SIZE])) for x in files)
            if self.showHumanReadable:
                for x in files:
                    # QPot: GNU's rounding (up; a decimal only below 10)
                    formatted_sizes.append(qpot_human(int(x[fs.A_SIZE] or 0)))
                # Recalculate the extent with the formatted sizes
                filesize_str_extent = max(len(size) for size in formatted_sizes)
            else:
                formatted_sizes = [str(x[fs.A_SIZE]) for x in files]

        user_name_str_extent = 0
        if len(files):
            user_name_str_extent = max(len(self.uid2name(x[fs.A_UID])) for x in files)

        group_name_str_extent = 0
        if len(files):
            group_name_str_extent = max(len(self.gid2name(x[fs.A_GID])) for x in files)
        links_str_extent = max(len(str(self.qpot_links(x))) for x in files) if files else 1
        now = time.time()

        for i, file in enumerate(files):
            perms = ["-"] * 10
            if file[fs.A_MODE] & stat.S_IRUSR:
                perms[1] = "r"
            if file[fs.A_MODE] & stat.S_IWUSR:
                perms[2] = "w"
            if file[fs.A_MODE] & stat.S_IXUSR:
                perms[3] = "x"
            if file[fs.A_MODE] & stat.S_ISUID:
                perms[3] = "S"
            if file[fs.A_MODE] & stat.S_IXUSR and file[fs.A_MODE] & stat.S_ISUID:
                perms[3] = "s"

            if file[fs.A_MODE] & stat.S_IRGRP:
                perms[4] = "r"
            if file[fs.A_MODE] & stat.S_IWGRP:
                perms[5] = "w"
            if file[fs.A_MODE] & stat.S_IXGRP:
                perms[6] = "x"
            if file[fs.A_MODE] & stat.S_ISGID:
                perms[6] = "S"
            if file[fs.A_MODE] & stat.S_IXGRP and file[fs.A_MODE] & stat.S_ISGID:
                perms[6] = "s"

            if file[fs.A_MODE] & stat.S_IROTH:
                perms[7] = "r"
            if file[fs.A_MODE] & stat.S_IWOTH:
                perms[8] = "w"
            if file[fs.A_MODE] & stat.S_IXOTH:
                perms[9] = "x"
            if file[fs.A_MODE] & stat.S_ISVTX:
                perms[9] = "T"
            if file[fs.A_MODE] & stat.S_IXOTH and file[fs.A_MODE] & stat.S_ISVTX:
                perms[9] = "t"

            linktarget = ""

            if file[fs.A_TYPE] == fs.T_DIR:
                perms[0] = "d"
            elif file[fs.A_TYPE] == fs.T_LINK:
                perms[0] = "l"
                linktarget = f" -> {file[fs.A_TARGET]}"

            permstr = "".join(perms)

            if CowrieConfig.get("shell", "ls_style", fallback="gnu") == "busybox":
                line = self.tpot_bb_long(permstr, file, formatted_sizes[i], linktarget)
            else:
                # QPot: GNU's columns: the link count, and the time as the locale shows it
                line = "{} {} {} {} {} {} {}{}".format(
                    permstr,
                    str(self.qpot_links(file)).rjust(links_str_extent),
                    self.uid2name(file[fs.A_UID]).ljust(user_name_str_extent),
                    self.gid2name(file[fs.A_GID]).ljust(group_name_str_extent),
                    formatted_sizes[i].rjust(filesize_str_extent),
                    qpot_ls_time(file[fs.A_CTIME], now),
                    file[fs.A_NAME],
                    linktarget,
                )

            self.write(f"{line}\n")


commands["/bin/ls"] = Command_ls
commands["ls"] = Command_ls
commands["/bin/dir"] = Command_ls
commands["dir"] = Command_ls
