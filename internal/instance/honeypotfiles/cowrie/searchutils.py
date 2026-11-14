# SPDX-License-Identifier: BSD-3-Clause

"""What someone looking for secrets runs, where the image stopped short (QPot).

A visitor with a shell reads files with cat; one who is looking for
credentials searches for them and packs what is found. On the image those
commands ended in ways no Linux server ends them:

  grep -r AKIA /root          "grep: /root: Is a directory" (the option was read and not acted on)
  ... | xargs grep -l KEY     nothing: grep read xargs' empty pipe where files were named
  source .env                 "source: command not found" (a shell builtin)
  tar czf /tmp/k.tgz ~/.ssh   "Cannot open: No such file or directory" (tar could only unpack)
  ssh-keygen -l -f key        "cannot execute binary file: Exec format error"
  uname -m | cut -c1-3        the whole line (-b and -c were taken and not acted on)

This module answers them. grep is the image's own with the directory walk
added, so every pattern, option and message of it stays as it is. Loaded
after coreutils (commands/__init__.py), so its names win. Texts are those of
GNU grep 3.11, GNU tar 1.35 and OpenSSH 9.6; BusyBox personas keep the
image's tar and take the same walk for grep -r.
"""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import io
import posixpath
import re
import stat as stat_mod
import struct
import tarfile
import time
import zlib

from cowrie.commands.coreutils import QpotCommand, qpot_busybox_applet
from cowrie.commands.cut import Command_cut
from cowrie.commands.fs import Command_egrep, Command_fgrep, Command_grep
from cowrie.commands.tar import Command_tar
from cowrie.shell import fs as tree_fs
from cowrie.shell.command import tpot_deadline

commands: dict = {}

# --- grep -r --------------------------------------------------------------------------------

# long options GNU grep takes that the image's getopt does not: the short form it does take
GREP_LONG = {
    "--ignore-case": "-i", "--no-ignore-case": None, "--files-with-matches": "-l", "--files-without-match": "-L",
    "--line-number": "-n", "--no-filename": "-h", "--with-filename": "-H", "--only-matching": "-o",
    "--extended-regexp": "-E", "--fixed-strings": "-F", "--basic-regexp": "-G", "--perl-regexp": "-P",
    "--invert-match": "-v", "--word-regexp": "-w", "--line-regexp": "-x", "--count": "-c", "--no-messages": "-s",
    "--text": "-a", "--null": "-Z", "--recursive": "-r", "--dereference-recursive": "-R",
}
GREP_LONG_VALUE = {"--max-count": "-m", "--after-context": "-A", "--before-context": "-B", "--file": "-f"}
GREP_GLOBS = ("--include", "--exclude", "--exclude-dir")
# what one recursive grep may walk and read
GREP_WALK_ENTRIES = 200000
GREP_WALK_SECONDS = 2.0
GREP_WALK_BYTES = 16 << 20


class QpotGrep:
    """The directory walk of grep -r and -R, mixed into the image's grep classes."""

    qpot_recursive = ""
    qpot_implicit = False
    qpot_binary_text = False
    qpot_skip_binary = False

    def tpot_parse(self):
        self.qpot_globs = {name: [] for name in GREP_GLOBS}
        args, kept, i = list(self.args), [], 0
        while i < len(args):
            arg = args[i]
            if arg == "--":
                kept += args[i:]
                break
            name, eq, value = arg.partition("=")
            if name in GREP_GLOBS:
                if not eq:
                    i += 1
                    value = args[i] if i < len(args) else ""
                self.qpot_globs[name].append(value)
            elif arg in GREP_LONG:
                if GREP_LONG[arg]:
                    kept.append(GREP_LONG[arg])
            elif name in GREP_LONG_VALUE and eq:
                kept += [GREP_LONG_VALUE[name], value]
            elif name in GREP_LONG_VALUE and i + 1 < len(args):
                kept += [GREP_LONG_VALUE[name], args[i + 1]]
                i += 1
            else:
                kept.append(arg)
            i += 1
        self.args = kept
        parsed = super().tpot_parse()
        if parsed is None:
            return None
        options, operands = parsed
        for opt, _ in options:
            if opt in ("-r", "-R"):
                self.qpot_recursive = opt[1]
            elif opt == "-a":
                self.qpot_binary_text = True
            elif opt == "-I":
                self.qpot_skip_binary = True
        patterns = any(opt in ("-e", "-f") for opt, _ in options)
        files = operands if patterns else operands[1:]
        if self.qpot_recursive and not files and (patterns or operands):
            # as GNU grep: a recursive search without a file is one of the working directory
            operands = [*operands, "."]
            files = ["."]
            self.qpot_implicit = True
        if files and "-" not in files:
            # files are named: the standard input is not read. The image searched it all the same
            #   whenever it was a pipe, so `find ... | xargs grep -l KEY` searched xargs' empty pipe.
            self.input_data = None
        if self.qpot_recursive:
            self.tpot_input_left = GREP_WALK_BYTES
        return options, operands

    def tpot_file(self, arg: str) -> None:
        path = self.fs.resolve_path(arg, self.cwd)
        node = self.fs.getfile(path) if self.qpot_recursive else None
        if node is None or node[tree_fs.A_TYPE] != tree_fs.T_DIR:
            super().tpot_file(arg)
            return
        if self.with_names is not False:
            self.tpot_names = True
        self.qpot_left = GREP_WALK_ENTRIES
        self.qpot_until = min(time.monotonic() + GREP_WALK_SECONDS, tpot_deadline(getattr(self, "protocol", None)))
        prefix = "" if self.qpot_implicit and arg == "." else (arg if arg.endswith("/") else arg + "/")
        self.qpot_walk(node, path, prefix)

    def qpot_walk(self, node, path: str, prefix: str) -> None:
        """The files below a directory, in its own order: a link is not entered (-r) and a link to a
        directory never is; what is no regular file is skipped, as grep skips devices when it recurses."""
        children = node[tree_fs.A_CONTENTS]
        if not isinstance(children, list):
            return
        for child in list(children):
            name = str(child[tree_fs.A_NAME])
            if name in (".", ".."):
                continue
            self.qpot_left -= 1
            if self.qpot_left < 0 or self.tpot_exhausted or (self.quiet and self.matched) or (
                    self.qpot_left % 512 == 0 and time.monotonic() > self.qpot_until):
                self.qpot_left = -1
                return
            kind, full = child[tree_fs.A_TYPE], posixpath.join(path, name)
            if kind == tree_fs.T_LINK:
                if self.qpot_recursive != "R":
                    continue
                target = self.fs.getfile(full)
                if target is None or target[tree_fs.A_TYPE] != tree_fs.T_FILE:
                    continue
                kind = tree_fs.T_FILE
            if kind == tree_fs.T_DIR:
                if not self.qpot_glob("--exclude-dir", name, False):
                    self.qpot_walk(child, full, prefix + name + "/")
                if self.qpot_left < 0:
                    return
            elif kind == tree_fs.T_FILE and self.qpot_wanted(name):
                self.qpot_search(full, prefix + name)

    def qpot_glob(self, option: str, name: str, default: bool) -> bool:
        globs = self.qpot_globs.get(option) or []
        if not globs:
            return default
        return any(fnmatch.fnmatchcase(name, glob) for glob in globs)

    def qpot_wanted(self, name: str) -> bool:
        return self.qpot_glob("--include", name, True) and not self.qpot_glob("--exclude", name, False)

    def qpot_search(self, path: str, label: str) -> None:
        try:
            contents = self.fs.file_contents(path)
        except PermissionError:
            if not self.no_messages:
                self.errorWrite(f"grep: {label}: Permission denied\n")
            self.errored = True
            return
        except Exception:  # noqa: BLE001 - a program of the persona without bytes: an empty file
            contents = b""
        if not isinstance(contents, bytes | bytearray):
            contents = b""
        binary = b"\x00" in contents[:32768] and not self.qpot_binary_text
        if binary and self.qpot_skip_binary:
            return
        if binary and not (self.count_only or self.list_files or self.quiet):
            # a binary file: GNU grep names it once where a line matches, and prints no line of it
            if self.tpot_input_left <= 0:
                return
            contents = contents[: self.tpot_input_left]
            self.tpot_input_left -= len(contents)
            matcher = self.compile_match(self.match)
            found = any((matcher.search(line) is not None) != self.invert for line in contents.split(b"\n")[:20000])
            if matcher.spent or not found:
                return
            self.matched = True
            self.write(f"grep: {label}: binary file matches\n" if self.tpot_gnu()
                       else f"Binary file {label} matches\n")
            return
        self.tpot_begin(label)
        self.grep_application(bytes(contents), self.match)
        self.tpot_finish(label)


class Command_qpot_grep(QpotGrep, Command_grep):
    pass


class Command_qpot_egrep(QpotGrep, Command_egrep):
    pass


class Command_qpot_fgrep(QpotGrep, Command_fgrep):
    pass


for _name, _cls in (("grep", Command_qpot_grep), ("egrep", Command_qpot_egrep), ("fgrep", Command_qpot_fgrep)):
    commands[_name] = _cls
    commands[f"/bin/{_name}"] = _cls
    commands[f"/usr/bin/{_name}"] = _cls


# --- cut -b, cut -c -------------------------------------------------------------------------


class Command_qpot_cut(Command_cut):
    """cut -b LIST and -c LIST: the bytes of each line the list names, each once and in the line's
    own order, as GNU cut and BusyBox's print them (both count bytes for -c). Fields are the
    image's."""

    qpot_positions = False

    def start(self) -> None:
        args, kept, index = list(self.args), [], 0
        while index < len(args):
            arg = args[index]
            if arg == "--":
                kept += args[index:]
                break
            name, eq, value = arg.partition("=")
            if name in ("--bytes", "--characters"):
                self.qpot_positions = True
                if not eq:
                    index += 1
                    value = args[index] if index < len(args) else ""
                kept += ["-b", value]
            else:
                if len(arg) > 1 and arg[0] == "-" and arg[1] != "-":
                    for letter in arg[1:]:
                        if letter in "bc":
                            self.qpot_positions = True
                        if letter in "bcdf":
                            break  # what follows in the word is the option's value
                kept.append(arg)
            index += 1
        self.args = kept
        super().start()

    def _process(self, data: bytes) -> None:
        if not self.qpot_positions:
            super()._process(data)
            return
        spans: list[list] = []
        for begin, end in sorted(self.field_indices, key=lambda span: span[0]):
            begin = max(begin, 0)
            if spans and (spans[-1][1] is None or begin <= spans[-1][1]):
                if spans[-1][1] is not None and (end is None or end > spans[-1][1]):
                    spans[-1][1] = end
            else:
                spans.append([begin, end])
        lines = data.split(b"\n")
        if lines and lines[-1] == b"":
            lines.pop()
        out = bytearray()
        for line in lines:
            for begin, end in spans:
                out += line[begin:end]
            out += b"\n"
        self.writeBytes(bytes(out))


commands["cut"] = Command_qpot_cut
commands["/bin/cut"] = Command_qpot_cut
commands["/usr/bin/cut"] = Command_qpot_cut


# --- source ---------------------------------------------------------------------------------


class Command_source(QpotCommand):
    """source FILE and . FILE: the file's commands run in the shell that called it, so what it sets
    is set there afterwards (`source .env; echo $DB_PASSWORD`)."""

    qpot_name = "source"

    def run(self) -> int | None:
        from cowrie.shell.bashparse import max_input_size
        from cowrie.shell.honeypot import HoneyPotShell
        from cowrie.shell.script import is_executable_binary

        word = "." if getattr(self, "qpot_dot", False) else "source"
        prefix = self.shell.error_prefix() if hasattr(self.shell, "error_prefix") else "bash: "
        if not self.args:
            self.errorWrite(f"{prefix}{word}: filename argument required\n{word}: usage: {word} filename [arguments]\n")
            return 2
        name = self.args[0]
        path = self.fs.resolve_path(name, self.cwd)
        if "/" not in name and not self.fs.exists(path):
            # a name without a slash is looked up on PATH, then here
            for directory in self.environ.get("PATH", "").split(":"):
                candidate = self.fs.resolve_path(f"{directory}/{name}", self.cwd) if directory else ""
                if candidate and self.fs.isfile(candidate):
                    path = candidate
                    break
        if not self.fs.exists(path):
            self.errorWrite(f"{prefix}{name}: No such file or directory\n")
            return 1
        if self.fs.isdir(path):
            self.errorWrite(f"{prefix}{word}: {name}: is a directory\n")
            return 1
        try:
            contents = self.fs.file_contents(path)
        except Exception:  # noqa: BLE001
            contents = b""
        if len(contents) > max_input_size() or is_executable_binary(contents):
            self.errorWrite(f"{prefix}{word}: {name}: cannot execute binary file\n")
            return 126
        text = contents.decode("utf-8", errors="replace")
        if not text.strip():
            return 0
        protocol = self.protocol
        depth = getattr(protocol, "_script_depth", 0)
        if depth >= 5:
            self.errorWrite(f"{prefix}{name}: too many levels of recursion\n")
            return 1
        protocol._script_depth = depth + 1
        try:
            shell = HoneyPotShell(protocol, interactive=False)
            shell.name = name
            shell.syntax_label = None
            # the caller's variables and directory are the file's, and the file's are the caller's after it
            caller = self.shell
            shell.environ = caller.environ
            if hasattr(caller, "exported") and hasattr(shell, "exported"):
                shell.exported = caller.exported
            if hasattr(caller, "cwd"):
                shell.cwd = caller.cwd
            if len(self.args) > 1:
                shell.set_positional_params(self.args[1:])

            def handed_back() -> None:
                # a line of only NAME=value gives the shell a new table of variables: what the file
                #   set is put into the caller's own
                if shell.environ is not caller.environ:
                    made = dict(shell.environ)
                    caller.environ.clear()
                    caller.environ.update(made)
                    shell.environ = caller.environ
                if hasattr(shell, "cwd") and hasattr(caller, "cwd"):
                    caller.cwd = shell.cwd

            protocol.cmdstack.append(shell)
            shell.lineReceived(text)
            handed_back()
            if shell in protocol.cmdstack:
                # a command of the file is still running (a download): what follows it is handed back too
                finish = shell._finish

                def finished(*args, **kwargs):
                    handed_back()
                    return finish(*args, **kwargs)

                shell._finish = finished
            return shell.last_exit_code or 0
        finally:
            protocol._script_depth = depth


class Command_dot(Command_source):
    qpot_dot = True


commands["source"] = Command_source
commands["."] = Command_dot


# --- tar ------------------------------------------------------------------------------------

TAR_MAX_ENTRIES = 20000
TAR_MAX_BYTES = 32 << 20
TAR_MODES = {"c": "create", "x": "extract", "t": "list", "r": "append", "u": "update", "A": "catenate", "d": "diff"}


def qpot_gzip_stream(data: bytes) -> bytes:
    """data as `tar z` writes it: gzip from a pipe, so no name and no time in its header."""
    compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
    body = compressor.compress(data) + compressor.flush()
    return b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03" + body + struct.pack(
        "<II", zlib.crc32(data) & 0xFFFFFFFF, len(data) & 0xFFFFFFFF)


def qpot_tar_plain(data: bytes) -> bytes | None:
    """The tar stream of an archive made here, without its compression; None for one that is larger
    than tar here packs (TAR_MAX_BYTES and its blocks), compressed or not: a few bytes of gzip can
    hold gigabytes, and they would be expanded on the thread every session shares."""
    limit = TAR_MAX_BYTES + (TAR_MAX_ENTRIES + 4) * 1024
    if len(data) > limit:
        return None
    try:
        if data[:2] == b"\x1f\x8b":
            unpacker = zlib.decompressobj(31)
        elif data[:3] == b"BZh":
            import bz2
            unpacker = bz2.BZ2Decompressor()
        elif data[:6] == b"\xfd7zXZ\x00":
            import lzma
            unpacker = lzma.LZMADecompressor()
        else:
            return data
        plain = unpacker.decompress(data, limit + 1)
    except Exception:  # noqa: BLE001 - no stream of the kind its first bytes name
        return None
    return plain if len(plain) <= limit else None


def qpot_mode_text(kind: str, mode: int) -> str:
    text = kind
    for shift, special, low, high in ((6, 0o4000, "s", "S"), (3, 0o2000, "s", "S"), (0, 0o1000, "t", "T")):
        bits = mode >> shift & 7
        execute = "x" if bits & 1 else "-"
        if mode & special:
            execute = low if bits & 1 else high
        text += ("r" if bits & 4 else "-") + ("w" if bits & 2 else "-") + execute
    return text


class _TarListing:
    """What tar -v prints, written as it is added."""

    def __init__(self, write) -> None:
        self.write = write

    def append(self, name: str) -> None:
        self.write(name + "\n")


class Command_qpot_tar(Command_tar):
    """GNU tar that also packs: `tar czf /tmp/k.tgz /root/.ssh` makes the archive in the tree, with the
    files' own bytes, and -f - writes it to the next command. Archives made here are listed and unpacked
    here; one that was downloaded is the image's to read, as before."""

    def qpot_names(self) -> dict:
        """uid and gid to name, from the persona's passwd and group."""
        found = {"u": {0: "root"}, "g": {0: "root"}}
        for key, name in (("u", "/etc/passwd"), ("g", "/etc/group")):
            try:
                text = self.fs.file_contents(name)[:1 << 20].decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                continue
            for line in text.splitlines():
                fields = line.split(":")
                if len(fields) > 2 and fields[2].isdigit():
                    found[key].setdefault(int(fields[2]), fields[0])
        return found

    def qpot_fail(self, text: str, code: int = 2) -> None:
        self.errorWrite(text)
        self.exit_code = code

    def qpot_options(self):
        """(mode letter, archive, flags, operands, directory) of the command line; None after tar's message."""
        args = list(self.args)
        old = bool(args) and not args[0].startswith("-")
        if old:
            args[0] = "-" + args[0]  # the old form: tar czf
        mode, archive, flags, operands, directory = "", None, set(), [], None
        i = 0
        while i < len(args):
            arg = args[i]
            if arg == "--":
                operands += args[i + 1:]
                break
            if arg.startswith("--"):
                name, eq, value = arg.partition("=")
                long = {"--create": "c", "--extract": "x", "--get": "x", "--list": "t", "--gzip": "z", "--gunzip": "z",
                        "--verbose": "v", "--bzip2": "j", "--xz": "J", "--absolute-names": "P",
                        "--to-stdout": "O"}.get(name)
                if long in TAR_MODES:
                    mode = mode or long
                elif long:
                    flags.add(long)
                elif name in ("--file", "--directory", "--exclude"):
                    if not eq:
                        i += 1
                        value = args[i] if i < len(args) else ""
                    if name == "--file":
                        archive = value
                    elif name == "--directory":
                        directory = value
                else:
                    self.qpot_fail(f"tar: unrecognized option '{name}'\n"
                                   "Try 'tar --help' or 'tar --usage' for more information.\n", 64)
                    return None
            elif arg.startswith("-") and len(arg) > 1:
                letters = arg[1:]
                for j, letter in enumerate(letters):
                    if letter in TAR_MODES:
                        if mode and mode != letter:
                            self.qpot_fail("tar: You may not specify more than one '-Acdtrux', '--delete' or  "
                                           "'--test-label' option\n"
                                           "Try 'tar --help' or 'tar --usage' for more information.\n")
                            return None
                        mode = letter
                    elif letter in "fC":
                        value = letters[j + 1:]
                        if not value:
                            i += 1
                            if i >= len(args):
                                if old and i == 1:
                                    self.qpot_fail(f"tar: Old option '{letter}' requires an argument.\n"
                                                   "Try 'tar --help' or 'tar --usage' for more information.\n")
                                else:
                                    self.qpot_fail(f"tar: option requires an argument -- '{letter}'\n"
                                                   "Try 'tar --help' or 'tar --usage' for more information.\n", 64)
                                return None
                            value = args[i]
                        if letter == "f":
                            archive = value
                        else:
                            directory = value
                        break
                    elif letter in "zjJvpPOhmka":
                        flags.add(letter)
                    else:
                        self.qpot_fail(f"tar: invalid option -- '{letter}'\n"
                                       "Try 'tar --help' or 'tar --usage' for more information.\n", 64)
                        return None
            else:
                operands.append(arg)
            i += 1
        return mode, archive, flags, operands, directory

    def call(self) -> None:
        if qpot_busybox_applet(self.fs, "tar"):
            super().call()
            return
        parsed = self.qpot_options()
        if parsed is None:
            return
        mode, archive, flags, operands, directory = parsed
        if not mode:
            self.qpot_fail("tar: You must specify one of the '-Acdtrux', '--delete' or '--test-label' options\n"
                           "Try 'tar --help' or 'tar --usage' for more information.\n")
            return
        if mode == "c":
            self.qpot_create(archive, flags, operands, directory)
            return
        if mode not in ("x", "t") or archive in (None, "-"):
            super().call()
            return
        path = self.fs.resolve_path(archive, self.cwd)
        node = self.fs.getfile(path) if path else None
        if node is None or node[tree_fs.A_REALFILE] or not isinstance(node[tree_fs.A_CONTENTS], bytes | bytearray):
            super().call()  # not there, or a file that was downloaded: the image's own reading
            return
        self.qpot_read(bytes(node[tree_fs.A_CONTENTS]), mode, flags, directory)

    def qpot_create(self, archive, flags, operands, directory) -> None:
        if not operands:
            self.qpot_fail("tar: Cowardly refusing to create an empty archive\n"
                           "Try 'tar --help' or 'tar --usage' for more information.\n")
            return
        if archive is None:
            self.qpot_fail("tar: Refusing to write archive contents to terminal (missing -f option?)\n"
                           "tar: Error is not recoverable: exiting now\n")
            return
        base = self.fs.resolve_path(directory, self.cwd) if directory else self.cwd
        if directory and not self.fs.isdir(base):
            self.qpot_fail(f"tar: {directory}: Cannot open: No such file or directory\n"
                           "tar: Error is not recoverable: exiting now\n")
            return
        target = None
        if archive != "-":
            target = self.fs.resolve_path(archive, self.cwd)
            parent = posixpath.dirname(target) or "/"
            if not self.fs.isdir(parent) or self.fs.isdir(target):
                self.qpot_fail(f"tar: {archive}: Cannot open: "
                               f"{'Is a directory' if self.fs.isdir(target) else 'No such file or directory'}\n"
                               "tar: Error is not recoverable: exiting now\n")
                return
        names = self.qpot_names()
        buffer = io.BytesIO()
        out = tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT)
        self.qpot_entries, self.qpot_bytes, failed, warned = TAR_MAX_ENTRIES, TAR_MAX_BYTES, False, False
        # -v names each member as it is packed: on the output, or beside the archive that goes there
        listing = _TarListing(self.write if target is not None else self.errorWrite) if "v" in flags else []
        for operand in operands:
            path = self.fs.resolve_path(operand, base)
            node = self.fs.getfile(path, follow_symlinks=False)
            if node is None:
                self.errorWrite(f"tar: {operand}: Cannot stat: No such file or directory\n")
                failed = True
                continue
            if operand.startswith("/") and "P" not in flags and not warned:
                self.errorWrite("tar: Removing leading `/' from member names\n")
                warned = True
            self.qpot_add(out, node, path, operand.rstrip("/") or "/", names, "P" in flags, listing, target)
        out.close()
        data = buffer.getvalue()
        if "z" in flags:
            data = qpot_gzip_stream(data)
        elif "j" in flags:
            import bz2
            data = bz2.compress(data)
        elif "J" in flags:
            import lzma
            data = lzma.compress(data)
        if target is None:
            self.writeBytes(data)
        else:
            try:
                if self.fs.exists(target):
                    self.fs.remove(target)
                self.fs.mkfile(target, self.user["uid"], self.user["gid"], len(data), stat_mod.S_IFREG | 0o644, time.time())
                self.fs.getfile(target)[tree_fs.A_CONTENTS] = data
            except Exception:  # noqa: BLE001 - a place of the tree nothing can be written to
                self.qpot_fail(f"tar: {archive}: Cannot open: Read-only file system\n"
                               "tar: Error is not recoverable: exiting now\n")
                return
        if failed:
            self.qpot_fail("tar: Exiting with failure status due to previous errors\n")

    def qpot_add(self, out, node, path: str, shown: str, names: dict, absolute: bool, listing: list, target) -> None:
        """node (at path, named shown on the command line) and what is below it, as tar walks: a
        directory before what it holds, in the directory's own order."""
        if self.qpot_entries <= 0 or path == target:
            return
        self.qpot_entries -= 1
        kind = node[tree_fs.A_TYPE]
        member = shown if absolute else shown.lstrip("/")
        info = tarfile.TarInfo(member or ".")
        info.mode = int(node[tree_fs.A_MODE] or 0) & 0o7777
        info.uid, info.gid = int(node[tree_fs.A_UID] or 0), int(node[tree_fs.A_GID] or 0)
        info.uname = names["u"].get(info.uid, "")
        info.gname = names["g"].get(info.gid, "")
        info.mtime = int(node[tree_fs.A_CTIME] or 0)
        if kind == tree_fs.T_DIR:
            info.type = tarfile.DIRTYPE
            info.name = (member or ".") + "/"
            out.addfile(info)
            listing.append(shown.rstrip("/") + "/")
            children = node[tree_fs.A_CONTENTS]
            for child in list(children) if isinstance(children, list) else []:
                name = str(child[tree_fs.A_NAME])
                if name not in (".", ".."):
                    self.qpot_add(out, child, posixpath.join(path, name), shown.rstrip("/") + "/" + name,
                                  names, absolute, listing, target)
        elif kind == tree_fs.T_LINK:
            info.type = tarfile.SYMTYPE
            info.linkname = str(node[tree_fs.A_TARGET] or "")
            out.addfile(info)
            listing.append(shown)
        elif kind == tree_fs.T_FILE:
            try:
                data = self.fs.file_contents(path)
            except Exception:  # noqa: BLE001 - a program of the persona without bytes
                data = b""
            data = bytes(data[: max(self.qpot_bytes, 0)]) if isinstance(data, bytes | bytearray) else b""
            self.qpot_bytes -= len(data)
            info.size = len(data)
            out.addfile(info, io.BytesIO(data))
            listing.append(shown)

    def qpot_read(self, data: bytes, mode: str, flags: set, directory) -> None:
        """List or unpack an archive made here."""
        try:
            plain = qpot_tar_plain(data)
            if plain is None:
                raise ValueError("an archive larger than tar here makes")
            archive = tarfile.open(fileobj=io.BytesIO(plain), mode="r:")
            members = []
            for member in archive:
                members.append(member)
                if len(members) >= TAR_MAX_ENTRIES:
                    break
        except Exception:  # noqa: BLE001
            self.qpot_fail("tar: This does not look like a tar archive\ntar: Exiting with failure status due to previous errors\n")
            return
        base = self.fs.resolve_path(directory, self.cwd) if directory else self.cwd
        left = TAR_MAX_BYTES  # what all the members together may put into the tree
        for member in members:
            shown = member.name + ("/" if member.isdir() and not member.name.endswith("/") else "")
            if "v" in flags and mode == "t":
                kind = "d" if member.isdir() else "l" if member.issym() else "-"
                owner = f"{member.uname or member.uid}/{member.gname or member.gid}"
                size = str(member.size)
                when = time.strftime("%Y-%m-%d %H:%M", time.localtime(member.mtime))
                link = f" -> {member.linkname}" if member.issym() else ""
                self.write(f"{qpot_mode_text(kind, member.mode)} {owner} {size.rjust(max(19 - len(owner) - 1, len(size)))} "
                           f"{when} {shown}{link}\n")
            elif "v" in flags or mode == "t":
                self.write(shown + "\n")
            if mode != "x":
                continue
            dest = self.fs.resolve_path(member.name.strip("/"), base)
            if not dest or dest == "/":
                continue
            try:
                if member.isdir():
                    if not self.fs.exists(dest):
                        self.fs.mkdir(dest, member.uid, member.gid, 4096, stat_mod.S_IFDIR | member.mode, member.mtime)
                elif member.isreg() and not member.issparse():
                    parent = posixpath.dirname(dest)
                    if parent and not self.fs.exists(parent):
                        self.mkfullpath(parent.lstrip("/"), member)
                    if self.fs.exists(dest):
                        self.fs.remove(dest)
                    body = archive.extractfile(member).read(max(min(left, member.size), 0))
                    left -= len(body)
                    self.fs.mkfile(dest, member.uid, member.gid, len(body), stat_mod.S_IFREG | member.mode, member.mtime)
                    self.fs.getfile(dest)[tree_fs.A_CONTENTS] = body
            except Exception:  # noqa: BLE001 - a place nothing can be written to: the member is skipped
                continue


commands["tar"] = Command_qpot_tar
commands["/bin/tar"] = Command_qpot_tar
commands["/usr/bin/tar"] = Command_qpot_tar


# --- ssh-keygen -----------------------------------------------------------------------------

KEYGEN_USAGE = """usage: ssh-keygen [-q] [-a rounds] [-b bits] [-C comment] [-f output_keyfile]
                  [-m format] [-N new_passphrase] [-O option]
                  [-t dsa | ecdsa | ecdsa-sk | ed25519 | ed25519-sk | rsa]
                  [-w provider] [-Z cipher]
       ssh-keygen -p [-a rounds] [-f keyfile] [-m format] [-N new_passphrase]
                   [-P old_passphrase] [-Z cipher]
       ssh-keygen -i [-f input_keyfile] [-m key_format]
       ssh-keygen -e [-f input_keyfile] [-m key_format]
       ssh-keygen -y [-f input_keyfile]
       ssh-keygen -c [-a rounds] [-C comment] [-f keyfile] [-P passphrase]
       ssh-keygen -l [-v] [-E fingerprint_hash] [-f input_keyfile]
       ssh-keygen -B [-f input_keyfile]
       ssh-keygen -D pkcs11
       ssh-keygen -F hostname [-lv] [-f known_hosts_file]
       ssh-keygen -H [-f known_hosts_file]
       ssh-keygen -K [-a rounds] [-w provider]
       ssh-keygen -R hostname [-f known_hosts_file]
       ssh-keygen -r hostname [-g] [-f input_keyfile]
       ssh-keygen -M generate [-O option] output_file
       ssh-keygen -M screen [-f input_file] [-O option] output_file
       ssh-keygen -I certificate_identity -s ca_key [-hU] [-D pkcs11_provider]
                  [-n principals] [-O option] [-V validity_interval]
                  [-z serial_number] file ...
       ssh-keygen -L [-f input_keyfile]
       ssh-keygen -A [-a rounds] [-f prefix_path]
       ssh-keygen -k -f krl_file [-u] [-s ca_public] [-z version_number]
                  file ...
       ssh-keygen -Q [-l] -f krl_file [file ...]
       ssh-keygen -Y find-principals -s signature_file -f allowed_signers_file
       ssh-keygen -Y match-principals -I signer_identity -f allowed_signers_file
       ssh-keygen -Y check-novalidate -n namespace -s signature_file
       ssh-keygen -Y sign -f key_file -n namespace file [-O option] ...
       ssh-keygen -Y verify -f allowed_signers_file -I signer_identity
                  -n namespace -s signature_file [-r krl_file] [-O option]
"""
KEYGEN_NAMES = {"ssh-ed25519": ("ED25519", 256), "ssh-rsa": ("RSA", 0), "ecdsa-sha2-nistp256": ("ECDSA", 256),
                "ecdsa-sha2-nistp384": ("ECDSA", 384), "ecdsa-sha2-nistp521": ("ECDSA", 521), "ssh-dss": ("DSA", 1024)}


def qpot_ssh_strings(blob: bytes) -> list:
    out, at = [], 0
    while at + 4 <= len(blob) and len(out) < 16:
        size = struct.unpack(">I", blob[at:at + 4])[0]
        at += 4
        if size > len(blob) - at:
            break
        out.append(blob[at:at + size])
        at += size
    return out


def qpot_key_line(line: str):
    """(type, blob, comment) of a public key line (also one of known_hosts or authorized_keys), or None."""
    words = line.split()
    for index, word in enumerate(words):
        if word in KEYGEN_NAMES and index + 1 < len(words):
            try:
                blob = base64.b64decode(words[index + 1], validate=True)
            except Exception:  # noqa: BLE001
                return None
            parts = qpot_ssh_strings(blob)
            if not parts or parts[0].decode("ascii", "replace") != word:
                return None
            return word, blob, " ".join(words[index + 2:]), " ".join(words[:index])
    return None


def qpot_key_bits(kind: str, blob: bytes) -> int:
    if kind != "ssh-rsa":
        return KEYGEN_NAMES[kind][1]
    parts = qpot_ssh_strings(blob)
    if len(parts) < 3:
        return 0
    return int.from_bytes(parts[2], "big").bit_length()


def qpot_private_public(text: str):
    """The public key line an unencrypted OpenSSH private key holds; "encrypted" for one with a
    passphrase; None for what is no such key."""
    match = re.search(r"-----BEGIN OPENSSH PRIVATE KEY-----(.*?)-----END OPENSSH PRIVATE KEY-----", text, re.S)
    if not match:
        return None
    try:
        raw = base64.b64decode("".join(match[1].split()), validate=True)
    except Exception:  # noqa: BLE001
        return None
    if not raw.startswith(b"openssh-key-v1\x00"):
        return None
    body, at = raw[15:], 0
    fields = []
    for _ in range(3):  # cipher, kdf, kdf options
        if at + 4 > len(body):
            return None
        size = struct.unpack(">I", body[at:at + 4])[0]
        fields.append(body[at + 4:at + 4 + size])
        at += 4 + size
    if at + 8 > len(body) or struct.unpack(">I", body[at:at + 4])[0] != 1:
        return None
    at += 4
    size = struct.unpack(">I", body[at:at + 4])[0]
    public = body[at + 4:at + 4 + size]
    at += 4 + size
    if fields[0] != b"none":
        return "encrypted"
    parts = qpot_ssh_strings(public)
    kind = parts[0].decode("ascii", "replace") if parts else ""
    if kind not in KEYGEN_NAMES:
        return None
    comment = ""
    if at + 4 <= len(body):
        private = qpot_ssh_strings(body[at:])
        inner = private[0][8:] if private else b""
        inside = qpot_ssh_strings(inner)
        # type, the key's own fields, then the comment: the last string before the padding
        if inside:
            comment = inside[-1].decode("utf-8", "replace")
    return kind, public, comment


def qpot_fingerprint(blob: bytes, md5: bool = False) -> str:
    if md5:
        digest = hashlib.md5(blob).hexdigest()  # noqa: S324 - the fingerprint format ssh-keygen -E md5 prints
        return "MD5:" + ":".join(digest[i:i + 2] for i in range(0, 32, 2))
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def qpot_randomart(kind: str, bits: int, blob: bytes) -> str:
    """The picture ssh-keygen draws of a new key's SHA256 fingerprint (the walk of key.c)."""
    marks = " .o+=*BOX@%&#/^SE"
    width, height = 17, 9
    field = [[0] * width for _ in range(height)]
    x, y = width // 2, height // 2
    for byte in hashlib.sha256(blob).digest():
        for _ in range(4):
            x = min(max(x + (1 if byte & 1 else -1), 0), width - 1)
            y = min(max(y + (1 if byte & 2 else -1), 0), height - 1)
            if field[y][x] < len(marks) - 3:
                field[y][x] += 1
            byte >>= 2
    field[height // 2][width // 2] = len(marks) - 2
    field[y][x] = len(marks) - 1
    title = f"[{KEYGEN_NAMES[kind][0]} {bits}]"
    left = (width - len(title)) // 2
    lines = ["+" + "-" * left + title + "-" * (width - len(title) - left) + "+"]
    lines += ["|" + "".join(marks[min(cell, len(marks) - 1)] for cell in row) + "|" for row in field]
    lines.append("+" + "-" * 4 + "[SHA256]" + "-" * 5 + "+")
    return "".join(line + "\n" for line in lines)


def qpot_ed25519_private(seed: bytes, public: bytes, comment: str, check: bytes) -> bytes:
    """An unencrypted OpenSSH private key file of an Ed25519 key, as ssh-keygen writes it."""
    def text(value: bytes) -> bytes:
        return struct.pack(">I", len(value)) + value

    blob = text(b"ssh-ed25519") + text(public)
    private = check + check + blob + text(seed + public) + text(comment.encode("utf-8"))
    private += bytes(range(1, 1 + (-len(private)) % 8))
    raw = b"openssh-key-v1\x00" + text(b"none") + text(b"none") + text(b"") + struct.pack(">I", 1) + text(blob) + text(private)
    body = base64.b64encode(raw).decode()
    return ("-----BEGIN OPENSSH PRIVATE KEY-----\n" + "".join(body[i:i + 70] + "\n" for i in range(0, len(body), 70))
            + "-----END OPENSSH PRIVATE KEY-----\n").encode()


# keys one connection may have made for it: making one costs the processor what it costs sshd's host
KEYGEN_MAX = 4


class Command_ssh_keygen(QpotCommand):
    """ssh-keygen: -l (fingerprints of a key or of known_hosts), -y (the public key of a private
    one), -F and -R (a host in known_hosts), and a new key pair (-t, -b, -C, -N, -f, -q), written
    to the tree with the fingerprint and picture ssh-keygen prints."""

    qpot_name = "ssh-keygen"
    qpot_state = ""

    def run(self) -> int | None:
        import getopt

        try:
            options, rest = getopt.getopt(list(self.args), "ABHKLQUXceghiklopquvyC:D:E:F:I:M:N:O:P:R:V:Y:Z:a:b:f:g:m:n:r:s:t:w:z:")
        except getopt.GetoptError as err:
            flag = err.opt
            self.errorWrite((f"option requires an argument -- {flag}\n" if "requires" in err.msg
                             else f"unknown option -- {flag}\n") + KEYGEN_USAGE)
            return 1
        opts = dict(options)
        if rest:
            self.errorWrite("Too many arguments.\n" + KEYGEN_USAGE)
            return 1
        home = str(self.environ.get("HOME") or "/root")
        md5 = opts.get("-E", "sha256").lower() == "md5"
        if "-E" in opts and opts["-E"].lower() not in ("md5", "sha256"):
            self.errorWrite(f"Invalid hash algorithm \"{opts['-E']}\"\n")
            return 255
        if "-F" in opts or "-R" in opts:
            return self.qpot_known(opts, home, md5)
        if "-l" in opts or "-y" in opts:
            self.qpot_opts, self.qpot_md5 = opts, md5
            if "-f" not in opts:
                from cowrie.commands.base import tpot_pty

                self.qpot_typed = bool(tpot_pty(self.protocol))
                self.qpot_default = f"{home}/.ssh/id_{self.qpot_default_kind()}"
                self.write(f"Enter file in which the key is ({self.qpot_default}): ")
                if not self.qpot_typed:
                    return 1  # its input is at its end: no file, no message
                self.qpot_state = "show"
                return None
            return self.qpot_show(opts, md5)
        if any("-" + flag in opts for flag in "ABHKLQUXceghikopuDIMVYnrsz"):
            # a mode this does not have: as ssh-keygen answers a command line it cannot read
            self.errorWrite(KEYGEN_USAGE)
            return 1
        return self.qpot_generate(opts, home)

    # --- a new key ---

    def qpot_default_kind(self) -> str:
        # OpenSSH 9.5 made ed25519 the default; before it was rsa
        from cowrie.commands.coreutils import qpot_package_version

        found = re.match(r"(?:\d+:)?(\d+)\.(\d+)", qpot_package_version("openssh-client") or "")
        return "ed25519" if not found or (int(found[1]), int(found[2])) >= (9, 5) else "rsa"

    def qpot_generate(self, opts: dict, home: str) -> int | None:
        kind = opts.get("-t") or self.qpot_default_kind()
        if kind not in ("ecdsa", "ed25519", "rsa"):
            self.errorWrite(f"unknown key type {kind}\n")
            return 255
        bits = {"ed25519": 256, "ecdsa": 256, "rsa": 3072}[kind]
        if "-b" in opts and kind != "ed25519":
            if not opts["-b"].isdigit():
                self.errorWrite("Bits has bad value " + opts["-b"] + " (invalid)\n")
                return 255
            bits = int(opts["-b"])
            if kind == "rsa" and bits < 1024:
                self.errorWrite("Invalid RSA key length: minimum is 1024 bits\n")
                return 255
            if kind == "rsa" and bits > 16384:
                self.errorWrite("Invalid RSA key length: maximum is 16384 bits\n")
                return 255
            if kind == "ecdsa" and bits not in (256, 384, 521):
                self.errorWrite("Invalid ECDSA key length: valid lengths are 256, 384 or 521 bits\n")
                return 255
        self.qpot_kind, self.qpot_bits, self.qpot_quiet = kind, bits, "-q" in opts
        user = str(self.environ.get("USER") or self.user.get("username") or "root")
        self.qpot_comment = opts.get("-C", f"{user}@{getattr(self.protocol, 'hostname', 'localhost')}")
        self.qpot_default = f"{home}/.ssh/id_{kind}"
        self.qpot_target = opts.get("-f")
        self.qpot_pass = opts.get("-N")
        from cowrie.commands.base import tpot_pty

        self.qpot_typed = bool(tpot_pty(self.protocol))
        if not self.qpot_quiet:
            self.write(f"Generating public/private {kind} key pair.\n")
        return self.qpot_next()

    def qpot_ask(self, state: str, text: str, hidden: bool = False) -> int | None:
        """Ask for a line: at a terminal the answer is waited for; without one ssh-keygen reads its
        standard input, which is at its end, and goes on with an empty answer."""
        self.write(text)
        if self.qpot_typed:
            self.qpot_state = state
            self.protocol.password_input = hidden
            return None
        self.write("\n" if hidden else "")
        return self.qpot_answer(state, "")

    def qpot_next(self) -> int | None:
        if self.qpot_target is None:
            return self.qpot_ask("file", f"Enter file in which to save the key ({self.qpot_default}): ")
        path = self.fs.resolve_path(self.qpot_target, self.cwd)
        if self.fs.exists(path) and not getattr(self, "qpot_overwrite", False):
            return self.qpot_ask("overwrite", f"{self.qpot_target} already exists.\nOverwrite (y/n)? ")
        if self.qpot_pass is None:
            return self.qpot_ask("pass1", "Enter passphrase (empty for no passphrase): ", True)
        return self.qpot_make(path)

    def qpot_answer(self, state: str, line: str) -> int | None:
        if state == "show":
            self.qpot_opts["-f"] = line.strip() or self.qpot_default
            return self.qpot_show(self.qpot_opts, self.qpot_md5)
        if state == "file":
            self.qpot_target = line.strip() or self.qpot_default
        elif state == "overwrite":
            if not line.strip().lower().startswith("y"):
                return 1
            self.qpot_overwrite = True
        elif state == "pass1":
            self.qpot_first = line
            return self.qpot_ask("pass2", "Enter same passphrase again: ", True)
        elif state == "pass2":
            if line != self.qpot_first:
                self.write("Passphrases do not match.  Try again.\n")
                return self.qpot_ask("pass1", "Enter passphrase (empty for no passphrase): ", True)
            self.qpot_pass = line
        return self.qpot_next()

    def lineReceived(self, line: str) -> None:  # noqa: N802 - Cowrie's name
        state, self.qpot_state = self.qpot_state, ""
        if not state:
            return
        hidden = getattr(self.protocol, "password_input", False)
        self.protocol.password_input = False
        if hidden:
            self.write("\n")
        try:
            code = self.qpot_answer(state, line)
        except Exception:  # noqa: BLE001
            code = 1
        if code is not None and not self.exited:
            self.exit(code)

    def handle_CTRL_C(self) -> None:  # noqa: N802 - Cowrie's name
        self.protocol.password_input = False
        self.write("^C\n")
        self.exit(130)

    def qpot_make(self, path: str) -> int | None:
        target = self.qpot_target
        if not self.fs.isdir(posixpath.dirname(path) or "/"):
            self.errorWrite(f"Saving key \"{target}\" failed: No such file or directory\n")
            return 1
        made = int(getattr(self.protocol, "qpot_keys_made", 0))
        if made >= KEYGEN_MAX or (self.qpot_kind == "rsa" and self.qpot_bits > 4096):
            # more keys, or a larger one, than a connection is given here: as when the tree is full
            self.errorWrite(f"Saving key \"{target}\" failed: No space left on device\n")
            return 1
        self.protocol.qpot_keys_made = made + 1
        if self.qpot_kind == "ed25519":
            return self.qpot_store(path, self.qpot_new_key())
        from twisted.internet import threads

        def done(result):
            if not self.exited:
                self.exit(self.qpot_store(path, result))

        def failed(_):
            if not self.exited:
                self.errorWrite(f"Saving key \"{target}\" failed: error in libcrypto\n")
                self.exit(1)

        threads.deferToThread(self.qpot_new_key).addCallbacks(done, failed)
        return None

    def qpot_new_key(self):
        """(type name, public blob, private key file) of a new key of the kind asked for."""
        import os

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

        if self.qpot_kind == "ed25519":
            key = ed25519.Ed25519PrivateKey.generate()
            seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + public
            return "ssh-ed25519", blob, qpot_ed25519_private(seed, public, self.qpot_comment, os.urandom(4))
        if self.qpot_kind == "rsa":
            key = rsa.generate_private_key(public_exponent=65537, key_size=self.qpot_bits)
        else:
            key = ec.generate_private_key({256: ec.SECP256R1(), 384: ec.SECP384R1(), 521: ec.SECP521R1()}[self.qpot_bits])
        line = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        name, encoded = line.split()[:2]
        private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
        return name, base64.b64decode(encoded), private

    def qpot_store(self, path: str, made) -> int:
        kind, blob, private = made
        target = self.qpot_target
        public = f"{kind} {base64.b64encode(blob).decode()}" + (f" {self.qpot_comment}" if self.qpot_comment else "") + "\n"
        try:
            for name, data, mode in ((path, private, 0o600), (path + ".pub", public.encode(), 0o644)):
                if self.fs.exists(name):
                    self.fs.remove(name)
                self.fs.mkfile(name, self.user["uid"], self.user["gid"], len(data), stat_mod.S_IFREG | mode, time.time())
                self.fs.getfile(name)[tree_fs.A_CONTENTS] = data
        except Exception:  # noqa: BLE001 - a place of the tree nothing can be written to
            self.errorWrite(f"Saving key \"{target}\" failed: Permission denied\n")
            return 1
        if not self.qpot_quiet:
            self.write(f"Your identification has been saved in {target}\n"
                       f"Your public key has been saved in {target}.pub\n"
                       f"The key fingerprint is:\n{qpot_fingerprint(blob)} {self.qpot_comment}\n"
                       f"The key's randomart image is:\n{qpot_randomart(kind, qpot_key_bits(kind, blob), blob)}")
        return 0

    def qpot_read(self, name: str):
        path = self.fs.resolve_path(name, self.cwd)
        if not self.fs.exists(path):
            self.errorWrite(f"ssh-keygen: {name}: No such file or directory\n")
            return None
        if self.fs.isdir(path):
            self.errorWrite(f"{name} is not a public key file.\n")
            return None
        try:
            return self.fs.file_contents(path)[:1 << 20].decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            self.errorWrite(f"{name} is not a public key file.\n")
            return None

    def qpot_show(self, opts: dict, md5: bool) -> int:
        name = opts["-f"]
        text = self.qpot_read(name)
        if text is None:
            return 255
        private = qpot_private_public(text)
        if private == "encrypted":
            if "-y" in opts:
                self.write("Enter passphrase: ")
                self.errorWrite(f"Load key \"{name}\": incorrect passphrase supplied to decrypt private key\n")
                return 255
            private = None
        if "-y" in opts:
            if not private:
                self.errorWrite(f"Load key \"{name}\": error in libcrypto\n" if "PRIVATE KEY" in text
                                else f"Load key \"{name}\": invalid format\n")
                return 255
            kind, blob, comment = private
            self.write(f"{kind} {base64.b64encode(blob).decode()}" + (f" {comment}" if comment else "") + "\n")
            return 0
        keys = []
        if private:
            kind, blob, comment = private
            keys.append((kind, blob, comment or "no comment"))
        else:
            for line in text.splitlines():
                if line.strip() and not line.lstrip().startswith("#"):
                    found = qpot_key_line(line)
                    if found:
                        # a line of known_hosts is named by its hosts, a key file's by its comment
                        keys.append((found[0], found[1], found[3] or found[2] or "no comment"))
        if not keys:
            self.errorWrite(f"{name} is not a public key file.\n")
            return 255
        for kind, blob, comment in keys:
            label, _ = KEYGEN_NAMES[kind]
            self.write(f"{qpot_key_bits(kind, blob)} {qpot_fingerprint(blob, md5)} {comment} ({label})\n")
        return 0

    def qpot_known(self, opts: dict, home: str, md5: bool) -> int:
        import hmac

        name = opts.get("-f") or f"{home}/.ssh/known_hosts"
        host = opts.get("-F") or opts.get("-R")
        path = self.fs.resolve_path(name, self.cwd)
        if not self.fs.exists(path):
            if "-R" in opts:
                self.errorWrite("mkstemp: No such file or directory\n" if not self.fs.isdir(posixpath.dirname(path))
                                else f"Cannot stat {name}: No such file or directory\n")
            return 255 if "-R" in opts else 1
        text = self.qpot_read(name)
        if text is None:
            return 255

        def names_host(first: str) -> bool:
            if first.startswith("|1|"):
                parts = first.split("|")
                if len(parts) != 4:
                    return False
                try:
                    salt, want = base64.b64decode(parts[2]), base64.b64decode(parts[3])
                except Exception:  # noqa: BLE001
                    return False
                return hmac.compare_digest(hmac.new(salt, host.encode(), hashlib.sha1).digest(), want)
            return any(fnmatch.fnmatchcase(host, pattern) for pattern in first.split(",") if not pattern.startswith("!"))

        found, kept = [], []
        for number, line in enumerate(text.splitlines(), 1):
            words = line.split()
            if words and not line.lstrip().startswith("#") and names_host(words[1] if words[0].startswith("@") else words[0]):
                found.append((number, line))
            else:
                kept.append(line)
        if "-F" in opts:
            for number, line in found:
                self.write(f"# Host {host} found: line {number}\n")
                key = qpot_key_line(line)
                if "-l" in opts and key:
                    self.write(f"{host} {KEYGEN_NAMES[key[0]][0]} {qpot_fingerprint(key[1], md5)}\n")
                else:
                    self.write(line + "\n")
            return 0 if found else 1
        if not found:
            self.errorWrite(f"Host {host} not found in {name}\n")
            return 0
        node = self.fs.getfile(path)
        data = ("".join(line + "\n" for line in kept)).encode()
        try:
            old = self.fs.file_contents(path)
            self.fs.mkfile(path + ".old", node[tree_fs.A_UID], node[tree_fs.A_GID], len(old), node[tree_fs.A_MODE], time.time())
            self.fs.getfile(path + ".old")[tree_fs.A_CONTENTS] = old
            node[tree_fs.A_CONTENTS] = data
            node[tree_fs.A_SIZE] = len(data)
        except Exception:  # noqa: BLE001
            self.errorWrite(f"{name}: Read-only file system\n")
            return 255
        for number, _ in found:
            self.write(f"# Host {host} found: line {number}\n")
        self.write(f"{name} updated.\nOriginal contents retained as {name}.old\n")
        return 0


commands["/usr/bin/ssh-keygen"] = Command_ssh_keygen
commands["/bin/ssh-keygen"] = Command_ssh_keygen
