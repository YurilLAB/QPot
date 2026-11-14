# SPDX-License-Identifier: BSD-3-Clause

"""The bait files of the persona (QPot).

QPot writes a plan per instance (internal/instance/bait.go) and mounts it
read-only at PLAN_PATH: the files of an ops box's working state (SSH keys and
config, a backup script, cloud credentials, a database dump, shell histories)
with canaries in them. honeyfs loads the persona's tree once per process and
hands it to plant() before any session sees it; plant() adds the plan's
directories, files, links and programs where the persona has none, so a file
of the persona always wins.

What only the running persona knows is filled in here: {{host}} is the host
name it drew, {{date:FMT}} the time of the file, placed between the persona's
installation and its boot (identity.json of the runtime) as the plan's "at"
says; {{date:FMT@ID}} is the time of another file, and |OFFSET moves either by
that many seconds. Owners are looked up in the persona's /etc/passwd. A file
marked gzip is compressed as `... | gzip > file` writes it.

The plan is QPot's own, but its reading is bounded all the same (size, number
of entries, length of a text) and an entry that does not fit is skipped: a
broken plan leaves the persona's tree as it was and never stops Cowrie.
"""

from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import json
import os
import posixpath
import re
import stat
import struct
import time
import zlib
from typing import Any

from twisted.logger import Logger

from cowrie.core.config import CowrieConfig

PLAN_PATH = "/home/cowrie/cowrie/qpot-bait.json"
MAX_PLAN_BYTES = 8 << 20
MAX_ENTRIES = 512
MAX_TEXT = 4 << 20
MAX_SMALL_FILE = 1 << 20
MAX_PATH = 1024
MAX_DEPTH = 32

# the node layout of cowrie.shell.fs (honeyfs keeps its own copy for the same reason: fs imports honeyfs)
A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(10)
T_LINK, T_DIR, T_FILE = 0, 1, 2

# {{host}}, {{date:FMT}}, {{date:FMT@ID}}, each date with an optional |OFFSET
PLACEHOLDER = re.compile(r"\{\{(?:(host)|date:([^{}|@]{1,40})(?:@([a-z0-9_-]{1,32}))?(?:\|(-?[0-9]{1,10}))?)\}\}")

_log = Logger()


def _read_bounded(path: str, limit: int) -> bytes | None:
    """The bytes of a regular file, None when it is missing, no regular file or larger than limit."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        with os.fdopen(fd, "rb") as handle:
            fd = None
            data = handle.read(limit + 1)
    except OSError:
        return None
    finally:
        if fd is not None:
            os.close(fd)
    return data if len(data) <= limit else None


def _list(value: Any) -> list:
    return value[:MAX_ENTRIES] if isinstance(value, list) else []


@functools.cache
def plan() -> dict:
    """The plan, read once; an empty one when there is none or it cannot be read."""
    data = _read_bounded(PLAN_PATH, MAX_PLAN_BYTES)
    if data is None:
        return {}
    try:
        loaded = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        _log.warn("QPot bait plan {path} is no JSON, nothing planted", path=PLAN_PATH)
        return {}
    if not isinstance(loaded, dict) or loaded.get("version") != 1:
        _log.warn("QPot bait plan {path} is of an unknown version, nothing planted", path=PLAN_PATH)
        return {}
    return {key: _list(loaded.get(key)) for key in ("dirs", "files", "links", "programs", "hosts")}


@functools.cache
def _hosts() -> dict[str, str]:
    found: dict[str, str] = {}
    for host in plan().get("hosts", []):
        if not isinstance(host, dict) or not isinstance(host.get("ip"), str):
            continue
        for name in _list(host.get("names"))[:16]:
            if isinstance(name, str) and 0 < len(name) <= 253:
                found[name.lower()] = host["ip"]
    return found


def internal_host(name: str) -> str | None:
    """The address of an internal host the bait files name (its alias, FQDN or address), else None."""
    if not isinstance(name, str) or len(name) > 253:
        return None
    return _hosts().get(name.lower().rstrip("."))


def _contents_root() -> str:
    try:
        return CowrieConfig.get("honeypot", "contents_path", fallback="") or ""
    except Exception:  # noqa: BLE001 - no config section: no honeyfs
        return ""


def _identity() -> tuple[int, int]:
    """(installed_at, booted_at) of the persona; a year back to a month back when unknown."""
    now = int(time.time())
    root = _contents_root()
    data = _read_bounded(os.path.join(os.path.dirname(root.rstrip("/")), "identity.json"), 1 << 16) if root else None
    try:
        ident = json.loads(data.decode("utf-8")) if data else {}
        installed, booted = ident.get("installed_at"), ident.get("booted_at")
        if type(installed) is int and type(booted) is int and 0 < installed <= booted <= now:
            return installed, booted
    except (UnicodeDecodeError, ValueError, AttributeError):
        pass
    return now - 365 * 86400, now - 30 * 86400


def _accounts(tree: list) -> dict[str, tuple[int, int]]:
    """name -> (uid, gid) of the persona's /etc/passwd (its honeyfs copy, else the tree's)."""
    root = _contents_root()
    data = _read_bounded(os.path.join(root, "etc/passwd"), MAX_SMALL_FILE) if root else None
    if data is None:
        node = _find(tree, "/etc/passwd")
        data = node[A_CONTENTS] if node is not None and isinstance(node[A_CONTENTS], bytes) else b""
    found = {"root": (0, 0)}
    for line in data.decode("utf-8", "replace").splitlines()[:4096]:
        parts = line.split(":")
        if len(parts) >= 4 and parts[2].isdigit() and parts[3].isdigit():
            found.setdefault(parts[0], (int(parts[2]), int(parts[3])))
    return found


def _parts(path: str) -> list[str] | None:
    """The parts of an absolute, normalised path, None for anything else."""
    if not isinstance(path, str) or not path.startswith("/") or len(path) > MAX_PATH or "\0" in path:
        return None
    parts = path.split("/")[1:]
    if not parts or len(parts) > MAX_DEPTH or any(p in ("", ".", "..") or len(p) > 255 for p in parts):
        return None
    return parts


def _child(node: list, name: str) -> list | None:
    children = node[A_CONTENTS]
    if not isinstance(children, list):
        return None
    return next((c for c in children if c[A_NAME] == name), None)


def _find(tree: list, path: str) -> list | None:
    """The node of an absolute path, without following links."""
    parts = _parts(path)
    node = tree
    for part in parts or []:
        node = _child(node, part)
        if node is None:
            return None
    return node if parts else None


def _touch(directory: list, when: int) -> None:
    """An entry was made in directory at when: its time moves on to it."""
    if not isinstance(directory[A_CTIME], (int, float)) or directory[A_CTIME] < when:
        directory[A_CTIME] = when


def _parent(tree: list, parts: list[str], when: int) -> list | None:
    """The directory of the last part, made (root's, 0755) where missing; None when a part of the
    way is no directory (a link, a file): the plan does not write through links."""
    node = tree
    for part in parts[:-1]:
        child = _child(node, part)
        if child is None:
            child = [part, T_DIR, 0, 0, 4096, stat.S_IFDIR | 0o755, when, [], None, None]
            node[A_CONTENTS].append(child)
            _touch(node, when)
        elif child[A_TYPE] != T_DIR or not isinstance(child[A_CONTENTS], list):
            return None
        node = child
    return node


# an identity file ssh reads: a private key is a few KB, its .pub one line
MAX_KEY_FILE = 1 << 16
# the armor lines of an OpenSSH private key, put together here (as canary's pemArmor does) so that
# the source holds no key-shaped text for a secret scanner to report
_OPENSSH_KEY = re.compile("-----" + "BEGIN" + " OPENSSH PRIVATE KEY-----" + r"([A-Za-z0-9+/=\s]{1,65536}?)"
                          + "-----" + "END" + " OPENSSH PRIVATE KEY-----")
_KEY_TYPES = ("ssh-", "ecdsa-sha2-", "sk-")


def _ssh_string(data: bytes, pos: int) -> tuple[bytes | None, int]:
    """The SSH wire string at pos and the position after it; None when data ends first."""
    if pos + 4 > len(data):
        return None, pos
    size = struct.unpack(">I", data[pos:pos + 4])[0]
    if pos + 4 + size > len(data):
        return None, pos
    return data[pos + 4:pos + 4 + size], pos + 4 + size


def key_type(blob: bytes) -> str | None:
    """The type a public key blob names (ssh-ed25519, ecdsa-sha2-nistp256 ...), None for no key blob."""
    name, _ = _ssh_string(blob, 0)
    if not name or len(name) > 64:
        return None
    text = name.decode("ascii", "replace")
    return text if text.startswith(_KEY_TYPES) and text.isprintable() else None


def public_key(data: bytes) -> bytes | None:
    """The public key blob of an identity file, as ssh offers it: an OpenSSH private key keeps its
    public half in the clear (encrypted or not), a .pub or authorized_keys line is one; None for
    anything else (a PEM key ssh would read the public half of from its .pub)."""
    text = data[:MAX_KEY_FILE].decode("ascii", "replace")
    found = _OPENSSH_KEY.search(text)
    if found:
        try:
            raw = base64.b64decode("".join(found.group(1).split()), validate=True)
        except (binascii.Error, ValueError):
            return None
        magic = b"openssh-key-v1\0"
        if not raw.startswith(magic):
            return None
        pos = len(magic)
        for _ in range(3):  # cipher, kdf and its options
            field, pos = _ssh_string(raw, pos)
            if field is None:
                return None
        if pos + 4 > len(raw) or struct.unpack(">I", raw[pos:pos + 4])[0] < 1:
            return None
        blob, _ = _ssh_string(raw, pos + 4)
        return blob if blob and key_type(blob) else None
    for line in text.splitlines()[:64]:
        words = line.split()
        for i, word in enumerate(words[:-1]):
            if word.startswith(_KEY_TYPES) and len(word) <= 64:
                try:
                    blob = base64.b64decode(words[i + 1], validate=True)
                except (binascii.Error, ValueError):
                    continue
                if key_type(blob) == word:
                    return blob
    return None


def key_fingerprint(blob: bytes) -> str:
    """The colon-separated MD5 fingerprint of a public key blob, the form Cowrie logs for a login's key."""
    return ":".join(f"{b:02x}" for b in hashlib.md5(blob).digest())  # noqa: S324 - OpenSSH's legacy fingerprint


def gzip_bytes(data: bytes) -> bytes:
    """data as GNU gzip writes it from a pipe at its default level: no name, no time, OS Unix."""
    compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
    body = compressor.compress(data) + compressor.flush()
    return b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03" + body + struct.pack(
        "<II", zlib.crc32(data) & 0xFFFFFFFF, len(data) & 0xFFFFFFFF)


def render(text: str, own: int, times: dict[str, int], host: str) -> str:
    """text with its placeholders filled in; ValueError for a reference to no file."""
    def fill(match: re.Match) -> str:
        if match.group(1):
            return host
        fmt, ref, offset = match.group(2), match.group(3), match.group(4)
        if ref is not None and ref not in times:
            raise ValueError(f"no file {ref}")
        when = time.gmtime(max((times[ref] if ref is not None else own) + int(offset or 0), 0))
        # %k (the hour padded with a space, mysqldump's) is glibc's; the image's libc is musl
        return time.strftime(fmt.replace("%k", f"{when.tm_hour:2d}"), when)
    return PLACEHOLDER.sub(fill, text)


def _mode(value: Any, default: int) -> int:
    return value & 0o7777 if type(value) is int and 0 <= value <= 0o7777 else default


def _at(value: Any) -> float:
    return min(max(float(value), 0.0), 1.0) if isinstance(value, (int, float)) else 0.5


# the persona's host key files and the [ssh] option that names the key its SSH server presents
HOST_KEYS = (("ssh_host_rsa_key.pub", "rsa_public_key"), ("ssh_host_ecdsa_key.pub", "ecdsa_public_key"),
             ("ssh_host_ed25519_key.pub", "ed25519_public_key"))


def _fill(node: list, data: bytes, sized: bool = True) -> None:
    """Give a file its bytes; a file of /proc keeps the size 0 the kernel shows for it."""
    node[A_CONTENTS] = data
    if sized:
        node[A_SIZE] = len(data)


def host_facts(tree: list) -> int:
    """What the host says of itself in files the image left empty; the number of files filled.

    /etc/ssh/ssh_host_*_key.pub: the keys the SSH server presents, so `ssh-keygen -lf` of them is
    the fingerprint the visitor's own client showed at the login (the files had the image's sizes
    and no bytes: `cat` printed nothing where `ls -l` showed 99). /proc/1/cgroup and
    /proc/self/cgroup: what a systemd host with the unified hierarchy shows (an empty file there
    is what a check for a container trips on); a persona of the older hierarchy keeps its files.
    """
    done = 0
    host = CowrieConfig.get("honeypot", "hostname", fallback="localhost")
    for name, option in HOST_KEYS:
        node = _find(tree, "/etc/ssh/" + name)
        if node is None or node[A_TYPE] != T_FILE:
            continue
        try:
            data = _read_bounded(CowrieConfig.get("ssh", option), 16384)
        except Exception:  # noqa: BLE001 - a key the configuration does not name
            data = None
        words = data.decode("ascii", "replace").split() if data else []
        if len(words) < 2:
            continue
        try:
            blob = base64.b64decode(words[1], validate=True)
        except (binascii.Error, ValueError):
            continue
        if key_type(blob) != words[0]:
            continue
        _fill(node, f"{words[0]} {words[1]} root@{host}\n".encode("ascii", "replace"))
        done += 1
    # the unified hierarchy: systemd 247 and later make it the default (Debian 11, Ubuntu 21.10, RHEL 9)
    unified = _find(tree, "/sys/fs/cgroup/cgroup.controllers") is not None
    init = _find(tree, "/proc/1/cgroup")
    if init is not None and init[A_TYPE] == T_FILE and not init[A_CONTENTS] and (
            unified or _find(tree, "/sys/fs/cgroup/systemd") is None and _find(tree, "/run/systemd/system") is not None):
        _fill(init, b"0::/init.scope\n", False)
        done += 1
        # the shell's own: the scope of a login session of root (/proc/self is a link to its process)
        own = _find(tree, "/proc/self")
        if own is not None and own[A_TYPE] == T_LINK and isinstance(own[A_TARGET], str):
            own = _find(tree, posixpath.normpath(posixpath.join("/proc", own[A_TARGET])))
        own = _child(own, "cgroup") if own is not None and own[A_TYPE] == T_DIR else None
        if own is not None and own[A_TYPE] == T_FILE and not own[A_CONTENTS]:
            session = 2 + int(hashlib.sha256(host.encode("utf-8", "replace")).hexdigest()[:4], 16) % 400
            _fill(own, f"0::/user.slice/user-0.slice/session-{session}.scope\n".encode(), False)
            done += 1
    return done


def plant(tree: list) -> int:
    """Add the plan to the persona's tree (before any session copies it); the number of entries added."""
    current = plan()
    if not current or not any(current.get(k) for k in ("dirs", "files", "links", "programs")):
        return 0
    installed, booted = _identity()
    span = booted - installed

    def when(at: Any) -> int:
        return installed + int(span * _at(at))

    def moved(entry: dict) -> int:
        """The time of a file: its place on the timeline, moved by its offset (not before the installation)."""
        offset = entry.get("offset", 0)
        offset = offset if type(offset) is int and abs(offset) <= 10 * 365 * 86400 else 0
        return max(when(entry.get("at")) + offset, installed)

    accounts = _accounts(tree)
    host = CowrieConfig.get("honeypot", "hostname", fallback="localhost")
    times = {f["id"]: moved(f) for f in current["files"]
             if isinstance(f, dict) and isinstance(f.get("id"), str)}
    added = 0

    def owner(entry: dict) -> tuple[int, int] | None:
        name = entry.get("owner", "root")
        return accounts.get(name) if isinstance(name, str) else None

    for entry in current["dirs"]:
        parts = _parts(entry.get("path")) if isinstance(entry, dict) else None
        ids = owner(entry) if parts else None
        if ids is None:
            continue
        made = when(entry.get("at"))
        parent = _parent(tree, parts, made)
        if parent is None or _child(parent, parts[-1]) is not None:
            continue
        parent[A_CONTENTS].append([parts[-1], T_DIR, ids[0], ids[1], 4096,
                                   stat.S_IFDIR | _mode(entry.get("mode"), 0o755), made, [], None, None])
        _touch(parent, made)
        added += 1

    for entry in current["programs"]:
        parts = _parts(entry.get("path")) if isinstance(entry, dict) else None
        size = entry.get("size") if parts else None
        if type(size) is not int or not 0 < size < 1 << 31:
            continue
        made = when(entry.get("at"))
        parent = _parent(tree, parts, made)
        if parent is None or _child(parent, parts[-1]) is not None:
            continue
        parent[A_CONTENTS].append([parts[-1], T_FILE, 0, 0, size, stat.S_IFREG | 0o755, made, [], None, None])
        _touch(parent, made)
        added += 1

    for entry in current["links"]:
        parts = _parts(entry.get("path")) if isinstance(entry, dict) else None
        target = entry.get("target") if parts else None
        if not isinstance(target, str) or not 0 < len(target) <= MAX_PATH or "\0" in target:
            continue
        made = when(entry.get("at"))
        parent = _parent(tree, parts, made)
        if parent is None or _child(parent, parts[-1]) is not None:
            continue
        parent[A_CONTENTS].append([parts[-1], T_LINK, 0, 0, len(target), stat.S_IFLNK | 0o777, made, [],
                                   target, None])
        _touch(parent, made)
        added += 1

    for entry in current["files"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("text"), str) or len(entry["text"]) > MAX_TEXT:
            continue
        ids = owner(entry)
        made = moved(entry)
        try:
            parts = _parts(render(entry.get("path"), made, times, host)) if isinstance(entry.get("path"), str) else None
            data = render(entry["text"], made, times, host).encode("utf-8")
        except (ValueError, OverflowError):
            continue
        if parts is None or ids is None:
            continue
        if entry.get("gzip") is True:
            data = gzip_bytes(data)
        parent = _parent(tree, parts, made)
        if parent is None or _child(parent, parts[-1]) is not None:
            # the persona's own file wins (gpu-ubuntu's ~/.bash_history)
            continue
        parent[A_CONTENTS].append([parts[-1], T_FILE, ids[0], ids[1], len(data),
                                   stat.S_IFREG | _mode(entry.get("mode"), 0o644), made, data, None, None])
        if entry.get("in_place") is not True:
            _touch(parent, made)
        added += 1
    _log.info("QPot bait: {added} entries planted", added=added)
    return added
