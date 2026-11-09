# SPDX-License-Identifier: BSD-3-Clause
"""Actor-bound permissions for Cowrie's connection-owned virtual filesystem.

Only emulated nodes are inspected here. The raw filesystem remains owned by its
virtual server; an individual process view never changes another channel's user.
"""
from __future__ import annotations

import errno
import functools
import os
import posixpath
import re
import stat
import time
from pathlib import Path

from cowrie.core.qpot_state import connection_filesystem, effective_user


class Denied(PermissionError):
    def __init__(self, path):
        super().__init__(errno.EACCES, "Permission denied", path)


def _remap_open_inodes(raw, before, after, memo=None):
    """Follow copies, while keeping removed/replaced open nodes unlinked."""
    records = getattr(raw, "_qpot_inodes", {})
    if not records:
        return
    linked, pending = set(), [after]
    while pending:
        node = pending.pop()
        linked.add(id(node))
        if node[1] == 1:
            pending.extend(node[7])
    if memo is None:
        memo, pending = {}, [(before, after)]
        while pending:
            old, new = pending.pop()
            memo[id(old)] = new
            if old[1] == new[1] == 1:
                children = {child[0]: child for child in new[7]}
                pending.extend((child, children[child[0]]) for child in old[7] if child[0] in children)
    for key, inode in list(records.items()):
        copied = memo.get(id(inode["node"]))
        if isinstance(copied, list) and id(copied) in linked:
            records.pop(key, None)
            inode["node"] = copied
            records[id(copied)] = inode


def _inode_registry(filesystem):
    raw = connection_filesystem(filesystem)
    if not hasattr(raw, "_qpot_inodes"):
        raw._qpot_inodes = {}
        private = raw._ensure_private_fs
        def ensure_private():
            before = raw.fs
            private()
            if raw.fs is not before:
                _remap_open_inodes(raw, before, raw.fs)
        raw._ensure_private_fs = ensure_private
        replaced = getattr(raw, "qpot_tree_replaced", None)
        def tree_replaced(before, after, memo=None):
            if callable(replaced):
                replaced(before, after, memo)
            _remap_open_inodes(raw, before, after, memo)
        raw.qpot_tree_replaced = tree_replaced
    return raw, raw._qpot_inodes


def _open_inode(filesystem, node):
    _, records = _inode_registry(filesystem)
    return records.setdefault(id(node), {"node": node, "writers": set(), "artifact": None})


class Filesystem:
    def __init__(self, filesystem, actor, on_denied=None):
        object.__setattr__(self, "_raw", getattr(filesystem, "_raw", filesystem))
        object.__setattr__(self, "_actor", actor)
        object.__setattr__(self, "_on_denied", on_denied)

    def _denied(self, path):
        if self._on_denied is not None:
            self._on_denied()
        raise Denied(path)

    def __getattr__(self, name):
        return getattr(self._raw, name)

    def __setattr__(self, name, value):
        setattr(self._raw, name, value)

    def _identity(self):
        user = self._actor()
        uid, gid = user.get("uid"), user.get("gid")
        if not isinstance(uid, int) or not isinstance(gid, int) or uid < 0 or gid < 0:
            self._denied("/")
        groups = {gid}
        snapshot = user.get("groups")
        if isinstance(snapshot, (list, tuple, set)):
            groups.update(value for value in list(snapshot)[:4096]
                          if isinstance(value, int) and 0 <= value < 0xFFFFFFFF)
            return uid, groups
        name = user.get("username", "")
        try:
            contents = self._raw.file_contents("/etc/group")
            if len(contents) <= 262144:
                for row in contents.decode("utf8", "replace").splitlines()[:4096]:
                    fields = row.split(":")
                    if len(fields) == 4 and name and name in fields[3].split(",") and fields[2].isascii() and fields[2].isdigit() and len(fields[2]) <= 10:
                        groups.add(int(fields[2]))
        except (OSError, ValueError, KeyError):
            pass
        return uid, groups

    def _allow(self, node, bits, path):
        uid, groups = self._identity()
        if uid == 0:
            return
        shift = 6 if uid == node[2] else 3 if node[3] in groups else 0
        if ((node[5] >> shift) & bits) != bits:
            self._denied(path)

    def _resolve(self, path, follow=True, missing=False):
        """Resolve bounded links while checking search access on every ancestor."""
        if not isinstance(path, str) or len(path) > 4096 or "\0" in path:
            raise OSError(errno.ENAMETOOLONG, "Invalid path", path)
        path = posixpath.normpath("/" + path.lstrip("/"))
        pending = [part for part in path.split("/") if part]
        resolved = []
        node = self._raw.fs
        links = 0
        steps = 0
        while pending:
            steps += 1
            if steps > 512:
                raise OSError(errno.ELOOP, "Too many symbolic links", path)
            if node[1] != 1:
                raise OSError(errno.ENOTDIR, "Not a directory", path)
            self._allow(node, 1, "/" + "/".join(resolved))
            part = pending.pop(0)
            child = next((entry for entry in node[7] if entry[0] == part), None)
            if child is None:
                if missing and not pending:
                    return None, "/" + "/".join([*resolved, part])
                return None, path
            if child[1] == 0 and (follow or pending):
                links += 1
                if links > 40:
                    raise OSError(errno.ELOOP, "Too many symbolic links", path)
                target = child[8]
                if not isinstance(target, str) or not target:
                    return None, path
                expanded = posixpath.normpath(posixpath.join("/" + "/".join(resolved), target))
                pending = [piece for piece in expanded.split("/") if piece] + pending
                resolved = []
                node = self._raw.fs
                continue
            resolved.append(part)
            node = child
        return node, "/" + "/".join(resolved)

    def getfile(self, path, follow_symlinks=True):
        if posixpath.normpath(path) == "/":
            return connection_filesystem(self._raw).fs
        return self._resolve(path, follow_symlinks)[0]

    def get_path(self, path, follow_symlinks=True):
        node, resolved = self._resolve(path, follow_symlinks)
        if node is None:
            from cowrie.shell.fs import FileNotFound
            raise FileNotFound(path)
        self._allow(node, 5, resolved)
        return self._raw.get_path(resolved, follow_symlinks=False)

    def exists(self, path):
        try:
            return self.getfile(path) is not None
        except PermissionError:
            return False

    def lexists(self, path):
        try:
            return self.getfile(path, False) is not None
        except PermissionError:
            return False

    def _required(self, path, bits=0, follow=True):
        node, resolved = self._resolve(path, follow)
        if node is None:
            raise OSError(errno.ENOENT, "No such file or directory", path)
        self._allow(node, bits, path)
        return node, resolved

    def file_contents(self, path):
        node, resolved = self._resolve(path)
        if node is not None:
            self._allow(node, 4, path)
        return self._raw.file_contents(resolved)

    def listdir(self, path):
        node, resolved = self._required(path, 5)
        if node[1] != 1:
            raise OSError(errno.ENOTDIR, "Not a directory", path)
        return self._raw.listdir(resolved)

    def stat(self, path, follow_symlinks=True):
        _, resolved = self._required(path, follow=follow_symlinks)
        return self._raw.stat(resolved, follow_symlinks=False)

    def lstat(self, path):
        return self.stat(path, False)

    def isdir(self, path):
        node = self.getfile(path)
        return node is not None and node[1] == 1

    def isfile(self, path):
        node = self.getfile(path)
        return node is not None and node[1] == 2

    def islink(self, path):
        node = self.getfile(path, False)
        return node is not None and node[1] == 0

    def is_executable(self, path, uid, gid):
        try:
            node, _ = self._required(path)
            if node[1] != 2 or not node[5] & 0o111:
                return False
            self._allow(node, 1, path)
            return True
        except PermissionError:
            return False

    def _parent(self, path):
        parent, resolved = self._required(posixpath.dirname(path) or "/", 3)
        if parent[1] != 1:
            raise OSError(errno.ENOTDIR, "Not a directory", path)
        return parent, posixpath.join(resolved, posixpath.basename(path))

    def _writable_path(self, resolved):
        # /proc is a generated per-channel view. No writable kernel controls
        # are implemented, so actor writes must fail before touching either
        # its snapshot or the canonical connection tree.
        if resolved == "/proc" or resolved.startswith("/proc/"):
            self._denied(resolved)

    def check_write(self, path):
        node, resolved = self._resolve(path, missing=True)
        self._writable_path(resolved)
        if node is None:
            _, resolved = self._parent(resolved)
        else:
            self._allow(node, 2, path)
            if node[1] == 1:
                raise OSError(errno.EISDIR, "Is a directory", path)
        return node, resolved

    def mkfile(self, path, uid, gid, size, mode, ctime=None):
        existing, resolved = self.check_write(path)
        # Redirection preserves the existing inode owner and mode.
        if existing is not None:
            self._raw._ensure_private_fs()
            existing = self._raw.getfile(resolved)
            existing[7], existing[9] = [], None
            self._raw.update_size(resolved, size)
            now = time.time() if ctime is None else ctime
            self._raw.utime(resolved, now, now)
            return True
        return self._raw.mkfile(resolved, uid, gid, size, mode, ctime)

    def mkdir(self, path, uid, gid, size, mode, ctime=None):
        _, resolved = self._parent(path)
        self._writable_path(resolved)
        if self.getfile(path, False) is not None:
            raise OSError(errno.EEXIST, "File exists", path)
        return self._raw.mkdir(resolved, uid, gid, size, mode, ctime)

    def mkdir2(self, path):
        user = self._actor()
        return self.mkdir(path, user["uid"], user["gid"], 4096, stat.S_IFDIR | 0o755)

    def _owner(self, path):
        node, resolved = self._required(path)
        self._writable_path(resolved)
        uid, _ = self._identity()
        if uid not in (0, node[2]):
            self._denied(path)
        return node, resolved

    def chmod(self, path, mode):
        _, resolved = self._owner(path)
        return self._raw.chmod(resolved, mode)

    def chown(self, path, uid, gid):
        node, resolved = self._owner(path)
        actor_uid, groups = self._identity()
        if actor_uid and (uid not in (-1, node[2]) or gid not in ({-1} | groups)):
            self._denied(path)
        return self._raw.chown(resolved, uid, gid)

    def utime(self, path, atime, mtime):
        _, resolved = self._owner(path)
        return self._raw.utime(resolved, atime, mtime)

    def touch(self, path):
        node, resolved = self._required(path)
        self._writable_path(resolved)
        uid, _ = self._identity()
        if uid not in (0, node[2]):
            self._allow(node, 2, path)
        now = time.time()
        return self._raw.utime(resolved, now, now)

    def _unlink(self, path):
        node, resolved = self._required(path, follow=False)
        self._writable_path(resolved)
        if resolved == "/":
            raise OSError(errno.EBUSY, "Device or resource busy", path)
        parent, _ = self._parent(resolved)
        uid, _ = self._identity()
        if parent[5] & stat.S_ISVTX and uid not in (0, parent[2], node[2]):
            self._denied(path)
        return node, resolved

    def remove(self, path):
        node, resolved = self._unlink(path)
        # The pinned active rmdir command uses this VFS operation for empty
        # directories too. SFTP's unlink-only boundary is enforced separately.
        if node[1] == 1 and node[7]:
            raise OSError(errno.ENOTEMPTY, "Directory not empty", path)
        return self._raw.remove(resolved)

    def rmdir(self, path):
        _, resolved = self._unlink(path)
        return self._raw.rmdir(resolved)

    def rename(self, oldpath, newpath):
        node, old = self._unlink(oldpath)
        _, new = self._parent(newpath)
        self._writable_path(new)
        target = self.getfile(new, False)
        if old == new:
            return None
        if node[1] == 1 and new.startswith(old.rstrip("/") + "/"):
            raise OSError(errno.EINVAL, "Invalid argument", newpath)
        if target is not None:
            self._unlink(new)
            if (target[1] == 1) != (node[1] == 1):
                raise OSError(errno.EISDIR if target[1] == 1 else errno.ENOTDIR, "Incompatible file type", newpath)
            if target[1] == 1 and target[7]:
                raise OSError(errno.ENOTEMPTY, "Directory not empty", newpath)
        # Every failure above precedes raw rename's destructive unlink.
        return self._raw.rename(old, new)

    def readlink(self, path):
        _, resolved = self._required(path, follow=False)
        return self._raw.readlink(resolved)

    def open(self, path, flags, mode):
        raw, _ = _inode_registry(self._raw)
        access = flags & os.O_ACCMODE
        node, resolved = self._resolve(path, missing=True)
        if access != os.O_RDONLY or flags & (os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            self._writable_path(resolved)
        if flags & os.O_EXCL and flags & os.O_CREAT and node is not None:
            raise OSError(errno.EEXIST, "File exists", path)
        if node is None and not flags & os.O_CREAT:
            raise OSError(errno.ENOENT, "No such file or directory", path)
        if access in (os.O_RDONLY, os.O_RDWR):
            if node is None:
                self._parent(resolved)
            else:
                self._allow(node, 4, path)
        if access in (os.O_WRONLY, os.O_RDWR):
            node, resolved = self.check_write(resolved)
            if node is None and raw.newcount >= 10000:
                raise OSError(errno.EDQUOT, "Disk quota exceeded", path)
        old_bytes = (self._raw.file_contents(resolved) if node is not None
                     and access != os.O_RDONLY and not flags & os.O_TRUNC else b"")
        if node is not None and access != os.O_RDONLY:
            self._raw._ensure_private_fs()
            node = self._raw.getfile(resolved)
        inode = _open_inode(raw, node) if node is not None else None
        redirections = getattr(raw, "_qpot_redirect_owners", {})
        if (access != os.O_RDONLY and inode is not None and
                (inode["writers"] or redirections.get(node[9]))):
            # Every descriptor of an inode writes the same live artifact.
            # Only the final writer may turn it into an immutable capture.
            inode["artifact"] = node[9]
            fd = os.open(inode["artifact"], flags & ~(os.O_CREAT | os.O_EXCL), mode & 0o666)
            raw.tempfiles[fd], raw.filenames[fd] = inode["artifact"], resolved
            if flags & os.O_TRUNC:
                node[4], node[7] = 0, []
                self._raw.utime(resolved, time.time(), time.time())
            inode["writers"].add(fd)
            if not hasattr(raw, "_qpot_open_nodes"):
                raw._qpot_open_nodes = {}
            raw._qpot_open_nodes[fd] = inode
            return fd
        # The emulated path was validated above. The raw implementation opens
        # a new private artifact, which needs creation even for an existing VFS
        # file opened without O_CREAT.
        raw_flags = flags | os.O_CREAT if access != os.O_RDONLY else flags
        fd = self._raw.open(resolved, raw_flags, mode)
        if access != os.O_RDONLY:
            user = self._actor()
            if node is None:
                self._raw.chown(resolved, user["uid"], user["gid"])
            else:
                replacement = self._raw.getfile(resolved)
                node[4], node[7], node[9] = replacement[4], replacement[7], replacement[9]
                self._raw.link_entry(node, posixpath.dirname(resolved))
                now = time.time()
                self._raw.utime(resolved, now, now)
            if old_bytes:
                self._raw.write(fd, old_bytes)
                self._raw.lseek(fd, 0, os.SEEK_SET)
                self._raw.update_size(resolved, len(old_bytes))
        if fd is not None:
            registry = getattr(raw, "_qpot_open_nodes", None)
            if registry is None:
                raw._qpot_open_nodes = registry = {}
            inode = _open_inode(raw, self._raw.getfile(resolved))
            inode["artifact"] = raw.tempfiles[fd]
            inode["writers"].add(fd)
            registry[fd] = inode
        return fd

    def close(self, fd):
        raw = connection_filesystem(self._raw)
        inode = getattr(raw, "_qpot_open_nodes", {}).pop(fd, None)
        if inode is None:
            return self._raw.close(fd)
        inode["writers"].discard(fd)
        if inode["writers"] or getattr(raw, "_qpot_redirect_owners", {}).get(inode["node"][9]):
            os.close(fd)
            del raw.tempfiles[fd], raw.filenames[fd]
            return None
        node, events = inode["node"], raw.events
        original_name = raw.filenames[fd]
        current_path = _node_path(raw, node)
        redirects = inode.pop("redirect_events", [])
        duplicate = False
        if redirects:
            import hashlib
            artifact = Path(raw.tempfiles[fd])
            duplicate = (artifact.parent / hashlib.sha256(artifact.read_bytes()).hexdigest()).exists()
        # An unlinked open inode must never update a replacement at its old
        # filename. NUL cannot name a virtual node through the path validator.
        raw.filenames[fd] = current_path if current_path is not None else "\0"
        class UploadEvents:
            def __getattr__(self, name):
                return getattr(events, name)
            def dispatch(self, event, *args, **fields):
                if event == "cowrie.session.file_upload":
                    node[9] = fields["outfile"]
                    fields["filename"] = posixpath.basename(original_name)
                    for emitter, destination in redirects:
                        emitter.dispatch("cowrie.session.file_download",
                                         "Saved redir contents with SHA-256 %(shasum)s to %(outfile)s",
                                         duplicate=duplicate, outfile=fields["outfile"],
                                         shasum=fields["shasum"], destfile=destination)
                return events.dispatch(event, *args, **fields)
        raw.events = UploadEvents()
        try:
            return raw.close(fd)
        finally:
            raw.events = events
            inode["artifact"] = None


def _node_path(raw, wanted):
    pending, seen = [(raw.fs, "/")], set()
    while pending and len(seen) < 65536:
        node, path = pending.pop()
        if node is wanted:
            return path
        if id(node) in seen:
            continue
        seen.add(id(node))
        if node[1] == 1:
            pending.extend((child, posixpath.join(path, child[0])) for child in node[7])
    return None


class Protocol:
    def __init__(self, protocol, actor, on_denied=None):
        object.__setattr__(self, "_protocol", getattr(protocol, "_protocol", protocol))
        object.__setattr__(self, "fs", Filesystem(self._protocol.fs, actor, on_denied))

    def __getattr__(self, name):
        return getattr(self._protocol, name)

    def __setattr__(self, name, value):
        setattr(self._protocol, name, value)


def _guard(instance, method):
    @functools.wraps(method)
    def guarded(*args, **kwargs):
        def denied(error):
            instance.errorWrite(f"{type(instance).__name__.removeprefix('Command_')}: {error.filename or ''}: Permission denied\n")
            instance.exit(1)
        try:
            result = method(*args, **kwargs)
        except PermissionError as error:
            denied(error)
            return None
        if hasattr(result, "addErrback"):
            def errback(failure):
                if failure.check(PermissionError):
                    denied(failure.value)
                    return None
                return failure
            result.addErrback(errback)
        return result
    return guarded


def install():
    """Install bounded adapters once; mutable state remains on each virtual FS."""
    from cowrie.shell import command, honeypot, pipe, server, filetransfer
    if getattr(command.HoneyPotCommand, "qpot_permissions", False):
        return
    command.HoneyPotCommand.qpot_permissions = True

    # The pinned process model gives each channel a private /proc, but its
    # shallow filesystem copy also copied connection-bound COW/mutation hooks.
    # Keep that process view while resolving every ordinary node against the
    # current connection tree and directing all writes to its canonical owner.
    from cowrie.commands import base
    original_view = base.tpot_proc_view
    view_types = {}
    writers = ("_ensure_private_fs", "mkfile", "mkdir", "link_entry", "unlink_entry",
               "chmod", "chown", "utime", "remove", "rename", "open", "close",
               "write", "lseek", "mkdir2", "rmdir", "update_realfile", "update_size")
    def shared_view(kind):
        if kind in view_types:
            return view_types[kind]
        parent = original_view(kind)
        def get_tree(self):
            canonical = connection_filesystem(self.tpot_connection).fs
            top = self.__dict__.get("_qpot_top_node")
            if top is None:
                top = self._qpot_top_node = list(canonical)
            top[:7], top[8:] = canonical[:7], canonical[8:]
            private = self.__dict__.get("_qpot_proc_node")
            top[7] = [private if child[0] == "proc" and private is not None else child
                      for child in canonical[7]]
            return top
        def set_tree(self, value):
            self._qpot_top_node = value
            self._qpot_proc_node = next((child for child in value[7] if child[0] == "proc"), None)
        methods = {"fs": property(get_tree, set_tree), "__module__": kind.__module__}
        for name in writers:
            def write(self, *args, _name=name, **kwargs):
                return getattr(connection_filesystem(self.tpot_connection), _name)(*args, **kwargs)
            methods[name] = write
        view_types[kind] = type(kind.__name__, (parent,), methods)
        return view_types[kind]
    base.tpot_proc_view = shared_view
    original_session = base.tpot_proc_session
    def proc_session(protocol):
        original_session(protocol)
        view = getattr(protocol, "fs", None)
        if getattr(view, "tpot_connection", None) is not None:
            # Instance-bound hooks copied by upstream must not shadow the
            # methods above: those closures are bound to the connection tree.
            for name in writers:
                view.__dict__.pop(name, None)
    base.tpot_proc_session = proc_session
    original_command = command.HoneyPotCommand.__init__
    def command_init(self, protocol, *args):
        original_command(self, protocol, *args)
        self.user = effective_user(self)
        self.protocol = Protocol(protocol, lambda: effective_user(self), lambda: setattr(self, "exit_code", 1))
        self.fs = self.protocol.fs
        for name in ("start", "call", "lineReceived", "eofReceived"):
            method = getattr(self, name, None)
            if method is not None:
                setattr(self, name, _guard(self, method))
    command.HoneyPotCommand.__init__ = command_init

    from cowrie.commands.cat import Command_cat
    def cat_output(self, data):
        if data is None:
            return
        if not self.number:
            self.writeBytes(data)
            return
        lines = data.split(b"\n")
        for index, line in enumerate(lines):
            if index == len(lines) - 1 and not line:
                break
            if getattr(self, "qpot_cat_line_start", True):
                self.write(f"{self.linenumber:>6}\t")
                self.linenumber += 1
                self.qpot_cat_line_start = False
            self.writeBytes(line)
            if index < len(lines) - 1:
                self.writeBytes(b"\n")
                self.qpot_cat_line_start = True
    Command_cat.output = cat_output

    from cowrie.commands.wc import Command_tpot_touch
    original_touch = Command_tpot_touch.tpot_touch
    def touch_operand(self, name, when, no_create, no_deref, only):
        if name:
            try:
                path = self.tpot_path(name)
                node, resolved = self.fs._resolve(path, follow=not no_deref or name.endswith("/"), missing=True)
                if name.endswith("/") and node is not None and node[1] != 1:
                    return original_touch(self, name, when, no_create, no_deref, only)
                if node is not None or not no_create:
                    self.fs._writable_path(resolved)
                if node is not None and when is None and not no_deref and only in (None, "both"):
                    self.fs.touch(path)
                    return True
            except OSError as error:
                self.tpot_fail("touch.cannot_touch", name, errno=errno.errorcode.get(error.errno, "EACCES"))
                return False
        return original_touch(self, name, when, no_create, no_deref, only)
    Command_tpot_touch.tpot_touch = touch_operand

    # The active finite cp implementation copies nodes directly, including
    # recursive children. Validate those reads and resolved writes before it
    # changes nodes, rather than relying on file_contents/mkfile being called.
    from cowrie.commands.wc import Command_tpot_cp, Command_tpot_rm, TpotFsTool
    original_rm_operand = Command_tpot_rm.tpot_rm_operand
    def rm_operand(self, name, preserve):
        try:
            _, resolved = self.fs._resolve(self.tpot_path(name), follow=name.endswith("/"))
            self.fs._writable_path(resolved)
        except PermissionError:
            self.tpot_fail("rm.cannot_remove", name, errno="EACCES")
            return False
        return (yield from original_rm_operand(self, name, preserve))
    Command_tpot_rm.tpot_rm_operand = rm_operand
    original_fs_main = TpotFsTool.tpot_main
    def fs_main(self, terminal):
        # Command construction has already snapshotted sudo's actual target.
        # The pinned tools' legacy boolean must not force that actor to root.
        previous = getattr(self, "pp", None)
        class EffectivePipe:
            tpot_sudo = False
            def __getattr__(self, name):
                return getattr(previous, name)
        self.pp = EffectivePipe()
        try:
            return original_fs_main(self, terminal)
        finally:
            self.pp = previous
    TpotFsTool.tpot_main = fs_main
    original_cp_operand = Command_tpot_cp.tpot_cp_operand
    def cp_operand(self, src, shown):
        try:
            return (yield from original_cp_operand(self, src, shown))
        except PermissionError:
            self.tpot_fail("cp.stat", src, errno="EACCES")
            return False
    Command_tpot_cp.tpot_cp_operand = cp_operand
    original_cp_file = Command_tpot_cp.tpot_cp_file
    def cp_file(self, src, shown, spath, tpath, source, *args, **kwargs):
        destination = self.fs.getfile(tpath)
        skipped = (destination is not None and (self.no_clobber or
                   (self.newer and float(destination[6] or 0) >= float(source[6] or 0))))
        if not skipped:
            try:
                if source[1] != 0:
                    self.fs._allow(source, 4, spath)
            except PermissionError:
                self.tpot_fail("cp.stat", src, errno="EACCES")
                return False
            try:
                self.fs.check_write(tpath)
            except OSError as error:
                self.tpot_fail("cp.create", shown, errno=errno.errorcode.get(error.errno, "EACCES"))
                return False
        raw = connection_filesystem(self.fs)
        inode = getattr(raw, "_qpot_inodes", {}).get(id(destination))
        live_backing = destination[9] if destination is not None and destination[1] == source[1] == 2 else None
        copied = yield from original_cp_file(self, src, shown, spath, tpath, source, *args, **kwargs)
        if (copied and not skipped and live_backing and
                ((inode is not None and inode["writers"]) or
                 getattr(raw, "_qpot_redirect_owners", {}).get(live_backing))):
            # cp overwrites an existing regular inode. Keep descriptors and
            # redirected writers attached to that inode's common live backing.
            data = self.fs.file_contents(spath)
            with open(live_backing, "wb") as artifact:
                artifact.write(data)
            destination[9], destination[7], destination[4] = live_backing, [], len(data)
        return copied
    Command_tpot_cp.tpot_cp_file = cp_file
    original_cp_enter = Command_tpot_cp.tpot_cp_enter
    def cp_enter(self, src, shown, spath, tpath, source, *args, **kwargs):
        try:
            self.fs._allow(source, 5, spath)
        except PermissionError:
            self.tpot_fail("cp.stat", src, errno="EACCES")
            return None
        try:
            _, resolved = self.fs._resolve(tpath, missing=True)
            self.fs._writable_path(resolved)
        except PermissionError:
            self.tpot_fail("cp.mkdir", shown, errno="EACCES")
            return None
        return original_cp_enter(self, src, shown, spath, tpath, source, *args, **kwargs)
    Command_tpot_cp.tpot_cp_enter = cp_enter

    original_shell = honeypot.HoneyPotShell.__init__
    def shell_init(self, protocol, *args, **kwargs):
        original_shell(self, protocol, *args, **kwargs)
        self.protocol = Protocol(protocol, lambda: self.user)
        if "groups" not in self.user:
            self.user["groups"] = sorted(self.protocol.fs._identity()[1])
    honeypot.HoneyPotShell.__init__ = shell_init

    original_pipe = pipe.PipeProtocol.__init__
    def pipe_init(self, protocol, *args, **kwargs):
        user = kwargs["user"]
        original_pipe(self, Protocol(protocol, lambda: user), *args, **kwargs)
    pipe.PipeProtocol.__init__ = pipe_init
    for method_name in ("_prepare_output_file", "_open_stdin"):
        original = getattr(pipe.PipeProtocol, method_name)
        def checked(self, target, *args, _original=original):
            try:
                path = self.protocol.fs.resolve_path(target, self.cwd)
                if _original.__name__ == "_prepare_output_file":
                    node, _ = self.protocol.fs.check_write(path)
                    retained = (self.protocol.fs._raw.file_contents(path)
                                if node is not None and args[0] and self._needs_new_backing(node)
                                else b"")
                else:
                    self.protocol.fs._required(path, 4)
                    retained = b""
                result = _original(self, target, *args)
                if retained and result is not None:
                    result["written"] = 0
                    self._write_to_file(result, retained)
                if isinstance(result, dict) and result.get("real"):
                    raw = connection_filesystem(self.protocol.fs)
                    result["qpot_inode"] = _open_inode(raw, self.protocol.fs.getfile(result["virtual"]))
                    terminal = getattr(self.protocol, "terminal", None)
                    if terminal is not None and hasattr(terminal, "redirFiles"):
                        owners = getattr(raw, "_qpot_redirect_owners", None)
                        if owners is None:
                            raw._qpot_redirect_owners = owners = {}
                        owners.setdefault(result["real"], set()).add(terminal)
                        terminal.redirFiles.add((result["real"], result["virtual"]))
                return result
            except PermissionError:
                self._emit_redirection_error(f"{self.error_prefix}{target}: Permission denied\n")
                return None
        setattr(pipe.PipeProtocol, method_name, checked)
    original_backing = pipe.PipeProtocol._needs_new_backing
    def needs_backing(self, node):
        return (original_backing(self, node) or
                bool(node and node[9] and re.fullmatch(r"[0-9a-f]{64}", posixpath.basename(node[9]))))
    pipe.PipeProtocol._needs_new_backing = needs_backing
    original_redirect_write = pipe.PipeProtocol._write_to_file
    def redirect_write(self, file_info, data):
        inode = file_info.get("qpot_inode")
        if inode is None:
            return original_redirect_write(self, file_info, data)
        try:
            with open(file_info["real"], "ab") as artifact:
                artifact.write(data)
                size = artifact.tell()
        except OSError as error:
            self._log.info("Failed to write redirected output: {error}", error=error)
            return
        file_info["written"] = inode["node"][4] = size
        inode["node"][6] = time.time()
    pipe.PipeProtocol._write_to_file = redirect_write

    def install_logging():
        # Channel finalization moves each redirection artifact to its content hash.
        # Keep the shared VFS pointing at that finalized artifact for later channels.
        from cowrie.insults.insults import LoggingServerProtocol
        if getattr(LoggingServerProtocol, "qpot_finalizer", False):
            return
        LoggingServerProtocol.qpot_finalizer = True
        original_lost = LoggingServerProtocol.connectionLost
        def logging_lost(self, *args, **kwargs):
            redirects = list(getattr(self, "redirFiles", ()))
            filesystem = getattr(getattr(self, "terminalProtocol", None), "fs", None)
            events = getattr(self, "events", None)
            if not redirects or filesystem is None or events is None:
                return original_lost(self, *args, **kwargs)
            raw = getattr(filesystem, "_raw", filesystem)
            owners = getattr(connection_filesystem(raw), "_qpot_redirect_owners", {})
            for real, virtual in redirects:
                active = owners.get(real, set())
                active.discard(self)
                if active:
                    # Finalizing while another channel still has this file
                    # open would rename its live backing out from under it.
                    next(iter(active)).redirFiles.add((real, virtual))
                    self.redirFiles.discard((real, virtual))
                else:
                    owners.pop(real, None)
                    inode = next((entry for entry in getattr(connection_filesystem(raw), "_qpot_inodes", {}).values()
                                  if entry["node"][9] == real and entry["writers"]), None)
                    if inode is not None:
                        # An SFTP descriptor still owns the same live backing.
                        # Its final close emits this channel's capture event.
                        inode.setdefault("redirect_events", []).append((events, virtual))
                        self.redirFiles.discard((real, virtual))
            redirects = list(self.redirFiles)
            wanted = {real for real, _ in redirects}
            nodes = {}
            pending, seen = [raw.fs], set()
            while pending and len(seen) < 65536:
                node = pending.pop()
                if id(node) in seen:
                    continue
                seen.add(id(node))
                if node[9] in wanted:
                    nodes.setdefault(node[9], []).append(node)
                if node[1] == 1:
                    pending.extend(node[7])
            original_redirects = self.redirFiles
            current = [None]
            class Redirects:
                def __bool__(self):
                    return bool(original_redirects)
                def __iter__(self):
                    for redirect in redirects:
                        current[0] = redirect[0]
                        yield redirect
                    current[0] = None
                def __getattr__(self, name):
                    return getattr(original_redirects, name)
            class FinalizationEvents:
                def __getattr__(self, name):
                    return getattr(events, name)
                def dispatch(self, event, *arguments, **fields):
                    if event == "cowrie.session.file_download" and current[0] is not None:
                        for node in nodes.get(current[0], ()):
                            if node[9] == current[0]:
                                node[9] = fields["outfile"]
                        for inode in getattr(connection_filesystem(raw), "_qpot_inodes", {}).values():
                            if inode["node"][9] == current[0]:
                                inode["node"][9] = fields["outfile"]
                    return events.dispatch(event, *arguments, **fields)
            self.events = FinalizationEvents()
            self.redirFiles = Redirects()
            try:
                return original_lost(self, *args, **kwargs)
            finally:
                self.events = events
                self.redirFiles = original_redirects
                for real, matching in nodes.items():
                    for node in matching:
                        if node[9] == real and node[4] == 0:
                            node[9], node[7] = None, b""
        LoggingServerProtocol.connectionLost = logging_lost

    original_init = server.CowrieServer.initFileSystem
    def init_fs(self, home):
        install_logging()
        if self.fs is None:
            original_init(self, home)
            from cowrie.core.config import CowrieConfig
            if CowrieConfig.get("shell", "opkg_release", fallback=""):
                installed = CowrieConfig.get("shell", "opkg_installed", fallback="")
                if not any(row.split()[:1] == ["curl"] for row in installed.split(",")):
                    # The generic base pickle contains curl even on firmware
                    # whose package manifest does not. Keep the finite opkg
                    # tool's baseline filesystem consistent with that manifest.
                    if self.fs.getfile("/usr/bin/curl", follow_symlinks=False) is not None:
                        self.fs.remove("/usr/bin/curl")
            from types import SimpleNamespace
            from cowrie.core.qpot_state import install_uts_files
            from cowrie.commands.coreutils import qpot_track_files
            install_uts_files(self)
            qpot_track_files(SimpleNamespace(fs=self.fs, hostname=self.hostname))
    server.CowrieServer.initFileSystem = init_fs
    original_sftp = filetransfer.SFTPServerForCowrieUser.__init__
    def sftp_init(self, avatar):
        original_sftp(self, avatar)
        actor = {"uid": avatar.uid, "gid": avatar.gid, "username": avatar.username}
        self.fs = Filesystem(self.fs, lambda: actor)
        actor["groups"] = sorted(self.fs._identity()[1])
    filetransfer.SFTPServerForCowrieUser.__init__ = sftp_init
    original_remove_file = filetransfer.SFTPServerForCowrieUser.removeFile
    def remove_file(self, filename):
        path = self._absPath(filename)
        node = self.fs.getfile(path, follow_symlinks=False)
        if node is not None and node[1] == 1:
            raise OSError(errno.EISDIR, "Is a directory", path)
        return original_remove_file(self, filename)
    filetransfer.SFTPServerForCowrieUser.removeFile = remove_file
    original_file = filetransfer.CowrieSFTPFile.__init__
    def file_init(self, sftpserver, filename, flags, attrs):
        existing = sftpserver.fs.getfile(filename)
        retained_size = existing[4] if existing is not None and not flags & filetransfer.FXF_TRUNC else 0
        original_file(self, sftpserver, filename, flags, attrs)
        self.qpot_append = bool(flags & filetransfer.FXF_APPEND)
        self.qpot_read = bool(flags & filetransfer.FXF_READ)
        self.qpot_write = bool(flags & filetransfer.FXF_WRITE)
        self.qpot_inode = _open_inode(sftpserver.fs, sftpserver.fs.getfile(filename))
        self.qpot_closed = False
        if flags & filetransfer.FXF_WRITE:
            self.size = retained_size
    filetransfer.CowrieSFTPFile.__init__ = file_init
    filetransfer.CowrieSFTPFile.qpot_node = property(lambda self: self.qpot_inode["node"])
    original_write = filetransfer.CowrieSFTPFile.writeChunk
    def write_chunk(self, offset, data):
        if not self.qpot_write or self.qpot_closed:
            raise OSError(errno.EBADF, "Bad file descriptor", self.filename)
        if not isinstance(offset, int) or offset < 0 or offset > (1 << 63) - 1 - len(data):
            raise OSError(errno.EFBIG, "File too large", self.filename)
        before = self.qpot_node[4]
        end = before + len(data) if self.qpot_append else max(before, offset + len(data))
        # Bound resulting sparse-file size as well as bytes received: otherwise
        # a one-byte seek can later force an enormous read_bytes allocation.
        limit = self.bytesReceivedLimit or 25_000_000
        if end > limit or (self.bytesReceivedLimit and self.bytesReceived + len(data) > self.bytesReceivedLimit):
            raise filetransfer.filetransfer.SFTPError(filetransfer.filetransfer.FX_FAILURE, "Quota exceeded")
        result = original_write(self, offset, data)
        self.size = end
        self.qpot_node[4] = self.size
        self.qpot_node[6] = time.time()
        return result
    filetransfer.CowrieSFTPFile.writeChunk = write_chunk
    original_read = filetransfer.CowrieSFTPFile.readChunk
    def read_chunk(self, offset, length):
        if not self.qpot_read or self.qpot_closed:
            raise OSError(errno.EBADF, "Bad file descriptor", self.filename)
        node = self.qpot_node
        uts_path = next((path for path in getattr(self.sftpserver.fs, "qpot_uts_paths", ())
                         if self.sftpserver.fs.getfile(path) is node), None)
        if uts_path is not None:
            if offset < 0 or length < 0:
                raise OSError(errno.EINVAL, "Invalid argument", self.filename)
            # An open descriptor owns its resolved inode. A template alias may
            # later change target, while this handle still names the same UTS
            # file and must keep its generated, connection-owned contents.
            data = self.sftpserver.fs.file_contents(uts_path)
            return data[offset:offset + length]
        if self.filename in getattr(self.sftpserver.fs, "generated_files", {}):
            return original_read(self, offset, length)
        if node[9]:
            if offset < 0 or length < 0:
                raise OSError(errno.EINVAL, "Invalid argument", self.filename)
            if offset >= (1 << 63):
                return b""
            with open(node[9], "rb") as artifact:
                available = max(0, os.fstat(artifact.fileno()).st_size - offset)
                artifact.seek(offset)
                return artifact.read(min(length, available))
        if isinstance(node[7], bytes):
            return node[7][offset:offset + length]
        return original_read(self, offset, length)
    filetransfer.CowrieSFTPFile.readChunk = read_chunk
    def close_file(self):
        if not self.qpot_closed:
            result = self.sftpserver.fs.close(self.fd)
            self.qpot_closed = True
            return result
    filetransfer.CowrieSFTPFile.close = close_file
    def file_attrs(self):
        node = self.qpot_node
        return {"size": node[4], "uid": node[2], "gid": node[3], "permissions": node[5],
                "atime": int(node[6]), "mtime": int(node[6])}
    filetransfer.CowrieSFTPFile.getAttrs = file_attrs
    def set_file_attrs(self, attrs):
        path = _node_path(self.sftpserver.fs._raw, self.qpot_node)
        if path is None:
            raise OSError(errno.ENOENT, "No such file or directory", self.filename)
        return self.sftpserver._setAttrs(path, attrs)
    filetransfer.CowrieSFTPFile.setAttrs = set_file_attrs
    def directory_next(self):
        if not self.files:
            raise StopIteration
        name = self.files.pop(0)
        path = posixpath.normpath(posixpath.join(self.dir, name))
        attrs_stat = self.server.fs.lstat(path)
        display = self.server.fs.lstat(path)
        from cowrie.commands.coreutils import qpot_id_names
        users = qpot_id_names(self.server.fs, "/etc/passwd")
        groups = qpot_id_names(self.server.fs, "/etc/group")
        display.st_uid = users.get(attrs_stat.st_uid, str(attrs_stat.st_uid))
        display.st_gid = groups.get(attrs_stat.st_gid, str(attrs_stat.st_gid))
        longname = filetransfer.twisted.conch.ls.lsLine(name, display)
        return name, longname, self.server._getAttrs(attrs_stat)
    filetransfer.CowrieSFTPDirectory.__next__ = directory_next
