# SPDX-FileCopyrightText: 2026 QPot contributors
# SPDX-License-Identifier: BSD-3-Clause

"""OpenWrt package transitions for tools already implemented by Cowrie.

The pinned image supplies repository metadata and the update/list commands.
This adapter installs a finite verified package graph into the connection VFS;
it never downloads or executes a package or starts a host process.
"""

from __future__ import annotations

import copy
import functools
import hashlib
import io
import json
from pathlib import Path
import posixpath
import re
import stat
import time
from types import MappingProxyType
import zipfile

from twisted.internet.defer import inlineCallbacks

from cowrie.commands import apt
from cowrie.commands.adduser import AccountError, qpot_effective_user, qpot_ownership_path
from cowrie.core.qpot_state import connection_filesystem, machine_state
from cowrie.shell.fs import A_CONTENTS, A_TYPE, T_DIR, T_FILE

commands = {}

# Exact file lists/sizes from the release's official mipsel_24kc IPKs.
# The accompanying finite snapshots are data only; no ELF is executed/loaded.
_CURL_FILES = {
    "21.02": [("/usr/bin/curl", 115735, "")],
    "22.03": [("/usr/bin/curl", 128227, "")],
}
_LIBCURL_FILES = {
    "21.02": [("/usr/lib/libcurl.so.4.8.0", 261539, ""), ("/usr/lib/libcurl.so.4", 0, "libcurl.so.4.8.0")],
    "22.03": [("/usr/lib/libcurl.so.4.8.0", 312183, ""), ("/usr/lib/libcurl.so.4", 0, "libcurl.so.4.8.0")],
}
_HTTP2_FILES = {
    "21.02": [("/usr/lib/libnghttp2.so.14.20.1", 119947, ""), ("/usr/lib/libnghttp2.so.14", 0, "libnghttp2.so.14.20.1")],
    "22.03": [("/usr/lib/libnghttp2.so.14.20.2", 115807, ""), ("/usr/lib/libnghttp2.so.14", 0, "libnghttp2.so.14.20.2")],
}
_MBEDTLS_FILES = [("/usr/lib/libmbedcrypto.so.2.28.8", 333903, ""),
                  ("/usr/lib/libmbedcrypto.so.7", 0, "libmbedcrypto.so.2.28.8"),
                  ("/usr/lib/libmbedtls.so.2.28.8", 103295, ""),
                  ("/usr/lib/libmbedtls.so.14", 0, "libmbedtls.so.2.28.8"),
                  ("/usr/lib/libmbedx509.so.2.28.8", 53767, ""),
                  ("/usr/lib/libmbedx509.so.1", 0, "libmbedx509.so.2.28.8")]


def package_files(branch):
    if branch not in _CURL_FILES:
        return {}
    result = {"curl": _CURL_FILES[branch], "libcurl4": _LIBCURL_FILES[branch], "libnghttp2-14": _HTTP2_FILES[branch]}
    if branch == "22.03":
        result["libmbedtls12"] = _MBEDTLS_FILES
    return result


_ASSETS_SHA256 = "f1965a7fb33198ca08ef2b45e00c11bff336c1a0c0772ecd74e747949ee8fdff"
_ASSETS_MAX_COMPRESSED = 2 << 20
_ASSETS_MAX_EXPANDED = 3 << 20


@functools.cache
def package_assets():
    """Read only fixed, authenticated data members, with no filesystem extraction.

    Sources/licenses accompany the product separately. The emulator never
    opens the corresponding-source archive or calls a binary/host loader.
    Shared bytes and tuple records are immutable; writes replace VFS content.
    """
    with Path(__file__).with_name("opkg_assets.zip").open("rb") as stream:
        archive = stream.read(_ASSETS_MAX_COMPRESSED + 1)
    if len(archive) > _ASSETS_MAX_COMPRESSED or hashlib.sha256(archive).hexdigest() != _ASSETS_SHA256:
        raise AccountError("invalid package data snapshot")
    result = {}
    with zipfile.ZipFile(io.BytesIO(archive)) as packed:
        members = packed.infolist()
        if (len(members) > 64 or len({item.filename for item in members}) != len(members)
                or sum(item.file_size for item in members) > _ASSETS_MAX_EXPANDED):
            raise AccountError("invalid package data bounds")
        header = packed.getinfo("manifest.json")
        if header.file_size > 65536:
            raise AccountError("invalid package manifest")
        manifest = json.loads(packed.read(header))
        if manifest.get("format") != 1 or manifest.get("architecture") != "mipsel_24kc":
            raise AccountError("invalid package architecture")
        for branch in _CURL_FILES:
            packages = {}
            for name, expected in package_files(branch).items():
                package = manifest["packages"][branch][name]
                files = package["files"]
                if (package["architecture"] != "mipsel_24kc" or len(files) != len(expected)
                        or sorted((item["path"], item["size"], item["target"]) for item in files) != sorted(expected)):
                    raise AccountError("invalid package file list")
                rows = []
                for item in files:
                    if item["target"]:
                        rows.append((item["path"], item["size"], item["target"], 0o777, None))
                        continue
                    digest = item["sha256"]
                    if (not re.fullmatch(r"[0-9a-f]{64}", digest)
                            or item["object"] != "objects/" + digest or item["mode"] not in (0o644, 0o755)):
                        raise AccountError("invalid package data member")
                    entry = packed.getinfo(item["object"])
                    if entry.file_size != item["size"] or not 0 < entry.file_size <= 1 << 20:
                        raise AccountError("invalid package data size")
                    content = packed.read(entry)
                    if (hashlib.sha256(content).hexdigest() != digest or content[:7] != b"\x7fELF\x01\x01\x01"
                            or content[18:20] != b"\x08\x00"):
                        raise AccountError("invalid package data digest")
                    rows.append((item["path"], item["size"], "", item["mode"], content))
                packages[name] = (package["version"], tuple(rows))
            result[branch] = MappingProxyType(packages)
    return MappingProxyType(result)


def package_dependencies(branch):
    return {"curl": ["libcurl4"], "libcurl4": ["libnghttp2-14"] + (["libmbedtls12"] if branch == "22.03" else [])}


def installed(protocol):
    return {**apt.tpot_opkg_installed(), **(getattr(protocol, "tpot_opkg_added", None) or {})}


def managed(protocol):
    return machine_state(protocol).attributes.get("qpot_opkg_files", {})


def _branch():
    return ".".join(apt.tpot_opkg("opkg_release").split(".")[:2])


def curl_version_text(protocol, version):
    """The selected release's installed curl and declared TLS/HTTP2 packages."""
    packages = installed(protocol)
    expected = apt.tpot_upstream(packages.get("curl", ""))
    if expected != ".".join(str(n) for n in version) or _branch() not in _CURL_FILES:
        return None
    arch = apt.tpot_opkg("opkg_arch")
    if arch != "mipsel_24kc":
        return None
    if _branch() == "21.02":
        package = next((name for name in packages if name.startswith("libwolfssl")), "")
        found = re.match(r"([0-9]+\.[0-9]+\.[0-9]+)", packages.get(package, ""))
        tls = "wolfSSL/" + (found.group(1) if found else "5.5.3")
    else:
        tls = "mbedTLS/" + apt.tpot_upstream(packages.get("libmbedtls12", "2.28.8-1"))
    http2 = apt.tpot_upstream(packages.get("libnghttp2-14", ""))
    date = {"7.83.1": "2022-05-11", "8.6.0": "2024-01-31"}.get(expected)
    if date is None or not http2:
        return None
    return (f"curl {expected} (mipsel-openwrt-linux-musl) libcurl/{expected} {tls} nghttp2/{http2}\n"
            f"Release-Date: {date}\nProtocols: file ftp ftps http https\nFeatures: HTTP2 IPv6 Largefile SSL\n")


def curl_load_error(protocol, tree):
    if "curl" not in (getattr(protocol, "tpot_opkg_added", None) or {}):
        return None
    aliases = ["/usr/lib/libcurl.so.4", "/usr/lib/libnghttp2.so.14"]
    if _branch() == "22.03":
        aliases += ["/usr/lib/libmbedtls.so.14", "/usr/lib/libmbedx509.so.1", "/usr/lib/libmbedcrypto.so.7"]
    for path in aliases:
        try:
            _, node = qpot_ownership_path(tree, path, "/")
            if node[A_TYPE] != T_FILE:
                raise AccountError("invalid shared library")
        except AccountError:
            return f"Error loading shared library {posixpath.basename(path)}: No such file or directory (needed by /usr/bin/curl)\n"
    return None


def _directory(tree, path):
    current = "/"
    for part in path.strip("/").split("/"):
        if not part:
            continue
        wanted = posixpath.join(current, part)
        resolved, node = qpot_ownership_path(tree, wanted, "/", True, True)
        if node is None:
            tree.mkdir(wanted, 0, 0, 4096, stat.S_IFDIR | 0o755)
            resolved = wanted
        elif node[A_TYPE] != T_DIR:
            raise AccountError(f"cannot create {path}")
        current = resolved
    return current


def _put(tree, path, size=0, target="", content=None, executable=False, replace=False, mode=None):
    directory = _directory(tree, posixpath.dirname(path))
    actual = posixpath.join(directory, posixpath.basename(path))
    _, old = qpot_ownership_path(tree, actual, "/", False, True)
    if old is not None and not replace:
        raise AccountError(f"check_data_file_clashes: {path} already exists")
    if tree.newcount >= 10000 and old is None:
        raise AccountError("no space left on device")
    if target:
        node = [posixpath.basename(path), 0, 0, 0, len(target), stat.S_IFLNK | 0o777, time.time(), [], target, None]
    else:
        data = content if content is not None else []
        node = [posixpath.basename(path), T_FILE, 0, 0, len(content) if content is not None else size,
                stat.S_IFREG | (mode if mode is not None else (0o755 if executable else 0o644)), time.time(), data, None, None]
    parent = tree.getfile(directory)
    if old is not None:
        parent[A_CONTENTS].remove(old)
    else:
        tree.newcount += 1
    parent[A_CONTENTS].append(node)


def _status(protocol, additions):
    packages = {**apt.tpot_opkg_installed(), **additions}
    return "\n".join(f"Package: {name}\nVersion: {version}\nStatus: install user installed\n"
                     + (f"Architecture: {apt.tpot_opkg('opkg_arch')}\n" if name in additions else "")
                     for name, version in sorted(packages.items())).encode()


def _stage(tree):
    stage = copy.copy(tree)
    stage._qpot_stage_nodes = {}
    stage.fs = copy.deepcopy(tree.fs, stage._qpot_stage_nodes)
    stage._private_fs = True
    # The real tree may have a tracker wrapper closing over the original FS.
    # A staging copy must never invoke it or mutate the original tree.
    stage._ensure_private_fs = lambda: None
    return stage


def _commit(tree, stage):
    before = tree.fs
    tree.fs, tree.newcount, tree._private_fs = stage.fs, stage.newcount, True
    replaced = getattr(tree, "qpot_tree_replaced", None)
    if callable(replaced):
        replaced(before, tree.fs, stage._qpot_stage_nodes)


class Command_opkg(apt.Command_opkg):
    @inlineCallbacks
    def start(self):
        if len(self.args) > 64 or sum(len(word) for word in self.args) > 16384:
            self.errorWrite("opkg: too many arguments\n")
            self.exit(255)
            return
        words = [word for word in self.args if word != "--force-reinstall"]
        if any(word.startswith("-") for word in words):
            self.errorWrite("opkg: unsupported option\n")
            self.exit(255)
            return
        if "--force-reinstall" in self.args and (not words or words[0] != "install"):
            self.errorWrite("opkg: --force-reinstall requires install\n")
            self.exit(255)
            return
        if words and words[0] in ("update", "install", "remove") and qpot_effective_user(self).get("uid") != 0:
            self.errorWrite("Could not lock /var/lock/opkg.lock: Permission denied.\n")
            self.exit(255)
            return
        if not words or words[0] not in ("install", "remove", "status", "info", "files"):
            yield super().start()
            return
        operation, names = words[0], words[1:]
        if len(names) > 16:
            self.errorWrite("opkg: too many packages\n")
            self.exit(255)
            return
        if operation in ("status", "info", "files"):
            self.describe(operation, names)
            return
        if not names:
            self.tpot_usage(f"opkg: the ``{operation}'' command requires at least one argument\n")
            return
        try:
            if operation == "install":
                self.install(names, "--force-reinstall" in self.args)
            else:
                self.remove(names)
        except (AccountError, OSError, ValueError) as error:
            message = error.message if isinstance(error, AccountError) else "package transaction failed"
            self.errorWrite(f"Collected errors:\n * opkg_install_cmd: {message}.\n")
            self.exit(255)

    def install(self, names, force):
        current = installed(self.protocol)
        branch = _branch()
        files = package_files(branch)
        available = apt.tpot_opkg_names() if getattr(self.protocol, "tpot_opkg_lists", False) else {}
        graph = package_dependencies(branch)
        verified = {"21.02": {"curl": "7.83.1-4.1", "libcurl4": "7.83.1-4.1", "libnghttp2-14": "1.43.0-1"},
                    "22.03": {"curl": "8.6.0-1", "libcurl4": "8.6.0-1", "libnghttp2-14": "1.44.0-1", "libmbedtls12": "2.28.8-1"}}
        planned = []

        def include(name):
            if name in planned or (name in current and not force):
                return
            if apt.tpot_opkg("opkg_arch") != "mipsel_24kc" or name not in files or name not in available or name not in apt.tpot_opkg_meta() or apt.tpot_opkg_version(name) != verified.get(branch, {}).get(name):
                raise AccountError(f"Cannot install package {name}")
            for dependency in graph.get(name, []):
                include(dependency)
            planned.append(name)

        for name in dict.fromkeys(names):
            include(name)
        if not planned:
            for name in dict.fromkeys(names):
                self.write(f"Package {name} ({current[name]}) installed in root is up to date.\n")
            self.exit(0)
            return
        snapshots = package_assets()[branch]
        if any(snapshots[name][0] != apt.tpot_opkg_version(name) for name in planned):
            raise AccountError("package data version does not match repository")
        # The command gate above authorizes this fixed package transaction.
        # Clone the underlying tree, never the actor facade whose setters proxy
        # to that tree and would otherwise break atomic staging.
        tree = connection_filesystem(self.fs)
        stage = _stage(tree)
        additions = dict(getattr(self.protocol, "tpot_opkg_added", None) or {})
        owned = dict(managed(self.protocol))
        for name in planned:
            version = apt.tpot_opkg_version(name)
            previous = set(owned.get(name, []))
            for path, size, target, mode, content in snapshots[name][1]:
                _put(stage, path, size, target, content=content, replace=path in previous, mode=mode)
            paths = [path for path, _, _ in files[name]]
            _put(stage, f"/usr/lib/opkg/info/{name}.list", content=("\n".join(paths) + "\n").encode(), replace=name in owned)
            additions[name], owned[name] = version, paths
        _put(stage, "/usr/lib/opkg/status", content=_status(self.protocol, additions), replace=True)
        _commit(tree, stage)
        self.protocol.tpot_opkg_added = additions
        machine_state(self.protocol).attributes["qpot_opkg_files"] = owned
        if "curl" in planned:
            apt.tpot_mark_installed(self.protocol, "curl", additions["curl"])
        for name in planned:
            version = additions[name]
            self.write(f"Installing {name} ({version}) to root...\n"
                       f"Downloading {apt.tpot_opkg_url(available[name])}/{name}_{version}_{apt.tpot_opkg('opkg_arch')}.ipk\n"
                       f"Configuring {name}.\n")
        self.exit(0)

    def remove(self, names):
        additions = dict(getattr(self.protocol, "tpot_opkg_added", None) or {})
        owned = dict(managed(self.protocol))
        gone = set(names) & set(additions)
        for package in installed(self.protocol):
            if package not in gone and gone.intersection(package_dependencies(_branch()).get(package, [])):
                raise AccountError(f"Package {package} depends on a package requested for removal")
        if not gone:
            self.write("No packages removed.\n")
            self.exit(0)
            return
        tree = connection_filesystem(self.fs)
        stage = _stage(tree)
        for name in sorted(gone):
            for path in owned.get(name, []) + [f"/usr/lib/opkg/info/{name}.list"]:
                resolved, node = qpot_ownership_path(stage, path, "/", False, True)
                if node is not None:
                    parent = stage.getfile(posixpath.dirname(resolved))
                    parent[A_CONTENTS].remove(node)
            additions.pop(name, None)
            owned.pop(name, None)
        _put(stage, "/usr/lib/opkg/status", content=_status(self.protocol, additions), replace=True)
        _commit(tree, stage)
        self.protocol.tpot_opkg_added = additions
        machine_state(self.protocol).attributes["qpot_opkg_files"] = owned
        if "curl" in gone:
            (getattr(self.protocol, "tpot_installed", None) or {}).pop("curl", None)
        for name in sorted(gone):
            self.write(f"Removing package {name} from root...\n")
        self.exit(0)

    def describe(self, operation, names):
        packages = installed(self.protocol)
        selected = names or sorted(packages)
        failed = False
        for name in selected[:4096]:
            if name not in packages:
                failed = True
                continue
            if operation == "files":
                paths = managed(self.protocol).get(name)
                if paths is None:
                    continue
                self.write(f"Package {name} ({packages[name]}) is installed on root and has the following files:\n"
                           + "\n".join(paths) + "\n")
            else:
                self.write(f"Package: {name}\nVersion: {packages[name]}\nStatus: install user installed\n"
                           f"Architecture: {apt.tpot_opkg('opkg_arch')}\n\n")
        self.exit(255 if failed else 0)


commands["/bin/opkg"] = Command_opkg
commands["opkg"] = Command_opkg
