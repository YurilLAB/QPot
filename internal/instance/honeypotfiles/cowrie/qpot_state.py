# SPDX-License-Identifier: BSD-3-Clause

"""Mutable machine state shared by the channels of one Cowrie connection.

Cowrie creates a fresh virtual server for each authenticated connection. Keeping
the state there makes a shell, an exec channel and SFTP describe one machine,
without allowing a later unrelated connection to inherit an attacker's changes.
The upstream package commands retain their existing protocol attributes through
the descriptors below; their implementation and finite package catalogs stay in
the pinned image.
"""

from __future__ import annotations


PACKAGE_ATTRIBUTES = frozenset({
    "tpot_installed", "tpot_faked", "tpot_apt_db", "tpot_apt_hidden",
    "tpot_opkg_added", "tpot_opkg_lists", "tpot_yum_db", "tpot_yum_cache",
    "tpot_yum_history", "tpot_dnf_session",
})


def effective_user(command) -> dict:
    """Snapshot an emulated process's credentials without mutating its login."""
    user = dict(getattr(command, "user", {}) or {})
    pipe = getattr(command, "pp", None)
    target = getattr(pipe, "tpot_sudo_user", None)
    if isinstance(target, dict):
        return dict(target)
    if getattr(pipe, "tpot_sudo", False):
        user.update(uid=0, gid=0, groups=[0], username="root", home="/root")
    return user


def connection_filesystem(filesystem):
    """The backing filesystem beneath actor and per-channel /proc views."""
    seen = set()
    while filesystem is not None and id(filesystem) not in seen:
        seen.add(id(filesystem))
        backing = getattr(filesystem, "_raw", None)
        if backing is None:
            backing = getattr(filesystem, "tpot_connection", None)
        if backing is None:
            return filesystem
        filesystem = backing
    raise ValueError("cyclic virtual filesystem view")


class MachineState:
    """State of one virtual server; never a process-wide attacker-state cache."""

    def __init__(self, hostname: str) -> None:
        self.hostname = hostname
        self.attributes: dict = {}


def machine_state(protocol) -> MachineState:
    """Return the server-owned state, with a protocol fallback for small adapters.

    Reading the initial hostname from raw attributes avoids recursion through
    HoneyPotBaseProtocol's hostname property while its constructor is running.
    """
    avatar = getattr(protocol, "user", None)
    server = getattr(avatar, "server", None)
    owners = [owner for owner in (server, avatar, protocol) if owner is not None]
    initial = "svr04"
    for owner in owners:
        values = getattr(owner, "__dict__", {})
        if isinstance(values.get("hostname"), str):
            initial = values["hostname"]
            break
    for owner in owners:
        found = getattr(owner, "qpot_machine_state", None)
        if isinstance(found, MachineState):
            return found
        state = MachineState(initial)
        try:
            owner.qpot_machine_state = state
        except (AttributeError, TypeError):
            continue
        return state
    raise TypeError("virtual machine has no writable state owner")


def install_uts_files(server) -> None:
    """Expose the persona's virtual UTS fields without copying its whole tree.

    The ancestor nodes are connection-owned; unrelated connections retain the
    shared base pickle. Generated hostname reads follow the same state as uname
    and hostname, including SFTP connections opened before a shell channel.
    These are emulated files; no host kernel settings are read or written.
    """
    fs = server.fs
    if getattr(fs, "qpot_uts_paths", None):
        return
    from cowrie.commands.uname import kernel_build_string, kernel_name, kernel_version
    from cowrie.shell.fs import A_CONTENTS, A_CTIME, A_NAME, A_TYPE, T_DIR, T_FILE

    root = getattr(fs, "fs", None)
    if not isinstance(root, list) or root[A_TYPE] != T_DIR:
        return
    proc = next((node for node in root[A_CONTENTS] if node[A_NAME] == "proc"), None)
    if proc is None or proc[A_TYPE] != T_DIR:
        return
    parent = list(root)
    parent[A_CONTENTS] = list(root[A_CONTENTS])
    top = parent
    for name in ("proc", "sys", "kernel"):
        found = next((node for node in parent[A_CONTENTS] if node[A_NAME] == name), None)
        if found is not None and found[A_TYPE] != T_DIR:
            return
        child = (list(found) if found is not None else
                 [name, T_DIR, 0, 0, 0, 0o40555, proc[A_CTIME], [], None, None])
        child[A_CONTENTS] = list(child[A_CONTENTS])
        parent[A_CONTENTS] = [node for node in parent[A_CONTENTS] if node[A_NAME] != name] + [child]
        parent = child
    state = machine_state(server)
    fields = {"hostname": lambda: state.hostname, "ostype": kernel_name,
              "osrelease": kernel_version, "version": kernel_build_string}
    paths = set()
    for name, value in fields.items():
        path = "/proc/sys/kernel/" + name
        # proc sysctl files report zero stat size, even when a read returns text.
        mode = 0o100644 if name == "hostname" else 0o100444
        parent[A_CONTENTS] = [node for node in parent[A_CONTENTS] if node[A_NAME] != name] + [
            [name, T_FILE, 0, 0, 0, mode, proc[A_CTIME], b"", None, None]]
        fs.generated_files[path] = lambda read=value: (read() + "\n").encode("utf-8")
        paths.add(path)
    fs.fs = top
    fs.qpot_uts_paths = frozenset(paths)


class SharedAttribute:
    """An existing upstream protocol attribute backed by its virtual machine."""

    def __init__(self, name: str) -> None:
        if name not in PACKAGE_ATTRIBUTES:
            raise ValueError("unsupported shared package attribute")
        self.name = name

    def __get__(self, protocol, owner=None):
        if protocol is None:
            return self
        values = machine_state(protocol).attributes
        if self.name not in values:
            raise AttributeError(self.name)
        return values[self.name]

    def __set__(self, protocol, value) -> None:
        machine_state(protocol).attributes[self.name] = value

    def __delete__(self, protocol) -> None:
        values = machine_state(protocol).attributes
        if self.name not in values:
            raise AttributeError(self.name)
        del values[self.name]
