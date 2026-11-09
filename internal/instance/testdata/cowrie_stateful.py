"""Exercise the production connection-state adapter without a network service.

Only the protocol's framework dependencies are replaced. State descriptors,
hostname property, constructor and command overlay are compiled from the exact
production source, rather than restated by this harness. The separate image
mode imports the full real Cowrie package and its existing package commands.
"""

from __future__ import annotations

import ast
import collections.abc
import importlib.util
import hashlib
import json
from pathlib import Path
import sys
import types
import tempfile
import time


def production_protocol(patch: Path):
    spec = importlib.util.spec_from_file_location("cowrie.core.qpot_state", patch / "qpot_state.py")
    state = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(state)
    tree = ast.parse((patch / "protocol.py").read_text())
    helpers = [node for node in tree.body if isinstance(node, (ast.ClassDef, ast.FunctionDef))
               and node.name in {"TpotCommands", "tpot_commands"}]
    original = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                    and node.name == "HoneyPotBaseProtocol")
    selected = []
    for node in original.body:
        if isinstance(node, ast.FunctionDef) and node.name in {"__init__", "hostname"}:
            selected.append(node)
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) \
                and isinstance(node.value.func, ast.Name) and node.value.func.id == "SharedAttribute":
            selected.append(node)
    selected.append(ast.parse("commands = {}").body[0])
    # The constructor's VFS tracker is separately exercised with the real FS in
    # the image tests. Here a spy establishes that all channels invoke the hook.
    tracker_calls = []
    coreutils = types.ModuleType("cowrie.commands.coreutils")
    coreutils.qpot_track_files = lambda protocol: tracker_calls.append(protocol.fs)
    sys.modules[coreutils.__name__] = coreutils
    ns = {"collections": collections, "SharedAttribute": state.SharedAttribute,
          "machine_state": state.machine_state}
    narrowed = ast.ClassDef(name="HoneyPotBaseProtocol", bases=[], keywords=[], body=selected,
                            decorator_list=[])
    module = ast.fix_missing_locations(ast.Module(body=helpers + [narrowed], type_ignores=[]))
    exec(compile(module, str(patch / "protocol.py"), "exec"), ns)
    return ns["HoneyPotBaseProtocol"], state, tracker_calls


def unit(patch: Path):
    Protocol, state, tracked = production_protocol(patch)

    def avatar(host="app01"):
        return types.SimpleNamespace(environ={"HOME": "/root"},
                                     server=types.SimpleNamespace(hostname=host, fs=object()))

    owner = avatar()
    first, existing = Protocol(owner), Protocol(owner)
    assert not hasattr(first, "tpot_apt_db")
    assert getattr(existing, "tpot_opkg_lists", False) is False
    first.hostname = "maintenance01"
    later = Protocol(owner)
    assert existing.hostname == later.hostname == owner.server.hostname == "maintenance01"
    assert first.fs is existing.fs is later.fs
    assert tracked == [first.fs, first.fs, first.fs]

    # A package install changes both the existing and a subsequently opened
    # channel; overwrites and removals must have the same scope as the VFS.
    first.tpot_apt_db = {"packages": {"curl": {"version": "8.14.1", "status": "ii"}}, "files": 23}
    first.tpot_installed = {"curl": "8.14.1"}
    first.tpot_faked = {"/usr/bin/tool": object()}
    assert existing.tpot_apt_db is later.tpot_apt_db is first.tpot_apt_db
    existing.tpot_apt_db["packages"]["curl"]["status"] = "rc"
    assert first.tpot_apt_db["packages"]["curl"]["status"] == "rc"
    existing.tpot_installed = {}
    assert first.tpot_installed == later.tpot_installed == {}
    existing.tpot_faked.clear()
    assert not first.tpot_faked
    del first.tpot_apt_db
    assert not hasattr(existing, "tpot_apt_db") and not hasattr(later, "tpot_apt_db")

    # The other supported upstream package managers use the same machine scope,
    # including boolean cache markers and list histories, with no eager defaults.
    for name in state.PACKAGE_ATTRIBUTES:
        value = {"marker": name}
        setattr(first, name, value)
        assert getattr(existing, name) is value
        setattr(existing, name, None)
        assert getattr(later, name) is None
        delattr(later, name)
        assert not hasattr(first, name)
    first.tpot_opkg_lists = False
    assert existing.tpot_opkg_lists is False
    first.tpot_yum_history = []
    existing.tpot_yum_history.append("install")
    assert later.tpot_yum_history == ["install"]

    # Attacker changes stay with one connection even when both machines began
    # with the same persona/hostname. The original global command table stays
    # unchanged while one connection's install/remove overlay is visible.
    isolated = Protocol(avatar())
    assert isolated.hostname == "app01"
    assert not hasattr(isolated, "tpot_yum_history")
    assert state.machine_state(first) is not state.machine_state(isolated)
    command = object()
    first.commands["/usr/bin/local-tool"] = command
    assert existing.commands["/usr/bin/local-tool"] is command
    assert "/usr/bin/local-tool" not in isolated.commands
    assert "/usr/bin/local-tool" not in Protocol.commands
    del later.commands["/usr/bin/local-tool"]
    assert "/usr/bin/local-tool" not in first.commands
    first.cwd, existing.cwd = "/tmp", "/root"
    first.tpot_session_pid, existing.tpot_session_pid = 1200, 1300
    assert first.cwd != existing.cwd and first.tpot_session_pid != existing.tpot_session_pid

    # Small protocol adapters without a CowrieServer still retain their own
    # state; unsupported field aliases must not accidentally become globals.
    small = types.SimpleNamespace(hostname="adapter01")
    assert state.machine_state(small) is state.machine_state(small)
    assert state.machine_state(small).hostname == "adapter01"
    try:
        state.SharedAttribute("arbitrary_attribute")
    except ValueError:
        pass
    else:
        raise AssertionError("unsupported shared state alias accepted")
    print(json.dumps({"result": "PASS", "scope": "production state adapter and constructor",
                      "shared_package_attributes": len(state.PACKAGE_ATTRIBUTES),
                      "channels": 3, "cross_connection_isolation": True,
                      "per_channel_cwd_and_pid": True, "tracker_dependency": "spy only"}))


def image(profile: str, facts_only: bool = False):
    """Use the real image's renderer, VFS and command classes, with transport-only adapters."""
    root = Path("/home/cowrie/cowrie")
    # These unchanged modules are the state contracts the adapter bridges.
    expected = {
        "commands/apt.py": "6dd5747a3cfde06fc9bb2aea7af5ac6105aff3723a1d756603b283c7b8c2ed95",
        "commands/yum.py": "2108391ee9b8abf710c980a3622b11a1fb32e63a115c5d64f1a04b7d0e25150a",
        "commands/cat.py": "168eaba6df5f33d1405a44d696d6bdc3a2d83e7cb7c17d225b420b37f883c57f",
        "commands/base.py": "ffbc10202186f76f527c1eb8f41c547207803ea09d2830159caccaa27e1ea924",
        "commands/fs.py": "dd24925180da23f7ece761bcba250adbbc791f8d2db6542adf883df684063061",
        "commands/wc.py": "f4f14c8b1ba974b05c34602c4a4b85d5017616a6a6e376d975d10125e7eb1836",
        "shell/fs.py": "f933006fb76b7ac006c85f582bff8614bbd9c5fb070798edbdc9e182625b5f26",
        "shell/realm.py": "7cc716e9e251b986a83186645295cc71ec2c818e807283e0abacab8140366107",
        "shell/command.py": "67dca09efa1263b97caa721999cfecb4ca321ccb9aa3a808be7ae9d6950551ee",
        "shell/honeypot.py": "aa7c328d2b13f5e9728db12bc43bebaba85a43ef40530a7eba4f7d51690b48e1",
        "shell/pipe.py": "c7281c3c2d2c0bc0a6d53cf33ba59d9c11dccf315ed6c3891d70525c16a6963a",
        "shell/filetransfer.py": "16bbc60026aef4307825b9e2c9e3d8969591bfcc90454fdc5c564515de650994",
        "shell/server.py": "9b0f53bb494dc4a7bf7eabc5d47a5776c4d979e58e681fcd265aeed5cdf4e297",
        "insults/insults.py": "7ffc0854cc238d0241b520708dee4c2b2b879f65df3a5cb52d7b85fb6f3f94db",
    }
    for name, digest in expected.items():
        assert hashlib.sha256((root / "src/cowrie" / name).read_bytes()).hexdigest() == digest, name
    sys.path.insert(0, str(root / "src"))
    sys.path.insert(0, "/usr/local/lib/tpot-cowrie")
    from tpot_personas import catalog, tree
    from tpot_personas.identity import draw
    from tpot_personas.render import render
    persona = catalog.by_id(profile)
    now = int(time.time())
    identity = draw(persona, 0x51504F54, now=now)
    temporary = Path(tempfile.mkdtemp(prefix="qpot-stateful-"))
    runtime, keys = temporary / "runtime", temporary / "keys"
    keys.mkdir()
    render(persona, identity, tree.load_pickle(root / "personas/base.pickle"), runtime,
           runtime_dir=runtime, keys_dir=keys, cowrie_root=root)
    from cowrie.core.config import CowrieConfig
    CowrieConfig.read(runtime / "cowrie.cfg")
    downloads = temporary / "downloads"
    downloads.mkdir()
    CowrieConfig.set("honeypot", "download_path", str(downloads))
    from cowrie.shell.protocol import HoneyPotBaseProtocol
    from cowrie.shell.server import CowrieServer
    from cowrie.shell.honeypot import HoneyPotShell
    from cowrie.commands import apt, yum
    from cowrie.core.qpot_state import machine_state
    from twisted.internet.defer import Deferred, succeed
    from twisted.python.failure import Failure

    def avatar():
        server = CowrieServer(None)
        server.initFileSystem("/root")
        return types.SimpleNamespace(server=server, environ={"HOME": "/root", "PATH":
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
            username="root", uid=0, gid=0, home="/root", avatar=types.SimpleNamespace(home="/root"),
            conn=types.SimpleNamespace(transport=types.SimpleNamespace(
                events=types.SimpleNamespace(dispatch=lambda *args, **kwargs: None))))

    def channel(owner):
        protocol = HoneyPotBaseProtocol(owner)
        protocol.logintime = time.time()
        # Match real connectionMade's per-channel process view. Only the
        # transport's start time is supplied by this non-wire adapter.
        protocol.getProtoTransport = lambda: types.SimpleNamespace(factory=types.SimpleNamespace(starttime=now))
        from cowrie.commands.base import tpot_proc_session
        tpot_proc_session(protocol)
        protocol.cmdstack = [HoneyPotShell(protocol, interactive=False)]
        protocol.events = types.SimpleNamespace(dispatch=lambda *args, **kwargs: None)
        return protocol

    def invoke(protocol, name, *args):
        shell = protocol.cmdstack[-1]
        cls = protocol.getCommand(name, shell.environ["PATH"].split(":"), shell.cwd)
        assert cls is not None, (profile, name, "program unavailable")
        if name == "touch":
            assert cls.__name__ == "Command_tpot_touch", (profile, "touch dispatch changed", cls)
        stdout, stderr, status = [], [], []
        protocol.pp = types.SimpleNamespace(
            targets={1: ("capture", None), 2: ("capture", None)}, stdin_from_pipe=False,
            write_stdout=stdout.append, write_stderr=stderr.append)
        command = cls(protocol, *args)
        def finish(code=None):
            command.exited = True
            status.append(command.exit_code if code is None else code)
        command.exit = finish
        # Package progress delays are not the contract under test; actual CLI
        # parsing, package state, files and command registration all execute.
        command.sleep = lambda *args: succeed(None)
        result = command.start()
        if isinstance(result, Deferred):
            assert result.called, (name, "unexpected asynchronous dependency")
            if isinstance(result.result, Failure):
                result.result.raiseException()
        assert status, (name, "command did not terminate")
        return {"stdout": b"".join(stdout).decode(), "stderr": b"".join(stderr).decode(), "code": status[-1]}

    owner = avatar()
    import copy
    from cowrie.core.qpot_state import install_uts_files
    probe_fs = copy.copy(owner.server.fs)
    probe_fs.generated_files = dict(probe_fs.generated_files)
    probe_fs.qpot_uts_paths = frozenset()
    probe_fs._private_fs = False
    shared_nodes = {node[0]: node for node in probe_fs.fs[7] if node[0] != "proc"}
    install_uts_files(types.SimpleNamespace(fs=probe_fs, hostname=owner.server.hostname))
    assert not probe_fs._private_fs, "read-only UTS setup copied the whole persona"
    assert all(node is shared_nodes[node[0]] for node in probe_fs.fs[7] if node[0] != "proc")
    from cowrie.commands.uname import kernel_build_string, kernel_name, kernel_version
    from cowrie.shell.filetransfer import SFTPServerForCowrieUser, FXF_READ
    uts = {"hostname": owner.server.hostname, "ostype": kernel_name(),
           "osrelease": kernel_version(), "version": kernel_build_string()}
    # SFTP is the first channel. Normal kernel fields must not depend on a
    # shell or command having previously initialized its private /proc view.
    uts_sftp = SFTPServerForCowrieUser(owner)
    uts_reader = uts_sftp.openFile("/proc/sys/kernel/hostname", FXF_READ, {})
    assert uts_reader.readChunk(0, 1024) == (uts["hostname"] + "\n").encode()
    assert uts_reader.getAttrs()["size"] == 0
    # Supported template links, rather than an unimplemented SFTP SYMLINK
    # operation. The open handle retains its inode after the alias retargets.
    alias = ["uts-alias", 0, 0, 0, len("/proc/sys/kernel/hostname"), 0o120777, now,
             [], "/proc/sys/kernel/hostname", None]
    owner.server.fs.link_entry(alias, "/tmp")
    uts_alias_reader = uts_sftp.openFile("/tmp/uts-alias", FXF_READ, {})
    assert uts_alias_reader.readChunk(0, 1024) == uts_reader.readChunk(0, 1024)
    alias[8], alias[4] = "/proc/sys/kernel/osrelease", len("/proc/sys/kernel/osrelease")
    uts_new_alias_reader = uts_sftp.openFile("/tmp/uts-alias", FXF_READ, {})
    assert uts_new_alias_reader.readChunk(0, 1024) == (uts["osrelease"] + "\n").encode()
    uts_new_alias_reader.close()
    assert uts_alias_reader.readChunk(0, 1024) == (uts["hostname"] + "\n").encode()
    if profile == "debian-bookworm":
        # A test-only kernel entry proves mutations are rejected before either
        # the canonical tree or a channel's generated /proc view can change.
        owner.server.fs._ensure_private_fs()
        owner.server.fs.getfile("/proc")[7].append(
            ["validation-control", 2, 0, 0, 13, 0o100644, now, b"kernel-state\n", None, None])
    first, second = channel(owner), channel(owner)
    original = first.hostname
    assert first.fs is not owner.server.fs and second.fs is not first.fs
    first.fs.mkfile("/stateful-root-proof", 0, 0, 4, 0o100644)
    first.fs.getfile("/stateful-root-proof")[7] = b"root"
    assert second.fs.file_contents("/stateful-root-proof") == b"root"
    persistent_name = first.fs.file_contents("/etc/hostname") if first.fs.exists("/etc/hostname") else None
    checks = []
    for name, expected in uts.items():
        path = "/proc/sys/kernel/" + name
        assert invoke(first, "cat", path)["stdout"] == expected + "\n"
        assert invoke(second, "cat", path)["stdout"] == expected + "\n"
        assert first.fs.stat(path).st_size == 0
    checks.append("virtual UTS files match persona uname and are readable before any shell channel")
    from cowrie.commands.coreutils import qpot_busybox_applet
    meminfo = first.fs.file_contents("/proc/meminfo")
    counters = {line.split(":", 1)[0]: int(line.split()[1]) for line in meminfo.decode().splitlines()}
    buffered = counters["Buffers"] + counters["Cached"]
    busybox_free = qpot_busybox_applet(first.fs, "free")
    banner = CowrieConfig.get("shell", "text_banner", fallback="")
    families = {"1.14.1": "early", "1.19.4": "buffers", "1.24.1": "cached",
                "1.26.2": "cached", "1.35.0": "modern"}
    family = next((model for version, model in families.items() if f"BusyBox v{version} " in banner), "") if busybox_free else ""
    assert not busybox_free or family, (profile, "unverified BusyBox free release", banner)
    expected = [counters["MemTotal"], counters["MemTotal"] - counters["MemFree"] - buffered,
                counters["MemFree"], counters["Shmem"], buffered, counters["MemAvailable"]]
    if family in ("early", "buffers", "cached"):
        expected = [counters["MemTotal"], counters["MemTotal"] - counters["MemFree"],
                    counters["MemFree"], counters["Shmem"], counters["Buffers"]]
        if family == "cached":
            expected.append(counters["Cached"])
    default_free = invoke(first, "free")
    def memory_row(result):
        assert result["code"] == 0, result
        return [int(value) for value in next(line for line in result["stdout"].splitlines()
                                           if line.lstrip().startswith("Mem:")).split()[1:]]
    assert memory_row(default_free) == expected
    rounding = 512 if family == "modern" else 0
    if family == "early":
        for option in ("-k", "-m", "-h", "-"):
            rejected = invoke(first, "free", option)
            assert rejected["code"] == 1 and rejected["stderr"] and not rejected["stdout"], rejected
        assert "Total:" in default_free["stdout"]
    else:
        kib_free = invoke(second, "free", "-k")
        mib_free = invoke(second, "free", "-m")
        assert kib_free["stdout"] == default_free["stdout"]
        assert memory_row(mib_free) == [(value + rounding) // 1024 for value in expected]
    invalid_free = invoke(first, "free", "-q")
    assert invalid_free["code"] == 1 and invalid_free["stderr"] and not invalid_free["stdout"], invalid_free
    if family == "early":
        assert invoke(first, "free", "operand")["stdout"] == default_free["stdout"]
    elif busybox_free:
        assert memory_row(invoke(first, "free", "-b")) == [value * 1024 for value in expected]
        assert memory_row(invoke(first, "free", "-g")) == [(value + ((1 << 19) if family == "modern" else 0)) // (1 << 20) for value in expected]
        assert invoke(first, "free", "-km")["stdout"] == kib_free["stdout"]
        assert invoke(first, "free", "-mk")["stdout"] == mib_free["stdout"]
        assert invoke(first, "free", "-mq")["stdout"] == mib_free["stdout"]
        assert invoke(first, "free", "operand")["stdout"] == kib_free["stdout"]
        if family != "modern":
            assert invoke(first, "free", "-h")["code"] == 1
            assert "available" not in default_free["stdout"].splitlines()[0]
    else:
        for arguments in (("-km",), ("-mk",), ("-mm",), ("operand",), ("-m", "operand")):
            failed = invoke(first, "free", *arguments)
            assert failed["code"] == 1 and failed["stderr"] and not failed["stdout"], failed
        human_free = invoke(first, "free", "-h")
        assert invoke(first, "free", "-mh")["stdout"] == human_free["stdout"]
        assert invoke(first, "free", "-hm")["stdout"] == human_free["stdout"]
    assert first.fs.file_contents("/proc/meminfo") == meminfo
    if profile in ("rhel-9", "openwrt", "tplink-archer-c7", "qnap-qts", "ipcam"):
        # Trusted renderer inputs around a MiB rounding boundary; these are
        # fixture counters, not writable virtual kernel controls for a visitor.
        node = first.fs.getfile("/proc/meminfo")
        original_contents, original_file = node[7], node[9]
        try:
            for total in (256 * 1024 + 511, 256 * 1024 + 512, 256 * 1024 + 513):
                custom = dict(counters, MemTotal=total, MemFree=total // 2, Buffers=2048,
                              Cached=4096, Shmem=0, MemAvailable=total // 2 + 4096)
                node[7] = "".join(f"{key}: {value} kB\n" for key, value in custom.items()).encode()
                node[9] = None
                assert memory_row(invoke(first, "free", "-m"))[0] == (total + rounding) // 1024
        finally:
            node[7], node[9] = original_contents, original_file
        assert first.fs.file_contents("/proc/meminfo") == meminfo
    checks.append("free default/-k/-m derive coherent KiB/MiB counters; GNU and BusyBox option/error semantics stay distinct")
    if facts_only:
        uts_reader.close()
        uts_alias_reader.close()
        print(json.dumps({"result": "PASS", "profile": profile, "checks": checks,
                          "scope": "actual image persona metadata and free facts; no full state sequence or SSH wire"}))
        return
    if profile == "debian-bookworm":
        import pickle
        from cowrie.core.qpot_permissions import Filesystem
        rootfs = Filesystem(first.fs, lambda: first.cmdstack[-1].user)
        snapshot = pickle.dumps(owner.server.fs.fs)
        for operation in (
            lambda: rootfs.mkfile("/proc/validation-control", 0, 0, 0, 0o100644),
            lambda: rootfs.mkfile("/proc/validation-new", 0, 0, 0, 0o100644),
            lambda: rootfs.mkdir2("/proc/validation-directory"),
            lambda: rootfs.remove("/proc/validation-control"),
            lambda: rootfs.rename("/proc/validation-control", "/tmp/from-proc"),
        ):
            try:
                operation()
                raise AssertionError("generated proc mutation succeeded")
            except PermissionError:
                pass
            assert pickle.dumps(owner.server.fs.fs) == snapshot
            assert second.fs.file_contents("/proc/validation-control") == b"kernel-state\n"
        denied = invoke(first, "chmod", "0600", "/proc/validation-control")
        assert denied["code"] == 1 and "Permission denied" in denied["stderr"], denied
        assert pickle.dumps(owner.server.fs.fs) == snapshot
        owner.server.fs.link_entry(["proc-copy-alias", 0, 0, 0, 24, 0o120777, now, [],
                                    "/proc/validation-control", None], "/tmp")
        copied_to_proc = invoke(first, "cp", "/stateful-root-proof", "/tmp/proc-copy-alias")
        assert copied_to_proc["code"] == 1, copied_to_proc
        assert owner.server.fs.file_contents("/proc/validation-control") == b"kernel-state\n"
        owner.server.fs.link_entry(["proc-dir-alias", 0, 0, 0, 5, 0o120777, now, [], "/proc", None], "/tmp")
        removed_from_proc = invoke(first, "rm", "/tmp/proc-dir-alias/validation-control")
        assert removed_from_proc["code"] == 1, removed_from_proc
        assert first.fs.file_contents("/proc/validation-control") == b"kernel-state\n"
        assert owner.server.fs.file_contents("/proc/validation-control") == b"kernel-state\n"
        denied_touch = invoke(first, "touch", "/proc/validation-control", "/tmp/touch-after-proc")
        assert denied_touch["code"] == 1 and "Permission denied" in denied_touch["stderr"], denied_touch
        assert second.fs.file_contents("/proc/validation-control") == b"kernel-state\n"
        assert second.fs.exists("/tmp/touch-after-proc")
        first.fs.mkfile("/tmp/touch-state", 0, 0, 4, 0o100644)
        first.fs.getfile("/tmp/touch-state")[7] = b"data"
        first.fs.utime("/tmp/touch-state", 100, 100)
        not_directory = invoke(first, "touch", "/tmp/touch-state/")
        assert not_directory["code"] == 1 and "Not a directory" in not_directory["stderr"], not_directory
        assert second.fs.getfile("/tmp/touch-state")[6] == 100
        assert invoke(first, "touch", "/tmp/touch-state")["code"] == 0
        assert second.fs.getfile("/tmp/touch-state")[6] >= now
        assert second.fs.file_contents("/tmp/touch-state") == b"data"
        checks.append("generated proc mutations deny before changing canonical or channel-view bytes")
        checks.append("plain touch updates current mtime across channels and continues after a denied proc operand")
    if persona.kind == "server":
        result = invoke(first, "hostname", "maintenance01")
        assert result["code"] == 0, result
    else:
        # Do not invent a missing firmware applet just to make a server test
        # pass. This pinned OpenWrt persona does not ship hostname(1).
        assert first.getCommand("hostname", first.cmdstack[-1].environ["PATH"].split(":"), "/root") is None
        checks.append("embedded persona retains its actual supported command set")
    third = channel(owner)
    if persona.kind == "server":
        assert invoke(second, "hostname")["stdout"].strip() == "maintenance01"
        assert invoke(third, "hostname")["stdout"].strip() == "maintenance01"
        assert invoke(second, "uname", "-n")["stdout"].strip() == "maintenance01"
        assert invoke(second, "cat", "/proc/sys/kernel/hostname")["stdout"] == "maintenance01\n"
        assert invoke(third, "cat", "/proc/sys/kernel/hostname")["stdout"] == "maintenance01\n"
        assert uts_reader.readChunk(0, 1024) == b"maintenance01\n"
        assert uts_alias_reader.readChunk(0, 1024) == b"maintenance01\n"
        checks += ["hostname across three channels", "uname runtime hostname", "persistent hostname unchanged"]
        checks.append("already-open SFTP UTS reader follows hostname changes across shell channels")
    uts_reader.close()
    uts_alias_reader.close()
    if persistent_name is not None:
        assert first.fs.file_contents("/etc/hostname") == persistent_name

    if persona.kind == "server":
        # Exercise the actual account commands and real VFS, including the
        # derived id/getent/ls/stat surfaces and a subsequent denied operation.
        created = invoke(first, "useradd", "-m", "-u", "23456", "-G", "root", "-s", "/bin/bash", "analystqa")
        assert created["code"] == 0, created
        identity_result = invoke(second, "id", "analystqa")
        assert identity_result["code"] == 0 and "uid=23456(analystqa)" in identity_result["stdout"], identity_result
        assert "0(root)" in identity_result["stdout"], identity_result
        passwd_result = invoke(third, "getent", "passwd", "analystqa")
        assert passwd_result["code"] == 0 and "/home/analystqa:/bin/bash" in passwd_result["stdout"], passwd_result
        group_result = invoke(third, "groups", "analystqa")
        assert group_result["code"] == 0 and "analystqa" in group_result["stdout"] and "root" in group_result["stdout"], group_result
        owner_result = invoke(second, "stat", "-c", "%u:%U", "/home/analystqa")
        assert owner_result["code"] == 0 and owner_result["stdout"].strip() == "23456:analystqa", owner_result
        listing = invoke(second, "ls", "-ld", "/home/analystqa")
        assert listing["code"] == 0 and "analystqa" in listing["stdout"], listing
        databases = ("/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow")
        before = {name: first.fs.file_contents(name) for name in databases}
        duplicate = invoke(second, "useradd", "analystqa")
        assert duplicate["code"] == 9, duplicate
        assert before == {name: first.fs.file_contents(name) for name in databases}
        assert invoke(first, "chmod", "0700", "/home/analystqa")["code"] == 0
        assert invoke(third, "stat", "-c", "%a", "/home/analystqa")["stdout"].strip() == "700"
        # Use the real command's authoritative shell-user snapshot, as su does;
        # no transport authentication or real OS account is changed by this adapter.
        saved_user = second.cmdstack[-1].user
        second.cmdstack[-1].user = dict(uid=23456, gid=23456, username="analystqa", home="/home/analystqa")
        denied = invoke(second, "useradd", "-m", "deniedqa")
        touch_continued = invoke(second, "touch", "/root/touch-denied", "/home/analystqa/touch-continued")
        assert touch_continued["code"] == 1 and "Permission denied" in touch_continued["stderr"], touch_continued
        assert first.fs.exists("/home/analystqa/touch-continued") and not first.fs.exists("/root/touch-denied")
        # Permissions have observable consequences, including access through
        # a symlink whose target is below an unsearchable ancestor.
        import stat
        first.fs.mkfile("/tmp/root-private", 0, 0, 10, stat.S_IFREG | 0o600)
        first.fs.getfile("/tmp/root-private")[7] = b"private-v1"
        exact = invoke(first, "cat", "/tmp/root-private")
        assert exact["code"] == 0 and exact["stdout"] == "private-v1", exact
        numbered = invoke(first, "cat", "-n", "/tmp/root-private")
        assert numbered["code"] == 0 and numbered["stdout"] == "     1\tprivate-v1", numbered
        first.fs.mkfile("/tmp/cat-second", 0, 0, 5, stat.S_IFREG | 0o600)
        first.fs.getfile("/tmp/cat-second")[7] = b"tail\n"
        joined = invoke(first, "cat", "-n", "/tmp/root-private", "/tmp/cat-second")
        assert joined["stdout"] == "     1\tprivate-v1tail\n", joined
        read_denied = invoke(second, "cat", "/tmp/root-private")
        assert read_denied["code"] != 0 and "Permission denied" in read_denied["stderr"], read_denied
        copy_denied = invoke(second, "cp", "/tmp/root-private", "/tmp/private-copy")
        assert copy_denied["code"] == 1 and not first.fs.exists("/tmp/private-copy"), copy_denied
        first.fs.mkfile("/tmp/skipped-copy", 23456, 23456, 4, stat.S_IFREG | 0o600)
        first.fs.getfile("/tmp/skipped-copy")[7] = b"keep"
        for option in ("-n", "-u"):
            skipped = invoke(second, "cp", option, "/tmp/root-private", "/tmp/skipped-copy")
            assert skipped["code"] == 0 and first.fs.file_contents("/tmp/skipped-copy") == b"keep", skipped
        mode_denied = invoke(second, "chmod", "0777", "/tmp/root-private")
        assert mode_denied["code"] != 0, mode_denied
        assert first.fs.getfile("/tmp/root-private")[5] & 0o777 == 0o600
        # A denied command leaves this channel usable.
        assert invoke(second, "id", "-un")["stdout"].strip() == "analystqa"
        from cowrie.core.qpot_permissions import Filesystem
        actorfs = Filesystem(first.fs, lambda: second.cmdstack[-1].user)
        for operation in (lambda: actorfs.open("/tmp/root-private", 1 | 512, 0o666),
                          lambda: actorfs.mkdir2("/root/denied-directory")):
            try:
                operation()
                raise AssertionError("denied mutation succeeded")
            except PermissionError:
                pass
        assert first.fs.file_contents("/tmp/root-private") == b"private-v1"
        # Root's failed rename must also preserve source bytes atomically.
        rootfs = Filesystem(first.fs, lambda: saved_user)
        try:
            rootfs.rename("/tmp/root-private", "/missing-parent/destination")
            raise AssertionError("rename into absent parent succeeded")
        except OSError:
            pass
        assert first.fs.file_contents("/tmp/root-private") == b"private-v1"
        second.cmdstack[-1].user = saved_user
        assert denied["code"] != 0 and not first.fs.exists("/home/deniedqa"), denied
        assert before == {name: first.fs.file_contents(name) for name in databases}
        checks += ["real useradd visible to id/getent/groups on other channels",
                   "new home and owner consistent in ls/stat", "chmod visible to later stat",
                   "duplicate/denied account changes preserve database bytes",
                   "nonowner read/write/chmod denied without losing channel or bytes",
                   "failed rename preserves source before destructive VFS mutation"]
    assert invoke(first, "mkdir", "/tmp/empty-rmdir")["code"] == 0
    assert invoke(first, "rmdir", "/tmp/empty-rmdir")["code"] == 0
    assert not first.fs.exists("/tmp/empty-rmdir")
    from cowrie.shell.filetransfer import SFTPServerForCowrieUser, FXF_READ, FXF_WRITE, FXF_CREAT, FXF_TRUNC
    sftp_owner = types.SimpleNamespace(server=owner.server, home="/root", uid=0, gid=0, username="root",
        conn=types.SimpleNamespace(transport=types.SimpleNamespace(events=first.events)))
    sftp = SFTPServerForCowrieUser(sftp_owner)
    writer = sftp.openFile("/tmp/shared-sftp", FXF_WRITE | FXF_CREAT | FXF_TRUNC, {"permissions": 0o600})
    writer.writeChunk(0, b"ABC")
    reader = sftp.openFile("/tmp/shared-sftp", FXF_READ, {})
    other_writer = sftp.openFile("/tmp/shared-sftp", FXF_WRITE, {})
    writer.writeChunk(3, b"D")
    other_writer.writeChunk(4, b"E")
    assert reader.readChunk(0, 100) == b"ABCDE"
    assert writer.getAttrs()["size"] == other_writer.getAttrs()["size"] == 5
    sftp.renameFile("/tmp/shared-sftp", "/tmp/renamed-sftp")
    writer.close()
    assert first.fs.file_contents("/tmp/renamed-sftp") == b"ABCDE"
    sftp.removeFile("/tmp/renamed-sftp")
    replacement = sftp.openFile("/tmp/renamed-sftp", FXF_WRITE | FXF_CREAT | FXF_TRUNC, {})
    replacement.writeChunk(0, b"replacement")
    replacement.close()
    other_writer.writeChunk(5, b"F")
    other_writer.close()
    assert reader.readChunk(0, 100) == b"ABCDEF"
    reader.close()
    assert first.fs.file_contents("/tmp/renamed-sftp") == b"replacement"
    quota = sftp.openFile("/tmp/quota-sftp", FXF_WRITE | FXF_CREAT | FXF_TRUNC, {})
    quota.bytesReceivedLimit = 4
    try:
        quota.writeChunk(100, b"x")
        raise AssertionError("sparse write bypassed quota")
    except Exception as error:
        from twisted.conch.ssh.filetransfer import SFTPError
        assert isinstance(error, SFTPError), error
    assert quota.getAttrs()["size"] == 0 and first.fs.file_contents("/tmp/quota-sftp") == b""
    quota.close()
    open_copy = sftp.openFile("/tmp/open-copy", FXF_WRITE | FXF_CREAT | FXF_TRUNC, {})
    open_copy.writeChunk(0, b"old")
    source = sftp.openFile("/tmp/copy-source", FXF_WRITE | FXF_CREAT | FXF_TRUNC, {})
    source.writeChunk(0, b"NEW")
    source.close()
    assert invoke(first, "cp", "/tmp/copy-source", "/tmp/open-copy")["code"] == 0
    open_copy.writeChunk(3, b"!")
    assert first.fs.file_contents("/tmp/open-copy") == b"NEW!"
    open_copy.close()
    assert first.fs.file_contents("/tmp/open-copy") == b"NEW!"
    assert first.fs.file_contents("/tmp/copy-source") == b"NEW"
    raw = owner.server.fs
    before_count, before_artifacts, before_fds = raw.newcount, set(downloads.iterdir()), set(raw.tempfiles)
    raw.newcount = 10000
    try:
        try:
            sftp.openFile("/tmp/over-inode-quota", FXF_WRITE | FXF_CREAT, {})
            raise AssertionError("inode quota bypassed")
        except OSError as error:
            import errno
            assert error.errno == errno.EDQUOT, error
        assert set(downloads.iterdir()) == before_artifacts and set(raw.tempfiles) == before_fds
        assert not first.fs.exists("/tmp/over-inode-quota")
    finally:
        raw.newcount = before_count
    checks += ["active rmdir removes an empty directory", "shared SFTP inode preserves interleaved writes/live reads/fstat",
               "SFTP rename/unlink/recreate keeps open inode separate from replacement", "sparse/inode quota rejects before mutation",
               "cp overwrites the live inode without changing immutable source capture"]
    if persona.family in ("debian", "ubuntu", "raspios"):
        initial = apt.tpot_apt_installed(first)
        assert "curl" in initial, "fixture requires the persona's installed curl"
        removed = invoke(first, "apt-get", "remove", "-y", "curl")
        assert removed["code"] == 0, removed
        assert "curl" not in apt.tpot_apt_installed(second)
        assert second.getCommand("curl", second.cmdstack[-1].environ["PATH"].split(":"), "/root") is None
        installed = invoke(second, "apt-get", "install", "-y", "curl")
        assert installed["code"] == 0, installed
        assert "curl" in apt.tpot_apt_installed(first) and apt.tpot_apt_db(first) is apt.tpot_apt_db(third)
        curl = invoke(third, "curl", "--version")
        assert curl["code"] == 0 and curl["stdout"].startswith("curl "), curl
        checks += ["real apt removal visible to existing channel", "real apt reinstall visible to original channel",
                   "restored real curl command available in third channel"]
    elif persona.family == "rhel":
        session = yum.tpot_dnf_session(first)
        session["installed"]["curl"] = "0:8.10.1-1.el9"
        assert yum.tpot_dnf_session(second) is session
        assert yum.tpot_dnf_installed(third)["curl"] == "0:8.10.1-1.el9"
        yum.tpot_dnf_mark(first, "curl", "0:8.10.1-1.el9")
        assert second.tpot_installed["curl"] == "8.10.1"
        checks += ["real DNF state/version readers share channel mutations"]
    elif persona.family == "centos":
        db = yum.tpot_yum_db(first)
        assert yum.tpot_yum_db(second) is db
        del db["curl"]
        assert "curl" not in yum.tpot_yum_db(third)
        checks += ["real Yum database removal visible across channels"]
    elif persona.family == "openwrt":
        assert first.getCommand("curl", first.cmdstack[-1].environ["PATH"].split(":"), "/root") is None
        during_install = sftp.openFile("/tmp/during-opkg", FXF_WRITE | FXF_CREAT | FXF_TRUNC, {})
        during_install.writeChunk(0, b"before")
        assert invoke(first, "opkg", "update")["code"] == 0
        assert second.tpot_opkg_lists is True
        installed = invoke(second, "opkg", "install", "curl")
        assert installed["code"] == 0, installed
        during_install.writeChunk(6, b"-after")
        assert during_install.getAttrs()["size"] == first.fs.stat("/tmp/during-opkg").st_size == 12
        during_install.close()
        assert first.fs.file_contents("/tmp/during-opkg") == b"before-after"
        assert "curl - " in invoke(third, "opkg", "list-installed")["stdout"]
        tool = invoke(third, "curl", "--version")
        assert tool["code"] == 0 and tool["stdout"].startswith("curl "), tool
        assert "mipsel-openwrt-linux-musl" in tool["stdout"], tool
        assert "/usr/bin/curl" in invoke(first, "which", "curl")["stdout"]
        assert "/usr/bin/curl" in invoke(second, "opkg", "files", "curl")["stdout"]
        from cowrie.commands import opkg
        import zipfile
        with zipfile.ZipFile(Path(opkg.__file__).with_name("opkg_assets.zip")) as archive:
            manifest = json.loads(archive.read("manifest.json"))
        branch = ".".join(CowrieConfig.get("shell", "opkg_release").split(".")[:2])
        verified = 0
        for package in manifest["packages"][branch].values():
            for entry in package["files"]:
                path = entry["path"]
                node = third.fs.getfile(path, follow_symlinks=False)
                assert node is not None, path
                if entry["target"]:
                    assert node[8] == entry["target"], (path, node[8])
                    continue
                data = third.fs.file_contents(path)
                assert len(data) == entry["size"] == third.fs.stat(path).st_size, path
                assert hashlib.sha256(data).hexdigest() == entry["sha256"], path
                assert node[5] & 0o777 == entry["mode"], path
                verified += 1
        assert verified >= 3
        stale_package = sftp.openFile("/usr/bin/curl", FXF_WRITE, {})
        stale_package.writeChunk(0, b"old")
        assert invoke(third, "opkg", "remove", "curl")["code"] == 0
        assert "curl" not in first.tpot_opkg_added
        assert first.getCommand("curl", first.cmdstack[-1].environ["PATH"].split(":"), "/root") is None
        assert invoke(third, "opkg", "install", "curl")["code"] == 0
        new_curl = first.fs.file_contents("/usr/bin/curl")
        assert stale_package.qpot_node is not first.fs.getfile("/usr/bin/curl")
        stale_package.close()
        assert first.fs.file_contents("/usr/bin/curl") == new_curl
        checks += ["real opkg update/install/list/remove share cache and database across channels",
                   "opkg install exposes real existing curl emulator and matching OpenWrt build; removal removes executable",
                   f"{verified} official package assets match independent archive manifest size/mode/SHA256",
                   "open SFTP inode survives opkg install; removed/reinstalled package keeps a distinct inode"]

    separate = channel(avatar())
    assert separate.hostname == original and machine_state(separate) is not machine_state(first)
    assert invoke(separate, "cat", "/proc/sys/kernel/hostname")["stdout"] == original + "\n"
    assert not separate.fs.exists("/stateful-root-proof")
    assert not hasattr(separate, "tpot_apt_db") and not hasattr(separate, "tpot_installed")
    if persona.kind == "server":
        assert not separate.fs.exists("/home/analystqa")
        assert invoke(separate, "getent", "passwd", "analystqa")["code"] == 2
    checks.append("unrelated connection retains pristine machine state")
    print(json.dumps({"result": "PASS", "profile": profile, "checks": checks,
                      "scope": "actual image Python modules/VFS; stdio and sleeps adapted, no SSH wire service"}))


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in {"--unit", "--image", "--facts"}:
        raise SystemExit("usage: cowrie_stateful.py --unit PATCH_DIRECTORY | --image PERSONA | --facts PERSONA")
    if sys.argv[1] == "--unit":
        unit(Path(sys.argv[2]))
    else:
        image(sys.argv[2], facts_only=sys.argv[1] == "--facts")
