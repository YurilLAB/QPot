# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import getopt
import json
import re
from pathlib import Path

from cowrie.commands.adduser import AccountError, qpot_group_ids, qpot_groups, qpot_number, qpot_passwd
from cowrie.core.config import CowrieConfig
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.pipe import PipeProtocol

commands = {}
# T-Pot: the options of sudo with a value (-u root, -uroot, --user root; --user=root is one word)
TPOT_SUDO_VALUES = "aCcDghpRrTtUu"
TPOT_SUDO_LONG_VALUES = frozenset({"--auth-type", "--close-from", "--login-class", "--chdir", "--group", "--host",
                                   "--prompt", "--chroot", "--role", "--command-timeout", "--type", "--other-user",
                                   "--user"})

sudo_shorthelp = (
    (
        """
sudo: Only one of the -e, -h, -i, -K, -l, -s, -v or -V options may be specified
usage: sudo [-D level] -h | -K | -k | -V
usage: sudo -v [-AknS] [-D level] [-g groupname|#gid] [-p prompt] [-u user name|#uid]
usage: sudo -l[l] [-AknS] [-D level] [-g groupname|#gid] [-p prompt] [-U user name] [-u user name|#uid] [-g groupname|#gid] [command]
usage: sudo [-AbEHknPS] [-r role] [-t type] [-C fd] [-D level] [-g groupname|#gid] [-p prompt] [-u user name|#uid] [-g groupname|#gid] [VAR=value] [-i|-s] [<command>]
usage: sudo -e [-AknS] [-r role] [-t type] [-C fd] [-D level] [-g groupname|#gid] [-p prompt] [-u user name|#uid] file ...
"""
    )
    .strip()
    .split("\n")
)

sudo_longhelp = (
    (
        """
sudo - execute a command as another user

usage: sudo [-D level] -h | -K | -k | -V
usage: sudo -v [-AknS] [-D level] [-g groupname|#gid] [-p prompt] [-u user name|#uid]
usage: sudo -l[l] [-AknS] [-D level] [-g groupname|#gid] [-p prompt] [-U user name] [-u user name|#uid] [-g groupname|#gid] [command]
usage: sudo [-AbEHknPS] [-r role] [-t type] [-C fd] [-D level] [-g groupname|#gid] [-p prompt] [-u user name|#uid] [-g groupname|#gid] [VAR=value] [-i|-s] [<command>]
usage: sudo -e [-AknS] [-r role] [-t type] [-C fd] [-D level] [-g groupname|#gid] [-p prompt] [-u user name|#uid] file ...

Options:
  -a type       use specified BSD authentication type
  -b            run command in the background
  -C fd         close all file descriptors >= fd
  -E            preserve user environment when executing command
  -e            edit files instead of running a command
  -g group      execute command as the specified group
  -H            set HOME variable to target user's home dir.
  -h            display help message and exit
  -i [command]  run a login shell as target user
  -K            remove timestamp file completely
  -k            invalidate timestamp file
  -l[l] command list user's available commands
  -n            non-interactive mode, will not prompt user
  -P            preserve group vector instead of setting to target's
  -p prompt     use specified password prompt
  -r role       create SELinux security context with specified role
  -S            read password from standard input
  -s [command]  run a shell as target user
  -t type       create SELinux security context with specified role
  -U user       when listing, list specified user's privileges
  -u user       run command (or edit file) as specified user
  -V            display version information and exit
  -v            update user's timestamp without running a command
  --            stop processing command line arguments
"""
    )
    .strip()
    .split("\n")
)


class Command_sudo(HoneyPotCommand):
    consumes_stdin = True

    def short_help(self) -> None:
        for ln in sudo_shorthelp:
            self.errorWrite(f"{ln}\n")
        self.exit()

    def long_help(self) -> None:
        for ln in sudo_longhelp:
            self.errorWrite(f"{ln}\n")
        self.exit()

    def version(self) -> None:
        version = CowrieConfig.get("shell", "sudo_version", fallback="1.8.5p2")
        grammar = CowrieConfig.get("shell", "sudo_grammar", fallback="41")
        lines = [f"Sudo version {version}", f"Sudoers policy plugin version {version}",
                 f"Sudoers file grammar version {grammar}", f"Sudoers I/O plugin version {version}"]
        if not version.startswith("1.8."):
            lines.append(f"Sudoers audit plugin version {version}")
        self.write("".join(line + "\n" for line in lines))
        self.exit()

    def tpot_list(self, command: list[str]) -> None:
        """T-Pot: sudo -l as sudo prints it: the Defaults (wrapped as sudo's lbuf wraps them at
        80 columns) and the rules of the user; with a command its full path."""
        path = CowrieConfig.get("shell", "sudo_list", fallback="")
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8")) if path else {}
        except (OSError, ValueError):
            data = {}
        name = self.user.get("username", "")
        name = name.decode("utf-8", "replace") if isinstance(name, bytes) else str(name)
        if self.user.get("uid") == 0:
            name = "root"
        host = self.protocol.hostname.split(".")[0]
        rules = data.get("rules", {}).get("root" if name == "root" else name)
        if rules is None:
            self.errorWrite(f"Sorry, user {name} may not run sudo on {host}.\n")
            self.exit(1)
            return
        if command:
            found = self.protocol.getCommand(command[0], self.environ.get("PATH", "").split(":"), self.cwd)
            if not found:
                self.exit(1)
                return
            program = command[0] if "/" in command[0] else next(
                (f"{d}/{command[0]}" for d in self.environ.get("PATH", "").split(":")
                 if d and self.fs.exists(f"{d}/{command[0]}")), f"/usr/bin/{command[0]}")
            self.write(" ".join([program] + command[1:]) + "\n")
            self.exit()
            return
        lines, line = [], "   "
        defaults = data.get("defaults", [])
        for index, entry in enumerate(defaults):
            text = entry + ("," if index < len(defaults) - 1 else "")
            if len(line) + 1 + len(text) > 80 and line.strip():
                lines.append(line)
                line = "   "
            line += " " + text
        lines.append(line)
        self.write(f"Matching Defaults entries for {name} on {host}:\n" + "\n".join(lines) + "\n\n"
                   f"User {name} may run the following commands on {host}:\n"
                   + "".join(f"    {rule}\n" for rule in rules))
        self.exit()

    def qpot_target(self, options):
        """Resolve this process's target using the current virtual account files."""
        username = "root"
        group = None
        for option, value in options:
            if option in ("-u", "--user"):
                username = value
            elif option in ("-g", "--group"):
                group = value
        if not username or len(username) > 128:
            raise AccountError("unknown user")
        users = qpot_passwd(self.fs)
        try:
            account = users.getpwuid(qpot_number(username[1:], "user ID")) if username.startswith("#") else users.getpwnam(username)
        except KeyError:
            raise AccountError(f"unknown user {username}") from None
        gid = account["pw_gid"]
        if group is not None:
            if group.startswith("#"):
                gid = qpot_number(group[1:], "group ID")
            else:
                found = next((entry for entry in qpot_groups(self.fs) if entry["name"] == group), None)
                if found is None:
                    raise AccountError(f"unknown group {group}")
                gid = found["gid"]
        return dict(uid=account["pw_uid"], gid=gid, username=account["pw_name"],
                    home=account["pw_dir"], shell=account["pw_shell"],
                    groups=qpot_group_ids(self.fs, account["pw_name"], gid))

    def start(self) -> None:
        if len(self.args) > 128 or sum(len(word) for word in self.args) > 16384:
            self.errorWrite("sudo: too many arguments\n")
            self.exit(1)
            return
        # T-Pot: sudo's options end at the first word that is no option (or after --); -l / --list
        # among them lists the rules, that word is the command (after VAR=value assignments)
        listing, index = False, 0
        while index < len(self.args):
            arg = self.args[index]
            if arg == "--":
                index += 1
                break
            if not arg.startswith("-") or arg == "-":
                break
            if arg.startswith("--"):
                listing = listing or arg == "--list"
                if arg in TPOT_SUDO_LONG_VALUES:
                    index += 1
            else:
                for pos, flag in enumerate(arg[1:], 1):
                    listing = listing or flag == "l"
                    if flag in TPOT_SUDO_VALUES:
                        if pos == len(arg) - 1:
                            index += 1
                        break
            index += 1
        while index < len(self.args) and re.match(r"[A-Za-z_][A-Za-z0-9_]*=", self.args[index]):
            index += 1
        start_value = index
        parsed_arguments = self.args[index:]
        if listing:
            self.tpot_list(parsed_arguments)
            return
        if index < len(self.args) and not self.protocol.getCommand(
                self.args[index], self.environ.get("PATH", "").split(":"), self.cwd):
            self.errorWrite(f"sudo: {self.args[index]}: command not found\n")
            self.exit(1)
            return
        try:
            optlist, _args = getopt.getopt(
                self.args[0:start_value], "bEeHhKknPSVva:C:g:i:l:p:r:s:t:U:u:",
                ["user=", "group=", "help", "version", "list", "login", "non-interactive", "set-home"]
            )
        except getopt.GetoptError as err:
            self.errorWrite("sudo: illegal option -- " + err.opt + "\n")
            self.short_help()
            return

        for o, _a in optlist:
            if o in ("-V", "--version"):
                self.version()
                return
            elif o in ("-h", "--help"):
                self.long_help()
                return

        try:
            target = self.qpot_target(optlist)
        except (AccountError, KeyError) as error:
            text = error.message if isinstance(error, AccountError) else "unknown user"
            self.errorWrite(f"sudo: {text}\n")
            self.exit(1)
            return
        if len(parsed_arguments) > 0:
            cmd = parsed_arguments[0]
            cmdclass = self.protocol.getCommand(
                cmd, self.environ.get("PATH", "").split(":"), self.cwd
            )

            if cmdclass:
                # sudo execs the command in its own place, with sudo's stdin,
                # stdout and redirections.
                pp = PipeProtocol(
                    self.protocol,
                    cmdclass,
                    parsed_arguments[1:],
                    self.input_data,
                    self.pp.targets,
                    cwd=self.cwd,
                    user=target,
                )
                pp.stdin_from_pipe = self.pp.stdin_from_pipe
                pp.tpot_sudo = target["uid"] == 0
                pp.tpot_sudo_user = target
                self.exec_command(pp, cmdclass, *parsed_arguments[1:])
            else:
                self.short_help()
        else:
            self.short_help()


commands["sudo"] = Command_sudo
commands["/usr/bin/sudo"] = Command_sudo
