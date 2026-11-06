# SPDX-License-Identifier: BSD-3-Clause

"""The AWS CLI v2 of the bait files (QPot).

Where QPot's bait put AWS credentials in root's ~/.aws (qpot_bait.py), it also
put the CLI that wrote them: /usr/local/bin/aws, installed by AWS's bundled
installer. This answers it, registered under the installer's paths only, so a
persona without the bait has no aws. The network behind the persona is out of
reach, so every call to AWS ends the way it ends on a box without a route out:
"Could not connect to the endpoint URL". Before that, the credentials the call
would sign with (the environment's, else the profile's in ~/.aws) are logged as
a cowrie.credentials.use event, the access key as its username and the secret
as its password: a stolen canary key used here trips like one typed in a login.

The texts follow aws-cli 2.9 (awscli/customizations/configure/list.py for the
list; the usage and error lines as the CLI prints them).
"""

from __future__ import annotations

import random
import re

from cowrie.core.config import CowrieConfig
from cowrie.shell.command import HoneyPotCommand

commands = {}

VERSION = "2.9.19"
PYTHON = "3.9.11"
MAX_FILE = 65536

USAGE = (
    "usage: aws [options] <command> <subcommand> [<subcommand> ...] [parameters]\n"
    "To see help text, you can run:\n\n"
    "  aws help\n"
    "  aws <command> help\n"
    "  aws <command> <subcommand> help\n\n"
)

# services whose endpoint has no region
GLOBAL = {"iam": "https://iam.amazonaws.com/", "organizations": "https://organizations.us-east-1.amazonaws.com/",
          "route53": "https://route53.amazonaws.com/", "cloudfront": "https://cloudfront.amazonaws.com/"}


def parse_ini(data: bytes) -> dict[str, dict[str, str]]:
    """The sections of an AWS config or credentials file (bounded: the first MAX_FILE bytes)."""
    sections: dict[str, dict[str, str]] = {}
    current = None
    for raw in data[:MAX_FILE].decode("utf-8", "replace").splitlines()[:2048]:
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1].strip(), {})
        elif current is not None and "=" in line:
            key, _, value = line.partition("=")
            current[key.strip().lower()] = value.strip()
    return sections


class Command_aws(HoneyPotCommand):
    def read(self, name: str) -> dict[str, dict[str, str]]:
        home = str(self.environ.get("HOME", "") or "")
        if not home.startswith("/"):
            return {}
        try:
            return parse_ini(self.fs.file_contents(home.rstrip("/") + "/.aws/" + name))
        except Exception:  # noqa: BLE001 - no file (or a folder): nothing configured
            return {}

    def options(self) -> tuple[dict[str, str], list[str]]:
        """The global options (--profile, --region, ...) and the words of the command."""
        opts: dict[str, str] = {}
        words: list[str] = []
        args = list(self.args)[:256]
        while args:
            arg = args.pop(0)
            if arg in ("--profile", "--region", "--output", "--endpoint-url") and args:
                opts[arg[2:]] = args.pop(0)
            elif arg.startswith(("--profile=", "--region=")):
                key, _, value = arg[2:].partition("=")
                opts[key] = value
            else:
                words.append(arg)
        return opts, words

    def profile(self, opts: dict[str, str]) -> str:
        return opts.get("profile") or str(self.environ.get("AWS_PROFILE", "") or "") or "default"

    def credentials(self, opts: dict[str, str]) -> tuple[str, str, str] | None:
        """(access key, secret, where) the CLI would sign with, None without any."""
        key = str(self.environ.get("AWS_ACCESS_KEY_ID", "") or "")
        secret = str(self.environ.get("AWS_SECRET_ACCESS_KEY", "") or "")
        if key and secret and "profile" not in opts:
            return key, secret, "env"
        found = self.read("credentials").get(self.profile(opts), {})
        key, secret = found.get("aws_access_key_id", ""), found.get("aws_secret_access_key", "")
        if key and secret:
            return key, secret, "shared-credentials-file"
        return None

    def region(self, opts: dict[str, str]) -> str:
        if opts.get("region"):
            return opts["region"]
        for name in ("AWS_REGION", "AWS_DEFAULT_REGION"):
            if self.environ.get(name):
                return str(self.environ[name])
        profile = self.profile(opts)
        section = "default" if profile == "default" else "profile " + profile
        return self.read("config").get(section, {}).get("region", "")

    def start(self) -> None:
        opts, words = self.options()
        if "--version" in words:
            self.write(f"aws-cli/{VERSION} Python/{PYTHON} Linux/{self.kernel()} exe/{self.exe()} prompt/off\n")
            self.exit(0)
            return
        if not words:
            self.errorWrite(USAGE + "aws: error: the following arguments are required: command\n")
            self.exit(2)
            return
        if words[0] == "configure":
            self.configure(opts, words[1:])
            return
        if words[0] == "help" or "help" in words[1:2]:
            self.errorWrite(USAGE + "aws: error: help is not available: the man and groff programs are missing\n")
            self.exit(255)
            return
        self.call_aws(opts, words)

    def kernel(self) -> str:
        return CowrieConfig.get("shell", "kernel_version", fallback="5.15.0")

    def exe(self) -> str:
        """exe/<arch>.<distribution>.<major version> of the persona."""
        arch = CowrieConfig.get("shell", "hardware_platform", fallback="x86_64")
        try:
            release = self.fs.file_contents("/etc/os-release")[:MAX_FILE].decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - no os-release
            release = ""
        ident = re.search(r'(?m)^ID="?([a-z0-9._-]{1,32})"?$', release)
        version = re.search(r'(?m)^VERSION_ID="?([0-9]{1,4})', release)
        return f"{arch}.{ident.group(1) if ident else 'linux'}.{version.group(1) if version else '0'}"

    def configure(self, opts: dict[str, str], words: list[str]) -> None:
        if words[:1] == ["list"]:
            found = self.credentials(opts)
            env_profile = "profile" not in opts and self.environ.get("AWS_PROFILE")
            rows = [("Name", "Value", "Type", "Location"), ("----", "-----", "----", "--------")]
            if opts.get("profile") or env_profile:
                rows.append(("profile", self.profile(opts), "manual" if opts.get("profile") else "env",
                             "--profile" if opts.get("profile") else "AWS_PROFILE"))
            else:
                rows.append(("profile", "<not set>", "None", "None"))
            if found:
                rows.append(("access_key", "*" * 16 + found[0][-4:], found[2], ""))
                rows.append(("secret_key", "*" * 16 + found[1][-4:], found[2], ""))
            else:
                rows.append(("access_key", "<not set>", "None", "None"))
                rows.append(("secret_key", "<not set>", "None", "None"))
            region = self.region(opts)
            rows.append(("region", region or "<not set>", "config-file" if region else "None",
                         "~/.aws/config" if region else "None"))
            for name, value, kind, where in rows:
                self.write("%10s %24s %16s    %s\n" % (name, value, kind, where))
            self.exit(0)
            return
        if words[:1] == ["get"] and len(words) == 2:
            name = words[1].lower()
            found = self.credentials(opts)
            value = {"aws_access_key_id": found[0] if found else "", "aws_secret_access_key": found[1] if found else "",
                     "region": self.region(opts)}.get(name, "")
            if value:
                self.write(value + "\n")
                self.exit(0)
            else:
                self.exit(1)
            return
        if not words:
            # the four prompts of `aws configure`, each with the value it keeps on an empty answer
            found = self.credentials(opts)
            region = self.region(opts)
            self.qpot_prompts = [
                f"AWS Access Key ID [{'*' * 16 + found[0][-4:] if found else 'None'}]: ",
                f"AWS Secret Access Key [{'*' * 16 + found[1][-4:] if found else 'None'}]: ",
                f"Default region name [{region or 'None'}]: ",
                "Default output format [json]: ",
            ]
            self.write(self.qpot_prompts.pop(0))
            return
        self.errorWrite(USAGE + "aws: error: argument operation: Invalid choice\n")
        self.exit(252)

    def lineReceived(self, line: str) -> None:
        prompts = getattr(self, "qpot_prompts", None)
        if prompts is None:
            HoneyPotCommand.lineReceived(self, line)
            return
        # what is typed at `aws configure` is the attacker's input: their keys, a stolen one
        self.protocol.events.dispatch("cowrie.command.input", "INPUT (%(realm)s): %(input)s",
                                      realm="aws", input=line)
        if prompts:
            self.write(prompts.pop(0))
        else:
            self.qpot_prompts = None
            self.exit(0)

    def handle_CTRL_C(self) -> None:
        timer = getattr(self, "qpot_timer", None)
        if timer is not None and timer.active():
            timer.cancel()
        HoneyPotCommand.handle_CTRL_C(self)

    def call_aws(self, opts: dict[str, str], words: list[str]) -> None:
        service = words[0]
        if not re.fullmatch(r"[a-z0-9-]{1,40}", service) or len(words) < 2:
            self.errorWrite(USAGE + "aws: error: the following arguments are required: operation\n")
            self.exit(252)
            return
        found = self.credentials(opts)
        region = self.region(opts)
        if found is None:
            self.qpot_timer = self.callLater(random.uniform(0.6, 1.4), self.qpot_fail,
                                             "\nUnable to locate credentials. You can configure credentials by "
                                             "running \"aws configure\".\n", 253)
            return
        self.protocol.events.dispatch(
            "cowrie.credentials.use",
            "AWS credentials of %(username)s used for %(service)s",
            realm="aws",
            username=found[0],
            password=found[1],
            service=service,
            input=" ".join(["aws"] + list(self.args))[:4096],
        )
        if service in GLOBAL:
            url = GLOBAL[service]
        elif not re.fullmatch(r"[a-z]{2}(-gov)?-[a-z]+-[0-9]{1,2}", region or ""):
            self.qpot_timer = self.callLater(random.uniform(0.4, 1.0), self.qpot_fail,
                                             "\nYou must specify a region. You can also configure your region by "
                                             "running \"aws configure\".\n", 253)
            return
        elif service == "s3" and region == "us-east-1":
            url = "https://s3.amazonaws.com/"
        else:
            name = "s3" if service in ("s3", "s3api") else service
            url = f"https://{name}.{region}.amazonaws.com/"
        # no route out: the name does not resolve, after the retries of the standard retry mode
        self.qpot_timer = self.callLater(random.uniform(2.0, 4.5), self.qpot_fail,
                                         f"\nCould not connect to the endpoint URL: \"{url}\"\n", 255)

    def qpot_fail(self, message: str, code: int) -> None:
        self.qpot_timer = None
        self.errorWrite(message)
        self.exit(code)


for _path in ("/usr/local/bin/aws", "/usr/local/aws-cli/v2/current/bin/aws",
              f"/usr/local/aws-cli/v2/{VERSION}/bin/aws", f"/usr/local/aws-cli/v2/{VERSION}/dist/aws"):
    commands[_path] = Command_aws
