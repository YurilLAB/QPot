#!/usr/bin/env python3
"""QPot: start Conpot as a device at a site of its own.

The image renders a device profile with values drawn per install (addresses,
MACs, serial numbers) and then starts Conpot. Some of what a visitor reads
is not drawn, though: the station and contact names an RTU reports over SNMP,
the name a BMC gives its system, the server a meter reports to, the room a
building controller says it stands in and the names of an ICCP server's
points are the same on every install of the image, and so name the image.

This does what the image's entrypoint does (tpot_templates.py render) with
one step added: after the profile is rendered, those values are replaced by
ones drawn from the site's seed, which QPot passes in QPOT_SITE_SEED. Every
value the image is known to carry must be found where it is expected; if one
is not, the image has changed and this stops instead of starting a device
with values nobody reviewed.

The seed comes from QPot, so nothing here has to be saved for the site to
stay the same, and nothing in the state folder (which the container writes)
is read for it. The values the image draws itself on a first start
(addresses, MACs, serial numbers) are drawn from the seed too; values an
earlier start kept in /var/lib/conpot are used where they are values the
image could have drawn, and ignored otherwise, and the identity is kept
there as the image keeps it. Without a seed this stops: a
site made up for one start would change the plant between two visits.
"""

import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
import tempfile
import tomllib
from pathlib import Path

sys.path.insert(0, "/opt/tpot")
import tpot_templates as tpot  # noqa: E402

SEED_ENV = "QPOT_SITE_SEED"

# Made-up station codes, as utilities abbreviate their sites.
_STATIONS = ["NWD", "ELM", "RVS", "HLD", "KGS", "WTN", "BRK", "ASH", "MRL", "FRD", "LKS", "OAK", "STN", "CLF", "GRV", "PKH"]
_BAYS = ["T1E", "T2E", "T1W", "T2W", "E01", "E02", "K1", "K2", "Bay 3", "Bay 5"]
_CONTACTS = ["SCADA Operations", "IT Service Desk", "Network Control", "OT Support", "Control Room", "Grid Operations", "Telecontrol Group", "Protection and Control"]
_BMC_NAMES = ["bmc%02d", "ipmi-node%02d", "srv%02d-bmc", "mgmt%02d", "node%02d-ipmi", "esx%02d-bmc", "stor%02d-bmc"]
_METER_SERVERS = ["kap%02d.meter.local", "ami-head%02d.int.local", "mdm%02d.util.local", "hes%02d.grid.local", "collector%02d.ami.local", "pwr-ctrl-%02d.int.local"]
_ROOMS = ["Plant Room", "Technikraum UG", "Mechanical Room 1", "Roof Plant Room", "Basement Plant", "Heizzentrale", "Energy Centre", "MER 01"]


def draw(seed, what, n):
    """A number below n that depends only on the seed and what is asked."""
    digest = hashlib.sha256((seed + "\x00" + what).encode()).digest()
    return int.from_bytes(digest[:8], "big") % n


def pick(seed, what, values):
    return values[draw(seed, what, len(values))]


def replacements(name, seed):
    """What to replace in a rendered profile: {file: [(text, new text)]}."""
    station = "%s%02d" % (pick(seed, "station", _STATIONS), 1 + draw(seed, "station-number", 24))
    if name == "IEC104":
        return {"template.toml": [
            ('sysContact = "Corporate IT"', 'sysContact = "%s"' % pick(seed, "contact", _CONTACTS)),
            ('sysName = "DE-BER01"', 'sysName = "%s-RTU%d"' % (station, 1 + draw(seed, "rtu", 3))),
            ('sysLocation = "BER01, T2E"', 'sysLocation = "%s, %s"' % (station, pick(seed, "bay", _BAYS))),
            ('FacilityName = "BER01 Substation"', 'FacilityName = "%s Substation"' % station),
        ], "dnp3.toml": [
            # The outstation's four points: every install read off, on, 25 and 100.
            ("{ index = 0, value = false }", "{ index = 0, value = %s }" % ("true", "false")[draw(seed, "dnp3-b0", 2)]),
            ("{ index = 1, value = true }", "{ index = 1, value = %s }" % ("true", "false")[draw(seed, "dnp3-b1", 2)]),
            ("{ index = 0, value = 25 }", "{ index = 0, value = %d }" % (12 + draw(seed, "dnp3-a0", 469))),
            ("{ index = 1, value = 100 }", "{ index = 1, value = %d }" % (500 + draw(seed, "dnp3-a1", 11500))),
        ]}
    if name == "ipmi":
        return {"template.toml": [
            ('SystemName = "DoE"', 'SystemName = "%s"' % (pick(seed, "bmc", _BMC_NAMES) % (1 + draw(seed, "bmc-number", 48)))),
        ]}
    if name == "kamstrup_382":
        return {"template.toml": [
            ("'pwr_ctrl_mgmt01.int.local'", "'%s'" % (pick(seed, "meter-server", _METER_SERVERS) % (1 + draw(seed, "meter-server-number", 8)))),
            ("'10.232.15.242'", "'10.%d.%d.%d'" % (draw(seed, "kap-a", 256), draw(seed, "kap-b", 256), 2 + draw(seed, "kap-c", 250))),
        ]}
    if name == "building_automation":
        return {"bacnet.toml": [
            ('location = "Technikzentrale"', 'location = "%s"' % pick(seed, "room", _ROOMS)),
        ]}
    if name == "iccp":
        return {"iccp.toml": [("BER01", station)]}
    return {}


def site_seed():
    """The site's seed, as QPot passes it."""
    seed = os.environ.get(SEED_ENV, "")
    if not (16 <= len(seed) <= 128 and seed.isascii() and seed.isalnum()):
        tpot.die(f"{SEED_ENV} holds no site seed; QPot sets it when it starts Conpot (qpot up)")
    return seed


# The most of an identity file that is read. The file is in a folder the
# container writes: what is in it must not keep the device from starting.
IDENTITY_MAX_BYTES = 65536


def read_state_json(path):
    """A JSON object from the state folder, or None: never through a link,
    never from a FIFO or anything but a regular file, never a large one."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > IDENTITY_MAX_BYTES:
            return None
        data = os.read(fd, IDENTITY_MAX_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        # RecursionError: brackets nested deeper than the parser goes.
        return None
    return value if isinstance(value, dict) else None


def plausible(gen, value):
    """Whether a kept value is one the image's generator could have drawn."""
    kind = gen.get("gen")
    if kind == "int":
        return type(value) is int and gen["min"] <= value <= gen["max"]
    if kind == "choice":
        return type(value) in (str, int) and value in gen["values"]
    if not isinstance(value, str) or len(value) > 64:
        return False
    if kind == "lan_ip":
        try:
            address = ipaddress.IPv4Address(value)
        except ValueError:
            return False
        return address.is_private and str(address) == value
    if kind == "mac":
        return re.fullmatch(re.escape(gen["oui"].upper()) + "(:[0-9A-F]{2}){3}", value) is not None
    if kind == "digits":
        return len(value) == gen["n"] and value.isdigit() and value.isascii() and value[0] != "0"
    if kind == "hex":
        digits = "0-9A-F" if gen.get("upper") else "0-9a-f"
        return re.fullmatch("[%s]{%d}" % (digits, gen["n"]), value) is not None
    if kind == "hexbytes":
        return re.fullmatch("[0-9A-F]{2}( [0-9A-F]{2}){%d}" % (gen["n"] - 1), value) is not None
    return False


class SeededDraws(object):
    """What the image's identity step takes from the secrets module, drawn
    from the site's seed instead: the same seed draws the same values."""

    def __init__(self, seed, what):
        self.seed, self.what, self.n = seed, what, 0

    def randbelow(self, n):
        self.n += 1
        return draw(self.seed, "%s#%d" % (self.what, self.n), n)

    def choice(self, values):
        return values[self.randbelow(len(values))]


def load_identity(name, tpl, seed):
    """The image's identity for this template: the values an earlier start
    kept in the state folder where they are values the image could have
    drawn, and values drawn from the site's seed for the rest: the seed
    draws the same values on every start. A kept file that is damaged, of
    another kind or holds values the image never draws is ignored where the
    image would stop. The identity is written back where the image keeps it
    when it differs from what was there."""
    stored = read_state_json(Path(tpot.IDENTITY_DIR) / ("%s.json" % name)) or {}
    values = stored.get("values")
    kept = {}
    if isinstance(values, dict):
        for token, gen in tpl.get("identity", {}).items():
            if "gen" in gen and token in values and plausible(gen, values[token]):
                kept[token] = values[token]
    drawn = tpot.secrets
    tpot.secrets = SeededDraws(seed, "identity:" + name)
    try:
        values = tpot.resolve_identity(tpl, kept)[0]
    finally:
        tpot.secrets = drawn
    primary = {k: values[k] for k, gen in tpl.get("identity", {}).items() if "gen" in gen}
    if primary != values_of(stored):
        save_identity(name, primary)
    return values


def values_of(stored):
    values = stored.get("values")
    return values if isinstance(values, dict) else None


def save_identity(name, primary):
    """Keep the identity where the image keeps it, as the image writes it, so
    that what reads it there finds it. Best effort: the next start draws the
    same values from the seed whether or not this worked."""
    try:
        fd, tmp = tempfile.mkstemp(dir=tpot.IDENTITY_DIR, prefix=".%s." % name)
        with os.fdopen(fd, "w") as f:
            json.dump({"version": 1, "template": name, "values": primary}, f, indent=2)
        os.replace(tmp, Path(tpot.IDENTITY_DIR) / ("%s.json" % name))
    except OSError as exc:
        tpot.info("identity of %s not kept in %s (%s); the next start draws the same" % (name, tpot.IDENTITY_DIR, exc))


def apply_site(name, rendered, seed):
    """Replace the values every install shares in the rendered profile."""
    for filename, pairs in replacements(name, seed).items():
        path = Path(rendered) / filename
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            tpot.die(f"{name}: {filename} is not in the profile ({exc}); the image has changed")
        for old, new in pairs:
            if old not in text:
                tpot.die(f"{name}/{filename}: '{old}' is not there; the image has changed and its values need review")
            text = text.replace(old, new)
        try:
            tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            tpot.die(f"{name}/{filename}: invalid TOML after the site's values: {exc}")
        path.write_text(text, encoding="utf-8")


def main(name):
    spec = tpot.load_spec(os.environ.get("TPOT_TEMPLATE_SPEC", tpot.DEFAULT_SPEC))
    if name not in spec["templates"]:
        tpot.die(f"template '{name}' is not part of the T-Pot spec")
    tmp = os.environ.get("CONPOT_TMP", "/tmp/conpot")
    rendered = Path(tmp) / "templates" / name
    seed = site_seed()
    tpot.render_dir(tpot.package_templates_dir() / name, rendered, load_identity(name, spec["templates"][name], seed))
    apply_site(name, rendered, seed)
    # The protocol servers QPot mounts draw the site's readings from the
    # same seed (QPOT_SITE_SEED, inherited by conpot).
    argv = [
        "conpot",
        "--mibcache", tmp,
        "--temp_dir", tmp,
        "--template", str(rendered),
        "--logfile", os.environ.get("CONPOT_LOG", "/var/log/conpot/conpot.log"),
        "--config", os.environ.get("CONPOT_CONFIG", "/etc/conpot/conpot.cfg"),
    ]
    os.execvp(argv[0], argv)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        tpot.die("usage: site_identity.py <template>")
    main(sys.argv[1])
