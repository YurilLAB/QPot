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
ones drawn from a seed kept beside the image's own identity. Every value the
image is known to carry must be found where it is expected; if one is not,
the image has changed and this stops instead of starting a device with
values nobody reviewed.
"""

import hashlib
import json
import os
import secrets
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, "/opt/tpot")
import tpot_templates as tpot  # noqa: E402

SITE_FILE = "qpot_site.json"

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


def load_seed(directory):
    """The site's seed, kept beside the image's own identity files."""
    path = Path(directory) / SITE_FILE
    try:
        seed = json.loads(path.read_text())["seed"]
        if isinstance(seed, str) and len(seed) >= 16:
            return seed
    except (OSError, ValueError, KeyError, TypeError):
        pass
    seed = secrets.token_hex(16)
    try:
        tmp = path.with_name("." + SITE_FILE + ".tmp")
        tmp.write_text(json.dumps({"version": 1, "seed": seed}))
        os.replace(tmp, path)
    except OSError as exc:
        tpot.info(f"WARNING: cannot keep the site in {directory} ({exc}), using one for this start only")
    return seed


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
    tpot.render_dir(tpot.package_templates_dir() / name, rendered, tpot.load_identity(name, spec["templates"][name]))
    seed = load_seed(tpot.IDENTITY_DIR)
    apply_site(name, rendered, seed)
    # For the protocol servers QPot mounts, which draw a site's readings.
    os.environ["QPOT_SITE_SEED"] = seed
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
