# Copyright (C) 2015  Lukas Rist <glaslos@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""
Service support based on gaspot.py [https://github.com/sjhilt/GasPot]
Original authors: Kyle Wilhoit and Stephen Hilt

QPot: this replaces the image's guardian_ast_server.py. The image's version
is recognised by published checks (Trend Micro, Rapid7, Kaspersky, several
papers): replies without the SOH and ETX a gauge frames them with, a numeric
date where a gauge prints "NOV 12, 2026 10:15 AM", readings drawn at random
at start that then never change, a TC volume unrelated to temperature, an
ullage unrelated to volume, one tank always in HIGH WATER ALARM, and
9999FF1B for everything but five commands.

Here one seeded model of the site gives every report its numbers. Volume
falls with the time of day, deliveries refill a tank and appear in the
delivery report, ullage is what is left of the tank, height follows from
volume and the tank's shape, TC volume from volume and temperature. The
model is a function of the seed and the clock alone, so two looks an hour
apart differ as a real site's would, and a restart changes nothing. Report
layouts follow the Veeder-Root TLS-300/350 serial interface manual
(576013-635) and a published capture of a real gauge.
"""

import asyncio
import datetime
import hashlib
import json
import logging
import math
import os
import secrets
import socket
import stat
import threading
import time

import conpot.core as conpot_core
from conpot.core.protocol_wrapper import conpot_protocol
from conpot.utils.asyncio_serve import serve_tcp_sync_handler

logger = logging.getLogger(__name__)

SOH = b"\x01"
ETX = b"\x03"
# "9999" says the command was not understood; "FF1B" is the checksum of
# SOH and "9999".
AST_ERROR = SOH + b"9999FF1B" + ETX

STATE_FILE = "/var/lib/conpot/qpot_gauge.json"
LABEL_LENGTH = 20
STEP = 300  # seconds between two points of the model
# How many midnights the model keeps, in memory and in the state file.
KEPT_DAYS = 4
HISTORY_DAYS = 10
MAX_REQUEST = 4096

# Sites: what the four header lines of a report say. Names are made up.
_NAMES = [
    "QUICK STOP", "MAIN ST FUEL", "HILLSIDE MARKET", "RIVER RD TRAVEL CTR", "CORNER PANTRY",
    "VALLEY GAS & GO", "LAKESIDE FUEL STOP", "NORTHGATE EXPRESS", "FOUR CORNERS MART", "PINE RIDGE FUEL",
    "COUNTY LINE STORE", "BRIDGE ST SERVICE", "EASTSIDE FOOD MART", "PRAIRIE TRAVEL PLAZA", "MILL CREEK FUEL",
]
_STREETS = ["MAIN ST", "OAK ST", "HIGHWAY 9", "STATE ROUTE 12", "MAPLE AVE", "COUNTY RD 41", "CHURCH ST", "US HWY 60", "ELM ST", "INDUSTRIAL BLVD"]
# Product line-ups; the coefficient is the thermal expansion per degree F.
_GAS, _DSL = 0.00070, 0.00045
_LINEUPS = [
    [("REGULAR", _GAS), ("PLUS", _GAS), ("PREMIUM", _GAS), ("DIESEL", _DSL)],
    [("UNLEADED", _GAS), ("PREMIUM", _GAS), ("DIESEL", _DSL)],
    [("REGULAR UNLEADED", _GAS), ("PREMIUM UNLEADED", _GAS), ("DIESEL", _DSL), ("KEROSENE", _DSL)],
    [("REGULAR", _GAS), ("MIDGRADE", _GAS), ("PREMIUM", _GAS), ("DIESEL #2", _DSL)],
    [("UNLEADED 87", _GAS), ("UNLEADED 93", _GAS), ("DIESEL", _DSL)],
]
# Nominal capacity in gallons and diameter in inches of common tanks.
_TANKS = [(6000, 96), (8000, 96), (10000, 96), (10000, 120), (12000, 120), (15000, 120)]
# Share of a day's sales in each hour of the day.
_HOURLY = [0.6, 0.4, 0.3, 0.3, 0.5, 1.0, 1.8, 2.4, 2.2, 1.8, 1.7, 1.9, 2.1, 1.9, 1.8, 2.0, 2.4, 2.6, 2.2, 1.7, 1.4, 1.1, 0.9, 0.7]
_HOURLY_TOTAL = sum(_HOURLY)


def _draw(seed, *what):
    """A number in [0, 1) that depends only on the seed and what is asked."""
    digest = hashlib.sha256(("\x00".join([seed] + [str(w) for w in what])).encode()).digest()
    return int.from_bytes(digest[:8], "big") / float(1 << 64)


def _pick(seed, values, *what):
    return values[int(_draw(seed, *what) * len(values)) % len(values)]


class Tank(object):
    """One tank: its shape, what it holds and how the site sells from it."""

    def __init__(self, seed, number, label, coefficient):
        self.number = number
        self.label = label
        self.coefficient = coefficient
        nominal, self.diameter = _pick(seed, _TANKS, "tank", number)
        # A tank chart's full volume is near the nominal size, not on it.
        self.full = int(nominal * (0.948 + 0.02 * _draw(seed, "full", number)))
        # A tank turns over every four to twelve days.
        self.daily = self.full * (0.08 + 0.17 * _draw(seed, "sales", number)) * (0.6 if coefficient == _DSL else 1.0)
        if number == 1:
            self.daily *= 1.3  # the first tank holds the grade that sells most
        self.reorder = self.full * (0.20 + 0.10 * _draw(seed, "reorder", number))
        self.start = self.full * (0.35 + 0.5 * _draw(seed, "start", number))
        self.base_temp = 52.0 + 20.0 * _draw(seed, "temp")
        self.temp_offset = 2.0 * _draw(seed, "tempoff", number) - 1.0
        self.water = 0.0
        if _draw(seed, "water", number) > 0.8:
            self.water = round(0.2 + 0.9 * _draw(seed, "waterlevel", number), 2)

    def height(self, volume):
        """The fuel height in inches for a volume, in a horizontal cylinder."""
        r = self.diameter / 2.0
        target = max(0.0, min(1.0, volume / float(self.full))) * math.pi * r * r
        lo, hi = 0.0, float(self.diameter)
        for _ in range(40):
            h = (lo + hi) / 2.0
            area = r * r * math.acos((r - h) / r) - (r - h) * math.sqrt(max(0.0, 2 * r * h - h * h))
            if area < target:
                lo = h
            else:
                hi = h
        return (lo + hi) / 2.0


class Site(object):
    """The gauge's whole picture at one moment, from the seed and the clock.

    The model runs forward from the anchor, a fixed midnight shortly before
    the gauge was first started, in steps of five minutes. Where it stood at
    each midnight is kept (the last few in memory, the latest in the state
    file), so a look costs at most a day of steps and a restart continues
    exactly where the model was.
    """

    def __init__(self, seed, labels=None, anchor=0, checkpoint=None):
        self.seed = seed
        # A name and a street, and no town: where the sensor is hosted is
        # not known here, and a header must not contradict it.
        self.header = [
            "%s #%d" % (_pick(seed, _NAMES, "name"), 100 + int(_draw(seed, "number") * 8900)),
            "%d %s" % (100 + int(_draw(seed, "street-number") * 9800), _pick(seed, _STREETS, "street")),
            "", "",
        ]
        # The gauge's clock is a few minutes off, as clocks nobody sets are.
        self.skew = int(_draw(seed, "clock") * 540) - 270
        lineup = _pick(seed, _LINEUPS, "lineup")
        self.tanks = [Tank(seed, i + 1, label, coefficient) for i, (label, coefficient) in enumerate(lineup)]
        for tank in self.tanks:
            if labels and labels.get(str(tank.number)):
                tank.label = labels[str(tank.number)]
        self.anchor = int(anchor) // 86400 * 86400
        # Midnights the model has reached: {epoch: {tank number: tank state}}.
        # The state file holds the last few (one, as written by an earlier
        # version): reports look back as far as the day before yesterday, and
        # a time before every known midnight is replayed from the anchor.
        self._days = {}
        for kept in (checkpoint if isinstance(checkpoint, list) else [checkpoint])[-KEPT_DAYS:]:
            if self._valid(kept):
                self._days[int(kept["t"])] = {int(n): s for n, s in kept["tanks"].items()}
        self._cache = {}
        self.newest = None  # the latest midnight reached since the last save

    def _valid(self, checkpoint):
        """Whether a stored checkpoint is one this model could have written."""
        try:
            t = int(checkpoint["t"])
            tanks = checkpoint["tanks"]
            if t % 86400 or t < self.anchor or set(int(n) for n in tanks) != set(k.number for k in self.tanks):
                return False
            for tank in self.tanks:
                s = tanks[str(tank.number)] if str(tank.number) in tanks else tanks[tank.number]
                if not 0 <= float(s["volume"]) <= tank.full or len(s["deliveries"]) > 5:
                    return False
                if s["pending"] is not None and len(s["pending"]) not in (4, 5):
                    return False
            return True
        except (KeyError, TypeError, ValueError, AttributeError):
            return False

    def checkpoint(self):
        """The midnights reached, oldest first, for the state file; None when
        no new one was reached since they were last handed out."""
        if self.newest is None or self.newest not in self._days:
            return None
        self.newest = None
        return [{"t": t, "tanks": {str(n): s for n, s in self._days[t].items()}} for t in sorted(self._days)]

    def _sold(self, tank, t):
        """Gallons sold from tank in the step that starts at t (epoch seconds)."""
        when = _utc(t)
        share = _HOURLY[when.hour] / _HOURLY_TOTAL / (3600.0 / STEP)
        day = 0.75 + 0.5 * _draw(self.seed, "day", tank.number, when.toordinal())
        return tank.daily * share * day * (0.6 + 0.8 * _draw(self.seed, "step", tank.number, t // STEP))

    def _advance(self, tank, s, t):
        """Move one tank's state over the step that starts at t."""
        volume, pending, deliveries = s["volume"], s["pending"], s["deliveries"]
        volume -= self._sold(tank, t)
        if pending is None and volume < tank.reorder:
            # The truck comes some hours after the level is seen.
            wait = 3600 * (2 + int(_draw(self.seed, "wait", tank.number, t) * 7))
            amount = int((tank.full * 0.9 - volume) / 100.0) * 100
            minutes = 10 + int(_draw(self.seed, "pour", tank.number, t) * 15)
            steps = max(1, (minutes * 60) // STEP)
            pending = [t + wait, t + wait + steps * STEP, amount / float(steps), amount]
        if pending is not None and t >= pending[0]:
            if len(pending) == 4:
                pending = pending + [volume]  # what the tank held when the pour began
            if t < pending[1]:
                volume += pending[2]
            if t + STEP >= pending[1]:
                deliveries = (deliveries + [{"start": pending[0], "end": pending[1], "before": pending[4], "after": volume}])[-5:]
                pending = None
        volume = min(max(volume, tank.full * 0.03), tank.full * 0.95)
        return {"volume": volume, "pending": pending, "deliveries": deliveries}

    def state(self, now):
        """Volume and deliveries of every tank at now (epoch seconds)."""
        end = max(int(now) // STEP * STEP, self.anchor)
        if end in self._cache:
            return self._cache[end]
        known = [d for d in self._days if d <= end]
        if known:
            t = max(known)
            current = {n: dict(s) for n, s in self._days[t].items()}
        else:
            t = self.anchor
            current = {k.number: {"volume": k.start, "pending": None, "deliveries": []} for k in self.tanks}
        while t < end:
            for tank in self.tanks:
                current[tank.number] = self._advance(tank, current[tank.number], t)
            t += STEP
            if t % 86400 == 0:
                self._days[t] = {n: dict(s) for n, s in current.items()}
                if self.newest is None or t > self.newest:
                    self.newest = t
                for old in sorted(self._days)[:-KEPT_DAYS]:
                    del self._days[old]
        if len(self._cache) >= 8:
            self._cache.clear()
        self._cache[end] = current
        return current

    def temperature(self, tank, now):
        day = _utc(now).timetuple().tm_yday
        season = 9.0 * math.sin(2 * math.pi * (day - 110) / 365.0)
        hour = 0.6 * math.sin(2 * math.pi * ((now % 86400) / 86400.0 - 0.4))
        return tank.base_temp + tank.temp_offset + season + hour

    def reading(self, tank, now, volume=None):
        """What the gauge shows for a tank: a row of the inventory report."""
        if volume is None:
            volume = self.state(now)[tank.number]["volume"]
        temp = self.temperature(tank, now)
        return {
            "volume": int(round(volume)),
            "tc": int(round(volume * (1 + tank.coefficient * (60.0 - temp)))),
            "ullage": int(round(tank.full - volume)),
            "height": tank.height(volume),
            "water": tank.water,
            "temp": temp,
        }


def stamp(when):
    """A gauge's date line: NOV  2, 2026  9:05 AM."""
    hour = when.hour % 12 or 12
    return "%s %2d, %d %2d:%02d %s" % (
        when.strftime("%b").upper(), when.day, when.year, hour, when.minute, "AM" if when.hour < 12 else "PM")


def _utc(epoch):
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).replace(tzinfo=None)


def _row(tank, r):
    # A label of at most twenty characters, then numbers that end under
    # the last letter of their headings whatever their size.
    return "%3d  %-20s%6d%10d%9d%9.2f%9.2f%9.2f" % (
        tank.number, tank.label[:LABEL_LENGTH], r["volume"], r["tc"], r["ullage"], r["height"], r["water"], r["temp"])


INVENTORY_HEADER = "TANK PRODUCT             VOLUME TC VOLUME   ULLAGE   HEIGHT    WATER     TEMP"


def _frame(code, now, site, lines):
    """One display-format reply: SOH, the function code, the report, ETX."""
    text = ["", code, stamp(now), ""] + site.header + [""] + lines + [""]
    return SOH + "\r\n".join(text).encode("ascii", "replace") + ETX


def _selected(site, tank_code):
    """The tanks a two-digit tank number names: 00 is all of them."""
    if not tank_code.isdigit():
        return None
    number = int(tank_code)
    if number == 0:
        return list(site.tanks)
    chosen = [t for t in site.tanks if t.number == number]
    return chosen or None


def report(site, command, epoch=None):
    """The reply to one six-character function code at a moment (epoch
    seconds; now when not given), or None when the gauge does not know it."""
    if epoch is None:
        epoch = time.time()
    now = _utc(epoch + site.skew)
    kind, tanks = command[:4], _selected(site, command[4:6])
    if command == "I90200":
        return _frame(command, now, site, [
            "SOFTWARE REVISION LEVEL", "VERSION 131.02", "SOFTWARE# 346330-100-B", "CREATED - 10.01.20.17.44", "",
            "S-MODULE# 330140-145-a", "SYSTEM FEATURES:", "  PERIODIC IN-TANK TESTS", "  ANNUAL IN-TANK TESTS"])
    if tanks is None:
        return None
    state = site.state(epoch)
    if kind == "I201":
        lines = ["IN-TANK INVENTORY", "", INVENTORY_HEADER]
        lines += [_row(t, site.reading(t, epoch)) for t in tanks]
        return _frame(command, now, site, lines)
    if kind == "I202":
        lines = ["DELIVERY REPORT", ""]
        for t in tanks:
            lines += ["T %d:%s" % (t.number, t.label), "INCREASE   DATE / TIME             GALLONS TC GALLONS WATER  TEMP DEG F  HEIGHT", ""]
            for d in reversed(state[t.number]["deliveries"][-3:]):
                after = site.reading(t, d["end"], d["after"])
                before = site.reading(t, d["start"], d["before"])
                for name, at, r in (("END", d["end"], after), ("START", d["start"], before)):
                    lines.append("%9s: %-21s%10d%11d%7.2f%11.2f%8.2f" % (
                        name, stamp(_utc(at + site.skew)), r["volume"], r["tc"], r["water"], r["temp"], r["height"]))
                lines += ["%9s: %-21s%10d%11d" % ("AMOUNT", "", after["volume"] - before["volume"], after["tc"] - before["tc"]), ""]
        return _frame(command, now, site, lines)
    if kind == "I203":
        lines = []
        # The last test ran in the small hours, when little is sold.
        began = (int(epoch) // 86400) * 86400 - 86400 + 2 * 3600 + 30 * 60
        for t in tanks:
            r = site.reading(t, began)
            later = site.temperature(t, began + 2 * 3600)
            changes = [0.04 * _draw(site.seed, "leak", t.number, began, i) - 0.02 for i in range(6)]
            lines += [
                "TANK %d    %s" % (t.number, t.label),
                "    TEST STATUS: OFF      0.2 GAL/HR TEST PASS",
                "TEST START TIME: %s    DURATION:  2 HOURS" % stamp(_utc(began + site.skew)),
                "START TEMP: %.1f DEG F   START VOLUME: %d GALLONS" % (r["temp"], r["volume"]),
                "ENDING TEMP: %.1f DEG F   LEAK RATE: %.2f GALLONS/HR" % (later, sum(changes) / 2.0),
                "CUMULATIVE PERIODIC VOLUME CHANGE (GALLONS):",
                " ".join("%.2f" % c for c in changes), ""]
        return _frame(command, now, site, lines)
    if kind == "I204":
        lines = ["TANK PRODUCT                   VOLUME TC VOLUME   ULLAGE   HEIGHT    WATER     TEMP"]
        # The shift began at six in the morning by the gauge's clock.
        shift = (int(epoch) // 86400) * 86400 + 6 * 3600
        if shift > epoch:
            shift -= 86400
        earlier = site.state(shift)
        for t in tanks:
            begin = site.reading(t, shift, earlier[t.number]["volume"])
            end = site.reading(t, epoch)
            delivered = sum(d["after"] - d["before"] for d in state[t.number]["deliveries"] if shift <= d["start"] < epoch)
            values = "%7d%10d%9d%9.2f%9.2f%9.2f"
            lines += [
                "%3d  %s" % (t.number, t.label),
                "SHIFT 1 STARTING VALUES     " + values % (begin["volume"], begin["tc"], begin["ullage"], begin["height"], begin["water"], begin["temp"]),
                "        ENDING VALUES       " + values % (end["volume"], end["tc"], end["ullage"], end["height"], end["water"], end["temp"]),
                "        DELIVERY VALUE      %7d" % int(round(delivered)),
                "        TOTALS              %7d" % int(round(begin["volume"] + delivered - end["volume"])), ""]
        return _frame(command, now, site, lines)
    if kind == "I205":
        lines = ["TANK PRODUCT                     STATUS", ""]
        for t in tanks:
            volume = state[t.number]["volume"]
            status = "NORMAL"
            if volume < t.full * 0.10:
                status = "LOW PRODUCT ALARM"
            elif volume < t.reorder:
                status = "DELIVERY NEEDED"
            lines.append("%4d %-28s%s" % (t.number, t.label, status))
        return _frame(command, now, site, lines)
    if kind == "I602":
        lines = ["TANK PRODUCT LABEL", "", "TANK    PRODUCT LABEL"]
        lines += ["%3d     %s" % (t.number, t.label) for t in tanks]
        return _frame(command, now, site, lines)
    return None

def gauge_seed():
    """The gauge's seed: drawn from the site's seed when QPot passes one."""
    site = os.environ.get("QPOT_SITE_SEED", "")
    if len(site) >= 16:
        return hashlib.sha256(("qpot-gauge\x00" + site).encode()).hexdigest()[:32]
    return secrets.token_hex(16)


# How much of the state file is read, and how far back a model without a
# recent midnight may start: the file is in a folder the container writes, so
# neither its size nor its anchor may make a start slow.
STATE_MAX_BYTES = 1 << 20
ANCHOR_MAX_AGE = 30 * 86400


def read_state_file(path):
    """The state file's JSON, or None: never through a link, never from a
    FIFO or anything but a regular file, never more than STATE_MAX_BYTES."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > STATE_MAX_BYTES:
            return None
        data = os.read(fd, STATE_MAX_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    try:
        state = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return state if isinstance(state, dict) else None


def load_state(path=None):
    """The labels visitors set and where the model stands, kept across
    restarts. Under QPot the gauge's seed is the site's (gauge_seed), never
    the file's: what is in the file can neither change the station and its
    tanks nor keep the gauge from starting."""
    path = path or STATE_FILE
    now = int(time.time())
    stored = read_state_file(path) or {}
    labels = {}
    if isinstance(stored.get("labels"), dict):
        for number, label in list(stored["labels"].items())[:16]:
            if (isinstance(number, str) and number.isdigit() and len(number) <= 2 and isinstance(label, str)
                    and 0 < len(label) <= LABEL_LENGTH and all(32 <= ord(c) < 127 for c in label)):
                labels[number] = label
    # The model starts ten days back, so the first look already shows
    # deliveries and tanks at different levels. A kept anchor is used when it
    # is a past midnight and the model need not be replayed from further back
    # than ANCHOR_MAX_AGE: a kept midnight that recent, or the anchor itself.
    anchor = stored.get("anchor")
    checkpoint = stored.get("checkpoint")
    kept = checkpoint if isinstance(checkpoint, list) else [checkpoint]
    recent = any(isinstance(c, dict) and isinstance(c.get("t"), int) and now - ANCHOR_MAX_AGE <= c["t"] <= now for c in kept)
    seed = gauge_seed()
    if (not os.environ.get("QPOT_SITE_SEED") and isinstance(stored.get("seed"), str) and 16 <= len(stored["seed"]) <= 64
            and all(c in "0123456789abcdef" for c in stored["seed"])):
        # Started without QPot's site step: the seed it drew at its first
        # start, as before there was a site seed.
        seed = stored["seed"]
    state = {"seed": seed, "labels": labels}
    if isinstance(anchor, int) and not isinstance(anchor, bool) and 0 < anchor <= now and (recent or now - anchor <= ANCHOR_MAX_AGE):
        state["anchor"] = anchor
        if recent:
            state["checkpoint"] = checkpoint
    else:
        state["anchor"] = (now // 86400 - 10) * 86400
    if state != stored:
        save_state(state, path)
    return state


def save_state(state, path=None):
    path = path or STATE_FILE
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f)
        os.replace(tmp, path)
    except OSError as e:
        logger.warning("GuardianAST state not saved: %s", e)


@conpot_protocol
class GuardianASTServer(object):
    def __init__(self, template, template_directory, args):
        # template is a dict from guardian_ast.toml (listen/device_info only).
        self.timeout = 5
        self.server = None
        self.databus = conpot_core.get_databus()
        self.state = load_state()
        self.site = Site(self.state["seed"], self.state["labels"], self.state["anchor"], self.state.get("checkpoint"))
        # Connections are served by several threads; the model is one.
        self.lock = threading.Lock()
        # Bring the model up to now before anyone connects: after a long
        # stop, or with a state file that holds no midnight, that is a replay
        # no visitor should wait for. Two days back first, so the midnights
        # the reports look back to are there.
        now = time.time() + self.site.skew
        self.site.state(now - 2 * 86400)
        self.site.state(now)
        reached = self.site.checkpoint()
        if reached is not None:
            self.state["checkpoint"] = reached
            save_state(self.state)
        logger.info("Conpot GuardianAST initialized")

    def set_label(self, command, request):
        """S602TT sets a tank's product label, as on the gauge's keypad."""
        tanks = _selected(self.site, command[4:6])
        start = request.find(command.encode()) + len(command)
        label = request[start:].split(b"\r")[0].split(b"\n")[0].split(ETX)[0]
        label = "".join(chr(c) for c in label[:LABEL_LENGTH] if 32 <= c < 127).rstrip()
        if not tanks or command[4:6] == "00" or not label:
            return None
        tanks[0].label = label
        self.state["labels"][str(tanks[0].number)] = label
        save_state(self.state)
        return report(self.site, "I602" + command[4:6])

    def handle(self, sock, addr):
        # A scanner may leave the connection open with nothing more to say.
        sock.settimeout(self.timeout)
        session = conpot_core.get_session(
            "guardian_ast", addr[0], addr[1], sock.getsockname()[0], sock.getsockname()[1])
        logger.info("New GuardianAST connection from %s:%d. (%s)", addr[0], addr[1], session.id)
        session.log_event(event_type="NEW_CONNECTION")
        buffered = b""
        try:
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buffered += chunk
                    if len(buffered) > MAX_REQUEST:
                        break
                    # A command is SOH (or the two characters ^A, as typed in
                    # a terminal) and at least six more characters.
                    while True:
                        positions = [p for p in (buffered.find(SOH), buffered.find(b"^A")) if p >= 0]
                        if not positions:
                            buffered = buffered[-1:]  # a gauge ignores what is not a command
                            break
                        at = min(positions)
                        skip = 1 if buffered[at:at + 1] == SOH else 2
                        body = buffered[at + skip:]
                        if len(body) < 6:
                            buffered = buffered[at:]
                            break
                        command = body[:6].decode("ascii", "replace")
                        end = len(body)
                        for mark in (b"\n", b"\r", ETX, SOH):
                            p = body.find(mark, 6)
                            if 0 <= p < end:
                                end = p
                        if command.startswith("S602") and end == len(body) and not body.endswith((b"\n", b"\r", ETX)):
                            if len(body) < 6 + LABEL_LENGTH:
                                buffered = buffered[at:]
                                break  # the label has not all arrived yet
                            end = 6 + LABEL_LENGTH
                        request = body[:end]
                        buffered = body[end:]
                        with self.lock:
                            if command.startswith("S602"):
                                response = self.set_label(command, request)
                            else:
                                response = report(self.site, command)
                            reached = self.site.checkpoint()
                            if reached is not None:
                                self.state["checkpoint"] = reached
                                save_state(self.state)
                        if response is None:
                            response = AST_ERROR
                        logger.info("%s command attempt %s:%d. (%s)", command, addr[0], addr[1], session.id)
                        sock.sendall(response)
                        session.log_event(
                            event_type="AST {0}".format(command), request=SOH + request,
                            response=response.decode("ascii", "replace"))
                except socket.timeout:
                    logger.debug("Socket timeout, remote: %s:%d. (%s)", addr[0], addr[1], session.id)
                    break
                except Exception as e:
                    logger.exception("Unknown Error: {}".format(str(e)))
                    break
        finally:
            logger.info("GuardianAST client disconnected %s:%d. (%s)", addr[0], addr[1], session.id)
            session.log_event(event_type="CONNECTION_LOST")
            sock.close()

    async def start(self, host, port):
        self.host = host
        self.port = port
        self._stop = asyncio.Event()
        self._ready = asyncio.Event()
        logger.info("GuardianAST server started on: {0}".format((host, port)))
        await serve_tcp_sync_handler(
            host, port, self, stop_event=self._stop, ready_event=self._ready, name="GuardianASTServer")

    def stop(self):
        if hasattr(self, "_stop"):
            self._stop.set()
