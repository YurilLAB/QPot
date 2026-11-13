# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# QPot: this is the image's output/jsonlog.py with one change. On a full disk
# the image's plugin lost events while Cowrie went on serving: with the plain
# log file (what the image is configured with) the write raised and the event
# was dropped, with the rotating one the write's result was ignored and a
# line was cut short (measured by QPot's failure soak: up to 60% of the
# connections taken while the disk was full left no line). For both kinds of
# file, lines are now queued in memory, written whole, and kept until the
# disk has taken them. A line the disk took only part of is ended there and
# written again, whole, when there is room: the collector tells lines apart
# by where they start, and a line it reads in two pieces gets another place
# than the same line read at once (found by the failure soak: one connection
# in 46,000 was stored twice). Lines that still wait when Cowrie is stopped
# on a full disk are written into a small file that has its blocks, and go
# into the log at the next start. See doc/disk-cleanup.md.
#
# A second change: no line is written longer than the collector reads. The
# collector discards, whole, a line longer than 102,400 bytes, and Cowrie
# writes a command twice (as "input" and in "message"): a visitor who ran
# one command of 60,000 characters left no record of it in the database or
# in the log backup (found on a live instance). A line that would be longer
# than QPOT_LINE_BYTES now has its long values cut, and names what was cut
# under "qpot_truncated" with each value's full length and SHA-256.

from __future__ import annotations

import collections
import errno
import hashlib
import json
import os
import time
from pathlib import Path

from twisted.internet import reactor
from twisted.logger import Logger

import cowrie.core.output
import cowrie.python.logfile
from cowrie.core.config import CowrieConfig

# What is held in memory while the disk takes nothing: past either bound new
# lines are dropped and counted. QPot's disk guard frees room or stops Cowrie
# within seconds, long before a honeypot's traffic fills this.
QPOT_PENDING_LINES = 100000
QPOT_PENDING_BYTES = 64 * 1024 * 1024
QPOT_RETRY_SECONDS = 1.0
# How long a stopping Cowrie waits for room for what it still holds. QPot's
# disk guard frees its reserve once the disk is full and has stopped filling,
# which can be a moment after it has told Cowrie to stop; the container is
# killed ten seconds after that.
QPOT_STOP_WAIT_SECONDS = 2.0
# Where the lines go that still wait after that: a file written in full when
# Cowrie starts, so that writing into it later needs no new block. The disk
# guard's reserve is anybody's once it is freed (the failure soak saw the
# database take it before Cowrie could); this file is Cowrie's alone. It is
# kept beside the persona's state, not among the logs, which cleanup prunes.
QPOT_SPILL_DEFAULT = "/home/cowrie/cowrie/etc/qpot-jsonlog.spill"
QPOT_SPILL_BYTES = 1024 * 1024
# The longest line written, under the collector's 102,400 bytes with room
# for what it adds, and the lengths long values are cut to, tried in turn
# until the line fits.
QPOT_LINE_BYTES = 96 * 1024
QPOT_VALUE_CHARS = (16384, 4096, 1024, 128, 16)


def qpot_line(event):
    """
    The log line for event, a newline included, never longer than
    QPOT_LINE_BYTES. An event that fits is written as it is.
    """
    data = (json.dumps(event, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) <= QPOT_LINE_BYTES:
        return data
    cut = {}
    for limit in QPOT_VALUE_CHARS:
        for key in list(event):
            value = event[key]
            if key == "qpot_truncated" or isinstance(value, (bool, int, float)) or value is None:
                continue
            text = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
            if len(text) <= limit:
                continue
            if key not in cut:
                digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
                cut[key] = {"chars": len(text), "sha256": digest}
            event[key] = text[:limit]
        event["qpot_truncated"] = cut
        data = (json.dumps(event, separators=(",", ":")) + "\n").encode("utf-8")
        if len(data) <= QPOT_LINE_BYTES:
            return data
    # More keys than any event Cowrie writes: keep what says who and what.
    kept = {}
    for key in ("eventid", "session", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
                "sensor", "timestamp", "username", "password", "input", "message"):
        if key in event:
            kept[key] = event[key]
    kept["qpot_truncated"] = {"keys": len(event)}
    return (json.dumps(kept, separators=(",", ":")) + "\n").encode("utf-8")


class Output(cowrie.core.output.Output):
    """
    jsonlog output
    """

    _log = Logger()

    def start(self):
        self.epoch_timestamp = CowrieConfig.getboolean(
            "output_jsonlog", "epoch_timestamp", fallback=False
        )
        fn = CowrieConfig.get("output_jsonlog", "logfile", fallback="cowrie.json")
        dirs = os.path.dirname(fn)
        base = os.path.basename(fn)

        self.qpot_pending = collections.deque()
        self.qpot_pending_bytes = 0
        self.qpot_torn = False  # the log ends in part of a line
        self.qpot_dropped = 0
        self.qpot_waiting = False  # the disk refused a write; said once
        self.qpot_retry = None
        self.qpot_rotating = False

        logtype = CowrieConfig.get("honeypot", "logtype", fallback="plain")
        if logtype == "rotating":
            self.outfile = cowrie.python.logfile.CowrieDailyLogFile(
                base, dirs, defaultMode=0o664
            )
            self.qpot_rotating = True
            self.qpot_path = self.outfile.path
        elif logtype == "plain":
            # Unbuffered, as the rotating file is: every write says how much
            # of a line the disk took.
            self.qpot_path = str(Path(dirs, base))
            self.outfile = open(self.qpot_path, "ab", buffering=0)
        else:
            raise ValueError
        self.qpot_end_torn_line()
        self.qpot_spill = CowrieConfig.get(
            "output_jsonlog", "qpot_spill", fallback=QPOT_SPILL_DEFAULT
        )
        self.qpot_spill_held = False  # the spill file holds lines not yet in the log
        self.qpot_restore_spill()
        self.qpot_prepare_spill()
        if self.qpot_pending:
            self.qpot_drain()

    def qpot_restore_spill(self):
        """
        Lines the last stop could not write are in the spill file, up to its
        first NUL byte: they go first.
        """
        try:
            with open(self.qpot_spill, "rb") as f:
                data = f.read(QPOT_SPILL_BYTES)
        except OSError:
            return
        end = data.find(b"\0")
        if end >= 0:
            data = data[:end]
        lines = data.splitlines(keepends=True)
        if lines and not lines[-1].endswith(b"\n"):
            lines.pop()  # cut short by a kill while it was written
        for line in lines:
            self.qpot_pending.append(line)
            self.qpot_pending_bytes += len(line)
        self.qpot_spill_held = bool(lines)

    def qpot_prepare_spill(self):
        """
        Give the spill file its blocks while the disk has them. A file that
        holds lines is left as it is.
        """
        if self.qpot_spill_held:
            return
        try:
            if os.path.getsize(self.qpot_spill) == QPOT_SPILL_BYTES:
                with open(self.qpot_spill, "rb") as f:
                    if f.read(1) == b"\0":
                        return
        except OSError:
            pass
        try:
            with open(self.qpot_spill, "wb", buffering=0) as f:
                if f.write(b"\0" * QPOT_SPILL_BYTES) != QPOT_SPILL_BYTES:
                    raise OSError(errno.ENOSPC, "no space left on device")
                os.fsync(f.fileno())
        except OSError as e:
            try:
                os.remove(self.qpot_spill)
            except OSError:
                pass
            self._log.error(
                "jsonlog: no spill file ({error}); events that wait when Cowrie "
                "is stopped on a full disk are lost",
                error=str(e),
            )

    def qpot_save_spill(self):
        """
        Write the lines that wait into the spill file's own blocks, whole
        lines only, ended by a NUL byte. Returns how many it took.
        """
        data, taken = b"", 0
        for line in self.qpot_pending:
            if len(data) + len(line) + 1 > QPOT_SPILL_BYTES:
                break
            data += line
            taken += 1
        if not taken:
            return 0
        try:
            with open(self.qpot_spill, "r+b", buffering=0) as f:
                if f.seek(0, 2) < len(data) + 1:
                    return 0  # not the file prepare made: it has no blocks to write into
                f.seek(0)
                if f.write(data + b"\0") != len(data) + 1:
                    return 0
                os.fsync(f.fileno())
        except OSError:
            return 0
        return taken

    def qpot_clear_spill(self):
        """The lines the spill file held are in the log: mark it empty."""
        try:
            with open(self.qpot_spill, "r+b", buffering=0) as f:
                f.write(b"\0")
                os.fsync(f.fileno())
        except OSError:
            return
        self.qpot_spill_held = False

    def qpot_file(self):
        """The file a line is written to: unbuffered, binary, appending."""
        return self.outfile._file if self.qpot_rotating else self.outfile

    def qpot_end_torn_line(self):
        """
        A log that ends in part of a line (Cowrie was stopped while the disk
        was full) gets its newline before the next line, so that one starts
        a line of its own.
        """
        try:
            with open(self.qpot_path, "rb") as f:
                size = f.seek(0, 2)
                if size > 0:
                    f.seek(size - 1)
                    self.qpot_torn = f.read(1) != b"\n"
        except OSError:
            pass

    def stop(self):
        if self.qpot_retry is not None and self.qpot_retry.active():
            self.qpot_retry.cancel()
        self.qpot_retry = None
        # The reactor has stopped; nothing else runs. This is the last
        # chance for the lines that wait.
        deadline = time.monotonic() + QPOT_STOP_WAIT_SECONDS
        self.qpot_drain(retry=False)
        while self.qpot_pending and time.monotonic() < deadline:
            time.sleep(0.1)
            self.qpot_drain(retry=False)
        if self.qpot_pending:
            waiting = len(self.qpot_pending)
            kept = self.qpot_save_spill()
            # What the spill file holds is the next start's to write. An
            # event that still arrives now must not find these lines waiting
            # and write them as well, nor mark the file empty.
            for _ in range(kept):
                self.qpot_pending_bytes -= len(self.qpot_pending.popleft())
            if kept:
                self.qpot_spill_held = False
            self._log.error(
                "jsonlog: stopping with {n} events the disk did not take; "
                "{kept} are kept for the next start",
                n=waiting,
                kept=kept,
            )
        if self.outfile:
            self.outfile.flush()

    def write(self, event):
        if self.epoch_timestamp:
            event["epoch"] = int(event["time"] * 1000000 / 1000)
        for i in list(event):
            # Remove twisted 15 legacy keys
            if i.startswith("log_") or i == "time" or i == "system":
                del event[i]
        try:
            data = qpot_line(event)
        except TypeError:
            self._log.error("jsonlog: Can't serialize: '{event!r}'", event=event)
            return
        if (
            len(self.qpot_pending) >= QPOT_PENDING_LINES
            or self.qpot_pending_bytes + len(data) > QPOT_PENDING_BYTES
        ):
            self.qpot_dropped += 1
            if self.qpot_dropped == 1:
                self._log.error(
                    "jsonlog: the disk takes nothing and {n} events wait in memory; "
                    "further events are dropped",
                    n=len(self.qpot_pending),
                )
            return
        self.qpot_pending.append(data)
        self.qpot_pending_bytes += len(data)
        self.qpot_drain()

    def qpot_drain(self, retry=True):
        """
        Write what waits, whole lines in order. Stops at the first write the
        disk refuses and tries again shortly. A line it took part of stays
        as it is, ended by a newline, and the whole line follows it.
        """
        out = self.outfile
        try:
            while self.qpot_pending:
                data = self.qpot_pending[0]
                if self.qpot_torn:
                    if self.qpot_file().write(b"\n") != 1:
                        raise OSError(errno.ENOSPC, "no space left on device")
                    self.qpot_torn = False
                if self.qpot_rotating and out.shouldRotate():
                    # Between lines only: a line is never split across files.
                    out.flush()
                    out.rotate()
                n = self.qpot_file().write(data)
                if n != len(data):
                    self.qpot_torn = bool(n)
                    raise OSError(errno.ENOSPC, "no space left on device")
                self.qpot_pending.popleft()
                self.qpot_pending_bytes -= len(data)
                if self.qpot_rotating:
                    out.lastDate = max(out.lastDate, out.toDate())
        except OSError as e:
            if not self.qpot_waiting:
                self.qpot_waiting = True
                self._log.error(
                    "jsonlog: the log cannot be written ({error}); events wait in "
                    "memory until it can",
                    error=str(e),
                )
            if retry and (self.qpot_retry is None or not self.qpot_retry.active()):
                self.qpot_retry = reactor.callLater(
                    QPOT_RETRY_SECONDS, self.qpot_drain
                )
            return
        if self.qpot_spill_held:
            self.qpot_clear_spill()
        if self.qpot_waiting:
            self.qpot_waiting = False
            self._log.info(
                "jsonlog: the log is written again; {n} events were dropped meanwhile",
                n=self.qpot_dropped,
            )
            self.qpot_dropped = 0
