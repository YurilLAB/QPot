# Copyright (C) 2026 MushMush Foundation
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

"""OPC UA honeypot protocol (IEC 62541 via asyncua, Conpot-owned TCP).

QPot: the image's server gives every variable the value its template names
and never changes it, so the PLC of every install reads 21.4 degrees, 3.82
bar and batch 1187 for ever. A controller's variables are written by its
program on every cycle. Here the four variables of the Beckhoff profile come
from one small model of a batch process, with numbers of its own per
instance (drawn from the site's seed) and moved by the clock: a pump that
runs for part of every batch, a pressure that follows the pump, a
temperature that follows both slowly, and a batch counter. The model is a
function of the seed and the time only, so a restart continues it.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import math
import os
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from types import SimpleNamespace

from asyncua import Server, ua

import conpot.core as conpot_core
from conpot.core.protocol_wrapper import conpot_protocol
from conpot.protocols.opcua.session import run_opcua_session
from conpot.utils.asyncio_serve import _set_listener_addrs

logger = logging.getLogger(__name__)

# The site's seed, given by the step that starts Conpot (site_identity.py).
SEED_ENV = "QPOT_SITE_SEED"
# How often the model writes its variables, in seconds.
PROCESS_TICK = 1.0
# Plants are commissioned between 200 and 700 days before this moment
# (2026-01-01 00:00 UTC): the batch counter counts from there.
_REFERENCE = 1767225600


def _draw(seed, what, n):
    """A number below n that depends only on the seed and what is asked."""
    digest = hashlib.sha256((seed + "\x00" + what).encode()).digest()
    return int.from_bytes(digest[:8], "big") % n


def _unit(seed, what):
    return _draw(seed, what, 1 << 32) / float(1 << 32)


def _lag(phase, on, cycle, tau):
    """A first-order lag behind a signal that is 1 for the first `on` seconds
    of every `cycle` and 0 for the rest, in its settled, repeating state.
    Between 0 and 1 and continuous everywhere, the cycle's end included."""
    a, b = on / tau, (cycle - on) / tau
    low = (1.0 - math.exp(-a)) * math.exp(-b) / (1.0 - math.exp(-(a + b)))
    if phase < on:
        return 1.0 - (1.0 - low) * math.exp(-phase / tau)
    high = 1.0 - (1.0 - low) * math.exp(-a)
    return high * math.exp(-(phase - on) / tau)


class Process:
    """The batch process behind MAIN.fTemperature, MAIN.fPressure,
    MAIN.bPumpRunning and MAIN.nBatchId."""

    NAMES = ("MAIN.fTemperature", "MAIN.fPressure", "MAIN.bPumpRunning", "MAIN.nBatchId")

    def __init__(self, seed):
        self.seed = seed
        self.cycle = 60.0 * (18 + _draw(seed, "cycle", 38))  # one batch: 18 to 55 minutes
        self.on = self.cycle * (0.55 + 0.30 * _unit(seed, "duty"))  # the pump runs this long of it
        self.temperature = 24.0 + 34.0 * _unit(seed, "temperature")  # degrees C at rest
        self.rise = 0.6 + 1.8 * _unit(seed, "rise")  # warmer by this while pumping
        self.pressure = 2.6 + 3.2 * _unit(seed, "pressure")  # bar with the pump running
        self.rest = 0.2 + 0.6 * _unit(seed, "rest")  # bar with it stopped
        self.pressure_tau = 6.0 + 12.0 * _unit(seed, "pressure-tau")
        self.day = 2.0 * math.pi * _unit(seed, "day")
        self.started = _REFERENCE - 86400 * (200 + _draw(seed, "commissioned", 500)) - _draw(seed, "commissioned-second", 86400)

    def _noise(self, what, now, size):
        return size * (2.0 * _unit(self.seed, "%s %d" % (what, int(now))) - 1.0)

    def values(self, now):
        """Every variable at one moment: {name: value}."""
        since = max(now - self.started, 0.0)
        batch = int(since // self.cycle)
        phase = since - batch * self.cycle
        pressure = self.rest + (self.pressure - self.rest) * _lag(phase, self.on, self.cycle, self.pressure_tau)
        temperature = (
            self.temperature
            + self.rise * _lag(phase, self.on, self.cycle, self.cycle / 4.0)
            + 0.5 * math.sin(2.0 * math.pi * (now % 86400) / 86400.0 + self.day)
        )
        return {
            "MAIN.fTemperature": temperature + self._noise("t", now, 0.03),
            "MAIN.fPressure": pressure + self._noise("p", now, 0.012),
            "MAIN.bPumpRunning": phase < self.on,
            "MAIN.nBatchId": 1 + batch % 2000000000,
        }


def process_from_environment():
    """The site's process, or None when no seed was given: the variables
    then keep the template's values, as in the image."""
    seed = os.environ.get(SEED_ENV, "")
    return Process(seed) if len(seed) >= 16 else None


@contextmanager
def _quiet_nodeset_load():
    """Mute asyncua's per-node INFO chatter while the standard nodeset loads.

    The bundled nodeset references parents that are not present yet, which
    logs ~1100 lines per start. Node management at runtime stays at INFO.
    """
    aspace_logger = logging.getLogger("asyncua.server.address_space")
    previous = aspace_logger.level
    aspace_logger.setLevel(logging.WARNING)
    try:
        yield
    finally:
        aspace_logger.setLevel(previous)


@conpot_protocol
class OPCUAServer(object):
    """OPC UA / opc.tcp honeypot.

    Conpot owns accept / session / timeouts. asyncua InternalServer +
    UaProcessor own application PDUs and the address space. BinaryServer is
    not used so scanners share Conpot's multi-connection accept model.
    """

    def __init__(self, template, template_directory, args):
        self.timeout = float(template.get("timeout", 5))
        self.host = None
        self.port = None
        self.server = None
        self.template = template
        self.databus = conpot_core.get_databus()

        self.endpoint_path = str(template.get("endpoint_path", "/conpot/server/"))
        if not self.endpoint_path.startswith("/"):
            self.endpoint_path = "/" + self.endpoint_path
        self.server_name = str(template.get("server_name", "Conpot OPC UA Server"))
        self.namespace_uri = str(
            template.get("namespace_uri", "http://conpot.org/OPCUA/")
        )
        self.application_uri = str(template.get("application_uri", "urn:conpot:opcua"))
        self._variables = list(template.get("variables", []) or [])
        self._process = process_from_environment()
        # [(node, name, variant type)] of the variables the process writes.
        self._driven = []

        self._ua: Server | None = None
        self._ua_started = False
        # Startup waits on _ready right after scheduling start(), so the Events
        # must exist before then and must not be replaced in start().
        self._stop = asyncio.Event()
        self._ready = asyncio.Event()
        logger.info(
            "OPC UA server configured (name=%s, path=%s)",
            self.server_name,
            self.endpoint_path,
        )

    def _coerce_value(self, entry: dict):
        kind = str(entry.get("type", "float"))
        if kind == "boolean":
            return bool(entry.get("value", False))
        if kind == "integer":
            return int(entry.get("value", 0))
        if kind == "string":
            return str(entry.get("value", ""))
        return float(entry.get("value", 0.0))

    async def _init_address_space(self) -> None:
        assert self._ua is not None
        self._ua.set_server_name(self.server_name)
        await self._ua.set_application_uri(self.application_uri)
        self._ua.set_security_policy([ua.SecurityPolicyType.NoSecurity])

        idx = await self._ua.register_namespace(self.namespace_uri)
        folder = await self._ua.nodes.objects.add_object(
            idx, str(self.template.get("folder_name", "Plant"))
        )
        if not self._variables:
            var = await folder.add_variable(idx, "Temperature", 25.0)
            await var.set_writable()
            logger.debug("Seeded default OPC UA variable Temperature=25.0")
            return

        live = self._process.values(time.time()) if self._process else {}
        self._driven = []
        for entry in self._variables:
            name = str(entry["name"])
            value = self._coerce_value(entry)
            if name in live and type(live[name]) is type(value):
                # A TwinCAT integer is 32 bits wide (DINT); asyncua would
                # make a Python int 64.
                kind = ua.VariantType.Int32 if isinstance(value, int) and not isinstance(value, bool) else None
                value = live[name]
                var = await folder.add_variable(idx, name, value, varianttype=kind)
                self._driven.append((var, name, kind))
            else:
                var = await folder.add_variable(idx, name, value)
            await var.set_writable()
            logger.debug("Added OPC UA variable %s=%r", name, value)

    async def _run_process(self) -> None:
        """Write the process's variables as the PLC's program would: every
        tick, whatever a client wrote in between."""
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=PROCESS_TICK)
                return
            except asyncio.TimeoutError:
                pass
            now = time.time()
            live = self._process.values(now)
            stamp = datetime.fromtimestamp(now, timezone.utc)
            try:
                for var, name, kind in self._driven:
                    await var.write_value(
                        ua.DataValue(ua.Variant(live[name], kind), SourceTimestamp=stamp, ServerTimestamp=stamp)
                    )
            except Exception:
                logger.exception("OPC UA process variables are no longer written")
                return

    async def _bootstrap_ua(self, host: str, port: int) -> None:
        """Init address space + endpoints for the bound host:port (no listen)."""
        with _quiet_nodeset_load():
            self._ua = Server()
            await self._ua.init()
        endpoint_host = self.template.get("endpoint_host") or host
        endpoint = f"opc.tcp://{endpoint_host}:{port}{self.endpoint_path}"
        self._ua.set_endpoint(endpoint)
        if self.template.get("endpoint_host"):
            # advertise the configured host, neither the client's URL nor the socket address
            self._ua.set_match_discovery_endpoint_url(False)
            self._ua.set_match_discovery_client_ip(False)
        if self.template.get("product_name"):
            self._ua.product_uri = str(self.template.get("product_uri", self.application_uri))
            self._ua.manufacturer_name = str(self.template.get("manufacturer_name", ""))
            self._ua.name = self.server_name
            await self._ua.set_build_info(
                self._ua.product_uri,
                self._ua.manufacturer_name,
                str(self.template["product_name"]),
                str(self.template.get("software_version", "")),
                str(self.template.get("build_number", "")),
                datetime.now(timezone.utc),
            )
        await self._init_address_space()
        await self._ua._setup_server_nodes()
        await self._ua.iserver.start()
        self._ua_started = True
        logger.info("OPC UA address space ready at %s", endpoint)

    async def _shutdown_ua(self) -> None:
        # Bound shutdown so Conpot stop()/test join(0.2) stays responsive;
        # asyncua InternalServer.stop can otherwise take ~1s.
        ua_server = self._ua
        self._ua = None
        started = self._ua_started
        self._ua_started = False
        if ua_server is None or not started:
            return
        try:
            await asyncio.wait_for(ua_server.iserver.stop(), timeout=0.05)
        except asyncio.TimeoutError:
            logger.debug("OPC UA InternalServer stop timed out")
        except Exception:
            logger.exception("Error stopping OPC UA InternalServer")

    async def handle(self, reader, writer):
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        sockname = writer.get_extra_info("sockname") or (self.host, self.port)

        session = conpot_core.get_session(
            "opcua",
            peer[0],
            peer[1],
            sockname[0],
            sockname[1],
        )
        logger.info(
            "New OPC UA connection from %s:%s. (%s)",
            peer[0],
            peer[1],
            session.id,
        )
        session.log_event(event_type="NEW_CONNECTION")

        try:
            if self._ua is None or not self._ua_started:
                logger.warning(
                    "OPC UA stack not ready; closing connection (%s)",
                    session.id,
                )
                return
            await run_opcua_session(
                iserver=self._ua.iserver,
                policies=self._ua._policies,
                limits=self._ua.limits,
                reader=reader,
                writer=writer,
                session=session,
                read_timeout=self.timeout,
                stop_event=self._stop,
            )
        except Exception as exc:
            from conpot.protocols.opcua.session import _is_peer_disconnect

            if _is_peer_disconnect(exc):
                logger.info("OPC UA peer reset. (%s)", session.id)
            else:
                logger.exception("OPC UA session error (%s)", session.id)
        finally:
            logger.info("OPC UA client disconnected. (%s)", session.id)
            session.log_event(event_type="CONNECTION_LOST")

    async def start(self, host, port):
        """Bind TCP, bootstrap asyncua for the real port, then accept clients.

        Endpoint URLs are built after bind so ephemeral ``port=0`` (tests)
        still advertises a correct GetEndpoints URL.
        """
        self.host = host
        self.port = port
        self._stop.clear()
        self._ready.clear()

        client_tasks: set[asyncio.Task] = set()

        async def _on_client(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            task = asyncio.current_task()
            if task is not None:
                client_tasks.add(task)
            peer = writer.get_extra_info("peername")
            try:
                await self.handle(reader, writer)
            except Exception:
                logger.exception("OPCUAServer connection handler crashed for %s", peer)
            finally:
                if task is not None:
                    client_tasks.discard(task)
                try:
                    writer.close()
                except Exception:
                    pass
                try:
                    await writer.wait_closed()
                except (Exception, BaseExceptionGroup):
                    pass

        listener = await asyncio.start_server(
            _on_client, host=host, port=port, reuse_address=True
        )
        bound_host, bound_port = listener.sockets[0].getsockname()[:2]
        _set_listener_addrs(self, bound_host, bound_port)
        # Keep a SimpleNamespace for tests that expect .server.server_port
        if self.server is None:
            self.server = SimpleNamespace(
                server_host=bound_host, server_port=bound_port
            )

        process_task = None
        try:
            await self._bootstrap_ua(bound_host, bound_port)
            logger.info("OPCUAServer listening on %s:%s", bound_host, bound_port)
            if self._driven:
                process_task = asyncio.create_task(self._run_process())
            self._ready.set()
            await self._stop.wait()
        finally:
            if process_task is not None:
                process_task.cancel()
                await asyncio.gather(process_task, return_exceptions=True)
            listener.close()
            await listener.wait_closed()
            for task in list(client_tasks):
                task.cancel()
            if client_tasks:
                await asyncio.gather(*client_tasks, return_exceptions=True)
            await self._shutdown_ua()

    def stop(self):
        self._stop.set()
