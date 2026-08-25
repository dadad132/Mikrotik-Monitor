"""RouterOS device connection and data collection.

Uses the `librouteros` binary-API client, which speaks the same protocol on
RouterOS v6 and v7 — so this layer is version-agnostic.

`Snapshot` is a read-only bundle of everything we fetched in one poll, so the
individual checks never have to talk to the router themselves.
"""
from __future__ import annotations

import logging
import socket
import time

import librouteros
import librouteros.exceptions

log = logging.getLogger(__name__)

# Logical dataset name -> RouterOS menu path.
DATASETS = {
    "resource": ("system", "resource"),
    "identity": ("system", "identity"),
    "routerboard": ("system", "routerboard"),
    "pkg_update": ("system", "package", "update"),
    "route": ("ip", "route"),
    "interface": ("interface",),
    "ip_address": ("ip", "address"),
    "health": ("system", "health"),
    "log": ("log",),
    "history": ("system", "history"),
    "active": ("user", "active"),
    "dhcp_lease": ("ip", "dhcp-server", "lease"),
    "dhcp_client": ("ip", "dhcp-client"),  # WAN-side client (not the lease table above)
    # client-count sources (any may be absent on a given board -> tolerated)
    "wireless_reg": ("interface", "wireless", "registration-table"),
    "wifi_reg": ("interface", "wifi", "registration-table"),  # wifiwave2 (v7)
    "arp": ("ip", "arp"),
    "hotspot_active": ("ip", "hotspot", "active"),
    # Bridge MAC table — most reliable "currently sending traffic" signal.
    # Entries are learned per-frame and aged out (default 5 min) when traffic
    # stops, so this reflects real-time layer-2 activity regardless of DHCP or
    # ARP state.
    "bridge_host": ("interface", "bridge", "host"),
    # per-client usage sources
    "queue_simple": ("queue", "simple"),
    "kid_control": ("ip", "kid-control", "device"),
}


# Datasets whose VALUE is distorted by the act of collecting the others, so
# they have to be read before mikromon has put any load on the box.
#
# /system/resource carries cpu-load, which RouterOS samples over roughly the
# last second. Pulling /log, /system/history, /ip/arp and /interface/bridge/host
# over the binary API is real work for the router's own CPU — on a small board
# it is easily tens of percent while it lasts. Read after those, cpu-load
# reports mikromon's own polling rather than the router's idle load, which is
# exactly the "mikromon says 76%, Winbox says 5%" contradiction: both are
# right, they are just measuring different moments.
#
# This used to be whatever order a set happened to iterate in. Python
# randomises string hashing per process, so which position /system/resource
# landed in was decided afresh at every restart and then stayed put for the
# life of that process — a device could read high for weeks, get "fixed" by an
# unrelated restart, and come back later. Fetch order is now fixed and
# cheapest-first, so the reading means the same thing on every run.
_FETCH_FIRST = ("resource", "health")

# Big, slow menus — deliberately last, after every measurement has been taken.
_FETCH_LAST = ("log", "history", "dhcp_lease", "arp", "bridge_host",
               "wireless_reg", "wifi_reg", "hotspot_active", "queue_simple",
               "kid_control")


def _fetch_order(datasets):
    """Deterministic collection order: measurements first, bulk menus last,
    everything else in a stable middle. Accepts any iterable (the engine
    passes a set) and never drops or duplicates a name."""
    wanted = set(datasets)
    first = [n for n in _FETCH_FIRST if n in wanted]
    last = [n for n in _FETCH_LAST if n in wanted]
    middle = sorted(wanted - set(first) - set(last))
    return first + middle + last


# How many times the reachability probe tries before reporting a device
# down, and the shortest each attempt may be given. The attempts share the
# caller's timeout budget rather than multiplying it -- see Device.reachable().
_REACH_ATTEMPTS = 2
_REACH_MIN_TIMEOUT = 1.0


class DeviceError(Exception):
    """Raised when we cannot talk to a device."""


class Snapshot:
    """Holds the rows fetched from each requested dataset for one poll."""

    def __init__(self, handle: "Device | None" = None):
        self.data: dict[str, list] = {}
        self.errors: dict[str, str] = {}
        self.handle = handle  # live Device, for optional active probes (ping)

    def rows(self, name: str) -> list:
        return self.data.get(name, [])

    def first(self, name: str) -> dict:
        rows = self.data.get(name) or []
        return rows[0] if rows else {}

    @property
    def resource(self) -> dict:
        return self.first("resource")


class Device:
    def __init__(self, cfg):
        self.cfg = cfg
        self.api = None
        # Milliseconds for the last successful reachability probe; None when
        # the last one failed or none has run yet.
        self.last_probe_ms = None

    @property
    def name(self) -> str:
        return self.cfg.name

    # ----- connectivity -----------------------------------------------------
    def reachable(self, timeout: float | None = None) -> bool:
        """Fast TCP check against the API port. No auth, no root needed.

        Also times the handshake into `last_probe_ms`. That round trip is
        already being paid for on every poll, so measuring it costs nothing —
        and over the WireGuard tunnel it is a fair proxy for how far away a
        router feels, which is exactly what a fleet view wants to show. It is
        the SERVER-to-router path, not the router's own internet latency;
        those are different numbers and only this one is free."""
        timeout = timeout if timeout is not None else min(self.cfg.timeout, 5)
        # Tried twice before giving up. These routers are reached across a
        # WireGuard tunnel, so the probe rides on UDP that can and does drop
        # the occasional packet -- and a lost SYN is indistinguishable from a
        # dead router if you only ask once.
        #
        # The attempts SPLIT the existing budget rather than adding to it: two
        # tries of half the timeout, not two of the whole one. Retrying was
        # first written the naive way and immediately doubled how long an
        # unreachable device ties the caller up, which matters -- a poll cycle
        # and several web handlers walk whole fleets, and the devices that are
        # down are exactly the slow ones. A floor keeps each attempt sane if
        # someone configures a very short timeout.
        per_try = max(_REACH_MIN_TIMEOUT, timeout / _REACH_ATTEMPTS)
        for attempt in range(_REACH_ATTEMPTS):
            started = time.monotonic()
            try:
                with socket.create_connection(
                    (self.cfg.host, self.cfg.api_port), timeout=per_try
                ):
                    self.last_probe_ms = round(
                        (time.monotonic() - started) * 1000, 1)
                    return True
            except OSError:
                if attempt + 1 < _REACH_ATTEMPTS:
                    continue
        # Deliberately not recorded: a failed connect times how long the OS
        # took to give up, which says nothing about latency and would drag a
        # fleet average around by whatever the timeout happens to be set to.
        self.last_probe_ms = None
        return False

    def connect(self):
        if self.api is not None:
            return self.api
        params = dict(
            username=self.cfg.username,
            password=self.cfg.password,
            host=self.cfg.host,
            port=self.cfg.api_port,
            timeout=self.cfg.timeout,
        )
        if self.cfg.use_ssl:
            import ssl

            ctx = ssl.create_default_context()
            if not self.cfg.verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            params["ssl_wrapper"] = ctx.wrap_socket
        try:
            self.api = librouteros.connect(**params)
        except librouteros.exceptions.TrapError as exc:
            raise DeviceError(f"Authentication/permission error: {exc}") from exc
        except (OSError, librouteros.exceptions.LibRouterosError) as exc:
            raise DeviceError(f"Connection failed: {exc}") from exc
        return self.api

    def close(self):
        if self.api is not None:
            try:
                self.api.close()
            except Exception:  # noqa: BLE001 — best-effort teardown
                pass
            self.api = None

    # ----- data collection --------------------------------------------------
    def fetch(self, datasets) -> Snapshot:
        """Fetch the requested datasets in one pass. Missing menus are tolerated.

        A menu that does not exist on a given board (e.g. /system/health on a
        CHR, or /ip/dhcp-server/lease with no DHCP server) is recorded as an
        error and returns no rows, rather than aborting the whole poll.

        Collected in a fixed order (see _fetch_order): the datasets whose
        values the collection itself would distort are read first, the
        expensive bulk menus last.
        """
        if self.api is None:
            self.connect()
        snap = Snapshot(handle=self)
        for name in _fetch_order(datasets):
            path = DATASETS.get(name)
            if path is None:
                continue
            try:
                snap.data[name] = list(self.api.path(*path))
            except Exception as exc:  # noqa: BLE001 — per-dataset isolation
                snap.data[name] = []
                snap.errors[name] = str(exc)
                log.debug("%s: dataset %s unavailable: %s", self.name, name, exc)
        return snap

    def run_command(self, path, cmd: str, **params) -> bool:
        """Fire a non-CRUD RouterOS command (e.g. check-for-updates) and say
        whether it was accepted. Best-effort by design: the monitor side is
        read-only in spirit, so anything that fails -- an older install whose
        monitor user genuinely lacks the rights, a menu that does not exist on
        this board -- degrades to False rather than disturbing the poll."""
        if self.api is None:
            return False
        try:
            list(self.api.path(*path)(cmd, **params))
            return True
        except Exception:  # noqa: BLE001 — never let a nicety break a poll
            log.debug("%s: command %s/%s not accepted", self.name,
                      "/".join(path), cmd)
            return False

    def ping(self, address: str, count: int = 3):
        """Best-effort ICMP ping FROM the router. Returns packet-loss % or None.

        Used only to enrich the 'why' of an internet-down alert. Any failure
        (older API, permissions, command shape) degrades silently to None.
        """
        from .util import as_int

        try:
            rows = list(self.api.path("ping")(
                "", address=str(address), count=str(count)
            ))
        except Exception:  # noqa: BLE001
            return None
        if not rows:
            return None
        # The final streamed row carries the running summary including loss %.
        last = rows[-1]
        if "packet-loss" in last:
            return as_int(last["packet-loss"])
        received = as_int(last.get("received"))
        return int(round((1 - received / count) * 100)) if count else None
