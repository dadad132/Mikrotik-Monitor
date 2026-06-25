"""RouterOS device connection and data collection.

Uses the `librouteros` binary-API client, which speaks the same protocol on
RouterOS v6 and v7 — so this layer is version-agnostic.

`Snapshot` is a read-only bundle of everything we fetched in one poll, so the
individual checks never have to talk to the router themselves.
"""
from __future__ import annotations

import logging
import socket

import librouteros

log = logging.getLogger(__name__)

# Logical dataset name -> RouterOS menu path.
DATASETS = {
    "resource": ("system", "resource"),
    "identity": ("system", "identity"),
    "routerboard": ("system", "routerboard"),
    "route": ("ip", "route"),
    "interface": ("interface",),
    "ip_address": ("ip", "address"),
    "health": ("system", "health"),
    "log": ("log",),
    "history": ("system", "history"),
    "active": ("user", "active"),
    "dhcp_lease": ("ip", "dhcp-server", "lease"),
    # client-count sources (any may be absent on a given board -> tolerated)
    "wireless_reg": ("interface", "wireless", "registration-table"),
    "wifi_reg": ("interface", "wifi", "registration-table"),  # wifiwave2 (v7)
    "arp": ("ip", "arp"),
    "hotspot_active": ("ip", "hotspot", "active"),
    # per-client usage sources
    "queue_simple": ("queue", "simple"),
    "kid_control": ("ip", "kid-control", "device"),
}


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

    @property
    def name(self) -> str:
        return self.cfg.name

    # ----- connectivity -----------------------------------------------------
    def reachable(self, timeout: float | None = None) -> bool:
        """Fast TCP check against the API port. No auth, no root needed."""
        timeout = timeout if timeout is not None else min(self.cfg.timeout, 5)
        try:
            with socket.create_connection(
                (self.cfg.host, self.cfg.api_port), timeout=timeout
            ):
                return True
        except OSError:
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
        """
        if self.api is None:
            self.connect()
        snap = Snapshot(handle=self)
        for name in datasets:
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
