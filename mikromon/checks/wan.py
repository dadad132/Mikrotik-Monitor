"""WAN failover and internet-down detection.

Strategy (works for the standard MikroTik failover pattern of two default
routes with different `distance` values, driven by check-gateway or recursive
routing):

  * Look at every default route (dst-address 0.0.0.0/0).
  * The *preferred* path is the one with the lowest distance.
  * The *current* path is the active default route with the lowest distance.
  * If no default route is active            -> INTERNET DOWN (all WANs failed).
  * If the current path is not the preferred -> FAILOVER (running on backup).

No special config is required, but naming the uplinks under `wan:` in the
config produces friendlier messages and lets you pin which link is primary.
"""
from __future__ import annotations

import re

from ..alert import Severity
from ..util import as_bool, as_int
from .base import Check

_DEFAULT_DST = ("0.0.0.0/0", "0.0.0.0/0%main")


def _is_default(route: dict) -> bool:
    dst = str(route.get("dst-address", ""))
    return dst in _DEFAULT_DST or dst.startswith("0.0.0.0/0")


def _is_active(route: dict) -> bool:
    if as_bool(route.get("disabled")):
        return False
    if "active" in route:
        return as_bool(route["active"])
    if "inactive" in route:
        return not as_bool(route["inactive"])
    # No explicit flag: treat a reachable gateway as active.
    return "unreachable" not in str(route.get("gateway-status", "")).lower()


def _iface_of(route: dict) -> str:
    """Best-effort interface name a route exits through."""
    m = re.search(r"via\s+(\S+)", str(route.get("gateway-status", "")))
    if m:
        return m.group(1)
    return str(route.get("immediate-gw", "") or route.get("gateway", ""))


def _label(route: dict) -> str:
    gw = str(route.get("gateway", "")) or "?"
    iface = _iface_of(route)
    dist = as_int(route.get("distance"), 1)
    if iface and iface != gw:
        return f"{gw} via {iface} (distance {dist})"
    return f"{gw} (distance {dist})"


def _matches_endpoint(route: dict, ep) -> bool:
    if ep.gateway and str(route.get("gateway", "")) == ep.gateway:
        return True
    if ep.interface and _iface_of(route) == ep.interface:
        return True
    return False


class WanCheck(Check):
    flags = ("wan_failover", "internet_down")
    requires = ("route",)
    name = "wan"

    def run(self, snap, dev, ctx) -> None:
        defaults = [r for r in snap.rows("route") if _is_default(r)]
        want_failover = dev.check_enabled("wan_failover")
        want_down = dev.check_enabled("internet_down")

        if not defaults:
            # Nothing routes to the internet at all.
            if want_down:
                ctx.transition(
                    "internet_down", healthy=False, severity=Severity.CRITICAL,
                    title="Internet DOWN — no default route present",
                    cause="The router has no default (0.0.0.0/0) route at all. "
                          "Both/all WAN uplinks appear to be unconfigured or down.",
                    recovery_title="Internet restored",
                )
            return

        active = [r for r in defaults if _is_active(r)]
        by_distance = lambda r: as_int(r.get("distance"), 1)

        # ---- internet down: no active default route -----------------------
        if want_down:
            down = not active
            cause = ""
            facts = {}
            if down:
                statuses = [f"{r.get('gateway', '?')}: "
                            f"{r.get('gateway-status', 'no status')}"
                            for r in sorted(defaults, key=by_distance)]
                cause = "All WAN gateways are unreachable — " + "; ".join(statuses)
                loss = self._probe(dev, snap)
                if loss is not None:
                    facts["ping_packet_loss_pct"] = loss
                    cause += f". Active ping test from router: {loss}% packet loss."
            ctx.transition(
                "internet_down", healthy=not down, severity=Severity.CRITICAL,
                title="Internet DOWN — all WAN uplinks unreachable",
                cause=cause, facts=facts,
                recovery_title="Internet restored — a WAN uplink is reachable again",
            )
            if down:
                return  # failover is meaningless while fully down

        if not active:
            return

        # ---- failover: are we on the preferred path? ----------------------
        if not want_failover:
            return

        current = min(active, key=by_distance)
        if dev.wan.configured:
            primary_routes = [r for r in defaults
                              if _matches_endpoint(r, dev.wan.primary)]
            preferred = (min(primary_routes, key=by_distance)
                         if primary_routes else min(defaults, key=by_distance))
            on_backup = not _matches_endpoint(current, dev.wan.primary)
        else:
            preferred = min(defaults, key=by_distance)
            on_backup = by_distance(current) > by_distance(preferred)

        cause = ""
        if on_backup:
            prim_status = str(preferred.get("gateway-status", "")) or "inactive"
            cause = (f"Primary uplink {_label(preferred)} is not carrying traffic "
                     f"({prim_status}). Traffic is now flowing via backup "
                     f"{_label(current)}.")
        ctx.transition(
            "wan_failover", healthy=not on_backup, severity=Severity.WARNING,
            title=f"WAN failover — now on BACKUP uplink ({_iface_of(current) or current.get('gateway')})",
            detail=f"Active default route: {_label(current)}.",
            cause=cause,
            facts={"current": _label(current), "preferred": _label(preferred)},
            recovery_title="WAN restored — back on PRIMARY uplink",
            recovery_detail=f"Traffic is flowing via {_label(current)} again.",
        )

    @staticmethod
    def _probe(dev, snap):
        """Optional active ping enrichment for internet-down alerts."""
        targets = getattr(dev.wan, "ping_targets", None)
        if not targets or snap.handle is None:
            return None
        for target in targets:
            loss = snap.handle.ping(target, count=3)
            if loss is not None:
                return loss
        return None
