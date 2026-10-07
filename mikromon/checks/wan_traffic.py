"""WAN throughput / data-usage anomaly.

Reads each WAN interface's cumulative rx/tx byte counters, turns the change
between polls into a bits-per-second rate, and compares it to a learned
per-time baseline. Sustained, well-above-normal throughput (e.g. a link pinned
near capacity, or an unexpected upload) raises an alert; it clears when the rate
returns to normal.
"""
from __future__ import annotations

from ..alert import Severity
from ..baseline import (is_high, is_low, learn, make_baseline, rate_bps,
                        sigma_str)
from ..util import as_bool, as_int, human_bps
from .base import Check

_WAN_AUTO_TYPES = ("ether", "lte", "sfp", "vdsl", "pppoe-out", "ppp-out", "gpon")
_DIR_LABEL = {"rx": "inbound (download)", "tx": "outbound (upload)"}


def _norm_iface(s) -> str:
    """Case/whitespace-insensitive interface name — matches the helper of the
    same name in push/features.py and checks/wan.py. The WAN uplinks editor's
    typed Interface text can differ in case from the router's own interface
    name for the same link; an exact == match silently (no error) drops that
    link's throughput samples every poll, leaving its graph blank."""
    return str(s or "").strip().lower()


def _wan_interfaces(snap, dev) -> list:
    if dev.traffic_interfaces:
        return list(dev.traffic_interfaces)
    wan = [e.interface for e in dev.wan.links if e.interface]
    if wan:
        return wan
    if dev.monitor_interfaces:
        return list(dev.monitor_interfaces)
    return [str(i.get("name", "")) for i in snap.rows("interface")
            if not as_bool(i.get("disabled"))
            and any(str(i.get("type", "")).startswith(t) for t in _WAN_AUTO_TYPES)]


class WanTrafficCheck(Check):
    flags = ("wan_traffic",)
    requires = ("interface",)
    name = "wan_traffic"

    def run(self, snap, dev, ctx) -> None:
        targets = _wan_interfaces(snap, dev)
        if not targets:
            return
        mem = ctx.memory("wan_traffic")
        last = mem.setdefault("last", {})       # name -> {rx, tx, ts}
        bl_store = mem.setdefault("bl", {})      # "name|dir" -> buckets
        floor = as_int(dev.th("traffic_floor_mbit")) * 1_000_000
        ratio = dev.th("traffic_ratio")
        zth = dev.th("baseline_z")
        low_min = float(dev.th("traffic_low_min_mbit") or 0) * 1_000_000
        low_ratio = float(dev.th("traffic_low_ratio") or 0)
        accept = dev.th("baseline_accept_hours") * 3600
        # While the router is on a backup line (or has none at all) the main
        # line carrying nothing is the failover alert's news, not this one's.
        conds = (ctx.store.data.get("devices", {}).get(ctx.device, {})
                 .get("conditions", {}))
        line_trouble = any(conds.get(k, {}).get("status") == "problem"
                           for k in ("wan_failover", "internet_down"))

        by_name = {_norm_iface(i.get("name", "")): i for i in snap.rows("interface")}
        for name in targets:
            iface = by_name.get(_norm_iface(name))
            if iface is None:
                continue
            rx, tx = as_int(iface.get("rx-byte")), as_int(iface.get("tx-byte"))
            prev = last.get(name)
            last[name] = {"rx": rx, "tx": tx, "ts": ctx.now}
            if not prev:
                continue
            dt = ctx.now - prev["ts"]
            for direction, cur, old in (("rx", rx, prev["rx"]),
                                        ("tx", tx, prev["tx"])):
                bps = rate_bps(old, cur, dt)
                if bps is None:
                    continue
                ctx.sample(f"{direction}_bps", bps, label=name)
                bl = make_baseline(
                    bl_store.setdefault(f"{name}|{direction}", {}), dev)
                s = bl.score(bps, ctx.now)
                high = is_high(s, bps, floor=floor, min_ratio=ratio, z=zth)
                low = (direction == "rx" and not line_trouble and low_min > 0
                       and is_low(s, bps, min_typical=low_min,
                                  max_ratio=low_ratio, z=zth))
                learn(bl, bps, ctx.now, high or low, mem,
                      f"{name}|{direction}", accept)
                ctx.transition(
                    f"wan_traffic:{name}:{direction}", healthy=not high,
                    severity=Severity.WARNING,
                    title=f"High {_DIR_LABEL[direction]} traffic on {name}: "
                          f"{human_bps(bps)}",
                    cause=f"Typical for this time is ~{human_bps(s['mean'])}; now "
                          f"{human_bps(bps)} ({sigma_str(s['z'])} normal). Possible "
                          f"large transfer, backup job, streaming, or abuse.",
                    facts={"bps": int(bps), "typical_bps": int(s["mean"]),
                           "interface": name, "direction": direction},
                    recovery_title=f"{name} {direction} traffic back to normal "
                                   f"({human_bps(bps)})",
                )
                if direction != "rx":
                    continue
                # Held for ten polls: a quiet few minutes is not a fault, a
                # line that has carried nearly nothing for ten minutes in the
                # middle of a working morning is.
                ctx.transition(
                    f"wan_traffic_low:{name}", healthy=not low,
                    severity=Severity.WARNING,
                    title=f"Traffic on {name} has nearly stopped: "
                          f"{human_bps(bps)}",
                    cause=f"Typical download for this time is "
                          f"~{human_bps(s['mean'])}; now {human_bps(bps)}. The "
                          f"line is up, so users may have no working internet "
                          f"anyway: DNS failing, an upstream filter, or the "
                          f"ISP passing nothing beyond its own network.",
                    facts={"bps": int(bps), "typical_bps": int(s["mean"]),
                           "interface": name},
                    recovery_title=f"Traffic on {name} back to normal "
                                   f"({human_bps(bps)})",
                    confirm=10,
                )
