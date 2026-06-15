"""WAN throughput / data-usage anomaly.

Reads each WAN interface's cumulative rx/tx byte counters, turns the change
between polls into a bits-per-second rate, and compares it to a learned
per-time baseline. Sustained, well-above-normal throughput (e.g. a link pinned
near capacity, or an unexpected upload) raises an alert; it clears when the rate
returns to normal.
"""
from __future__ import annotations

from ..alert import Severity
from ..baseline import Baseline, is_high, rate_bps, sigma_str
from ..util import as_bool, as_int, human_bps
from .base import Check

_WAN_AUTO_TYPES = ("ether", "lte", "sfp", "vdsl", "pppoe-out", "ppp-out", "gpon")
_DIR_LABEL = {"rx": "inbound (download)", "tx": "outbound (upload)"}


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

        by_name = {str(i.get("name", "")): i for i in snap.rows("interface")}
        for name in targets:
            iface = by_name.get(name)
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
                bl = Baseline(bl_store.setdefault(f"{name}|{direction}", {}),
                              alpha=dev.th("baseline_alpha"),
                              warmup=dev.th("baseline_warmup"),
                              scheme=dev.th("baseline_buckets"))
                s = bl.score(bps, ctx.now)
                high = is_high(s, bps, floor=floor, min_ratio=ratio, z=zth)
                if not high:
                    bl.update(bps, ctx.now)
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
