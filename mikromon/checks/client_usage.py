"""Per-client 'top-talker' detection.

Attributes bytes to individual clients and flags one that is using far more
than it normally does. Attribution needs the router to already account per
client, via either:
  * Simple Queues  (/queue/simple — one queue per client/target), or
  * Kid Control    (/ip/kid-control/device).

If neither is configured there's nothing to attribute and the check stays
quiet (see the README for how to enable a source).
"""
from __future__ import annotations

from ..alert import Severity
from ..baseline import Baseline, is_high, rate_bps, sigma_str
from ..util import as_int, human_bps
from .base import Check

_PRUNE_AFTER = 86400  # forget a client not seen for a day


def _sum_pair(value) -> int:
    """Parse a RouterOS 'up/down' byte field like '12345/67890' to a total."""
    if value is None:
        return 0
    text = str(value)
    if "/" in text:
        return sum(as_int(p) for p in text.split("/")[:2])
    return as_int(text)


def _gather(snap) -> dict:
    """label -> cumulative total bytes, merged across available sources."""
    clients: dict[str, int] = {}
    for q in snap.rows("queue_simple"):
        label = str(q.get("name") or q.get("target") or "").split(",")[0]
        if label:
            clients[label] = clients.get(label, 0) + _sum_pair(q.get("bytes"))
    for k in snap.rows("kid_control"):
        label = str(k.get("name") or k.get("mac-address")
                    or k.get("ip-address") or "")
        if label:
            clients[label] = (clients.get(label, 0)
                              + as_int(k.get("bytes-up"))
                              + as_int(k.get("bytes-down")))
    return clients


class ClientUsageCheck(Check):
    flags = ("client_usage",)
    requires = ("queue_simple", "kid_control")
    name = "client_usage"

    def run(self, snap, dev, ctx) -> None:
        clients = _gather(snap)
        mem = ctx.memory("client_usage")
        tracked = mem.setdefault("clients", {})  # label -> {total, ts, seen, bl}
        floor = as_int(dev.th("client_floor_mbit")) * 1_000_000
        ratio = dev.th("client_usage_ratio")
        zth = dev.th("baseline_z")

        for label, total in clients.items():
            st = tracked.setdefault(label, {"total": None, "ts": 0, "bl": {}})
            prev_total, prev_ts = st.get("total"), st.get("ts", 0)
            st["total"], st["ts"], st["seen"] = total, ctx.now, ctx.now

            bps = rate_bps(prev_total, total, ctx.now - prev_ts)
            if bps is None:
                continue
            # Per-client baseline is time-agnostic (global) to stay compact.
            bl = Baseline(st["bl"], alpha=dev.th("baseline_alpha"),
                          warmup=dev.th("baseline_warmup"), scheme="global")
            s = bl.score(bps, ctx.now)
            high = is_high(s, bps, floor=floor, min_ratio=ratio, z=zth)
            if not high:
                bl.update(bps, ctx.now)
            ctx.transition(
                f"client_usage:{label}", healthy=not high,
                severity=Severity.WARNING,
                title=f"Top-talker: '{label}' using {human_bps(bps)}",
                cause=f"This client normally uses ~{human_bps(s['mean'])}; now "
                      f"{human_bps(bps)} ({sigma_str(s['z'])} its own normal). "
                      f"Check for a large download/upload, backup, or malware.",
                facts={"client": label, "bps": int(bps),
                       "typical_bps": int(s["mean"])},
                recovery_title=f"'{label}' usage back to normal ({human_bps(bps)})",
            )

        # Prune clients we haven't seen for a while (keeps state small).
        for label in list(tracked):
            if ctx.now - tracked[label].get("seen", 0) > _PRUNE_AFTER:
                del tracked[label]
