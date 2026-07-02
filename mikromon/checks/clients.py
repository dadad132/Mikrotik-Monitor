"""Device-count anomaly: alert when an unusual number of clients are connected.

Counts the number of *distinct* devices (by MAC) currently on the network,
combining the sources you choose (DHCP bound leases, wireless/wifi
registrations, ARP, hotspot). A learned per-time baseline decides what's
"normal", so a quiet Sunday and a busy Tuesday afternoon are judged separately.

Source guidance:
  wireless  — clients currently associated with the router's WiFi.  Most
              accurate for wireless networks; entries disappear the instant a
              client disconnects.
  arp       — dynamic+complete ARP entries.  The router learns these from any
              client that recently exchanged packets with the gateway; they
              expire in seconds when the device goes offline.  Best choice for
              wired clients.
  dhcp      — DHCP bound leases cross-referenced with dynamic ARP.  A lease
              stays "bound" for the full lease time after a device disconnects,
              so we only count leases whose MAC also appears in the dynamic ARP
              table.  Falls back to ARP alone when no local DHCP server is
              running (ARP still reflects who is actually on the wire).
  hotspot   — active hotspot sessions.
"""
from __future__ import annotations

from ..alert import Severity
from ..baseline import Baseline, is_high, sigma_str
from ..util import as_bool
from .base import Check


def _arp_dynamic_macs(snap) -> set[str]:
    """MACs from dynamic+complete ARP entries only.

    Dynamic entries are learned from traffic and expire within seconds when a
    device goes offline.  Static (manually-added) entries never expire and
    must be excluded or they inflate the count with offline devices.
    """
    return {
        str(r.get("mac-address", "")).upper()
        for r in snap.rows("arp")
        if r.get("mac-address")
        and as_bool(r.get("complete", True))
        and as_bool(r.get("dynamic", True))
    }


class ClientCountCheck(Check):
    flags = ("client_count",)
    requires = ("dhcp_lease",)
    name = "client_count"

    @classmethod
    def datasets(cls, cfg) -> set:
        srcs = set(cfg.client_count_sources)
        ds = set()
        if "dhcp" in srcs:
            ds.add("dhcp_lease")
            # Always fetch ARP alongside DHCP for cross-referencing.
            ds.add("arp")
        if "wireless" in srcs:
            ds.update({"wireless_reg", "wifi_reg"})
        if "arp" in srcs:
            ds.add("arp")
        if "hotspot" in srcs:
            ds.add("hotspot_active")
        return ds or {"dhcp_lease"}

    def run(self, snap, dev, ctx) -> None:
        srcs = set(dev.client_count_sources)
        macs: set[str] = set()
        breakdown = {}

        if "dhcp" in srcs:
            # Dynamic ARP = devices that have recently exchanged packets with
            # the router.  These entries expire in seconds after a device goes
            # offline, making them the best "currently reachable" signal.
            arp_dynamic = _arp_dynamic_macs(snap)

            # Non-stale DHCP leases.  "bound" can persist for the full lease
            # duration after a device disconnects, so we use it as a candidate
            # list only, not as the truth.
            dhcp_bound: set[str] = set()
            for lease in snap.rows("dhcp_lease"):
                status = str(lease.get("status", "")).lower()
                if status in ("waiting", "expired", "offered"):
                    continue
                mac = str(lease.get("mac-address", "")).upper()
                if mac:
                    dhcp_bound.add(mac)

            if dhcp_bound and arp_dynamic:
                # Intersection: device must have both a valid lease AND a live
                # ARP entry.  This drops stale-bound devices that disconnected
                # mid-lease.
                counted = dhcp_bound & arp_dynamic
            elif dhcp_bound:
                # ARP data unavailable (fetch error / empty table) — fall back
                # to lease-based counting.
                counted = dhcp_bound
            else:
                # No local DHCP server (relay, upstream DHCP, or static IPs).
                # Count dynamic ARP entries directly — they still reflect who
                # is on the wire even without a local DHCP server.
                counted = arp_dynamic

            macs |= counted
            breakdown["dhcp"] = len(counted)

        if "wireless" in srcs:
            wmacs = {str(r.get("mac-address", "")).upper()
                     for r in (snap.rows("wireless_reg") + snap.rows("wifi_reg"))
                     if r.get("mac-address")}
            macs |= wmacs
            breakdown["wifi"] = len(wmacs)

        if "arp" in srcs:
            # Explicit ARP source: dynamic+complete only — same reasoning as
            # above; static entries do not reflect current connectivity.
            amacs = _arp_dynamic_macs(snap)
            macs |= amacs
            breakdown["arp"] = len(amacs)

        if "hotspot" in srcs:
            hmacs = {str(r.get("mac-address", "")).upper()
                     for r in snap.rows("hotspot_active") if r.get("mac-address")}
            macs |= hmacs
            breakdown["hotspot"] = len(hmacs)

        count = len(macs)
        ctx.sample("client_count", count)
        bl = Baseline(ctx.memory("client_count").setdefault("bl", {}),
                      alpha=dev.th("baseline_alpha"),
                      warmup=dev.th("baseline_warmup"),
                      scheme=dev.th("baseline_buckets"))
        s = bl.score(count, ctx.now)
        high = is_high(s, count, floor=dev.th("client_min_count"),
                       min_ratio=dev.th("client_count_ratio"),
                       z=dev.th("baseline_z"))
        if not high:
            bl.update(count, ctx.now)  # only learn from normal samples

        parts = ", ".join(f"{k}:{v}" for k, v in breakdown.items())
        pct = int((count - s["mean"]) / s["mean"] * 100) if s["mean"] else 0
        ctx.transition(
            "client_count", healthy=not high, severity=Severity.WARNING,
            title=f"Unusually many devices connected: {count}",
            detail=f"Sources — {parts}.",
            cause=f"Typical for this time is ~{s['mean']:.0f} device(s); now "
                  f"{count} (+{pct}%, {sigma_str(s['z'])} normal). Could be a new "
                  f"batch of devices, a rogue AP, or unexpected guests.",
            facts={"count": count, "typical": round(s["mean"], 1),
                   "breakdown": breakdown},
            recovery_title=f"Device count back to normal ({count})",
        )
