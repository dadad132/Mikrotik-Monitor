"""Device-count anomaly: alert when an unusual number of clients are connected.

Source guide (best → least accurate for "currently connected"):

  bridge   — Bridge MAC table (/interface bridge host).  RouterOS learns a
              MAC entry the instant any frame arrives from a device and ages it
              out (default 5 min) when traffic stops.  Works for wired AND
              wireless clients (when the wireless interface is a bridge member),
              requires no DHCP or ARP, and is independent of IP version.
              Best default for most MikroTik setups.

  wireless — Wireless registration table.  Entries exist only while the
              client is associated; drop immediately on disconnect.  Use this
              in addition to bridge when wireless clients are NOT bridge members
              (e.g. routed WiFi / CAPsMAN with separate IP ranges).

  arp      — Dynamic+complete ARP entries.  Expire within seconds of last
              activity.  Good fallback when bridging is not used.

  dhcp     — DHCP bound leases cross-referenced with dynamic ARP.  Leases
              stay "bound" for the full lease time after disconnect, so we
              only count leases whose MAC also appears in dynamic ARP.  Falls
              back to ARP-only when there is no local DHCP server.

  hotspot  — Active hotspot sessions.
"""
from __future__ import annotations

from ..alert import Severity
from ..baseline import Baseline, is_high, sigma_str
from ..util import as_bool
from .base import Check


def _arp_dynamic_macs(snap) -> set[str]:
    """Dynamic+complete ARP MACs — exclude static entries that never expire."""
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
    def datasets(cls, device_cfg) -> set:
        srcs = set(device_cfg.client_count_sources)
        ds = set()
        if "bridge" in srcs:
            ds.add("bridge_host")
        if "dhcp" in srcs:
            ds.add("dhcp_lease")
            ds.add("arp")
        if "wireless" in srcs:
            ds.update({"wireless_reg", "wifi_reg"})
        if "arp" in srcs:
            ds.add("arp")
        if "hotspot" in srcs:
            ds.add("hotspot_active")
        return ds or {"bridge_host"}

    def run(self, snap, dev, ctx) -> None:
        srcs = set(dev.client_count_sources)
        macs: set[str] = set()
        breakdown = {}

        if "bridge" in srcs:
            # Local=yes entries are the bridge's own MAC addresses (the router
            # itself).  We want only client MACs learned from external ports.
            bmacs = {
                str(r.get("mac-address", "")).upper()
                for r in snap.rows("bridge_host")
                if r.get("mac-address")
                and not as_bool(r.get("local", False))
            }
            macs |= bmacs
            breakdown["bridge"] = len(bmacs)

        if "dhcp" in srcs:
            arp_dynamic = _arp_dynamic_macs(snap)
            dhcp_bound: set[str] = set()
            for lease in snap.rows("dhcp_lease"):
                status = str(lease.get("status", "")).lower()
                if status in ("waiting", "expired", "offered"):
                    continue
                mac = str(lease.get("mac-address", "")).upper()
                if mac:
                    dhcp_bound.add(mac)

            if dhcp_bound and arp_dynamic:
                counted = dhcp_bound & arp_dynamic
            elif dhcp_bound:
                counted = dhcp_bound
            else:
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
            bl.update(count, ctx.now)

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
