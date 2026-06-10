"""Device-count anomaly: alert when an unusual number of clients are connected.

Counts the number of *distinct* devices (by MAC) currently on the network,
combining the sources you choose (DHCP bound leases, wireless/wifi
registrations, ARP, hotspot). A learned per-time baseline decides what's
"normal", so a quiet Sunday and a busy Tuesday afternoon are judged separately.
"""
from __future__ import annotations

from ..alert import Severity
from ..baseline import Baseline, is_high, sigma_str
from ..util import as_bool
from .base import Check


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
            n = 0
            for lease in snap.rows("dhcp_lease"):
                bound = (str(lease.get("status", "")) == "bound"
                         or bool(lease.get("active-address")))
                mac = str(lease.get("mac-address", "")).upper()
                if bound and mac:
                    macs.add(mac)
                    n += 1
            breakdown["dhcp"] = n
        if "wireless" in srcs:
            wmacs = {str(r.get("mac-address", "")).upper()
                     for r in (snap.rows("wireless_reg") + snap.rows("wifi_reg"))
                     if r.get("mac-address")}
            macs |= wmacs
            breakdown["wifi"] = len(wmacs)
        if "arp" in srcs:
            amacs = {str(r.get("mac-address", "")).upper()
                     for r in snap.rows("arp")
                     if r.get("mac-address") and as_bool(r.get("complete", True))}
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
