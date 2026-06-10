"""New / unknown DHCP client detection.

Tracks the set of MAC addresses that have taken a lease. The first poll seeds
the known set silently; after that, a never-before-seen MAC raises an alert.
Off by default (set `dhcp_new_clients: true` per device) since it is chatty on
guest / high-churn networks.
"""
from __future__ import annotations

from ..alert import Severity
from ..util import as_bool
from .base import Check


class DhcpCheck(Check):
    flags = ("dhcp_new_clients",)
    requires = ("dhcp_lease",)
    name = "dhcp"

    def run(self, snap, dev, ctx) -> None:
        mem = ctx.memory("dhcp")
        seeding = not mem.get("initialized")
        known = set(mem.get("known_macs", []))

        for lease in snap.rows("dhcp_lease"):
            mac = str(lease.get("mac-address", "")).upper()
            if not mac:
                continue
            if mac in known:
                continue
            known.add(mac)
            if seeding:
                continue
            ip = str(lease.get("address", ""))
            host = str(lease.get("host-name", "") or lease.get("comment", ""))
            static = as_bool(lease.get("dynamic")) is False
            ctx.event(
                f"dhcp_new:{mac}", Severity.INFO,
                f"New DHCP client: {host or mac}",
                detail=f"MAC {mac}, IP {ip}"
                       + (", static lease" if static else ""),
                cause="A device not seen before requested an address. Confirm it "
                      "is an expected/authorized device.",
                facts={"mac": mac, "ip": ip, "host": host},
            )

        mem["known_macs"] = sorted(known)
        mem["initialized"] = True
