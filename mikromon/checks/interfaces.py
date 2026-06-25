"""Interface monitoring: link down and flapping.

Flapping is detected from RouterOS's cumulative `link-downs` counter: we track
how much it increases over a sliding time window and alert when a link goes
down too many times too quickly (a far better signal than a single down event).
"""
from __future__ import annotations

from ..alert import Severity
from ..util import as_bool, as_int
from .base import Check

# Interface types worth auto-watching when the user didn't list any explicitly.
_AUTO_TYPES = ("ether", "lte", "wlan", "sfp", "wireless", "vdsl", "pppoe-out",
               "ppp-out", "gpon")

# Physical port types where "nothing plugged in" is a normal, non-alerting
# state. A down ether/sfp that the admin never configured or used is a spare
# port, not a fault — so we only alert on it once it looks like it's in use.
_PHYSICAL = ("ether", "sfp")


def _configured_ifaces(snap):
    """Names of interfaces that carry an enabled IP address (clearly in use)."""
    out = set()
    for addr in snap.rows("ip_address"):
        if as_bool(addr.get("disabled")):
            continue
        name = str(addr.get("interface", "")).strip()
        if name:
            out.add(name)
    return out


def _watch_list(snap, dev):
    if dev.monitor_interfaces:
        return set(dev.monitor_interfaces)
    auto = set()
    for iface in snap.rows("interface"):
        if as_bool(iface.get("disabled")):
            continue
        itype = str(iface.get("type", "")).lower()
        if any(itype.startswith(t) for t in _AUTO_TYPES):
            auto.add(str(iface.get("name", "")))
    return auto


class InterfaceCheck(Check):
    flags = ("interfaces",)
    requires = ("interface", "ip_address")
    name = "interfaces"

    def run(self, snap, dev, ctx) -> None:
        watch = _watch_list(snap, dev)
        if not watch:
            return
        mem = ctx.memory("interfaces")
        flap_hist = mem.setdefault("flap", {})  # name -> list[[ts, downs_delta]]
        last_downs = mem.setdefault("link_downs", {})  # name -> last counter
        window = as_int(dev.th("flap_window_s"), 600)
        threshold = as_int(dev.th("flap_threshold"), 4)

        # If the admin enumerated interfaces explicitly, every watched one is
        # intentional, so a down state is always worth reporting. Otherwise
        # (auto-watch) we suppress spare/unplugged physical ports.
        explicit = bool(dev.monitor_interfaces)
        configured = _configured_ifaces(snap)

        by_name = {str(i.get("name", "")): i for i in snap.rows("interface")}
        for name in watch:
            iface = by_name.get(name)
            if iface is None:
                continue  # configured to watch an interface that doesn't exist
            disabled = as_bool(iface.get("disabled"))
            running = as_bool(iface.get("running"))
            comment = str(iface.get("comment", ""))
            itype = str(iface.get("type", "")).lower()
            downs = as_int(iface.get("link-downs"))

            # Does this port look like it's actually in use? Any of: the admin
            # asked to watch it, it has an IP, it's labelled, it has carried a
            # link this uptime, or it's up right now.
            in_use = (explicit or name in configured or bool(comment)
                      or downs > 0 or running)
            physical = any(itype.startswith(t) for t in _PHYSICAL)
            # A down physical port that isn't in use = nothing plugged in /
            # not configured -> not a fault, so treat it as healthy.
            unplugged = physical and not running and not disabled and not in_use

            # ---- link down (ignore administratively disabled + spare ports) --
            ctx.transition(
                f"iface_down:{name}", healthy=running or disabled or unplugged,
                severity=Severity.WARNING,
                title=f"Interface {name} link DOWN",
                detail=(f"Comment: {comment}" if comment else ""),
                cause="The physical/logical link is down — cable, SFP, peer "
                      "device, or upstream provider issue.",
                recovery_title=f"Interface {name} link UP",
            )

            # ---- flapping (rate of link-downs over the window) ------------
            downs = as_int(iface.get("link-downs"))
            prev = last_downs.get(name)
            last_downs[name] = downs
            if prev is None or downs < prev:
                # First sighting, or counter reset by a reboot — re-baseline.
                continue
            delta = downs - prev
            hist = flap_hist.setdefault(name, [])
            if delta > 0:
                hist.append([ctx.now, delta])
            # Drop samples older than the window.
            cutoff = ctx.now - window
            hist[:] = [h for h in hist if h[0] >= cutoff]
            recent = sum(h[1] for h in hist)
            if recent >= threshold:
                cool = mem.setdefault("flap_cooldown", {})
                if ctx.now - cool.get(name, 0) >= window:
                    cool[name] = ctx.now
                    ctx.event(
                        f"iface_flap:{name}", Severity.WARNING,
                        f"Interface {name} is FLAPPING",
                        detail=f"{recent} link-downs in the last "
                               f"{window // 60} min.",
                        cause="Rapid up/down cycling — often a failing cable/SFP, "
                              "duplex mismatch, or an unstable upstream link.",
                        facts={"link_downs_in_window": recent},
                    )
