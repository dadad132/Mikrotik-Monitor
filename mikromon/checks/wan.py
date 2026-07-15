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


def _matches_endpoint(route: dict, ep, dhcp_by_iface: dict | None = None) -> bool:
    if ep.gateway and str(route.get("gateway", "")) == ep.gateway:
        return True
    if ep.interface and _iface_of(route) == ep.interface:
        return True
    # Most reliable of all: look up this interface's OWN DHCP client and
    # compare its ACTUAL, live gateway field directly — rather than only
    # depending on gateway-status TEXT happening to contain "via <interface>"
    # in exactly the expected format. Confirmed live: that text format
    # doesn't always parse cleanly for every link on the same router, making
    # a genuinely healthy uplink look like "no route found" (reported
    # offline) while its siblings on the same device matched fine.
    if dhcp_by_iface is not None and ep.interface in dhcp_by_iface:
        dhcp_gw = str(dhcp_by_iface[ep.interface].get("gateway", ""))
        if dhcp_gw and str(route.get("gateway", "")) == dhcp_gw:
            return True
    return False


def _fo_role(idx: int) -> str:
    """Role name push/features.py's gateway-failover route builder tags
    comments with — mikromon:failover:primary/secondary/link3/link4/... —
    for every configured uplink, not just the first two."""
    return "primary" if idx == 0 else "secondary" if idx == 1 else f"link{idx + 1}"


def _fo_route_idx(comment: str, links) -> int | None:
    """Which configured link (if any) a mikromon-managed failover route
    belongs to, judged purely by its comment — needed when gateway/interface
    matching can't tell, e.g. a PPP remote-address gateway that doesn't match
    the uplink's interface name via gateway-status. Checks every configured
    link, not just the first two, since failover now manages all of them."""
    for i, ep in enumerate(links):
        if comment == ep.label(i):
            return i
    if comment.startswith("mikromon:failover:"):
        for i in range(len(links)):
            if comment == f"mikromon:failover:{_fo_role(i)}":
                return i
    return None


class WanCheck(Check):
    flags = ("wan_failover", "internet_down")
    requires = ("route", "dhcp_client")
    name = "wan"

    def run(self, snap, dev, ctx) -> None:
        defaults = [r for r in snap.rows("route") if _is_default(r)]
        want_failover = dev.check_enabled("wan_failover")
        want_down = dev.check_enabled("internet_down")
        links = dev.wan.links
        dhcp_by_iface = {c.get("interface", ""): c
                        for c in snap.rows("dhcp_client") if c.get("interface")}

        # ---- clear stale wan_failover / wan_link:N conditions -------------
        # Confirmed live: a device with wan_failover monitoring turned off
        # kept showing every uplink as permanently offline, because nothing
        # below ever runs again to say otherwise once want_failover is
        # false — transition() only clears a condition when it's actually
        # called with healthy=True, so a real "problem" recorded before the
        # check was disabled (or before a link was removed, dropping to <=1
        # configured uplinks) just stays frozen indefinitely. Clear anything
        # the code below won't reach this poll, using confirm=1 so it
        # doesn't linger for another debounce cycle.
        existing = ctx.store.data.get("devices", {}).get(ctx.device, {}).get("conditions", {})
        if not want_failover:
            for key in list(existing):
                if key == "wan_failover" or key.startswith("wan_link:"):
                    ctx.transition(
                        key, healthy=True, severity=Severity.WARNING, title="",
                        recovery_title="WAN failover monitoring is off — "
                                      "clearing this stale alert",
                        confirm=1)
        elif len(links) <= 1:
            for key in list(existing):
                if key.startswith("wan_link:"):
                    ctx.transition(
                        key, healthy=True, severity=Severity.WARNING, title="",
                        recovery_title="No backup uplink is configured anymore — "
                                      "clearing this stale alert",
                        confirm=1)

        # ---- per-uplink status for BACKUP links only (one alert each) -----
        # Three mutually-exclusive tiers, each with its own single email:
        #   1. the primary (links[0]) goes down -> the "wan_failover" alert
        #      below (it already frames this as "primary down, on backup X").
        #   2. a backup link (links[1:]) goes down while the primary is still
        #      up -> alerted here.
        #   3. every configured link is down -> "internet_down" below.
        # The primary's own up/down transition is intentionally NOT alerted
        # here too — that would just be a second, less informative email for
        # the same event tier 1 already covers. And backup links are only
        # evaluated when NOT everything is down, so a full outage produces
        # exactly one "internet down" email instead of one per link plus one
        # overall.
        if want_failover and len(links) > 1:
            all_down = not defaults or not any(_is_active(r) for r in defaults)
            if not all_down:
                for idx, ep in enumerate(links):
                    if idx == 0:
                        continue  # primary: covered by the failover alert below
                    link_name = ep.label(idx)
                    ep_routes = [r for r in defaults
                                if _matches_endpoint(r, ep, dhcp_by_iface)]
                    if not ep_routes:
                        ep_routes = [r for r in defaults
                                    if _fo_route_idx(str(r.get("comment", "")), links) == idx]
                    if ep_routes:
                        link_up = any(_is_active(r) for r in ep_routes)
                        gw_status = str(ep_routes[0].get("gateway-status", "unknown"))
                    else:
                        link_up = False
                        gw_status = "no route found"
                    ctx.transition(
                        f"wan_link:{idx}", healthy=link_up,
                        severity=Severity.WARNING,
                        title=f"Backup WAN uplink \"{link_name}\" is DOWN "
                              f"(primary is still up)",
                        cause=(f"Gateway status: {gw_status}." if not link_up else ""),
                        recovery_title=f"Backup WAN uplink \"{link_name}\" is back UP",
                        recovery_detail=f"Gateway: {gw_status}.",
                    )

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
        if links:
            cur_comment = str(current.get("comment", ""))
            prim_name = links[0].label(0)
            # Preferred = the highest-priority configured uplink (links[0]).
            # Try interface/gateway match first, fall back to the route's own
            # comment (needed when the failover route's gateway is a PPP
            # remote IP that doesn't match the uplink's interface name via
            # gateway-status).
            primary_routes = [r for r in defaults
                              if _matches_endpoint(r, links[0], dhcp_by_iface)]
            if not primary_routes:
                primary_routes = [r for r in defaults
                                  if _fo_route_idx(str(r.get("comment", "")), links) == 0]
            preferred = (min(primary_routes, key=by_distance)
                         if primary_routes else min(defaults, key=by_distance))
            # Which configured link is currently carrying traffic? Falls back
            # to the managed route's own comment — either the uplink's own
            # name (current scheme) or the older internal tag (routers not
            # yet re-pushed after the switch) — for the same reason as above.
            cur_idx = next((i for i, ep in enumerate(links)
                            if _matches_endpoint(current, ep, dhcp_by_iface)), None)
            if cur_idx is None:
                cur_idx = _fo_route_idx(cur_comment, links)
            on_backup = ((cur_idx != 0) if cur_idx is not None
                        else not _matches_endpoint(current, links[0], dhcp_by_iface))
            cur_name = (links[cur_idx].label(cur_idx) if cur_idx is not None
                        else (_iface_of(current) or current.get("gateway", "?")))
            rank = (f" (priority {cur_idx + 1} of {len(links)})"
                    if cur_idx is not None else "")
        else:
            preferred = min(defaults, key=by_distance)
            on_backup = by_distance(current) > by_distance(preferred)
            cur_name = _iface_of(current) or current.get("gateway", "?")
            prim_name = _iface_of(preferred) or preferred.get("gateway", "?")
            rank = ""

        cause = ""
        if on_backup:
            prim_status = str(preferred.get("gateway-status", "")) or "inactive"
            cause = (f"Primary uplink {prim_name} ({_label(preferred)}) is not "
                     f"carrying traffic ({prim_status}). Traffic is now flowing via "
                     f"{cur_name} ({_label(current)}).")
        ctx.transition(
            "wan_failover", healthy=not on_backup, severity=Severity.WARNING,
            title=f"Primary WAN \"{prim_name}\" is DOWN — running on backup "
                  f"\"{cur_name}\"{rank}",
            detail=f"Active default route: {_label(current)}.",
            cause=cause,
            facts={"current": _label(current), "preferred": _label(preferred),
                   "current_link": cur_name, "primary_link": prim_name},
            recovery_title=f"WAN restored — back on primary uplink {prim_name}",
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
