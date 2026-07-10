"""The device-page "engines" — one declarative feature per tab.

Each feature can:
  * read(pusher, cfg)        -> current state read live from the router
  * summarize(current, cfg)  -> short human lines describing that state
  * form(current, cfg)       -> declarative field descriptors (the web renders them)
  * plan(pusher, cfg, flat, multi) -> a push Plan (desired state diffed vs current)

Everything routes through the same engine (reconcile / settings) so every tab
gets dry-run preview, apply, automatic rollback and audit logging for free.

These RouterOS field mappings are conservative and clearly tagged with a
`comment` so the engine only ever touches rows it created — but they are
EXPERIMENTAL until validated against real hardware. The activity log is how you
see what a real router accepted or rejected.
"""
from __future__ import annotations

import re

from .plan import Operation, Plan
from .reconcile import _norm, reconcile_list

DNS_BYPASS_LIST = "mikromon-dns-bypass"


def _slug(s, fallback="adopted"):
    s = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(s or "").strip()).strip("-")
    return s[:40] or fallback


# ---- small parsing helpers -------------------------------------------------
def _rows(multi, name, cols):
    """Read repeatable form rows named '<name>__<col>' (parallel arrays)."""
    series = {c: multi.get(f"{name}__{c}", []) for c in cols}
    n = max((len(v) for v in series.values()), default=0)
    out = []
    for i in range(n):
        row = {c: (series[c][i].strip() if i < len(series[c]) else "")
               for c in cols}
        if any(row.values()):
            out.append(row)
    return out


def _prefix_owner(prefix):
    return lambda r: str(r.get("comment", "")).startswith(prefix)


def _set_field(path, row, field, value, label):
    rid = row[".id"]
    return Operation(
        "set", path, {".id": rid, field: value},
        desc=f"set {label} {field}={value}",
        inverse=Operation("set", path, {".id": rid, field: row.get(field, "")},
                          desc=f"revert {label} {field}"))


# ===========================================================================
# Routes — live internet lines: DHCP/PPP client status + primary-line switcher
# ===========================================================================
_ROUTE = ("ip", "route")
_DHCP_CLIENT = ("ip", "dhcp-client")
_PPPOE_CLIENT = ("interface", "pppoe-client")
_L2TP_CLIENT = ("interface", "l2tp-client")
_NETWATCH = ("tool", "netwatch")
_PPP_ACTIVE = ("ppp", "active")
_IP_ADDRESS = ("ip", "address")
_FAILOVER_TAG = "mikromon:failover:"


def _default_routes(api):
    return [r for r in api.fetch(_ROUTE)
            if str(r.get("dst-address", "")).startswith("0.0.0.0/0")]


def _route_matches(route, link):
    gw = str(route.get("gateway", ""))
    if link.interface and (gw == link.interface or link.interface in gw):
        return True
    return bool(link.gateway) and gw == link.gateway


def _safe_fetch(api, path):
    try:
        return api.fetch(path)
    except Exception:  # noqa: BLE001
        return []


def detect_isp_ifaces(api) -> set:
    """Interface names that look like they're ACTUALLY carrying an internet
    connection right now — a bound DHCP lease, a running PPPoE/L2TP session,
    or the live gateway of an active default route. Used to point out which
    physical port the ISP is plugged into when setting up a router from
    scratch, since that varies (ether1 on one job, ether5 on another) and
    otherwise has to be guessed."""
    online = set()
    for c in _safe_fetch(api, _DHCP_CLIENT):
        if str(c.get("status", "")).lower() == "bound" and c.get("interface"):
            online.add(c["interface"])
    for c in _safe_fetch(api, _PPPOE_CLIENT):
        if str(c.get("running", "false")).lower() in ("true", "yes") and c.get("name"):
            online.add(c["name"])
    for c in _safe_fetch(api, _L2TP_CLIENT):
        if str(c.get("running", "false")).lower() in ("true", "yes") and c.get("name"):
            online.add(c["name"])
    for r in _safe_fetch(api, _ROUTE):
        if (str(r.get("dst-address", "")).startswith("0.0.0.0/0")
                and str(r.get("active", "true")).lower() not in ("false", "no")):
            m = re.search(r"via\s+(\S+)", str(r.get("gateway-status", "")))
            if m:
                online.add(m.group(1))
    return online


def _fo_names(cfg):
    """Label for each of the (up to 2) managed failover links — each
    uplink's own configured name/interface (WanEndpoint.label), not an
    internal tag, so route/Netwatch comments on the router match what was
    typed into the WAN uplinks editor."""
    links = list(getattr(getattr(cfg, "wan", None), "links", []) or [])[:2]
    return [link.label(idx) for idx, link in enumerate(links)]


def _fo_owns(cfg):
    """Predicate for routes/netwatch entries mikromon's gateway failover
    manages: comment equals a link's own name or its '<name>-Check'
    companion route, OR (back-compat) starts with the old internal
    mikromon:failover: tag used before comments switched to the link's own
    name — so routers not yet re-pushed after the switch still get their
    old entries recognized, cleaned up, and replaced."""
    names = _fo_names(cfg)
    owned = set(names) | {f"{n}-Check" for n in names}

    def _owns(r):
        c = str(r.get("comment", ""))
        return c in owned or c.startswith(_FAILOVER_TAG)
    return _owns


def routes_read(pusher, cfg):
    dhcp = _safe_fetch(pusher.api, _DHCP_CLIENT)
    pppoe = _safe_fetch(pusher.api, _PPPOE_CLIENT)
    l2tp = _safe_fetch(pusher.api, _L2TP_CLIENT)
    ppp = [{"_type": "pppoe", **c} for c in pppoe] + [{"_type": "l2tp", **c} for c in l2tp]
    ppp_active = _safe_fetch(pusher.api, _PPP_ACTIVE)
    ip_addrs = _safe_fetch(pusher.api, _IP_ADDRESS)
    all_routes = _safe_fetch(pusher.api, _ROUTE)
    routes = [r for r in all_routes
              if str(r.get("dst-address", "")).startswith("0.0.0.0/0")
              and not str(r.get("comment", "")).startswith("mikromon:sdwan")]
    fo_owns = _fo_owns(cfg)
    failover_routes = [r for r in all_routes if fo_owns(r)]
    netwatch = _safe_fetch(pusher.api, _NETWATCH)
    failover_watch = [w for w in netwatch if fo_owns(w)]
    return {"routes": routes, "dhcp": dhcp, "ppp": ppp,
            "ppp_active": ppp_active, "ip_addrs": ip_addrs,
            "failover_routes": failover_routes, "failover_watch": failover_watch}


def routes_summary(current, cfg):
    lines = []
    routes = current.get("routes", [])
    for c in current.get("dhcp", []):
        iface = c.get("interface", "?")
        status = c.get("status", "unknown")
        dist = c.get("default-route-distance", "?")
        if str(c.get("add-default-route", "yes")).lower() in ("no", "false"):
            lines.append(f"DHCP {iface} · no default route")
        else:
            rs = _route_status_for(routes, c, "dhcp")
            rs_str = f" · route {rs}" if rs else ""
            lines.append(f"DHCP {iface} · {status}{rs_str} · distance {dist}")
    for c in current.get("ppp", []):
        ctype = c.get("_type", "ppp").upper()
        name = c.get("name", "?")
        running = str(c.get("running", "false")).lower() in ("true", "yes")
        dist = c.get("default-route-distance", "?")
        if str(c.get("add-default-route", "yes")).lower() in ("no", "false"):
            lines.append(f"{ctype} {name} · no default route")
        else:
            state = "connected" if running else "disconnected"
            rs = _route_status_for(routes, c, c.get("_type", "ppp"))
            rs_str = f" · route {rs}" if rs else ""
            lines.append(f"{ctype} {name} · {state}{rs_str} · distance {dist}")
    for r in current.get("routes", []):
        gw = r.get("gateway", "?")
        dist = r.get("distance", "?")
        active = str(r.get("active", "true")).lower() not in ("false", "no")
        lines.append(f"route via {gw} · distance {dist}"
                     + ("" if active else " · inactive"))
    # Failover summary
    names = _fo_names(cfg)
    fo_by_comment = {r.get("comment", ""): r for r in current.get("failover_routes", [])
                     if not str(r.get("comment", "")).endswith("-Check")}
    watch_by_comment = {w.get("comment", ""): w for w in current.get("failover_watch", [])}
    for idx, name in enumerate(names):
        role = "primary" if idx == 0 else "secondary"
        r = fo_by_comment.get(name)
        w = watch_by_comment.get(name)
        if r:
            active = str(r.get("active", "true")).lower() not in ("false", "no")
            disabled = str(r.get("disabled", "false")).lower() in ("true", "yes")
            state = "disabled by netwatch" if disabled else ("route active" if active else "route inactive")
            watch_info = f"watch {w['host']} every {w.get('interval','?')}" if w else "no netwatch"
            lines.append(f"Failover {role} \"{name}\" {r.get('gateway','?')} · {state} · {watch_info}")
    return lines or ["No internet lines found on this router."]


def _route_status_for(routes, client, ctype):
    """Return 'active', 'inactive', or '' (no matching default route found).

    DHCP routes are matched by gateway IP; PPPoE/L2TP routes are matched by the
    interface/client name.  The RouterOS 'active' flag is True when the route is
    in the forwarding table — reliable for interface-down detection but only
    reflects internet reachability if check-gateway is also configured."""
    if ctype == "dhcp":
        gw = str(client.get("gateway", ""))
    else:
        gw = str(client.get("name", ""))
    if not gw:
        return ""
    for r in routes:
        if str(r.get("gateway", "")) == gw:
            active = str(r.get("active", "true")).lower() not in ("false", "no")
            return "active" if active else "inactive"
    return ""


def _dist_from_routes(routes, client, ctype):
    """Find the distance of the matching 0.0.0.0/0 route for this client.

    RouterOS omits default-route-distance from the API response when
    add-default-route=no, so we fall back to reading the distance from the
    actual route table (which includes our managed static failover routes)."""
    gw = str(client.get("gateway", "")) if ctype == "dhcp" else str(client.get("name", ""))
    if not gw:
        return ""
    for r in routes:
        if str(r.get("gateway", "")) == gw:
            return str(r.get("distance", ""))
    return ""


def _wan_sortable_items(current):
    routes = current.get("routes", [])
    items = []
    for c in current.get("dhcp", []):
        iface = c.get("interface", "?")
        status = c.get("status", "unknown")
        dist = c.get("default-route-distance", "") or _dist_from_routes(routes, c, "dhcp") or "1"
        rid = c.get(".id", "").lstrip("*")
        if str(c.get("add-default-route", "yes")).lower() in ("no", "false"):
            conn_info = f"{status} · no default route"
        else:
            rs = _route_status_for(routes, c, "dhcp")
            conn_info = f"{status}" + (f" · route {rs}" if rs else "")
        items.append({
            "id": f"dhcp:{rid}",
            "label": f"DHCP {iface} [{conn_info}] · distance {dist}",
            "_dist": dist,
        })
    for c in current.get("ppp", []):
        ctype = c.get("_type", "ppp").upper()
        name = c.get("name", "?")
        running = str(c.get("running", "false")).lower() in ("true", "yes")
        dist = c.get("default-route-distance", "") or _dist_from_routes(routes, c, c.get("_type", "ppp")) or "1"
        rid = c.get(".id", "").lstrip("*")
        state = "connected" if running else "disconnected"
        if str(c.get("add-default-route", "yes")).lower() in ("no", "false"):
            conn_info = f"{state} · no default route"
        else:
            rs = _route_status_for(routes, c, c.get("_type", "ppp"))
            conn_info = f"{state}" + (f" · route {rs}" if rs else "")
        items.append({
            "id": f"{c.get('_type', 'ppp')}:{rid}",
            "label": f"{ctype} {name} [{conn_info}] · distance {dist}",
            "_dist": dist,
        })

    def _dist_key(item):
        try:
            return int(item["_dist"])
        except (ValueError, TypeError):
            return 9999

    return sorted(items, key=_dist_key)


def _wan_clients_sorted(current):
    """All WAN clients (DHCP + PPPoE + L2TP) that add a default route, sorted by distance."""
    clients = []
    for c in current.get("dhcp", []):
        if str(c.get("add-default-route", "yes")).lower() not in ("no", "false"):
            clients.append({"_type": "dhcp", **c})
    for c in current.get("ppp", []):
        if str(c.get("add-default-route", "yes")).lower() not in ("no", "false"):
            clients.append(dict(c))

    def _k(c):
        try:
            return int(c.get("default-route-distance", "1"))
        except (ValueError, TypeError):
            return 1

    return sorted(clients, key=_k)


def _wan_gateway_for(client):
    """Gateway value for a static route to this WAN: IP for DHCP, interface name for PPPoE/L2TP."""
    if client.get("_type") == "dhcp":
        return client.get("gateway", "")
    return client.get("name", "")


def routes_form(current, cfg):
    items = _wan_sortable_items(current)

    # Pre-fill check IPs from the existing failover watch config
    fo_enabled = bool(current.get("failover_routes"))
    primary_check = "1.1.1.1"
    secondary_check = "8.8.8.8"
    names = _fo_names(cfg)
    for w in current.get("failover_watch", []):
        c = w.get("comment", "")
        if names and c == names[0] and w.get("host"):
            primary_check = w["host"]
        elif len(names) > 1 and c == names[1] and w.get("host"):
            secondary_check = w["host"]

    links = list(getattr(getattr(cfg, "wan", None), "links", []) or [])

    fields = [
        {"type": "sortable", "name": "wan_order",
         "label": "Internet line priority — drag or use ↑/↓ to set primary (top = primary)",
         "items": items,
         "hint": "Top line becomes distance 1 (primary). RouterOS does not allow "
                 "editing distances on dynamic DHCP/PPPoE routes directly — the "
                 "change is saved on the client config and takes effect the next time "
                 "that line reconnects or renews its DHCP lease. To apply immediately: "
                 "disconnect and reconnect the line from RouterOS after applying."},
        {"type": "heading", "label": "Gateway Failover",
         "hint": "Static routes with check-gateway=ping + Netwatch. "
                 "Gateways are detected automatically from the configured WAN uplinks."},
        {"type": "toggle", "name": "fo_enabled", "value": "1",
         "on": fo_enabled, "label": "Enable gateway failover"},
        {"type": "text", "name": "fo_primary_check",
         "label": "Primary check IP", "value": primary_check,
         "placeholder": "1.1.1.1",
         "hint": "Netwatch pings this IP to confirm the primary line has internet."},
    ]
    if len(links) > 1:
        fields.append({"type": "text", "name": "fo_secondary_check",
                       "label": "Secondary check IP", "value": secondary_check,
                       "placeholder": "8.8.8.8",
                       "hint": "Netwatch pings this IP to confirm the backup line has internet."})
    return fields


def _apply_wan_order(ops, order, pusher):
    """Build distance-change ops from a wan_order list.

    RouterOS dynamic routes (DHCP / PPPoE / L2TP) are read-only in /ip/route —
    attempting to set their distance returns 'no such item'. The only supported
    path is setting default-route-distance on the client itself, which takes
    effect on the next connection or DHCP renewal."""
    if not order:
        return
    dhcp_clients = _safe_fetch(pusher.api, _DHCP_CLIENT)
    pppoe_clients = _safe_fetch(pusher.api, _PPPOE_CLIENT)
    l2tp_clients = _safe_fetch(pusher.api, _L2TP_CLIENT)
    client_map = {}
    for c in dhcp_clients:
        rid = c.get(".id", "").lstrip("*")
        client_map[f"dhcp:{rid}"] = (_DHCP_CLIENT, c, f"DHCP {c.get('interface','?')}")
    for c in pppoe_clients:
        rid = c.get(".id", "").lstrip("*")
        client_map[f"pppoe:{rid}"] = (_PPPOE_CLIENT, c, f"PPPOE {c.get('name','?')}")
    for c in l2tp_clients:
        rid = c.get(".id", "").lstrip("*")
        client_map[f"l2tp:{rid}"] = (_L2TP_CLIENT, c, f"L2TP {c.get('name','?')}")
    for rank, item_id in enumerate(order, start=1):
        want = str(rank)
        if item_id not in client_map:
            continue
        cpath, c, clabel = client_map[item_id]
        if _norm(str(c.get("default-route-distance", "1"))) != want:
            ops.append(_set_field(cpath, c, "default-route-distance", want, clabel))


def _gateway_for_link(link, pppoe_names, dhcp_by_iface,
                      ppp_active_by_name=None, ip_addr_by_iface=None):
    """Return the RouterOS gateway IP (or interface name) for a WAN uplink.

    Priority:
      1. Explicit gateway set in the WAN uplinks editor (manual override).
      2. PPP/PPPoE interface → look up the remote address of the active session:
         a. /ppp/active  remote-address field
         b. /ip/address  network field (PPP point-to-point creates a /32 where
            'network' is the remote/ISP end — that IS the gateway IP)
         If neither returns an IP, fall back to the interface name so RouterOS
         can still route via the PPPoE interface directly.
      3. DHCP client on the interface → use the DHCP-assigned gateway IP."""
    gw = getattr(link, "gateway", "") or ""
    if gw:
        return gw
    iface = getattr(link, "interface", "") or ""
    if not iface:
        return ""

    if iface in pppoe_names:
        # Try /ppp/active first — some RouterOS versions expose remote-address
        if ppp_active_by_name:
            sess = ppp_active_by_name.get(iface, {})
            remote = sess.get("remote-address", "")
            if remote:
                return remote
        # Try /ip/address — PPP assigns a /32 local with 'network' = remote end
        if ip_addr_by_iface:
            addr = ip_addr_by_iface.get(iface, {})
            network = addr.get("network", "")
            if network and network not in ("0.0.0.0", ""):
                return network
        # Last resort: use the interface name (RouterOS accepts it as a gateway)
        return iface

    # Not PPP — check DHCP client for this interface
    dhcp = dhcp_by_iface.get(iface)
    if dhcp:
        return dhcp.get("gateway", "")
    return ""


def _apply_failover(ops, flat, pusher, cfg):
    """Reconcile gateway-failover routes + Netwatch entries — the standard,
    hand-written MikroTik failover pattern: two static default routes
    (primary distance 1, secondary distance 2) each with check-gateway=ping,
    plus a Netwatch probe per link that disables/enables ITS OWN route based
    on reachability of a public IP, reached via a dedicated check-route
    forced out that same gateway (so the two probes never interfere with
    each other). No custom scripting beyond the single-line disable/enable
    commands below — no distance-flipping, no debounce counters.

    Route/Netwatch comments use each uplink's own configured name (e.g.
    "Fibre", "Backup" — whatever was typed into the WAN uplinks editor), not
    an internal tag, so what's on the router matches what the link is
    called. Only the top two configured links are managed, matching the
    fixed primary/secondary check-IP fields below. If an uplink is renamed
    later, the OLD name's route/Netwatch entry is orphaned (no longer
    recognized as ours) and needs manual cleanup — the trade-off of using
    the link's own name instead of a fixed internal tag."""
    all_routes = _safe_fetch(pusher.api, _ROUTE)
    netwatch = _safe_fetch(pusher.api, _NETWATCH)
    all_links = list(getattr(getattr(cfg, "wan", None), "links", []) or [])
    links = all_links[:2]
    names = _fo_names(cfg)
    owns = _fo_owns(cfg)

    if not flat.get("fo_enabled"):
        ops.extend(reconcile_list(_ROUTE, "comment", [], all_routes,
                                  owns=owns, label="failover route"))
        ops.extend(reconcile_list(_NETWATCH, "comment", [], netwatch,
                                  owns=owns, label="netwatch"))
        # Restore each WAN client to plain, working routing — equivalent to
        # running, per link:
        #   /ip dhcp-client set [find name="..."] add-default-route=yes \
        #       default-route-distance=<N> disabled=no
        # default-route-distance gets a distinct value per link (10, 11,
        # 12... in priority order) so multiple uplinks can't collide at
        # RouterOS's implicit default of 1; disabled=no in case an earlier
        # troubleshooting step left the client itself switched off.
        pppoe_clients = _safe_fetch(pusher.api, _PPPOE_CLIENT)
        dhcp_clients  = _safe_fetch(pusher.api, _DHCP_CLIENT)
        for idx, link in enumerate(all_links):
            iface = getattr(link, "interface", "") or ""
            if not iface:
                continue
            want_dist = str(10 + idx)
            for c in pppoe_clients:
                if c.get("name") == iface:
                    if c.get("add-default-route", "yes") == "no":
                        ops.append(_set_field(_PPPOE_CLIENT, c, "add-default-route",
                                              "yes", f"PPPoE {iface}"))
                    if _norm(str(c.get("default-route-distance", "") or "")) != want_dist:
                        ops.append(_set_field(_PPPOE_CLIENT, c,
                                              "default-route-distance", want_dist,
                                              f"PPPoE {iface}"))
                    if c.get("disabled", "false") not in ("false", "no", False):
                        ops.append(_set_field(_PPPOE_CLIENT, c, "disabled", "no",
                                              f"PPPoE {iface}"))
            for c in dhcp_clients:
                if c.get("interface") == iface:
                    if c.get("add-default-route", "yes") == "no":
                        ops.append(_set_field(_DHCP_CLIENT, c, "add-default-route",
                                              "yes", f"DHCP {iface}"))
                    if _norm(str(c.get("default-route-distance", "") or "")) != want_dist:
                        ops.append(_set_field(_DHCP_CLIENT, c,
                                              "default-route-distance", want_dist,
                                              f"DHCP {iface}"))
                    if c.get("disabled", "false") not in ("false", "no", False):
                        ops.append(_set_field(_DHCP_CLIENT, c, "disabled", "no",
                                              f"DHCP {iface}"))
        return

    # ---- enabled: detect gateways live from the router at apply time ------
    pppoe_clients = _safe_fetch(pusher.api, _PPPOE_CLIENT)
    dhcp_clients  = _safe_fetch(pusher.api, _DHCP_CLIENT)
    pppoe_names = {c.get("name", "") for c in pppoe_clients if c.get("name")}
    dhcp_by_iface = {c.get("interface", ""): c for c in dhcp_clients if c.get("interface")}
    ppp_active_by_name = {s.get("name", ""): s
                          for s in _safe_fetch(pusher.api, _PPP_ACTIVE) if s.get("name")}
    ip_addr_by_iface = {a.get("interface", ""): a
                        for a in _safe_fetch(pusher.api, _IP_ADDRESS) if a.get("interface")}
    fo_by_comment = {r.get("comment", ""): r for r in all_routes if owns(r)}

    gateways = []
    for idx, link in enumerate(links):
        gw = _gateway_for_link(link, pppoe_names, dhcp_by_iface,
                               ppp_active_by_name, ip_addr_by_iface)
        if not gw:
            # Fall back to the gateway already on the router from a
            # previous apply (e.g. a PPPoE session that isn't up right now).
            existing = fo_by_comment.get(names[idx])
            if existing and existing.get("gateway"):
                gw = existing["gateway"]
        gateways.append(gw)
    if not gateways or not gateways[0]:
        return  # primary gateway not detectable — cannot build routes

    # Primary always checks 1.1.1.1, secondary always checks 8.8.8.8 — fixed
    # roles, matching the form fields.
    check_ips = [flat.get("fo_primary_check", "").strip() or "1.1.1.1",
                flat.get("fo_secondary_check", "").strip() or "8.8.8.8"]

    def _net(ip):
        return ip if "/" in ip else f"{ip}/32"

    # The check routes are the critical piece: each forces ITS Netwatch ping
    # through its OWN gateway, so both probes are safe to run at the same
    # time without one route's disable affecting the other's check path.
    # scope=30 / target-scope=10 on every route matches the standard
    # pattern; the default routes resolve their gateway via ARP (directly
    # connected, scope=0 <= target-scope=10).
    desired_routes = []
    desired_watch = []
    for idx, gw in enumerate(gateways):
        if not gw:
            continue
        name = names[idx]
        host = check_ips[idx].split("/")[0]
        desired_routes.append({
            "comment": name, "dst-address": "0.0.0.0/0", "gateway": gw,
            "distance": str(idx + 1), "check-gateway": "ping",
            "scope": "30", "target-scope": "10",
        })
        desired_routes.append({
            "comment": f"{name}-Check", "dst-address": _net(host), "gateway": gw,
            "distance": "1", "scope": "30", "target-scope": "10",
        })
        desired_watch.append({
            "comment": name, "host": host, "interval": "5s",
            "down-script": f'/ip route disable [find comment="{name}"]',
            "up-script":   f'/ip route enable [find comment="{name}"]',
        })

    ops.extend(reconcile_list(_ROUTE, "comment", desired_routes, all_routes,
                              owns=owns, label="failover route"))
    ops.extend(reconcile_list(_NETWATCH, "comment", desired_watch, netwatch,
                              owns=owns, label="netwatch"))

    # Stop these WAN clients creating their own dynamic default routes — they
    # compete with our static routes and prevent failover from working. When
    # the client has add-default-route=yes, it creates a dynamic route at
    # distance=1 that stays active even when Netwatch disables our static
    # primary route, so the secondary static never wins. Setting
    # add-default-route=no removes the dynamic route immediately on active
    # connections and leaves only our managed static routes in control.
    for link in links:
        iface = getattr(link, "interface", "") or ""
        if not iface:
            continue
        for c in pppoe_clients:
            if c.get("name") == iface and c.get("add-default-route", "yes") != "no":
                ops.append(_set_field(_PPPOE_CLIENT, c, "add-default-route", "no",
                                      f"PPPoE {iface}"))
        for c in dhcp_clients:
            if c.get("interface") == iface and c.get("add-default-route", "yes") != "no":
                ops.append(_set_field(_DHCP_CLIENT, c, "add-default-route", "no",
                                      f"DHCP {iface}"))


def routes_plan(pusher, cfg, flat, multi):
    ops = []
    _apply_wan_order(ops, multi.get("wan_order", []), pusher)
    _apply_failover(ops, flat, pusher, cfg)
    return Plan(cfg.name, ops, summary="routes / failover")


# ===========================================================================
# SD-WAN — failover / load-balance policy + per-subnet policy routing
# ===========================================================================
_MANGLE = ("ip", "firewall", "mangle")
_POL_TAG = "mikromon:sdwan:pol:"   # mangle mark-routing rule
_RT_TAG = "mikromon:sdwan:rt:"     # the matching marked default route


def sdwan_read(pusher, cfg):
    all_routes = _safe_fetch(pusher.api, _ROUTE)
    routes = [r for r in all_routes
              if str(r.get("dst-address", "")).startswith("0.0.0.0/0")
              and not str(r.get("comment", "")).startswith("mikromon:sdwan")]
    policy = [r for r in _safe_fetch(pusher.api, _MANGLE)
              if str(r.get("comment", "")).startswith(_POL_TAG)]
    fo_owns = _fo_owns(cfg)
    failover_routes = [r for r in all_routes
                       if fo_owns(r) and not str(r.get("comment", "")).endswith("-Check")
                       and str(r.get("dst-address", "")).startswith("0.0.0.0/0")]
    netwatch = _safe_fetch(pusher.api, _NETWATCH)
    failover_watch = [w for w in netwatch if fo_owns(w)]
    return {"routes": routes, "policy": policy,
            "failover_routes": failover_routes, "failover_watch": failover_watch}


def _policy_rows(current):
    rows = []
    for m in current.get("policy", []):
        enc = m.get("comment", "")[len(_POL_TAG):]
        subnet, _, via = enc.partition("|")
        rows.append({"subnet": m.get("src-address", subnet), "via": via})
    return rows


def sdwan_summary(current, cfg):
    links = list(getattr(getattr(cfg, "wan", None), "links", []) or [])
    lines = []
    names = _fo_names(cfg)
    fo_routes = {r.get("comment", ""): r for r in current.get("failover_routes", [])}
    fo_watch  = {w.get("comment", ""): w for w in current.get("failover_watch", [])}
    for name in names:
        r = fo_routes.get(name)
        if not r:
            continue
        gw = r.get("gateway", "?")
        dist = r.get("distance", "?")
        disabled = str(r.get("disabled", "false")).lower() in ("true", "yes")
        active   = str(r.get("active",   "true" )).lower() not in ("false", "no")
        state = "disabled" if disabled else ("active" if active else "inactive")
        w = fo_watch.get(name)
        watch = f" · watch {w['host']} every {w.get('interval','?')}" if w else ""
        lines.append(f"{name} via {gw} · distance {dist} · {state}{watch}")
    # If no managed failover routes, fall back to plain default routes
    if not lines:
        for r in current.get("routes", []):
            gw  = r.get("gateway", "?")
            dist = r.get("distance", "?")
            active = str(r.get("active", "true")).lower() not in ("false", "no")
            matched = next(((i, lk) for i, lk in enumerate(links)
                            if (lk.gateway and lk.gateway == gw)
                            or (lk.interface and lk.interface == gw)), None)
            prefix = f"{matched[1].label(matched[0])} via {gw}" if matched else f"route via {gw}"
            lines.append(f"{prefix} · distance {dist}" + ("" if active else " · inactive"))
    pol = len(current.get("policy", []))
    if pol:
        lines.append(f"{pol} LAN→WAN policy rule(s)")
    return lines or ["No WAN routes configured."]


def sdwan_form(current, cfg):
    links = ", ".join(e.label(i) for i, e in enumerate(cfg.wan.links)) or "(none)"
    return [
        {"type": "select", "name": "mode",
         "label": "Auto-set distances for configured WAN uplinks",
         "options": [
             ("manual", "Manual — no automatic distance changes"),
             ("failover", "Failover — strict priority (1, 2, 3 … in link order)"),
             ("loadbalance", "Load balance — all equal (distance 1)"),
         ],
         "value": "manual",
         "hint": "Failover/load-balance auto-assigns distances to the static WAN "
                 "uplinks below. Use the Routes tab to change which line is primary."},
        {"type": "static", "label": "Configured WAN uplinks (priority order)",
         "value": links,
         "hint": "Edit them on the Devices page → WAN uplinks section."},
        {"type": "rows", "name": "pol",
         "label": "Send specific LAN subnets out a chosen WAN (policy routing)",
         "cols": [("subnet", "LAN subnet or host", "192.168.88.0/24"),
                  ("via", "out this WAN (interface or gateway)", "ether1")],
         "rows": _policy_rows(current),
         "hint": "Each row marks that source and routes it via the chosen WAN "
                 "(mangle mark + marked default route). Leave empty for none."},
    ]


def sdwan_plan(pusher, cfg, flat, multi):
    mode = flat.get("mode", "manual")
    ops = []
    if mode != "manual":
        routes = [r for r in _default_routes(pusher.api)
                  if not str(r.get("comment", "")).startswith("mikromon:sdwan")]
        for i, link in enumerate(cfg.wan.links):
            want = "1" if mode == "loadbalance" else str(i + 1)
            for r in routes:
                if _route_matches(r, link) and _norm(r.get("distance", "")) != want:
                    ops.append(_set_field(_ROUTE, r, "distance", want,
                                          f"route via {link.label(i)}"))
    mangle_desired, route_desired = [], []
    for r in _rows(multi, "pol", ("subnet", "via")):
        subnet, via = r["subnet"], r["via"]
        if not subnet or not via:
            continue
        mark = "mm-" + _slug(via)
        enc = f"{subnet}|{via}"
        mangle_desired.append({
            "chain": "prerouting", "src-address": subnet, "action": "mark-routing",
            "new-routing-mark": mark, "passthrough": "yes", "comment": _POL_TAG + enc})
        route_desired.append({
            "dst-address": "0.0.0.0/0", "gateway": via, "routing-mark": mark,
            "comment": _RT_TAG + enc})
    mangle_plan = pusher.plan_managed_list(
        _MANGLE, "comment", mangle_desired,
        owns=_prefix_owner(_POL_TAG), label="policy mark")
    route_plan = pusher.plan_managed_list(
        _ROUTE, "comment", route_desired,
        owns=_prefix_owner(_RT_TAG), label="policy route")
    return Plan(cfg.name, ops + mangle_plan.ops + route_plan.ops,
                summary=f"wan {mode}")


# ===========================================================================
# Security — conservative, reversible firewall drops (tagged, WAN-aware)
# ===========================================================================
_FILTER = ("ip", "firewall", "filter")
_SEC_TAG = "mikromon:sec:"


_IP_SERVICE = ("ip", "service")
_IP_SETTINGS = ("ip", "settings")
_RAW = ("ip", "firewall", "raw")


def _service_disabled(pusher, name) -> bool:
    """True if the named /ip service row (e.g. 'ssh') is disabled on the router."""
    row = next((s for s in pusher.api.fetch(_IP_SERVICE)
                if s.get("name") == name), None)
    return row is not None and _norm(row.get("disabled", "")) == "true"


def _syn_cookies_on(pusher) -> bool:
    """True if /ip settings tcp-syncookies is enabled (kernel SYN-flood guard).
    Tolerant of yes/no vs true/false so it never falsely reports a change."""
    s = pusher.api.fetch(_IP_SETTINGS)
    row = s[0] if s else {}
    return _norm(row.get("tcp-syncookies", "")) in ("true", "yes")


def security_read(pusher, cfg):
    rules = [r for r in pusher.api.fetch(_FILTER) if _prefix_owner(_SEC_TAG)(r)]
    return {"rules": rules, "ssh_disabled": _service_disabled(pusher, "ssh"),
            "syn_cookies": _syn_cookies_on(pusher),
            "telnet_disabled": _service_disabled(pusher, "telnet"),
            "ftp_disabled": _service_disabled(pusher, "ftp")}


def security_unmanaged(pusher, cfg):
    """All firewall filter rules we don't own — shown read-only for now."""
    out = []
    for r in pusher.api.fetch(_FILTER):
        if not str(r.get("comment", "")).startswith("mikromon:"):
            out.append({"id": r.get(".id"),
                        "text": f"{r.get('chain', '?')}/{r.get('action', '?')}"
                                f"{' · ' + r['comment'] if r.get('comment') else ''}"})
    return out


def security_summary(current, cfg):
    rules = current.get("rules", [])
    lines = [f"{r.get('comment', '')[len(_SEC_TAG):]} — {r.get('chain')}/"
             f"{r.get('action')}" for r in rules]
    if not lines:
        lines = ["No mikromon security rules on the router yet."]
    lines.append("TCP SYN-cookies: "
                 + ("ON." if current.get("syn_cookies") else "off."))
    lines.append("SSH service is currently "
                 + ("DISABLED." if current.get("ssh_disabled") else "enabled."))
    lines.append("Telnet service is currently "
                 + ("DISABLED." if current.get("telnet_disabled") else "enabled."))
    lines.append("FTP service is currently "
                 + ("DISABLED." if current.get("ftp_disabled") else "enabled."))
    return lines


def security_form(current, cfg):
    have = {r.get("comment", "") for r in current.get("rules", [])}
    def on(key):
        # exact match or "<key>-<suffix>" so e.g. "ddos" doesn't also match the
        # multi-rule "ddos_detect-*" comments.
        pre = _SEC_TAG + key
        return any(c == pre or c.startswith(pre + "-") for c in have)
    return [{"type": "toggle", "name": "opt", "value": "disable_telnet_ftp",
             "label": "Disable Telnet & FTP services",
             "on": bool(current.get("telnet_disabled") and current.get("ftp_disabled")),
             "desc": "Turn off the router's Telnet and FTP servers (/ip service). "
                     "These are legacy plaintext protocols — disable them unless "
                     "you specifically need them."},
            {"type": "toggle", "name": "opt", "value": "syn_cookies",
             "label": "SYN attack — TCP SYN-cookies",
             "on": bool(current.get("syn_cookies")),
             "desc": "Kernel-level SYN-flood defence (/ip settings "
                     "tcp-syncookies=yes). Lets the router weather a SYN flood "
                     "without exhausting connection memory."},
            {"type": "toggle", "name": "opt", "value": "ddos_detect",
             "label": "DDoS attack — auto-detect & blacklist",
             "on": on("ddos_detect"),
             "desc": "Rate-detects DDoS in a detect-ddos chain, flags the "
                     "attacker + target IPs for 10 min, and drops them early in "
                     "raw/prerouting. Adds a forward jump so the detector runs."},
            {"type": "toggle", "name": "opt", "value": "ssh_blacklist",
             "label": "SSH brute-force — staged blacklist", "on": on("ssh_blacklist"),
             "desc": "Escalating tarpit on SSH (port 22): repeat attempts move a "
                     "source through connection1→2→3, then a 1-day "
                     "bruteforce_blacklist that is dropped."},
            {"type": "toggle", "name": "opt", "value": "disable_ssh",
             "label": "Disable the SSH service",
             "on": bool(current.get("ssh_disabled")),
             "desc": "Turn the router's SSH server off entirely (/ip service "
                     "ssh). Manage over WinBox or the tunnel instead. Re-enable "
                     "here any time — reflects the router's current state."}]


def security_plan(pusher, cfg, flat, multi):
    opts = set(multi.get("opt", []))
    desired = []
    if "ddos_detect" in opts:
        # A dedicated detect-ddos chain: rule 1 lets traffic under the rate pass
        # (return); over the rate, the source + target get flagged for 10 min.
        # A forward jump feeds new connections in (the snippet on its own would
        # never run without it). The raw/prerouting drop (below) blocks flagged
        # attacker→target traffic before connection tracking, where it's cheap.
        desired += [
            {"chain": "detect-ddos", "action": "return",
             "dst-limit": "32,32,src-and-dst-addresses/10s",
             "comment": _SEC_TAG + "ddos_detect-1return"},
            {"chain": "detect-ddos", "action": "add-dst-to-address-list",
             "address-list": "ddos-targets", "address-list-timeout": "10m",
             "comment": _SEC_TAG + "ddos_detect-2target"},
            {"chain": "detect-ddos", "action": "add-src-to-address-list",
             "address-list": "ddos-attackers", "address-list-timeout": "10m",
             "comment": _SEC_TAG + "ddos_detect-3src"},
            {"chain": "forward", "connection-state": "new", "action": "jump",
             "jump-target": "detect-ddos",
             "comment": _SEC_TAG + "ddos_detect-4jump"},
        ]
    if "ssh_blacklist" in opts:
        # Staged SSH (port 22) brute-force tarpit: each repeat NEW attempt moves
        # the source connection1 -> 2 -> 3 -> bruteforce_blacklist, then dropped.
        # (Dropped the snippet's `,!secured` two-list matcher — not valid RouterOS
        # syntax and `secured` was never defined — and used a drop instead of the
        # accept rule so it actually blocks regardless of the input policy.)
        ssh_base = {"chain": "input", "protocol": "tcp", "dst-port": "22",
                    "connection-state": "new"}
        desired += [
            {"chain": "input", "protocol": "tcp", "dst-port": "22",
             "src-address-list": "bruteforce_blacklist", "action": "drop",
             "comment": _SEC_TAG + "ssh_blacklist-1drop"},
            {**ssh_base, "src-address-list": "connection3",
             "action": "add-src-to-address-list",
             "address-list": "bruteforce_blacklist", "address-list-timeout": "1d",
             "comment": _SEC_TAG + "ssh_blacklist-2block"},
            {**ssh_base, "src-address-list": "connection2",
             "action": "add-src-to-address-list",
             "address-list": "connection3", "address-list-timeout": "1h",
             "comment": _SEC_TAG + "ssh_blacklist-3stage3"},
            {**ssh_base, "src-address-list": "connection1",
             "action": "add-src-to-address-list",
             "address-list": "connection2", "address-list-timeout": "15m",
             "comment": _SEC_TAG + "ssh_blacklist-4stage2"},
            {**ssh_base, "action": "add-src-to-address-list",
             "address-list": "connection1", "address-list-timeout": "5m",
             "comment": _SEC_TAG + "ssh_blacklist-5stage1"},
        ]
    fw_plan = pusher.plan_managed_list(_FILTER, "comment", desired,
                                       owns=_prefix_owner(_SEC_TAG),
                                       label="security rule")
    # DDoS auto-detect also needs a raw/prerouting drop (a different menu).
    raw_desired = []
    if "ddos_detect" in opts:
        raw_desired.append({"chain": "prerouting", "action": "drop",
                            "src-address-list": "ddos-attackers",
                            "dst-address-list": "ddos-targets",
                            "comment": _SEC_TAG + "ddos_detect-raw"})
    raw_plan = pusher.plan_managed_list(_RAW, "comment", raw_desired,
                                        owns=_prefix_owner(_SEC_TAG),
                                        label="raw rule")
    ops = list(fw_plan.ops) + raw_plan.ops
    # SYN attack — the kernel TCP SYN-cookies setting (/ip settings). Reversible
    # set, only emitted when the desired state differs from the router's, so the
    # toggle (which mirrors the live state) never churns.
    want_syn = "syn_cookies" in opts
    srow = next(iter(pusher.api.fetch(_IP_SETTINGS)), {})
    if srow and (_norm(srow.get("tcp-syncookies", "")) in ("true", "yes")) != want_syn:
        ops.append(Operation(
            "set", _IP_SETTINGS, {"tcp-syncookies": "yes" if want_syn else "no"},
            desc=("enable TCP SYN-cookies" if want_syn
                  else "disable TCP SYN-cookies"),
            inverse=Operation(
                "set", _IP_SETTINGS,
                {"tcp-syncookies": srow.get("tcp-syncookies", "no")},
                desc="restore the TCP SYN-cookies setting")))
    # Disable/enable the SSH service — a reversible `set` on the /ip service ssh
    # row. Only emitted when the desired state differs from what's on the router,
    # so leaving the toggle as-is (it mirrors the live state) never churns or
    # re-enables SSH the user turned off by hand.
    want_disabled = "disable_ssh" in opts
    ssh = next((s for s in pusher.api.fetch(_IP_SERVICE)
                if s.get("name") == "ssh"), None)
    if ssh is not None and _norm(ssh.get("disabled", "")) != (
            "true" if want_disabled else "false"):
        ops.insert(0, Operation(
            "set", _IP_SERVICE,
            {".id": ssh[".id"], "disabled": "yes" if want_disabled else "no"},
            desc=("disable the SSH service" if want_disabled
                  else "enable the SSH service"),
            inverse=Operation(
                "set", _IP_SERVICE,
                {".id": ssh[".id"], "disabled": ssh.get("disabled", "no")},
                desc="restore the SSH service to its previous state")))
    want_tf_disabled = "disable_telnet_ftp" in opts
    all_services = pusher.api.fetch(_IP_SERVICE)
    for svc_name in ("telnet", "ftp"):
        svc = next((s for s in all_services if s.get("name") == svc_name), None)
        if svc is not None and _norm(svc.get("disabled", "")) != (
                "true" if want_tf_disabled else "false"):
            ops.insert(0, Operation(
                "set", _IP_SERVICE,
                {".id": svc[".id"], "disabled": "yes" if want_tf_disabled else "no"},
                desc=(f"disable the {svc_name.upper()} service" if want_tf_disabled
                      else f"enable the {svc_name.upper()} service"),
                inverse=Operation(
                    "set", _IP_SERVICE,
                    {".id": svc[".id"], "disabled": svc.get("disabled", "no")},
                    desc=f"restore the {svc_name.upper()} service to its previous state")))
    return Plan(cfg.name, ops, summary="security")


# ===========================================================================
# DNS — content filtering: DNS servers + a bypass address-list
# ===========================================================================
_DNS = ("ip", "dns")
_ADDR_LIST = ("ip", "firewall", "address-list")
_NAT = ("ip", "firewall", "nat")
_DNSFORCE_TAG = "mikromon:dnsforce:"

# Quick DNS presets — point the router's resolver at a known public DNS with one
# switch. (value, label, "primary,secondary"). Rendered as mutually-exclusive
# toggles (only one on at a time); all off = use the manually-typed servers.
_DNS_PRESETS = [
    ("adguard_default", "AdGuard — block ads & trackers",
     "94.140.14.14,94.140.15.15"),
    ("adguard_family", "AdGuard Family — ads, trackers, adult + Safe Search",
     "94.140.14.15,94.140.15.16"),
    ("adguard_nofilter", "AdGuard — no filtering (just fast, private DNS)",
     "94.140.14.140,94.140.14.141"),
    ("opendns", "OpenDNS — safe browsing",
     "208.67.222.222,208.67.220.220"),
    ("google", "Google Public DNS",
     "8.8.8.8,8.8.4.4"),
    ("cloudflare", "Cloudflare — fast & private",
     "1.1.1.1,1.0.0.1"),
]
_DNS_PRESET_SERVERS = {k: s for k, _label, s in _DNS_PRESETS}


def _server_set(s):
    """Order-insensitive set of the IPs in a comma-separated servers string."""
    return frozenset(x.strip() for x in str(s or "").split(",") if x.strip())


def _active_preset(dns):
    """Which provider preset the router's DNS currently matches, so its toggle
    shows on. Tolerant on purpose: matches if ANY of a provider's IPs appears in
    the configured OR dynamic (WAN-learned) servers — so it still detects the
    provider when only the primary is set, the order differs, or an extra server
    is present. '' when nothing matches (a custom/unknown DNS)."""
    live = (_server_set(dns.get("servers", ""))
            | _server_set(dns.get("dynamic-servers", "")))
    return next((k for k, s in _DNS_PRESET_SERVERS.items()
                 if live & _server_set(s)), "")


def nextdns_read(pusher, cfg):
    dns = pusher.api.fetch(_DNS)
    bypass = [r for r in pusher.api.fetch(_ADDR_LIST)
              if str(r.get("list", "")) == DNS_BYPASS_LIST]
    static = [r for r in pusher.api.fetch(_DNS_STATIC)
              if str(r.get("comment", "")).startswith(_DNSBLOCK_TAG)]
    forced = [r for r in pusher.api.fetch(_NAT)
              if str(r.get("comment", "")).startswith(_DNSFORCE_TAG)]
    return {"dns": dns[0] if dns else {}, "bypass": bypass,
            "static": static, "forced": forced}


def nextdns_summary(current, cfg):
    dns = current.get("dns", {})
    out = [f"DNS servers: {dns.get('servers', '(none)')}",
           f"allow-remote-requests: {dns.get('allow-remote-requests', '?')}"]
    out.append(f"{len(current.get('bypass', []))} bypass address(es)")
    out.append("Force client DNS: " +
               ("on" if current.get("forced") else "off"))
    groups = sorted({str(r.get("comment", ""))[len(_DNSBLOCK_TAG):]
                     for r in current.get("static", [])})
    if groups:
        labels = [_BLOCK_BY_KEY.get(g, (g, []))[0] for g in groups]
        out.append("Blocking: " + ", ".join(labels))
    return out


# DNS-static "sinkhole" blocking: each toggle maps to a curated set of domains
# answered as 0.0.0.0 on the router. Starter lists — extend per site as needed.
_DNS_STATIC = ("ip", "dns", "static")
_DNSBLOCK_TAG = "mikromon:dnsblock:"
_BLOCK_GROUPS = [
    ("Categories", [
        ("ads", "Advertisements & trackers",
         ["doubleclick.net", "googlesyndication.com", "googleadservices.com",
          "adservice.google.com", "g.doubleclick.net", "ads.yahoo.com",
          "advertising.com", "adnxs.com", "scorecardresearch.com"]),
        ("porn", "Pornography",
         ["pornhub.com", "xvideos.com", "xnxx.com", "xhamster.com",
          "redtube.com", "youporn.com"]),
        ("gambling", "Gambling",
         ["bet365.com", "pokerstars.com", "888casino.com", "betway.com",
          "williamhill.com"]),
        ("social", "Social networks",
         ["facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com",
          "twitter.com", "x.com", "tiktok.com", "tiktokcdn.com",
          "snapchat.com", "reddit.com", "pinterest.com"]),
        ("streaming", "Video streaming",
         ["netflix.com", "nflxvideo.net", "youtube.com", "googlevideo.com",
          "ytimg.com", "hulu.com", "twitch.tv", "primevideo.com"]),
        ("gaming", "Online gaming",
         ["steampowered.com", "epicgames.com", "roblox.com", "ea.com",
          "battle.net", "leagueoflegends.com"]),
    ]),
    ("Apps", [
        ("app_tiktok", "TikTok", ["tiktok.com", "tiktokcdn.com", "tiktokv.com"]),
        ("app_facebook", "Facebook", ["facebook.com", "fbcdn.net", "fb.com"]),
        ("app_instagram", "Instagram", ["instagram.com", "cdninstagram.com"]),
        ("app_whatsapp", "WhatsApp", ["whatsapp.com", "whatsapp.net"]),
        ("app_youtube", "YouTube",
         ["youtube.com", "googlevideo.com", "ytimg.com", "youtu.be"]),
        ("app_netflix", "Netflix", ["netflix.com", "nflxvideo.net", "nflximg.net"]),
        ("app_snapchat", "Snapchat", ["snapchat.com", "sc-cdn.net"]),
        ("app_discord", "Discord", ["discord.com", "discordapp.com", "discord.gg"]),
        ("app_telegram", "Telegram", ["telegram.org", "telegram.me", "t.me"]),
    ]),
]
_BLOCK_BY_KEY = {k: (label, doms) for _g, items in _BLOCK_GROUPS
                 for k, label, doms in items}


def _domain_regexp(domain):
    """Match the domain and any subdomain (RouterOS POSIX regexp)."""
    return r".*" + domain.replace(".", r"\.") + "$"


def nextdns_form(current, cfg):
    dns = current.get("dns", {})
    ips = "\n".join(r.get("address", "") for r in current.get("bypass", []))
    blocked = {str(r.get("comment", ""))[len(_DNSBLOCK_TAG):]
               for r in current.get("static", [])}
    cur_ip = next((r.get("address") for r in current.get("static", [])
                   if r.get("address")), "") or "127.0.0.1"
    cur_preset = _active_preset(dns)
    fields = [
        {"type": "static", "label": "Quick DNS provider",
         "value": "Flip one on to point the router at that DNS — only one at a "
                  "time (turning one on switches the others off). The one that "
                  "matches the router's current DNS is shown on. Leave them all "
                  "off to keep the current DNS unchanged."},
    ]
    for k, label, _servers in _DNS_PRESETS:
        fields.append({"type": "toggle", "name": "dns_preset", "value": k,
                       "label": label, "on": k == cur_preset,
                       "exclusive": "dns_preset"})
    fields += [
        {"type": "toggle", "name": "opt", "value": "allow_remote",
         "label": "Allow remote DNS requests",
         "on": _norm(dns.get("allow-remote-requests", "")) == "true",
         "hint": "Must be ON for the router to answer client DNS — blocking does "
                 "nothing without it. (Turned on automatically when you force "
                 "client DNS below.)"},
        {"type": "toggle", "name": "opt", "value": "force_dns",
         "label": "Force all client DNS through this router",
         "on": bool(current.get("forced")),
         "hint": "Redirects every client's port-53 traffic to the router (NAT) so "
                 "a device hard-coded to 8.8.8.8 can't bypass the blocks. Needed "
                 "for the filtering to actually take effect."},
        {"type": "textarea", "name": "bypass", "label": "Bypass IPs (one per line)",
         "value": ips, "hint": "Hosts allowed to skip the filter."},
        {"type": "text", "name": "block_ip",
         "label": "Blocked domains resolve to (sinkhole IP)", "value": cur_ip,
         "hint": "Where blocked names point. RouterOS rejects 0.0.0.0 here; "
                 "127.0.0.1 is a safe blackhole. Use a block-page IP if you have "
                 "one."},
    ]
    for group, items in _BLOCK_GROUPS:
        fields.append({"type": "static", "label": f"Block {group.lower()}",
                       "value": "Answers these domains as 0.0.0.0 on the router "
                                "(DNS sinkhole). Starter lists — extendable."})
        for key, label, _doms in items:
            fields.append({"type": "toggle", "name": "block", "value": key,
                           "label": label, "on": key in blocked})
    return fields


def nextdns_plan(pusher, cfg, flat, multi):
    opts = set(multi.get("opt", []))
    force_dns = "force_dns" in opts
    # A switched-on provider preset sets the DNS servers. The toggles are
    # mutually exclusive in the UI, but if more than one arrives (e.g. no JS)
    # just take the first. With NONE on we leave /ip dns servers untouched
    # (the servers field was removed from the form).
    chosen = [k for k in multi.get("dns_preset", []) if k in _DNS_PRESET_SERVERS]
    # RouterOS returns true/false here, so send true/false (not yes/no) to avoid
    # a perpetual no-op diff. Forcing client DNS only works if the router answers
    # DNS, so allow-remote-requests is implied on when force_dns is on.
    desired_dns = {"allow-remote-requests": "true" if ("allow_remote" in opts
                   or force_dns) else "false"}
    if chosen:
        desired_dns["servers"] = _DNS_PRESET_SERVERS[chosen[0]]
    plan = pusher.plan_settings(_DNS, desired_dns, label="dns")
    ips = [x.strip() for x in (flat.get("bypass", "") or "").splitlines()
           if x.strip()]
    desired_list = [{"list": DNS_BYPASS_LIST, "address": ip} for ip in ips]
    list_plan = pusher.plan_managed_list(
        _ADDR_LIST, "address", desired_list,
        manage_tag="mikromon:dns-bypass",
        owns=lambda r: str(r.get("list", "")) == DNS_BYPASS_LIST,
        label="bypass")
    # category / app DNS-sinkhole entries (0.0.0.0 is rejected by RouterOS as an
    # A record, so use a real blackhole IP — 127.0.0.1 by default).
    block_ip = (flat.get("block_ip", "") or "").strip() or "127.0.0.1"
    enabled = set(multi.get("block", []))
    static_desired = []
    for key in enabled:
        _label, doms = _BLOCK_BY_KEY.get(key, ("", []))
        for d in doms:
            static_desired.append({"regexp": _domain_regexp(d),
                                   "address": block_ip,
                                   "comment": _DNSBLOCK_TAG + key})
    static_plan = pusher.plan_managed_list(
        _DNS_STATIC, "regexp", static_desired,
        owns=_prefix_owner(_DNSBLOCK_TAG), label="dns block")
    # Force-DNS: redirect client port-53 traffic to the router so hard-coded
    # resolvers can't slip past the sinkhole. dstnat/redirect only sees client
    # (forwarded) traffic in prerouting, so the router's own DNS is untouched.
    force_desired = []
    if force_dns:
        for proto in ("udp", "tcp"):
            force_desired.append({
                "chain": "dstnat", "protocol": proto, "dst-port": "53",
                "action": "redirect", "to-ports": "53",
                "comment": _DNSFORCE_TAG + proto})
    force_plan = pusher.plan_managed_list(
        _NAT, "comment", force_desired,
        owns=_prefix_owner(_DNSFORCE_TAG), label="dns redirect")
    return Plan(cfg.name,
                plan.ops + list_plan.ops + static_plan.ops + force_plan.ops,
                summary="dns filter")


# ===========================================================================
# QoS — simple queues with up/down limits
# ===========================================================================
_QUEUE = ("queue", "simple")
_QOS_TAG = "mikromon:qos:"


def qos_read(pusher, cfg):
    return [r for r in pusher.api.fetch(_QUEUE) if _prefix_owner(_QOS_TAG)(r)]


def qos_unmanaged(pusher, cfg):
    out = []
    for r in pusher.api.fetch(_QUEUE):
        if not _prefix_owner(_QOS_TAG)(r):
            out.append({"id": r.get(".id"),
                        "text": f"{r.get('name')} → {r.get('target', '?')} "
                                f"({r.get('max-limit', '?')})"})
    return out


def qos_summary(current, cfg):
    return [f"{r.get('name')} → {r.get('target')} ({r.get('max-limit')})"
            for r in current] or ["No mikromon-managed queues yet."]


def qos_form(current, cfg):
    rows = []
    for r in current:
        up, _, down = str(r.get("max-limit", "/")).partition("/")
        rows.append({"name": r.get("name", ""), "target": r.get("target", ""),
                     "down": down.replace("M", ""), "up": up.replace("M", ""),
                     "off": "yes" if _norm(r.get("disabled", "")) == "true" else ""})
    return [{"type": "rows", "name": "q", "label": "Queues (speed limits)",
             "cols": [("name", "name", "office"),
                      ("target", "target subnet/iface/IP", "192.168.88.10"),
                      ("down", "download Mbps", "50"),
                      ("up", "upload Mbps", "20"),
                      ("off", "paused? (yes)", "")],
             "rows": rows,
             "hint": "Each row is a speed limit (simple queue). max-limit is "
                     "upload/download. Put 'yes' in the last column to PAUSE a "
                     "limit (disable it) without deleting it; clear it to resume. "
                     "Blank rows are ignored."}]


def qos_plan(pusher, cfg, flat, multi):
    # Keyed by the queue name (preserved as-is) so adopted queues round-trip.
    desired = []
    for r in _rows(multi, "q", ("name", "target", "down", "up", "off")):
        if not r["name"] or not r["target"]:
            continue
        down = (r["down"] or "0") + "M"
        up = (r["up"] or "0") + "M"
        paused = r["off"].strip().lower() in ("yes", "y", "1", "true", "off")
        # RouterOS prints disabled as true/false — use the same token so an
        # unchanged queue produces no diff (no perpetual churn).
        desired.append({"name": r["name"], "target": r["target"],
                        "max-limit": f"{up}/{down}",
                        "disabled": "true" if paused else "false",
                        "comment": _QOS_TAG + r["name"]})
    return pusher.plan_managed_list(_QUEUE, "name", desired,
                                    owns=_prefix_owner(_QOS_TAG), label="queue")


# ===========================================================================
# Port forwarding — dst-nat rules
# ===========================================================================
_NAT = ("ip", "firewall", "nat")
_PF_TAG = "mikromon:pf:"


def portfwd_read(pusher, cfg):
    return [r for r in pusher.api.fetch(_NAT) if _prefix_owner(_PF_TAG)(r)]


def portfwd_unmanaged(pusher, cfg):
    """Existing dst-nat rules we don't own yet (safe to adopt as port-forwards)."""
    out = []
    for r in pusher.api.fetch(_NAT):
        if (not _prefix_owner(_PF_TAG)(r) and str(r.get("chain")) == "dstnat"
                and str(r.get("action")) == "dst-nat"):
            out.append({"id": r.get(".id"),
                        "text": f"{r.get('protocol', '?')}/{r.get('dst-port', '?')}"
                                f" → {r.get('to-addresses', '?')}:"
                                f"{r.get('to-ports', '?')}"})
    return out


def portfwd_summary(current, cfg):
    return [f"{r.get('protocol')}/{r.get('dst-port')} → {r.get('to-addresses')}:"
            f"{r.get('to-ports')}" for r in current] or \
           ["No mikromon port-forwards on the router yet."]


def portfwd_form(current, cfg):
    rows = [{"name": r.get("comment", "")[len(_PF_TAG):],
             "proto": r.get("protocol", "tcp"), "dport": r.get("dst-port", ""),
             "toaddr": r.get("to-addresses", ""), "toport": r.get("to-ports", "")}
            for r in current]
    return [{"type": "rows", "name": "pf", "label": "Port forwards",
             "cols": [("name", "name", "web"), ("proto", "tcp/udp", "tcp"),
                      ("dport", "external port", "8080"),
                      ("toaddr", "internal IP", "192.168.88.10"),
                      ("toport", "internal port", "80")],
             "rows": rows}]


def portfwd_plan(pusher, cfg, flat, multi):
    desired = []
    for r in _rows(multi, "pf", ("name", "proto", "dport", "toaddr", "toport")):
        if not r["name"] or not r["dport"] or not r["toaddr"]:
            continue
        desired.append({"chain": "dstnat", "action": "dst-nat",
                        "protocol": (r["proto"] or "tcp").lower(),
                        "dst-port": r["dport"], "to-addresses": r["toaddr"],
                        "to-ports": r["toport"] or r["dport"],
                        "comment": _PF_TAG + r["name"]})
    return pusher.plan_managed_list(_NAT, "comment", desired,
                                    owns=_prefix_owner(_PF_TAG), label="port-forward")


# ===========================================================================
# Interfaces — read-only inventory of ports / VLANs / bridges
# ===========================================================================
def interfaces_read(pusher, cfg):
    ifaces = pusher.api.fetch(("interface",))
    try:
        addrs = pusher.api.fetch(("ip", "address"))
    except Exception:  # noqa: BLE001 — keep working if /ip/address is unreadable
        addrs = []
    return {"ifaces": ifaces, "addrs": addrs}


def interfaces_summary(current, cfg):
    ifaces = current.get("ifaces", []) if isinstance(current, dict) else current
    up = sum(1 for r in ifaces if _norm(r.get("running", "")) == "true")
    by_type = {}
    for r in ifaces:
        t = str(r.get("type", "?"))
        by_type[t] = by_type.get(t, 0) + 1
    kinds = ", ".join(f"{n}× {t}" for t, n in sorted(by_type.items()))
    return [f"{len(ifaces)} interfaces, {up} running", f"types: {kinds}"]


# ===========================================================================
# Remote access — a temporary allow rule for Winbox/SSH/WebFig
# ===========================================================================
_REMOTE_TAG = "mikromon:remote:"
_SERVICES = {"winbox": "8291", "ssh": "22", "webfig": "80"}


def remote_read(pusher, cfg):
    return [r for r in pusher.api.fetch(_FILTER) if _prefix_owner(_REMOTE_TAG)(r)]


def remote_summary(current, cfg):
    return [f"allow {r.get('dst-port')} from {r.get('src-address')}"
            for r in current] or ["No temporary access rules right now."]


def remote_form(current, cfg):
    return [
        {"type": "select", "name": "service", "label": "Service",
         "options": [("winbox", "Winbox (8291)"), ("ssh", "SSH (22)"),
                     ("webfig", "WebFig (80)")], "value": "winbox"},
        {"type": "text", "name": "src", "label": "Allow from IP",
         "placeholder": "your public IP, e.g. 41.x.x.x"},
        {"type": "static", "label": "Note",
         "value": "Adds an accept rule at the top of the input chain. Auto-expiry "
                  "needs an on-router scheduler (coming with provisioning) — for "
                  "now, revoke it here when done."},
    ]


def remote_plan(pusher, cfg, flat, multi):
    svc = flat.get("service", "winbox")
    port = _SERVICES.get(svc, "8291")
    src = flat.get("src", "").strip()
    # keep existing temp rules, add/refresh the requested one
    existing = remote_read(pusher, cfg)
    desired = [{"chain": "input", "action": "accept", "protocol": "tcp",
                "dst-port": r.get("dst-port"), "src-address": r.get("src-address"),
                "comment": r.get("comment")} for r in existing]
    if src:
        desired.append({"chain": "input", "action": "accept", "protocol": "tcp",
                        "dst-port": port, "src-address": src,
                        "comment": _REMOTE_TAG + f"{svc}-{src}"})
    return pusher.plan_managed_list(_FILTER, "comment", desired,
                                    owns=_prefix_owner(_REMOTE_TAG),
                                    label="remote-access rule")


# ===========================================================================
# Tunnel — WireGuard VPN (RouterOS 7.1+ only; graceful notice on v6/unknown)
# ===========================================================================
_WG_IFACE = ("interface", "wireguard")
_WG_PEERS = ("interface", "wireguard", "peers")
_WG_TAG = "mikromon:wg:"


def _ros_version(api):
    """Return (major, minor, full_string) from /system/resource.

    Returns (0, 0, "unknown") when the version cannot be read.
    Examples: "7.14.3" → (7, 14, "7.14.3"), "6.49.8" → (6, 49, "6.49.8").
    """
    try:
        res = api.fetch(("system", "resource"))
        ver = str(res[0].get("version", "")) if res else ""
        if not ver:
            return (0, 0, "unknown")
        parts = ver.split(".")
        major = int(parts[0]) if parts[0].isdigit() else 0
        minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        return (major, minor, ver)
    except Exception:
        return (0, 0, "unknown")


def _wg_supported(major, minor):
    """WireGuard requires RouterOS 7.1+. Unknown version (0,0) → attempt anyway."""
    if major == 0:
        return True   # version undetectable; try and let error handling catch it
    return (major, minor) >= (7, 1)


def tunnel_read(pusher, cfg):
    major, minor, ver_str = _ros_version(pusher.api)
    if not _wg_supported(major, minor):
        return {"version": ver_str, "ifaces": [], "peers": [], "unsupported": True}
    try:
        ifaces = pusher.api.fetch(_WG_IFACE)
        peers = pusher.api.fetch(_WG_PEERS)
        return {"version": ver_str, "ifaces": ifaces, "peers": peers}
    except Exception as exc:
        msg = str(exc)
        # API rejects the WireGuard menu on firmware that predates it.
        if any(kw in msg.lower()
               for kw in ("no such command", "bad command", "invalid command")):
            return {"version": ver_str, "ifaces": [], "peers": [], "unsupported": True}
        return {"version": ver_str, "ifaces": [], "peers": [], "error": msg}


def tunnel_summary(current, cfg):
    if current.get("unsupported"):
        v = current.get("version", "unknown")
        return [f"WireGuard requires RouterOS 7.1+. This router runs {v}."]
    error = current.get("error")
    if error:
        return [f"Could not read WireGuard data: {error}"]
    ifaces = current.get("ifaces", [])
    peers = current.get("peers", [])
    if not ifaces:
        return ["No WireGuard interfaces configured on this router yet."]
    lines = []
    for i in ifaces:
        up = i.get("running") in ("true", True)
        lines.append(f"{i.get('name', '?')} · port {i.get('listen-port', '?')}"
                     f" · {'running' if up else 'down'}")
    managed = sum(1 for p in peers
                  if str(p.get("comment", "")).startswith(_WG_TAG))
    lines.append(f"{len(peers)} peer(s) total, {managed} managed by mikromon")
    return lines


def tunnel_unmanaged(pusher, cfg):
    major, minor, _ver = _ros_version(pusher.api)
    if not _wg_supported(major, minor):
        return []
    try:
        peers = pusher.api.fetch(_WG_PEERS)
    except Exception:
        return []
    out = []
    for p in peers:
        if not str(p.get("comment", "")).startswith(_WG_TAG):
            ea = p.get("endpoint-address", "")
            ep = p.get("endpoint-port", "")
            ep_str = f"{ea}:{ep}" if ea and ep else ea or "(no endpoint)"
            out.append({
                "id": p.get(".id"),
                "text": (f"…{p.get('public-key', '?')[-12:]} · {ep_str}"
                         f" · {p.get('allowed-address', '?')}"),
            })
    return out


def tunnel_form(current, cfg):
    if current.get("unsupported"):
        v = current.get("version", "unknown")
        return [{"type": "static", "label": "Not supported on this firmware",
                 "value": (f"WireGuard is available on RouterOS 7.1 and later. "
                           f"This router is running {v}. "
                           f"Upgrade to 7.1+ to use the Tunnel tab.")}]
    ifaces = current.get("ifaces", [])
    managed_peers = [p for p in current.get("peers", [])
                     if str(p.get("comment", "")).startswith(_WG_TAG)]
    rows = []
    for p in managed_peers:
        lbl = p.get("comment", "")[len(_WG_TAG):]
        ea = p.get("endpoint-address", "")
        eport = p.get("endpoint-port", "")
        endpoint = f"{ea}:{eport}" if ea and eport else ea
        rows.append({
            "name": lbl,
            "iface": p.get("interface", ""),
            "pubkey": p.get("public-key", ""),
            "endpoint": endpoint,
            "allowed": p.get("allowed-address", ""),
            "keepalive": str(p.get("persistent-keepalive", "")),
        })

    fields = []
    if not ifaces:
        fields.append({
            "type": "static", "label": "No WireGuard interfaces yet",
            "value": ("Fill in a name and port below to create the first interface. "
                      "The router generates the key pair automatically."),
        })
        fields.append({"type": "text", "name": "new_iface_name",
                        "label": "Interface name", "placeholder": "wg0", "value": ""})
        fields.append({"type": "text", "name": "new_iface_port",
                        "label": "Listen port", "placeholder": "13231", "value": ""})
    else:
        iface_lines = []
        for i in ifaces:
            pk = i.get("public-key") or "(generating…)"
            iface_lines.append(f"{i.get('name')}: port {i.get('listen-port', '?')}"
                                f"  ·  public key: {pk}")
        fields.append({
            "type": "static", "label": "WireGuard interfaces (read-only)",
            "value": "\n".join(iface_lines),
        })
        iface_opts = [(i.get("name", ""), i.get("name", "")) for i in ifaces]
        fields.append({
            "type": "select", "name": "peer_iface", "label": "Attach new peers to",
            "options": iface_opts,
            "value": iface_opts[0][0] if iface_opts else "",
        })

    fields.append({
        "type": "rows", "name": "wgp", "label": "Peers",
        "cols": [
            ("name",      "name / label",            "site-a"),
            ("pubkey",    "peer public key",          "abc123…"),
            ("endpoint",  "endpoint  ip:port",        "203.0.113.1:51820"),
            ("allowed",   "allowed addresses (CIDR)", "10.0.1.0/24"),
            ("keepalive", "keepalive (s)",             "25"),
        ],
        "rows": rows,
        "hint": ("Public key must match the remote peer's WireGuard public key. "
                 "Leave endpoint blank for dial-in / road-warrior peers."),
    })
    return fields


def _wg_adopt_name(row):
    existing = row.get("comment", "")
    if existing:
        return _slug(existing, "peer")
    return _slug(row.get("public-key", "")[:16], "peer")


def tunnel_plan(pusher, cfg, flat, multi):
    major, minor, ver_str = _ros_version(pusher.api)
    if not _wg_supported(major, minor):
        return Plan(cfg.name, [],
                    summary=f"wireguard not available (RouterOS {ver_str}, requires 7.1+)")
    ops = []
    try:
        ifaces = pusher.api.fetch(_WG_IFACE)
    except Exception:
        ifaces = []
    if not ifaces:
        new_name = (flat.get("new_iface_name", "") or "").strip()
        new_port = (flat.get("new_iface_port", "") or "13231").strip()
        if new_name:
            ops.append(Operation(
                "add", _WG_IFACE,
                {"name": new_name, "listen-port": new_port},
                desc=f"add WireGuard interface '{new_name}' on port {new_port}",
                inverse=Operation(
                    "remove", _WG_IFACE, {".id": ""},
                    desc=f"remove WireGuard interface '{new_name}'")))
            ifaces = [{"name": new_name}]
    peer_iface = (flat.get("peer_iface", "").strip()
                  or (ifaces[0].get("name", "wg0") if ifaces else "wg0"))
    desired_peers = []
    for r in _rows(multi, "wgp", ("name", "pubkey", "endpoint", "allowed", "keepalive")):
        if not r["name"] or not r["pubkey"]:
            continue
        ep = r.get("endpoint", "").strip()
        # rpartition handles "1.2.3.4:51820" correctly; bare IPs get ep_port=""
        ep_addr, _, ep_port = ep.rpartition(":")
        if not ep_addr:
            ep_addr, ep_port = ep, ""
        peer = {
            "interface": peer_iface,
            "public-key": r["pubkey"].strip(),
            "allowed-address": (r["allowed"].strip() or "0.0.0.0/0,::/0"),
            "comment": _WG_TAG + r["name"],
        }
        if ep_addr:
            peer["endpoint-address"] = ep_addr
        if ep_port:
            peer["endpoint-port"] = ep_port
        ka = r.get("keepalive", "").strip()
        if ka:
            peer["persistent-keepalive"] = ka
        desired_peers.append(peer)
    peer_plan = pusher.plan_managed_list(
        _WG_PEERS, "public-key", desired_peers,
        owns=_prefix_owner(_WG_TAG), label="wg-peer")
    return Plan(cfg.name, ops + peer_plan.ops, summary="wireguard tunnel")


# ===========================================================================
# Custom scripts — the universal escape hatch: paste any RouterOS script, add
# it to /system/script (tagged so we own it), Run it on demand, Remove it later.
# Anything the typed tabs don't cover can be done here, still dry-run-first,
# logged and (for add/remove) reversible.
# ===========================================================================
_SCRIPT = ("system", "script")
_SCRIPT_TAG = "mikromon:script:"
# Full RouterOS policy set so a Run actually has rights to change config.
_SCRIPT_POLICY = ("ftp,reboot,read,write,policy,test,password,sniff,"
                  "sensitive,romon")


def scripts_read(pusher, cfg):
    return [r for r in pusher.api.fetch(_SCRIPT) if _prefix_owner(_SCRIPT_TAG)(r)]


def scripts_summary(current, cfg):
    return [f"{r.get('name')} — {len((r.get('source') or ''))} chars"
            + (f" · last run {r['last-started']}" if r.get("last-started") else "")
            for r in current] or ["No mikromon-managed scripts on the router yet."]


def scripts_form(current, cfg):
    return [
        {"type": "text", "name": "new_name", "label": "Script name",
         "placeholder": "block-badnet"},
        {"type": "textarea", "name": "new_source",
         "label": "Script source (RouterOS commands)", "value": "",
         "hint": "Paste a RouterOS script. Saving adds it to /system script "
                 "(tagged so mikromon owns it) — it does not run yet. Use the "
                 "Run button on a saved script to execute it. Re-saving with the "
                 "same name updates the source."},
    ]


def _managed_desired(existing):
    """Reconstruct the current managed scripts as a desired list (preserve)."""
    return [{"name": r.get("name"), "source": r.get("source", ""),
             "comment": r.get("comment") or (_SCRIPT_TAG + str(r.get("name")))}
            for r in existing]


def scripts_plan(pusher, cfg, flat, multi):
    existing = scripts_read(pusher, cfg)
    action = flat.get("script_action", "")
    target = flat.get("script_name", "")

    if action == "run":
        row = next((r for r in existing if r.get("name") == target), None)
        if row is None:
            return Plan(cfg.name, [], summary="run script (not found)")
        op = Operation("run", _SCRIPT, {"_cmd": "run", ".id": row[".id"]},
                       desc=f"run script '{target}' on the router (background)",
                       detach=True)
        return Plan(cfg.name, [op], summary=f"run script {target}")

    if action == "remove":
        desired = [d for d in _managed_desired(existing) if d["name"] != target]
        return pusher.plan_managed_list(_SCRIPT, "name", desired,
                                        owns=_prefix_owner(_SCRIPT_TAG),
                                        label="script")

    # default: add / update from the form
    nm = _slug(flat.get("new_name", ""), "")
    src = flat.get("new_source", "")
    is_new = nm not in {d["name"] for d in _managed_desired(existing)}
    desired = [d for d in _managed_desired(existing) if d["name"] != nm]
    if nm and src.strip():
        row = {"name": nm, "source": src, "comment": _SCRIPT_TAG + nm}
        if is_new:
            # A script created over the API inherits a *restricted* policy, so
            # when Run fires it later it silently can't touch /ip, /interface,
            # etc. Stamp the full policy + dont-require-permissions on creation
            # so the script actually executes. Only on the initial add — these
            # are read-back in a different form, so we never re-compare them
            # (no perpetual diff when re-saving).
            row["policy"] = _SCRIPT_POLICY
            row["dont-require-permissions"] = "yes"
        desired.append(row)
    return pusher.plan_managed_list(_SCRIPT, "name", desired,
                                    owns=_prefix_owner(_SCRIPT_TAG), label="script")


# ===========================================================================
# Restrict management access — the brute-force fix. Locks the management
# services (API / Winbox / SSH / WebFig) to trusted source IPs via /ip service,
# disables insecure services, and drops known attacker IPs. Per-row `set`s with
# inverses (fully reversible) plus a tagged block-list + drop rule.
# ===========================================================================
_SERVICE = ("ip", "service")
_HARDEN_TAG = "mikromon:harden:"
_BLOCK_LIST = "mikromon-blocked"
# service name -> (label, default-restrict?)
_MGMT_SVC = [("api", "API (8728)", True), ("api-ssl", "API-SSL (8729)", True),
             ("winbox", "Winbox (8291)", True), ("ssh", "SSH (22)", True),
             ("www", "WebFig HTTP (80)", False),
             ("www-ssl", "WebFig HTTPS (443)", False)]
_INSECURE_SVC = [("telnet", "Telnet (23)"), ("ftp", "FTP (21)")]


def harden_read(pusher, cfg):
    return pusher.api.fetch(_SERVICE)


def harden_summary(current, cfg):
    by = {s.get("name"): s for s in current}
    out = []
    for name, label, _d in _MGMT_SVC + [(n, l, False) for n, l in _INSECURE_SVC]:
        s = by.get(name)
        if s is None:
            continue
        if _norm(s.get("disabled", "")) == "true":
            out.append(f"{label}: disabled")
        else:
            addr = s.get("address") or "ANY (open to the internet!)"
            out.append(f"{label}: allowed from {addr}")
    return out or ["No /ip service rows found."]


def harden_form(current, cfg):
    by = {s.get("name"): s for s in current}
    cur_addr = ((by.get("api") or {}).get("address")
                or (by.get("winbox") or {}).get("address") or "")
    fields = [
        {"type": "text", "name": "allowed",
         "label": "Allow management ONLY from these IPs/subnets (comma-separated)",
         "value": cur_addr,
         "placeholder": "102.36.140.219/32, 192.168.88.0/24",
         "hint": "Applied to the services ticked below. ⚠ Include this monitoring "
                 "server's public IP (and your own admin IP) or you will lock "
                 "mikromon — and yourself — out. Leave blank to skip service "
                 "restriction and only block attackers below."},
        {"type": "static", "label": "Restrict these management services",
         "value": ""},
    ]
    for name, label, default in _MGMT_SVC:
        s = by.get(name)
        if s is None:
            continue
        addr = s.get("address") or "anywhere"
        fields.append({"type": "toggle", "name": "svc", "value": name,
                       "label": f"Restrict {label}", "on": default,
                       "desc": f"currently allowed from: {addr}"})
    fields.append({"type": "static", "label": "Disable insecure services",
                   "value": ""})
    for name, label in _INSECURE_SVC:
        s = by.get(name)
        disabled = s is not None and _norm(s.get("disabled", "")) == "true"
        fields.append({"type": "toggle", "name": "disable", "value": name,
                       "label": f"Disable {label}", "on": disabled,
                       "desc": "already disabled" if disabled else
                               "plaintext / legacy — safe to turn off"})
    fields.append({"type": "text", "name": "block",
                   "label": "Block these attacker IPs (comma-separated)",
                   "placeholder": "45.198.224.18",
                   "hint": "Added to a drop list at the top of the input chain."})
    return fields


def _service_set(row, field, value, label):
    """A reversible set on one /ip service row."""
    return _set_field(_SERVICE, row, field, value, label)


def harden_plan(pusher, cfg, flat, multi):
    services = pusher.api.fetch(_SERVICE)
    by = {s.get("name"): s for s in services}
    allowed = ",".join(x.strip() for x in flat.get("allowed", "").split(",")
                       if x.strip())
    svc = set(multi.get("svc", []))
    disable = set(multi.get("disable", []))
    ops = []
    if allowed:
        for name in svc:
            row = by.get(name)
            if row is None:
                continue
            if _norm(row.get("address", "")) != _norm(allowed):
                ops.append(_service_set(row, "address", allowed, f"service {name}"))
            if _norm(row.get("disabled", "")) == "true":
                ops.append(_service_set(row, "disabled", "no", f"service {name}"))
    for name in disable:
        row = by.get(name)
        if row is None or _norm(row.get("disabled", "")) == "true":
            continue
        ops.append(_service_set(row, "disabled", "yes", f"service {name}"))
    # block attacker IPs: a managed address-list + one drop rule (own tag)
    block = [x.strip() for x in (flat.get("block", "") or "").split(",")
             if x.strip()]
    extra = []
    if block:
        desired_list = [{"list": _BLOCK_LIST, "address": ip} for ip in block]
        list_plan = pusher.plan_managed_list(
            _ADDR_LIST, "address", desired_list,
            owns=lambda r: str(r.get("list", "")) == _BLOCK_LIST,
            label="blocked IP")
        drop = [{"chain": "input", "action": "drop",
                 "src-address-list": _BLOCK_LIST,
                 "comment": _HARDEN_TAG + "block-attackers"}]
        drop_plan = pusher.plan_managed_list(
            _FILTER, "comment", drop,
            owns=_prefix_owner(_HARDEN_TAG + "block-attackers"),
            label="block rule")
        extra = list_plan.ops + drop_plan.ops
    return Plan(cfg.name, ops + extra, summary="restrict management access")


# ===========================================================================
# Hub tunnel (dial-home) - the router dials OUT to the monitoring hub over
# WireGuard so it is reachable at a CONSTANT private IP with no public IP and
# through CGNAT (persistent-keepalive holds the NAT hole open). Requires
# RouterOS 7.1+ (WireGuard). The router generates its own keypair; we read the
# public key back so it can be added as a peer on the hub. Provisioning (the
# Provision tab) automates the hub side end-to-end.
# ===========================================================================
_HUB_WG = ("interface", "wireguard")
_HUB_PEERS = ("interface", "wireguard", "peers")
_HUB_ADDR = ("ip", "address")
_HUB_TAG = "mikromon:tunnel:"
_HUB_NAME = "mikromon"


def hubtunnel_read(pusher, cfg):
    ifaces = [r for r in pusher.api.fetch(_HUB_WG) if r.get("name") == _HUB_NAME]
    addrs = [r for r in pusher.api.fetch(_HUB_ADDR)
             if r.get("interface") == _HUB_NAME]
    peers = [r for r in pusher.api.fetch(_HUB_PEERS)
             if str(r.get("comment", "")).startswith(_HUB_TAG)]
    return {"iface": ifaces[0] if ifaces else {},
            "address": addrs[0] if addrs else {},
            "peer": peers[0] if peers else {}}


def hubtunnel_summary(current, cfg):
    iface = current.get("iface", {})
    if not iface:
        return ["No WireGuard tunnel yet. Set the hub details and Preview to "
                "create one that dials your monitoring hub (RouterOS 7.1+)."]
    addr = current.get("address", {}).get("address", "(no address)")
    peer = current.get("peer", {})
    out = [f"WireGuard '{_HUB_NAME}' present - tunnel IP {addr}",
           f"router public key: {iface.get('public-key', '(appears after apply)')}"]
    if peer:
        out.append(f"dials hub {peer.get('endpoint-address', '?')}:"
                   f"{peer.get('endpoint-port', '?')} - keepalive "
                   f"{peer.get('persistent-keepalive', '?')}")
    return out


def hubtunnel_form(current, cfg):
    peer = current.get("peer", {})
    addr = current.get("address", {})
    return [
        {"type": "text", "name": "endpoint",
         "label": "Hub address - your monitoring server's IP",
         "value": peer.get("endpoint-address", ""),
         "placeholder": "102.36.140.219"},
        {"type": "text", "name": "port", "label": "Hub UDP port (WireGuard)",
         "value": peer.get("endpoint-port", "") or "51820"},
        {"type": "text", "name": "hub_pubkey",
         "label": "Hub WireGuard public key",
         "value": peer.get("public-key", ""),
         "placeholder": "the monitoring server's WireGuard public key"},
        {"type": "text", "name": "tunnel_ip",
         "label": "This device's tunnel IP (with mask)",
         "value": addr.get("address", ""), "placeholder": "10.10.0.2/24"},
        {"type": "text", "name": "allowed",
         "label": "Route to the hub (allowed-address)",
         "value": peer.get("allowed-address", "") or "10.10.0.0/16"},
        {"type": "text", "name": "keepalive", "label": "Persistent keepalive",
         "value": peer.get("persistent-keepalive", "") or "25s",
         "hint": "Keeps the NAT hole open so the hub can reach back (CGNAT)."},
    ]


def hubtunnel_plan(pusher, cfg, flat, multi):
    endpoint = flat.get("endpoint", "").strip()
    hub_pubkey = flat.get("hub_pubkey", "").strip()
    tunnel_ip = flat.get("tunnel_ip", "").strip()
    port = (flat.get("port", "") or "51820").strip()
    allowed = (flat.get("allowed", "") or "10.10.0.0/16").strip()
    if not (endpoint and hub_pubkey and tunnel_ip):
        return Plan(cfg.name, [],
                    summary="tunnel (need hub IP, hub key and tunnel IP)")
    peer_cur = hubtunnel_read(pusher, cfg).get("peer", {})
    ka = ((peer_cur.get("persistent-keepalive") if peer_cur
           else flat.get("keepalive")) or "25s").strip() or "25s"
    iface_plan = pusher.plan_managed_list(
        _HUB_WG, "name", [{"name": _HUB_NAME, "comment": _HUB_TAG + "if"}],
        owns=lambda r: r.get("name") == _HUB_NAME, label="wg interface")
    addr_plan = pusher.plan_managed_list(
        _HUB_ADDR, "address",
        [{"address": tunnel_ip, "interface": _HUB_NAME,
          "comment": _HUB_TAG + "addr"}],
        owns=lambda r: r.get("interface") == _HUB_NAME, label="tunnel address")
    peer_plan = pusher.plan_managed_list(
        _HUB_PEERS, "comment",
        [{"interface": _HUB_NAME, "public-key": hub_pubkey,
          "endpoint-address": endpoint, "endpoint-port": port,
          "allowed-address": allowed, "persistent-keepalive": ka,
          "comment": _HUB_TAG + "hub"}],
        owns=_prefix_owner(_HUB_TAG + "hub"), label="hub peer")
    return Plan(cfg.name, iface_plan.ops + addr_plan.ops + peer_plan.ops,
                summary="hub tunnel (wireguard)")


# ===========================================================================
# WireGuard self-repair — diagnose the dial-home tunnel over the API, fix what
# is safely auto-fixable (a disabled interface, a missing keepalive), and return
# a structured report. Anything that can't be auto-fixed (unsupported firmware,
# a missing interface/peer, no handshake with the hub) is reported with a clear,
# actionable message of exactly what failed and what to do.
# ===========================================================================
def _wg_report(version, supported, steps, applied):
    """Roll the per-check findings up into an overall status + the report dict.
    failed  = a hard problem we could not auto-fix (clear message in `steps`).
    repaired= we applied one or more fixes and hit no hard errors.
    attention = nothing to fix but a warning needs a human (e.g. no handshake).
    healthy = everything checks out."""
    has_error = any(s["level"] == "error" for s in steps)
    has_warn = any(s["level"] == "warn" for s in steps)
    status = ("failed" if has_error else "repaired" if applied
              else "attention" if has_warn else "healthy")
    return {"status": status, "version": version, "supported": supported,
            "steps": steps, "applied": applied}


def wireguard_repair(api, *, iface=_HUB_NAME):
    """Diagnose + self-repair the WireGuard dial-home tunnel. Reads live state,
    applies safe fixes via the API, and returns a report (see _wg_report).
    Each fix is captured; if a fix itself fails, that becomes an error finding
    so the user sees precisely what went wrong."""
    steps = []
    applied = []

    def note(level, msg):
        steps.append({"level": level, "msg": msg})

    def try_fix(op, problem):
        try:
            api.execute(op)
        except Exception as exc:  # noqa: BLE001 — capture, don't crash the report
            note("error", f"{problem} Automatic fix FAILED: {exc}")
            return
        applied.append(op.desc)
        note("fixed", f"{problem} Fixed automatically ({op.desc}).")

    major, minor, ver = _ros_version(api)
    supported = _wg_supported(major, minor)
    if not supported:
        note("error", f"WireGuard needs RouterOS 7.1+, but this router runs "
                      f"{ver}. WireGuard cannot run here — upgrade RouterOS, or "
                      f"use a different transport for this device.")
        return _wg_report(ver, supported, steps, applied)

    try:
        ifaces = api.fetch(_HUB_WG)
    except Exception as exc:  # noqa: BLE001
        note("error", f"Could not read the WireGuard interfaces: {exc}")
        return _wg_report(ver, supported, steps, applied)
    wg = next((r for r in ifaces if r.get("name") == iface), None)
    if wg is None:
        note("error", f"There is no WireGuard interface '{iface}' on the router. "
                      f"Re-run Provision (or the Hub tunnel tab) to create the "
                      f"tunnel — self-repair can't recreate it without the hub "
                      f"key and tunnel IP.")
        return _wg_report(ver, supported, steps, applied)
    note("ok", f"WireGuard interface '{iface}' exists.")
    if _norm(wg.get("disabled", "")) == "true":
        try_fix(Operation("set", _HUB_WG,
                          {".id": wg[".id"], "disabled": "no"},
                          desc=f"enable interface '{iface}'",
                          inverse=Operation(
                              "set", _HUB_WG,
                              {".id": wg[".id"], "disabled": "yes"},
                              desc=f"disable interface '{iface}'")),
                f"Interface '{iface}' was disabled.")
    elif _norm(wg.get("running", "")) == "false":
        note("warn", f"Interface '{iface}' is enabled but not running yet — "
                     f"give it a moment, then re-check.")

    try:
        peers = api.fetch(_HUB_PEERS)
    except Exception as exc:  # noqa: BLE001
        note("error", f"Could not read the WireGuard peers: {exc}")
        return _wg_report(ver, supported, steps, applied)
    peer = next((p for p in peers
                 if str(p.get("comment", "")).startswith(_HUB_TAG)), None)
    if peer is None:
        note("error", "No hub peer is configured on the tunnel — the router has "
                      "nothing to dial home to. Re-run Provision, or set the hub "
                      "details on the Hub tunnel tab and apply.")
        return _wg_report(ver, supported, steps, applied)
    note("ok", "The hub peer is configured.")
    if not (peer.get("endpoint-address") or "").strip():
        note("error", "The hub peer has no endpoint address — set the hub's IP "
                      "on the Hub tunnel tab and apply, or re-run Provision.")
    if not (peer.get("persistent-keepalive") or "").strip():
        try_fix(Operation("set", _HUB_PEERS,
                          {".id": peer[".id"], "persistent-keepalive": "25s"},
                          desc="set persistent-keepalive=25s on the hub peer",
                          inverse=Operation(
                              "set", _HUB_PEERS,
                              {".id": peer[".id"], "persistent-keepalive": "0"},
                              desc="clear keepalive on the hub peer")),
                "Persistent-keepalive was not set (it holds the NAT hole open "
                "through CGNAT so the hub can reach back).")
    handshake = (peer.get("last-handshake") or "").strip()
    if handshake:
        note("ok", f"Last handshake with the hub: {handshake} ago — the tunnel "
                   f"is passing traffic.")
    else:
        note("warn", "No WireGuard handshake with the hub yet — the tunnel is "
                     "NOT passing traffic. This is not something the router can "
                     "fix by itself; check that (1) the hub's UDP port "
                     f"{peer.get('endpoint-port', '51820')} is open to the "
                     "internet, (2) this router can reach "
                     f"{peer.get('endpoint-address', 'the hub')} (no ISP/CGNAT "
                     "block on that port), and (3) the router's public key "
                     f"({wg.get('public-key', '(read it on the Hub tunnel tab)')}) "
                     "is registered as a peer on the hub.")
    return _wg_report(ver, supported, steps, applied)


# ===========================================================================
# Zero-touch provisioning over the API — mikromon connects to the router and
# applies everything itself (no script to paste). Idempotent: each step checks
# what's already there. Returns the router's WireGuard public key so the caller
# can register it as a peer on the hub.
# ===========================================================================
def provision_apply(api, name, pwuser, pwd, *, harden=True, enable_api=True,
                    lock_api=False, hub_pubkey="", hub_ip="", port="51820",
                    subnet="10.10.0.0/24", tunnel_ip=""):
    steps = []

    def do(op):
        api.execute(op)
        steps.append(op.desc)

    def ensure_user(uname, upwd, group):
        """Create the user if missing, else (re)set its password + group."""
        row = next((u for u in api.fetch(("user",))
                    if u.get("name") == uname), None)
        if row is None:
            do(Operation("add", ("user",),
                         {"name": uname, "password": upwd, "group": group,
                          "comment": "mikromon-managed"},
                         desc=f"add {group} user {uname}"))
        else:
            do(Operation("set", ("user",),
                         {".id": row[".id"], "password": upwd, "group": group},
                         desc=f"reset {group} user {uname}"))

    # 1) a single mikromon management user (full access — used for both polling
    #    and config-push). One login keeps provisioning simple.
    ensure_user(pwuser, pwd, "full")

    # 2) optionally make sure the API service is enabled. Optional because some
    # sites keep the binary API off (managing the router only over the tunnel,
    # WinBox or REST) and don't want provisioning to flip it back on.
    if enable_api:
        svc = next((s for s in api.fetch(("ip", "service"))
                    if s.get("name") == "api"), None)
        if svc is not None and _norm(svc.get("disabled", "")) == "true":
            do(Operation("set", ("ip", "service"),
                         {".id": svc[".id"], "disabled": "no"}, desc="enable API"))

    # 3) basic hardening
    if harden:
        for s in api.fetch(("ip", "service")):
            if s.get("name") in ("telnet", "ftp") and \
                    _norm(s.get("disabled", "")) != "true":
                do(Operation("set", ("ip", "service"),
                             {".id": s[".id"], "disabled": "yes"},
                             desc=f"disable {s.get('name')}"))

    # 4) WireGuard dial-home tunnel (RouterOS 7.1+) — only if the hub is ready
    router_pub = ""
    if hub_pubkey and tunnel_ip:
        wg = next((w for w in api.fetch(_HUB_WG)
                   if w.get("name") == _HUB_NAME), None)
        if wg is None:
            do(Operation("add", _HUB_WG,
                         {"name": _HUB_NAME, "listen-port": "13231",
                          "comment": _HUB_TAG + "if"},
                         desc="add WireGuard interface mikromon"))
            wg = next((w for w in api.fetch(_HUB_WG)
                       if w.get("name") == _HUB_NAME), None)
        router_pub = (wg or {}).get("public-key", "")
        # Use /16 so that any 10.10.x.x device IP works regardless of the third
        # octet that _alloc_tunnel_ip randomises.
        _sn_base = ".".join(subnet.split("/")[0].split(".")[:2])  # "10.10"
        _net16 = f"{_sn_base}.0.0/16"
        if not any(a.get("interface") == _HUB_NAME
                   for a in api.fetch(_HUB_ADDR)):
            do(Operation("add", _HUB_ADDR,
                         {"address": tunnel_ip + "/16", "interface": _HUB_NAME,
                          "comment": _HUB_TAG + "addr"}, desc="add tunnel address"))
        if not any(str(p.get("comment", "")).startswith(_HUB_TAG)
                   for p in api.fetch(_HUB_PEERS)):
            do(Operation("add", _HUB_PEERS,
                         {"interface": _HUB_NAME, "public-key": hub_pubkey,
                          "endpoint-address": hub_ip, "endpoint-port": port,
                          "allowed-address": _net16, "persistent-keepalive": "25s",
                          "comment": _HUB_TAG + "hub"}, desc="add hub peer"))

    # 5) Lock the API to the VPN tunnel — bind the api / api-ssl services to the
    # tunnel subnet so they're no longer reachable from the internet (WireGuard
    # encrypts the tunnel itself). This is done LAST and is BEST-EFFORT: binding
    # the address cuts our current (non-tunnel) session, so a disconnect here is
    # expected — mikromon reconnects over the tunnel afterwards. Captured in the
    # steps either way so the outcome is visible in the activity log.
    if lock_api and tunnel_ip:
        _sn_base = ".".join(subnet.split("/")[0].split(".")[:2])
        _net16 = f"{_sn_base}.0.0/16"
        for svc in ("api", "api-ssl"):
            row = next((s for s in api.fetch(("ip", "service"))
                        if s.get("name") == svc), None)
            if row is None or _norm(row.get("address", "")) == _norm(_net16):
                continue
            try:
                api.execute(Operation(
                    "set", ("ip", "service"),
                    {".id": row[".id"], "address": _net16},
                    desc=f"bind {svc} to the tunnel {_net16}"))
                steps.append(f"bind {svc} to the tunnel {_net16}")
            except Exception as exc:  # noqa: BLE001 — disconnect is expected
                steps.append(f"bind {svc} to the tunnel {_net16} "
                             f"(session dropped as expected: {exc})")
    return {"router_pubkey": router_pub, "steps": steps}


# ===========================================================================
# Update — check/install RouterOS upgrades + RouterBOOT firmware. Install
# REBOOTS the router, so it is a `run` command (no inverse) gated behind the
# normal dry-run -> explicit-confirm step with a loud warning.
# ===========================================================================
_PKG_UPDATE = ("system", "package", "update")
_ROUTERBOARD = ("system", "routerboard")


def update_read(pusher, cfg):
    upd = pusher.api.fetch(_PKG_UPDATE)
    rb = pusher.api.fetch(_ROUTERBOARD)
    return {"update": upd[0] if upd else {}, "routerboard": rb[0] if rb else {}}


def update_available(current):
    u = current.get("update", {})
    latest = str(u.get("latest-version", "")).strip()
    installed = str(u.get("installed-version", "")).strip()
    return bool(latest) and latest != installed


def firmware_available(current):
    rb = current.get("routerboard", {})
    cur = str(rb.get("current-firmware", "")).strip()
    up = str(rb.get("upgrade-firmware", "")).strip()
    return bool(up) and bool(cur) and up != cur


def update_summary(current, cfg):
    u = current.get("update", {})
    rb = current.get("routerboard", {})
    out = [f"Channel: {u.get('channel', '?')}",
           f"Installed RouterOS: {u.get('installed-version', '?')}",
           f"Latest available: {u.get('latest-version', '(run a check)')}",
           f"Status: {u.get('status', '?')}"]
    if update_available(current):
        out.append("⬆ An update is available — use the buttons below to install.")
    if rb.get("current-firmware") or rb.get("upgrade-firmware"):
        out.append(f"RouterBOOT firmware: {rb.get('current-firmware', '?')} "
                   f"(available {rb.get('upgrade-firmware', '?')})")
    return out


def update_form(current, cfg):
    u = current.get("update", {})
    return [{"type": "select", "name": "channel", "label": "Update channel",
             "options": [("stable", "Stable (recommended)"),
                         ("long-term", "Long-term (most conservative)"),
                         ("testing", "Testing")],
             "value": u.get("channel", "stable") or "stable",
             "hint": "Preview to change the channel. Then use the buttons below "
                     "to check for and install updates."}]


def update_plan(pusher, cfg, flat, multi):
    action = flat.get("update_action", "")
    if action == "check":
        op = Operation("run", _PKG_UPDATE, {"_cmd": "check-for-updates"},
                       desc="check for RouterOS updates")
        return Plan(cfg.name, [op], summary="check for updates (no install)")
    if action == "install":
        cur = update_read(pusher, cfg).get("update", {})
        latest = cur.get("latest-version", "") or "latest"
        installed = cur.get("installed-version", "?")
        op = Operation("run", _PKG_UPDATE, {"_cmd": "install"},
                       desc=f"download & INSTALL RouterOS {latest} (currently "
                            f"{installed}) — THE ROUTER WILL REBOOT now",
                       detach=True)
        return Plan(cfg.name, [op], summary="install RouterOS update + reboot")
    if action == "firmware":
        op = Operation("run", _ROUTERBOARD, {"_cmd": "upgrade"},
                       desc="upgrade RouterBOOT firmware — applies on next reboot")
        return Plan(cfg.name, [op], summary="routerboard firmware upgrade")
    if action == "reboot":
        op = Operation("run", ("system",), {"_cmd": "reboot"},
                       desc="reboot the router now — it will go offline ~1–2 min",
                       detach=True)
        return Plan(cfg.name, [op], summary="reboot")
    channel = flat.get("channel", "").strip()
    if channel:
        return pusher.plan_settings(_PKG_UPDATE, {"channel": channel},
                                    label="update channel")
    return Plan(cfg.name, [], summary="no update action")



# ===========================================================================
# Adoption — bring an existing (unmanaged) row under management by stamping the
# feature's ownership comment onto it. A single, reversible `set` (the inverse
# restores the previous comment), so it round-trips into the editor without
# touching any other field.
# ===========================================================================
def _qos_adopt_name(row):
    return _slug(row.get("name"), "queue")


def _pf_adopt_name(row):
    base = row.get("comment") or f"port-{row.get('dst-port', '')}"
    rid = _slug(row.get(".id", ""))
    return _slug(base, "fwd") + (f"-{rid}" if rid else "")


def adopt_plan(pusher, cfg, feature, row_id):
    """Build the (single) op that adopts row `row_id` for `feature`."""
    path, prefix = feature["path"], feature["prefix"]
    row = next((r for r in pusher.api.fetch(path)
                if r.get(".id") == row_id), None)
    if row is None:
        return Plan(cfg.name, [], summary="adopt (row not found)")
    new_comment = prefix + feature["adopt_name"](row)
    op = _set_field(path, row, "comment", new_comment, "rule")
    op.desc = f"adopt {'/'.join(path)} row → manage it as '{new_comment}'"
    op.inverse.desc = "release (restore previous comment)"
    return Plan(cfg.name, [op], summary="adopt")


# ===========================================================================
# Registry — keyed by URL slug; order follows the device tab bar.
# ===========================================================================
FEATURES = {
    "routes": {"title": "Routes", "write": True,
               "read": routes_read,
               "form": routes_form, "plan": routes_plan},
    "wan": {"title": "WAN — failover & load balancing", "write": True,
            "read": sdwan_read, "summary": sdwan_summary, "form": sdwan_form,
            "plan": sdwan_plan},
    "security": {"title": "Security", "write": True, "read": security_read,
                 "summary": security_summary, "form": security_form,
                 "plan": security_plan, "unmanaged": security_unmanaged},
    "harden": {"title": "Restrict management access", "write": True,
               "read": harden_read, "summary": harden_summary,
               "form": harden_form, "plan": harden_plan},
    "nextdns": {"title": "DNS", "write": True,
                "read": nextdns_read, "summary": nextdns_summary,
                "form": nextdns_form, "plan": nextdns_plan},
    "qos": {"title": "Queues", "write": True, "read": qos_read,
            "summary": qos_summary, "form": qos_form, "plan": qos_plan,
            "unmanaged": qos_unmanaged, "adopt": True, "path": _QUEUE,
            "prefix": _QOS_TAG, "adopt_name": _qos_adopt_name},
    "portfwd": {"title": "Port forwarding", "write": True, "read": portfwd_read,
                "summary": portfwd_summary, "form": portfwd_form,
                "plan": portfwd_plan, "unmanaged": portfwd_unmanaged,
                "adopt": True, "path": _NAT, "prefix": _PF_TAG,
                "adopt_name": _pf_adopt_name},
    "interfaces": {"title": "Interfaces", "write": False,
                   "read": interfaces_read, "summary": interfaces_summary},
    "remote": {"title": "Remote access", "write": True, "read": remote_read,
               "summary": remote_summary, "form": remote_form,
               "plan": remote_plan},
    "tunnel": {"title": "WireGuard Tunnel", "write": True,
               "read": tunnel_read, "summary": tunnel_summary, "form": tunnel_form,
               "plan": tunnel_plan, "unmanaged": tunnel_unmanaged,
               "adopt": True, "path": _WG_PEERS, "prefix": _WG_TAG,
               "adopt_name": _wg_adopt_name},
    "scripts": {"title": "Custom scripts", "write": True, "read": scripts_read,
                "summary": scripts_summary, "form": scripts_form,
                "plan": scripts_plan},
    "update": {"title": "Update RouterOS", "write": True, "read": update_read,
               "summary": update_summary, "form": update_form,
               "plan": update_plan},
}

# tab label -> url slug (Overview/Backups handled elsewhere)
TAB_SLUGS = {"Routes": "routes", "WAN": "wan", "Security": "security",
             "Restrict access": "harden", "DNS": "nextdns",
             "QoS": "qos", "Port forwarding": "portfwd", "Interfaces": "interfaces",
             "Remote access": "remote", "Tunnel": "tunnel",
             "Scripts": "scripts", "Update": "update"}


# ===========================================================================
# Device decommission — remove the hub tunnel and monitoring user when a
# device is deleted from the dashboard so the router stops dialling home.
# ===========================================================================

def device_offboard(api, cfg):
    """Remove the hub WireGuard tunnel and monitoring user from the router.

    Called automatically when a device is deleted from the dashboard.
    Each step is independent — one failure does not abort the rest.
    Returns a list of step dicts: {"level": "ok"|"warn"|"error", "msg": str}
    """
    steps = []

    def note(level, msg):
        steps.append({"level": level, "msg": msg})

    # 1. Hub tunnel WireGuard peer (comment tagged "mikromon:tunnel:")
    try:
        peers = api.fetch(_HUB_PEERS)
        hub_peers = [p for p in peers
                     if str(p.get("comment", "")).startswith(_HUB_TAG)]
        for p in hub_peers:
            api.execute(Operation("remove", _HUB_PEERS, {".id": p[".id"]},
                                  desc="remove hub tunnel WireGuard peer"))
        if hub_peers:
            ep = hub_peers[0].get("endpoint-address", "")
            note("ok", "Removed hub tunnel peer"
                       + (f" (endpoint {ep})" if ep else ""))
        else:
            note("warn", "No hub tunnel peer found (already removed?)")
    except Exception as exc:  # noqa: BLE001
        note("error", f"Could not remove hub tunnel peer: {exc}")

    # 2. Hub tunnel IP address on the 'mikromon' interface
    try:
        addrs = api.fetch(_HUB_ADDR)
        hub_addrs = [a for a in addrs
                     if a.get("interface") == _HUB_NAME
                     or str(a.get("comment", "")).startswith(_HUB_TAG)]
        for a in hub_addrs:
            api.execute(Operation("remove", _HUB_ADDR, {".id": a[".id"]},
                                  desc=f"remove tunnel IP {a.get('address', '')}"))
        if hub_addrs:
            note("ok", "Removed tunnel IP: "
                       + ", ".join(a.get("address", "?") for a in hub_addrs))
    except Exception as exc:  # noqa: BLE001
        note("error", f"Could not remove tunnel IP address: {exc}")

    # 3. WireGuard interface named 'mikromon' (taking the tunnel fully down)
    try:
        ifaces = api.fetch(_HUB_WG)
        hub_ifaces = [i for i in ifaces if i.get("name") == _HUB_NAME]
        for i in hub_ifaces:
            api.execute(Operation("remove", _HUB_WG, {".id": i[".id"]},
                                  desc=f"remove WireGuard interface '{_HUB_NAME}'"))
        if hub_ifaces:
            note("ok", f"Removed WireGuard interface '{_HUB_NAME}' — tunnel is down")
        else:
            note("warn", f"WireGuard interface '{_HUB_NAME}' not found "
                         f"(not provisioned, or already removed)")
    except Exception as exc:  # noqa: BLE001
        note("error", f"Could not remove WireGuard interface: {exc}")

    # 4. Monitoring user
    username = cfg.username
    if username:
        try:
            users = api.fetch(("user",))
            target = next((u for u in users
                           if str(u.get("name", "")) == username), None)
            if target:
                api.execute(Operation("remove", ("user",), {".id": target[".id"]},
                                      desc=f"remove monitoring user '{username}'"))
                note("ok", f"Removed monitoring user '{username}'")
            else:
                note("warn", f"Monitoring user '{username}' not found "
                             f"(already removed?)")
        except Exception as exc:  # noqa: BLE001
            note("error", f"Could not remove monitoring user '{username}': {exc}")

    return steps
