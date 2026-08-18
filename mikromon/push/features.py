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

import ipaddress
import re

from .api import PushError
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
_ROUTING_TABLE = ("routing", "table")


def _routing_mark_field(major) -> str:
    """RouterOS 7.1+ renamed /ip route's own field from routing-mark to
    routing-table, and stopped auto-creating a virtual table the first time
    a mark is used — the table must now be declared first via
    /routing/table (see _reconcile_routing_tables), or the add is rejected
    outright ('unknown parameter routing-mark' if the OLD field name is
    still sent). The mangle mark-routing action's own new-routing-mark field
    is unchanged on both versions. Unknown version (major 0) assumes v7,
    matching this codebase's existing bias elsewhere (_wg_supported) toward
    assuming the newer/current behavior when undetectable."""
    return "routing-mark" if 0 < major < 7 else "routing-table"


def _reconcile_routing_tables(pusher, marks, prefix) -> list:
    """Ensure each name in `marks` is declared as an FIB routing table via
    /routing/table — required on RouterOS 7.1+ before any route or mangle
    rule can reference it as a routing-table. A no-op wherever `marks` is
    empty (including on RouterOS 6, which never needs this menu at all —
    _safe_fetch tolerates it not existing there). `prefix` scopes cleanup to
    just the caller's own mark-naming convention, so this never touches a
    routing table created by a different feature or by hand."""
    current = _safe_fetch(pusher.api, _ROUTING_TABLE)
    desired = [{"name": m, "fib": "yes"} for m in marks]
    return reconcile_list(_ROUTING_TABLE, "name", desired, current,
                          owns=lambda r, p=prefix: str(r.get("name", "")).startswith(p),
                          label="routing table")


def _safe_fetch(api, path):
    try:
        return api.fetch(path)
    except Exception:  # noqa: BLE001
        return []


def _norm_iface(s) -> str:
    """Case/whitespace-insensitive interface name for matching a WAN
    uplink's configured Interface (human-typed, or picked from a dropdown)
    against the router's actual PPPoE client name / DHCP client interface.
    Confirmed live: an exact `==` match silently fails on a stray case or
    whitespace difference — no error, the link just never gets processed
    at all, which looks identical to "nothing is wrong" until you check
    the router's own log and see mikromon never touched that interface."""
    return str(s or "").strip().lower()


def _looks_like_ip(s) -> bool:
    """True if `s` parses as an IPv4/IPv6 address — used to tell whether
    _gateway_for_link found a real gateway IP (from ppp-active/ip-address/
    dhcp-client) or fell back to using the interface's own name (its last
    resort, when neither PPP nor DHCP exposed a usable address)."""
    try:
        ipaddress.ip_address(str(s).split("/")[0])
        return True
    except ValueError:
        return False


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
    failover_routes = [r for r in all_routes
                       if str(r.get("comment", "")).startswith(_FAILOVER_TAG)]
    return {"routes": routes, "dhcp": dhcp, "ppp": ppp,
            "ppp_active": ppp_active, "ip_addrs": ip_addrs,
            "failover_routes": failover_routes}


def routes_summary(current, cfg):
    lines = []
    routes = current.get("routes", [])
    ppp_active_by_name = {_norm_iface(s.get("name", "")): s
                          for s in current.get("ppp_active", []) if s.get("name")}
    ip_addr_by_iface = {_norm_iface(a.get("interface", "")): a
                        for a in current.get("ip_addrs", []) if a.get("interface")}
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
            rs = _route_status_for(routes, c, c.get("_type", "ppp"),
                                   ppp_active_by_name, ip_addr_by_iface)
            rs_str = f" · route {rs}" if rs else ""
            lines.append(f"{ctype} {name} · {state}{rs_str} · distance {dist}")
    for r in current.get("routes", []):
        gw = r.get("gateway", "?")
        dist = r.get("distance", "?")
        active = str(r.get("active", "true")).lower() not in ("false", "no")
        lines.append(f"route via {gw} · distance {dist}"
                     + ("" if active else " · inactive"))
    # Failover summary — one line per configured link (covers any number of
    # uplinks, not just primary/secondary). A DHCP link has a managed route
    # to report on; a PPP/PPPoE link has none (see _apply_failover — its
    # priority is set directly on its own connection instead), so its own
    # connection state is reported here instead.
    fo_by_comment = {r.get("comment", ""): r for r in current.get("failover_routes", [])}
    ppp_by_iface = {_norm_iface(c.get("name", "")): c for c in current.get("ppp", [])}
    links = list(getattr(getattr(cfg, "wan", None), "links", []) or [])
    for idx, link in enumerate(links):
        role = _fo_role(idx)
        r = fo_by_comment.get(f"{_FAILOVER_TAG}{role}")
        if r:
            active = str(r.get("active", "true")).lower() not in ("false", "no")
            state = "route active" if active else "route inactive"
            gw = r.get("gateway", "?")
            note = ("" if _looks_like_ip(gw) else
                   " (no gateway IP found from PPP/DHCP — routed via the "
                   "interface directly; try re-applying once the line is "
                   "fully connected)")
            lines.append(f"Failover {role} via {gw}{note} · {state}")
            continue
        iface_key = _norm_iface(getattr(link, "interface", "") or "")
        client = ppp_by_iface.get(iface_key)
        if client:
            running = str(client.get("running", "false")).lower() in ("true", "yes")
            dist = client.get("default-route-distance", "?")
            state = "connected" if running else "disconnected"
            lines.append(f"Failover {role} via its own PPP connection "
                        f"(no separate route needed) · {state} · distance {dist}")
    return lines or ["No internet lines found on this router."]


def _ppp_client_gateway(client, ppp_active_by_name, ip_addr_by_iface):
    """Best-effort gateway (IP) for a PPP-type (PPPoE/L2TP) client, mirroring
    _gateway_for_link's own precedence — so a route-table lookup by gateway
    can actually find the route this client's traffic uses. A managed
    failover route's own 'gateway' field is normally an IP (the PPP remote
    address or the /ip/address 'network'), not the client's name, so
    comparing straight against client.get("name") (the old behaviour) almost
    never matched and silently fell through to whatever default the caller
    used — e.g. always showing distance 1 for a PPPoE line regardless of
    what was actually pushed."""
    name_key = _norm_iface(client.get("name", ""))
    if ppp_active_by_name:
        remote = ppp_active_by_name.get(name_key, {}).get("remote-address", "")
        if remote:
            return remote
    if ip_addr_by_iface:
        network = ip_addr_by_iface.get(name_key, {}).get("network", "")
        if network and network not in ("0.0.0.0", ""):
            return network
    return str(client.get("name", ""))


def _route_status_for(routes, client, ctype,
                      ppp_active_by_name=None, ip_addr_by_iface=None):
    """Return 'active', 'inactive', or '' (no matching default route found).

    DHCP routes are matched by gateway IP; PPPoE/L2TP routes are matched the
    same way the failover route builder computed their gateway (PPP
    remote-address / /ip/address network, falling back to the client name).
    The RouterOS 'active' flag is True when the route is in the forwarding
    table — reliable for interface-down detection but only reflects internet
    reachability if check-gateway is also configured."""
    if ctype == "dhcp":
        gw = str(client.get("gateway", ""))
    else:
        gw = _ppp_client_gateway(client, ppp_active_by_name, ip_addr_by_iface)
    if not gw:
        return ""
    for r in routes:
        if str(r.get("gateway", "")) == gw:
            active = str(r.get("active", "true")).lower() not in ("false", "no")
            return "active" if active else "inactive"
    return ""


def _dist_from_routes(routes, client, ctype,
                      ppp_active_by_name=None, ip_addr_by_iface=None):
    """Find the distance of the matching 0.0.0.0/0 route for this client.

    RouterOS omits default-route-distance from the API response when
    add-default-route=no, so we fall back to reading the distance from the
    actual route table (which includes our managed static failover routes)."""
    gw = (str(client.get("gateway", "")) if ctype == "dhcp"
          else _ppp_client_gateway(client, ppp_active_by_name, ip_addr_by_iface))
    if not gw:
        return ""
    for r in routes:
        if str(r.get("gateway", "")) == gw:
            return str(r.get("distance", ""))
    return ""


def _wan_sortable_items(current):
    routes = current.get("routes", [])
    ppp_active_by_name = {_norm_iface(s.get("name", "")): s
                          for s in current.get("ppp_active", []) if s.get("name")}
    ip_addr_by_iface = {_norm_iface(a.get("interface", "")): a
                        for a in current.get("ip_addrs", []) if a.get("interface")}
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
        dist = (c.get("default-route-distance", "")
                or _dist_from_routes(routes, c, c.get("_type", "ppp"),
                                     ppp_active_by_name, ip_addr_by_iface)
                or "1")
        rid = c.get(".id", "").lstrip("*")
        state = "connected" if running else "disconnected"
        if str(c.get("add-default-route", "yes")).lower() in ("no", "false"):
            conn_info = f"{state} · no default route"
        else:
            rs = _route_status_for(routes, c, c.get("_type", "ppp"),
                                   ppp_active_by_name, ip_addr_by_iface)
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
    fo_enabled = bool(current.get("failover_routes"))

    fields = [
        {"type": "list", "name": "wan_priority_info",
         "label": "Internet line priority (top = primary)",
         "items": items,
         "hint": "Read-only — set the priority order and each line's Distance "
                 "on the WAN tab. That's what Gateway Failover below actually "
                 "applies; this just reports what's currently live on the router."},
        {"type": "heading", "label": "Gateway Failover",
         "hint": "Sets each configured uplink's priority (not just the "
                 "first two). A DHCP line gets a dedicated route straight "
                 "to its real gateway; a PPPoE/dial-up line's priority is "
                 "set directly on its own connection instead (no gateway "
                 "to detect — RouterOS's own PPP client already routes it "
                 "correctly). RouterOS then uses whichever line is "
                 "currently connected and has priority — no separate check "
                 "IP, no ping health check. This means it reacts when a "
                 "line's own connection actually drops, but not to a line "
                 "that's technically still connected while the internet "
                 "beyond it is down."},
        {"type": "toggle", "name": "fo_enabled", "value": "1",
         "on": fo_enabled, "label": "Enable gateway failover",
         "desc": "Turning this on or off can take between 2–5 minutes to "
                 "fully take effect on the router."},
    ]
    return fields


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
         can still route via the PPPoE interface directly. Deliberately does
         NOT fall back to the interface's own assigned address (/ip/address's
         'address' field) — that's this router's own IP, not a next hop, and
         is not a usable gateway even though it looks like a plausible one.
      3. DHCP client on the interface → use the DHCP-assigned gateway IP."""
    gw = getattr(link, "gateway", "") or ""
    if gw:
        return gw
    iface = getattr(link, "interface", "") or ""
    if not iface:
        return ""
    iface_key = _norm_iface(iface)

    if iface_key in pppoe_names:
        # Try /ppp/active first — some RouterOS versions expose remote-address
        if ppp_active_by_name:
            sess = ppp_active_by_name.get(iface_key, {})
            remote = sess.get("remote-address", "")
            if remote:
                return remote
        # Try /ip/address — PPP assigns a /32 local with 'network' = remote end
        if ip_addr_by_iface:
            addr = ip_addr_by_iface.get(iface_key, {})
            network = addr.get("network", "")
            if network and network not in ("0.0.0.0", ""):
                return network
        # Last resort: use the router's OWN (correctly-cased) name for this
        # PPPoE client as the gateway — not the WAN editor's possibly
        # differently-cased text, which RouterOS wouldn't recognize.
        return pppoe_names[iface_key]

    # Not PPP — check DHCP client for this interface
    dhcp = dhcp_by_iface.get(iface_key)
    if dhcp:
        return dhcp.get("gateway", "")
    return ""


def detect_wan_gateways(api, links) -> dict:
    """Best-effort AUTO-DETECTED gateway for every configured WAN link,
    keyed by the link's own `interface` value — deliberately ignoring any
    manual override already saved on the link (see _gateway_for_link's
    priority order), since the whole point is to show what mikromon would
    detect on its own, for comparison against — or confirmation of — that
    override. Used by the WAN tab to show each line's detected gateway
    without needing a Winbox session to check."""
    import types

    pppoe_clients = _safe_fetch(api, _PPPOE_CLIENT)
    dhcp_clients = _safe_fetch(api, _DHCP_CLIENT)
    pppoe_names = {_norm_iface(c.get("name", "")): c.get("name", "")
                  for c in pppoe_clients if c.get("name")}
    dhcp_by_iface = {_norm_iface(c.get("interface", "")): c
                     for c in dhcp_clients if c.get("interface")}
    ppp_active_by_name = {_norm_iface(s.get("name", "")): s
                          for s in _safe_fetch(api, _PPP_ACTIVE) if s.get("name")}
    ip_addr_by_iface = {_norm_iface(a.get("interface", "")): a
                        for a in _safe_fetch(api, _IP_ADDRESS) if a.get("interface")}
    out = {}
    for link in links:
        iface = getattr(link, "interface", "") or ""
        if not iface:
            continue
        bare = types.SimpleNamespace(interface=iface, gateway="")
        out[iface] = _gateway_for_link(bare, pppoe_names, dhcp_by_iface,
                                       ppp_active_by_name, ip_addr_by_iface)
    return out


def _fo_role(idx):
    """mikromon:failover: comment suffix for the link at this priority
    position — primary/secondary/link3/link4/... covering any number of
    configured uplinks, matching checks/wan.py's _fo_role."""
    return "primary" if idx == 0 else "secondary" if idx == 1 else f"link{idx + 1}"


def _fo_distance(idx, link):
    """Distance for this link's STATIC FAILOVER ROUTE while failover is on:
    its own explicit Distance (set in the WAN uplinks editor) if chosen,
    else its position + 1 (1, 2, 3... in priority order) — failover's
    managed routes need some strictly-ordered value to prioritize among
    themselves, regardless of what's chosen. This is unrelated to what the
    underlying client's own default-route-distance gets restored to when
    failover is turned off — see the disabled branch below, which uses the
    explicit Distance ONLY (nothing computed) and otherwise leaves that
    field untouched entirely."""
    explicit = getattr(link, "distance", None)
    return str(explicit) if explicit else str(idx + 1)


def _apply_failover(ops, flat, pusher, cfg):
    """Reconcile distance-based priority for EVERY configured WAN uplink,
    not just a primary/secondary pair — a 3rd, 4th... link is handled too,
    each at its own distance (see _fo_distance). Two different mechanisms
    depending on link type:

      - DHCP links: a managed static default route (dst-address=0.0.0.0/0,
        gateway = the real DHCP-assigned IP, distance = priority order),
        with the client's own add-default-route turned off so its dynamic
        route doesn't compete. A real, DHCP-provided gateway IP has always
        been reliably detectable.

      - PPP/PPPoE links: NO managed route at all. Every gateway value that
        could be constructed for one — the interface name, the interface's
        own assigned address — turned out unreliable on real hardware: some
        ISPs' PPPoE/CGNAT sessions don't expose anything RouterOS will
        treat as a genuinely active gateway for a hand-built route (the
        line would come up looking permanently down, or the opposite —
        immediately fail over with no hesitation, depending on what was
        tried). RouterOS's own PPP client, though, already creates a
        correctly-routed dynamic default route the instant the session
        connects — that's simply how PPPoE has always worked, no gateway
        to guess at all. So these links are left at add-default-route=yes,
        and only the client's own default-route-distance field is set
        directly — mikromon controls priority, RouterOS's own client
        handles the actual routing. Distance-based failover behaves
        identically either way: RouterOS always prefers whichever default
        route (static or dynamic) has the lowest distance and is active.

    Two earlier designs lived here for PPP links specifically: Netwatch +
    a hand-rolled down/up-script (never recovered once a PPPoE session
    renegotiated with a new gateway IP, since routes were snapshotted at
    apply-time), then a recursive check-gateway=ping scheme, then a plain
    static route using the detected/fallback gateway directly — none of
    these ever produced a reliably ACTIVE route for this failure mode.
    Any leftover routes/Netwatch entries from those are cleaned up
    automatically below, whether failover is being turned on or off.

    Gateways are derived from cfg.wan.links (the WAN uplinks the user
    configured) matched against live PPPoE/DHCP data on the router."""
    fo_owns = _prefix_owner(_FAILOVER_TAG)
    all_routes = _safe_fetch(pusher.api, _ROUTE)
    links = list(getattr(getattr(cfg, "wan", None), "links", []) or [])

    # One-time migration cleanup: this feature no longer creates Netwatch
    # entries at all (two designs ago), so any left over are removed
    # unconditionally here, regardless of whether failover is being turned
    # on or off below. Leftover check:-comment routes from the recursive
    # design (one design ago) are cleaned up further down by the normal
    # "stale route" sweep, since they're simply never in handled_routes now.
    for w in _safe_fetch(pusher.api, _NETWATCH):
        if fo_owns(w):
            ops.append(Operation(
                "remove", _NETWATCH, {".id": w[".id"]},
                desc=f"remove old netwatch comment={w.get('comment', '')} "
                    f"(replaced by a plain distance-based route)",
                inverse=Operation(
                    "add", _NETWATCH, {f: v for f, v in w.items() if f != ".id"},
                    desc=f"restore netwatch comment={w.get('comment', '')}")))

    if not flat.get("fo_enabled"):
        # Restore + remove ONE LINK AT A TIME — never every managed route
        # removed in a single batch before any client is restored. Reported
        # live: turning failover off removed all managed routes for every
        # link up front, then restored clients afterward — the router's own
        # connection to mikromon typically rides over one of these very WAN
        # links, so that gap (nothing routing at all, for every link at
        # once) could drop the API connection mid-apply, before the restore
        # ops it needed were ever reached, leaving the router with no
        # default route until someone fixes it by hand.
        #
        # Restoring THIS link's client BEFORE removing THIS link's static
        # route means there's always at least one route covering it —
        # RouterOS is fine with two default routes to the same destination
        # existing briefly (lowest distance wins); it is never fine with
        # zero. Doing this link-by-link (not client-restore-for-everyone,
        # then route-removal-for-everyone) also means a push that gets
        # interrupted partway leaves already-handled links in a working
        # state instead of every link mid-transition simultaneously.
        #
        # default-route-distance is only touched when the link has an
        # explicit Distance chosen in the WAN uplinks editor — that exact
        # value, nothing computed. If no Distance is chosen, this field is
        # left alone entirely: while failover is on, it's never written to
        # (only add-default-route is), so it stays frozen at whatever it
        # was before failover was ever turned on — that IS the restore, we
        # simply don't overwrite it with a guess.
        # disabled=no in case an earlier troubleshooting step left the
        # client itself switched off.
        #
        # None of this is forced live via a disable/enable bounce: the
        # interface being changed is very often the one carrying mikromon's
        # own WireGuard tunnel back to the hub, so bouncing it automatically
        # risks cutting off our own remote access mid-apply with no way to
        # fix it back. A pending add-default-route/distance change takes
        # effect on that line's next natural reconnect.
        pppoe_clients = _safe_fetch(pusher.api, _PPPOE_CLIENT)
        dhcp_clients  = _safe_fetch(pusher.api, _DHCP_CLIENT)
        fo_by_comment = {r.get("comment", ""): r for r in all_routes if fo_owns(r)}
        handled_routes: set[str] = set()
        for idx, link in enumerate(links):
            role = _fo_role(idx)
            iface = getattr(link, "interface", "") or ""
            if iface:
                explicit_dist = getattr(link, "distance", None)
                want_dist = str(explicit_dist) if explicit_dist else None
                iface_key = _norm_iface(iface)
                for c in pppoe_clients:
                    if _norm_iface(c.get("name")) == iface_key:
                        if str(c.get("add-default-route", "yes")).lower() in ("no", "false"):
                            ops.append(_set_field(_PPPOE_CLIENT, c, "add-default-route",
                                                  "yes", f"PPPoE {iface}"))
                        if (want_dist is not None
                                and _norm(str(c.get("default-route-distance", "") or "")) != want_dist):
                            ops.append(_set_field(_PPPOE_CLIENT, c,
                                                  "default-route-distance", want_dist,
                                                  f"PPPoE {iface}"))
                        if c.get("disabled", "false") not in ("false", "no", False):
                            ops.append(_set_field(_PPPOE_CLIENT, c, "disabled", "no",
                                                  f"PPPoE {iface}"))
                for c in dhcp_clients:
                    if _norm_iface(c.get("interface")) == iface_key:
                        if str(c.get("add-default-route", "yes")).lower() in ("no", "false"):
                            ops.append(_set_field(_DHCP_CLIENT, c, "add-default-route",
                                                  "yes", f"DHCP {iface}"))
                        if (want_dist is not None
                                and _norm(str(c.get("default-route-distance", "") or "")) != want_dist):
                            ops.append(_set_field(_DHCP_CLIENT, c,
                                                  "default-route-distance", want_dist,
                                                  f"DHCP {iface}"))
                        if c.get("disabled", "false") not in ("false", "no", False):
                            ops.append(_set_field(_DHCP_CLIENT, c, "disabled", "no",
                                                  f"DHCP {iface}"))
            # THEN remove this link's own static route(s) — only after its
            # client is already restored above.
            for comment in (f"{_FAILOVER_TAG}{role}", f"{_FAILOVER_TAG}check:{role}"):
                handled_routes.add(comment)
                r = fo_by_comment.get(comment)
                if r:
                    ops.append(Operation(
                        "remove", _ROUTE, {".id": r[".id"]},
                        desc=f"remove failover route comment={comment}",
                        inverse=Operation(
                            "add", _ROUTE, {f: v for f, v in r.items() if f != ".id"},
                            desc=f"restore failover route comment={comment}")))
        # Cleanup: any failover-owned routes left over that don't belong to
        # any currently configured link (e.g. an uplink removed from the WAN
        # editor while failover was on) — no client depends on these, so a
        # plain batch remove is fine.
        for comment, r in fo_by_comment.items():
            if comment not in handled_routes:
                ops.append(Operation(
                    "remove", _ROUTE, {".id": r[".id"]},
                    desc=f"remove stale failover route comment={comment}",
                    inverse=Operation(
                        "add", _ROUTE, {f: v for f, v in r.items() if f != ".id"},
                        desc=f"restore stale failover route comment={comment}")))
        return

    if not links:
        return

    # Detect gateways live from the router at apply time. Lookups are keyed
    # by normalized (case/whitespace-insensitive) interface name — see
    # _norm_iface — since the WAN uplinks editor's typed/selected Interface
    # text can differ in case from the router's own name for the same
    # client, which a plain == match would silently (no error) treat as
    # "no such interface", skipping that link entirely.
    pppoe_clients = _safe_fetch(pusher.api, _PPPOE_CLIENT)
    dhcp_clients  = _safe_fetch(pusher.api, _DHCP_CLIENT)
    pppoe_names = {_norm_iface(c.get("name", "")): c.get("name", "")
                  for c in pppoe_clients if c.get("name")}
    dhcp_by_iface = {_norm_iface(c.get("interface", "")): c
                     for c in dhcp_clients if c.get("interface")}
    ppp_active_by_name = {_norm_iface(s.get("name", "")): s
                          for s in _safe_fetch(pusher.api, _PPP_ACTIVE) if s.get("name")}
    ip_addr_by_iface = {_norm_iface(a.get("interface", "")): a
                        for a in _safe_fetch(pusher.api, _IP_ADDRESS) if a.get("interface")}
    fo_by_comment = {r.get("comment", ""): r for r in all_routes if fo_owns(r)}

    is_ppp = []
    gateways = []
    for idx, link in enumerate(links):
        iface = getattr(link, "interface", "") or ""
        iface_key = _norm_iface(iface) if iface else ""
        # link_type is an explicit override (WAN tab's "Connection type") —
        # auto-detection (does this interface match a PPPoE client on the
        # router?) is normally reliable, but has no way to be corrected by
        # hand if it ever guesses wrong for a given interface.
        link_type = (getattr(link, "link_type", "") or "").lower()
        if link_type == "ppp":
            ppp_link = True
        elif link_type == "dhcp":
            ppp_link = False
        else:
            ppp_link = bool(iface_key) and iface_key in pppoe_names
        is_ppp.append(ppp_link)
        gw = _gateway_for_link(link, pppoe_names, dhcp_by_iface,
                               ppp_active_by_name, ip_addr_by_iface)
        if not gw and not ppp_link:
            # Fall back to the gateway already on the router from a
            # previous apply (e.g. a DHCP lease that isn't bound right now).
            existing = fo_by_comment.get(f"{_FAILOVER_TAG}{_fo_role(idx)}")
            if existing and existing.get("gateway"):
                gw = existing["gateway"]
        gateways.append(gw)
    # Only bail for an undetectable gateway when the primary link actually
    # needs one (DHCP) — a PPP primary never builds a route from `gw` at
    # all (see below), so an empty value there is never fatal.
    if not is_ppp[0] and not gateways[0]:
        return

    # Built and reconciled ONE LINK AT A TIME, not as one big batch covering
    # every link at once. Reported live: turning failover on/off could
    # leave the router briefly with no working default route at all,
    # because every link's static route (or every client restore) was
    # queued as a single group, so a router whose mikromon connection
    # rides over one of these WAN links could drop mid-apply before
    # reaching the op that would have fixed it.
    #
    # PPP/PPPoE links: no managed static route at all. Every gateway value
    # we could construct for these — the interface name, the interface's
    # own assigned address — turned out unreliable on real hardware (some
    # ISPs' PPPoE/CGNAT sessions just don't expose anything RouterOS will
    # actually treat as a valid, active gateway for a hand-built route).
    # RouterOS's OWN PPP client, though, already creates a correctly
    # routed dynamic default route the moment the session comes up — that
    # is how PPPoE has always worked, with no gateway to guess at all.
    # So for these links we leave add-default-route=yes and just set the
    # client's own default-route-distance directly, letting RouterOS's own
    # mechanism do the actual routing while mikromon only controls
    # priority. Distance-based failover works identically either way:
    # RouterOS always prefers whichever default route (static or dynamic)
    # has the lowest distance and is actually active.
    #
    # DHCP links: unchanged — a real, DHCP-assigned gateway IP has always
    # been reliably detectable, so they keep the managed static route +
    # add-default-route=no approach.
    handled_routes = set()
    for idx, link in enumerate(links):
        role = _fo_role(idx)
        distance = _fo_distance(idx, link)
        iface = getattr(link, "interface", "") or ""
        if not iface:
            continue
        iface_key = _norm_iface(iface)

        if is_ppp[idx]:
            for c in pppoe_clients:
                if _norm_iface(c.get("name")) != iface_key:
                    continue
                if str(c.get("add-default-route", "yes")).lower() in ("no", "false"):
                    ops.append(_set_field(_PPPOE_CLIENT, c, "add-default-route", "yes",
                                          f"PPPoE {iface}"))
                if _norm(str(c.get("default-route-distance", "") or "")) != distance:
                    ops.append(_set_field(_PPPOE_CLIENT, c, "default-route-distance",
                                          distance, f"PPPoE {iface}"))
            continue

        gw = gateways[idx]
        if not gw:
            continue
        main_comment = f"{_FAILOVER_TAG}{role}"
        handled_routes.add(main_comment)

        link_routes = [
            {"comment": main_comment, "dst-address": "0.0.0.0/0", "gateway": gw,
             "distance": distance},
        ]
        # 1. THIS link's default route, first.
        ops.extend(reconcile_list(
            _ROUTE, "comment", link_routes, all_routes,
            owns=lambda r, mc=main_comment: str(r.get("comment", "")) == mc,
            label="failover route"))

        # 2. THEN stop this link's client creating its own competing dynamic
        # route. A client with add-default-route=yes creates a dynamic
        # route that stays active regardless of priority, so a
        # lower-priority static route never gets a chance to win. Setting
        # add-default-route=no removes the dynamic route immediately on
        # active connections and leaves only our managed route in control —
        # safe to do now since that route was just confirmed present above.
        for c in dhcp_clients:
            if (_norm_iface(c.get("interface")) == iface_key
                    and str(c.get("add-default-route", "yes")).lower() not in ("no", "false")):
                ops.append(_set_field(_DHCP_CLIENT, c, "add-default-route", "no",
                                      f"DHCP {iface}"))

    # Cleanup: any failover-owned routes left over that don't belong to any
    # currently configured link (e.g. an uplink removed from the WAN
    # editor, or a gateway that couldn't be detected this apply) — no live
    # client depends on these, so a plain batch remove is fine.
    for r in all_routes:
        c = str(r.get("comment", ""))
        if fo_owns(r) and c not in handled_routes:
            ops.append(Operation(
                "remove", _ROUTE, {".id": r[".id"]},
                desc=f"remove stale failover route comment={c}",
                inverse=Operation(
                    "add", _ROUTE, {f: v for f, v in r.items() if f != ".id"},
                    desc=f"restore stale failover route comment={c}")))


def routes_plan(pusher, cfg, flat, multi):
    ops: list[Operation] = []
    # _apply_failover sets every configured link's distance itself (whether
    # failover is on or off, from link.distance) — it used to be preceded by
    # a second pass driven by the Routes tab's drag-order list, which pushed
    # sequential ranks (1, 2, 3...) onto each client's own
    # default-route-distance regardless of what Distance was actually chosen
    # on the WAN tab. That ran on EVERY apply, including ones that never
    # touched the drag list, silently overwriting explicit Distance choices
    # right back to 1/2/3 — removed; distance now has exactly one source of
    # truth (link.distance).
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
    failover_routes = [r for r in all_routes
                       if str(r.get("comment", "")).startswith(_FAILOVER_TAG)]
    return {"routes": routes, "policy": policy,
            "failover_routes": failover_routes}


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
    fo_routes = {r.get("comment", ""): r for r in current.get("failover_routes", [])}
    for idx, (role, rc) in enumerate((
            ("primary",   f"{_FAILOVER_TAG}primary"),
            ("secondary", f"{_FAILOVER_TAG}secondary"))):
        r = fo_routes.get(rc)
        if not r:
            continue
        link = links[idx] if idx < len(links) else None
        name = link.label(idx) if link else role.title()
        gw = r.get("gateway", "?")
        dist = r.get("distance", "?")
        active = str(r.get("active", "true")).lower() not in ("false", "no")
        state = "active" if active else "inactive"
        lines.append(f"{name} via {gw} · distance {dist} · {state}")
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
        {"type": "static", "label": "Configured WAN uplinks (priority order)",
         "value": links,
         "hint": "Edit them, including each link's own route Distance, on "
                 "the Devices page → WAN uplinks section. Gateway Failover "
                 "(Netwatch health checks, automatic switchover) lives on "
                 "the Routes tab."},
        {"type": "rows", "name": "pol",
         "label": "Send specific LAN subnets out a chosen WAN (policy routing)",
         "cols": [("subnet", "LAN subnet or host", "192.168.88.0/24"),
                  ("via", "out this WAN (interface or gateway)", "ether1")],
         "rows": _policy_rows(current),
         "hint": "Each row marks that source and routes it via the chosen WAN "
                 "(mangle mark + marked default route). Leave empty for none."},
    ]


def sdwan_plan(pusher, cfg, flat, multi):
    """Per-subnet policy routing only — WAN uplink Distance (and the full
    Gateway Failover feature) lives entirely on the Routes tab now, so
    there's only ever one place to manage it."""
    major, _minor, _ver = _ros_version(pusher.api)
    mark_field = _routing_mark_field(major)
    mangle_desired, route_desired, marks = [], [], []
    for r in _rows(multi, "pol", ("subnet", "via")):
        subnet, via = r["subnet"], r["via"]
        if not subnet or not via:
            continue
        mark = "mm-" + _slug(via)
        marks.append(mark)
        enc = f"{subnet}|{via}"
        mangle_desired.append({
            "chain": "prerouting", "src-address": subnet, "action": "mark-routing",
            "new-routing-mark": mark, "passthrough": "yes", "comment": _POL_TAG + enc})
        route_desired.append({
            "dst-address": "0.0.0.0/0", "gateway": via, mark_field: mark,
            "comment": _RT_TAG + enc})
    mangle_plan = pusher.plan_managed_list(
        _MANGLE, "comment", mangle_desired,
        owns=_prefix_owner(_POL_TAG), label="policy mark")
    route_plan = pusher.plan_managed_list(
        _ROUTE, "comment", route_desired,
        owns=_prefix_owner(_RT_TAG), label="policy route")
    # RouterOS 7.1+ routing tables (see _reconcile_routing_tables) — declared
    # before the routes above so a referenced table always exists first; a
    # no-op wherever no policy row is configured, and on RouterOS 6 (whose
    # /routing/table menu doesn't exist — _safe_fetch tolerates that).
    table_ops = _reconcile_routing_tables(
        pusher, marks if mark_field == "routing-table" else [], prefix="mm-")
    return Plan(cfg.name, table_ops + mangle_plan.ops + route_plan.ops,
                summary="wan policy routing")


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
        # the source connection1 -> 2 -> 3 -> bruteforce_blacklist, then a final
        # accept for everything NOT on bruteforce_blacklist. Matches the
        # requested reference exactly, including the `,!secured` matcher on the
        # "third attempt" rule — `secured` isn't a defined address-list, so
        # RouterOS may reject that one rule outright or treat it as always-false.
        # Also note: unlike an unconditional drop, this final accept only
        # actually blocks a blacklisted source if nothing later in the input
        # chain would otherwise accept it and/or the chain's own default action
        # is drop — it depends on the rest of the router's ruleset.
        ssh_base = {"chain": "input", "protocol": "tcp", "dst-port": "22",
                    "connection-state": "new"}
        desired += [
            {**ssh_base, "src-address-list": "connection3",
             "action": "add-src-to-address-list",
             "address-list": "bruteforce_blacklist", "address-list-timeout": "1d",
             "comment": _SEC_TAG + "ssh_blacklist-1blacklist"},
            {**ssh_base, "src-address-list": "connection2,!secured",
             "action": "add-src-to-address-list",
             "address-list": "connection3", "address-list-timeout": "1h",
             "comment": _SEC_TAG + "ssh_blacklist-2third"},
            {**ssh_base, "src-address-list": "connection1",
             "action": "add-src-to-address-list",
             "address-list": "connection2", "address-list-timeout": "15m",
             "comment": _SEC_TAG + "ssh_blacklist-3second"},
            {**ssh_base, "action": "add-src-to-address-list",
             "address-list": "connection1", "address-list-timeout": "5m",
             "comment": _SEC_TAG + "ssh_blacklist-4first"},
            {"chain": "input", "protocol": "tcp", "dst-port": "22",
             "src-address-list": "!bruteforce_blacklist", "action": "accept",
             "comment": _SEC_TAG + "ssh_blacklist-5accept"},
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
    srow: dict = next(iter(pusher.api.fetch(_IP_SETTINGS)), {})
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
    """Read-only now (see the FEATURES["nextdns"] comment) — silent unless
    this router still has leftover state from the retired local-blocking
    feature, so a router that never used it (the normal case going
    forward, with NextDNS.io doing the filtering instead) shows nothing
    here at all."""
    groups = sorted({str(r.get("comment", ""))[len(_DNSBLOCK_TAG):]
                     for r in current.get("static", [])})
    forced = bool(current.get("forced"))
    bypass_n = len(current.get("bypass", []))
    if not (groups or forced or bypass_n):
        return []
    out = ["Legacy local blocking (no longer managed here — use NextDNS "
          "above instead):"]
    if groups:
        labels = [_BLOCK_BY_KEY.get(g, (g, []))[0] for g in groups]
        out.append("Still blocking: " + ", ".join(labels))
    if forced:
        out.append("Force client DNS through this router: still on")
    if bypass_n:
        out.append(f"{bypass_n} bypass address(es) still configured")
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


def nextdns_form(current, cfg):
    """DNS server selection + making sure clients actually use it — NOT the
    retired local sinkhole blocking (that's now NextDNS.io's job, see the
    panels above this form). "Force client DNS" still matters here: without
    it, a device that hard-codes its own resolver (8.8.8.8, say) bypasses
    whatever's chosen below — the quick preset OR the NextDNS profile —
    entirely, which would also quietly defeat NextDNS's own filtering."""
    dns = current.get("dns", {})
    ips = "\n".join(r.get("address", "") for r in current.get("bypass", []))
    cur_preset = _active_preset(dns)
    fields: list[dict] = [
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
         "hint": "Must be ON for the router to answer client DNS at all. "
                 "(Turned on automatically when you force client DNS below.)"},
        {"type": "toggle", "name": "opt", "value": "force_dns",
         "label": "Force all client DNS through this router",
         "on": bool(current.get("forced")),
         "hint": "Redirects every client's port-53 traffic to the router (NAT) "
                 "so a device hard-coded to someone else's resolver can't "
                 "bypass the DNS chosen here — or NextDNS's filtering, if "
                 "that's enabled above."},
        {"type": "textarea", "name": "bypass", "label": "Bypass IPs (one per line)",
         "value": ips, "hint": "Hosts allowed to use their own DNS even when "
                 "\"Force all client DNS\" above is on."},
    ]
    return fields


def nextdns_plan(pusher, cfg, flat, multi):
    opts = set(multi.get("opt", []))
    force_dns = "force_dns" in opts
    # A switched-on provider preset sets the DNS servers. The toggles are
    # mutually exclusive in the UI, but if more than one arrives (e.g. no JS)
    # just take the first. With NONE on we leave /ip dns servers untouched
    # (the servers field was removed from the form).
    chosen = [k for k in multi.get("dns_preset", []) if k in _DNS_PRESET_SERVERS]
    # MikroTik's boolean fields are normally yes/no, but /ip dns is a
    # confirmed exception — allow-remote-requests is true/false on the
    # router, so sending yes/no here would never match on read-back and
    # cause an endless (harmless but noisy) "set" every single apply. true
    # = yes/on, false = no/off — same meaning, just this menu's own spelling.
    # Forcing client DNS only works if the router answers DNS, so
    # allow-remote-requests is implied on when force_dns is on.
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
    # Force-DNS: redirect client port-53 traffic to the router so a
    # hard-coded resolver can't slip past whatever's chosen above (a quick
    # preset, or NextDNS via the panels above this form). dstnat/redirect
    # only sees client (forwarded) traffic in prerouting, so the router's
    # own DNS is untouched.
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
    return Plan(cfg.name, plan.ops + list_plan.ops + force_plan.ops,
                summary="dns")


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
        # MikroTik's boolean fields are normally yes/no, but /queue simple is
        # a confirmed exception — disabled reads back as true/false on the
        # router, so sending yes/no here would never match and cause an
        # endless (harmless but noisy) "set" every single apply. true =
        # yes/paused, false = no/running — same meaning, just this menu's
        # own spelling.
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
    by_type: dict[str, int] = {}
    for r in ifaces:
        t = str(r.get("type", "?"))
        by_type[t] = by_type.get(t, 0) + 1
    kinds = ", ".join(f"{n}× {t}" for t, n in sorted(by_type.items()))
    return [f"{len(ifaces)} interfaces, {up} running", f"types: {kinds}"]


# ===========================================================================
# Remote access — a temporary RouterOS login (auto-expires on its own)
# ===========================================================================
_REMOTE_TAG = "mikromon:remote:"
_REMOTE_SCHED_PREFIX = "mikromon-tempaccess-"
_REMOTE_DEFAULT_MINUTES = 30
_REMOTE_DEFAULT_GROUP = "full"


def remote_read(pusher, cfg):
    users = [u for u in pusher.api.fetch(("user",))
            if str(u.get("comment", "")).startswith(_REMOTE_TAG)]
    scheds = pusher.api.fetch(("system", "scheduler"))
    return {"users": users, "scheds": scheds}


def remote_summary(current, cfg):
    users = current.get("users", [])
    if not users:
        return ["Nobody currently has temporary access."]
    sched_by_name = {s.get("name"): s for s in current.get("scheds", [])}
    lines = []
    for u in users:
        name = u.get("name", "?")
        sched = sched_by_name.get(_REMOTE_SCHED_PREFIX + name)
        exp = ("expires on its own soon" if sched
              else "expiry missing — revoke below to be safe")
        lines.append(f"{name} — {exp}")
    return lines


def remote_form(current, cfg):
    users = current.get("users", [])
    fields: list[dict] = [
        {"type": "heading", "label": "Grant temporary access",
         "hint": f"Type who it's for and click Create — the password and "
                f"address to give them come right after. It stops working "
                f"on its own in {_REMOTE_DEFAULT_MINUTES} minutes."},
        {"type": "text", "name": "tempuser", "label": "Who is this for?",
         "placeholder": "e.g. alice, or the contractor's name"},
        {"type": "toggle", "name": "restrict_source", "value": "1",
         "label": "Restrict to this company's own WireGuard presence",
         "on": False,
         "desc": "Only lets the login be used from this company's own "
                 "tunnel (a router's own connection, a linked VPN-group "
                 "network, or a Personal VPN access peer). Leave OFF if "
                 "this router is also reachable some other way (a public "
                 "IP, port-forward, different VPN, etc.) — turning this on "
                 "would block that other path too."},
    ]
    # Only shown once someone actually has access — a first-time visitor
    # just sees the one field above, nothing else.
    if users:
        fields.append({
            "type": "rows", "name": "keep", "label": "Currently has access",
            "cols": [("name", "name", "")],
            "rows": [{"name": u.get("name", "")} for u in users],
            "can_add": False,
            "hint": "Delete a row and apply to cut off that person's access "
                    "right away.",
        })
    return fields


def remote_plan(pusher, cfg, flat, multi):
    ops = []
    current = remote_read(pusher, cfg)
    current_users = {u.get("name"): u for u in current["users"]}
    sched_by_name = {s.get("name"): s for s in current["scheds"]}
    keep_names = {r.strip() for r in multi.get("keep__name", []) if r.strip()}
    for uname, u in current_users.items():
        if uname in keep_names:
            continue
        ops.append(Operation("remove", ("user",), {".id": u[".id"]},
                             desc=f"revoke temporary login '{uname}'"))
        sched = sched_by_name.get(_REMOTE_SCHED_PREFIX + uname)
        if sched:
            ops.append(Operation("remove", ("system", "scheduler"),
                                 {".id": sched[".id"]},
                                 desc=f"cancel expiry for '{uname}'"))
    new_username = (flat.get("tempuser") or "").strip()
    # A blank generated password means the web layer couldn't supply one (or
    # this is being computed somewhere that never will, e.g. a stray direct
    # call) — never push a user with an empty password.
    password = flat.get("_tempuser_password", "")
    if new_username and new_username not in current_users and password:
        minutes = _REMOTE_DEFAULT_MINUTES
        # web.py's _org_wg_addresses computes every address that belongs to
        # this company's own WireGuard presence (its routers' tunnel IPs,
        # linked VPN-group subnets, and every Personal VPN peer already
        # issued to the team) — restricting the login to it means it works
        # for anyone on the company's own tunnel, not pinned to whichever
        # one person happened to click Create, while still excluding every
        # OTHER company sharing this hub. Empty (e.g. devices_db not
        # configured, or this org has nothing registered yet) -> no
        # restriction, same as before this existed.
        allowed = (flat.get("_remote_allowed_address") or "").strip()
        user_params = {"name": new_username, "password": password,
                       "group": _REMOTE_DEFAULT_GROUP,
                       "comment": _REMOTE_TAG + new_username}
        if allowed:
            user_params["address"] = allowed
        ops.append(Operation(
            "add", ("user",), user_params,
            desc=f"create temporary login '{new_username}' "
                 f"({_REMOTE_DEFAULT_GROUP}, expires in {minutes} min"
                 + (f", restricted to {allowed}" if allowed else "") + ")"))
        sched_name = _REMOTE_SCHED_PREFIX + new_username
        event = (f'/user remove [find name="{new_username}"]\n'
                 f'/system scheduler remove [find name="{sched_name}"]')
        ops.append(Operation(
            "add", ("system", "scheduler"),
            {"name": sched_name, "interval": f"{minutes}m", "on-event": event,
             "comment": _REMOTE_TAG + "expiry:" + new_username,
             "policy": "ftp,reboot,read,write,policy,test,password,"
                      "sensitive,romon"},
            desc=f"expire '{new_username}' automatically after {minutes} min"))
    return Plan(cfg.name, ops, summary="temporary access")


_REMOTE_TEST_SERVICES = (("winbox", "Winbox", 8291), ("www", "WebFig", 80),
                         ("ssh", "SSH", 22))


def remote_test(api) -> list:
    """Diagnose why Remote access might not be reachable even though the
    temporary login itself was created successfully — that only proves
    mikromon's OWN server (which sits ON the hub) can reach the router; it
    says nothing about whether any particular person's own computer can.
    Checks, read-only, never changes anything:
      - each management service (Winbox/WebFig/SSH) enabled + any address
        restriction, since a restriction that excludes the tunnel silently
        drops the connection (RouterOS gives no error — it just never
        replies, which is exactly a "stuck on Connecting" symptom)
      - any currently-active temporary login's OWN address restriction (the
        opt-in checkbox on the Remote access tab) — separate from, and
        invisible to, the service-level checks above; a router can pass
        every one of those and still refuse a specific login because of
        this
      - the tunnel's own input-chain firewall accept rule, added during
        Provision — if a router was provisioned before this existed, or it
        was removed by hand, traffic arriving over the tunnel FOR THE
        ROUTER ITSELF can be silently dropped too
    Returns a list of {"level", "msg"} steps; the caller (web.py) appends
    its own raw-TCP reachability findings and renders the combined report."""
    steps = []

    def note(level, msg):
        steps.append({"level": level, "msg": msg})

    services = _safe_fetch(api, _SERVICE)
    by = {s.get("name"): s for s in services}
    for svc_name, label, port in _REMOTE_TEST_SERVICES:
        s = by.get(svc_name)
        if s is None:
            note("warn", f"{label} (port {port}): could not read its status "
                         f"from /ip/service.")
            continue
        if _norm(s.get("disabled", "")) == "true":
            note("error", f"{label} is DISABLED on this router — turn it on "
                          f"(Restrict management access tab, or run "
                          f"\"/ip service enable {svc_name}\") before it can "
                          f"be reached at all.")
            continue
        addr = (s.get("address") or "").strip()
        if addr:
            note("warn", f"{label} is restricted to {addr} — if the address "
                        f"you're connecting FROM isn't inside that range, "
                        f"RouterOS drops the connection with no error at "
                        f"all, which looks exactly like a stuck "
                        f"\"Connecting…\". Check the Restrict management "
                        f"access tab.")
        else:
            note("ok", f"{label} is enabled and not address-restricted.")

    # The temporary login itself can ALSO carry its own address restriction
    # (the opt-in "Restrict to this company's own WireGuard presence"
    # checkbox) — separate from, and invisible to, the /ip/service checks
    # above. A router can pass every service check and still refuse a
    # specific login if THIS is what's blocking it.
    users = _safe_fetch(api, ("user",))
    remote_users = [u for u in users
                    if str(u.get("comment", "")).startswith(_REMOTE_TAG)]
    for u in remote_users:
        uname = u.get("name", "?")
        addr = (u.get("address") or "").strip()
        if addr:
            note("warn", f"The login '{uname}' itself is restricted to "
                        f"{addr} (set when it was created, via the "
                        f"\"Restrict to this company's own WireGuard "
                        f"presence\" option) — if you're connecting from "
                        f"outside that range, RouterOS refuses the login "
                        f"with no error at all, even though every service "
                        f"check above passes. Regenerate '{uname}' with "
                        f"that option OFF if this router is also reached "
                        f"some other way.")
        else:
            note("ok", f"The login '{uname}' has no address restriction of "
                       f"its own.")

    fw = _safe_fetch(api, _FILTER)
    tunnel_rule = next((r for r in fw
                        if str(r.get("comment", "")) == "mikromon:tunnel:fw"),
                       None)
    if tunnel_rule is None:
        note("error", "The tunnel's own firewall accept rule "
                      "(mikromon:tunnel:fw) is MISSING — traffic arriving "
                      "over the WireGuard tunnel for this router itself may "
                      "be silently dropped. Re-run Provision to restore it.")
    elif _norm(tunnel_rule.get("disabled", "")) == "true":
        note("error", "The tunnel's firewall accept rule exists but is "
                      "DISABLED — re-enable it, or re-run Provision.")
    else:
        note("ok", "The tunnel's firewall accept rule is present and enabled.")
    return steps


# ===========================================================================
# Tunnel — WireGuard VPN (RouterOS 7.1+ only; graceful notice on v6/unknown)
# ===========================================================================
_WG_IFACE = ("interface", "wireguard")
_WG_PEERS = ("interface", "wireguard", "peers")
_WG_TAG = "mikromon:wg:"
_WG_RW_TAG = "mikromon:wg-rw:"
_VPN_ROUTE_TAG = "mikromon:vpnroute:"


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


def _doh_supported(major, minor):
    """DNS-over-HTTPS (/ip/dns use-doh-server) requires RouterOS 7.1+ — same
    cutoff as WireGuard. Unknown version (0,0) → attempt anyway."""
    if major == 0:
        return True
    return (major, minor) >= (7, 1)


# ===========================================================================
# NextDNS cloud profile — one real NextDNS.io Configuration ID per router
# (separate blocklists/allowlists/query-logs), NOT the same thing as the
# "nextdns" feature above (that one is mikromon's own local DNS-filter
# rules; this one talks to the actual NextDNS.io service via
# mikromon/nextdns.py). Auto-provisioning the profile itself is web-layer
# glue (needs the platform's NextDNS API key + devices_db to persist the
# assigned id) — this module only knows how to point a router's DNS at an
# already-created profile id, or clear it.
# ===========================================================================

def nextdns_cloud_ops(pusher, profile_id: str) -> Plan:
    """Point /ip/dns at this router's own NextDNS profile via DNS-over-HTTPS
    (empty profile_id clears it back to plain DNS). DoH embeds the profile
    id directly in the request, so — unlike NextDNS's IP-linking method —
    this works regardless of the router's public IP being stable, shared,
    or behind NAT (the same reason mikromon's site-to-site VPN uses
    WireGuard rather than depending on a fixed public IP)."""
    major, minor, _ver = _ros_version(pusher.api)
    if profile_id and not _doh_supported(major, minor):
        return Plan(pusher.cfg.name, [],
                    summary="nextdns (RouterOS needs 7.1+ for DNS-over-HTTPS)")
    desired = ({"use-doh-server": f"https://dns.nextdns.io/{profile_id}",
               "verify-doh-cert": "yes"} if profile_id
              else {"use-doh-server": ""})
    if profile_id:
        current = _safe_fetch(pusher.api, _DNS)
        cur = current[0] if current else {}
        # DoH still needs an ordinary DNS resolver to look up the DoH
        # server's OWN hostname in the first place — confirmed in
        # MikroTik's own documentation: "DoH server FQDN will be resolved
        # by regular DNS resolver." A router whose /ip/dns servers list has
        # never been set (common on a fresh unit that's only ever had this
        # single toggle pushed to it) has nothing to resolve
        # dns.nextdns.io with, so DoH — and therefore ALL DNS — never
        # comes up at all, which reads to a user as "NextDNS doesn't
        # connect." Only fills it in when it's genuinely empty; an
        # existing resolver (from the local filter tab's own DNS presets,
        # or whatever the router came with) is left alone.
        cur_servers = str(cur.get("servers", "")).strip()
        if not cur_servers:
            desired["servers"] = "1.1.1.1,8.8.8.8"
        # Confirmed live: this alone still isn't enough for anything BUT
        # the router itself to actually use NextDNS — allow-remote-requests
        # is what lets it answer DNS queries FROM LAN clients at all
        # (RouterOS's own DNS tab makes this explicit: "Must be ON for the
        # router to answer client DNS at all"). The one-click Enable button
        # here never touched it, only the DNS tab's separate quick-provider
        # form did — so a router that had never had THAT form applied kept
        # silently NOT serving DNS to anyone, and every client fell back to
        # its own/ISP-assigned resolver instead, looking exactly like
        # "NextDNS isn't being used" even though DoH itself was configured
        # correctly. Only turned on, never off, on disable — that's a
        # separate, deliberate choice the other form still owns.
        if _norm(cur.get("allow-remote-requests", "")) != "true":
            desired["allow-remote-requests"] = "true"
    plan = pusher.plan_settings(_DNS, desired, label="nextdns")
    return Plan(pusher.cfg.name, plan.ops, summary="nextdns")


def _detect_lan_subnets(pusher, cfg) -> list:
    """Candidate LAN subnets for the VPN tab's subnet picker: every IP
    address configured on this router except ones on a configured WAN
    uplink (the ISP/internet side — never what you'd want to route other
    sites into)."""
    wan_ifaces = {_norm_iface(lk.interface) for lk in cfg.wan.links if lk.interface}
    out, seen = [], set()
    for row in _safe_fetch(pusher.api, _IP_ADDRESS):
        if str(row.get("disabled", "false")).lower() in ("true", "yes"):
            continue
        iface = _norm_iface(row.get("interface", ""))
        if not iface or iface in wan_ifaces:
            continue
        addr = str(row.get("address", ""))
        network = str(row.get("network", ""))
        if "/" not in addr or not network:
            continue
        cidr = f"{network}/{addr.split('/', 1)[1]}"
        if cidr not in seen:
            seen.add(cidr)
            out.append(cidr)
    return out


def tunnel_read(pusher, cfg):
    major, minor, ver_str = _ros_version(pusher.api)
    if not _wg_supported(major, minor):
        return {"version": ver_str, "ifaces": [], "peers": [], "unsupported": True}
    try:
        ifaces = pusher.api.fetch(_WG_IFACE)
        peers = pusher.api.fetch(_WG_PEERS)
        lan_subnets = _detect_lan_subnets(pusher, cfg)
        return {"version": ver_str, "ifaces": ifaces, "peers": peers,
                "lan_subnets": lan_subnets}
    except Exception as exc:
        msg = str(exc)
        # API rejects the WireGuard menu on firmware that predates it.
        if any(kw in msg.lower()
               for kw in ("no such command", "bad command", "invalid command")):
            return {"version": ver_str, "ifaces": [], "peers": [], "unsupported": True}
        return {"version": ver_str, "ifaces": [], "peers": [], "error": msg}


def tunnel_form(current, cfg):
    """VPN tab — site-to-site: a router is either the "main" VPN host for a
    group of other routers, a "sub-unit" of another router's group, or not
    part of any group yet. Grouping itself (making a router the main host,
    adding/removing sub-units) is handled by dedicated actions in web.py's
    VPN-grouping box (current["vpn_role"] etc. is injected there, from
    hub.json, before this is called) — this form only ever pushes the
    routes that grouping implies, nothing to configure here directly."""
    if current.get("unsupported"):
        v = current.get("version", "unknown")
        return [{"type": "static", "label": "Not supported on this firmware",
                 "value": (f"WireGuard is available on RouterOS 7.1 and later. "
                           f"This router is running {v}. "
                           f"Upgrade to 7.1+ to use the VPN tab.")}]
    role = current.get("vpn_role")
    if role == "member":
        main_name = current.get("vpn_main", "?")
        return [
            {"type": "heading", "label": "Site-to-site VPN"},
            {"type": "static", "label": "Status",
             "value": f'This router is a sub-unit of "{main_name}"\'s VPN '
                      f'group. To change this, remove it from {main_name}\'s '
                      f'VPN tab first.'},
            {"type": "static", "label": "How this works",
             "value": "Routes to the main host and every other sub-unit — "
                      "plus the firewall rule that actually lets that "
                      "traffic pass through the tunnel — are pushed "
                      "automatically whenever the group changes. There's "
                      "nothing to do on this tab."},
        ]
    if role == "main":
        members = current.get("vpn_members") or {}
        member_list = ", ".join(sorted(members)) or "(none yet)"
        return [
            {"type": "heading", "label": "Site-to-site VPN — main host"},
            {"type": "static", "label": "This router's shared network",
             "value": current.get("vpn_own_subnet") or "(not detected)"},
            {"type": "static", "label": "Sub-units", "value": member_list},
            {"type": "static", "label": "How this works",
             "value": "Routes to every sub-unit listed above — plus the "
                      "firewall rule that actually lets that traffic pass "
                      "through the tunnel — are pushed automatically to "
                      "every affected router as soon as you add or remove "
                      "one below."},
        ]
    detected = current.get("lan_subnets") or []
    fields: list[dict] = [
        {"type": "heading", "label": "Site-to-site VPN",
         "hint": "Connects this router's own network to other routers' "
                 "networks through the WireGuard tunnel, so devices on "
                 "either side can reach each other directly — no separate "
                 "VPN client needed on those devices."},
        {"type": "static", "label": "Status",
         "value": "Not part of a VPN group yet. Make this router the main "
                  "host below, or add it as a sub-unit from another "
                  "router's VPN tab."},
    ]
    if detected:
        fields.append({"type": "static", "label": "Detected network(s) here",
                       "value": ", ".join(detected)})
    return fields


_VPN_FW_TAG = "mikromon:vpnfw:"


def _vpn_wg_iface_name(pusher) -> str:
    """This router's own dial-home WireGuard interface name, identified by
    the comment provisioning tags it with ("mikromon:tunnel:if") rather than
    assuming the literal name "mikromon" — belt-and-braces in case it was
    ever renamed by hand. "" if not found, so the caller skips the firewall
    op instead of guessing wrong."""
    for row in _safe_fetch(pusher.api, _WG_IFACE):
        if str(row.get("comment", "")) == "mikromon:tunnel:if":
            return row.get("name", "")
    return ""


def _vpn_firewall_ops(pusher, iface: str) -> list:
    """Forward-chain accept for the site-to-site tunnel, in both directions.
    Without this, a route alone isn't enough: routing decides WHERE a packet
    goes, but RouterOS's default (or hardened) forward policy commonly drops
    NEW forwarded traffic that isn't LAN-sourced, which would silently
    swallow VPN-group traffic even though the route is completely correct.
    Only "in-interface"/"out-interface" match this tunnel specifically — no
    address-list to keep in sync, since the interface itself already scopes
    this to exactly the traffic a grouped site legitimately carries.
    Added at the very front of the filter list (place-before=0) so an
    existing "drop everything else" rule further down can't shadow it — the
    same reasoning as the input-chain rule provisioning already adds for
    reaching the router's own management services over the tunnel. `iface`
    empty means "not part of a group" (or the interface couldn't be found) —
    remove any previously-added rule in that case."""
    current = _safe_fetch(pusher.api, _FILTER)
    tagged = {r.get("comment"): r for r in current
             if str(r.get("comment", "")).startswith(_VPN_FW_TAG)}
    desired = {
        _VPN_FW_TAG + "in": {"chain": "forward", "in-interface": iface},
        _VPN_FW_TAG + "out": {"chain": "forward", "out-interface": iface},
    } if iface else {}
    ops = []
    for tag, params in desired.items():
        if tag not in tagged:
            direction = tag.rsplit(":", 1)[-1]
            ops.append(Operation(
                "add", _FILTER, {**params, "action": "accept", "comment": tag,
                                 "place-before": 0},
                desc=f"allow VPN site-to-site traffic through the tunnel "
                     f"({direction})",
                inverse=Operation("remove", _FILTER, {},
                                  desc=f"remove VPN forward rule ({direction})")))
    for tag, row in tagged.items():
        if tag not in desired:
            direction = tag.rsplit(":", 1)[-1]
            ops.append(Operation(
                "remove", _FILTER, {".id": row[".id"]},
                desc=f"remove VPN forward rule ({direction}) — no longer in "
                     f"a group",
                inverse=Operation("add", _FILTER,
                                  {f: v for f, v in row.items() if f != ".id"},
                                  desc=f"restore VPN forward rule ({direction})")))
    return ops


def _vpn_hub_peer_ops(pusher, hub_subnet: str, other_subnets: list) -> list:
    """The router's OWN WireGuard peer entry FOR THE HUB (tagged
    "mikromon:tunnel:hub", created by Provision) restricts which SOURCE
    addresses it accepts decrypted traffic from via its allowed-address
    field — by default just the hub's own tunnel pool (e.g. 10.10.0.0/16).
    That's enough for the router's own dial-home traffic, but a reply (or
    any packet) arriving via a site-to-site VPN link has an inner source
    address on a REMOTE router's LAN, not a tunnel address — WireGuard
    silently drops it unless that subnet is ALSO in this peer's
    allowed-address. Routes and the forward-chain firewall rule alone are
    NOT enough; this is the piece that actually makes cross-site ping
    work — without it you get an immediate "host unreachable", not a
    timeout, since WireGuard itself refuses the packet rather than routing
    even getting a chance to drop it. Reverts to just `hub_subnet` alone
    when `other_subnets` is empty (not in a group, or just left one)."""
    peers = _safe_fetch(pusher.api, _HUB_PEERS)
    peer = next((p for p in peers
                if str(p.get("comment", "")).startswith(_HUB_TAG)), None)
    if peer is None:
        return []  # not provisioned for the tunnel — nothing to extend
    desired_set = {hub_subnet} | set(other_subnets)
    current_allowed = str(peer.get("allowed-address", "")).strip()
    current_set = {a.strip() for a in current_allowed.split(",") if a.strip()}
    if current_set == desired_set:
        return []
    desired_str = ", ".join(sorted(desired_set))
    extra = sorted(other_subnets)
    extra_desc = (", ".join(extra) if extra
                 else "(no other sites — reverting to just the hub pool)")
    return [Operation(
        "set", _HUB_PEERS,
        {".id": peer[".id"], "allowed-address": desired_str},
        desc=f"extend the hub peer's allowed-address to also accept "
             f"{extra_desc} — otherwise WireGuard silently drops "
             f"site-to-site VPN traffic sourced from those subnets",
        inverse=Operation(
            "set", _HUB_PEERS,
            {".id": peer[".id"], "allowed-address": current_allowed},
            desc="revert the hub peer's allowed-address"))]


def hub_endpoint_ops(pusher, endpoint: str, port: str,
                     pubkey: str | None = None) -> list:
    """Update the router's OWN hub-peer entry's endpoint-address/
    endpoint-port — for migrating the hub to a new server/IP (or adopting a
    DDNS hostname) without re-provisioning every router by hand. When
    `pubkey` is also given, updates public-key too — for a migration where
    the NEW server generated its own fresh WireGuard identity instead of
    the old server's private key being copied over (avoids ever needing to
    move a private key between hosts by hand at all: a router just needs
    to be told the new server's public key + address, both of which are
    freely shareable). Deliberately leaves allowed-address untouched (see
    _vpn_hub_peer_ops) so this never undoes a router's VPN-group
    extensions. No-op if the router has no hub peer at all, or already
    matches."""
    peers = _safe_fetch(pusher.api, _HUB_PEERS)
    peer = next((p for p in peers
                if str(p.get("comment", "")).startswith(_HUB_TAG)), None)
    if peer is None:
        return []
    cur_endpoint = str(peer.get("endpoint-address", "")).strip()
    cur_port = str(peer.get("endpoint-port", "")).strip()
    cur_pubkey = str(peer.get("public-key", "")).strip()
    want_pubkey = pubkey.strip() if pubkey else cur_pubkey
    if cur_endpoint == endpoint and cur_port == str(port) and cur_pubkey == want_pubkey:
        return []
    new_params = {".id": peer[".id"], "endpoint-address": endpoint,
                 "endpoint-port": str(port)}
    old_params = {".id": peer[".id"], "endpoint-address": cur_endpoint,
                 "endpoint-port": cur_port}
    if pubkey:
        new_params["public-key"] = want_pubkey
        old_params["public-key"] = cur_pubkey
    return [Operation(
        "set", _HUB_PEERS, new_params,
        desc=f"point the hub peer at {endpoint}:{port}"
             + (" with a new public key" if pubkey else "")
             + f" (was {cur_endpoint or '?'}:{cur_port or '?'})",
        inverse=Operation(
            "set", _HUB_PEERS, old_params,
            desc="revert the hub peer's endpoint"))]


def tunnel_plan(pusher, cfg, flat, multi):
    """Push (or remove) static routes so this router can reach every other
    site in its VPN group through the hub, the forward-chain firewall rule
    that actually lets that traffic pass (_vpn_firewall_ops), and the
    matching expansion of the router's OWN hub-peer allowed-address
    (_vpn_hub_peer_ops) — routes and the firewall rule alone are not
    enough; WireGuard itself will otherwise silently drop inbound traffic
    sourced from a remote site's LAN. web.py's _prep_vpn_group injects
    flat["_vpn_other_subnets"] (every OTHER site's subnet in this router's
    own group, from hub.json), flat["_vpn_hub_ip"] (the gateway to use —
    the hub's own tunnel address), flat["_vpn_hub_subnet"] (the hub's whole
    tunnel pool, e.g. 10.10.0.0/16) and flat["_vpn_in_group"] before
    calling this; flat["_vpn_error"] is set instead if a submitted subnet
    conflicted with another site or the tunnel network (surfaced via a
    dedicated grouping action, not this form, but tunnel_plan still checks
    it defensively)."""
    if flat.get("_vpn_error"):
        raise PushError(flat["_vpn_error"])
    in_group = bool(flat.get("_vpn_in_group"))
    hub_ip = flat.get("_vpn_hub_ip") or ""
    hub_subnet = flat.get("_vpn_hub_subnet") or "10.10.0.0/16"
    other_subnets = flat.get("_vpn_other_subnets") or []
    current_routes = _safe_fetch(pusher.api, _ROUTE)
    desired = ([{"dst-address": subnet, "gateway": hub_ip}
               for subnet in other_subnets] if (in_group and hub_ip) else [])
    ops = reconcile_list(_ROUTE, "dst-address", desired, current_routes,
                         manage_tag=_VPN_ROUTE_TAG,
                         owns=_prefix_owner(_VPN_ROUTE_TAG),
                         label="VPN site route")
    iface = _vpn_wg_iface_name(pusher) if in_group else ""
    ops += _vpn_firewall_ops(pusher, iface)
    ops += _vpn_hub_peer_ops(pusher, hub_subnet,
                             other_subnets if in_group else [])
    return Plan(cfg.name, ops,
               summary=f"vpn: {len(other_subnets)} site route(s)"
                       if in_group else "vpn (not part of a group)")


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
    if op.inverse:
        op.inverse.desc = "release (restore previous comment)"
    return Plan(cfg.name, [op], summary="adopt")


# ===========================================================================
# Registry — keyed by URL slug; order follows the device tab bar.
# ===========================================================================
FEATURES = {
    "routes": {"title": "Routes — Gateway Failover", "write": True,
               "read": routes_read,
               "form": routes_form, "plan": routes_plan},
    "wan": {"title": "WAN — policy routing", "write": True,
            "read": sdwan_read, "summary": sdwan_summary, "form": sdwan_form,
            "plan": sdwan_plan},
    "security": {"title": "Security", "write": True, "read": security_read,
                 "summary": security_summary, "form": security_form,
                 "plan": security_plan, "unmanaged": security_unmanaged},
    "harden": {"title": "Restrict management access", "write": True,
               "read": harden_read, "summary": harden_summary,
               "form": harden_form, "plan": harden_plan},
    # DNS server selection (quick provider presets, force-client-DNS) still
    # lives here and still writes to the router — only the local sinkhole
    # domain-blocking half of this tab was retired (nextdns_form/_plan no
    # longer touch /ip/dns/static or take a block_ip/block list at all),
    # in favor of the real NextDNS.io cloud integration's own Security/
    # Parental Control/Privacy panels (see nextdns_cloud_ops above and
    # web.py's _nextdns_box/_nextdns_*_box, rendered into this same tab via
    # extra_html) — cloud threat intelligence and real category/service
    # toggles instead of a fixed local domain list, not a step down.
    # summary still surfaces any block-group entries left over on a router
    # from before this change, read-only (nothing here can touch them
    # anymore).
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
    "tunnel": {"title": "VPN", "write": True,
               "read": tunnel_read, "form": tunnel_form, "plan": tunnel_plan},
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
             "Remote access": "remote", "VPN": "tunnel",
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
