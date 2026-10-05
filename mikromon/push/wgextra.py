"""Extra WireGuard: this router dialling somebody else's VPN server.

The router already runs one WireGuard interface, "mikromon" -- the tunnel we
manage it over. This adds others beside it, for a VPN service such as AdGuard
VPN, filled in from the [Interface] and [Peer] sections of the config file
that service hands out.

RouterOS is happy with several WireGuard interfaces, each with its own key
and listen port, and nothing here touches the management tunnel's own rows.
What CAN go wrong is all in the routing, so that is where the care goes:

  * RouterOS does not turn a peer's allowed-address into routes the way the
    phone and PC apps turn AllowedIPs into routes. So a route is added for
    each allowed range, which is what makes traffic for exactly those
    addresses -- and nothing else -- go through the tunnel.

  * A range that covered our own server would send the management tunnel's
    packets into somebody else's VPN, and we would lose the router. The same
    goes for its default gateway, its own networks, the VPN server it is
    dialling (a routing loop) and the site-to-site subnets. Each of those is
    refused before anything is sent, with the reason.

  * Devices on the LAN reach the far side masqueraded behind the tunnel
    address, because a VPN service only answers the one address it issued.

  * New connections arriving FROM the tunnel are dropped, into the LAN and
    into the router. Replies to traffic the site started still flow. Without
    this, the default firewall -- which only guards the interfaces in its WAN
    list -- would let the far end open connections to anything on the LAN.

DNS from the config file is deliberately not applied. The router has one DNS
setting for everything, the DNS tab (NextDNS) owns it, and pointing the whole
site at a server inside this tunnel would take its DNS down whenever the
tunnel drops.

The private key is sent to the router and nowhere else: never shown back,
never written into a plan line, the preview or the activity log.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import re
import socket

from .api import PlanRefused
from .plan import Operation, Plan
from .reconcile import reconcile_list

_WG = ("interface", "wireguard")
_PEERS = ("interface", "wireguard", "peers")
_ADDR = ("ip", "address")
_ROUTE = ("ip", "route")
_NAT = ("ip", "firewall", "nat")
_FILTER = ("ip", "firewall", "filter")
_IFACES = ("interface",)
_RESOURCE = ("system", "resource")

# Every row this feature owns carries a comment starting with this.
TAG = "mikromon:wgx:"
# The management tunnel's own rows -- never ours, never touched.
_HUB_IFACE_TAG = "mikromon:tunnel:if"
_HUB_PEER_PREFIX = "mikromon:tunnel:"

# The management tunnel listens on 13231; extra interfaces start above it.
FIRST_PORT = 13232
DEFAULT_KEEPALIVE = 25
DEFAULT_ENDPOINT_PORT = 51820

_NAME_OK = re.compile(r"^[a-z][a-z0-9-]{0,14}$")
_HOST_OK = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class WgError(ValueError):
    """One connection that cannot be used, with the reason a person needs."""


# ---------------------------------------------------------------------------
# Parsing what was typed in
# ---------------------------------------------------------------------------
def parse_key(text: str, what: str) -> str:
    """A WireGuard key: 44 characters of base64 that decode to 32 bytes."""
    raw = (text or "").strip()
    if not raw:
        raise WgError(f"The {what} is missing.")
    try:
        ok = len(base64.b64decode(raw, validate=True)) == 32
    except (binascii.Error, ValueError):
        ok = False
    if not ok or len(raw) != 44:
        # Never quote the value back: for the private key that would put it
        # on the page and in the activity log.
        raise WgError(
            f"The {what} is not a WireGuard key. It should be 44 characters "
            f"ending in '=', copied exactly from the config file.")
    return raw


def parse_address(text: str) -> ipaddress.IPv4Interface:
    raw = (text or "").strip()
    if not raw:
        raise WgError("The interface address is missing (Address in the "
                      "[Interface] section, e.g. 10.2.0.2/32).")
    # A config file often lists an IPv6 address too; only the IPv4 one is
    # used, so take the first IPv4 entry rather than refusing the paste.
    parts = [p for p in re.split(r"[\s,;]+", raw) if p]
    for part in parts:
        try:
            iface = ipaddress.ip_interface(part)
        except ValueError:
            raise WgError(f"{part!r} is not an address. It should look like "
                          f"10.2.0.2/32.") from None
        if iface.version == 4:
            return iface
    raise WgError("The interface address has to include an IPv4 address, "
                  "e.g. 10.2.0.2/32.")


def parse_allowed(text: str) -> list:
    """The destinations that go through this tunnel, as IPv4 networks."""
    out = []
    for part in re.split(r"[\s,;]+", (text or "").strip()):
        if not part:
            continue
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError:
            raise WgError(f"{part!r} in Allowed IPs is not an address or "
                          f"range.") from None
        if net.version != 4:
            raise WgError(
                f"{part} is IPv6. Only IPv4 is routed into an extra tunnel; "
                f"remove the IPv6 entries from Allowed IPs.")
        if net.prefixlen == 0:
            raise WgError(
                "Allowed IPs is 0.0.0.0/0, which sends every packet the site "
                "has through this tunnel -- including the connection we "
                "manage this router over. List only the addresses that "
                "should use it.")
        if net not in out:
            out.append(net)
    if not out:
        raise WgError("Allowed IPs is empty. List the addresses that should "
                      "go through this tunnel.")
    return out


def parse_endpoint(text: str) -> tuple:
    """(host, port) from 'host:port', 'host' or '[v6]:port'."""
    raw = (text or "").strip()
    if not raw:
        raise WgError("The endpoint is missing (Endpoint in the [Peer] "
                      "section, e.g. vpn.example.com:51820).")
    port = None
    m = re.match(r"^\[([0-9A-Fa-f:.]+)\](?::(\d+))?$", raw)
    if m:
        host, port = m.group(1), m.group(2)
    elif raw.count(":") == 1:
        host, port = raw.split(":")
    else:
        host = raw
    host = host.strip()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOST_OK.match(host):
            raise WgError(f"{host!r} is not a host name or IP address."
                          ) from None
    try:
        port = int(port) if port not in (None, "") else DEFAULT_ENDPOINT_PORT
    except ValueError:
        raise WgError(f"{raw!r}: the port after ':' has to be a number."
                      ) from None
    if not 1 <= port <= 65535:
        raise WgError(f"{raw!r}: port {port} is out of range.")
    return host, port


def parse_keepalive(text) -> int:
    raw = str(text if text is not None else "").strip().lower()
    if not raw:
        return DEFAULT_KEEPALIVE
    secs = keepalive_seconds(raw)
    if secs is None or not 0 <= secs <= 65535:
        raise WgError(f"{raw!r} is not a keepalive. Use a number of seconds, "
                      f"e.g. 25, or 0 for none.")
    return secs


def keepalive_seconds(value) -> int | None:
    """'25', '25s', '1m5s' or '00:00:25' as seconds. None if unreadable."""
    raw = str(value or "").strip().lower()
    if not raw:
        return 0
    if raw.isdigit():
        return int(raw)
    if re.match(r"^\d+:\d{2}:\d{2}$", raw):
        h, m, s = (int(x) for x in raw.split(":"))
        return h * 3600 + m * 60 + s
    total, found = 0, False
    for num, unit in re.findall(r"(\d+)\s*([hms])", raw):
        found = True
        total += int(num) * {"h": 3600, "m": 60, "s": 1}[unit]
    if not found or re.sub(r"\d+\s*[hms]", "", raw).strip():
        return None
    return total


def make(name, *, private_key="", address="", public_key="", allowed="",
         endpoint="", keepalive="", key_required=True) -> dict:
    """One validated connection. Raises WgError with the reason."""
    clean = (name or "").strip().lower()
    if not _NAME_OK.match(clean):
        raise WgError(
            "The connection name becomes the interface name on the router: "
            "use a short lower-case name like 'adguard' -- letters, numbers "
            "and dashes, starting with a letter.")
    host, port = parse_endpoint(endpoint)
    return {
        "name": clean,
        "private_key": (parse_key(private_key, "private key")
                        if key_required or (private_key or "").strip()
                        else ""),
        "address": parse_address(address),
        "public_key": parse_key(public_key, "peer public key"),
        "allowed": parse_allowed(allowed),
        "endpoint_host": host,
        "endpoint_port": port,
        "keepalive": parse_keepalive(keepalive),
    }


# ---------------------------------------------------------------------------
# Reading the router
# ---------------------------------------------------------------------------
def _fetch(api, path) -> list:
    try:
        return list(api.fetch(path) or [])
    except Exception:  # noqa: BLE001 - a missing menu reads as nothing
        return []


def _yes(v) -> bool:
    return str(v or "").strip().lower() in ("true", "yes")


def _ros_major_minor(api) -> tuple:
    rows = _fetch(api, _RESOURCE)
    ver = str(rows[0].get("version", "")) if rows else ""
    nums = re.findall(r"\d+", ver)
    major = int(nums[0]) if nums else 0
    minor = int(nums[1]) if len(nums) > 1 else 0
    return major, minor, ver or "unknown"


def _owner(name: str):
    """Rows belonging to connection `name`: its interface and its parts."""
    exact, prefix = TAG + name, TAG + name + ":"
    return lambda r: (str(r.get("comment", "")) == exact
                      or str(r.get("comment", "")).startswith(prefix))


def _comment(name: str, part: str = "") -> str:
    return TAG + name + (":" + part if part else "")


def _resolve_default(host: str) -> set:
    """IPv4 addresses for a host name, best-effort and quick.

    Used only to check that an allowed range does not swallow a VPN server's
    own address. A name that will not resolve is not a reason to refuse --
    it is just one check that cannot be made.
    """
    try:
        return {ipaddress.ip_address(host)}
    except ValueError:
        pass
    import concurrent.futures as cf
    ex = cf.ThreadPoolExecutor(max_workers=1)
    try:
        fut = ex.submit(socket.getaddrinfo, host, None, socket.AF_INET)
        infos = fut.result(timeout=3)
        return {ipaddress.ip_address(i[4][0]) for i in infos}
    except Exception:  # noqa: BLE001
        return set()
    finally:
        ex.shutdown(wait=False)


# Swapped out by the tests, so they never touch DNS.
resolve = _resolve_default


def read_router(api) -> dict:
    """Everything the tab and the plan need, in one pass."""
    major, minor, ver = _ros_major_minor(api)
    unsupported = 0 < major and (major, minor) < (7, 1)
    out = {"version": ver, "unsupported": unsupported, "conns": [],
           "wg": [], "peers": [], "addresses": [], "routes": [], "nat": [],
           "filter": [], "interfaces": []}
    if unsupported:
        return out
    out.update(wg=_fetch(api, _WG), peers=_fetch(api, _PEERS),
               addresses=_fetch(api, _ADDR), routes=_fetch(api, _ROUTE),
               nat=_fetch(api, _NAT), filter=_fetch(api, _FILTER),
               interfaces=_fetch(api, _IFACES))
    for row in out["wg"]:
        comment = str(row.get("comment", ""))
        if not comment.startswith(TAG) or ":" in comment[len(TAG):]:
            continue
        name = comment[len(TAG):]
        if row.get("name") != name:
            continue
        mine = _owner(name)
        out["conns"].append({
            "name": name,
            "iface": row,
            "peer": next((p for p in out["peers"]
                          if p.get("comment") == _comment(name, "peer")), {}),
            "addr": next((a for a in out["addresses"]
                          if a.get("comment") == _comment(name, "addr")), {}),
            "routes": [r for r in out["routes"] if mine(r)],
            "nat": [r for r in out["nat"] if mine(r)],
            "filter": [r for r in out["filter"] if mine(r)],
        })
    out["conns"].sort(key=lambda c: c["name"])
    return out


def _net(text):
    try:
        return ipaddress.ip_network(str(text).strip(), strict=False)
    except ValueError:
        return None


def _hub_context(state: dict) -> dict:
    """What the management tunnel and the site depend on."""
    hub_peer = next((p for p in state["peers"]
                     if str(p.get("comment", "")).startswith(_HUB_PEER_PREFIX)),
                    {})
    hub_iface = next((w for w in state["wg"]
                      if w.get("comment") == _HUB_IFACE_TAG
                      or w.get("name") == "mikromon"), {})
    hub_nets = []
    for part in str(hub_peer.get("allowed-address", "")).split(","):
        n = _net(part)
        if n is not None and n.version == 4:
            hub_nets.append(n)
    for a in state["addresses"]:
        if hub_iface and a.get("interface") == hub_iface.get("name"):
            n = _net(a.get("address", ""))
            if n is not None:
                hub_nets.append(n)
    endpoint = str(hub_peer.get("endpoint-address", "")).strip()
    gateways = set()
    for r in state["routes"]:
        if str(r.get("dst-address", "")) != "0.0.0.0/0":
            continue
        for gw in str(r.get("gateway", "")).split(","):
            try:
                gateways.add(ipaddress.ip_address(gw.split("%")[0].strip()))
            except ValueError:
                continue
    return {"hub_nets": hub_nets,
            "hub_endpoint": endpoint,
            "hub_endpoint_ips": resolve(endpoint) if endpoint else set(),
            "gateways": gateways}


def check(conn: dict, state: dict, ctx: dict, others=()) -> list:
    """Why this connection would break something, before anything is sent.

    `others` are the other extra connections as they will be after this
    push, as (name, [networks]).
    """
    name = conn["name"]
    mine = _owner(name)
    problems = []

    managed = {c["name"] for c in state["conns"]}
    taken = {str(i.get("name", "")) for i in state["interfaces"]}
    taken |= {str(w.get("name", "")) for w in state["wg"]}
    if name not in managed and name in taken:
        problems.append(
            f"{name}: an interface called {name} already exists on this "
            f"router and was not made here. Pick another name.")

    own = conn["address"]
    own_net = own.network
    router_nets = []
    for a in state["addresses"]:
        if mine(a) or _yes(a.get("disabled")):
            continue
        n = _net(a.get("address", ""))
        if n is not None and n.version == 4:
            router_nets.append((n, str(a.get("interface", "?"))))

    for n, iface in router_nets:
        if own_net.overlaps(n):
            problems.append(
                f"{name}: the address {own} overlaps {n} on {iface}. Two "
                f"interfaces claiming one range route unpredictably.")
    for n in ctx["hub_nets"]:
        if own_net.overlaps(n):
            problems.append(
                f"{name}: the address {own} overlaps {n}, which the "
                f"management tunnel uses. Ask the VPN provider for a "
                f"different address range.")

    endpoint_ips = resolve(conn["endpoint_host"])
    for net in conn["allowed"]:
        if net.subnet_of(own_net):
            continue  # the tunnel's own subnet: already on the interface
        hit = next((ip for ip in ctx["hub_endpoint_ips"] if ip in net), None)
        if hit is not None:
            problems.append(
                f"{name}: Allowed IPs {net} includes {hit}, our management "
                f"server. Its traffic would go into this tunnel and we "
                f"would lose the router.")
        for gw in ctx["gateways"]:
            if gw in net:
                problems.append(
                    f"{name}: Allowed IPs {net} includes {gw}, this "
                    f"router's internet gateway. The whole site would lose "
                    f"its internet connection.")
        for ip in endpoint_ips:
            if ip in net:
                problems.append(
                    f"{name}: Allowed IPs {net} includes {ip}, the VPN "
                    f"server's own address. The tunnel's packets would be "
                    f"routed into the tunnel and it would never connect.")
        for n in ctx["hub_nets"]:
            if net.overlaps(n):
                problems.append(
                    f"{name}: Allowed IPs {net} overlaps {n}, which the "
                    f"management tunnel and site-to-site VPN use.")
        for n, iface in router_nets:
            if net.overlaps(n):
                problems.append(
                    f"{name}: Allowed IPs {net} overlaps {n} on {iface}. "
                    f"Devices on that network would be cut off.")
        for other, nets in others:
            for n in nets:
                if net.overlaps(n):
                    problems.append(
                        f"{name}: Allowed IPs {net} overlaps {n}, which "
                        f"already goes through {other}.")
        for r in state["routes"]:
            if mine(r) or _yes(r.get("dynamic")):
                continue
            if str(r.get("comment", "")).startswith(TAG):
                continue  # another extra connection: covered above
            if _net(r.get("dst-address", "")) == net:
                problems.append(
                    f"{name}: {net} is already routed via "
                    f"{r.get('gateway', '?')} by a route that was not made "
                    f"here. Remove that route first, or leave {net} out.")
    # One message per fact, however many ranges hit it.
    return list(dict.fromkeys(problems))


# ---------------------------------------------------------------------------
# What the router is told
# ---------------------------------------------------------------------------
def _add(path, params, desc, undo):
    return Operation("add", path, params, desc=desc,
                     inverse=Operation("remove", path, {}, desc=undo))


def _set(path, row, changes, desc, undo):
    old = {k: row.get(k, "") for k in changes}
    return Operation("set", path, {".id": row[".id"], **changes}, desc=desc,
                     inverse=Operation("set", path, {".id": row[".id"], **old},
                                       desc=undo))


def _remove(path, row, fields, desc, undo):
    restore = {k: row[k] for k in fields if row.get(k) not in (None, "")}
    return Operation("remove", path, {".id": row[".id"]}, desc=desc,
                     inverse=Operation("add", path, restore, desc=undo))


_IFACE_FIELDS = ("name", "listen-port", "private-key", "mtu", "comment")
_PEER_FIELDS = ("interface", "public-key", "endpoint-address",
                "endpoint-port", "allowed-address", "persistent-keepalive",
                "preshared-key", "comment")
_ADDR_FIELDS = ("address", "interface", "comment")
_RULE_FIELDS = ("chain", "in-interface", "out-interface", "connection-state",
                "action", "comment")


def _free_port(state) -> int:
    used = set()
    for w in state["wg"]:
        try:
            used.add(int(str(w.get("listen-port", "")).strip()))
        except ValueError:
            continue
    port = FIRST_PORT
    while port in used:
        port += 1
    return port


def _top_id(rows) -> str:
    """The first rule a new one can be placed before ("" if none).

    Dynamic rules -- the fasttrack counter RouterOS shows at the top -- cannot
    be placed before, so they are skipped.
    """
    for r in rows:
        if not _yes(r.get("dynamic")) and r.get(".id"):
            return str(r[".id"])
    return ""


def _short(key: str) -> str:
    return key[:8] + "…" if len(key) > 8 else key


def _rules(name: str) -> list:
    """The firewall and NAT rows one connection needs, keyed by comment."""
    return [
        (_FILTER, {"chain": "forward", "in-interface": name,
                   "connection-state": "new", "action": "drop",
                   "comment": _comment(name, "in-lan")},
         f"drop new connections from {name} into the LAN (replies to the "
         f"site's own traffic still flow)"),
        (_FILTER, {"chain": "input", "in-interface": name,
                   "connection-state": "new", "action": "drop",
                   "comment": _comment(name, "in-router")},
         f"drop new connections from {name} to the router itself"),
        (_NAT, {"chain": "srcnat", "out-interface": name,
                "action": "masquerade", "comment": _comment(name, "nat")},
         f"masquerade LAN traffic going out {name} behind the tunnel "
         f"address"),
    ]


def _connection_ops(conn: dict, existing: dict | None, state: dict) -> list:
    """Create or update one connection. Nothing for an unchanged one."""
    name = conn["name"]
    ops = []
    ex = existing or {}

    # The interface, carrying the private key.
    iface = ex.get("iface")
    if not iface:
        port = _free_port(state)
        ops.append(_add(_WG, {"name": name, "listen-port": str(port),
                              "private-key": conn["private_key"],
                              "comment": _comment(name)},
                        f"create WireGuard interface {name} (listen port "
                        f"{port}, private key from the config file)",
                        f"remove WireGuard interface {name}"))
    elif conn["private_key"] and conn["private_key"] != iface.get(
            "private-key"):
        ops.append(_set(_WG, iface, {"private-key": conn["private_key"]},
                        f"replace {name}'s private key",
                        f"put back {name}'s previous private key"))

    # Its address.
    want_addr = str(conn["address"])
    addr = ex.get("addr")
    if not addr:
        ops.append(_add(_ADDR, {"address": want_addr, "interface": name,
                                "comment": _comment(name, "addr")},
                        f"give {name} the address {want_addr}",
                        f"remove {want_addr} from {name}"))
    elif str(addr.get("address", "")) != want_addr:
        ops.append(_set(_ADDR, addr, {"address": want_addr},
                        f"change {name}'s address to {want_addr} (was "
                        f"{addr.get('address', '?')})",
                        f"put {name}'s address back"))

    # The VPN server it dials.
    allowed = ",".join(str(n) for n in conn["allowed"])
    want_peer = {"interface": name, "public-key": conn["public_key"],
                 "endpoint-address": conn["endpoint_host"],
                 "endpoint-port": str(conn["endpoint_port"]),
                 "allowed-address": allowed,
                 "persistent-keepalive": f"{conn['keepalive']}s",
                 "comment": _comment(name, "peer")}
    where = f"{conn['endpoint_host']}:{conn['endpoint_port']}"
    peer = ex.get("peer")
    if not peer:
        ops.append(_add(_PEERS, want_peer,
                        f"add {name}'s peer: server {where}, public key "
                        f"{_short(conn['public_key'])}, allowed {allowed}, "
                        f"keepalive {conn['keepalive']}s",
                        f"remove {name}'s peer"))
    else:
        changes = {}
        for field in ("public-key", "endpoint-address", "endpoint-port",
                      "interface"):
            if str(peer.get(field, "")).strip() != want_peer[field]:
                changes[field] = want_peer[field]
        have = {_net(p) for p in str(peer.get("allowed-address", ""))
                .split(",") if p.strip()}
        if have != set(conn["allowed"]):
            changes["allowed-address"] = allowed
        if keepalive_seconds(peer.get("persistent-keepalive")) != \
                conn["keepalive"]:
            changes["persistent-keepalive"] = want_peer["persistent-keepalive"]
        if changes:
            said = ", ".join(
                f"{k}={_short(v) if k == 'public-key' else v}"
                for k, v in changes.items())
            ops.append(_set(_PEERS, peer, changes,
                            f"update {name}'s peer: {said}",
                            f"put {name}'s peer back"))

    # Protection first, then NAT, so traffic never flows unguarded.
    have_rules = {r.get("comment"): r for r in
                  ex.get("filter", []) + ex.get("nat", [])}
    for path, want, desc in _rules(name):
        row = have_rules.get(want["comment"])
        if row is None:
            params = dict(want)
            top = _top_id(state["filter"] if path == _FILTER
                          else state["nat"])
            if top:
                params["place-before"] = top
            ops.append(_add(path, params, desc, f"undo: {desc}"))
        else:
            changes = {k: v for k, v in want.items()
                       if str(row.get(k, "")) != v}
            if changes:
                ops.append(_set(path, row, changes, f"repair: {desc}",
                                f"undo repair: {desc}"))

    # Routes last: only once everything above exists does traffic move.
    desired = [{"dst-address": str(n), "gateway": name}
               for n in conn["allowed"]
               if not n.subnet_of(conn["address"].network)]
    ops += reconcile_list(_ROUTE, "dst-address", desired,
                          ex.get("routes", []),
                          manage_tag=_comment(name, "route"),
                          owns=lambda r: r.get("comment") ==
                          _comment(name, "route"),
                          label=f"route via {name}")
    return ops


def _removal_ops(existing: dict) -> list:
    """Take one connection off the router, leaving nothing behind."""
    name = existing["name"]
    ops = []
    for r in existing.get("routes", []):
        ops.append(_remove(_ROUTE, r, ("dst-address", "gateway", "comment"),
                           f"remove route {r.get('dst-address', '?')} via "
                           f"{name}", f"restore route via {name}"))
    for path, rows in ((_NAT, existing.get("nat", [])),
                       (_FILTER, existing.get("filter", []))):
        for r in rows:
            ops.append(_remove(path, r, _RULE_FIELDS,
                               f"remove {name}'s {r.get('chain', '')} rule "
                               f"({r.get('action', '')})",
                               f"restore {name}'s {r.get('chain', '')} rule"))
    if existing.get("peer"):
        ops.append(_remove(_PEERS, existing["peer"], _PEER_FIELDS,
                           f"remove {name}'s peer", f"restore {name}'s peer"))
    if existing.get("addr"):
        ops.append(_remove(_ADDR, existing["addr"], _ADDR_FIELDS,
                           f"remove {name}'s address "
                           f"{existing['addr'].get('address', '')}",
                           f"restore {name}'s address"))
    ops.append(_remove(_WG, existing["iface"], _IFACE_FIELDS,
                       f"remove WireGuard interface {name}",
                       f"restore WireGuard interface {name}"))
    return ops


# ---------------------------------------------------------------------------
# The tab: read / summary / form / plan
# ---------------------------------------------------------------------------
def wgextra_read(pusher, cfg):
    return read_router(pusher.api)


def wgextra_summary(current, cfg):
    if current.get("unsupported"):
        return [f"WireGuard needs RouterOS 7.1 or later; this router runs "
                f"{current.get('version', 'unknown')}."]
    conns = current.get("conns") or []
    if not conns:
        return ["No extra WireGuard connections yet. The management tunnel "
                "is separate and is not shown here."]
    lines = []
    for c in conns:
        peer, iface = c["peer"], c["iface"]
        hs = str(peer.get("last-handshake", "")).strip()
        state = ("disabled" if _yes(iface.get("disabled")) else
                 f"connected, last handshake {hs} ago" if hs else
                 "no handshake yet: check the keys and the endpoint")
        lines.append(
            f"{c['name']}: {c['addr'].get('address', 'no address')} to "
            f"{peer.get('endpoint-address', '?')}:"
            f"{peer.get('endpoint-port', '?')}, carrying "
            f"{peer.get('allowed-address', 'nothing')} ({state})")
    return lines


def _block_fields(i: int, conn: dict | None) -> list:
    """The fields for one connection; `conn` None is the empty 'add' block."""
    p = f"c{i}_"
    if conn is None:
        head = [{"type": "heading", "label": "Add a connection",
                 "hint": "Copy each value from the WireGuard config file "
                         "the VPN provider gave you."},
                {"type": "text", "name": p + "name",
                 "label": "Connection name (becomes the interface name)",
                 "value": "", "placeholder": "adguard"}]
        peer, addr = {}, {}
        key_hint = "PrivateKey in the [Interface] section."
        key_ph = "PrivateKey"
    else:
        peer, addr = conn["peer"], conn["addr"]
        pub = conn["iface"].get("public-key", "")
        head = [{"type": "heading", "label": f"Connection: {conn['name']}",
                 "hint": (f"This router's public key: {pub}" if pub else "")},
                {"type": "hidden", "name": p + "existing",
                 "value": conn["name"]}]
        key_hint = "Leave blank to keep the key the router already has."
        key_ph = "unchanged"
    ka = keepalive_seconds(peer.get("persistent-keepalive"))
    fields = head + [
        {"type": "secret", "name": p + "private_key",
         "label": "Interface: private key", "placeholder": key_ph,
         "hint": key_hint},
        {"type": "text", "name": p + "address", "label": "Interface: address",
         "value": addr.get("address", ""), "placeholder": "10.2.0.2/32"},
        {"type": "text", "name": p + "public_key",
         "label": "Peer: public key", "value": peer.get("public-key", ""),
         "placeholder": "PublicKey in the [Peer] section"},
        {"type": "text", "name": p + "allowed", "label": "Peer: allowed IPs",
         "value": peer.get("allowed-address", ""),
         "placeholder": "94.140.14.14/32, 94.140.15.15/32",
         "hint": "Only these addresses go through the tunnel. Everything "
                 "else, including our management connection, is "
                 "unaffected."},
        {"type": "text", "name": p + "endpoint", "label": "Peer: endpoint",
         "value": (f"{peer.get('endpoint-address', '')}:"
                   f"{peer.get('endpoint-port', '')}"
                   if peer.get("endpoint-address") else ""),
         "placeholder": "vpn.example.com:51820"},
        {"type": "text", "name": p + "keepalive",
         "label": "Peer: persistent keepalive (seconds)",
         "value": str(ka) if peer else str(DEFAULT_KEEPALIVE),
         "placeholder": str(DEFAULT_KEEPALIVE)},
    ]
    if conn is not None:
        fields.append({"type": "select", "name": p + "action",
                       "label": "This connection", "value": "keep",
                       "options": [("keep", "Keep (apply any edits above)"),
                                   ("remove", "Remove it from the router")]})
    return fields


def wgextra_form(current, cfg):
    if current.get("unsupported"):
        return [{"type": "static", "label": "Not supported on this firmware",
                 "value": f"WireGuard needs RouterOS 7.1 or later. This "
                          f"router runs {current.get('version', 'unknown')}."}]
    fields = []
    conns = current.get("conns") or []
    for i, c in enumerate(conns):
        fields += _block_fields(i, c)
    fields += _block_fields(len(conns), None)
    return fields


_TYPED = ("name", "private_key", "address", "public_key", "allowed",
          "endpoint")


def _blocks(flat: dict) -> list:
    idx = sorted({int(m.group(1)) for k in flat
                  for m in [re.match(r"^c(\d+)_", str(k))] if m})
    return [{k[len(f"c{i}_"):]: str(v or "").strip()
             for k, v in flat.items() if str(k).startswith(f"c{i}_")}
            for i in idx]


def wgextra_plan(pusher, cfg, flat, multi):
    state = read_router(pusher.api)
    if state["unsupported"]:
        raise PlanRefused(
            f"Nothing was sent to the router.\nWireGuard needs RouterOS 7.1 "
            f"or later; this router runs {state['version']}.")
    by_name = {c["name"]: c for c in state["conns"]}
    problems, wanted, removing = [], [], []

    for b in _blocks(flat):
        existing = b.get("existing", "")
        if existing:
            if existing not in by_name:
                problems.append(f"{existing} is no longer on the router. "
                                f"Reload the tab.")
                continue
            if b.get("action") == "remove":
                removing.append(by_name[existing])
                continue
            name, key_required = existing, False
        else:
            # Keepalive arrives pre-filled, so it says nothing about whether
            # anybody started filling the block in.
            if not any(b.get(k) for k in _TYPED):
                continue  # the untouched "add" block
            name, key_required = b.get("name", ""), True
            if name.strip().lower() in by_name:
                problems.append(
                    f"{name.strip().lower()} already exists. Edit it in its "
                    f"own section instead of adding it again.")
                continue
        try:
            wanted.append(make(
                name, private_key=b.get("private_key", ""),
                address=b.get("address", ""),
                public_key=b.get("public_key", ""),
                allowed=b.get("allowed", ""),
                endpoint=b.get("endpoint", ""),
                keepalive=b.get("keepalive", ""),
                key_required=key_required))
        except WgError as exc:
            label = (name or "").strip() or "the new connection"
            problems.append(f"{label}: {exc}")

    names = [c["name"] for c in wanted]
    for n in set(names):
        if names.count(n) > 1:
            problems.append(f"There are two connections called {n}.")

    # Each connection is checked against every OTHER one as it will be
    # after this push: edited ones as typed, untouched ones as they are.
    after = {c["name"]: c["allowed"] for c in wanted}
    gone = {c["name"] for c in removing}
    for c in state["conns"]:
        if c["name"] not in after and c["name"] not in gone:
            after[c["name"]] = [n for n in (
                _net(p) for p in str(c["peer"].get("allowed-address", ""))
                .split(",")) if n is not None]
    ctx = _hub_context(state)
    for conn in wanted:
        others = [(n, nets) for n, nets in after.items() if n != conn["name"]]
        problems += check(conn, state, ctx, others)

    if problems:
        raise PlanRefused("Nothing was sent to the router.\n"
                          + "\n".join(dict.fromkeys(problems)))

    ops = []
    for c in removing:
        ops += _removal_ops(c)
    for conn in wanted:
        ops += _connection_ops(conn, by_name.get(conn["name"]), state)
    label = ", ".join(sorted({c["name"] for c in wanted} | gone)) or "none"
    return Plan(cfg.name, ops, summary=f"extra WireGuard: {label}")

