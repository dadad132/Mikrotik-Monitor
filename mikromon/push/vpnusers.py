"""VPN remote users: a laptop or phone that connects straight to a site's
router over WireGuard and reaches the site's network.

The router becomes a small WireGuard server, on an interface of its own
("mikromon-users") -- separate from "mikromon", the tunnel this dashboard
manages it over, so nothing done here can touch the management connection.
Each remote device is one peer on that interface with one address in a small
subnet of its own (10.11.N.0/24, unique per router across the platform, so a
laptop can hold tunnels to several sites at once without their addresses
colliding).

What makes a remote user work, all of which a plan here sets up and tags:

  * the interface, listening on a UDP port (13231, WireGuard's usual, unless
    something on the router already has it)
  * the subnet's gateway address on that interface
  * a firewall rule letting that UDP port in from the internet -- the default
    MikroTik firewall drops everything arriving from WAN that it did not
    start, and the handshake is exactly that
  * forward rules both ways between the interface and the site, ahead of any
    "drop" rule, and membership of the LAN interface list, so the default
    firewall treats a connected laptop like a device on site (DNS from the
    router, reaching the router itself)
  * for a user who sends ALL their traffic through the site: a masquerade
    rule, so the site's internet line carries it
  * the peer: the device's PUBLIC key and its one address

The device's private key is never sent to the router: either it never leaves
the device (the user pastes the device's public key here), or the dashboard
makes the pair, sends only the public half, and shows the private half once
in the config file it hands over.

Whether a laptop can actually REACH the router is the part that does not
depend on configuration: it needs a public address that leads to this
router. read() says what it found -- MikroTik's free DDNS name, the public
address, or that the router sits behind someone else's NAT (an LTE line,
always) -- and the page says so before anybody is handed a config that
cannot connect.
"""
from __future__ import annotations

import ipaddress
import re

from .api import PlanRefused
from .plan import Operation, Plan

_WG = ("interface", "wireguard")
_PEERS = ("interface", "wireguard", "peers")
_ADDR = ("ip", "address")
_FILTER = ("ip", "firewall", "filter")
_NAT = ("ip", "firewall", "nat")
_LIST = ("interface", "list")
_LIST_MEMBER = ("interface", "list", "member")
_CLOUD = ("ip", "cloud")
_DNS = ("ip", "dns")
_RESOURCE = ("system", "resource")

IFACE_NAME = "mikromon-users"
TAG = "mikromon:vpnusers:"           # infrastructure rows
PEER_TAG = "mikromon:vpnuser:"       # one per remote device, + its label
DEFAULT_PORT = 13231
USERS_POOL = "10.11.0.0/16"          # one /24 per router
KEEPALIVE = 25

_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._'@-]{0,39}$")


def _safe(api, path) -> list:
    try:
        return api.fetch(path)
    except Exception:  # noqa: BLE001 -- a menu missing on this board
        return []


def _yes(v) -> bool:
    return str(v).lower() in ("true", "yes", "1")


def _version(api):
    rows = _safe(api, _RESOURCE)
    ver = str(rows[0].get("version", "")) if rows else ""
    m = re.match(r"(\d+)\.(\d+)", ver)
    return (int(m.group(1)), int(m.group(2)), ver) if m else (0, 0, ver or "unknown")


def is_public(ip: str) -> bool:
    """A routable internet address: not private, not CGNAT (100.64/10),
    not loopback or link-local."""
    try:
        a = ipaddress.ip_address(ip.split("/")[0])
    except ValueError:
        return False
    if a in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return a.is_global


def read(pusher, cfg) -> dict:
    """Everything the VPN tab needs to show remote users and to build a plan."""
    api = pusher.api
    major, minor, ver = _version(api)
    out: dict = {"version": ver, "unsupported": bool(major and (major, minor) < (7, 1))}
    if out["unsupported"]:
        return out
    ifaces = _safe(api, _WG)
    mine = next((i for i in ifaces if str(i.get("comment", "")) == TAG + "if"),
                None)
    out["iface"] = mine
    out["used_ports"] = sorted({int(i.get("listen-port") or 0) for i in ifaces
                                if i is not mine and str(i.get("listen-port", "")).isdigit()})
    addrs = _safe(api, _ADDR)
    out["addr"] = next((a for a in addrs
                        if str(a.get("comment", "")) == TAG + "addr"), None)
    nets = []
    for a in addrs:
        try:
            nets.append(str(ipaddress.ip_interface(a.get("address", "")).network))
        except ValueError:
            continue
    out["router_nets"] = nets
    out["peers"] = [p for p in _safe(api, _PEERS)
                    if str(p.get("comment", "")).startswith(PEER_TAG)]
    for p in out["peers"]:
        p["label"] = str(p.get("comment", ""))[len(PEER_TAG):]
    # The LAN networks a remote user may be given: every address on the
    # router except the WAN lines', the management tunnel's and our own.
    wan = {(lk.interface or "").strip().lower() for lk in cfg.wan.links}
    lans = []
    for a in addrs:
        iface = str(a.get("interface", "")).strip().lower()
        if (not iface or iface in wan or iface in ("mikromon", IFACE_NAME)
                or _yes(a.get("disabled"))):
            continue
        try:
            net = str(ipaddress.ip_interface(a.get("address", "")).network)
        except ValueError:
            continue
        if net not in lans:
            lans.append(net)
    out["lan_subnets"] = lans
    # Where a laptop would connect to.
    cloud = (_safe(api, _CLOUD) or [{}])[0]
    out["cloud"] = {"ddns": _yes(cloud.get("ddns-enabled")),
                    "dns_name": str(cloud.get("dns-name", "") or ""),
                    "public_address": str(cloud.get("public-address", "") or "")}
    wan_ip = ""
    if cfg.wan.links:
        prim = (cfg.wan.links[0].interface or "").strip().lower()
        for a in addrs:
            if str(a.get("interface", "")).strip().lower() == prim:
                wan_ip = str(a.get("address", "")).split("/")[0]
                break
    out["wan_ip"] = wan_ip
    lists = {str(r.get("name", "")) for r in _safe(api, _LIST)}
    out["has_lan_list"] = "LAN" in lists
    out["has_wan_list"] = "WAN" in lists
    dns = (_safe(api, _DNS) or [{}])[0]
    out["router_dns"] = _yes(dns.get("allow-remote-requests"))
    return out


def reachability(cur: dict, hub_seen_ip: str = "") -> dict:
    """{"endpoint", "ok", "why"}: the address to give a laptop, and whether
    it can work. `hub_seen_ip` is the router's public address as this server
    sees it on the management tunnel -- the most reliable answer there is."""
    cloud = cur.get("cloud") or {}
    wan_ip = cur.get("wan_ip") or ""
    public = cloud.get("public_address") or hub_seen_ip
    if wan_ip and not is_public(wan_ip):
        why = (f"The main line hands this router a private address ({wan_ip}), "
               f"so it is behind someone else's router or the ISP's CGNAT. A "
               f"laptop cannot reach it from outside unless that device "
               f"forwards UDP port {_port(cur)} to this router.")
        return {"endpoint": cloud.get("dns_name") or public or "",
                "ok": False, "why": why}
    if cloud.get("ddns") and cloud.get("dns_name"):
        return {"endpoint": cloud["dns_name"], "ok": True,
                "why": "MikroTik's free DDNS name, which follows the address "
                       "if the ISP changes it."}
    ip = wan_ip if is_public(wan_ip) else public
    if ip:
        return {"endpoint": ip, "ok": True,
                "why": "This router's public address. If the ISP changes it, "
                       "tick 'Use MikroTik's DDNS name' so laptops follow it."}
    return {"endpoint": "", "ok": False,
            "why": "No public address could be found for this router."}


def _port(cur: dict) -> int:
    iface = cur.get("iface")
    if iface and str(iface.get("listen-port", "")).isdigit():
        return int(iface["listen-port"])
    used = set(cur.get("used_ports") or [])
    port = DEFAULT_PORT
    while port in used:
        port += 1
    return port


def pick_users_subnet(cur: dict, taken: set) -> str:
    """This router's remote-user subnet: the one it already has, else the
    first /24 of the pool that no other router has been given and that does
    not overlap anything on this router."""
    addr = cur.get("addr")
    if addr:
        try:
            return str(ipaddress.ip_interface(addr["address"]).network)
        except (KeyError, ValueError):
            pass
    mine = []
    for n in cur.get("router_nets") or []:
        try:
            mine.append(ipaddress.ip_network(n, strict=False))
        except ValueError:
            continue
    for net in ipaddress.ip_network(USERS_POOL).subnets(new_prefix=24):
        if str(net) in taken or any(net.overlaps(m) for m in mine):
            continue
        return str(net)
    raise PlanRefused("Nothing was sent to the router.\nThe remote-user "
                      "address pool is used up.")


def _next_ip(subnet: str, peers: list) -> str:
    net = ipaddress.ip_network(subnet)
    used = {str(net.network_address + 1)}
    for p in peers:
        for part in str(p.get("allowed-address", "")).split(","):
            used.add(part.strip().split("/")[0])
    for host in list(net.hosts())[1:]:
        if str(host) not in used:
            return str(host)
    raise PlanRefused("Nothing was sent to the router.\nThis router has no "
                      "free remote-user addresses left; remove one first.")


def plan(pusher, cfg, flat: dict, multi: dict) -> Plan:
    """Add a remote user, remove one, or switch remote users off entirely.

    The web layer injects "_vu_subnet" (this router's subnet, allocated
    platform-wide) and, when the dashboard makes the keys, "_vu_pubkey".
    """
    from ..wgkeys import valid_key

    api = pusher.api
    cur = read(pusher, cfg)
    if cur.get("unsupported"):
        raise PlanRefused("Nothing was sent to the router.\nRemote users need "
                          f"WireGuard, which arrived in RouterOS 7.1; this "
                          f"router runs {cur.get('version')}.")
    action = (flat.get("vpnuser_action") or "add").strip()
    if action == "remove":
        pid = (flat.get("peer_id") or "").strip()
        peer = next((p for p in cur["peers"] if p.get(".id") == pid), None)
        if peer is None:
            raise PlanRefused("Nothing was sent to the router.\nThat remote "
                              "user is no longer on the router.")
        keep = {k: v for k, v in peer.items()
                if k in ("interface", "public-key", "allowed-address",
                         "comment")}
        return Plan(cfg.name, [Operation(
            "remove", _PEERS, {".id": pid},
            desc=f"remove remote user '{peer['label']}' "
                 f"({peer.get('allowed-address', '')}) — it can no longer "
                 f"connect",
            inverse=Operation("add", _PEERS, keep,
                              desc=f"restore remote user '{peer['label']}'"))],
            summary=f"remove remote user {peer['label']}")
    if action == "off":
        return Plan(cfg.name, _teardown_ops(api), summary="remote users off")

    # ---- add ----------------------------------------------------------------
    reasons = []
    label = re.sub(r"\s+", " ", (flat.get("vu_label") or "").strip())
    if not _LABEL_RE.match(label):
        reasons.append("Give the device a name (letters, digits, spaces, "
                       "dots, dashes; up to 40 characters).")
    elif any(p["label"].lower() == label.lower() for p in cur["peers"]):
        reasons.append(f"There is already a remote user called '{label}'.")
    making = flat.get("vu_keys") == "make"
    pub = (flat.get("_vu_pubkey") or ("" if making else
                                      flat.get("vu_pubkey")) or "").strip()
    if making and not pub:
        # A preview: the dashboard makes the pair when the change is
        # applied, so there is nothing to check yet.
        pass
    elif not valid_key(pub):
        reasons.append("That is not a WireGuard public key. In the WireGuard "
                       "app it is the line marked 'Public key' (44 "
                       "characters ending in '='), not the private key.")
    elif any(str(p.get("public-key", "")) == pub for p in cur["peers"]):
        reasons.append("That public key already belongs to another remote "
                       "user on this router.")
    subnet = flat.get("_vu_subnet") or ""
    if not subnet:
        try:
            subnet = pick_users_subnet(cur, set(flat.get("_vu_taken") or ()))
        except PlanRefused as exc:
            reasons.append(str(exc).split("\n", 1)[-1])
    flat["_vu_subnet_chosen"] = subnet
    nets = [n for n in (multi.get("vu_net") or []) if n]
    full = flat.get("vu_full") == "1"
    if not nets and not full:
        reasons.append("Pick at least one network the device may reach, or "
                       "send all its traffic through the site.")
    for n in nets:
        if n not in cur.get("lan_subnets", []):
            reasons.append(f"{n} is not one of this router's networks.")
    if reasons:
        raise PlanRefused("Nothing was sent to the router.\n"
                          + "\n".join(reasons))

    port = _port(cur)
    net = ipaddress.ip_network(subnet)
    gw = f"{net.network_address + 1}/{net.prefixlen}"
    ops = []
    if cur.get("iface") is None:
        ops.append(Operation(
            "add", _WG, {"name": IFACE_NAME, "listen-port": str(port),
                         "comment": TAG + "if"},
            desc=f"create WireGuard interface '{IFACE_NAME}' for remote "
                 f"users, listening on UDP {port} (separate from the "
                 f"management tunnel)",
            inverse=Operation("remove", _WG, {},
                              desc=f"remove interface '{IFACE_NAME}'")))
    if cur.get("addr") is None:
        ops.append(Operation(
            "add", _ADDR, {"address": gw, "interface": IFACE_NAME,
                           "comment": TAG + "addr"},
            desc=f"give it {gw}, the gateway of the remote-user subnet",
            inverse=Operation("remove", _ADDR, {},
                              desc="remove the remote-user gateway address")))
    ops += _firewall_ops(api, port, cur)
    if cur.get("has_lan_list"):
        members = _safe(api, _LIST_MEMBER)
        if not any(str(m.get("comment", "")) == TAG + "lan" for m in members):
            ops.append(Operation(
                "add", _LIST_MEMBER, {"list": "LAN", "interface": IFACE_NAME,
                                      "comment": TAG + "lan"},
                desc="treat connected remote users like devices on the LAN "
                     "(the default firewall then lets them use the router's "
                     "DNS and reach the router)",
                inverse=Operation("remove", _LIST_MEMBER, {},
                                  desc="take remote users out of the LAN list")))
    if full:
        nat = _safe(api, _NAT)
        if not any(str(r.get("comment", "")) == TAG + "nat" for r in nat):
            params = {"chain": "srcnat", "action": "masquerade",
                      "src-address": str(net), "comment": TAG + "nat"}
            if cur.get("has_wan_list"):
                params["out-interface-list"] = "WAN"
            elif cfg.wan.links and cfg.wan.links[0].interface:
                params["out-interface"] = cfg.wan.links[0].interface
            ops.append(Operation(
                "add", _NAT, params,
                desc=f"masquerade remote users' internet traffic ({net}) out "
                     f"of the site's internet line",
                inverse=Operation("remove", _NAT, {},
                                  desc="remove the remote-user masquerade")))
    if flat.get("vu_ddns") == "1" and not (cur.get("cloud") or {}).get("ddns"):
        ops.append(Operation(
            "set", _CLOUD, {"ddns-enabled": "yes"},
            desc="switch on MikroTik's free DDNS name for this router, so "
                 "laptops still find it if the ISP changes its address",
            inverse=Operation("set", _CLOUD, {"ddns-enabled": "no"},
                              desc="switch MikroTik's DDNS name off again")))
    ip = _next_ip(str(net), cur["peers"])
    flat["_vu_ip"] = ip
    flat["_vu_port"] = port
    key_note = (f"key {pub[:10]}…" if pub else
                "a key the dashboard makes when you apply")
    ops.append(Operation(
        "add", _PEERS, {"interface": IFACE_NAME, "public-key": pub,
                        "allowed-address": f"{ip}/32",
                        "comment": PEER_TAG + label},
        desc=f"add remote user '{label}' at {ip} ({key_note})",
        inverse=Operation("remove", _PEERS, {},
                          desc=f"remove remote user '{label}'")))
    return Plan(cfg.name, ops, summary=f"remote user {label}")


def _firewall_ops(api, port: int, cur: dict) -> list:
    """The three rules, each added once, at the very top so a "drop
    everything else" further down cannot shadow them."""
    rules = _safe(api, _FILTER)
    have = {str(r.get("comment", "")) for r in rules}
    want = [
        ("in", {"chain": "input", "protocol": "udp", "dst-port": str(port),
                "action": "accept"},
         f"let WireGuard handshakes in on UDP {port} (the default firewall "
         f"drops anything from the internet it did not start)"),
        ("fwd-in", {"chain": "forward", "in-interface": IFACE_NAME,
                    "action": "accept"},
         "let connected remote users reach the site"),
        ("fwd-out", {"chain": "forward", "out-interface": IFACE_NAME,
                     "action": "accept"},
         "let the site answer them"),
    ]
    ops = []
    for tag, params, desc in want:
        if TAG + tag in have:
            continue
        ops.append(Operation(
            "add", _FILTER, {**params, "comment": TAG + tag,
                             "place-before": 0},
            desc=desc,
            inverse=Operation("remove", _FILTER, {},
                              desc=f"remove firewall rule {TAG + tag}")))
    return ops


def _teardown_ops(api) -> list:
    """Everything this feature added, peers first."""
    ops = []
    for path, what in ((_PEERS, "remote user"), (_NAT, "masquerade rule"),
                       (_FILTER, "firewall rule"),
                       (_LIST_MEMBER, "LAN list membership"),
                       (_ADDR, "gateway address"), (_WG, "interface")):
        for r in _safe(api, path):
            c = str(r.get("comment", ""))
            if (c.startswith(TAG) or c.startswith(PEER_TAG)) and r.get(".id"):
                label = c[len(PEER_TAG):] if c.startswith(PEER_TAG) else c
                ops.append(Operation("remove", path, {".id": r[".id"]},
                                     desc=f"remove {what} ({label})"))
    if not ops:
        raise PlanRefused("Nothing was sent to the router.\nRemote users are "
                          "not set up on this router.")
    return ops


def client_config(*, private_key: str, address: str, router_pubkey: str,
                  endpoint: str, port: int, allowed: list,
                  dns: str = "", label: str = "") -> str:
    """The [Interface]/[Peer] file the WireGuard app imports. With no
    private key (the device made its own), the PrivateKey line says to keep
    the one the app created."""
    lines = [f"# {label} — easymikrotik remote access" if label else
             "# easymikrotik remote access", "[Interface]"]
    if private_key:
        lines.append(f"PrivateKey = {private_key}")
    lines.append(f"Address = {address}")
    if dns:
        lines.append(f"DNS = {dns}")
    lines += ["", "[Peer]", f"PublicKey = {router_pubkey}",
              f"Endpoint = {endpoint}:{port}",
              f"AllowedIPs = {', '.join(allowed)}",
              f"PersistentKeepalive = {KEEPALIVE}"]
    return "\n".join(lines) + "\n"
