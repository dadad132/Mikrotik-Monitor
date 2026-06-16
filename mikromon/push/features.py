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
from .reconcile import _norm

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
# SD-WAN — failover / load balancing by adjusting default-route distances
# ===========================================================================
_ROUTE = ("ip", "route")


def _default_routes(api):
    return [r for r in api.fetch(_ROUTE)
            if str(r.get("dst-address", "")).startswith("0.0.0.0/0")]


def _route_matches(route, link):
    gw = str(route.get("gateway", ""))
    if link.interface and (gw == link.interface or link.interface in gw):
        return True
    return bool(link.gateway) and gw == link.gateway


_MANGLE = ("ip", "firewall", "mangle")
_POL_TAG = "mikromon:sdwan:pol:"   # mangle mark-routing rule
_RT_TAG = "mikromon:sdwan:rt:"     # the matching marked default route


def sdwan_read(pusher, cfg):
    routes = _default_routes(pusher.api)
    policy = [r for r in pusher.api.fetch(_MANGLE)
              if str(r.get("comment", "")).startswith(_POL_TAG)]
    return {"routes": routes, "policy": policy}


def _policy_rows(current):
    rows = []
    for m in current.get("policy", []):
        enc = m.get("comment", "")[len(_POL_TAG):]
        subnet, _, via = enc.partition("|")
        rows.append({"subnet": m.get("src-address", subnet), "via": via})
    return rows


def sdwan_summary(current, cfg):
    routes = current.get("routes", [])
    lines = [f"{r.get('gateway', '?')} · distance {r.get('distance', '?')}"
             f"{' · inactive' if r.get('active') in ('false', False) else ''}"
             for r in routes] or ["No default (0.0.0.0/0) routes found."]
    lines.append(f"{len(current.get('policy', []))} LAN→WAN policy rule(s)")
    return lines


def sdwan_form(current, cfg):
    links = ", ".join(e.label(i) for i, e in enumerate(cfg.wan.links)) or "(none)"
    return [
        {"type": "select", "name": "mode", "label": "Failover / load-balance mode",
         "options": [("failover", "Failover — strict priority (top WAN first)"),
                     ("loadbalance", "Load balance — share across links")],
         "value": "failover"},
        {"type": "static", "label": "Using these WAN uplinks (priority order)",
         "value": links,
         "hint": "Edit them in the WAN uplinks box above. Apply sets each link's "
                 "default-route distance to its priority (or equal for load-balance)."},
        {"type": "rows", "name": "pol",
         "label": "Send specific LANs out a chosen WAN (policy routing)",
         "cols": [("subnet", "LAN subnet or host", "192.168.88.0/24"),
                  ("via", "out this WAN (interface or gateway)", "ether1")],
         "rows": _policy_rows(current),
         "hint": "Each row marks that source and routes it via the chosen WAN "
                 "(mangle mark + marked default route). Leave empty for none."},
    ]


def sdwan_plan(pusher, cfg, flat, multi):
    mode = flat.get("mode", "failover")
    # distance for failover/load-balance — skip our own marked policy routes
    routes = [r for r in _default_routes(pusher.api)
              if not str(r.get("comment", "")).startswith("mikromon:sdwan")]
    ops = []
    for i, link in enumerate(cfg.wan.links):
        want = "1" if mode == "loadbalance" else str(i + 1)
        for r in routes:
            if _route_matches(r, link) and _norm(r.get("distance", "")) != want:
                ops.append(_set_field(_ROUTE, r, "distance", want,
                                      f"route via {link.label(i)}"))
    # per-subnet policy: a mangle mark + a marked default route per row
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
                summary=f"sd-wan {mode}")


# ===========================================================================
# Security — conservative, reversible firewall drops (tagged, WAN-aware)
# ===========================================================================
_FILTER = ("ip", "firewall", "filter")
_SEC_TAG = "mikromon:sec:"


def security_read(pusher, cfg):
    return [r for r in pusher.api.fetch(_FILTER)
            if _prefix_owner(_SEC_TAG)(r)]


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
    return [f"{r.get('comment', '')[len(_SEC_TAG):]} — {r.get('chain')}/"
            f"{r.get('action')}" for r in current] or \
           ["No mikromon security rules on the router yet."]


def security_form(current, cfg):
    have = {r.get("comment", "") for r in current}
    def on(key):
        return any(c.startswith(_SEC_TAG + key) for c in have)
    wan = ", ".join(e.interface for e in cfg.wan.links if e.interface) or "WAN"
    return [{"type": "toggle", "name": "opt", "value": "drop_invalid",
             "label": "Drop invalid connections", "on": on("drop_invalid"),
             "desc": "Drop packets in connection-state=invalid (input + forward)."},
            {"type": "toggle", "name": "opt", "value": "block_mgmt_wan",
             "label": "Block management from WAN", "on": on("block_mgmt_wan"),
             "desc": f"Drop new FTP/SSH/Telnet/Winbox from {wan} (anti-brute-force)."},
            {"type": "toggle", "name": "opt", "value": "block_icmp_wan",
             "label": "Block ping from WAN", "on": on("block_icmp_wan"),
             "desc": f"Drop ICMP arriving on {wan}."}]


def security_plan(pusher, cfg, flat, multi):
    opts = set(multi.get("opt", []))
    wan_ifaces = [e.interface for e in cfg.wan.links if e.interface]
    desired = []
    if "drop_invalid" in opts:
        for chain in ("input", "forward"):
            desired.append({"chain": chain, "connection-state": "invalid",
                            "action": "drop",
                            "comment": _SEC_TAG + f"drop_invalid-{chain}"})
    if "block_mgmt_wan" in opts:
        for ifc in (wan_ifaces or [""]):
            desired.append({"chain": "input", "protocol": "tcp",
                            "in-interface": ifc, "dst-port": "21,22,23,8291",
                            "connection-state": "new", "action": "drop",
                            "comment": _SEC_TAG + f"block_mgmt_wan-{ifc or 'wan'}"})
    if "block_icmp_wan" in opts:
        for ifc in (wan_ifaces or [""]):
            desired.append({"chain": "input", "protocol": "icmp",
                            "in-interface": ifc, "action": "drop",
                            "comment": _SEC_TAG + f"block_icmp_wan-{ifc or 'wan'}"})
    return pusher.plan_managed_list(_FILTER, "comment", desired,
                                    owns=_prefix_owner(_SEC_TAG), label="security rule")


# ===========================================================================
# NextDNS / DNS content filtering — DNS servers + a bypass address-list
# ===========================================================================
_DNS = ("ip", "dns")
_ADDR_LIST = ("ip", "firewall", "address-list")


def nextdns_read(pusher, cfg):
    dns = pusher.api.fetch(_DNS)
    bypass = [r for r in pusher.api.fetch(_ADDR_LIST)
              if str(r.get("list", "")) == DNS_BYPASS_LIST]
    static = [r for r in pusher.api.fetch(_DNS_STATIC)
              if str(r.get("comment", "")).startswith(_DNSBLOCK_TAG)]
    return {"dns": dns[0] if dns else {}, "bypass": bypass, "static": static}


def nextdns_summary(current, cfg):
    dns = current.get("dns", {})
    out = [f"DNS servers: {dns.get('servers', '(none)')}",
           f"allow-remote-requests: {dns.get('allow-remote-requests', '?')}"]
    out.append(f"{len(current.get('bypass', []))} bypass address(es)")
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
    fields = [
        {"type": "text", "name": "servers", "label": "DNS servers (comma-separated)",
         "value": dns.get("servers", ""),
         "placeholder": "45.90.28.0, 45.90.30.0  (e.g. your NextDNS endpoints)"},
        {"type": "toggle", "name": "opt", "value": "allow_remote",
         "label": "Allow remote DNS requests",
         "on": _norm(dns.get("allow-remote-requests", "")) == "true"},
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
    servers = ",".join(x.strip() for x in flat.get("servers", "").split(",")
                       if x.strip())
    # RouterOS returns true/false here, so send true/false (not yes/no) to avoid
    # a perpetual no-op diff.
    desired_dns = {"servers": servers,
                   "allow-remote-requests": "true" if "allow_remote"
                   in set(multi.get("opt", [])) else "false"}
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
    return Plan(cfg.name, plan.ops + list_plan.ops + static_plan.ops,
                summary="nextdns / dns filter")


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
                     "down": down.replace("M", ""), "up": up.replace("M", "")})
    return [{"type": "rows", "name": "q", "label": "Queues",
             "cols": [("name", "name", "office"),
                      ("target", "target subnet/iface", "192.168.88.0/24"),
                      ("down", "download Mbps", "50"),
                      ("up", "upload Mbps", "20")],
             "rows": rows,
             "hint": "max-limit is upload/download. Blank rows are ignored."}]


def qos_plan(pusher, cfg, flat, multi):
    # Keyed by the queue name (preserved as-is) so adopted queues round-trip.
    desired = []
    for r in _rows(multi, "q", ("name", "target", "down", "up")):
        if not r["name"] or not r["target"]:
            continue
        down = (r["down"] or "0") + "M"
        up = (r["up"] or "0") + "M"
        desired.append({"name": r["name"], "target": r["target"],
                        "max-limit": f"{up}/{down}",
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
    return pusher.api.fetch(("interface",))


def interfaces_summary(current, cfg):
    up = sum(1 for r in current if _norm(r.get("running", "")) == "true")
    return [f"{len(current)} interfaces, {up} running"]


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
    desired = [d for d in _managed_desired(existing) if d["name"] != nm]
    if nm and src.strip():
        desired.append({"name": nm, "source": src, "comment": _SCRIPT_TAG + nm})
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
# Hub tunnel (dial-home) — the router dials OUT to the monitoring hub so it is
# reachable at a CONSTANT private IP with no public IP / through CGNAT. It is
# VERSION-ADAPTIVE: WireGuard on RouterOS 7.1+ (the router makes its own keys;
# we read the public key back), and OpenVPN (ovpn-client) on older firmware that
# has no WireGuard. The tab shows the right form/engine for the box automatically.
# ===========================================================================
_HUB_WG = ("interface", "wireguard")
_HUB_PEERS = ("interface", "wireguard", "peers")
_HUB_ADDR = ("ip", "address")
_HUB_OVPN = ("interface", "ovpn-client")
_HUB_TAG = "mikromon:tunnel:"
_HUB_NAME = "mikromon"


def _hub_mode(api):
    """'wg' on RouterOS 7.1+ (WireGuard); else 'legacy' (SSTP/OpenVPN, works on
    v6). Returns (mode, version_string)."""
    major, minor, ver = _ros_version(api)
    return ("wg" if _wg_supported(major, minor) else "legacy"), ver


def _no_wg_menu(exc):
    return any(k in str(exc).lower()
               for k in ("no such command", "bad command", "invalid command"))


# ---- WireGuard transport (RouterOS 7.1+) ----------------------------------
def _hub_wg_read(pusher, cfg):
    ifaces = [r for r in pusher.api.fetch(_HUB_WG) if r.get("name") == _HUB_NAME]
    addrs = [r for r in pusher.api.fetch(_HUB_ADDR)
             if r.get("interface") == _HUB_NAME]
    peers = [r for r in pusher.api.fetch(_HUB_PEERS)
             if str(r.get("comment", "")).startswith(_HUB_TAG)]
    return {"iface": ifaces[0] if ifaces else {},
            "address": addrs[0] if addrs else {},
            "peer": peers[0] if peers else {}}


def _hub_wg_summary(current):
    iface = current.get("iface", {})
    if not iface:
        return ["No WireGuard tunnel yet. Fill the form and Preview to create one "
                "that dials your monitoring hub (RouterOS 7.1+)."]
    addr = current.get("address", {}).get("address", "(no address)")
    peer = current.get("peer", {})
    out = [f"WireGuard '{_HUB_NAME}' present · tunnel IP {addr}",
           f"router public key: {iface.get('public-key', '(appears after apply)')}"]
    if peer:
        out.append(f"dials hub {peer.get('endpoint-address', '?')}:"
                   f"{peer.get('endpoint-port', '?')} · keepalive "
                   f"{peer.get('persistent-keepalive', '?')}")
    return out


def _hub_wg_form(current):
    peer = current.get("peer", {})
    addr = current.get("address", {})
    return [
        {"type": "text", "name": "endpoint",
         "label": "Hub endpoint — your monitoring server's public host / DDNS",
         "value": peer.get("endpoint-address", ""),
         "placeholder": "monitor.example.com  or  102.36.140.219"},
        {"type": "text", "name": "port", "label": "Hub UDP port",
         "value": peer.get("endpoint-port", "") or "13231"},
        {"type": "text", "name": "hub_pubkey",
         "label": "Hub WireGuard public key",
         "value": peer.get("public-key", ""),
         "placeholder": "paste the monitoring server's WireGuard public key"},
        {"type": "text", "name": "tunnel_ip",
         "label": "This device's tunnel IP (with mask)",
         "value": addr.get("address", ""), "placeholder": "10.10.0.2/24",
         "hint": "Each device gets a unique address in the tunnel subnet "
                 "(hub is 10.10.0.1)."},
        {"type": "text", "name": "allowed",
         "label": "Route to the hub (allowed-address)",
         "value": peer.get("allowed-address", "") or "10.10.0.0/24"},
        {"type": "text", "name": "keepalive", "label": "Persistent keepalive",
         "value": peer.get("persistent-keepalive", "") or "25s",
         "hint": "Keeps the NAT mapping open so the hub can reach back — essential "
                 "behind CGNAT. Leave at 25s."},
    ]


def _hub_wg_plan(pusher, cfg, flat, multi):
    endpoint = flat.get("endpoint", "").strip()
    port = (flat.get("port", "") or "13231").strip()
    hub_pubkey = flat.get("hub_pubkey", "").strip()
    tunnel_ip = flat.get("tunnel_ip", "").strip()
    allowed = (flat.get("allowed", "") or "10.10.0.0/24").strip()
    if not (endpoint and hub_pubkey and tunnel_ip):
        return Plan(cfg.name, [],
                    summary="tunnel (need hub endpoint, hub key and tunnel IP)")
    peer_cur = _hub_wg_read(pusher, cfg).get("peer", {})
    # preserve the keepalive RouterOS already stored (avoids format-churn diffs)
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
    # interface must exist before the address/peer that reference it
    return Plan(cfg.name, iface_plan.ops + addr_plan.ops + peer_plan.ops,
                summary="hub tunnel (wireguard)")


# ---- Legacy transports for older firmware: SSTP (default) or OpenVPN ------
# SSTP is preferred for older units: TLS over 443, NAT/firewall-friendly, and it
# works with username/password only (no certificate import needed). OpenVPN is
# offered too. Both dial OUT to the hub and the hub assigns the tunnel IP.
_HUB_SSTP = ("interface", "sstp-client")
_LEGACY_PATH = {"sstp": _HUB_SSTP, "ovpn": _HUB_OVPN}


def _hub_legacy_read(pusher, cfg):
    def owned(path):
        rows = [r for r in pusher.api.fetch(path)
                if str(r.get("comment", "")).startswith(_HUB_TAG)]
        return rows[0] if rows else {}
    return {"sstp": owned(_HUB_SSTP), "ovpn": owned(_HUB_OVPN)}


def _hub_legacy_active(current):
    """The transport currently configured (sstp wins), and its row."""
    if current.get("sstp"):
        return "sstp", current["sstp"]
    if current.get("ovpn"):
        return "ovpn", current["ovpn"]
    return "sstp", {}


def _hub_legacy_summary(current):
    t, row = _hub_legacy_active(current)
    if not row:
        return ["No dial-home tunnel yet. Pick SSTP (simplest — TLS 443, no "
                "certificates) or OpenVPN, set the hub host and Preview. Works on "
                "RouterOS v6 and v7."]
    up = _norm(row.get("running", "")) == "true"
    label = "SSTP" if t == "sstp" else "OpenVPN"
    return [f"{label} client '{row.get('name')}' → {row.get('connect-to', '?')}:"
            f"{row.get('port', '?')} · {'connected' if up else 'down / connecting'}",
            "The hub assigns this router's tunnel IP."]


def _hub_legacy_form(current):
    t, row = _hub_legacy_active(current)
    return [
        {"type": "select", "name": "transport",
         "label": "Tunnel type (this RouterOS is too old for WireGuard)",
         "options": [("sstp", "SSTP — TLS over 443, no certificate setup "
                              "(recommended)"),
                     ("ovpn", "OpenVPN — TCP, may need the hub's CA imported")],
         "value": t},
        {"type": "text", "name": "connect_to",
         "label": "Hub host — your monitoring server (host / DDNS)",
         "value": row.get("connect-to", ""), "placeholder": "monitor.example.com"},
        {"type": "text", "name": "port", "label": "Hub port",
         "value": row.get("port", "") or "443",
         "hint": "SSTP: 443. OpenVPN: 1194 (TCP)."},
        {"type": "text", "name": "user", "label": "VPN username",
         "value": row.get("user", "")},
        {"type": "text", "name": "password", "label": "VPN password", "value": "",
         "placeholder": "(unchanged)" if row else ""},
        {"type": "toggle", "name": "opt", "value": "verify",
         "label": "Verify the hub's server certificate",
         "on": _norm(row.get("verify-server-certificate", "")) == "true",
         "desc": "Off is simplest (username/password only)."},
    ]


def _hub_legacy_plan(pusher, cfg, flat, multi):
    transport = (flat.get("transport", "") or "sstp").strip()
    path = _LEGACY_PATH.get(transport, _HUB_SSTP)
    connect_to = flat.get("connect_to", "").strip()
    if not connect_to:
        return Plan(cfg.name, [], summary=f"{transport} tunnel (need the hub host)")
    default_port = "443" if transport == "sstp" else "1194"
    desired = {
        "name": _HUB_NAME, "connect-to": connect_to,
        "port": (flat.get("port", "") or default_port).strip(),
        "user": flat.get("user", "").strip(),
        "verify-server-certificate": "true" if "verify"
        in set(multi.get("opt", [])) else "false",
        "add-default-route": "false", "disabled": "false",
        "comment": _HUB_TAG + transport,
    }
    if transport == "ovpn":
        desired["certificate"] = (flat.get("certificate", "") or "none").strip()
    pwd = flat.get("password", "")
    if pwd:  # RouterOS never returns the password — only set it when given
        desired["password"] = pwd
    return pusher.plan_managed_list(path, "name", [desired],
                                    owns=_prefix_owner(_HUB_TAG),
                                    label=f"{transport} client")


# ---- version-adaptive dispatch --------------------------------------------
def hubtunnel_read(pusher, cfg):
    mode, ver = _hub_mode(pusher.api)
    if mode == "wg":
        try:
            data = _hub_wg_read(pusher, cfg)
        except Exception as exc:  # noqa: BLE001 — older box without WG menu
            if not _no_wg_menu(exc):
                raise
            data, mode = _hub_legacy_read(pusher, cfg), "legacy"
    else:
        data = _hub_legacy_read(pusher, cfg)
    data["mode"], data["version"] = mode, ver
    return data


def hubtunnel_summary(current, cfg):
    if current.get("mode") == "legacy":
        return _hub_legacy_summary(current)
    return _hub_wg_summary(current)


def hubtunnel_form(current, cfg):
    if current.get("mode") == "legacy":
        return _hub_legacy_form(current)
    return _hub_wg_form(current)


def hubtunnel_plan(pusher, cfg, flat, multi):
    mode, _ver = _hub_mode(pusher.api)
    if mode == "legacy":
        return _hub_legacy_plan(pusher, cfg, flat, multi)
    return _hub_wg_plan(pusher, cfg, flat, multi)


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
                       desc="check for RouterOS updates (no reboot)")
        return Plan(cfg.name, [op], summary="check for updates")
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
    "sdwan": {"title": "SD-WAN — failover & load balancing", "write": True,
              "read": sdwan_read, "summary": sdwan_summary, "form": sdwan_form,
              "plan": sdwan_plan},
    "security": {"title": "Security", "write": True, "read": security_read,
                 "summary": security_summary, "form": security_form,
                 "plan": security_plan, "unmanaged": security_unmanaged},
    "harden": {"title": "Restrict management access", "write": True,
               "read": harden_read, "summary": harden_summary,
               "form": harden_form, "plan": harden_plan},
    "nextdns": {"title": "NextDNS / DNS filtering", "write": True,
                "read": nextdns_read, "summary": nextdns_summary,
                "form": nextdns_form, "plan": nextdns_plan},
    "qos": {"title": "QoS — bandwidth limits", "write": True, "read": qos_read,
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
    "hubtunnel": {"title": "Hub tunnel (dial-home)", "write": True,
                  "read": hubtunnel_read, "summary": hubtunnel_summary,
                  "form": hubtunnel_form, "plan": hubtunnel_plan},
    "update": {"title": "Update RouterOS", "write": True, "read": update_read,
               "summary": update_summary, "form": update_form,
               "plan": update_plan},
}

# tab label -> url slug (Overview/Backups handled elsewhere)
TAB_SLUGS = {"SD-WAN": "sdwan", "Security": "security",
             "Restrict access": "harden", "NextDNS": "nextdns",
             "QoS": "qos", "Port forwarding": "portfwd", "Interfaces": "interfaces",
             "Remote access": "remote", "Tunnel": "tunnel",
             "Hub tunnel": "hubtunnel", "Scripts": "scripts", "Update": "update"}
