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
        if not _prefix_owner(_SEC_TAG)(r):
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
    return {"dns": dns[0] if dns else {}, "bypass": bypass}


def nextdns_summary(current, cfg):
    dns = current.get("dns", {})
    out = [f"DNS servers: {dns.get('servers', '(none)')}",
           f"allow-remote-requests: {dns.get('allow-remote-requests', '?')}"]
    out.append(f"{len(current.get('bypass', []))} bypass address(es)")
    return out


def nextdns_form(current, cfg):
    dns = current.get("dns", {})
    ips = "\n".join(r.get("address", "") for r in current.get("bypass", []))
    return [
        {"type": "text", "name": "servers", "label": "DNS servers (comma-separated)",
         "value": dns.get("servers", ""),
         "placeholder": "45.90.28.0, 45.90.30.0  (e.g. your NextDNS endpoints)"},
        {"type": "toggle", "name": "opt", "value": "allow_remote",
         "label": "Allow remote DNS requests",
         "on": _norm(dns.get("allow-remote-requests", "")) == "true"},
        {"type": "textarea", "name": "bypass", "label": "Bypass IPs (one per line)",
         "value": ips, "hint": "Hosts allowed to skip the filter."},
    ]


def nextdns_plan(pusher, cfg, flat, multi):
    servers = ",".join(x.strip() for x in flat.get("servers", "").split(",")
                       if x.strip())
    desired_dns = {"servers": servers,
                   "allow-remote-requests": "yes" if "allow_remote"
                   in set(multi.get("opt", [])) else "no"}
    plan = pusher.plan_settings(_DNS, desired_dns, label="dns")
    ips = [x.strip() for x in (flat.get("bypass", "") or "").splitlines()
           if x.strip()]
    desired_list = [{"list": DNS_BYPASS_LIST, "address": ip} for ip in ips]
    list_plan = pusher.plan_managed_list(
        _ADDR_LIST, "address", desired_list,
        manage_tag="mikromon:dns-bypass",
        owns=lambda r: str(r.get("list", "")) == DNS_BYPASS_LIST,
        label="bypass")
    return Plan(cfg.name, plan.ops + list_plan.ops, summary="nextdns / dns filter")


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
}

# tab label -> url slug (Overview/Backups handled elsewhere)
TAB_SLUGS = {"SD-WAN": "sdwan", "Security": "security", "NextDNS": "nextdns",
             "QoS": "qos", "Port forwarding": "portfwd", "Interfaces": "interfaces",
             "Remote access": "remote"}
