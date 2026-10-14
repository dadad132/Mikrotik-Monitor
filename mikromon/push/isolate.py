"""Cutting one PC off the network at its router, for the support team.

When the antivirus agent on a PC finds something the support team does not
want spreading, they can isolate that PC from the Antivirus page. Its router
then drops everything the PC sends through it -- to the internet and to the
site's other networks -- except its reports to EasyMikroTik, so the team
still hears what the agent sees. Releasing it removes exactly what was added.

On the router, all tagged mikromon:edr: so nothing else is touched:

  * the PC's address, in the address list mikromon-isolated;
  * two forward rules at the very top of the filter list: accept HTTPS from
    isolated PCs to EasyMikroTik, then drop everything else they send. At
    the top, because a drop below the usual "accept established" rule never
    sees a connection the PC already has open;
  * and the PC's open connections, cleared from the connection table.
    FastTrack sends the packets of an established connection around the
    firewall altogether, so the rule alone would leave those flowing.

What it cannot do: stop the PC reaching other PCs on its own switch or
Wi-Fi. That traffic never reaches the router's firewall, and the page says
so before anyone relies on it.
"""
from __future__ import annotations

import ipaddress

from .plan import Operation, Plan

LIST = "mikromon-isolated"
HUB_LIST = "mikromon-edr-hub"
TAG = "mikromon:edr:"
_PC = TAG + "pc:"
_HUB = TAG + "hub"
_BLOCK = TAG + "block"
_ADDR = ("ip", "firewall", "address-list")
_FILTER = ("ip", "firewall", "filter")
_CONN = ("ip", "firewall", "connection")
_ROUTER_ADDR = ("ip", "address")
# What a removed rule or entry is put back with, if a release has to roll
# back. Counters and flags RouterOS reports but will not take are left out.
_KEEP = ("list", "address", "chain", "src-address-list", "dst-address-list",
         "protocol", "dst-port", "action", "comment", "disabled")


class IsolateError(ValueError):
    """An isolation that must not be sent, with the reason a person needs."""


def pc_tag(agent_id: str) -> str:
    return _PC + str(agent_id)


def check_ip(text) -> str:
    """The PC's IPv4 address, or IsolateError saying what is wrong with it."""
    raw = str(text or "").strip()
    try:
        ip = ipaddress.IPv4Address(raw)
    except ValueError:
        raise IsolateError(f"{raw or 'An empty address'} is not an IPv4 "
                           f"address, like 192.168.88.23.") from None
    if (ip.is_loopback or ip.is_multicast or ip.is_unspecified
            or ip.is_link_local or ip == ipaddress.IPv4Address(
                "255.255.255.255")):
        raise IsolateError(f"{ip} is not the address of a PC on a network.")
    return str(ip)


def _yes(v) -> bool:
    return str(v).strip().lower() in ("true", "yes")


def _restore(row: dict) -> dict:
    return {k: row[k] for k in _KEEP if k in row}


def _first_id(rows, start=0) -> str:
    """The first rule from `start` on that a new rule can be placed before.
    The FastTrack counter RouterOS shows at the top is dynamic, and cannot
    be placed before, so it is skipped."""
    for r in rows[start:]:
        if not _yes(r.get("dynamic")) and r.get(".id"):
            return str(r[".id"])
    return ""


def on_router_network(api, ip: str):
    """Whether `ip` is on one of the router's own networks -- None when its
    addresses could not be read. Isolating an address the router never
    routes would change nothing, and is usually the wrong router."""
    try:
        rows = api.fetch(_ROUTER_ADDR)
    except Exception:  # noqa: BLE001 -- a check, not a reason to stop
        return None
    target = ipaddress.IPv4Address(ip)
    for r in rows:
        try:
            if target in ipaddress.ip_interface(
                    str(r.get("address", ""))).network:
                return True
        except ValueError:
            continue
    return False


def isolate_plan(device: str, api, *, ip: str, agent_id: str, label: str,
                 hub_host: str = "") -> Plan:
    """What to send so the router drops what `label` (at `ip`) sends.

    Idempotent: what is already there is left alone, so isolating a second
    PC only adds its address, and isolating one again only moves it."""
    ip = check_ip(ip)
    addrs = api.fetch(_ADDR)
    rules = api.fetch(_FILTER)
    ops = []

    mine = [r for r in addrs if r.get("comment") == pc_tag(agent_id)]
    if not mine:
        ops.append(Operation(
            "add", _ADDR, {"list": LIST, "address": ip,
                           "comment": pc_tag(agent_id)},
            desc=f"add {label} ({ip}) to the address list {LIST}",
            inverse=Operation("remove", _ADDR, {},
                              desc=f"take {ip} off {LIST}")))
    else:
        entry = mine[0]
        if (str(entry.get("address")) != ip or entry.get("list") != LIST
                or _yes(entry.get("disabled"))):
            ops.append(Operation(
                "set", _ADDR, {".id": entry[".id"], "address": ip,
                               "list": LIST, "disabled": "no"},
                desc=f"update {label} in {LIST}: {ip}",
                inverse=Operation("set", _ADDR,
                                  {".id": entry[".id"], **_restore(entry)},
                                  desc=f"put {label}'s entry back")))
        for extra in mine[1:]:
            ops.append(Operation(
                "remove", _ADDR, {".id": extra[".id"]},
                desc=f"remove a second entry for {label}",
                inverse=Operation("add", _ADDR, _restore(extra),
                                  desc=f"restore the second entry")))

    if hub_host and not any(r.get("comment") == _HUB for r in addrs):
        ops.append(Operation(
            "add", _ADDR, {"list": HUB_LIST, "address": hub_host,
                           "comment": _HUB},
            desc=f"add {hub_host} to the address list {HUB_LIST}",
            inverse=Operation("remove", _ADDR, {},
                              desc=f"take {hub_host} off {HUB_LIST}")))

    have = {str(r.get("comment", "")): i for i, r in enumerate(rules)}
    top = _first_id(rules)
    hub_rule = {"chain": "forward", "src-address-list": LIST,
                "dst-address-list": HUB_LIST, "protocol": "tcp",
                "dst-port": "443", "action": "accept", "comment": _HUB}
    block_rule = {"chain": "forward", "src-address-list": LIST,
                  "action": "drop", "comment": _BLOCK}
    if hub_host and _HUB not in have:
        # Anywhere above the drop will do, and the very top always is.
        ops.append(_add_rule(hub_rule, top,
                             f"let isolated PCs reach {hub_host} over HTTPS, "
                             f"so their agent still reports"))
    if _BLOCK not in have:
        # Placed before the same rule as the accept above, which keeps the
        # accept first. With the accept already on the router, straight
        # after it instead.
        where = (_first_id(rules, have[_HUB] + 1)
                 if _HUB in have else top)
        ops.append(_add_rule(block_rule, where,
                             "drop everything else isolated PCs send "
                             "through the router"))
    for comment in (_HUB, _BLOCK):
        if comment in have and _yes(rules[have[comment]].get("disabled")):
            row = rules[have[comment]]
            ops.append(Operation(
                "set", _FILTER, {".id": row[".id"], "disabled": "no"},
                desc=f"switch the rule {comment} back on",
                inverse=Operation("set", _FILTER, {".id": row[".id"],
                                                   "disabled": "yes"},
                                  desc=f"switch {comment} off again")))
    return Plan(device, ops, summary=f"isolate {label} ({ip})")


def _add_rule(params: dict, before: str, desc: str) -> Operation:
    p = dict(params)
    if before:
        p["place-before"] = before
    return Operation("add", _FILTER, p, desc=desc,
                     inverse=Operation("remove", _FILTER, {},
                                       desc=f"remove {params['comment']}"))


def release_plan(device: str, api, *, agent_id: str, label: str) -> Plan:
    """What to send to let `label` back on. When it was the last PC isolated
    on this router, the two rules and the EasyMikroTik entry go as well, so
    the router is left as it was found."""
    addrs = api.fetch(_ADDR)
    rules = api.fetch(_FILTER)
    ops = []
    mine = [r for r in addrs if r.get("comment") == pc_tag(agent_id)]
    for r in mine:
        ops.append(Operation(
            "remove", _ADDR, {".id": r[".id"]},
            desc=f"take {label} ({r.get('address', '')}) off {LIST}",
            inverse=Operation("add", _ADDR, _restore(r),
                              desc=f"put {label} back on {LIST}")))
    others = [r for r in addrs if str(r.get("comment", "")).startswith(_PC)
              and r.get("comment") != pc_tag(agent_id)]
    if not others:
        for r in rules:
            if r.get("comment") in (_HUB, _BLOCK):
                ops.append(Operation(
                    "remove", _FILTER, {".id": r[".id"]},
                    desc=f"remove the rule {r.get('comment')}: no PC is "
                         f"isolated here any more",
                    inverse=Operation("add", _FILTER, _restore(r),
                                      desc=f"restore {r.get('comment')}")))
        for r in addrs:
            if r.get("comment") == _HUB:
                ops.append(Operation(
                    "remove", _ADDR, {".id": r[".id"]},
                    desc=f"take {r.get('address', '')} off {HUB_LIST}",
                    inverse=Operation("add", _ADDR, _restore(r),
                                      desc=f"restore {HUB_LIST}")))
    return Plan(device, ops, summary=f"release {label}")


def connection_ids(api, ip: str) -> list:
    """The ids of the router's open connections to or from `ip`."""
    ids = []
    for c in api.fetch(_CONN):
        for side in ("src-address", "dst-address"):
            addr = str(c.get(side, ""))
            if (addr == ip or addr.startswith(ip + ":")) and c.get(".id"):
                ids.append(str(c[".id"]))
                break
    return ids


def clear_connections(api, ip: str) -> int:
    """Clear `ip`'s open connections, best effort: one may end on its own
    while this runs, and that must not undo an isolation already in place.
    Returns how many were cleared."""
    ids = connection_ids(api, ip)
    if not ids:
        return 0
    try:
        api.execute(Operation("remove", _CONN, {".id": ",".join(ids)}))
        return len(ids)
    except Exception:  # noqa: BLE001 -- one gone already: try them singly
        cleared = 0
        for cid in ids:
            try:
                api.execute(Operation("remove", _CONN, {".id": cid}))
                cleared += 1
            except Exception:  # noqa: BLE001
                continue
        return cleared
