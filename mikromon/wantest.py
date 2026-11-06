"""Testing one internet line of a router, and saying what is wrong with it.

The WAN tab's "Test this line" button. The router is asked to ping the
internet THROUGH one uplink -- out of that interface, from that line's own
address -- so the answer is about that line, not about whichever line the
router happens to be using. Then the line's setup on the router is read and
checked, and every problem found is said in plain words with what to do.

The case it is really for: the dashboard says a line is offline, yet it
answers. Then the line is fine and something around it is wrong -- no route
through it, a route the monitor cannot tie to it, a backup that would never
take over, no NAT so the office cannot use it, a firewall rule eating the
monitor's own checks -- and the scan says which.

Everything here only reads from the router; nothing is changed. `api` is a
push.api.PushApi (fetch / ping_rows), or anything with the same two methods.
"""
from __future__ import annotations

import ipaddress
import re
import time

from .checks.wan import (_fo_route_idx, _in_main, _is_default, _is_usable,
                         _matches_endpoint, _norm_iface)
from .push.plan import Operation

TARGETS = ("1.1.1.1", "8.8.8.8")
TAG = "mikromon:failover:"
# How a ping is sent out of one line, by RouterOS version and kind of line:
#   PPPoE and other point-to-point lines: out of the interface. Reliable on
#     every version, and nothing on the router changes.
#   Ethernet lines on RouterOS 7: out of the interface first; if nothing
#     answers, confirmed through a temporary VRF that holds one route via the
#     line's gateway (RouterOS 7's ping has no routing-table option; only
#     vrf=). The VRF's answer is the one believed.
#   Ethernet lines on RouterOS 6: a temporary route with a routing mark,
#     pinged with routing-table= (out of the interface alone times out there).
# Every temporary route and VRF carries TEST_TAG and is removed straight
# after, or at the start of the next test if one was ever left behind.
TEST_TABLE = "mikromon-linetest"
TEST_VRF = TEST_TABLE
TEST_TAG = "mikromon:linetest"
_UNSUPPORTED = ("unknown parameter", "no such command", "expected end of command",
                "bad command name")
BUDGET_SECONDS = 20.0


# ---- one ping ------------------------------------------------------------------
def _ms(value) -> float | None:
    """RouterOS round-trip times: "12ms", "12ms345us", "1s20ms", "850us", 12."""
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    total, found = 0.0, False
    for num, unit in re.findall(r"(\d+(?:\.\d+)?)(ms|us|s)", str(value)):
        found = True
        total += float(num) * {"s": 1000.0, "ms": 1.0, "us": 0.001}[unit]
    if found:
        return round(total, 1)
    try:
        return float(value)
    except ValueError:
        return None


def explain_trap(text: str, interface: str = "") -> str:
    """The router's refusal, in words a person can act on."""
    low = (text or "").lower()
    if any(k in low for k in _UNSUPPORTED):
        return (f"This RouterOS version does not accept that way of pinging "
                f"({text[:80]}).")
    if "permission" in low or "not enough" in low:
        return ("The router's login used by this website is not allowed to "
                "run ping (it needs the \"test\" permission). Add it to that "
                "user's group under System > Users > Groups.")
    if "not running" in low:
        return f"{interface or 'The interface'} is not running: no link, or not connected."
    if "no route" in low or "unreachable" in low:
        return "The router has no usable route out of this line."
    if "no such item" in low or "invalid value" in low or "input does not match" in low:
        return (f"The router does not know an interface called "
                f"\"{interface}\". Check the WAN uplinks list.")
    if "timed out" in low or "timeout" in low:
        return "The router did not answer in time."
    return (text or "The router refused to ping.")[:200]


def ping_via(api, address: str, *, interface: str = "", src_address: str = "",
             routing_table: str = "", vrf: str = "", count: int = 3,
             interval: str = "300ms") -> dict:
    """Ping `address` from the router, out of `interface` and from
    `src_address` (or in a routing table, or a VRF). Returns {"address",
    "interface", "src_address", "sent", "received", "loss", "avg_ms",
    "error", "raw"}; `error` is set (and loss None) when the router would not
    run the ping at all, and `raw` holds the router's own words."""
    out = {"address": address, "interface": interface, "src_address": src_address,
           "sent": 0, "received": 0, "loss": None, "avg_ms": None, "error": "",
           "raw": ""}
    params = {"address": address, "count": str(count), "interval": interval}
    if interface:
        params["interface"] = interface
    if src_address:
        params["src-address"] = src_address
    if routing_table:
        params["routing-table"] = routing_table
    if vrf:
        params["vrf"] = vrf
    try:
        rows = list(api.ping_rows(**params))
    except Exception as exc:  # noqa: BLE001 -- the router's words are the evidence
        out["raw"] = str(exc)[:200]
        out["error"] = explain_trap(str(exc), interface)
        return out
    summary = next((r for r in reversed(rows) if "sent" in r), None)
    if summary is None:
        out["error"] = "The router gave no ping results."
        return out

    def num(v):
        try:
            return int(str(v).rstrip("%"))
        except (TypeError, ValueError):
            return 0
    out["sent"], out["received"] = num(summary.get("sent")), num(summary.get("received"))
    if "packet-loss" in summary:
        out["loss"] = num(summary["packet-loss"])
    else:
        out["loss"] = (100 - round(100 * out["received"] / out["sent"])
                       if out["sent"] else 100)
    out["avg_ms"] = _ms(summary.get("avg-rtt"))
    return out


# ---- which way out ---------------------------------------------------------------------
def _read(fetch, path):
    """Rows of one menu, or None when it could not be read (an old RouterOS,
    a package that is not installed, a login not allowed to see it)."""
    try:
        return list(fetch(path))
    except Exception:  # noqa: BLE001 -- one menu missing must not stop the rest
        return None


def _safe(fetch, path) -> list:
    return _read(fetch, path) or []


def _addr(text) -> str:
    return str(text or "").split("/")[0].strip()


def _off(row) -> bool:
    return str(row.get("disabled", "")).lower() in ("true", "yes")


def pick_source(fetch, ep) -> dict:
    """How to send a ping out of this line: {"interface", "src_address",
    "kind": "dhcp"|"ppp"|"static"|"", "problem"}."""
    want = _norm_iface(ep.interface)
    addrs = _safe(fetch, ("ip", "address"))
    if want:
        for row in _safe(fetch, ("interface", "pppoe-client")):
            if _norm_iface(row.get("name")) == want:
                local = next((_addr(a.get("address")) for a in addrs
                              if _norm_iface(a.get("interface")) == want), "")
                return {"interface": row.get("name"), "src_address": local,
                        "kind": "ppp", "problem": "" if local else
                        f"{row.get('name')} has no address: the PPPoE session is not up."}
        for row in _safe(fetch, ("ip", "dhcp-client")):
            if _norm_iface(row.get("interface")) == want:
                local = _addr(row.get("address"))
                return {"interface": row.get("interface"), "src_address": local,
                        "kind": "dhcp", "problem": "" if local else
                        f"{row.get('interface')} has not been given an address by the ISP yet."}
        local = next((_addr(a.get("address")) for a in addrs
                      if _norm_iface(a.get("interface")) == want and not _off(a)), "")
        return {"interface": ep.interface, "src_address": local, "kind": "static",
                "problem": "" if local else f"{ep.interface} has no IP address on the router."}
    # Only a gateway was given: the line is the interface whose subnet holds it.
    try:
        gw = ipaddress.ip_address(ep.gateway)
    except ValueError:
        return {"interface": "", "src_address": "", "kind": "",
                "problem": "This line has neither an interface nor a gateway set."}
    for a in addrs:
        try:
            if gw in ipaddress.ip_interface(str(a.get("address"))).network:
                return {"interface": a.get("interface"), "src_address": _addr(a.get("address")),
                        "kind": "static", "problem": ""}
        except ValueError:
            continue
    return {"interface": "", "src_address": "", "kind": "",
            "problem": f"No interface on the router is in the same network as {ep.gateway}."}


def _line_gateway(fetch, ep, source) -> str:
    """Where this line's traffic goes next: the ISP's gateway address, or
    for a PPPoE line the connection itself."""
    if source.get("kind") == "ppp":
        return source.get("interface") or ""
    want = _norm_iface(source.get("interface") or ep.interface)
    if source.get("kind") == "dhcp":
        for row in _safe(fetch, ("ip", "dhcp-client")):
            if _norm_iface(row.get("interface")) == want and row.get("gateway"):
                return str(row["gateway"])
    if ep.gateway:
        return ep.gateway
    for r in _safe(fetch, ("ip", "route")):
        if _is_default(r) and _in_main(r) and _matches_endpoint(r, ep, None,
                                                               _safe(fetch, ("ip", "address"))):
            gw = str(r.get("gateway", "")).split("%")[0]
            if gw:
                return gw
    return ""


def _major(fetch) -> int:
    rows = _safe(fetch, ("system", "resource"))
    ver = str(rows[0].get("version", "")) if rows else ""
    head = ver.split(".")[0]
    return int(head) if head.isdigit() else 0


def _remove(api, path, rid) -> None:
    try:
        api.execute(Operation("remove", path, {".id": rid}))
    except Exception:  # noqa: BLE001 -- the next test tries again
        pass


def _cleanup(api) -> None:
    """Remove what a test puts on the router -- this run's, or what a broken
    earlier run left: the route first, then the VRF it is in, then the
    routing table the first version of this test made on RouterOS 7. Only
    things carrying the test's own tag or name are touched."""
    for r in _safe(api.fetch, ("ip", "route")):
        if r.get("comment") == TEST_TAG and r.get(".id"):
            _remove(api, ("ip", "route"), r[".id"])
    for v in _safe(api.fetch, ("ip", "vrf")):
        # Ours: tagged -- or, where the router would not take the tag, our
        # name with no comment and no interfaces, as the test makes it.
        ours = v.get("comment") == TEST_TAG or (
            v.get("name") == TEST_VRF and not v.get("comment")
            and str(v.get("interfaces", "") or "none").lower() in ("none", ""))
        if ours and v.get(".id"):
            _remove(api, ("ip", "vrf"), v[".id"])
    for t in _safe(api.fetch, ("routing", "table")):
        if t.get("name") == TEST_TABLE and t.get("comment") == TEST_TAG and t.get(".id"):
            _remove(api, ("routing", "table"), t[".id"])


def _add(api, path, params) -> str:
    """Add a row; "" when done, else the router's reason. A router that does
    not take a comment on this menu gets the row without one."""
    try:
        api.execute(Operation("add", path, params))
        return ""
    except Exception as exc:  # noqa: BLE001
        why = str(exc)[:200]
    if "comment" in params and "comment" in why.lower():
        rest = {k: v for k, v in params.items() if k != "comment"}
        try:
            api.execute(Operation("add", path, rest))
            return ""
        except Exception as exc:  # noqa: BLE001
            why = str(exc)[:200]
    return why


def _setup(api, method: str, gateway: str) -> str:
    """Put the temporary route (and on RouterOS 7, its VRF) on the router.
    Returns "" when done, else why not."""
    if method == "mark":
        return _add(api, ("ip", "route"), {"dst-address": "0.0.0.0/0", "gateway": gateway,
                                           "routing-mark": TEST_TABLE, "comment": TEST_TAG})
    why = _add(api, ("ip", "vrf"), {"name": TEST_VRF, "interfaces": "none",
                                    "comment": TEST_TAG})
    if why:
        return why
    # The gateway is reached in the main table ("@main"); a version that does
    # not take that form gets the plain address.
    for gw in dict.fromkeys((gateway if "@" in gateway else f"{gateway}@main", gateway)):
        why = _add(api, ("ip", "route"), {"dst-address": "0.0.0.0/0", "gateway": gw,
                                          "routing-table": TEST_VRF, "comment": TEST_TAG})
        if not why:
            return ""
    return why


def _methods(source: dict, major: int, gateway: str) -> list:
    """The ways to try, in order: see the comment at the top."""
    if source.get("kind") == "ppp" or not gateway:
        return ["interface"]
    if 0 < major < 7:
        return ["mark"]
    if major >= 7:
        return ["interface", "vrf"]
    return ["interface", "vrf", "mark"]          # version unknown: every way


def _unsupported(r: dict) -> bool:
    return any(k in (r.get("raw") or "").lower() for k in _UNSUPPORTED)


def test_line(api, ep, targets=None, *, clock=time.monotonic) -> dict:
    """Ping the internet through one line, stopping at the first answer.

    Returns {"source": pick_source(), "gateway", "method": the way that
    answered (or the last tried), "via": "route"|"interface", "tried": [ping
    results, each with its "method"], "ok": something answered, "ran": at
    least one ping was actually sent, "weak": only a way that can miss on
    an Ethernet line was used, "reason": why nothing ran, "note"}."""
    source = pick_source(api.fetch, ep)
    out = {"source": source, "gateway": "", "method": "", "via": "", "note": "",
           "tried": [], "ok": False, "ran": False, "weak": False, "reason": ""}
    if not source["interface"]:
        out["reason"] = source.get("problem") or "No way out of this line was found."
        return out
    gateway = _line_gateway(api.fetch, ep, source) if source.get("kind") != "ppp" else ""
    out["gateway"] = gateway
    chain = _methods(source, _major(api.fetch), gateway)
    if any(m != "interface" for m in chain):
        _cleanup(api)
    targets = list(targets) if targets else list(TARGETS)
    deadline = clock() + BUDGET_SECONDS
    setup_failed = []
    for method in chain:
        if clock() > deadline:
            break
        if method != "interface":
            why = _setup(api, method, gateway)
            if why:
                setup_failed.append(why)
                _cleanup(api)
                continue
        results = []
        try:
            for target in targets:
                if clock() > deadline:
                    break
                if method == "interface":
                    r = ping_via(api, target, interface=source["interface"],
                                 src_address=source["src_address"])
                elif method == "vrf":
                    # No source address: inside the VRF the router picks it
                    # from the route, and a local address is not "in" it.
                    r = ping_via(api, target, vrf=TEST_VRF)
                else:
                    r = ping_via(api, target, src_address=source["src_address"],
                                 routing_table=TEST_TABLE)
                r["method"] = method
                results.append(r)
                if r["received"] > 0:
                    break
                if r["error"] and ("permission" in r["error"] or _unsupported(r)):
                    break                  # another target will be refused the same way
        finally:
            if method != "interface":
                _cleanup(api)
        out["tried"] += results
        out["method"] = method
        if any(r["received"] > 0 for r in results):
            break
        if any(r["error"] and "permission" in r["error"] for r in results):
            break                          # no way of pinging is allowed at all
    out["ok"] = any(r["received"] > 0 for r in out["tried"])
    ran = [r for r in out["tried"] if not r["error"]]
    out["ran"] = bool(ran)
    out["via"] = "route" if out["method"] in ("vrf", "mark") else "interface"
    if not out["ran"]:
        out["reason"] = (next((r["error"] for r in out["tried"] if r["error"]), "")
                         or "; ".join(setup_failed) or "No way of pinging was possible.")
    elif not out["ok"] and source.get("kind") != "ppp" \
            and all(r["method"] in ("interface", "vrf") for r in ran):
        # On an Ethernet line neither way can prove a line DEAD: out of the
        # interface alone it can stay silent while the line works, and a
        # RouterOS 7 VRF is not proven to get its answers back on every
        # version. An answer is proof; silence here is only a strong hint.
        out["weak"] = True
        if any(r["method"] == "vrf" for r in ran):
            out["note"] = ("Nothing answered either way it was tried. On an "
                           "Ethernet line on RouterOS 7 that is a strong hint, "
                           "not proof, that the line is down.")
        else:
            out["note"] = ("Pinged out of the interface only, which on an Ethernet "
                           "line can fail while the line works"
                           + (f"; the surer way could not be used ({setup_failed[0]})."
                              if setup_failed else "."))
    return out


# ---- what is wrong -------------------------------------------------------------------------
def _f(level, code, msg, fix=""):
    return {"level": level, "code": code, "msg": msg, "fix": fix}


def _yes(value) -> bool:
    return str(value or "").lower() in ("true", "yes")


def diagnose_line(fetch, links, idx: int, *, shown_offline: bool, ping_ok: bool,
                  source: dict | None = None, ran: bool = True, weak: bool = False,
                  reason: str = "") -> list:
    """Read the line's setup on the router and say what is wrong with it.
    Returns [{"level": "error"|"warn"|"ok", "code", "msg", "fix"}], errors
    first."""
    ep = links[idx]
    label = ep.label(idx)
    source = source or {}
    iface = source.get("interface") or ep.interface
    want = _norm_iface(iface)
    out = []

    # -- the interface itself
    ifaces = _safe(fetch, ("interface",))
    row = next((r for r in ifaces if _norm_iface(r.get("name")) == want), None)
    if want and ifaces and row is None:
        out.append(_f("error", "iface_missing",
                      f"The router has no interface called \"{iface}\".",
                      "Correct the interface of this line in the WAN uplinks list."))
    elif row is not None:
        if _off(row):
            out.append(_f("error", "iface_disabled", f"{iface} is switched off on the router.",
                          "Enable it under Interfaces."))
        elif "running" in row and not _yes(row.get("running")):
            out.append(_f("error", "iface_down",
                          f"{iface} has no link: nothing is connected, or the modem is off.",
                          "Check the cable, the modem and its power."))

    # -- how the line gets its address
    kind = source.get("kind")
    dhcp = next((r for r in _safe(fetch, ("ip", "dhcp-client"))
                 if _norm_iface(r.get("interface")) == want), None)
    if kind == "dhcp" and dhcp is not None:
        if _off(dhcp):
            out.append(_f("error", "dhcp_off", f"The DHCP client on {iface} is switched off.",
                          "Enable it under IP > DHCP Client."))
        elif str(dhcp.get("status", "bound")).lower() != "bound":
            out.append(_f("error", "dhcp_unbound",
                          f"{iface} is not getting an address from the ISP "
                          f"(DHCP status: {dhcp.get('status')}).",
                          "Restart the modem; if it stays like this, the ISP side is down."))
    if kind == "ppp":
        ppp = next((r for r in _safe(fetch, ("interface", "pppoe-client"))
                    if _norm_iface(r.get("name")) == want), None)
        if ppp is not None and (_off(ppp) or ("running" in ppp and not _yes(ppp.get("running")))):
            out.append(_f("error", "ppp_down", f"The PPPoE connection {iface} is not connected.",
                          "Check its username and password, and the modem."))
    if source.get("problem") and not any(x["level"] == "error" for x in out):
        out.append(_f("error", "no_ip", source["problem"]))

    # -- the line's route to the internet
    routes = [r for r in _safe(fetch, ("ip", "route"))
              if _is_default(r) and _in_main(r)]
    addrs = _safe(fetch, ("ip", "address"))
    dhcp_by_iface = {_norm_iface(r.get("interface")): r
                     for r in _safe(fetch, ("ip", "dhcp-client")) if r.get("interface")}

    def owner(r):
        i = _fo_route_idx(str(r.get("comment", "")), links)
        if i is not None:
            return i
        return next((i for i, e in enumerate(links)
                     if _matches_endpoint(r, e, dhcp_by_iface, addrs)), None)
    mine = [r for r in routes if owner(r) == idx]
    tagged = [r for r in mine if str(r.get("comment", "")).startswith(TAG)]
    if not mine:
        level = "error" if (len(links) > 1 or not ping_ok) else "warn"
        out.append(_f(level, "route_missing",
                      f"The router has no internet route through {label}, so "
                      f"no traffic will ever use it"
                      + (" -- not even when the other line fails." if len(links) > 1 else "."),
                      "Turn on Gateway Failover on this tab (or push it again) so every "
                      "line gets its route."))
    else:
        if all(_off(r) for r in mine):
            out.append(_f("error", "route_disabled",
                          f"The internet route through {label} is switched off.",
                          "Push Gateway Failover again, or enable the route under IP > Routes."))
        elif not any(_is_usable(r) for r in mine):
            gs = str(mine[0].get("gateway-status", "") or "no status")
            out.append(_f("error" if not ping_ok else "warn", "route_unreachable",
                          f"The router cannot use the route through {label}: "
                          f"its gateway {mine[0].get('gateway', '?')} is not answering ({gs}).",
                          "If the ping above worked, the gateway on this line is wrong: "
                          "check it in the WAN uplinks list." if ping_ok else
                          "The modem or ISP is not answering on this line."))
        if any(str(r.get("check-gateway", "")) for r in tagged):
            out.append(_f("warn", "netwatch_stale",
                          f"The route through {label} still has an old gateway check "
                          f"from an earlier version; it can switch the line off by itself.",
                          "Push Gateway Failover again to clear it."))
    # Order of the lines: the primary must have the lowest distance.
    dist = {}
    for r in routes:
        i = owner(r)
        if i is not None and not _off(r):
            try:
                dist.setdefault(i, int(r.get("distance", 1)))
            except ValueError:
                pass
    if idx in dist:
        better = [i for i, d in dist.items() if i > idx and d <= dist[idx]]
        worse = [i for i, d in dist.items() if i < idx and d >= dist[idx]]
        if better or worse:
            other = links[(better or worse)[0]].label((better or worse)[0])
            out.append(_f("warn", "ladder_wrong",
                          f"{label} and {other} are not in the order set on this tab "
                          f"(route priorities {dist[idx]} and {dist[(better or worse)[0]]}), "
                          f"so the router may use the wrong line first.",
                          "Push Gateway Failover again to put them in order."))
    if kind == "dhcp" and dhcp is not None and tagged \
            and str(dhcp.get("add-default-route", "")).lower() == "yes":
        out.append(_f("warn", "dhcp_default_on",
                      f"The DHCP client on {iface} also adds its own internet route, "
                      f"which competes with the one this website manages.",
                      "Push Gateway Failover again (it turns that off)."))
    if any(str(n.get("comment", "")).startswith(TAG) for n in _safe(fetch, ("tool", "netwatch"))):
        out.append(_f("warn", "netwatch_stale",
                      "Old failover checks from an earlier version are still in Tools > "
                      "Netwatch; they can switch lines on and off by themselves.",
                      "Push Gateway Failover again to remove them."))

    # -- can the office use it?
    member_rows = _read(fetch, ("interface", "list", "member"))
    members = {}
    for m in member_rows or []:
        members.setdefault(str(m.get("list", "")), set()).add(_norm_iface(m.get("interface")))
    nat_rows = _read(fetch, ("ip", "firewall", "nat"))
    nat = [r for r in nat_rows or []
           if r.get("chain") == "srcnat" and not _off(r)
           and r.get("action") in ("masquerade", "src-nat")]
    unsure = []                        # a rule this check cannot judge

    def covers(r):
        oi = str(r.get("out-interface", "") or "")
        ol = str(r.get("out-interface-list", "") or "")
        if not oi and not ol:
            return True
        if oi:
            return (_norm_iface(oi) == want) if not oi.startswith("!") else _norm_iface(oi[1:]) != want
        neg, name = ol.startswith("!"), ol.lstrip("!")
        if name == "all":
            return not neg
        if name in ("dynamic", "static", "none") or member_rows is None:
            unsure.append(r)          # built-in, or members unreadable
            return False
        return (want in members.get(name, set())) != neg
    covered = any(covers(r) for r in nat)
    if want and nat_rows is not None and not covered and not unsure:
        out.append(_f("error", "nat_missing",
                      f"Nothing translates the office's traffic onto {iface} (no "
                      f"masquerade rule covers it), so the router itself can reach "
                      f"the internet through {label} but the PCs behind it cannot.",
                      f"Add an IP > Firewall > NAT rule: chain srcnat, out-interface "
                      f"{iface} (or a list it is in), action masquerade."))

    # -- the monitor's own checks
    narrowing = ("connection-state", "dst-address", "dst-address-list",
                 "src-address", "src-address-list", "out-interface-list",
                 "dst-port", "src-port", "icmp-options", "connection-mark",
                 "packet-mark", "routing-mark", "layer7-protocol", "content")
    for r in _safe(fetch, ("ip", "firewall", "filter")):
        proto = str(r.get("protocol", "") or "")
        if (r.get("chain") == "output" and not _off(r)
                and r.get("action") in ("drop", "reject")
                and (proto == "icmp" or (not proto and not any(
                    r.get(k) for k in narrowing)))
                and _norm_iface(r.get("out-interface", "") or iface) == want):
            out.append(_f("warn", "icmp_blocked",
                          "A firewall rule stops the router itself from sending "
                          "pings, so this test and the website's own internet check "
                          "can fail while the line works.",
                          "Allow ICMP in the output chain, or remove that rule."))
            break
    dns = next(iter(_safe(fetch, ("ip", "dns"))), None)
    if dns is not None and not str(dns.get("servers", "")).strip() \
            and not str(dns.get("dynamic-servers", "")).strip():
        out.append(_f("warn", "dns_none",
                      "The router has no DNS server, so names do not work even "
                      "where the line does.",
                      "Set DNS servers under IP > DNS (for example 1.1.1.1)."))

    if shown_offline and ping_ok:
        out.append(_f("warn", "stale_monitor",
                      f"{label} works (it answered above), but the dashboard shows it "
                      f"offline." + ("" if [x for x in out if x["level"] == "error"] else
                                     " Nothing on the router is wrong with it; the "
                                     "dashboard catches up within two checks. If it "
                                     "does not, the interface or gateway in the WAN "
                                     "uplinks list does not match this line on the "
                                     "router."),
                      ""))
    if not ran:
        # A ping that was never sent says nothing about the line.
        out.append(_f("error", "test_not_run",
                      f"The test could not be run on the router: {reason}",
                      "This is not a fault on the line; the checks below are "
                      "still right. Tell support, with this message."))
    elif not ping_ok and weak and not [x for x in out if x["level"] == "error"]:
        out.append(_f("warn", "test_weak",
                      f"{label} did not answer, and nothing on the router "
                      f"explains it. On this kind of line the test cannot be "
                      f"completely sure, but most likely the modem or the ISP "
                      f"is down.",
                      "If users on this line have no internet, restart the "
                      "modem, then call the ISP."))
    elif not ping_ok and not [x for x in out if x["level"] == "error"]:
        out.append(_f("error", "isp_down",
                      f"{label} is set up correctly on the router, but nothing on "
                      f"the internet answers through it.",
                      "The fault is outside the router: the modem or the ISP. "
                      "Restart the modem, then call the ISP."))
    if not out:
        out.append(_f("ok", "all_ok", f"{label} works and nothing is wrong with its setup."))
    rank = {"error": 0, "warn": 1, "ok": 2}
    return sorted(out, key=lambda x: rank[x["level"]])


# ---- the report ---------------------------------------------------------------------------
def _way(test: dict, r: dict) -> str:
    src = test.get("source") or {}
    method = r.get("method") or ("route" if test.get("via") == "route" else "interface")
    if method == "interface":
        return (f" out of {src.get('interface')}"
                + (f" (from {src.get('src_address')})" if src.get("src_address") else ""))
    return (f" through {src.get('interface')} by a temporary route via "
            f"{test.get('gateway')}"
            + (f" (from {src.get('src_address')})" if method == "mark"
               and src.get("src_address") else ""))


def report_from(test: dict, findings: list, label: str, shown_offline: bool) -> dict:
    """{"status": "healthy"|"attention"|"failed"|"not_run", "steps": [{"level",
    "msg"}]}, the shape the tab's report box shows."""
    steps = []
    ran = test.get("ran", True)
    if not ran:
        steps.append({"level": "error",
                      "msg": f"The test could not be run, so it says nothing about "
                             f"whether {label} works: {test.get('reason') or 'unknown reason'}"})
    if test.get("note"):
        steps.append({"level": "warn", "msg": test["note"]})
    for r in test.get("tried") or []:
        if r["error"]:
            steps.append({"level": "warn" if not ran or test.get("ok") else "error",
                          "msg": f"Ping {r['address']}{_way(test, r)}: {r['error']}"})
            continue
        avg = f", average {r['avg_ms']:g} ms" if r["avg_ms"] is not None else ""
        msg = (f"Ping {r['address']}{_way(test, r)}: {r['sent']} sent, "
               f"{r['received']} answered, {r['loss']}% lost{avg}.")
        if r["received"]:
            level = "ok"
        elif test.get("ok") and r.get("method") != test.get("method"):
            # Silent out of the interface alone, then answered the surer
            # way: normal for an Ethernet line, not a problem.
            level = "ok"
            msg += " (Normal for this kind of line; the next way answered.)"
        elif test.get("ok") or test.get("weak"):
            level = "warn"
        else:
            level = "error"
        steps.append({"level": level, "msg": msg})
    steps.append({"level": "warn" if shown_offline else "ok",
                  "msg": f"The dashboard shows {label} as "
                         f"{'OFFLINE' if shown_offline else 'online'}."})
    for f in findings:
        if f["code"] == "test_not_run":
            continue                       # said first, above
        steps.append({"level": f["level"],
                      "msg": f["msg"] + (f" What to do: {f['fix']}" if f.get("fix") else "")})
    levels = {s["level"] for s in steps}
    if not ran:
        status = "not_run"
    elif test.get("ok"):
        status = "failed" if "error" in levels else "attention" if "warn" in levels else "healthy"
    else:
        status = "attention" if test.get("weak") and "error" not in levels else "failed"
    return {"status": status, "steps": steps}
