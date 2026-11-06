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
# A ping is sent out of one line by a route of its own in a routing table
# nothing else uses, removed again straight after. ("interface=" alone does
# not do it: on an Ethernet line the router then looks for the internet
# address on the cable itself instead of going through the line's gateway.)
TEST_TABLE = "mikromon-linetest"
TEST_TAG = "mikromon:linetest"
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
             routing_table: str = "", count: int = 3, interval: str = "300ms") -> dict:
    """Ping `address` from the router, out of `interface` and from
    `src_address`. Returns {"address", "interface", "src_address", "sent",
    "received", "loss", "avg_ms", "error"}; `error` is set (and loss None)
    when the router would not run the ping at all."""
    out = {"address": address, "interface": interface, "src_address": src_address,
           "sent": 0, "received": 0, "loss": None, "avg_ms": None, "error": ""}
    params = {"address": address, "count": str(count), "interval": interval}
    if interface:
        params["interface"] = interface
    if src_address:
        params["src-address"] = src_address
    if routing_table:
        params["routing-table"] = routing_table
    try:
        rows = list(api.ping_rows(**params))
    except Exception as exc:  # noqa: BLE001 -- the router's words are the evidence
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


def _cleanup(api, major: int, table_added: bool = False) -> None:
    """Remove the test's route (and, on RouterOS 7, its table) -- this run's,
    or one a broken earlier run left behind."""
    for r in _safe(api.fetch, ("ip", "route")):
        if r.get("comment") == TEST_TAG and r.get(".id"):
            try:
                api.execute(Operation("remove", ("ip", "route"), {".id": r[".id"]}))
            except Exception:  # noqa: BLE001 -- the next test tries again
                pass
    if major >= 7 or major == 0:
        for t in _safe(api.fetch, ("routing", "table")):
            if t.get("name") == TEST_TABLE and t.get(".id") \
                    and (table_added or t.get("comment") == TEST_TAG):
                try:
                    api.execute(Operation("remove", ("routing", "table"),
                                          {".id": t[".id"]}))
                except Exception:  # noqa: BLE001
                    pass


def _add_test_route(api, major: int, gateway: str) -> str:
    """Put this line's route in the test's own table. Returns "" when done,
    else why not."""
    try:
        if major >= 7 or major == 0:
            if not any(t.get("name") == TEST_TABLE
                       for t in _safe(api.fetch, ("routing", "table"))):
                api.execute(Operation("add", ("routing", "table"),
                                      {"name": TEST_TABLE, "fib": "yes",
                                       "comment": TEST_TAG}))
            field = "routing-table"
        else:
            field = "routing-mark"
        api.execute(Operation("add", ("ip", "route"),
                              {"dst-address": "0.0.0.0/0", "gateway": gateway,
                               field: TEST_TABLE, "comment": TEST_TAG}))
        return ""
    except Exception as exc:  # noqa: BLE001
        return str(exc)[:200]


def test_line(api, ep, targets=None, *, clock=time.monotonic) -> dict:
    """Ping the internet through one line, stopping at the first answer.
    Returns {"source": pick_source(), "gateway", "via": "route"|"interface",
    "note", "tried": [ping_via() ...], "ok": bool}.

    The ping goes out by a route of the test's own, in a table nothing else
    uses, which is removed again afterwards -- the only router change, and
    it touches no traffic. Where that route cannot be added, the router is
    asked to ping out of the interface instead, which is reliable for a
    PPPoE line and only a hint for an Ethernet one (said in `note`)."""
    source = pick_source(api.fetch, ep)
    out = {"source": source, "gateway": "", "via": "", "note": "", "tried": [],
           "ok": False}
    if not source["interface"]:
        return out
    gateway = _line_gateway(api.fetch, ep, source)
    out["gateway"] = gateway
    major = _major(api.fetch)
    table = ""
    if gateway:
        _cleanup(api, major)
        why = _add_test_route(api, major, gateway)
        if why:
            out["note"] = (f"The test route could not be added ({why}), so the "
                           f"router was asked to ping out of {source['interface']} "
                           f"instead; on an Ethernet line that may fail even when "
                           f"the line works.")
        else:
            table = TEST_TABLE
    else:
        out["note"] = ("No gateway was found for this line, so the router was "
                       f"asked to ping out of {source['interface']} instead; on "
                       f"an Ethernet line that may fail even when the line works.")
    out["via"] = "route" if table else "interface"
    deadline = clock() + BUDGET_SECONDS
    try:
        for target in (list(targets) if targets else list(TARGETS)):
            if clock() > deadline:
                break
            if table:
                r = ping_via(api, target, src_address=source["src_address"],
                             routing_table=table)
            else:
                r = ping_via(api, target, interface=source["interface"],
                             src_address=source["src_address"])
            out["tried"].append(r)
            if r["received"] > 0:
                break
            if r["error"] and "permission" in r["error"]:
                break                      # the next target will be refused too
    finally:
        if table:
            _cleanup(api, major, table_added=True)
    out["ok"] = any(r["received"] > 0 for r in out["tried"])
    return out


# ---- what is wrong -------------------------------------------------------------------------
def _f(level, code, msg, fix=""):
    return {"level": level, "code": code, "msg": msg, "fix": fix}


def _yes(value) -> bool:
    return str(value or "").lower() in ("true", "yes")


def diagnose_line(fetch, links, idx: int, *, shown_offline: bool, ping_ok: bool,
                  source: dict | None = None) -> list:
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
    if not ping_ok and not [x for x in out if x["level"] == "error"]:
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
def report_from(test: dict, findings: list, label: str, shown_offline: bool) -> dict:
    """{"status": "healthy"|"attention"|"failed", "steps": [{"level", "msg"}]},
    the shape the tab's report box shows."""
    steps = []
    src = test.get("source") or {}
    way = (f" through {src.get('interface')}" if src.get("interface") else "") + \
          (f" (from {src.get('src_address')}" if src.get("src_address") else "") + \
          (f", via {test.get('gateway')})" if src.get("src_address") and test.get("via") == "route"
           else ")" if src.get("src_address") else "")
    if test.get("note"):
        steps.append({"level": "warn", "msg": test["note"]})
    for r in test.get("tried") or []:
        if r["error"]:
            steps.append({"level": "error", "msg": f"Ping {r['address']}{way}: {r['error']}"})
            continue
        avg = f", average {r['avg_ms']:g} ms" if r["avg_ms"] is not None else ""
        steps.append({"level": "ok" if r["received"] else "error",
                      "msg": f"Ping {r['address']}{way}: {r['sent']} sent, "
                             f"{r['received']} answered, {r['loss']}% lost{avg}."})
    if not test.get("tried"):
        steps.append({"level": "error",
                      "msg": f"{label} could not be pinged: {src.get('problem') or 'no way out found'}"})
    steps.append({"level": "warn" if shown_offline else "ok",
                  "msg": f"The dashboard shows {label} as "
                         f"{'OFFLINE' if shown_offline else 'online'}."})
    for f in findings:
        steps.append({"level": f["level"],
                      "msg": f["msg"] + (f" What to do: {f['fix']}" if f.get("fix") else "")})
    levels = {s["level"] for s in steps}
    status = ("failed" if not test.get("ok") or "error" in levels
              else "attention" if "warn" in levels else "healthy")
    return {"status": status, "steps": steps}
