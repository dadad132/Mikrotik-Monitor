"""The WAN tab's "Test this line" (mikromon/wantest.py and its page).

The router pings the internet out of ONE line, from that line's address; then
the line's setup is read and every problem is said in plain words. The case
it exists for: the dashboard says a line is offline, but it answers -- so
something around it is wrong, and the scan says what.

Run: python tests/wan_line_test_test.py
"""
import http.cookiejar
import json
import os
import re
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import push as push_pkg  # noqa: E402
from mikromon import wantest as W  # noqa: E402
from mikromon import web  # noqa: E402
from mikromon.auth import AuthStore  # noqa: E402
from mikromon.config import DEFAULT_THRESHOLDS, WanEndpoint  # noqa: E402
from mikromon.devices_store import DevicesStore  # noqa: E402
from mikromon.metrics import MetricsStore  # noqa: E402
from mikromon.push import api as push_api  # noqa: E402
from mikromon.webguard import GuardedHTTPServer  # noqa: E402

FAILS = []


def check(name, ok, extra=""):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}" + (f"  ({extra})" if extra and not ok else ""))
    if not ok:
        FAILS.append(name)


class Router:
    """A two-line router: ether1 (fibre, DHCP, primary) and pppoe-out1
    (backup). Tests change its tables to make each fault."""

    def __init__(self):
        self.t = {
            ("interface",): [{"name": "ether1", "running": "true", "disabled": "false"},
                             {"name": "pppoe-out1", "running": "true", "disabled": "false"}],
            ("ip", "dhcp-client"): [{"interface": "ether1", "status": "bound",
                                     "address": "41.0.0.10/24", "gateway": "41.0.0.1",
                                     "add-default-route": "no", "disabled": "false"}],
            ("interface", "pppoe-client"): [{"name": "pppoe-out1", "running": "true",
                                             "disabled": "false"}],
            ("ip", "address"): [{"interface": "ether1", "address": "41.0.0.10/24"},
                                {"interface": "pppoe-out1", "address": "102.1.1.5/32"},
                                {"interface": "bridge", "address": "192.168.88.1/24"}],
            ("ip", "route"): [
                {"dst-address": "0.0.0.0/0", "gateway": "41.0.0.1", "distance": "10",
                 "active": "true", "comment": "mikromon:failover:primary",
                 "gateway-status": "41.0.0.1 reachable via ether1"},
                {"dst-address": "0.0.0.0/0", "gateway": "pppoe-out1", "distance": "20",
                 "active": "false", "gateway-status": "pppoe-out1 reachable"}],
            ("ip", "firewall", "nat"): [{"chain": "srcnat", "action": "masquerade",
                                         "out-interface-list": "WAN"}],
            ("interface", "list", "member"): [{"list": "WAN", "interface": "ether1"},
                                              {"list": "WAN", "interface": "pppoe-out1"}],
            ("ip", "firewall", "filter"): [],
            ("tool", "netwatch"): [],
            ("ip", "dns"): [{"servers": "1.1.1.1", "dynamic-servers": ""}],
            ("system", "resource"): [{"version": "7.14.3 (stable)"}],
            ("routing", "table"): [{".id": "*1", "name": "main", "fib": "true"}],
        }
        # (line, address) or (line, address, "interface"|"vrf"|"mark") -> received
        # of 3, or an Exception. The three-part key wins, so an Ethernet line can
        # stay silent to interface= (RouterOS ARPs for the target) and still
        # answer through a VRF.
        self.answer = {}
        self.pings = []         # pings the router accepted
        self.refused = []       # pings refused because this version lacks the parameter
        self.ops = []           # (action, path, params), in order, refused ones too
        self.refuse_add = None  # an error to raise when a route is added
        self.refuse_paths = {}  # path -> error to raise when a row is added there
        self.refuse_main = False  # refuse gateways written "<gw>@main"
        self.major = None       # the real version, when its resource menu is gone
        self.n = 100

    GATEWAY_OF = {"41.0.0.1": "ether1", "pppoe-out1": "pppoe-out1"}

    def real_major(self):
        if self.major is not None:
            return self.major
        rows = self.t.get(("system", "resource")) or [{}]
        head = str(rows[0].get("version", "")).split(".")[0]
        return int(head) if head.isdigit() else 0

    def execute(self, op):
        self.ops.append((op.action, op.path, dict(op.params)))
        rows = self.t.setdefault(op.path, [])
        if op.action == "add":
            if self.refuse_add and op.path == ("ip", "route"):
                raise push_api.PushError(self.refuse_add)
            if op.path in self.refuse_paths:
                raise push_api.PushError(self.refuse_paths[op.path])
            if (self.refuse_main and op.path == ("ip", "route")
                    and str(op.params.get("gateway", "")).endswith("@main")):
                raise push_api.PushError("invalid value for argument gateway")
            self.n += 1
            rows.append({".id": f"*{self.n}", **op.params})
            return f"*{self.n}"
        if op.action == "remove":
            self.t[op.path] = [r for r in rows if r.get(".id") != op.params[".id"]]
        return None

    def routes(self):
        return self.t[("ip", "route")]

    def line_of(self, p):
        """Which line a ping really leaves by."""
        if p.get("vrf"):
            route = next(r for r in self.routes() if r.get("routing-table") == p["vrf"])
            return self.GATEWAY_OF[route["gateway"].split("@")[0]]
        if p.get("routing-table"):
            route = next(r for r in self.routes()
                         if p["routing-table"] in (r.get("routing-table"), r.get("routing-mark")))
            return self.GATEWAY_OF[route["gateway"].split("@")[0]]
        return p.get("interface", "")

    def fetch(self, path):
        if path not in self.t:
            raise push_api.PushError(f"no such menu {path}")
        return [dict(r) for r in self.t[path]]

    def ping_rows(self, **p):
        major = self.real_major()
        if major == 7 and "routing-table" in p:
            self.refused.append(p)
            raise push_api.PushError("unknown parameter routing-table")
        if major == 6 and "vrf" in p:
            self.refused.append(p)
            raise push_api.PushError("unknown parameter vrf")
        self.pings.append(p)
        line = self.line_of(p)
        kind = "vrf" if p.get("vrf") else "mark" if p.get("routing-table") else "interface"
        got = self.answer.get((line, p["address"], kind),
                              self.answer.get((line, p["address"]), 3))
        if isinstance(got, Exception):
            raise push_api.PushError(str(got))
        return [{"seq": "0"}, {"sent": "3", "received": str(got),
                               "packet-loss": str(100 - round(100 * got / 3)),
                               "avg-rtt": "12ms345us" if got else ""}]


LINKS = [WanEndpoint(interface="ether1", name="Fibre"),
         WanEndpoint(interface="pppoe-out1", name="LTE backup")]


def run(r, idx, shown_offline):
    test = W.test_line(r, LINKS[idx])
    findings = W.diagnose_line(r.fetch, LINKS, idx, shown_offline=shown_offline,
                               ping_ok=test["ok"], source=test["source"],
                               ran=test["ran"], weak=test["weak"], reason=test["reason"])
    return test, findings, {f["code"] for f in findings}


def silent_interface(r, line="ether1"):
    """interface= gets no answer on this line, as RouterOS does on Ethernet
    when it cannot ARP for the target; every other way is left alone."""
    for a in W.TARGETS:
        r.answer[(line, a, "interface")] = 0


def adds(r, path):
    return [o for o in r.ops if o[0] == "add" and o[1] == path]


def pos(r, action, path):
    return next(i for i, o in enumerate(r.ops) if o[0] == action and o[1] == path)


def left_over(r):
    return (any(x.get("comment") == W.TEST_TAG for x in r.t[("ip", "route")])
            or bool(r.t.get(("ip", "vrf"))))


print("Pinging out of one line")
r = Router()
test, findings, codes = run(r, 0, False)
check("RouterOS 7 Ethernet: out of the interface first, from its address, and it answers",
      test["ok"] and test["method"] == "interface" and test["ran"] and not test["weak"]
      and r.pings[0]["interface"] == "ether1" and r.pings[0]["src-address"] == "41.0.0.10")
check("...and then the router is not changed at all", r.ops == [], r.ops)
check("...it is counted: sent, answered, loss, average time",
      test["tried"][0]["received"] == 3 and test["tried"][0]["loss"] == 0
      and test["tried"][0]["avg_ms"] == 12.3 and test["tried"][0]["method"] == "interface")
check("it stops at the first address that answers", len(r.pings) == 1)
check("a healthy line, shown online, is reported as fine", codes == {"all_ok"}, codes)

r = Router()
silent_interface(r)
test, findings, codes = run(r, 0, False)
vp = next((p for p in r.pings if "vrf" in p), {})
check("RouterOS 7 Ethernet, interface= silent but the VRF answers: ok, by the VRF",
      test["ok"] and test["method"] == "vrf" and test["via"] == "route" and test["ran"]
      and not test["weak"], test["method"])
check("...the VRF ping has vrf= and neither a source address nor routing-table=",
      vp.get("vrf") == W.TEST_VRF and "src-address" not in vp and "routing-table" not in vp
      and "interface" not in vp, vp)
vrf_add = adds(r, ("ip", "vrf"))
route_add = adds(r, ("ip", "route"))
check("...a VRF and a default route via the gateway in it are added",
      len(vrf_add) == 1 and vrf_add[0][2]["name"] == W.TEST_VRF
      and vrf_add[0][2]["interfaces"] == "none" and vrf_add[0][2]["comment"] == W.TEST_TAG
      and len(route_add) == 1 and route_add[0][2]["dst-address"] == "0.0.0.0/0"
      and route_add[0][2]["gateway"] == "41.0.0.1@main"
      and route_add[0][2]["routing-table"] == W.TEST_VRF
      and route_add[0][2]["comment"] == W.TEST_TAG, route_add)
check("...both are removed afterwards", not left_over(r))
check("...the route is removed BEFORE the VRF it is in",
      pos(r, "remove", ("ip", "route")) < pos(r, "remove", ("ip", "vrf")))
check("...and the route is added after the VRF",
      pos(r, "add", ("ip", "vrf")) < pos(r, "add", ("ip", "route")))
check("...no routing table is declared, and no ping carried routing-table=",
      not adds(r, ("routing", "table")) and not r.refused
      and not any("routing-table" in p for p in r.pings)
      and [x["name"] for x in r.t[("routing", "table")]] == ["main"])

r = Router()
r.answer[("ether1", "1.1.1.1")] = 0
r.answer[("ether1", "8.8.8.8")] = 0
test, findings, codes = run(r, 0, True)
check("RouterOS 7 Ethernet, no way answers: the test ran both ways",
      test["ran"] and not test["ok"] and test["method"] == "vrf"
      and {t["method"] for t in test["tried"]} == {"interface", "vrf"})
check("...and, since neither way can prove an Ethernet line dead, it says "
      "'most likely the modem or ISP' rather than certain",
      test["weak"] and "test_weak" in codes and "isp_down" not in codes
      and "test_not_run" not in codes and "strong hint" in test["note"], codes)
rep = W.report_from(test, findings, "Fibre", True)
check("...and the report is 'attention', not 'the test could not run'",
      rep["status"] == "attention")

r = Router()
silent_interface(r)
test, findings, codes = run(r, 0, False)
rep = W.report_from(test, findings, "Fibre", False)
check("a working RouterOS 7 Ethernet line (silent out of the interface, answering "
      "through the VRF) is reported healthy, not 'something is wrong'",
      test["ok"] and test["method"] == "vrf" and rep["status"] == "healthy"
      and any("Normal for this kind of line" in st["msg"] for st in rep["steps"]), rep)

r = Router()
r.t[("ip", "vrf")] = [{".id": "*v1", "name": W.TEST_VRF, "interfaces": "ether5"}]
silent_interface(r)
run(r, 0, False)
check("a VRF of the customer's that happens to share the test's name is never removed",
      any(v.get(".id") == "*v1" for v in r.t[("ip", "vrf")]))

r = Router()
test, _, codes = run(r, 1, False)
check("a PPPoE line: out of the interface, from its session address",
      test["ok"] and test["method"] == "interface"
      and r.pings[0]["interface"] == "pppoe-out1" and r.pings[0]["src-address"] == "102.1.1.5"
      and "vrf" not in r.pings[0] and "routing-table" not in r.pings[0])
check("...and the router is not changed at all", r.ops == [], r.ops)
r = Router()
r.t[("system", "resource")] = [{"version": "6.49.8"}]
test, _, _ = run(r, 1, False)
check("...the same on RouterOS 6", test["ok"] and r.ops == []
      and r.pings[0]["interface"] == "pppoe-out1" and r.pings[0]["src-address"] == "102.1.1.5")

r = Router()
r.t[("system", "resource")] = [{"version": "6.49.8"}]
test, _, _ = run(r, 0, False)
added = adds(r, ("ip", "route"))
check("RouterOS 6 Ethernet: a route with a routing mark, pinged with routing-table=, from its address",
      len(added) == 1 and added[0][2].get("routing-mark") == W.TEST_TABLE
      and added[0][2]["gateway"] == "41.0.0.1" and test["ok"] and test["method"] == "mark"
      and r.pings[0]["routing-table"] == W.TEST_TABLE and r.pings[0]["src-address"] == "41.0.0.10"
      and "vrf" not in r.pings[0] and "interface" not in r.pings[0], r.pings)
check("...no VRF or routing table is made, and the route is removed afterwards",
      not adds(r, ("ip", "vrf")) and not adds(r, ("routing", "table")) and not left_over(r))

# The field failure: every ping refused for the RouterOS 7 parameter.
r = Router()
for a in W.TARGETS:
    r.answer[("ether1", a)] = RuntimeError("unknown parameter routing-table")
r.refuse_paths[("ip", "vrf")] = "unknown parameter vrf"
test, findings, codes = run(r, 0, True)
rep = W.report_from(test, findings, "Fibre", True)
check("every ping refused: the test did not run, and says why",
      not test["ran"] and not test["ok"] and not test["weak"]
      and "does not accept that way of pinging" in test["reason"], test["reason"])
check("...it is 'test_not_run' and never 'isp_down'",
      "test_not_run" in codes and "isp_down" not in codes and "test_weak" not in codes, codes)
check("...the report is 'not_run' and its first step says the test could not be run",
      rep["status"] == "not_run" and rep["steps"][0]["msg"].startswith("The test could not be run"),
      rep["steps"][:1])
check("...and the router is left clean", not left_over(r))
r = Router()
for a in W.TARGETS:
    r.answer[("ether1", a)] = RuntimeError("unknown parameter vrf")
test, findings, codes = run(r, 0, False)
check("a router refusing every kind of ping is never blamed on the ISP",
      not test["ran"] and "isp_down" not in codes and "test_not_run" in codes, codes)

r = Router()
r.t[("ip", "route")] += [
    {".id": "*9", "dst-address": "0.0.0.0/0", "gateway": "41.0.0.1@main",
     "routing-table": W.TEST_TABLE, "comment": W.TEST_TAG},
    {".id": "*10", "dst-address": "10.9.0.0/16", "gateway": "41.0.0.1", "comment": "mine"}]
r.t[("ip", "vrf")] = [{".id": "*8", "name": W.TEST_VRF, "interfaces": "none",
                       "comment": W.TEST_TAG},
                      {".id": "*11", "name": "customer", "interfaces": "ether5"}]
r.t[("routing", "table")] += [{".id": "*7", "name": W.TEST_TABLE, "fib": "true",
                               "comment": W.TEST_TAG},
                              {".id": "*6", "name": "office-table", "fib": "true"}]
test, _, _ = run(r, 0, False)
check("leftovers of earlier tests (tagged route, VRF, old routing table) are removed first",
      test["ok"] and not any(x.get("comment") == W.TEST_TAG for x in r.t[("ip", "route")])
      and not [v for v in r.t[("ip", "vrf")] if v["name"] == W.TEST_VRF]
      and [x["name"] for x in r.t[("routing", "table")] if x["name"] == W.TEST_TABLE] == [],
      r.t[("routing", "table")])
check("...but what is not the test's is kept: another routing table, VRF and route",
      "office-table" in [x["name"] for x in r.t[("routing", "table")]]
      and "main" in [x["name"] for x in r.t[("routing", "table")]]
      and [v["name"] for v in r.t[("ip", "vrf")]] == ["customer"]
      and any(x.get("comment") == "mine" for x in r.t[("ip", "route")]))
r = Router()
r.t[("routing", "table")] += [{".id": "*7", "name": W.TEST_TABLE, "fib": "true"}]
run(r, 0, False)
check("a routing table of the test's name that the test did not tag is not touched",
      any(x["name"] == W.TEST_TABLE for x in r.t[("routing", "table")]))

r = Router()
silent_interface(r)
r.refuse_main = True
test, _, _ = run(r, 0, False)
gws = [o[2]["gateway"] for o in adds(r, ("ip", "route"))]
check("a router refusing 'gw@main' is given the plain gateway, and the VRF ping answers",
      gws == ["41.0.0.1@main", "41.0.0.1"] and test["ok"] and test["method"] == "vrf", gws)
check("...and it is cleaned up after", not left_over(r))

r = Router()
del r.t[("system", "resource")]
r.major = 7
silent_interface(r)
test, _, _ = run(r, 0, False)
kinds = ["vrf" if "vrf" in p else "interface" for p in r.pings]
check("version unreadable (really 7): interface first, then the VRF, and it ends ok",
      test["ok"] and test["method"] == "vrf" and kinds[0] == "interface" and kinds[-1] == "vrf"
      and "routing-mark" not in adds(r, ("ip", "route"))[0][2], kinds)
check("...the mark way is not used when the VRF way works",
      not any("routing-table" in p for p in r.pings + r.refused))
r = Router()
del r.t[("system", "resource")]
r.major = 6
silent_interface(r)
test, _, _ = run(r, 0, False)
check("version unreadable (really 6): VRF is refused as unsupported, so the mark way is used",
      test["ok"] and test["method"] == "mark" and len(r.refused) == 1 and "vrf" in r.refused[0]
      and r.pings[-1].get("routing-table") == W.TEST_TABLE
      and r.pings[-1].get("src-address") == "41.0.0.10", (test["method"], r.refused))
check("...and nothing is left on the router", not left_over(r))

r = Router()
for a in W.TARGETS:
    r.answer[("ether1", a)] = 0
r.refuse_paths[("ip", "vrf")] = "not enough permissions"
test, findings, codes = run(r, 0, True)
rep = W.report_from(test, findings, "Fibre", True)
check("only interface= usable on an Ethernet line and nothing answers: weak, not failed",
      test["ran"] and not test["ok"] and test["weak"] and "interface only" in test["note"], test["note"])
check("...so 'test_weak', never 'isp_down'", "test_weak" in codes and "isp_down" not in codes
      and "test_not_run" not in codes, codes)
check("...and the report is 'attention'", rep["status"] == "attention", rep["status"])

r = Router()
r.answer[("ether1", "1.1.1.1", "interface")] = 0
test, _, _ = run(r, 0, False)
check("one address not answering: the next is tried",
      [p["address"] for p in r.pings] == ["1.1.1.1", "8.8.8.8"] and test["ok"]
      and r.ops == [])
r = Router()
r.answer[("ether1", "1.1.1.1")] = RuntimeError("not enough permissions (9)")
test, _, _ = run(r, 0, False)
check("a refused ping says why (no 'test' permission) and is not retried",
      "test\" permission" in test["tried"][0]["error"] and len(r.pings) == 1 and not test["ok"])


class _Rec:
    def __init__(self):
        self.p = None

    def ping_rows(self, **p):
        self.p = p
        return [{"sent": "3", "received": "3"}]


rec = _Rec()
res = W.ping_via(rec, "1.1.1.1", vrf="x")
check("ping_via with vrf sends vrf, and not routing-table",
      rec.p.get("vrf") == "x" and "routing-table" not in rec.p and res["received"] == 3, rec.p)
check("explain_trap says RouterOS does not accept that way of pinging",
      "does not accept that way of pinging" in W.explain_trap("unknown parameter routing-table"))
check("round-trip times in RouterOS's forms are read",
      W._ms("12ms") == 12 and W._ms("1s20ms") == 1020 and abs(W._ms("850us") - 0.85) < 0.06
      and W._ms("") is None)

print("Shown offline, but it answers: what is wrong")
r = Router()
r.t[("ip", "route")] = [x for x in r.t[("ip", "route")] if x["gateway"] != "pppoe-out1"]
_, findings, codes = run(r, 1, True)
check("no route through the line: it could never take over", "route_missing" in codes, codes)
check("...and the dashboard's 'offline' is explained as the line working",
      "stale_monitor" in codes)
check("problems come first, in plain words with what to do",
      findings[0]["level"] == "error" and "What" not in findings[0]["msg"]
      and findings[0]["fix"])
r = Router()
r.t[("ip", "firewall", "nat")] = [{"chain": "srcnat", "action": "masquerade",
                                   "out-interface": "ether1"}]
_, _, codes = run(r, 1, True)
check("no masquerade for the line: the router reaches the internet, the office cannot",
      "nat_missing" in codes, codes)
r = Router()
_, _, codes = run(r, 0, False)
check("a masquerade by interface list covers the lines in it", "nat_missing" not in codes)
r = Router()
r.t[("ip", "route")][1]["distance"] = "5"
_, _, codes = run(r, 1, True)
check("a backup with a better priority than the primary is pointed out",
      "ladder_wrong" in codes, codes)
r = Router()
r.t[("ip", "dhcp-client")][0]["add-default-route"] = "yes"
_, _, codes = run(r, 0, True)
check("a DHCP client adding its own route beside the managed one", "dhcp_default_on" in codes)
r = Router()
r.t[("tool", "netwatch")] = [{"host": "8.8.8.8", "comment": "mikromon:failover:primary"}]
_, _, codes = run(r, 0, True)
check("old failover checks left in netwatch", "netwatch_stale" in codes)
r = Router()
r.t[("ip", "firewall", "filter")] = [{"chain": "output", "action": "drop", "protocol": "icmp"}]
_, _, codes = run(r, 0, True)
check("a firewall rule stopping the router's own pings", "icmp_blocked" in codes)
r = Router()
r.t[("ip", "firewall", "filter")] = [{"chain": "output", "action": "drop",
                                      "connection-state": "invalid"},
                                     {"chain": "output", "action": "drop",
                                      "dst-address-list": "bogons"}]
_, _, codes = run(r, 0, False)
check("an output rule that only drops some traffic is not called a ping block",
      "icmp_blocked" not in codes, codes)
r = Router()
del r.t[("ip", "firewall", "nat")]
_, _, codes = run(r, 1, False)
check("a NAT list the router would not show is not reported as missing", "nat_missing" not in codes)
r = Router()
del r.t[("interface", "list", "member")]
_, _, codes = run(r, 1, False)
check("...nor when the interface lists could not be read", "nat_missing" not in codes)
r = Router()
_, _, codes = run(r, 1, False)
check("a backup standing by (its route not the active one) is not called unusable",
      "route_unreachable" not in codes and codes == {"all_ok"}, codes)
r = Router()
r.t[("ip", "route")][1]["gateway-status"] = "pppoe-out1 unreachable"
r.answer[("pppoe-out1", "1.1.1.1")] = 0
r.answer[("pppoe-out1", "8.8.8.8")] = 0
_, _, codes = run(r, 1, True)
check("...but one whose gateway is unreachable is", "route_unreachable" in codes, codes)
r = Router()
r.t[("ip", "dns")] = [{"servers": "", "dynamic-servers": ""}]
_, _, codes = run(r, 0, False)
check("no DNS server", "dns_none" in codes)
r = Router()
del r.t[("tool", "netwatch")]
del r.t[("ip", "dns")]
_, _, codes = run(r, 0, False)
check("a menu the router does not have is skipped, not fatal", codes == {"all_ok"}, codes)

print("Shown offline, and it does not answer")
r = Router()
r.t[("interface",)][1]["running"] = "false"
r.answer[("pppoe-out1", "1.1.1.1")] = RuntimeError("interface not running")
r.answer[("pppoe-out1", "8.8.8.8")] = RuntimeError("interface not running")
test, _, codes = run(r, 1, True)
check("a line with no link says so", "iface_down" in codes and not test["ok"], codes)
r = Router()
r.t[("ip", "dhcp-client")][0].update(status="searching...", address="")
_, _, codes = run(r, 0, True)
check("a DHCP line the ISP gives no address", "dhcp_unbound" in codes, codes)
r = Router()
r.answer[("pppoe-out1", "1.1.1.1")] = 0
r.answer[("pppoe-out1", "8.8.8.8")] = 0
_, findings, codes = run(r, 1, True)
check("a PPPoE line set up right where nothing answers: the ISP or the modem, for sure",
      "isp_down" in codes and "stale_monitor" not in codes, codes)
r = Router()
r.t[("system", "resource")] = [{"version": "6.49.8"}]
r.answer[("ether1", "1.1.1.1")] = 0
r.answer[("ether1", "8.8.8.8")] = 0
test, _, codes = run(r, 0, True)
check("...and an Ethernet line on RouterOS 6, where the route-mark way is sure",
      "isp_down" in codes and not test["weak"], codes)
r = Router()
_, _, codes = run(r, 0, True)
check("works, and nothing is wrong on the router: the dashboard catches up",
      codes == {"stale_monitor"}, codes)

print("The report")
r = Router()
test, findings, _ = run(r, 1, True)
rep = W.report_from(test, findings, "LTE backup", True)
check("a line that works but is shown offline is 'attention', not 'failed'",
      rep["status"] == "attention" and "OFFLINE" in " ".join(s["msg"] for s in rep["steps"]))
r = Router()
r.answer[("pppoe-out1", "1.1.1.1")] = 0
r.answer[("pppoe-out1", "8.8.8.8")] = 0
test, findings, _ = run(r, 1, True)
check("a dead line is 'failed'", W.report_from(test, findings, "LTE", True)["status"] == "failed")
check("the dashboard's rule for 'offline' (backup down)",
      web._line_shown_offline({"up": 1, "wan_health": "full",
                               "problems": [{"key": "wan_link:1"}]}, 1)
      and not web._line_shown_offline({"up": 1, "wan_health": "full", "problems": []}, 1))
check("...(primary down, running on the backup)",
      web._line_shown_offline({"up": 1, "wan_health": "partial", "problems": []}, 0)
      and not web._line_shown_offline({"up": 1, "wan_health": "partial", "problems": []}, 1))

print("On the website")
tmp = tempfile.mkdtemp()
mdb, sfile, adb, ddb, pdb = (os.path.join(tmp, x) for x in ("m.db", "s.json", "a.db", "d.db", "p.db"))
MetricsStore(mdb).close()
with open(sfile, "w") as fh:
    json.dump({"devices": {"R1": {"facts": {"wan_links": ["Fibre", "LTE backup"]}, "conditions": {
        "reachability": {"status": "ok"},
        "wan_link:1": {"status": "problem", "title": "Backup WAN uplink \"LTE backup\" is DOWN"}}}}}, fh)
a = AuthStore(adb)
org = a.signup("owner@alpha.test", "a-password-for-the-test", "Alpha")
a.signup("owner@beta.test", "a-password-for-the-test", "Beta")
a.close()
ds = DevicesStore(ddb)
ds.upsert({"name": "R1", "host": "10.10.3.7", "username": "mkm-1", "password": "k7Vq2pXw9tLm",
           "wan": {"links": [{"name": "Fibre", "interface": "ether1"},
                             {"name": "LTE backup", "interface": "pppoe-out1"}]}},
          DEFAULT_THRESHOLDS, org_id=org)
ds.close()
router = Router()


class _Dev:
    def close(self):
        pass

    def reachable(self, timeout=None, attempts=None):
        return True


class _Api:
    def __init__(self, dev):
        pass

    def connect(self):
        return self

    def close(self):
        pass

    def fetch(self, path):
        return router.fetch(path) if path in router.t else []

    def ping_rows(self, **p):
        return router.ping_rows(**p)

    def execute(self, op):
        return router.execute(op)


push_pkg.rw_device = lambda cfg: _Dev()
push_api.PushApi = _Api
srv = GuardedHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, AuthStore(adb), web.SessionManager(), secure_cookies=False,
    devices_db=ddb, defaults=dict(DEFAULT_THRESHOLDS), push_log_db=pdb, admin_2fa=False))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()


def login(email):
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    op.open(urllib.request.Request(BASE + "/login", data=urllib.parse.urlencode(
        {"email": email, "password": "a-password-for-the-test"}).encode()), timeout=30)
    return op


def req(op, path, data=None):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    try:
        rr = op.open(urllib.request.Request(BASE + path, data=body), timeout=30)
        return rr.status, rr.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


owner = login("owner@alpha.test")
st, page = req(owner, "/device?name=R1&tab=wan")
csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
check("the WAN tab has a 'Test this line' button per line",
      st == 200 and page.count("Test this line") >= 2 and 'id="wan-test"' in page, st)
st, page = req(owner, "/device?name=R1")
check("the overview offers the test next to an offline line", "#wan-test" in page and "Test it" in page)
router.t[("ip", "route")] = [x for x in router.t[("ip", "route")] if x["gateway"] != "pppoe-out1"]
st, page = req(owner, "/device/wan-test", {"csrf": csrf, "device": "R1", "link": "1"})
check("testing the offline backup shows it answering and what is wrong",
      st == 200 and "LTE backup" in page and "3 answered" in page
      and "no internet route through LTE backup" in page, st)
st, _ = req(owner, "/device/wan-test", {"csrf": "wrong", "device": "R1", "link": "1"})
check("a request without the page's token is refused", st in (400, 403), st)
for bad in ("9", "abc", "-1", ""):
    st, _ = req(owner, "/device/wan-test", {"csrf": csrf, "device": "R1", "link": bad})
    check(f"a line that is not in the list ({bad!r}) is refused", st == 400, st)
other = login("owner@beta.test")
_, page = req(other, "/dashboard")
csrf_b = re.search(r'name="csrf" value="([^"]+)"', page)
st, _ = req(other, "/device/wan-test", {"csrf": csrf_b.group(1) if csrf_b else "",
                                        "device": "R1", "link": "0"})
check("another company cannot test this company's router", st == 403, st)
srv.shutdown()

print("FAILED: " + ", ".join(FAILS) if FAILS else "ALL LINE TEST TESTS PASSED")
sys.exit(1 if FAILS else 0)
