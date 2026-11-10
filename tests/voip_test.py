"""VoIP priority on the Queues tab: calls first on a router's upload.

Checked against a fake router that answers the way librouteros does (yes/no
as True/False, numbers as ints):
  * what goes on the router, in what order, with rates in bits
  * a PPPoE line is shaped on pppoe-out1, never on the port under it
  * applying the same settings twice sends nothing; a change sends only
    the fields that changed
  * FastTrack and the SIP helper: only what this switched off is switched
    back on, even when a FastTrack rule's id has changed
  * every refusal sends nothing
  * rollback puts rows back with fields RouterOS accepts
  * the warnings that say why calls might not get priority
  * the Queues tab, preview and apply, end to end through the dashboard

Run:  ./.venv/bin/python tests/voip_test.py
"""
from __future__ import annotations

import http.cookiejar
import itertools
import json
import os
import re
import sys
import tempfile
import threading
import types
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mikromon.push as push_pkg  # noqa: E402
from mikromon import guide_tabs, web  # noqa: E402
from mikromon.auth import AuthStore  # noqa: E402
from mikromon.config import DEFAULT_THRESHOLDS, WanEndpoint  # noqa: E402
from mikromon.devices_store import DevicesStore  # noqa: E402
from mikromon.metrics import MetricsStore  # noqa: E402
from mikromon.push import Pusher  # noqa: E402
from mikromon.push import voip as vp  # noqa: E402
from mikromon.push.api import PlanRefused, PushError  # noqa: E402
from mikromon.util import mbps_text, mbps_to_bps, rate_bps  # noqa: E402

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


def _ros(v):
    """A stored value as librouteros hands it back."""
    if isinstance(v, str):
        if v.lower() in ("yes", "true"):
            return True
        if v.lower() in ("no", "false"):
            return False
        if v.isdigit():
            return int(v)
    return v


class FakeApi:
    """A router's tables in memory; executes ops and records them."""

    def __init__(self, state):
        self.state = state
        self.executed = []
        self.fail_desc = None
        self._n = 100

    def fetch(self, path):
        return [{k: _ros(v) for k, v in r.items()}
                for r in self.state.get(tuple(path), [])]

    def execute(self, op):
        if self.fail_desc and op.desc == self.fail_desc:
            raise PushError("simulated failure: " + op.desc)
        self.executed.append(op)
        rows = self.state.setdefault(tuple(op.path), [])
        if op.action == "add":
            self._n += 1
            row = {k: v for k, v in op.params.items() if k != "place-before"}
            row[".id"] = f"*{self._n}"
            before = op.params.get("place-before")
            idx = next((i for i, r in enumerate(rows)
                        if r.get(".id") == before), len(rows))
            rows.insert(idx, row)
            return row[".id"]
        if op.action == "remove":
            self.state[tuple(op.path)] = [r for r in rows
                                          if r.get(".id") != op.params[".id"]]
            return None
        if op.action == "set":
            for r in rows:
                if r.get(".id") == op.params.get(".id"):
                    r.update({k: v for k, v in op.params.items() if k != ".id"})
            return None
        raise PushError("unknown action " + op.action)


def router(version="7.16 (stable)", cpu=12, board="hEX"):
    return {
        ("system", "resource"): [{"version": version, "cpu-load": cpu,
                                  "board-name": board}],
        ("interface",): [{"name": n} for n in
                         ("ether1", "ether2", "bridge", "pppoe-out1",
                          "mikromon")],
        ("interface", "pppoe-client"): [
            {".id": "*P1", "name": "pppoe-out1", "interface": "ether1",
             "running": True}],
        ("ip", "firewall", "filter"): [
            {".id": "*0", "chain": "forward", "action": "passthrough",
             "dynamic": True,
             "comment": "special dummy rule to show fasttrack counters"},
            {".id": "*5", "chain": "forward", "action": "fasttrack-connection",
             "connection-state": "established,related", "hw-offload": True,
             "disabled": False, "comment": "defconf: fasttrack"},
            {".id": "*6", "chain": "forward", "action": "fasttrack-connection",
             "disabled": True, "comment": "switched off by the owner"},
            {".id": "*7", "chain": "forward", "action": "accept",
             "connection-state": "established,related"}],
        ("ip", "firewall", "mangle"): [],
        ("queue", "tree"): [],
        ("queue", "simple"): [],
        ("ip", "firewall", "service-port"): [
            {".id": "*S1", "name": "sip", "ports": "5060,5061",
             "disabled": False}],
        ("ip", "route"): [{"dst-address": "0.0.0.0/0", "gateway": "pppoe-out1",
                           "active": True, "routing-table": "main"}],
    }


cfg = types.SimpleNamespace(
    name="R1", push_username="", push_password="",
    wan=types.SimpleNamespace(links=[WanEndpoint(interface="ether1",
                                                 name="Vodacom")]))
ON = {"voip_on": "on", "voip_up": "18", "voip_guar": "5",
      "voip_rtp": "asterisk", "voip_sip": "5060,5061", "voip_dscp": "1",
      "voip_alg": "1"}


def plan_for(api, **over):
    return vp.plan(Pusher(cfg, api, dry_run=True), cfg, {**ON, **over}, {})


def apply(api, **over):
    p = Pusher(cfg, api, dry_run=False)
    pl = vp.plan(p, cfg, {**ON, **over}, {})
    p.apply(pl)
    return pl


def ops_on(pl, path):
    return [o for o in pl.ops if o.path == path]


def owned(api, path):
    return [r for r in api.state.get(path, [])
            if str(r.get("comment", "")).startswith(vp.TAG)]


TREE, MANGLE, FILTER = vp._TREE, vp._MANGLE, vp._FILTER
SVC = vp._SERVICE_PORT

print("units")
check("rates read the router's bits and a person's 18M alike",
      rate_bps(18000000) == rate_bps("18000000") == rate_bps("18M")
      == 18_000_000 and rate_bps("512k") == 512_000 and rate_bps(True) == -1)
check("...and a form shows plain Mbps",
      mbps_text(18_000_000) == "18" and mbps_text(500_000) == "0.5"
      and mbps_text(-1) == "" and mbps_to_bps("0.5") == 500_000
      and mbps_to_bps("abc") == -1)

print("\nswitching it on, on a PPPoE line")
api = FakeApi(router())
pl = plan_for(api)
tree = ops_on(pl, TREE)
check("three queues, the parent on pppoe-out1 -- not ether1, which only "
      "carries PPPoE frames -- with no voip_iface given",
      [o.params["name"] for o in tree]
      == [vp.Q_PARENT, vp.Q_VOICE, vp.Q_OTHER]
      and tree[0].params["parent"] == "pppoe-out1")
check("rates go in bits: 18 Mbps upload, 5 kept for calls, 1.8 for the rest",
      tree[0].params["max-limit"] == "18000000"
      and tree[1].params["limit-at"] == "5000000"
      and tree[2].params["limit-at"] == "1800000"
      and not any("M" in str(o.params.get("max-limit", "")) for o in tree))
mg = [o for o in ops_on(pl, MANGLE) if o.action == "add"]
keys = [o.params["comment"][len(vp.TAG):] for o in mg
        if o.params["comment"].startswith(vp.TAG)]
check("call rules: SIP UDP and TCP, the voice ports, DSCP 46, then the "
      "packet label last", keys == ["sip-udp", "sip-tcp", "rtp", "dscp", "pkt"])
check("...appended, never put in front of somebody's own rules",
      not any("place-before" in o.params for o in mg))
check("...and the packet label lets later rules (the WAN tab's) see the "
      "packet", next(o for o in mg if o.params["comment"].endswith(":pkt"))
      .params["passthrough"] == "yes")
idx = {id(o): i for i, o in enumerate(pl.ops)}
marker = next(o for o in mg if o.params["comment"].startswith(vp.STATE_TAG))
ft = ops_on(pl, FILTER)
check("the record of what changes goes in before FastTrack is touched",
      ft and idx[id(marker)] < idx[id(ft[0])]
      and marker.params["disabled"] == "yes"
      and "*5/" in marker.params["comment"]
      and marker.params["comment"].endswith("alg=1"))
check("only the FastTrack rule that is on is switched off -- not the owner's "
      "switched-off one, not the dynamic counter",
      [(o.params[".id"], o.params["disabled"]) for o in ft] == [("*5", "yes")])
check("the SIP helper is switched off as asked",
      [(o.params[".id"], o.params["disabled"]) for o in ops_on(pl, SVC)]
      == [("*S1", "yes")])
check("every undo of an add is a remove", all(
    o.inverse and o.inverse.action == "remove" for o in pl.ops
    if o.action == "add"))

print("\napplying, then applying again")
apply(api)
check("on the router: 3 queues, 5 call rules, the record, FastTrack off",
      len(owned(api, TREE)) == 3 and len(owned(api, MANGLE)) == 5
      and any(str(r.get("comment", "")).startswith(vp.STATE_TAG)
              for r in api.state[MANGLE])
      and next(r for r in api.state[FILTER] if r[".id"] == "*5")["disabled"]
      == "yes")
check("the same settings again send nothing", plan_for(api).empty)
cur = vp.read(Pusher(cfg, api), cfg)
f = {d["name"]: d for d in vp.form(cur, cfg)}
check("the form reads back what was set, in Mbps",
      f["voip_iface"]["value"] == "pppoe-out1" and f["voip_up"]["value"] == "18"
      and f["voip_guar"]["value"] == "5" and f["voip_rtp"]["value"] == "asterisk"
      and f["voip_sip"]["value"] == "5060,5061" and f["voip_dscp"]["on"]
      and f["voip_alg"]["on"])
lines = vp.summary(cur, cfg)
check("the summary says it is on, where, and how fast",
      lines[0].startswith("On: calls on pppoe-out1 go first")
      and "18 Mbps" in lines[0] and "Downloads are not changed" in lines[0])

print("\nchanging settings")
pl = plan_for(api, voip_up="20")
check("a new upload speed only sets the limits that changed",
      all(o.action == "set" and o.path == TREE for o in pl.ops)
      and len(pl.ops) == 3
      and all(set(o.params) <= {".id", "max-limit", "limit-at"} for o in pl.ops))
check("...and each undo holds the old values and the id only",
      all(set(o.inverse.params) == set(o.params) for o in pl.ops)
      and any(rate_bps(o.inverse.params.get("max-limit")) == 18_000_000
              for o in pl.ops))
pl = plan_for(api, voip_rtp="3cx")
check("3CX's voice ports are one change to one rule",
      len(pl.ops) == 1 and pl.ops[0].params.get("dst-port") == "9000-10999")
# what RouterOS adds to a rule once it has counted traffic
for r in api.state[MANGLE]:
    r.update({"bytes": "123456", "packets": "789", "invalid": "false",
              "dynamic": "false"})
pl = plan_for(api, voip_dscp="")
rm = [o for o in pl.ops if o.action == "remove"]
check("unticking DSCP removes that one rule, and its undo carries only "
      "fields RouterOS accepts",
      len(rm) == 1 and set(rm[0].inverse.params) <= set(vp._MANGLE_FIELDS)
      and "bytes" not in rm[0].inverse.params)
apply(api, voip_dscp="")
pl = plan_for(api)
add = [o for o in pl.ops if o.action == "add"]
pkt_id = next(r[".id"] for r in api.state[MANGLE]
              if r.get("comment") == vp.TAG + "pkt")
check("ticking it again puts the rule in front of the packet label, so a new "
      "call's first packet is labelled too",
      len(add) == 1 and add[0].params.get("place-before") == pkt_id)
apply(api)

print("\nFastTrack switched back on by hand, or a new one added")
next(r for r in api.state[FILTER] if r[".id"] == "*5")["disabled"] = "no"
cur = vp.read(Pusher(cfg, api), cfg)
check("the summary says calls are skipping the queues again",
      any("FastTrack rule is switched on again" in ln
          for ln in vp.summary(cur, cfg)))
pl = plan_for(api)
check("applying again switches it off again, and nothing else",
      [(o.path, o.params) for o in pl.ops]
      == [(FILTER, {".id": "*5", "disabled": "yes"})])
apply(api)
api.state[FILTER].append({".id": "*8", "chain": "forward",
                          "action": "fasttrack-connection", "disabled": "no",
                          "comment": "added later"})
pl = plan_for(api)
check("a new FastTrack rule is switched off and added to the record",
      any(o.path == FILTER and o.params == {".id": "*8", "disabled": "yes"}
          for o in pl.ops)
      and any(o.action == "set" and "*8/" in o.params.get("comment", "")
              and "*5/" in o.params.get("comment", "") for o in pl.ops))
apply(api)

print("\nswitching it off")
api.state[MANGLE].append({".id": "*90", "chain": "prerouting",
                          "action": "accept", "comment": "owner's rule"})
pl = vp.plan(Pusher(cfg, api, dry_run=True), cfg, {"voip_on": "off"}, {})
on_again = [o.params[".id"] for o in pl.ops
            if o.path == FILTER and o.params.get("disabled") == "no"]
check("FastTrack rules this switched off come back on; the owner's own "
      "switched-off one stays off", sorted(on_again) == ["*5", "*8"])
check("the SIP helper comes back on",
      any(o.path == SVC and o.params == {".id": "*S1", "disabled": "no"}
          for o in pl.ops))
order = [o.params.get(".id") for o in pl.ops if o.action == "remove"]
names = {r[".id"]: (r.get("comment") or "") for r in
         api.state[MANGLE] + api.state[TREE]}
seq = [names[i][len(vp.TAG):] if names[i].startswith(vp.TAG) else names[i]
       for i in order]
check("the packet label goes before the rules that feed it, the children "
      "before their parent, the record last",
      seq.index("pkt") < seq.index("sip-udp")
      and seq.index("q-voice") < seq.index("q-parent")
      and seq[-1].startswith(vp.STATE_TAG))
check("somebody's own rule is not touched",
      "*90" not in order and "*6" not in on_again)
p = Pusher(cfg, api, dry_run=False)
p.apply(pl)
check("afterwards nothing of it is left, and FastTrack is back as it was",
      not owned(api, TREE) and not owned(api, MANGLE)
      and not any(str(r.get("comment", "")).startswith(vp.STATE_TAG)
                  for r in api.state[MANGLE])
      and {r[".id"]: r["disabled"] for r in api.state[FILTER]
           if r["action"] == "fasttrack-connection"}
      == {"*5": "no", "*6": True, "*8": "no"})

print("\na FastTrack rule whose id changed while it was on")
api = FakeApi(router())
apply(api)
rule = next(r for r in api.state[FILTER] if r[".id"] == "*5")
rule[".id"] = "*15"
api.state[FILTER].append({".id": "*16", "chain": "forward",
                          "action": "fasttrack-connection", "disabled": "yes",
                          "comment": "a different rule"})
pl = vp.plan(Pusher(cfg, api, dry_run=True), cfg, {"voip_on": "off"}, {})
check("it is found by what it matches and switched back on -- a different "
      "switched-off rule is left alone",
      [o.params[".id"] for o in pl.ops
       if o.path == FILTER and o.params.get("disabled") == "no"] == ["*15"])

print("\nthe SIP helper already off")
st = router()
st[SVC][0]["disabled"] = True
api = FakeApi(st)
pl = plan_for(api)
check("nothing is sent for it, and it is not recorded as ours",
      not ops_on(pl, SVC) and any(
          o.params.get("comment", "").endswith("alg=0") for o in pl.ops))
apply(api)
pl = vp.plan(Pusher(cfg, api, dry_run=True), cfg, {"voip_on": "off"}, {})
check("...so switching off does not turn it on", not ops_on(pl, SVC))

print("\nrefusals send nothing")


def refused(state=None, **over):
    a = FakeApi(state or router())
    try:
        plan_for(a, **over)
        return ""
    except PlanRefused as exc:
        return str(exc) if not a.executed else "EXECUTED"


def with_rows(path, rows):
    st = router()
    st[path] = rows
    return st


cases = [
    ("RouterOS 6", refused(router(version="6.49.8")), "7.1"),
    ("an interface the router does not have", refused(voip_iface="ether9"),
     "no interface called ether9"),
    ("the management tunnel", refused(voip_iface="mikromon"), "VPN tunnel"),
    ("the port under a PPPoE line", refused(voip_iface="ether1"),
     "choose pppoe-out1"),
    ("too much kept for calls", refused(voip_guar="17"), "at most 16.2"),
    ("a backwards voice range",
     refused(voip_rtp="custom", voip_rtp_custom="20000-10000"), "Voice ports"),
    ("16 SIP ports", refused(voip_sip=",".join(str(5060 + i)
                                               for i in range(16))),
     "up to 15"),
    ("a hand-made queue tree on the line",
     refused(with_rows(TREE, [{".id": "*T1", "name": "up", "parent":
                               "pppoe-out1", "disabled": False}])),
     "set up by hand"),
    ("the VoIP script already run by hand",
     refused(with_rows(MANGLE, [{".id": "*M1", "chain": "prerouting",
                                 "action": "mark-connection",
                                 "new-connection-mark": "voip-conn"}])),
     "run by hand"),
    ("a queue of somebody else's with our name",
     refused(with_rows(vp._SIMPLE, [{".id": "*Q1", "name": "mm-voip-upload",
                                     "max-limit": "1M/1M"}])),
     "not the dashboard's"),
    ("a form without voip_on", refused(voip_on=""), "on or off"),
]
for what, got, needle in cases:
    check(f"refused: {what}",
          got.startswith("Nothing was sent to the router.") and needle in got)

print("\na failure halfway rolls back cleanly")
api = FakeApi(router())
api.fail_desc = next(o.desc for o in plan_for(api).ops if o.path == FILTER)
try:
    Pusher(cfg, api, dry_run=False).apply(plan_for(api))
    raised = False
except PushError:
    raised = True
check("the apply reports the failure, and leaves none of its rows behind",
      raised and not owned(api, TREE) and not owned(api, MANGLE)
      and not any(str(r.get("comment", "")).startswith(vp.STATE_TAG)
                  for r in api.state[MANGLE]))
api = FakeApi(router())
apply(api)
for r in api.state[MANGLE] + api.state[TREE]:
    r.update({"bytes": "1", "packets": "1", "rate": "0", "invalid": "false",
              "dynamic": "false"})
off = vp.plan(Pusher(cfg, api, dry_run=True), cfg, {"voip_on": "off"}, {})
api.fail_desc = off.ops[-1].desc            # the record, last
try:
    Pusher(cfg, api, dry_run=False).apply(off)
except PushError:
    pass
readds = [o for o in api.executed if o.action == "add"]
check("switching off that fails at the end puts every row back, with only "
      "fields RouterOS accepts",
      len(owned(api, TREE)) == 3 and len(owned(api, MANGLE)) == 5
      and readds and all(not ({"bytes", "packets", "rate", "invalid",
                               "dynamic"} & set(o.params)) for o in readds))

print("\nwhat can keep calls from getting priority")
st = router(cpu=90)
st[MANGLE] = [
    {".id": "*A", "chain": "prerouting", "action": "mark-connection",
     "new-connection-mark": "lb", "comment": "load balancing"},
    {".id": "*B", "chain": "prerouting", "action": "mark-packet",
     "new-packet-mark": "pm1"},
    {".id": "*C", "chain": "prerouting", "action": "mark-routing",
     "src-address": "192.168.10.0/24",
     "comment": "mikromon:sdwan:pol:192.168.10.0/24|ether2"}]
st[vp._SIMPLE] = [{".id": "*Q", "name": "office", "target": "192.168.88.0/24",
                   "max-limit": "10000000/50000000", "disabled": False}]
two = types.SimpleNamespace(name="R1", wan=types.SimpleNamespace(links=[
    WanEndpoint(interface="ether1", name="Vodacom"),
    WanEndpoint(interface="ether2", name="LTE")]))
api = FakeApi(st)
p = Pusher(two, api, dry_run=False)
p.apply(vp.plan(p, two, dict(ON), {}))
check("with the WAN tab's rule there, ours still go at the end",
      not any("place-before" in o.params for o in api.executed
              if o.action == "add")
      and api.state[MANGLE][2]["comment"].startswith("mikromon:sdwan:pol:"))
text = "\n".join(vp.summary(vp.read(Pusher(two, api), two), two))
for what, needle in (("the backup line is not shaped", "while the router uses ether2"),
                     ("the WAN tab's other line", "out through ether2"),
                     ("the router's own connection marks", "connection-marking rules"),
                     ("the router's own packet marks", "pm1"),
                     ("a speed limit phones would wait in", "office"),
                     ("a busy processor", "90%")):
    check(f"warned: {what}", needle in text)

print("\nPPPoE that is switched off, or carried over a VLAN")
st = router()
st[("interface", "pppoe-client")][0]["disabled"] = True
st[("ip", "dhcp-client")] = [{"interface": "ether1", "status": "bound"}]
st[("ip", "route")] = [{"dst-address": "0.0.0.0/0", "gateway": "100.64.0.1",
                        "gateway-status": "100.64.0.1 reachable via  ether1",
                        "active": True, "routing-table": "main"}]
api = FakeApi(st)
check("a switched-off PPPoE connection left from an old line does not take "
      "the line over: ether1, which has the internet, is the default",
      vp.read(Pusher(cfg, api), cfg)["default_iface"] == "ether1")
check("...and ether1 can be chosen",
      ops_on(plan_for(api, voip_iface="ether1"), TREE)[0].params["parent"]
      == "ether1")
st = router()
st[("interface", "pppoe-client")][0]["interface"] = "vlan10"
st[("interface", "vlan")] = [{"name": "vlan10", "interface": "ether1",
                              "vlan-id": 10}]
st[("interface",)].append({"name": "vlan10"})
check("PPPoE over a VLAN on ether1: the line is pppoe-out1",
      vp.read(Pusher(cfg, FakeApi(st)), cfg)["default_iface"] == "pppoe-out1")
check("...and the port under the VLAN is refused",
      "choose pppoe-out1" in refused(st, voip_iface="ether1"))

print("\nsmaller things")
pl = plan_for(FakeApi(router()), voip_sip="5060, 5061,")
check("a stray comma in the SIP ports is not sent to the router",
      next(o for o in pl.ops if o.params.get("comment") == vp.TAG + "sip-udp")
      .params["dst-port"] == "5060,5061")
st = router()
st[MANGLE] = [
    {".id": "*C", "chain": "prerouting", "action": "mark-routing",
     "comment": "mikromon:sdwan:pol:192.168.10.0/24|ether1"},
    {".id": "*D", "chain": "prerouting", "action": "mark-routing",
     "comment": "mikromon:sdwan:pol:192.168.20.0/24|100.64.0.1"}]
api = FakeApi(st)
apply(api)
check("a WAN-tab rule naming the port under the shaped PPPoE line, or a "
      "gateway address, is not reported as another line",
      "WAN tab" not in "\n".join(vp.summary(vp.read(Pusher(cfg, api), cfg),
                                            cfg)))

api = FakeApi(router())
api.fail_desc = next(o.desc for o in plan_for(api).ops if o.path == SVC)
try:
    Pusher(cfg, api, dry_run=False).apply(plan_for(api))
except PushError:
    pass
check("a failure after FastTrack was switched off turns it back on, and "
      "leaves nothing of this behind",
      next(r for r in api.state[FILTER] if r[".id"] == "*5")["disabled"]
      == "no" and not owned(api, TREE) and not owned(api, MANGLE)
      and not any(str(r.get("comment", "")).startswith(vp.STATE_TAG)
                  for r in api.state[MANGLE]))

api = FakeApi(router())
apply(api)
pl = plan_for(api, voip_alg="")
check("unticking the SIP helper turns it back on, with the record updated "
      "first", len(pl.ops) == 2 and pl.ops[0].path == MANGLE
      and pl.ops[0].params["comment"].endswith("alg=0")
      and pl.ops[1].path == SVC
      and pl.ops[1].params == {".id": "*S1", "disabled": "no"})

print("\nthe record deleted by hand")
api = FakeApi(router())
apply(api)
api.state[MANGLE] = [r for r in api.state[MANGLE] if not str(
    r.get("comment", "")).startswith(vp.STATE_TAG)]
off = vp.plan(Pusher(cfg, api, dry_run=True), cfg, {"voip_on": "off"}, {})
check("switching off without the record never touches FastTrack",
      not ops_on(off, FILTER) and len(owned(api, MANGLE)) == 5)
check("the box says the record is missing",
      any("went missing" in ln for ln in vp.summary(
          vp.read(Pusher(cfg, api), cfg), cfg)))
apply(api)
rec = next(r for r in api.state[MANGLE]
           if str(r.get("comment", "")).startswith(vp.STATE_TAG))
check("...and still says so after applying again: a fresh, empty record "
      "would have forgotten what was switched off",
      rec["comment"].endswith("lost=1") and any(
          "went missing" in ln for ln in vp.summary(
              vp.read(Pusher(cfg, api), cfg), cfg)))

# ---- through the dashboard ----------------------------------------------------
print("\nthe Queues tab, end to end")


class FakePath:
    def __init__(self, r, segs):
        self.r, self.segs = r, segs

    def __iter__(self):
        return iter([{k: _ros(v) for k, v in x.items()}
                     for x in self.r.tables.setdefault(self.segs, [])])

    def add(self, **params):
        nid = f"*{next(self.r.ids)}"
        self.r.tables.setdefault(self.segs, []).append(
            {".id": nid, **{k: str(v) for k, v in params.items()
                            if k != "place-before"}})
        self.r.log.append(("add", self.segs, dict(params)))
        return nid

    def update(self, **params):
        for x in self.r.tables.setdefault(self.segs, []):
            if x.get(".id") == params.get(".id"):
                x.update({k: str(v) for k, v in params.items() if k != ".id"})
        self.r.log.append(("set", self.segs, dict(params)))

    def remove(self, rid):
        rows = self.r.tables.setdefault(self.segs, [])
        self.r.tables[self.segs] = [x for x in rows if x.get(".id") != rid]
        self.r.log.append(("remove", self.segs, rid))

    def __call__(self, cmd, **params):
        self.r.log.append(("run", self.segs, cmd))
        return iter([{"ret": "ok"}])


class FakeRouter:
    def __init__(self):
        self.ids = itertools.count(200)
        self.log = []
        self.tables = {tuple(k): [dict(r) for r in v]
                       for k, v in router().items()}
        self.tables[("system", "scheduler")] = []


class FakeDevice:
    def __init__(self, r):
        self.router, self.api = r, None

    def reachable(self, timeout=None, attempts=None):
        return True

    def connect(self):
        self.api = types.SimpleNamespace(path=lambda *s: FakePath(self.router, s))
        return self.api

    def ping(self, address, count=2):
        return 0

    def close(self):
        pass


ROUTER = FakeRouter()
push_pkg.rw_device = lambda c: FakeDevice(ROUTER)
tmp = tempfile.mkdtemp()
mdb, sfile, adb, ddb = (os.path.join(tmp, x) for x in
                        ("m.db", "s.json", "a.db", "d.db"))
MetricsStore(mdb).close()
with open(sfile, "w") as fh:
    json.dump({"devices": {}}, fh)
a = AuthStore(adb)
org = a.signup("owner@alpha.test", "a-password-for-the-test", "Alpha")
a.close()
ds = DevicesStore(ddb)
ds.upsert({"name": "R1", "host": "10.10.3.7", "username": "u", "password": "p",
           "wan": {"links": [{"name": "Vodacom", "interface": "ether1"}]}},
          DEFAULT_THRESHOLDS, org_id=org)
ds.close()
srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, AuthStore(adb), web.SessionManager(), secure_cookies=False,
    devices_db=ddb, defaults=dict(DEFAULT_THRESHOLDS), admin_2fa=False))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()
op = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def req(path, data=None):
    body = urllib.parse.urlencode(data, doseq=True).encode() if data else None
    try:
        r = op.open(urllib.request.Request(BASE + path, data=body), timeout=30)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


try:
    req("/login", {"email": "owner@alpha.test",
                   "password": "a-password-for-the-test"})
    st, page = req("/device?name=R1&tab=qos")
    tok = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    box = page[page.index('id="voip"'):]
    box = box[:box.index("Queue Setup Builder")]
    check("the Queues tab has a VoIP priority box that says it is off",
          st == 200 and "Calls share the upload" in box
          and "Preview switching it on" in box)
    check("...posting to the voip feature, shown back on the Queues tab",
          'name="feature" value="voip"' in box and 'name="view" value="qos"' in box
          and 'name="voip_on" value="on"' in box
          and 'href="/guide#tab-voip"' in box)
    check("...and it is not a switch that applies itself",
          "data-mm-instant-form" not in box)
    check("...offering pppoe-out1 as the line", re.search(
        r'<option value="pppoe-out1" selected>', box) is not None)

    form = {"csrf": tok, "device": "R1", "feature": "voip", "view": "qos",
            **ON}
    before = len(ROUTER.log)
    st, prev = req("/device/push", form)
    check("Preview shows the change on the Queues tab and sends nothing",
          st == 200 and "Dry run" in prev and "pppoe-out1" in prev
          and len([e for e in ROUTER.log[before:] if e[0] != "run"]) == 0)
    apply_form = re.search(r'<form method="POST" action="/device/push">'
                           r'(?:(?!</form>).)*name="apply"(?:(?!</form>).)*'
                           r'</form>', prev, re.S).group(0)
    check("...whose Apply still names the voip feature and the Queues tab",
          'name="feature" value="voip"' in apply_form
          and 'name="view" value="qos"' in apply_form)

    st, done = req("/device/push", {**form, "apply": "1", "safe_revert": "1"})
    log = ROUTER.log[before:]
    i_backup = next(i for i, e in enumerate(log)
                    if e[0] == "run" and e[1] == ("system", "backup"))
    i_queue = next(i for i, e in enumerate(log)
                   if e[0] == "add" and e[1] == ("queue", "tree"))
    check("applied: a backup first, then the queues",
          st == 200 and i_backup < i_queue)
    check("...the router has the queues and FastTrack is off",
          len([r for r in ROUTER.tables[("queue", "tree")]
               if str(r.get("comment", "")).startswith(vp.TAG)]) == 3
          and next(r for r in ROUTER.tables[("ip", "firewall", "filter")]
                   if r[".id"] == "*5")["disabled"] in ("yes", "True"))
    check("...and the management tunnel was not touched",
          not any(e[1][:1] == ("interface",) for e in log
                  if e[0] in ("add", "set", "remove")))
    st, page = req("/device?name=R1&tab=qos")
    check("the tab now says it is on, with a way to switch it off",
          "On: calls on pppoe-out1 go first" in page
          and "Preview switching it off" in page)

    real_read = vp.read
    vp.read = lambda *a, **k: (_ for _ in ()).throw(PushError("read failed"))
    try:
        st, page = req("/device?name=R1&tab=qos")
    finally:
        vp.read = real_read
    check("a router the VoIP box cannot read still gets the rest of the tab",
          st == 200 and "Could not read VoIP priority" in page
          and "Queue Setup Builder" in page)
finally:
    srv.shutdown()

print("\nthe guide")
check("the box's ? lands on a section of the guide",
      "voip" in guide_tabs.BY_SLUG
      and guide_tabs.BY_SLUG["voip"]["steps"])

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL VOIP TESTS PASSED")
