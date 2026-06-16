"""Tests for the config-push (read-write) engine — all offline via a fake API.

Covers the parts that would be dangerous if wrong: the idempotent diff, the
dry-run preview, ownership scoping (never touch hand-made rules), and automatic
rollback when an apply fails partway through.

Run:  ./.venv/Scripts/python.exe tests/push_test.py
"""
from __future__ import annotations

import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon.push import Pusher, reconcile_list
from mikromon.push.api import PushError

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


class FakeApi:
    """Records executed ops and mutates an in-memory router state."""

    def __init__(self, state=None):
        self.state = state or {}
        self.executed = []
        self.fail_desc = None
        self._n = 0

    def fetch(self, path):
        return [dict(r) for r in self.state.get(tuple(path), [])]

    def execute(self, op):
        if self.fail_desc and op.desc == self.fail_desc:
            raise PushError("simulated failure: " + op.desc)
        self.executed.append(op)
        rows = self.state.setdefault(tuple(op.path), [])
        if op.action == "add":
            self._n += 1
            nid = f"*{self._n}"
            row = dict(op.params)
            row[".id"] = nid
            rows.append(row)
            return nid
        if op.action == "remove":
            self.state[tuple(op.path)] = [
                r for r in rows if r.get(".id") != op.params[".id"]]
            return None
        if op.action == "set":
            for r in rows:
                if r.get(".id") == op.params.get(".id"):
                    r.update({k: v for k, v in op.params.items() if k != ".id"})
            return None
        if op.action == "run":
            return [{"ran": dict(op.params)}]
        raise PushError("unknown action")


PATH = ("ip", "firewall", "address-list")
TAG = "mikromon:blocklist"
cfg = types.SimpleNamespace(name="R1", push_username="", push_password="")


# ---- 1. reconcile: add / set / remove, with ownership scoping --------------
print("reconcile_list:")
current = [
    {".id": "*1", "address": "1.1.1.1", "list": "block", "comment": TAG},   # owned, keep
    {".id": "*2", "address": "9.9.9.9", "list": "block", "comment": TAG},   # owned, stale
    {".id": "*3", "address": "8.8.8.8", "list": "block", "comment": "manual"},  # not ours
]
desired = [
    {"address": "1.1.1.1", "list": "block"},   # unchanged
    {"address": "2.2.2.2", "list": "block"},   # new
]
ops = reconcile_list(PATH, "address", desired, current, manage_tag=TAG,
                     label="entry")
kinds = sorted((o.action, o.params.get("address", o.params.get(".id")))
               for o in ops)
check("adds the new address", ("add", "2.2.2.2") in
      [(o.action, o.params.get("address")) for o in ops])
check("removes the stale owned row (*2)",
      any(o.action == "remove" and o.params.get(".id") == "*2" for o in ops))
check("leaves the unchanged owned row alone",
      not any(o.params.get("address") == "1.1.1.1" for o in ops))
check("never touches the hand-made row (8.8.8.8 / *3)",
      not any(o.params.get(".id") == "*3" or o.params.get("address") == "8.8.8.8"
              for o in ops))
add_op = next(o for o in ops if o.action == "add")
check("new add carries the manage tag", add_op.params.get("comment") == TAG)
check("add has a remove inverse", add_op.inverse.action == "remove")
rm_op = next(o for o in ops if o.action == "remove")
check("remove has an add inverse that restores the row",
      rm_op.inverse.action == "add" and
      rm_op.inverse.params.get("address") == "9.9.9.9")

# a 'set' when a field changes
ops2 = reconcile_list(PATH, "address",
                      [{"address": "1.1.1.1", "list": "drop"}],
                      [current[0]], manage_tag=TAG)
check("changed field produces a set", len(ops2) == 1 and ops2[0].action == "set")
check("set inverse restores the old value",
      ops2[0].inverse.params.get("list") == "block")


# ---- 2. dry-run preview does not execute anything --------------------------
print("dry-run preview:")
api = FakeApi({PATH: list(current)})
p = Pusher(cfg, api, dry_run=True)
plan = p.plan_managed_list(PATH, "address", desired, manage_tag=TAG,
                           label="entry")
res = p.apply(plan)
check("dry-run reports it is a dry-run", res.get("dry_run") is True)
check("dry-run executed nothing", api.executed == [])
check("diff text lists changes", "change(s)" in res["diff"])


# ---- 3. apply for real converges the state ---------------------------------
print("apply (commit):")
api = FakeApi({PATH: [dict(r) for r in current]})
p = Pusher(cfg, api, dry_run=False)
plan = p.plan_managed_list(PATH, "address", desired, manage_tag=TAG,
                           label="entry")
res = p.apply(plan)
addrs = sorted(r["address"] for r in api.state[PATH])
check("apply executed ops", res.get("applied", 0) >= 2)
check("state converged to desired + manual",
      addrs == ["1.1.1.1", "2.2.2.2", "8.8.8.8"])


# ---- 4. rollback when a later op fails -------------------------------------
print("rollback on failure:")
start = [{".id": "*3", "address": "8.8.8.8", "list": "block", "comment": "manual"}]
api = FakeApi({PATH: [dict(r) for r in start]})
p = Pusher(cfg, api, dry_run=False)
desired_two = [{"address": "2.2.2.2", "list": "block"},
               {"address": "3.3.3.3", "list": "block"}]
plan = p.plan_managed_list(PATH, "address", desired_two, manage_tag=TAG,
                           label="entry")
# make the SECOND add fail
second = [o for o in plan.ops if o.action == "add"][1]
api.fail_desc = second.desc
raised = False
try:
    p.apply(plan)
except PushError:
    raised = True
final = sorted(r["address"] for r in api.state[PATH])
check("apply raised on failure", raised)
check("rollback removed the first add (state restored)",
      final == ["8.8.8.8"])


# ---- 5. backups: plan + list ----------------------------------------------
print("backups:")
api = FakeApi({("file",): [
    {".id": "*1", "name": "mikromon-20260101.backup", "size": "100",
     "creation-time": "jan/01/2026"},
    {".id": "*2", "name": "flash/skins", "size": "0"},
]})
p = Pusher(cfg, api, dry_run=True)
backups = p.list_backups()
check("list_backups filters to backup files only",
      [b["name"] for b in backups] == ["mikromon-20260101.backup"])
plan = p.plan_backup("nightly")
check("backup plan is a single run op",
      len(plan.ops) == 1 and plan.ops[0].action == "run")
check("backup dry-run previews the save",
      "nightly" in p.apply(plan)["diff"])

# ---- 6. ownership by comment PREFIX (multi-rule features) ------------------
print("ownership by prefix:")
from mikromon.push.reconcile import reconcile_list as rl
SEC = ("ip", "firewall", "filter")
cur = [
    {".id": "*1", "chain": "input", "action": "drop", "comment": "mikromon:sec:a"},
    {".id": "*2", "chain": "input", "action": "drop", "comment": "manual-rule"},
]
ops = rl(SEC, "comment",
         [{"chain": "input", "action": "drop", "comment": "mikromon:sec:b"}],
         cur, owns=lambda r: str(r.get("comment", "")).startswith("mikromon:sec:"),
         label="sec")
check("prefix-owned stale rule removed (*1)",
      any(o.action == "remove" and o.params.get(".id") == "*1" for o in ops))
check("new prefixed rule added",
      any(o.action == "add" and o.params.get("comment") == "mikromon:sec:b"
          for o in ops))
check("manual rule (*2) untouched",
      not any(o.params.get(".id") == "*2" for o in ops))


# ---- 7. plan_settings on a singleton menu (e.g. /ip/dns) -------------------
print("plan_settings:")
api = FakeApi({("ip", "dns"): [{".id": "*0", "servers": "1.1.1.1",
                                "allow-remote-requests": "false"}]})
p = Pusher(cfg, api, dry_run=False)
plan = p.plan_settings(("ip", "dns"),
                       {"servers": "8.8.8.8", "allow-remote-requests": "false"})
check("settings plan only includes changed fields",
      len(plan.ops) == 1 and plan.ops[0].params.get("servers") == "8.8.8.8"
      and "allow-remote-requests" not in plan.ops[0].params)
check("settings op carries the row id", plan.ops[0].params.get(".id") == "*0")
check("settings inverse restores old value",
      plan.ops[0].inverse.params.get("servers") == "1.1.1.1")
p.apply(plan)
check("settings apply updates the row",
      api.state[("ip", "dns")][0]["servers"] == "8.8.8.8")
nochange = p.plan_settings(("ip", "dns"), {"servers": "8.8.8.8"})
check("no-op settings plan is empty", nochange.empty)


# ---- 8. audit log records applies + failures -------------------------------
print("audit log:")
import tempfile
from mikromon.push import AuditLog

dbp = os.path.join(tempfile.mkdtemp(), "audit.db")
audit = AuditLog(dbp)
api = FakeApi({SEC: []})
p = Pusher(cfg, api, dry_run=False, audit=audit, user="alice")
p.apply(p.plan_managed_list(SEC, "comment",
        [{"chain": "input", "action": "drop", "comment": "mikromon:sec:x"}],
        owns=lambda r: True, label="sec"), feature="security")
rows = audit.recent()
check("apply was logged", len(rows) == 1 and rows[0]["status"] == "ok")
check("log captured user + feature",
      rows[0]["username"] == "alice" and rows[0]["feature"] == "security")
# a failing apply logs an error with detail
api.fail_desc = None
bad = FakeApi({SEC: []})
bad.fail_desc = "add sec comment=mikromon:sec:y"  # won't match; force via execute
p2 = Pusher(cfg, bad, dry_run=False, audit=audit, user="bob")
plan = p2.plan_managed_list(SEC, "comment",
        [{"chain": "input", "action": "drop", "comment": "mikromon:sec:y"}],
        owns=lambda r: True, label="sec")
bad.fail_desc = plan.ops[0].desc
err = False
try:
    p2.apply(plan, feature="security")
except PushError:
    err = True
logged = audit.recent(limit=1)[0]
check("failed apply raised", err)
check("failure logged with error status + detail",
      logged["status"] == "error" and "FAILED" in logged["detail"])
check("recent() filters by device",
      all(r["device"] == "R1" for r in audit.recent(device="R1")))


# ---- 9. feature plan builders produce sane RouterOS rows -------------------
print("feature builders:")
import types as _t
from mikromon.push import features as F

devcfg = _t.SimpleNamespace(
    name="R1", wan=_t.SimpleNamespace(
        links=[_t.SimpleNamespace(interface="ether1", gateway="", name="ISP1",
                                  label=lambda i=0: "ISP1")]))

# security toggles -> firewall drop rules
api = FakeApi({("ip", "firewall", "filter"): []})
ps = Pusher(devcfg, api, dry_run=True)
plan = F.security_plan(ps, devcfg, {}, {"opt": ["drop_invalid", "block_mgmt_wan"]})
adds = [o for o in plan.ops if o.action == "add"]
check("security builds tagged drop rules",
      adds and all(o.params["comment"].startswith("mikromon:sec:") for o in adds)
      and any(o.params.get("connection-state") == "invalid" for o in adds))

# qos rows -> simple queues
api = FakeApi({("queue", "simple"): []})
pq = Pusher(devcfg, api, dry_run=True)
plan = F.qos_plan(pq, devcfg, {},
                  {"q__name": ["office"], "q__target": ["192.168.88.0/24"],
                   "q__down": ["50"], "q__up": ["20"]})
q = [o for o in plan.ops if o.action == "add"][0]
check("qos builds a simple queue with up/down limit",
      q.params["name"] == "office" and q.params["comment"] == "mikromon:qos:office"
      and q.params["max-limit"] == "20M/50M")

# port-forward rows -> dst-nat
api = FakeApi({("ip", "firewall", "nat"): []})
pp = Pusher(devcfg, api, dry_run=True)
plan = F.portfwd_plan(pp, devcfg, {},
                      {"pf__name": ["web"], "pf__proto": ["tcp"],
                       "pf__dport": ["8080"], "pf__toaddr": ["192.168.88.10"],
                       "pf__toport": ["80"]})
nat = [o for o in plan.ops if o.action == "add"][0]
check("portfwd builds a dst-nat rule",
      nat.params["action"] == "dst-nat" and nat.params["to-addresses"] == "192.168.88.10"
      and nat.params["dst-port"] == "8080")


# ---- 10. adoption: import an existing rule into management -----------------
print("adoption:")
QUEUE = ("queue", "simple")
api = FakeApi({QUEUE: [
    {".id": "*1", "name": "office", "target": "192.168.88.0/24",
     "max-limit": "20M/50M"},                                   # unmanaged
    {".id": "*2", "name": "mm", "target": "10.0.0.0/24",
     "max-limit": "5M/5M", "comment": "mikromon:qos:mm"},       # already managed
]})
qcfg = _t.SimpleNamespace(name="R1", wan=_t.SimpleNamespace(links=[]))
pa = Pusher(qcfg, api, dry_run=False)

unmanaged = F.qos_unmanaged(pa, qcfg)
check("qos_unmanaged lists only the unmanaged queue",
      [u["id"] for u in unmanaged] == ["*1"])

plan = F.adopt_plan(pa, qcfg, F.FEATURES["qos"], "*1")
check("adopt is a single set op on the comment",
      len(plan.ops) == 1 and plan.ops[0].action == "set"
      and plan.ops[0].params.get("comment") == "mikromon:qos:office")
check("adopt inverse restores the previous (empty) comment",
      plan.ops[0].inverse.params.get("comment") == "")
pa.apply(plan)
check("after adopt the queue is owned by mikromon",
      any(r.get("comment") == "mikromon:qos:office"
          for r in api.state[QUEUE] if r[".id"] == "*1"))
check("adopted queue now appears in the managed editor",
      any(r["name"] == "office" for r in F.qos_read(pa, qcfg)))
# round-trip: re-applying the editor's view makes NO changes (no churn)
cur = F.qos_read(pa, qcfg)
multi = {"q__name": [r.get("name", "") for r in cur],
         "q__target": [r.get("target", "") for r in cur],
         "q__down": [str(r.get("max-limit", "/")).split("/")[1].replace("M", "")
                     for r in cur],
         "q__up": [str(r.get("max-limit", "/")).split("/")[0].replace("M", "")
                   for r in cur]}
roundtrip = F.qos_plan(pa, qcfg, {}, multi)
check("re-applying adopted+managed queues is a no-op (no churn)",
      roundtrip.empty)

# port-forward adoption only offers dst-nat rules
napi = FakeApi({("ip", "firewall", "nat"): [
    {".id": "*1", "chain": "dstnat", "action": "dst-nat", "protocol": "tcp",
     "dst-port": "8080", "to-addresses": "192.168.88.10", "to-ports": "80"},
    {".id": "*2", "chain": "srcnat", "action": "masquerade"}]})
pf = Pusher(qcfg, napi, dry_run=False)
um = F.portfwd_unmanaged(pf, qcfg)
check("portfwd_unmanaged offers only dst-nat rules (not masquerade)",
      [u["id"] for u in um] == ["*1"])


# ---- 11. sd-wan: failover distances + per-subnet policy --------------------
print("sd-wan:")
link1 = _t.SimpleNamespace(interface="ether1", gateway="", name="ISP1",
                           label=lambda i=0: "ISP1")
scfg = _t.SimpleNamespace(name="R1", wan=_t.SimpleNamespace(links=[link1]))
sapi = FakeApi({("ip", "route"): [
    {".id": "*1", "dst-address": "0.0.0.0/0", "gateway": "ether1",
     "distance": "5"}],
    ("ip", "firewall", "mangle"): []})
sp = Pusher(scfg, sapi, dry_run=True)
plan = F.sdwan_plan(sp, scfg, {"mode": "failover"},
                    {"pol__subnet": ["10.0.0.0/24"], "pol__via": ["ether2"]})
check("failover sets the primary link's route distance to 1",
      any(o.action == "set" and o.params.get("distance") == "1" for o in plan.ops))
check("policy adds a mangle mark-routing rule",
      any(o.path == ("ip", "firewall", "mangle")
          and o.params.get("action") == "mark-routing" for o in plan.ops))
check("policy adds a marked default route",
      any(o.path == ("ip", "route") and o.params.get("routing-mark")
          and o.params.get("dst-address") == "0.0.0.0/0" for o in plan.ops))


# ---- 12. custom scripts: add / run / remove, ownership-scoped --------------
print("custom scripts:")
SCR = ("system", "script")
sc_api = FakeApi({SCR: [
    {".id": "*1", "name": "block-bad", "source": ":log info hi",
     "comment": "mikromon:script:block-bad"},          # managed
    {".id": "*2", "name": "vendor-thing", "source": ":log info x"},  # hand-made
]})
psc = Pusher(qcfg, sc_api, dry_run=True)

managed = F.scripts_read(psc, qcfg)
check("scripts_read lists only mikromon-owned scripts",
      [s["name"] for s in managed] == ["block-bad"])

# add a brand-new script via the form
add = F.scripts_plan(psc, qcfg, {"new_name": "harden", "new_source": "/ip service ..."}, {})
add_ops = [o for o in add.ops if o.action == "add"]
check("save adds a tagged script with its source",
      len(add_ops) == 1 and add_ops[0].params["name"] == "harden"
      and add_ops[0].params["comment"] == "mikromon:script:harden"
      and add_ops[0].params["source"] == "/ip service ...")
check("saving does not disturb the hand-made script",
      not any(o.params.get(".id") == "*2" for o in add.ops))
check("re-saving the existing managed script unchanged is a no-op",
      F.scripts_plan(psc, qcfg,
                     {"new_name": "block-bad", "new_source": ":log info hi"},
                     {}).empty)

# run an existing managed script
run = F.scripts_plan(psc, qcfg,
                     {"script_action": "run", "script_name": "block-bad"}, {})
check("run produces a single run op against the script id",
      len(run.ops) == 1 and run.ops[0].action == "run"
      and run.ops[0].params.get(".id") == "*1")

# remove an existing managed script
rm = F.scripts_plan(psc, qcfg,
                    {"script_action": "remove", "script_name": "block-bad"}, {})
check("remove produces a single reversible remove op",
      len(rm.ops) == 1 and rm.ops[0].action == "remove"
      and rm.ops[0].params.get(".id") == "*1"
      and rm.ops[0].inverse.action == "add")
check("remove never targets the hand-made script",
      not any(o.params.get(".id") == "*2" for o in rm.ops))


# ---- 13. restrict management access (the brute-force fix) ------------------
print("restrict management access:")
SVC = ("ip", "service")
h_api = FakeApi({
    SVC: [
        {".id": "*1", "name": "api", "port": "8728", "address": "",
         "disabled": "false"},
        {".id": "*2", "name": "winbox", "port": "8291", "address": "",
         "disabled": "false"},
        {".id": "*3", "name": "telnet", "port": "23", "address": "",
         "disabled": "false"},
        {".id": "*4", "name": "ssh", "port": "22", "address": "",
         "disabled": "false"}],
    ("ip", "firewall", "address-list"): [],
    ("ip", "firewall", "filter"): []})
ph = Pusher(qcfg, h_api, dry_run=True)
plan = F.harden_plan(ph, qcfg,
                     {"allowed": "102.36.140.219/32", "block": "45.198.224.18"},
                     {"svc": ["api", "winbox", "ssh"], "disable": ["telnet"]})
set_api = next((o for o in plan.ops
                if o.params.get(".id") == "*1" and "address" in o.params), None)
check("restrict locks the API service to the trusted IP",
      set_api is not None and set_api.params.get("address") == "102.36.140.219/32")
check("service restrict is reversible (inverse restores old address)",
      set_api.inverse.params.get("address") == "")
check("restrict disables telnet",
      any(o.action == "set" and o.params.get(".id") == "*3"
          and o.params.get("disabled") == "yes" for o in plan.ops))
check("attacker IP added to the block address-list",
      any(o.path == ("ip", "firewall", "address-list") and o.action == "add"
          and o.params.get("address") == "45.198.224.18" for o in plan.ops))
check("a drop rule for the block list is added (own tag)",
      any(o.path == ("ip", "firewall", "filter")
          and o.params.get("src-address-list") == "mikromon-blocked"
          and o.params.get("comment", "").startswith("mikromon:harden:")
          for o in plan.ops))
# idempotent: re-applying when already locked makes no service change
h_api2 = FakeApi({SVC: [
    {".id": "*1", "name": "api", "port": "8728",
     "address": "102.36.140.219/32", "disabled": "false"}],
    ("ip", "firewall", "address-list"): [], ("ip", "firewall", "filter"): []})
plan2 = F.harden_plan(Pusher(qcfg, h_api2, dry_run=True), qcfg,
                      {"allowed": "102.36.140.219/32"}, {"svc": ["api"]})
check("re-restricting an already-locked service is a no-op", plan2.empty)


# ---- 14. NextDNS content blocking grid (DNS sinkhole) ----------------------
print("nextdns content blocking grid:")
nd_api = FakeApi({
    ("ip", "dns"): [{".id": "*0", "servers": "1.1.1.1",
                     "allow-remote-requests": "true"}],
    ("ip", "firewall", "address-list"): [],
    ("ip", "dns", "static"): []})
pn = Pusher(qcfg, nd_api, dry_run=True)
plan = F.nextdns_plan(pn, qcfg, {"servers": "1.1.1.1", "bypass": ""},
                      {"opt": ["allow_remote"], "block": ["app_tiktok", "social"]})
static_adds = [o for o in plan.ops
               if o.path == ("ip", "dns", "static") and o.action == "add"]
check("enabling block groups adds tagged sinkhole entries (valid A address)",
      static_adds and all(o.params.get("address") == "127.0.0.1"
          and o.params.get("comment", "").startswith("mikromon:dnsblock:")
          for o in static_adds))
check("a custom sinkhole IP is honored",
      all(o.params.get("address") == "192.0.2.1" for o in F.nextdns_plan(
          pn, qcfg, {"servers": "1.1.1.1", "bypass": "", "block_ip": "192.0.2.1"},
          {"block": ["app_facebook"]}).ops
          if o.path == ("ip", "dns", "static") and o.action == "add"))
check("the TikTok app block creates a regexp matching tiktok.com",
      any("tiktok" in o.params.get("regexp", "") for o in static_adds))
# disabling a group removes its sinkhole entries (reversible)
nd_api2 = FakeApi({
    ("ip", "dns"): [{".id": "*0", "servers": "1.1.1.1",
                     "allow-remote-requests": "true"}],
    ("ip", "firewall", "address-list"): [],
    ("ip", "dns", "static"): [
        {".id": "*9", "regexp": r".*tiktok\.com$", "address": "0.0.0.0",
         "comment": "mikromon:dnsblock:app_tiktok"}]})
plan2 = F.nextdns_plan(Pusher(qcfg, nd_api2, dry_run=True), qcfg,
                       {"servers": "1.1.1.1", "bypass": ""},
                       {"opt": ["allow_remote"], "block": []})
rm = next((o for o in plan2.ops if o.path == ("ip", "dns", "static")
           and o.action == "remove"), None)
check("disabling a block group removes its dns-static entries",
      rm is not None and rm.params.get(".id") == "*9"
      and rm.inverse.action == "add")


# ---- 15. remote tunnel (WireGuard, dials out from the router) --------------
print("remote tunnel:")
WG = ("interface", "wireguard")
WGP = ("interface", "wireguard", "peers")
IPA = ("ip", "address")
RES = ("system", "resource")
OVPN = ("interface", "ovpn-client")
t_api = FakeApi({RES: [{"version": "7.14.3"}], WG: [], WGP: [], IPA: []})
pt = Pusher(qcfg, t_api, dry_run=True)
plan = F.hubtunnel_plan(pt, qcfg,
                     {"endpoint": "monitor.example.com", "port": "13231",
                      "hub_pubkey": "HUBKEY==", "tunnel_ip": "10.10.0.2/24",
                      "allowed": "10.10.0.0/24", "keepalive": "25s"}, {})
iface_add = next((o for o in plan.ops if o.path == WG and o.action == "add"), None)
addr_add = next((o for o in plan.ops if o.path == IPA and o.action == "add"), None)
peer_add = next((o for o in plan.ops if o.path == WGP and o.action == "add"), None)
check("tunnel creates the mikromon wireguard interface",
      iface_add is not None and iface_add.params.get("name") == "mikromon")
check("interface is created before the address/peer that reference it",
      plan.ops.index(iface_add) < plan.ops.index(addr_add)
      and plan.ops.index(iface_add) < plan.ops.index(peer_add))
check("tunnel address is bound to the interface",
      addr_add.params.get("address") == "10.10.0.2/24"
      and addr_add.params.get("interface") == "mikromon")
check("peer dials the hub with key, endpoint and keepalive",
      peer_add.params.get("public-key") == "HUBKEY=="
      and peer_add.params.get("endpoint-address") == "monitor.example.com"
      and peer_add.params.get("persistent-keepalive") == "25s"
      and peer_add.params.get("comment", "").startswith("mikromon:tunnel:"))
check("missing required fields yields an empty (safe) plan",
      F.hubtunnel_plan(pt, qcfg, {"endpoint": "x"}, {}).empty)
# idempotent: a fully-configured router produces no changes
cfgd = FakeApi({
    RES: [{"version": "7.14.3"}],
    WG: [{".id": "*1", "name": "mikromon", "public-key": "ROUTERPUB=",
          "comment": "mikromon:tunnel:if"}],
    IPA: [{".id": "*2", "address": "10.10.0.2/24", "interface": "mikromon",
           "comment": "mikromon:tunnel:addr"}],
    WGP: [{".id": "*3", "interface": "mikromon", "public-key": "HUBKEY==",
           "endpoint-address": "monitor.example.com", "endpoint-port": "13231",
           "allowed-address": "10.10.0.0/24", "persistent-keepalive": "25s",
           "comment": "mikromon:tunnel:hub"}]})
plan2 = F.hubtunnel_plan(Pusher(qcfg, cfgd, dry_run=True), qcfg,
                      {"endpoint": "monitor.example.com", "port": "13231",
                       "hub_pubkey": "HUBKEY==", "tunnel_ip": "10.10.0.2/24",
                       "allowed": "10.10.0.0/24", "keepalive": "25s"}, {})
check("re-applying an already-configured tunnel is a no-op", plan2.empty)

# v6 router (no WireGuard) -> the hub tunnel falls back to OpenVPN automatically
v6 = FakeApi({RES: [{"version": "6.49.8"}], OVPN: []})
pv6 = Pusher(qcfg, v6, dry_run=True)
cur6 = F.hubtunnel_read(pv6, qcfg)
check("v6 router selects the OpenVPN transport", cur6.get("mode") == "ovpn")
oplan = F.hubtunnel_plan(pv6, qcfg,
                         {"connect_to": "monitor.example.com", "port": "1194",
                          "user": "router1", "password": "s3cret"}, {})
ov_add = next((o for o in oplan.ops if o.path == OVPN and o.action == "add"), None)
check("v6 hub tunnel creates a tagged ovpn-client dialing the hub",
      ov_add is not None
      and ov_add.params.get("connect-to") == "monitor.example.com"
      and ov_add.params.get("user") == "router1"
      and ov_add.params.get("password") == "s3cret"
      and ov_add.params.get("comment", "").startswith("mikromon:tunnel:"))
check("v6 with no hub host is a safe no-op",
      F.hubtunnel_plan(pv6, qcfg, {"connect_to": ""}, {}).empty)


# ---- 16. update RouterOS (check / install+reboot / firmware) ---------------
print("update RouterOS:")
PKG = ("system", "package", "update")
RB = ("system", "routerboard")
u_api = FakeApi({
    PKG: [{".id": "*0", "channel": "stable", "installed-version": "7.14",
           "latest-version": "7.15", "status": "New version is available"}],
    RB: [{".id": "*0", "current-firmware": "7.14", "upgrade-firmware": "7.15"}]})
pu = Pusher(qcfg, u_api, dry_run=True)
cur = F.update_read(pu, qcfg)
check("update_read reports installed vs latest version",
      cur["update"]["installed-version"] == "7.14"
      and cur["update"]["latest-version"] == "7.15")
check("update_available detects a newer version", F.update_available(cur) is True)
check("firmware_available detects newer RouterBOOT", F.firmware_available(cur) is True)
chk = F.update_plan(pu, qcfg, {"update_action": "check"}, {})
check("check is a single non-reboot run op",
      len(chk.ops) == 1 and chk.ops[0].action == "run"
      and chk.ops[0].params.get("_cmd") == "check-for-updates")
inst = F.update_plan(pu, qcfg, {"update_action": "install"}, {})
check("install runs the install command and warns about reboot",
      inst.ops[0].params.get("_cmd") == "install"
      and "REBOOT" in inst.ops[0].desc.upper())
fw = F.update_plan(pu, qcfg, {"update_action": "firmware"}, {})
check("firmware upgrade runs routerboard upgrade",
      fw.ops[0].path == RB and fw.ops[0].params.get("_cmd") == "upgrade")
ch = F.update_plan(pu, qcfg, {"channel": "long-term"}, {})
check("changing channel produces a settings set",
      len(ch.ops) == 1 and ch.ops[0].action == "set"
      and ch.ops[0].params.get("channel") == "long-term")
# up-to-date device: nothing to do
u2 = FakeApi({PKG: [{".id": "*0", "channel": "stable",
                     "installed-version": "7.15", "latest-version": "7.15",
                     "status": "System is already up to date"}],
              RB: [{".id": "*0", "current-firmware": "7.15",
                    "upgrade-firmware": "7.15"}]})
cur2 = F.update_read(Pusher(qcfg, u2, dry_run=True), qcfg)
check("update_available false when current == latest",
      F.update_available(cur2) is False)
check("no action + unchanged channel is a no-op",
      F.update_plan(Pusher(qcfg, u2, dry_run=True), qcfg,
                    {"channel": "stable"}, {}).empty)


# ---- 17. detach: background run / reboot / install survive disconnect ------
print("detach (background run / reboot):")
import socket as _socket
from mikromon.push.api import PushApi
from mikromon.push.plan import Operation


class _FakePath:
    def __init__(self, exc):
        self.exc = exc

    def __call__(self, cmd, **kw):
        raise self.exc


class _FakeRouterApi:
    def __init__(self, exc):
        self.exc = exc

    def path(self, *p):
        return _FakePath(self.exc)


class _FakeDev:
    def __init__(self, exc):
        self.api = _FakeRouterApi(exc)


pa = PushApi(_FakeDev(_socket.timeout("timed out")))
res = pa.execute(Operation("run", ("system",), {"_cmd": "reboot"}, detach=True))
check("detached run swallows a post-send timeout (treated as submitted)",
      isinstance(res, dict) and res.get("detached") is True)
raised = False
try:
    pa.execute(Operation("run", ("system",), {"_cmd": "reboot"}))  # not detached
except PushError:
    raised = True
check("a non-detached run still surfaces the timeout as an error", raised)
raised2 = False
try:
    pa2 = PushApi(_FakeDev(ValueError("failure: no such item")))
    pa2.execute(Operation("run", ("system",), {"_cmd": "x"}, detach=True))
except PushError:
    raised2 = True
check("detached run still raises on a real command error (not a disconnect)",
      raised2)

# feature ops are marked detach where they should be
sr = F.scripts_plan(
    Pusher(qcfg, FakeApi({("system", "script"): [
        {".id": "*1", "name": "x", "comment": "mikromon:script:x"}]}),
        dry_run=True),
    qcfg, {"script_action": "run", "script_name": "x"}, {})
check("script Run is a detached (background) op", sr.ops[0].detach is True)
rb = F.update_plan(Pusher(qcfg, u_api, dry_run=True), qcfg,
                   {"update_action": "reboot"}, {})
check("reboot is a detached run on /system",
      rb.ops[0].path == ("system",) and rb.ops[0].params.get("_cmd") == "reboot"
      and rb.ops[0].detach is True)
check("install is detached too (survives the reboot disconnect)",
      inst.ops[0].detach is True)


print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL PUSH ENGINE TESTS PASSED")
