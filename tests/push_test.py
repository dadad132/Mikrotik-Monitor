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

# de-dupe: older non-idempotent builds could stack identical owned rows; a
# reconcile must collapse them to ONE (keep the first, remove the extras) so
# rules don't pile up every time the same config is applied.
dup_current = [
    {".id": "*1", "address": "1.1.1.1", "list": "block", "comment": TAG},  # keep
    {".id": "*2", "address": "1.1.1.1", "list": "block", "comment": TAG},  # dup
    {".id": "*3", "address": "1.1.1.1", "list": "block", "comment": TAG},  # dup
    {".id": "*9", "address": "1.1.1.1", "list": "block", "comment": "manual"},  # not ours
]
dops = reconcile_list(PATH, "address",
                      [{"address": "1.1.1.1", "list": "block"}],
                      dup_current, manage_tag=TAG, label="entry")
removed_ids = {o.params.get(".id") for o in dops if o.action == "remove"}
check("collapses duplicate owned rows to one (removes the extras)",
      removed_ids == {"*2", "*3"})
check("keeps a single owned row and never the hand-made duplicate (*9)",
      "*1" not in removed_ids and "*9" not in removed_ids
      and not any(o.action == "add" for o in dops))
check("de-dupe removal is reversible (add inverse restores the row)",
      all(o.inverse.action == "add" for o in dops if o.action == "remove"))

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
check("list_backups exposes the file id (for delete)",
      backups[0].get("id") == "*1")
# backups are unencrypted so a restore needs no password
check("plan_backup saves unencrypted",
      plan.ops[0].params.get("dont-encrypt") == "yes")
# restore = a detached (reboot) run that loads the .backup
r = p.plan_restore("nightly")
check("plan_restore loads the .backup as a detached reboot run",
      r.ops[0].action == "run" and r.ops[0].detach
      and r.ops[0].params.get("_cmd") == "load"
      and r.ops[0].params.get("name") == "nightly.backup")
# delete = remove the file by its id; missing file = safe empty plan
d = p.plan_delete_backup("mikromon-20260101.backup")
check("plan_delete_backup removes the file by id",
      len(d.ops) == 1 and d.ops[0].action == "remove"
      and d.ops[0].params.get(".id") == "*1")
check("plan_delete_backup on a missing file is an empty (safe) plan",
      p.plan_delete_backup("nope.backup").empty)

print("backups: pruning keeps only the newest 10 across BOTH prefixes:")
# On-demand ("mikromon-...") and automatic pre-change safety-net
# ("before-<feature>-...") backups share one combined 10-slot budget. Mixed
# on purpose so pruning must sort by the trailing timestamp, not by name
# (which would wrongly group all "before-..." before all "mikromon-...").
managed_files = [
    {".id": "*1", "name": "mikromon-20260101-000000.backup"},
    {".id": "*2", "name": "before-wan-20260102-000000.backup"},
    {".id": "*3", "name": "mikromon-20260103-000000.backup"},
    {".id": "*4", "name": "before-dns-20260104-000000.backup"},
    {".id": "*5", "name": "mikromon-20260105-000000.backup"},
    {".id": "*6", "name": "before-wan-20260106-000000.backup"},
    {".id": "*7", "name": "mikromon-20260107-000000.backup"},
    {".id": "*8", "name": "before-dns-20260108-000000.backup"},
    {".id": "*9", "name": "mikromon-20260109-000000.backup"},
    {".id": "*10", "name": "before-wan-20260110-000000.backup"},
    {".id": "*11", "name": "mikromon-20260111-000000.backup"},
    {".id": "*12", "name": "my-custom-name.backup"},  # user-named: never touched
]
api = FakeApi({("file",): managed_files})
p = Pusher(cfg, api, dry_run=True)
plan = p.plan_backup(None, keep=10)  # about to add an 12th managed backup
prune_ops = [op for op in plan.ops if op.action == "remove"]
check("adding one more prunes exactly the 2 oldest managed backups (11+1-10)",
      {op.params[".id"] for op in prune_ops} == {"*1", "*2"})
check("the user's custom-named backup is never pruned",
      "*12" not in {op.params[".id"] for op in prune_ops})

# ---- 5b. commit-confirm auto-revert (safe mode) ---------------------------
print("commit-confirm auto-revert:")
api = FakeApi({("system", "scheduler"): []})
p = Pusher(cfg, api, dry_run=True)
arm = p.plan_arm_revert("before-scripts-20260101-101010", minutes=2,
                        hub_ip="10.10.0.1")
op = arm.ops[0]
ev = op.params.get("on-event", "")
check("arm adds a scheduler named mikromon-autorevert",
      op.action == "add" and op.path == ("system", "scheduler")
      and op.params.get("name") == "mikromon-autorevert")
check("arm fires after the window and can load the pre-change backup",
      op.params.get("interval") == "2m"
      and '/system backup load name="before-scripts-20260101-101010.backup"' in ev)
check("revert is gated on a hub connectivity check (not a human guess)",
      "/ping 10.10.0.1 count=4" in ev and ":if (" in ev)
check("when the router can still reach the hub, the scheduler just clears itself",
      'else={' in ev
      and 'scheduler remove [find name="mikromon-autorevert"]' in ev)
# disarm finds the armed scheduler by name and removes it by id
api2 = FakeApi({("system", "scheduler"): [
    {".id": "*9", "name": "mikromon-autorevert"},
    {".id": "*8", "name": "something-else"}]})
p2 = Pusher(cfg, api2, dry_run=True)
dis = p2.plan_disarm_revert()
check("disarm removes the autorevert scheduler by id",
      len(dis.ops) == 1 and dis.ops[0].action == "remove"
      and dis.ops[0].params.get(".id") == "*9")
check("disarm is an empty (safe) plan when nothing is armed",
      Pusher(cfg, FakeApi({("system", "scheduler"): []}), dry_run=True)
      .plan_disarm_revert().empty)

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
# last_change: most recent REAL apply, ignoring backup/arm/confirm sub-steps
audit.append("R1", "alice", "scripts:backup", "apply", "ok", "snap")
audit.append("R1", "alice", "scripts", "apply", "ok", "the change")
audit.append("R1", "alice", "scripts:arm-revert", "apply", "ok", "armed")
ts, feat = audit.last_change("R1")
check("last_change finds the real change, not its backup/arm sub-steps",
      feat == "scripts" and ts is not None)
check("last_change is empty for a device with no applied changes",
      audit.last_change("ghost") == (None, None))


# ---- 9. feature plan builders produce sane RouterOS rows -------------------
print("feature builders:")
import types as _t
from mikromon.push import features as F

devcfg = _t.SimpleNamespace(
    name="R1", wan=_t.SimpleNamespace(
        links=[_t.SimpleNamespace(interface="ether1", gateway="", name="ISP1",
                                  label=lambda i=0: "ISP1")]))

# The Security tab now exposes ONLY the 4 user-requested toggles; the old
# built-in protections were removed and their option keys produce no rules.
api = FakeApi({("ip", "firewall", "filter"): [], ("ip", "firewall", "raw"): [],
               ("ip", "settings"): [{"tcp-syncookies": "no"}]})
ps = Pusher(devcfg, api, dry_run=True)
plan = F.security_plan(ps, devcfg, {},
                       {"opt": ["drop_invalid", "block_mgmt_wan", "block_icmp_wan",
                                "synflood", "ddos", "ssh_bruteforce", "port_scan"]})
check("removed security toggles produce no firewall rules",
      not any(o.path == ("ip", "firewall", "filter") and o.action == "add"
              for o in plan.ops))
form_vals = {f["value"] for f in F.security_form(
    {"rules": [], "ssh_disabled": False, "syn_cookies": False}, devcfg)}
check("security form exposes the 5 supported toggles",
      form_vals == {"disable_telnet_ftp", "syn_cookies", "ddos_detect",
                    "ssh_blacklist", "disable_ssh"})
# a leftover rule from a removed toggle is reconciled AWAY on the next apply
off_api = FakeApi({("ip", "firewall", "filter"): [
    {".id": "*1", "chain": "input", "action": "drop",
     "comment": "mikromon:sec:synflood"}],
    ("ip", "firewall", "raw"): [], ("ip", "settings"): [{"tcp-syncookies": "no"}]})
off = F.security_plan(Pusher(devcfg, off_api, dry_run=True), devcfg, {}, {"opt": []})
check("a leftover rule from a removed toggle is reconciled away",
      any(o.action == "remove" and o.params.get(".id") == "*1" for o in off.ops))

# Security tab "Disable SSH" toggle -> reversible set on /ip service ssh
ssh_on = FakeApi({("ip", "firewall", "filter"): [],
                  ("ip", "service"): [
                      {".id": "*ssh", "name": "ssh", "disabled": "false"},
                      {".id": "*api", "name": "api", "disabled": "false"}]})
dis = F.security_plan(Pusher(devcfg, ssh_on, dry_run=True), devcfg, {},
                      {"opt": ["disable_ssh"]})
sops = [o for o in dis.ops if o.path == ("ip", "service")]
check("Security 'disable SSH' sets the ssh service disabled=yes (reversible)",
      len(sops) == 1 and sops[0].action == "set"
      and sops[0].params == {".id": "*ssh", "disabled": "yes"}
      and sops[0].inverse.params.get("disabled") == "false")
noop = F.security_plan(Pusher(devcfg, ssh_on, dry_run=True), devcfg, {}, {"opt": []})
check("SSH toggle off while ssh already enabled = no service op (no churn)",
      not any(o.path == ("ip", "service") for o in noop.ops))
ssh_off = FakeApi({("ip", "firewall", "filter"): [],
                   ("ip", "service"): [
                       {".id": "*ssh", "name": "ssh", "disabled": "true"}]})
en = F.security_plan(Pusher(devcfg, ssh_off, dry_run=True), devcfg, {}, {"opt": []})
sops = [o for o in en.ops if o.path == ("ip", "service")]
check("SSH toggle off while ssh disabled re-enables it (disabled=no)",
      len(sops) == 1 and sops[0].params == {".id": "*ssh", "disabled": "no"})
# the form reflects the live SSH state so re-applying never fights the user
frm = F.security_form({"rules": [], "ssh_disabled": True, "syn_cookies": True},
                      devcfg)
check("Security form shows a 'Disable the SSH service' toggle, on when disabled",
      any(f.get("value") == "disable_ssh" and f.get("on") is True for f in frm))
check("Security form shows the SYN-cookies toggle, on when enabled",
      any(f.get("value") == "syn_cookies" and f.get("on") is True for f in frm))


def _sec(opts, state=None):
    st = {("ip", "firewall", "filter"): [], ("ip", "firewall", "raw"): [],
          ("ip", "settings"): [{"tcp-syncookies": "no"}]}
    st.update(state or {})
    return F.security_plan(Pusher(devcfg, FakeApi(st), dry_run=True), devcfg, {},
                           {"opt": opts})


# SYN attack: /ip settings tcp-syncookies as a reversible, churn-free toggle
sset = [o for o in _sec(["syn_cookies"]).ops if o.path == ("ip", "settings")]
check("SYN-cookies on sets /ip settings tcp-syncookies=yes (reversible)",
      len(sset) == 1 and sset[0].params.get("tcp-syncookies") == "yes"
      and sset[0].inverse.params.get("tcp-syncookies") == "no")
check("SYN-cookies already on (true) = no /ip settings churn",
      not any(o.path == ("ip", "settings") for o in
              _sec(["syn_cookies"],
                   {("ip", "settings"): [{"tcp-syncookies": "true"}]}).ops))

# DDoS auto-detect: detect-ddos chain + forward jump (filter) + raw drop
ddp = _sec(["ddos_detect"])
fadds = [o for o in ddp.ops if o.path == ("ip", "firewall", "filter")
         and o.action == "add"]
radds = [o for o in ddp.ops if o.path == ("ip", "firewall", "raw")
         and o.action == "add"]
check("DDoS detect builds the detect-ddos chain + a forward jump",
      any(o.params.get("chain") == "detect-ddos"
          and o.params.get("action") == "return" for o in fadds)
      and any(o.params.get("address-list") == "ddos-attackers" for o in fadds)
      and any(o.params.get("action") == "jump"
              and o.params.get("jump-target") == "detect-ddos" for o in fadds))
check("DDoS detect adds a raw/prerouting drop for flagged attacker->target",
      len(radds) == 1 and radds[0].params.get("chain") == "prerouting"
      and radds[0].params.get("src-address-list") == "ddos-attackers"
      and radds[0].params.get("dst-address-list") == "ddos-targets")
ddoff = F.security_plan(Pusher(devcfg, FakeApi({
    ("ip", "firewall", "filter"): [
        {".id": "*j", "chain": "forward", "action": "jump",
         "comment": "mikromon:sec:ddos_detect-4jump"}],
    ("ip", "firewall", "raw"): [
        {".id": "*r", "chain": "prerouting",
         "comment": "mikromon:sec:ddos_detect-raw"}],
    ("ip", "settings"): [{"tcp-syncookies": "no"}]}), dry_run=True),
    devcfg, {}, {"opt": []})
check("turning DDoS detect off removes its filter + raw rules",
      {o.params.get(".id") for o in ddoff.ops if o.action == "remove"} == {"*j", "*r"})

# SSH staged blacklist: 5 input rules on port 22, single src-address-list each
sadds = [o for o in _sec(["ssh_blacklist"]).ops
         if o.path == ("ip", "firewall", "filter") and o.action == "add"]
check("SSH staged blacklist adds a drop + 4 staging rules on port 22",
      len(sadds) == 5
      and all(o.params.get("dst-port") == "22" for o in sadds)
      and any(o.params.get("action") == "drop"
              and o.params.get("src-address-list") == "bruteforce_blacklist"
              for o in sadds)
      and any(o.params.get("address-list") == "connection1" for o in sadds))
check("SSH staged blacklist never uses an invalid two-list matcher",
      all("," not in (o.params.get("src-address-list") or "") for o in sadds))

# ddos_detect rules light the ddos_detect toggle (and the old 'ddos' toggle,
# which shared a comment prefix, has been removed entirely)
ddform = {f["value"]: f["on"] for f in F.security_form(
    {"rules": [{"comment": "mikromon:sec:ddos_detect-1return"}],
     "ssh_disabled": False, "syn_cookies": False}, devcfg)}
check("ddos_detect rules light the ddos_detect toggle; no 'ddos' toggle exists",
      ddform.get("ddos_detect") is True and "ddos" not in ddform)

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
     "max-limit": "20M/50M", "disabled": "false"},              # unmanaged
    {".id": "*2", "name": "mm", "target": "10.0.0.0/24",
     "max-limit": "5M/5M", "disabled": "false",
     "comment": "mikromon:qos:mm"},                             # already managed
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
                   for r in cur],
         "q__off": ["" for r in cur]}
roundtrip = F.qos_plan(pa, qcfg, {}, multi)
check("re-applying adopted+managed queues is a no-op (no churn)",
      roundtrip.empty)
# pausing a queue (status off) disables it without deleting it
pause = F.qos_plan(pa, qcfg, {},
                   {"q__name": ["office"], "q__target": ["192.168.88.0/24"],
                    "q__down": ["50"], "q__up": ["20"], "q__off": ["yes"]})
check("pausing a speed limit sets disabled=true (kept, not deleted)",
      any(o.action == "set" and o.params.get("disabled") == "true"
          for o in pause.ops))

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

# gateway failover switched OFF: restoring add-default-route must give each
# configured WAN link its own distinct, high distance (10, 11, ...) instead
# of leaving RouterOS's implicit default (1 for every client) — otherwise
# every uplink ties at distance 1 as soon as more than one is up.
link_a = _t.SimpleNamespace(interface="ether2-terana", gateway="", name="Main",
                            label=lambda i=0: "Main")
link_b = _t.SimpleNamespace(interface="ether3-vodacom", gateway="", name="Backup",
                            label=lambda i=0: "Backup")
fcfg = _t.SimpleNamespace(name="R1", wan=_t.SimpleNamespace(links=[link_a, link_b]))
fapi = FakeApi({
    ("ip", "route"): [],
    ("tool", "netwatch"): [],
    ("interface", "pppoe-client"): [],
    ("ip", "dhcp-client"): [
        {".id": "*1", "interface": "ether2-terana", "add-default-route": "no"},
        {".id": "*2", "interface": "ether3-vodacom", "add-default-route": "no"},
    ],
})
fp = Pusher(fcfg, fapi, dry_run=True)
# fo_enabled absent -> failover OFF; wan_order is whatever the Routes tab was
# showing (unchanged order here) — it's submitted on every Routes tab push
# regardless of the failover toggle, same as it would be from the real UI.
foff = F.routes_plan(fp, fcfg, {}, {"wan_order": ["dhcp:1", "dhcp:2"]})
dist_ops = {o.params.get(".id"): o.params.get("default-route-distance")
           for o in foff.ops if "default-route-distance" in o.params}
check("failover OFF gives the primary link a distinct high distance (10)",
      dist_ops.get("*1") == "10")
check("failover OFF gives the secondary link a distinct high distance (11), "
      "not colliding with the primary at 1",
      dist_ops.get("*2") == "11")
check("failover OFF restores add-default-route=yes on both — 'off' means "
      "off, no managed static route left in control",
      sum(1 for o in foff.ops if o.params.get("add-default-route") == "yes") == 2)

# The exact live scenario reported: failover WAS on (static primary/secondary
# routes + check-routes + netwatch already exist at distance 1/2), then
# switched off. Every managed route/netwatch entry must be torn down
# entirely and the client's own default route restored.
existing_fo_routes = [
    {".id": "*10", "comment": "mikromon:failover:primary", "gateway": "196.39.82.159",
     "dst-address": "0.0.0.0/0", "distance": "1"},
    {".id": "*11", "comment": "mikromon:failover:secondary", "gateway": "102.214.189.2",
     "dst-address": "0.0.0.0/0", "distance": "2"},
    {".id": "*12", "comment": "mikromon:failover:check:primary", "gateway": "196.39.82.159",
     "dst-address": "8.8.8.8/32", "distance": "1"},
    {".id": "*13", "comment": "mikromon:failover:check:secondary", "gateway": "102.214.189.2",
     "dst-address": "1.1.1.1/32", "distance": "1"},
]
existing_netwatch = [
    {".id": "*20", "comment": "mikromon:failover:watch:primary", "host": "8.8.8.8"},
    {".id": "*21", "comment": "mikromon:failover:watch:secondary", "host": "1.1.1.1"},
]
fapi3 = FakeApi({
    ("ip", "route"): existing_fo_routes,
    ("tool", "netwatch"): existing_netwatch,
    ("interface", "pppoe-client"): [],
    ("ip", "dhcp-client"): [
        {".id": "*1", "interface": "ether2-terana", "add-default-route": "no"},
        {".id": "*2", "interface": "ether3-vodacom", "add-default-route": "no"},
    ],
})
fp3 = Pusher(fcfg, fapi3, dry_run=False)
foff3 = fp3.apply(F.routes_plan(fp3, fcfg, {}, {"wan_order": ["dhcp:1", "dhcp:2"]}),
                  feature="routes")
live_routes = {r["comment"]: r for r in fapi3.fetch(("ip", "route"))}
check("all managed failover routes (primary/secondary/checks) are removed",
      not any(c.startswith("mikromon:failover:") for c in live_routes))
check("netwatch entries are removed",
      fapi3.fetch(("tool", "netwatch")) == [])
live_clients = {c["interface"]: c for c in fapi3.fetch(("ip", "dhcp-client"))}
check("add-default-route is restored to yes on both underlying clients",
      live_clients["ether2-terana"]["add-default-route"] == "yes"
      and live_clients["ether3-vodacom"]["add-default-route"] == "yes")
check("each client's own default-route-distance is set to its high, "
      "non-colliding rank (10, 11) in the same push",
      live_clients["ether2-terana"]["default-route-distance"] == "10"
      and live_clients["ether3-vodacom"]["default-route-distance"] == "11")

# The exact bug reported live: turning failover OFF while the Routes tab's
# drag list still submits its own order must NOT fall back to plain 1,2,3 —
# _apply_wan_order itself must know failover is off and use the high offset.
fapi2 = FakeApi({
    ("ip", "route"): [], ("tool", "netwatch"): [],
    ("interface", "pppoe-client"): [],
    ("ip", "dhcp-client"): [
        {".id": "*1", "interface": "ether2-terana", "add-default-route": "yes"},
        {".id": "*2", "interface": "ether3-vodacom", "add-default-route": "yes"},
        {".id": "*3", "interface": "ether4-afrihost", "add-default-route": "yes"},
    ],
})
fp2 = Pusher(fcfg, fapi2, dry_run=True)
foff2 = F.routes_plan(fp2, fcfg, {}, {"wan_order": ["dhcp:1", "dhcp:2", "dhcp:3"]})
dist_ops2 = {o.params.get(".id"): o.params.get("default-route-distance")
            for o in foff2.ops if "default-route-distance" in o.params}
check("failover OFF: a 3rd, unmanaged uplink in the drag list also gets a "
      "high distance (12), never plain rank 1/2/3",
      dist_ops2.get("*1") == "10" and dist_ops2.get("*2") == "11"
      and dist_ops2.get("*3") == "12")

# gateway failover switched ON: dragging a link to the top of the Routes tab
# list must make failover treat THAT one as primary — previously it always
# used cfg.wan.links[0]/[1] regardless of the drag order, so reordering had
# no effect on which uplink actually became distance 1.
link_main = _t.SimpleNamespace(interface="ether2-terana", gateway="10.0.0.1",
                               name="Main", label=lambda i=0: "Main")
link_backup = _t.SimpleNamespace(interface="ether3-vodacom", gateway="10.0.1.1",
                                 name="Backup", label=lambda i=0: "Backup")
o2cfg = _t.SimpleNamespace(name="R1", wan=_t.SimpleNamespace(links=[link_main, link_backup]))
o2api = FakeApi({
    ("ip", "route"): [],
    ("tool", "netwatch"): [],
    ("interface", "pppoe-client"): [],
    ("interface", "l2tp-client"): [],
    ("ip", "dhcp-client"): [
        {".id": "*1", "interface": "ether2-terana", "add-default-route": "yes"},
        {".id": "*2", "interface": "ether3-vodacom", "add-default-route": "yes"},
    ],
})
o2p = Pusher(o2cfg, o2api, dry_run=True)
# Backup (client *2) dragged to rank 0 (top / primary); Main (client *1) to rank 1.
reordered = F.routes_plan(o2p, o2cfg, {"fo_enabled": "1"},
                          {"wan_order": ["dhcp:2", "dhcp:1"]})
added_routes = {o.params.get("comment"): o.params for o in reordered.ops
               if o.action == "add" and o.path == ("ip", "route")}
check("dragging Backup to the top makes IT the failover primary (distance 1)",
      added_routes.get("mikromon:failover:primary", {}).get("gateway") == "10.0.1.1")
check("Main (dragged to 2nd) becomes the failover secondary (distance 2)",
      added_routes.get("mikromon:failover:secondary", {}).get("gateway") == "10.0.0.1")

# The exact live bug: with a 3rd uplink ALSO configured as a WAN link,
# failover ON must give it its own rank-based distance (3) via a real static
# route — previously only links[0]/[1] ever got a managed route (hardcoded
# distance 1/2), so a 3rd configured link's intended distance never applied
# and it kept colliding with whatever ELSE happened to sit at distance 2.
link_fibre = _t.SimpleNamespace(interface="ether2-terana", gateway="196.39.82.159",
                                name="Fibre", label=lambda i=0: "Fibre")
link_backup3 = _t.SimpleNamespace(interface="ether3-vodacom", gateway="102.214.189.2",
                                  name="Backup", label=lambda i=0: "Backup")
link_afrihost = _t.SimpleNamespace(interface="ether4-afrihost", gateway="41.0.0.1",
                                   name="Afrihost", label=lambda i=0: "Afrihost")
o3cfg = _t.SimpleNamespace(name="R1", wan=_t.SimpleNamespace(
    links=[link_fibre, link_backup3, link_afrihost]))
o3api = FakeApi({
    ("ip", "route"): [], ("tool", "netwatch"): [],
    ("interface", "pppoe-client"): [], ("interface", "l2tp-client"): [],
    ("ip", "dhcp-client"): [
        {".id": "*1", "interface": "ether2-terana", "add-default-route": "yes"},
        {".id": "*2", "interface": "ether3-vodacom", "add-default-route": "yes"},
        {".id": "*3", "interface": "ether4-afrihost", "add-default-route": "yes"},
    ],
})
o3p = Pusher(o3cfg, o3api, dry_run=True)
plan3 = F.routes_plan(o3p, o3cfg, {"fo_enabled": "1"},
                      {"wan_order": ["dhcp:1", "dhcp:2", "dhcp:3"]})
added3 = {o.params.get("comment"): o.params for o in plan3.ops
         if o.action == "add" and o.path == ("ip", "route")}
check("a 3rd configured WAN link gets its own managed static route at "
      "distance 3 (not left to collide with whatever else is at 2)",
      added3.get("mikromon:failover:link3", {}).get("distance") == "3"
      and added3.get("mikromon:failover:link3", {}).get("gateway") == "41.0.0.1")
check("primary/secondary still get their own check-route + Netwatch (active "
      "monitoring), the 3rd does not (static route + native check-gateway only)",
      "mikromon:failover:check:primary" in added3
      and "mikromon:failover:check:secondary" in added3
      and "mikromon:failover:check:link3" not in added3)
watch3 = {o.params.get("comment") for o in plan3.ops
         if o.action == "add" and o.path == ("tool", "netwatch")}
check("no Netwatch entry is created for the 3rd link",
      "mikromon:failover:watch:link3" not in watch3
      and {"mikromon:failover:watch:primary", "mikromon:failover:watch:secondary"} <= watch3)

print("detect_isp_ifaces: find which port actually has the internet:")
isp_api = FakeApi({
    ("ip", "dhcp-client"): [
        {"interface": "ether1", "status": "bound"},
        {"interface": "ether2", "status": "searching"},  # not bound: no lease yet
    ],
    ("interface", "pppoe-client"): [
        {"name": "pppoe-out1", "running": "true"},
        {"name": "pppoe-out2", "running": "false"},
    ],
    ("interface", "l2tp-client"): [],
    ("ip", "route"): [
        {"dst-address": "0.0.0.0/0", "active": "true",
         "gateway-status": "10.0.0.1 reachable via ether5"},
        {"dst-address": "0.0.0.0/0", "active": "false",
         "gateway-status": "10.0.0.2 unreachable via ether6"},
        {"dst-address": "192.168.1.0/24", "active": "true"},  # not a default route
    ],
})
online = F.detect_isp_ifaces(isp_api)
check("a bound DHCP client's interface is detected",
      "ether1" in online)
check("a DHCP client still searching (no lease) is NOT detected",
      "ether2" not in online)
check("a running PPPoE session is detected", "pppoe-out1" in online)
check("a non-running PPPoE session is NOT detected", "pppoe-out2" not in online)
check("the gateway interface of an ACTIVE default route is detected",
      "ether5" in online)
check("an inactive default route's interface is NOT detected",
      "ether6" not in online)


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
check("a new script is stamped with full policy so Run can actually execute it",
      add_ops[0].params.get("policy", "").startswith("ftp,reboot,read,write")
      and add_ops[0].params.get("dont-require-permissions") == "yes")
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
# force-DNS: redirect client port-53 to the router (and imply allow-remote)
nd_api3 = FakeApi({
    ("ip", "dns"): [{".id": "*0", "servers": "1.1.1.1",
                     "allow-remote-requests": "false"}],
    ("ip", "firewall", "address-list"): [],
    ("ip", "firewall", "nat"): [],
    ("ip", "dns", "static"): []})
fp = F.nextdns_plan(Pusher(qcfg, nd_api3, dry_run=True), qcfg,
                    {"bypass": ""}, {"opt": ["force_dns"], "block": []})
nat_adds = [o for o in fp.ops if o.path == ("ip", "firewall", "nat")
            and o.action == "add"]
check("forcing client DNS adds udp+tcp dstnat redirect rules on port 53",
      len(nat_adds) == 2
      and all(o.params.get("action") == "redirect"
              and o.params.get("dst-port") == "53"
              and o.params.get("comment", "").startswith("mikromon:dnsforce:")
              for o in nat_adds)
      and {o.params.get("protocol") for o in nat_adds} == {"udp", "tcp"})
check("forcing client DNS implies allow-remote-requests=true",
      any(o.path == ("ip", "dns") and o.action == "set"
          and o.params.get("allow-remote-requests") == "true" for o in fp.ops))
# DNS provider presets (AdGuard / OpenDNS / Google / Cloudflare): switching one
# toggle on sets /ip dns servers to that pair and wins over the typed field; the
# toggles are mutually exclusive and the form pre-switches the matching one on.
ag_api = FakeApi({("ip", "dns"): [{".id": "*0", "servers": "8.8.8.8",
                                   "allow-remote-requests": "true"}],
                  ("ip", "firewall", "address-list"): [],
                  ("ip", "dns", "static"): []})


def _dns_servers(flat_in, multi_in):
    p = F.nextdns_plan(Pusher(qcfg, ag_api, dry_run=True), qcfg, flat_in, multi_in)
    s = next((o for o in p.ops if o.path == ("ip", "dns") and o.action == "set"),
             None)
    return s.params.get("servers") if s else None


check("AdGuard Family toggle sets its DNS pair (overrides typed field)",
      _dns_servers({"servers": "8.8.8.8"},
                   {"opt": ["allow_remote"], "dns_preset": ["adguard_family"]})
      == "94.140.14.15,94.140.15.16")
check("Cloudflare toggle sets 1.1.1.1,1.0.0.1",
      _dns_servers({"servers": "8.8.8.8"},
                   {"opt": ["allow_remote"], "dns_preset": ["cloudflare"]})
      == "1.1.1.1,1.0.0.1")
check("OpenDNS + Google presets exist with the right IPs",
      F._DNS_PRESET_SERVERS["opendns"] == "208.67.222.222,208.67.220.220"
      and F._DNS_PRESET_SERVERS["google"] == "8.8.8.8,8.8.4.4")
check("no provider toggle on leaves the DNS servers untouched (no servers set)",
      _dns_servers({}, {"opt": ["allow_remote"]}) is None)
agform = F.nextdns_form({"dns": {"servers": "1.1.1.1,1.0.0.1"},
                         "bypass": [], "static": [], "forced": []}, qcfg)
ptoggles = [f for f in agform if f.get("name") == "dns_preset"]
check("DNS form renders 6 mutually-exclusive provider toggles",
      len(ptoggles) == 6
      and all(f.get("type") == "toggle" and f.get("exclusive") == "dns_preset"
              for f in ptoggles))
check("DNS form switches on the toggle matching the live servers (Cloudflare)",
      next(f for f in ptoggles if f["value"] == "cloudflare")["on"] is True
      and all(not f["on"] for f in ptoggles if f["value"] != "cloudflare"))


def _active(servers, dynamic=""):
    f = F.nextdns_form({"dns": {"servers": servers, "dynamic-servers": dynamic},
                        "bypass": [], "static": [], "forced": []}, qcfg)
    return [t["value"] for t in f if t.get("name") == "dns_preset" and t["on"]]


# tolerant detection: any provider IP present (primary-only, different order, an
# extra server, or DNS learned dynamically from the WAN) still ticks the provider
check("detects Google when both IPs are set", _active("8.8.8.8,8.8.4.4") == ["google"])
check("detects Google from the primary IP only", _active("8.8.8.8") == ["google"])
check("detects regardless of order", _active("8.8.4.4,8.8.8.8") == ["google"])
check("detects even with an extra server present",
      _active("8.8.8.8,8.8.4.4,192.168.1.1") == ["google"])
check("detects DNS learned dynamically from the WAN",
      _active("", dynamic="1.1.1.1,1.0.0.1") == ["cloudflare"])
check("a truly custom DNS ticks nothing", _active("192.168.1.1,9.9.9.9") == [])


# ---- 15. hub tunnel — WireGuard dial-home (RouterOS 7.1+) -------------------
print("hub tunnel (WireGuard):")
WG = ("interface", "wireguard")
WGP = ("interface", "wireguard", "peers")
IPA = ("ip", "address")
t_api = FakeApi({WG: [], WGP: [], IPA: []})
pt = Pusher(qcfg, t_api, dry_run=True)
plan = F.hubtunnel_plan(pt, qcfg,
                        {"endpoint": "102.36.140.219", "port": "51820",
                         "hub_pubkey": "HUBKEY==", "tunnel_ip": "10.10.0.2/24",
                         "allowed": "10.10.0.0/24", "keepalive": "25s"}, {})
iface_add = next((o for o in plan.ops if o.path == WG and o.action == "add"), None)
addr_add = next((o for o in plan.ops if o.path == IPA and o.action == "add"), None)
peer_add = next((o for o in plan.ops if o.path == WGP and o.action == "add"), None)
check("hub tunnel creates the mikromon wireguard interface",
      iface_add is not None and iface_add.params.get("name") == "mikromon")
check("interface is created before the address/peer that reference it",
      plan.ops.index(iface_add) < plan.ops.index(addr_add)
      and plan.ops.index(iface_add) < plan.ops.index(peer_add))
check("tunnel address bound to the interface",
      addr_add.params.get("address") == "10.10.0.2/24"
      and addr_add.params.get("interface") == "mikromon")
check("peer dials the hub IP with the hub key + keepalive",
      peer_add.params.get("public-key") == "HUBKEY=="
      and peer_add.params.get("endpoint-address") == "102.36.140.219"
      and peer_add.params.get("endpoint-port") == "51820"
      and peer_add.params.get("persistent-keepalive") == "25s"
      and peer_add.params.get("comment", "").startswith("mikromon:tunnel:"))
check("missing hub IP / key / tunnel IP yields an empty (safe) plan",
      F.hubtunnel_plan(pt, qcfg, {"endpoint": "x"}, {}).empty)
cfgd = FakeApi({
    WG: [{".id": "*1", "name": "mikromon", "public-key": "ROUTERPUB=",
          "comment": "mikromon:tunnel:if"}],
    IPA: [{".id": "*2", "address": "10.10.0.2/24", "interface": "mikromon",
           "comment": "mikromon:tunnel:addr"}],
    WGP: [{".id": "*3", "interface": "mikromon", "public-key": "HUBKEY==",
           "endpoint-address": "102.36.140.219", "endpoint-port": "51820",
           "allowed-address": "10.10.0.0/24", "persistent-keepalive": "25s",
           "comment": "mikromon:tunnel:hub"}]})
plan2 = F.hubtunnel_plan(Pusher(qcfg, cfgd, dry_run=True), qcfg,
                         {"endpoint": "102.36.140.219", "port": "51820",
                          "hub_pubkey": "HUBKEY==", "tunnel_ip": "10.10.0.2/24",
                          "allowed": "10.10.0.0/24", "keepalive": "25s"}, {})
check("re-applying an already-configured WireGuard tunnel is a no-op", plan2.empty)

# zero-touch: provision_apply drives the router over the API (no script paste)
pa_api = FakeApi({
    ("user",): [],
    ("ip", "service"): [
        {".id": "*s1", "name": "api", "disabled": "true"},
        {".id": "*s2", "name": "telnet", "disabled": "false"}],
    WG: [], WGP: [], IPA: []})
res = F.provision_apply(pa_api, "Branch9", "mikromon", "pw1234567890", harden=True,
                        hub_pubkey="HUBKEY==", hub_ip="102.36.140.219",
                        port="51820", subnet="10.10.0.0/24", tunnel_ip="10.10.0.2")
ex = pa_api.executed
check("provision_apply creates the management user over the API",
      any(o.action == "add" and o.path == ("user",)
          and o.params.get("name") == "mikromon" for o in ex))
check("provision_apply enables the API service",
      any(o.action == "set" and o.path == ("ip", "service")
          and o.params.get(".id") == "*s1" and o.params.get("disabled") == "no"
          for o in ex))
check("provision_apply hardens (disables telnet)",
      any(o.path == ("ip", "service") and o.params.get(".id") == "*s2"
          and o.params.get("disabled") == "yes" for o in ex))
check("provision_apply creates the WG interface, address and hub peer",
      any(o.action == "add" and o.path == WG for o in ex)
      # /16 (not /24): so any device on the hub's 10.10.x.x range is reachable
      # regardless of the third octet _alloc_tunnel_ip randomised for it.
      and any(o.action == "add" and o.path == IPA
              and o.params.get("address") == "10.10.0.2/16" for o in ex)
      and any(o.action == "add" and o.path == WGP
              and o.params.get("public-key") == "HUBKEY==" for o in ex))
check("provision_apply returns a result dict (router pubkey key present)",
      isinstance(res, dict) and "router_pubkey" in res)
# idempotent: running again against the now-configured router adds nothing new
pa_api.executed = []
F.provision_apply(pa_api, "Branch9", "mikromon", "pwNEWNEW12345", harden=True,
                  hub_pubkey="HUBKEY==", hub_ip="102.36.140.219", port="51820",
                  subnet="10.10.0.0/24", tunnel_ip="10.10.0.2")
check("provision_apply is idempotent (user set, no duplicate WG/peer adds)",
      not any(o.action == "add" and o.path in (WG, IPA, WGP)
              for o in pa_api.executed)
      and any(o.action == "set" and o.path == ("user",)
              for o in pa_api.executed))
# enabling the API is OPTIONAL — enable_api=False leaves /ip service api alone
na_api = FakeApi({
    ("user",): [],
    ("ip", "service"): [{".id": "*s1", "name": "api", "disabled": "true"}],
    WG: [], WGP: [], IPA: []})
F.provision_apply(na_api, "Branch9", "mikromon", "pw1234567890",
                  harden=False, enable_api=False)
check("provision_apply leaves the API service untouched when enable_api=False",
      any(o.action == "add" and o.path == ("user",) for o in na_api.executed)
      and not any(o.path == ("ip", "service") for o in na_api.executed))
# lock_api binds api + api-ssl to the tunnel subnet (no public exposure) last
la_api = FakeApi({
    ("user",): [],
    ("ip", "service"): [
        {".id": "*s1", "name": "api", "disabled": "false", "address": ""},
        {".id": "*s2", "name": "api-ssl", "disabled": "false", "address": ""}],
    WG: [{".id": "*w", "name": "mikromon", "public-key": "RPUB="}],
    WGP: [], IPA: []})
F.provision_apply(la_api, "B", "mikromon", "pw1234567890", harden=False,
                  lock_api=True, hub_pubkey="HUBKEY==", hub_ip="1.2.3.4",
                  subnet="10.10.0.0/24", tunnel_ip="10.10.0.2")
bound = {o.params.get(".id") for o in la_api.executed
         if o.path == ("ip", "service")
         # /16 to match the peer's allowed-address widening (see above).
         and o.params.get("address") == "10.10.0.0/16"}
check("lock_api binds api + api-ssl to the tunnel subnet", bound == {"*s1", "*s2"})
# single-user provisioning: ONE full-access user (does both polling + push)
tu_api = FakeApi({("user",): [], ("ip", "service"): [],
                  WG: [], WGP: [], IPA: []})
F.provision_apply(tu_api, "B", "mikromon", "pw1234567890",
                  harden=False, enable_api=False)
uadds = [o for o in tu_api.executed
         if o.action == "add" and o.path == ("user",)]
check("provision_apply creates exactly ONE full-access user (no 2nd user)",
      len(uadds) == 1
      and uadds[0].params.get("name") == "mikromon"
      and uadds[0].params.get("group") == "full")


# ---- 15b. WireGuard self-repair: diagnose, auto-fix, report clearly ---------
print("wireguard self-repair:")
RES = ("system", "resource")
HUBTAG = "mikromon:tunnel:"

# unsupported firmware -> hard failure with a clear message, no fixes attempted
rep = F.wireguard_repair(FakeApi({RES: [{"version": "6.49.8"}]}))
check("repair flags RouterOS < 7.1 as a clear failure (no fix possible)",
      rep["status"] == "failed" and rep["applied"] == []
      and any(s["level"] == "error" and "7.1+" in s["msg"] for s in rep["steps"]))

# missing interface -> failure telling the user to re-provision
rep = F.wireguard_repair(FakeApi({RES: [{"version": "7.14.3"}], WG: [], WGP: []}))
check("repair fails clearly when the WireGuard interface is missing",
      rep["status"] == "failed"
      and any("no wireguard interface" in s["msg"].lower() for s in rep["steps"]))

# disabled interface + missing keepalive -> auto-repaired
broken = FakeApi({
    RES: [{"version": "7.14.3"}],
    WG: [{".id": "*i", "name": "mikromon", "disabled": "true",
          "public-key": "ROUTERPUB="}],
    WGP: [{".id": "*p", "interface": "mikromon", "comment": HUBTAG + "hub",
           "endpoint-address": "102.36.140.219", "endpoint-port": "51820",
           "last-handshake": "1m2s"}]})
rep = F.wireguard_repair(broken)
check("repair re-enables a disabled interface AND restores keepalive",
      rep["status"] == "repaired" and len(rep["applied"]) == 2
      and any(o.action == "set" and o.params.get("disabled") == "no"
              for o in broken.executed)
      and any(o.action == "set" and o.params.get("persistent-keepalive") == "25s"
              for o in broken.executed))

# everything present but no handshake -> needs attention, clear guidance, no fix
nohs = FakeApi({
    RES: [{"version": "7.14.3"}],
    WG: [{".id": "*i", "name": "mikromon", "disabled": "false",
          "running": "true", "public-key": "ROUTERPUB="}],
    WGP: [{".id": "*p", "interface": "mikromon", "comment": HUBTAG + "hub",
           "endpoint-address": "102.36.140.219", "endpoint-port": "51820",
           "persistent-keepalive": "25s", "last-handshake": ""}]})
rep = F.wireguard_repair(nohs)
check("repair reports no-handshake as needing attention with guidance",
      rep["status"] == "attention" and rep["applied"] == []
      and any(s["level"] == "warn" and "handshake" in s["msg"].lower()
              for s in rep["steps"]))

# fully healthy -> no changes
good = FakeApi({
    RES: [{"version": "7.14.3"}],
    WG: [{".id": "*i", "name": "mikromon", "disabled": "false",
          "running": "true", "public-key": "ROUTERPUB="}],
    WGP: [{".id": "*p", "interface": "mikromon", "comment": HUBTAG + "hub",
           "endpoint-address": "102.36.140.219", "endpoint-port": "51820",
           "persistent-keepalive": "25s", "last-handshake": "30s"}]})
rep = F.wireguard_repair(good)
check("repair reports a healthy tunnel and changes nothing",
      rep["status"] == "healthy" and rep["applied"] == [] and not good.executed)


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
