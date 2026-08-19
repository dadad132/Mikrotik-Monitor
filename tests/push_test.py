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

# SSH staged blacklist: 4 staging rules + a final accept, all on port 22
sadds = [o for o in _sec(["ssh_blacklist"]).ops
         if o.path == ("ip", "firewall", "filter") and o.action == "add"]
check("SSH staged blacklist adds 4 staging rules + a final accept on port 22",
      len(sadds) == 5
      and all(o.params.get("dst-port") == "22" for o in sadds)
      and any(o.params.get("action") == "accept"
              and o.params.get("src-address-list") == "!bruteforce_blacklist"
              for o in sadds)
      and any(o.params.get("address-list") == "connection1" for o in sadds))
check("SSH staged blacklist's 'third attempt' rule uses the requested "
      "connection2,!secured matcher (matches the reference exactly, even "
      "though 'secured' is not a defined address-list)",
      any(o.params.get("src-address-list") == "connection2,!secured"
          for o in sadds))

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


# ---- 11. sd-wan (WAN tab): per-subnet policy routing only ------------------
# WAN uplink Distance and the full Gateway Failover feature live entirely
# on the Routes tab now (via _apply_failover) — the WAN tab no longer has
# its own separate, overlapping distance-setting mode, to avoid there being
# two different places that look like they control the same thing.
print("sd-wan (WAN tab — policy routing only):")
link1 = _t.SimpleNamespace(interface="ether1", gateway="", name="ISP1",
                           label=lambda i=0: "ISP1", distance=10)
scfg = _t.SimpleNamespace(name="R1", wan=_t.SimpleNamespace(links=[link1]))
sapi = FakeApi({
    ("ip", "route"): [],
    ("interface", "pppoe-client"): [],
    ("ip", "dhcp-client"): [
        {".id": "*1", "interface": "ether1", "default-route-distance": "5"}],
    ("ip", "firewall", "mangle"): [],
    ("routing", "table"): [],
    ("system", "resource"): [{"version": "7.14.3"}]})
sp = Pusher(scfg, sapi, dry_run=True)
plan = F.sdwan_plan(sp, scfg, {},
                    {"pol__subnet": ["10.0.0.0/24"], "pol__via": ["ether2"]})
check("the WAN tab never touches a WAN client's own distance (that's the "
      "Routes tab's job, exclusively)",
      not any(o.path in (("ip", "dhcp-client"), ("interface", "pppoe-client"))
             for o in plan.ops))
check("policy adds a mangle mark-routing rule",
      any(o.path == ("ip", "firewall", "mangle")
          and o.params.get("action") == "mark-routing" for o in plan.ops))
check("on RouterOS 7, policy adds a marked default route using the v7 "
      "routing-table field, not the removed v6 routing-mark",
      any(o.path == ("ip", "route") and o.params.get("routing-table")
          and "routing-mark" not in o.params
          and o.params.get("dst-address") == "0.0.0.0/0" for o in plan.ops))
check("on RouterOS 7, the referenced routing table is declared via "
      "/routing/table (fib) — required or the route add is rejected "
      "outright ('unknown parameter routing-mark' if the old field name "
      "is sent instead)",
      any(o.path == ("routing", "table") and o.action == "add"
          and o.params.get("fib") == "yes" for o in plan.ops))

# Same feature on RouterOS 6: the old routing-mark field name, and
# /routing/table never touched at all — that menu doesn't exist pre-v7,
# and a routing-mark auto-creates its own virtual table on first use.
sapi6 = FakeApi({
    ("ip", "route"): [],
    ("interface", "pppoe-client"): [],
    ("ip", "dhcp-client"): [
        {".id": "*1", "interface": "ether1", "default-route-distance": "5"}],
    ("ip", "firewall", "mangle"): [],
    ("system", "resource"): [{"version": "6.49.10"}]})
plan6 = F.sdwan_plan(Pusher(scfg, sapi6, dry_run=True), scfg, {},
                     {"pol__subnet": ["10.0.0.0/24"], "pol__via": ["ether2"]})
check("on RouterOS 6, policy still uses the old routing-mark field and "
      "never touches /routing/table",
      any(o.path == ("ip", "route") and o.params.get("routing-mark")
          and "routing-table" not in o.params for o in plan6.ops)
      and not any(o.path == ("routing", "table") for o in plan6.ops))


# ---- 11b. detect_isp_ifaces: find which port actually has the internet ----
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


# ---- 13b. Remote access: a temporary RouterOS login, not a firewall rule --
print("remote access (temporary login):")
r_cfg = types.SimpleNamespace(name="R1", push_username="", push_password="")
r_api = FakeApi({("user",): [], ("system", "scheduler"): []})
r_pusher = Pusher(r_cfg, r_api, dry_run=True)

preview_plan = F.remote_plan(r_pusher, r_cfg,
                             {"tempuser": "alice", "_tempuser_password": "PREVIEWPW1!"}, {})
check("creating a temporary login adds a user + an expiry scheduler",
      len(preview_plan.ops) == 2
      and any(o.path == ("user",) and o.action == "add"
              and o.params.get("name") == "alice" for o in preview_plan.ops)
      and any(o.path == ("system", "scheduler") and o.action == "add"
              for o in preview_plan.ops))
check("the generated password never appears in the dry-run diff text (it's "
      "only ever in Operation.params, which diff_text() never prints) — the "
      "audit log stores diff_text() as its 'detail' field, so a leaked "
      "password there would be permanent",
      "PREVIEWPW1!" not in preview_plan.diff_text())
user_add = next(o for o in preview_plan.ops if o.path == ("user",))
check("the temp user gets full access and a comment tag for tracking",
      user_add.params.get("group") == "full"
      and user_add.params.get("comment") == "mikromon:remote:alice")
sched_add = next(o for o in preview_plan.ops if o.path == ("system", "scheduler"))
check("the scheduler's on-event removes the user AND itself when it fires",
      '/user remove [find name="alice"]' in sched_add.params.get("on-event", "")
      and "/system scheduler remove" in sched_add.params.get("on-event", ""))
check("no password is pushed if the web layer never supplied one (a stray "
      "call must fail safe, not create a passwordless/blank-password user)",
      F.remote_plan(r_pusher, r_cfg, {"tempuser": "bob"}, {}).empty)

# web.py's _org_wg_addresses computes who's allowed to actually USE the temp
# login (this company's own WireGuard presence) and injects it as
# flat["_remote_allowed_address"] — remote_plan restricts the created user
# to it, comma-joined addresses and all, rather than leaving it wide open.
addr_plan = F.remote_plan(r_pusher, r_cfg, {
    "tempuser": "carol", "_tempuser_password": "CarolPW1!",
    "_remote_allowed_address": "10.10.5.5/32,192.168.10.0/24"}, {})
carol_add = next(o for o in addr_plan.ops if o.path == ("user",))
check("a supplied allowed-address list is set on the new user",
      carol_add.params.get("address") == "10.10.5.5/32,192.168.10.0/24")
check("the plan's description mentions the restriction, not just silently "
      "applying it", "restricted to" in carol_add.desc)
no_addr_plan = F.remote_plan(r_pusher, r_cfg, {
    "tempuser": "dave", "_tempuser_password": "DavePW1!"}, {})
dave_add = next(o for o in no_addr_plan.ops if o.path == ("user",))
check("no allowed-address supplied (e.g. devices_db not configured) -> no "
      "address restriction pushed at all, same as before this existed",
      "address" not in dave_add.params)

# Apply for real (a DIFFERENT password than the preview used — previews and
# confirms are never guaranteed the same one, since it's never shown until
# a real commit).
commit_plan = F.remote_plan(Pusher(r_cfg, r_api, dry_run=False), r_cfg,
                            {"tempuser": "alice", "_tempuser_password": "REALPW2@"}, {})
for op in commit_plan.ops:
    r_api.execute(op)
check("the router actually gets the applied (not the previewed) password",
      r_api.state[("user",)][0]["password"] == "REALPW2@")

# Submitting the same username again while it's still active is a no-op —
# never silently resets an active login's password/timer. (Her row is still
# present in "keep", matching a real form submission that never touched the
# revoke list — only an explicitly-deleted row means "revoke this one".)
resubmit_plan = F.remote_plan(Pusher(r_cfg, r_api, dry_run=True), r_cfg,
                              {"tempuser": "alice", "_tempuser_password": "NEWPW3#"},
                              {"keep__name": ["alice"]})
check("re-submitting an already-active username changes nothing",
      resubmit_plan.empty)

current_state = F.remote_read(Pusher(r_cfg, r_api, dry_run=True), r_cfg)
check("remote_summary reports the active login in plain language",
      any("alice" in line for line in F.remote_summary(current_state, r_cfg)))
check("remote_form lists the active login as a revocable row",
      any(r["name"] == "alice"
          for f in F.remote_form(current_state, r_cfg) if f.get("name") == "keep"
          for r in f["rows"]))

# Revoke: submit with alice no longer in the "keep" list -> removes BOTH the
# user and its scheduler, never leaving an orphaned expiry entry behind.
revoke_plan = F.remote_plan(Pusher(r_cfg, r_api, dry_run=False), r_cfg, {}, {"keep__name": []})
for op in revoke_plan.ops:
    r_api.execute(op)
check("revoking removes the user", r_api.state[("user",)] == [])
check("revoking also cancels the now-pointless expiry scheduler",
      r_api.state[("system", "scheduler")] == [])

# remote_test: diagnoses WHY a login might not be reachable even though it
# was created — read-only, never changes anything.
RT_SVC = ("ip", "service")
RT_FW = ("ip", "firewall", "filter")
rt_healthy_api = FakeApi({
    RT_SVC: [
        {"name": "winbox", "disabled": "false", "address": ""},
        {"name": "www", "disabled": "false", "address": ""},
        {"name": "ssh", "disabled": "false", "address": ""},
    ],
    RT_FW: [{".id": "*1", "chain": "input", "in-interface": "mikromon",
            "action": "accept", "comment": "mikromon:tunnel:fw",
            "disabled": "false"}],
})
rt_healthy = F.remote_test(rt_healthy_api)
check("remote_test: all services open + tunnel rule present -> all 'ok', "
      "nothing to fix", all(s["level"] == "ok" for s in rt_healthy)
      and len(rt_healthy) == 4)

rt_disabled_api = FakeApi({
    RT_SVC: [{"name": "winbox", "disabled": "true", "address": ""},
            {"name": "www", "disabled": "false", "address": ""},
            {"name": "ssh", "disabled": "false", "address": ""}],
    RT_FW: [{".id": "*1", "chain": "input", "in-interface": "mikromon",
            "action": "accept", "comment": "mikromon:tunnel:fw",
            "disabled": "false"}],
})
rt_disabled = F.remote_test(rt_disabled_api)
check("remote_test flags a disabled Winbox service as an error",
      any(s["level"] == "error" and "Winbox is DISABLED" in s["msg"]
          for s in rt_disabled))

rt_restricted_api = FakeApi({
    RT_SVC: [{"name": "winbox", "disabled": "false", "address": "41.1.2.3/32"},
            {"name": "www", "disabled": "false", "address": ""},
            {"name": "ssh", "disabled": "false", "address": ""}],
    RT_FW: [{".id": "*1", "chain": "input", "in-interface": "mikromon",
            "action": "accept", "comment": "mikromon:tunnel:fw",
            "disabled": "false"}],
})
rt_restricted = F.remote_test(rt_restricted_api)
check("remote_test warns when Winbox is address-restricted (a likely cause "
      "of a silent 'stuck on Connecting' if the tunnel isn't in that range)",
      any(s["level"] == "warn" and "restricted to 41.1.2.3/32" in s["msg"]
          for s in rt_restricted))

rt_no_fw_api = FakeApi({
    RT_SVC: [{"name": "winbox", "disabled": "false", "address": ""},
            {"name": "www", "disabled": "false", "address": ""},
            {"name": "ssh", "disabled": "false", "address": ""}],
    RT_FW: [],
})
rt_no_fw = F.remote_test(rt_no_fw_api)
check("remote_test flags a MISSING tunnel firewall accept rule as an error",
      any(s["level"] == "error" and "MISSING" in s["msg"] for s in rt_no_fw))

rt_disabled_fw_api = FakeApi({
    RT_SVC: [{"name": "winbox", "disabled": "false", "address": ""},
            {"name": "www", "disabled": "false", "address": ""},
            {"name": "ssh", "disabled": "false", "address": ""}],
    RT_FW: [{".id": "*1", "chain": "input", "in-interface": "mikromon",
            "action": "accept", "comment": "mikromon:tunnel:fw",
            "disabled": "true"}],
})
rt_disabled_fw = F.remote_test(rt_disabled_fw_api)
check("remote_test flags a DISABLED (but present) tunnel firewall rule too",
      any(s["level"] == "error" and "DISABLED" in s["msg"]
          for s in rt_disabled_fw))

# The exact scenario that caused real confusion: every /ip/service check and
# the tunnel firewall rule all pass, but the LOGIN ITSELF still carries an
# address restriction (the opt-in checkbox) that the service-level checks
# never look at — remote_test must surface this separately, or "everything
# green" is actively misleading.
RT_USER = ("user",)
rt_restricted_login_api = FakeApi({
    RT_SVC: [{"name": "winbox", "disabled": "false", "address": ""},
            {"name": "www", "disabled": "false", "address": ""},
            {"name": "ssh", "disabled": "false", "address": ""}],
    RT_FW: [{".id": "*1", "chain": "input", "in-interface": "mikromon",
            "action": "accept", "comment": "mikromon:tunnel:fw",
            "disabled": "false"}],
    RT_USER: [{"name": "tmpalice", "comment": "mikromon:remote:tmpalice",
              "address": "10.10.0.0/16"}],
})
rt_restricted_login = F.remote_test(rt_restricted_login_api)
check("remote_test flags a temp login's OWN address restriction even when "
      "every service-level check passes clean",
      any(s["level"] == "warn" and "tmpalice" in s["msg"]
          and "10.10.0.0/16" in s["msg"] for s in rt_restricted_login))

rt_open_login_api = FakeApi({
    RT_SVC: [{"name": "winbox", "disabled": "false", "address": ""},
            {"name": "www", "disabled": "false", "address": ""},
            {"name": "ssh", "disabled": "false", "address": ""}],
    RT_FW: [{".id": "*1", "chain": "input", "in-interface": "mikromon",
            "action": "accept", "comment": "mikromon:tunnel:fw",
            "disabled": "false"}],
    RT_USER: [{"name": "tmpbob", "comment": "mikromon:remote:tmpbob",
              "address": ""}],
})
rt_open_login = F.remote_test(rt_open_login_api)
check("a temp login with no address restriction of its own reports 'ok', "
      "not silently skipped",
      any(s["level"] == "ok" and "tmpbob" in s["msg"] for s in rt_open_login))

rt_unmanaged_user_api = FakeApi({
    RT_SVC: [{"name": "winbox", "disabled": "false", "address": ""},
            {"name": "www", "disabled": "false", "address": ""},
            {"name": "ssh", "disabled": "false", "address": ""}],
    RT_FW: [{".id": "*1", "chain": "input", "in-interface": "mikromon",
            "action": "accept", "comment": "mikromon:tunnel:fw",
            "disabled": "false"}],
    RT_USER: [{"name": "admin", "comment": "", "address": "192.168.1.0/24"}],
})
rt_unmanaged = F.remote_test(rt_unmanaged_user_api)
check("a human-made user (no mikromon:remote: comment) is never reported "
      "on — only logins mikromon itself created",
      not any("admin" in s["msg"] for s in rt_unmanaged))


# ---- 14. DNS tab: server selection + force-client-DNS ----------------------
# The local sinkhole domain-blocking half of this tab (block groups,
# block_ip) was retired in favor of the real NextDNS.io cloud integration's
# own panels — nextdns_plan/_form no longer take or emit any of that, only
# DNS server selection and force-client-DNS remain here.
print("DNS tab (server selection + force-client-DNS; local sinkhole blocking "
      "retired in favor of the NextDNS.io cloud panels):")
nd_api = FakeApi({
    ("ip", "dns"): [{".id": "*0", "servers": "1.1.1.1",
                     "allow-remote-requests": "true"}],
    ("ip", "firewall", "address-list"): []})
pn = Pusher(qcfg, nd_api, dry_run=True)
check("nextdns_plan no longer touches /ip/dns/static at all",
      not any(o.path == ("ip", "dns", "static") for o in F.nextdns_plan(
          pn, qcfg, {"servers": "1.1.1.1", "bypass": ""},
          {"opt": ["allow_remote"]}).ops))
# force-DNS: redirect client port-53 to the router (and imply allow-remote)
nd_api3 = FakeApi({
    ("ip", "dns"): [{".id": "*0", "servers": "1.1.1.1",
                     "allow-remote-requests": "false"}],
    ("ip", "firewall", "address-list"): [],
    ("ip", "firewall", "nat"): []})
fp = F.nextdns_plan(Pusher(qcfg, nd_api3, dry_run=True), qcfg,
                    {"bypass": ""}, {"opt": ["force_dns"]})
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
                  ("ip", "firewall", "address-list"): []})


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
check("DNS form no longer renders the retired sinkhole block-group toggles "
      "or the sinkhole-IP field",
      not any(f.get("name") in ("block", "block_ip") for f in agform))


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


# ---- 15a2. VPN tab: site-to-site mesh over the existing WireGuard hub ------
print("tunnel_read/tunnel_form/tunnel_plan (VPN tab — site-to-site mesh):")
from mikromon.config import WanEndpoint as _VpnWanEndpoint  # noqa: E402

_TRES = ("system", "resource")
_VPN_ROUTE_TAG = F._VPN_ROUTE_TAG
t_wan_cfg = types.SimpleNamespace(
    name="R1", push_username="", push_password="",
    wan=types.SimpleNamespace(links=[_VpnWanEndpoint(interface="ether1", name="WAN1")]))
t_cfg = t_wan_cfg  # kept for any later reuse in this section

check("tunnel_form still shows the RouterOS-version notice on unsupported firmware",
      any("7.1" in f.get("value", "")
          for f in F.tunnel_form({"unsupported": True, "version": "6.49"}, t_cfg)))

# _detect_lan_subnets / tunnel_read: only non-WAN, non-disabled addresses count
t_read_api = FakeApi({
    _TRES: [{"version": "7.14.3"}],
    WG: [{"name": "wg0", "listen-port": "13231", "public-key": "ROUTERPUB="}],
    WGP: [],
    IPA: [
        {"address": "203.0.113.5/30", "network": "203.0.113.4",
         "interface": "ether1", "disabled": "false"},          # WAN uplink -> excluded
        {"address": "192.168.1.1/24", "network": "192.168.1.0",
         "interface": "bridge-lan", "disabled": "false"},      # LAN -> included
        {"address": "10.5.5.1/29", "network": "10.5.5.0",
         "interface": "bridge-voip", "disabled": "true"},      # disabled -> excluded
    ],
})
t_read_pusher = Pusher(t_cfg, t_read_api, dry_run=True)
t_current = F.tunnel_read(t_read_pusher, t_cfg)
check("tunnel_read detects the LAN subnet and excludes the WAN uplink's own subnet",
      t_current.get("lan_subnets") == ["192.168.1.0/24"])
check("tunnel_read excludes a disabled address entirely",
      "10.5.5.0/29" not in (t_current.get("lan_subnets") or []))

# tunnel_form: not part of any group yet (vpn_role is None — the default
# when web.py hasn't injected anything, matching a device hub.json has
# never registered) -> shows the detected network, nothing to submit that
# affects grouping (that's the dedicated make-main/add-member actions).
form_ungrouped = F.tunnel_form(t_current, t_cfg)
check("tunnel_form (ungrouped) shows the detected network",
      any(f.get("label") == "Detected network(s) here"
          and f.get("value") == "192.168.1.0/24" for f in form_ungrouped))
check("tunnel_form (ungrouped) has no vpn_join/vpn_subnet fields anymore — "
      "grouping is a dedicated action, not a form toggle",
      not any(f.get("name") in ("vpn_join", "vpn_subnet") for f in form_ungrouped))

# tunnel_form: this router IS the main host (web.py injects vpn_role="main",
# vpn_own_subnet, vpn_members from hub.json before calling this)
t_current_main = dict(t_current, vpn_role="main", vpn_own_subnet="192.168.1.0/24",
                      vpn_members={"Branch": {"subnet": "192.168.2.0/24"}})
form_main = F.tunnel_form(t_current_main, t_cfg)
check("tunnel_form (main) shows this router's own shared network",
      any(f.get("label") == "This router's shared network"
          and f.get("value") == "192.168.1.0/24" for f in form_main))
check("tunnel_form (main) lists its sub-units",
      any(f.get("label") == "Sub-units" and "Branch" in f.get("value", "")
          for f in form_main))

# tunnel_form: this router is a SUB-UNIT of another router's group
t_current_member = dict(t_current, vpn_role="member", vpn_main="HQ")
form_member = F.tunnel_form(t_current_member, t_cfg)
check("tunnel_form (sub-unit) reports whose group it belongs to, read-only",
      any("HQ" in f.get("value", "") for f in form_member))

# tunnel_plan: routes are entirely driven by what web.py's _prep_vpn_group
# injects (flat["_vpn_in_group"]/["_vpn_other_subnets"]/["_vpn_hub_ip"]) —
# tunnel_plan itself has no notion of "main" vs "sub-unit", just "what do
# I need to route to". One route per other site in the group, via the
# hub's own tunnel IP.
t_plan_api = FakeApi({("ip", "route"): []})
t_plan_pusher = Pusher(t_cfg, t_plan_api, dry_run=True)
in_group_flat = {"_vpn_in_group": True, "_vpn_hub_ip": "10.10.0.1",
                 "_vpn_other_subnets": ["192.168.2.0/24", "192.168.3.0/24"]}
group_plan = F.tunnel_plan(t_plan_pusher, t_cfg, in_group_flat, {})
route_adds = [o for o in group_plan.ops
             if o.path == ("ip", "route") and o.action == "add"]
check("being in a group adds exactly one route per other site in it",
      len(route_adds) == 2)
check("each route's gateway is the hub's own tunnel IP",
      all(o.params.get("gateway") == "10.10.0.1" for o in route_adds))
check("each route's destination is the other site's subnet",
      {o.params.get("dst-address") for o in route_adds} ==
      {"192.168.2.0/24", "192.168.3.0/24"})
check("routes are tagged so only mikromon's own VPN routes are ever touched",
      all(o.params.get("comment") == _VPN_ROUTE_TAG for o in route_adds))

# idempotent: re-applying against a router that already has both routes is a no-op
t_plan_api2 = FakeApi({("ip", "route"): [
    {".id": "*1", "dst-address": "192.168.2.0/24", "gateway": "10.10.0.1",
     "comment": _VPN_ROUTE_TAG},
    {".id": "*2", "dst-address": "192.168.3.0/24", "gateway": "10.10.0.1",
     "comment": _VPN_ROUTE_TAG},
]})
t_plan_pusher2 = Pusher(t_cfg, t_plan_api2, dry_run=True)
check("re-applying the same group state is a no-op",
      F.tunnel_plan(t_plan_pusher2, t_cfg, in_group_flat, {}).empty)

# not part of any group: any previously-owned routes are removed
not_grouped_flat = {"_vpn_in_group": False, "_vpn_hub_ip": "10.10.0.1",
                    "_vpn_other_subnets": []}
leave_plan = F.tunnel_plan(t_plan_pusher2, t_cfg, not_grouped_flat, {})
route_removes = [o for o in leave_plan.ops
                if o.path == ("ip", "route") and o.action == "remove"]
check("leaving the group (or never joining) removes every route mikromon "
      "owns here",
      len(route_removes) == 2)

# an unrelated hand-made route is never touched
t_plan_api3 = FakeApi({("ip", "route"): [
    {".id": "*9", "dst-address": "172.16.0.0/24", "gateway": "192.168.1.254",
     "comment": "hand-made static route"},
]})
t_plan_pusher3 = Pusher(t_cfg, t_plan_api3, dry_run=True)
untouched_plan = F.tunnel_plan(t_plan_pusher3, t_cfg, not_grouped_flat, {})
check("a route mikromon doesn't own is never modified or removed",
      not any(o.params.get("dst-address") == "172.16.0.0/24"
              for o in untouched_plan.ops))

# The forward-chain firewall rule: a route alone isn't enough for LAN-to-LAN
# site-to-site traffic to actually pass — RouterOS's default/hardened forward
# policy can silently drop it. tunnel_plan looks up this router's own
# dial-home WireGuard interface (tagged "mikromon:tunnel:if" during
# provisioning) and adds a forward-chain accept for it in both directions.
FW = ("ip", "firewall", "filter")
_VPN_FW_TAG = F._VPN_FW_TAG
t_fw_api = FakeApi({
    ("ip", "route"): [],
    WG: [{"name": "mikromon", "comment": "mikromon:tunnel:if"}],
})
t_fw_pusher = Pusher(t_cfg, t_fw_api, dry_run=True)
fw_plan = F.tunnel_plan(t_fw_pusher, t_cfg, in_group_flat, {})
fw_adds = [o for o in fw_plan.ops if o.path == FW and o.action == "add"]
check("being in a group with a found WG interface adds exactly 2 forward "
      "rules (in + out)", len(fw_adds) == 2)
check("one forward rule matches on in-interface (WG -> LAN direction)",
      any(o.params.get("in-interface") == "mikromon" for o in fw_adds))
check("the other matches on out-interface (LAN -> WG direction)",
      any(o.params.get("out-interface") == "mikromon" for o in fw_adds))
check("both forward rules accept and are tagged as mikromon's own",
      all(o.params.get("action") == "accept"
          and str(o.params.get("comment", "")).startswith(_VPN_FW_TAG)
          for o in fw_adds))
check("both are placed at the very front of the filter list, so an existing "
      "\"drop everything else\" rule further down can't shadow them",
      all(o.params.get("place-before") == 0 for o in fw_adds))

# idempotent: already-tagged forward rules aren't re-added
t_fw_api2 = FakeApi({
    ("ip", "route"): [
        {".id": "*1", "dst-address": "192.168.2.0/24", "gateway": "10.10.0.1",
         "comment": _VPN_ROUTE_TAG},
        {".id": "*2", "dst-address": "192.168.3.0/24", "gateway": "10.10.0.1",
         "comment": _VPN_ROUTE_TAG},
    ],
    WG: [{"name": "mikromon", "comment": "mikromon:tunnel:if"}],
    FW: [
        {".id": "*10", "chain": "forward", "in-interface": "mikromon",
         "action": "accept", "comment": _VPN_FW_TAG + "in"},
        {".id": "*11", "chain": "forward", "out-interface": "mikromon",
         "action": "accept", "comment": _VPN_FW_TAG + "out"},
    ],
})
t_fw_pusher2 = Pusher(t_cfg, t_fw_api2, dry_run=True)
check("re-applying with both routes AND forward rules already in place is "
      "a total no-op",
      F.tunnel_plan(t_fw_pusher2, t_cfg, in_group_flat, {}).empty)

# leaving the group removes the forward rules too, not just the routes
leave_fw_plan = F.tunnel_plan(t_fw_pusher2, t_cfg, not_grouped_flat, {})
fw_removes = [o for o in leave_fw_plan.ops if o.path == FW and o.action == "remove"]
check("leaving the group removes both forward rules",
      {o.params.get(".id") for o in fw_removes} == {"*10", "*11"})

# a router that's grouped but whose own WireGuard interface can't be found
# (e.g. pre-7.1 firmware, or a stray read failure) skips the firewall step
# entirely rather than guessing an interface name or crashing.
t_fw_api3 = FakeApi({("ip", "route"): []})  # no ("interface","wireguard") at all
t_fw_pusher3 = Pusher(t_cfg, t_fw_api3, dry_run=True)
no_iface_plan = F.tunnel_plan(t_fw_pusher3, t_cfg, in_group_flat, {})
check("no WireGuard interface found -> no forward-rule ops attempted "
      "(routes still get added normally)",
      not any(o.path == FW for o in no_iface_plan.ops)
      and any(o.path == ("ip", "route") for o in no_iface_plan.ops))

# The router's OWN hub-peer allowed-address must ALSO be extended to every
# other site's subnet — the fix for the actual root cause found live: a
# route + firewall rule alone are not enough, because WireGuard itself
# silently drops decrypted traffic whose inner source isn't covered by the
# receiving peer's allowed-address (fixed by default to just the hub's own
# tunnel pool, e.g. 10.10.0.0/16 — never a remote site's LAN subnet).
t_peer_api = FakeApi({
    ("ip", "route"): [],
    WG: [{"name": "mikromon", "comment": "mikromon:tunnel:if"}],
    WGP: [{".id": "*p1", "comment": "mikromon:tunnel:hub",
          "allowed-address": "10.10.0.0/16"}],
})
t_peer_pusher = Pusher(t_cfg, t_peer_api, dry_run=True)
peer_plan = F.tunnel_plan(t_peer_pusher, t_cfg, in_group_flat, {})
peer_sets = [o for o in peer_plan.ops if o.path == WGP and o.action == "set"]
check("being in a group extends the hub peer's allowed-address to include "
      "every other site's subnet", len(peer_sets) == 1
      and peer_sets[0].params.get("allowed-address") ==
          "10.10.0.0/16, 192.168.2.0/24, 192.168.3.0/24")
check("the hub peer .id is targeted correctly (not a blind update)",
      peer_sets[0].params.get(".id") == "*p1")

# idempotent: already extended (any order/spacing) -> no-op
t_peer_api2 = FakeApi({
    ("ip", "route"): [
        {".id": "*1", "dst-address": "192.168.2.0/24", "gateway": "10.10.0.1",
         "comment": _VPN_ROUTE_TAG},
        {".id": "*2", "dst-address": "192.168.3.0/24", "gateway": "10.10.0.1",
         "comment": _VPN_ROUTE_TAG},
    ],
    WG: [{"name": "mikromon", "comment": "mikromon:tunnel:if"}],
    FW: [
        {".id": "*10", "chain": "forward", "in-interface": "mikromon",
         "action": "accept", "comment": _VPN_FW_TAG + "in"},
        {".id": "*11", "chain": "forward", "out-interface": "mikromon",
         "action": "accept", "comment": _VPN_FW_TAG + "out"},
    ],
    WGP: [{".id": "*p1", "comment": "mikromon:tunnel:hub",
          "allowed-address": "192.168.3.0/24,10.10.0.0/16,192.168.2.0/24"}],
})
t_peer_pusher2 = Pusher(t_cfg, t_peer_api2, dry_run=True)
check("re-applying with the hub peer already correctly extended (different "
      "order/spacing) is a total no-op",
      F.tunnel_plan(t_peer_pusher2, t_cfg, in_group_flat, {}).empty)

# leaving the group reverts the hub peer back to JUST the hub's own pool
leave_peer_plan = F.tunnel_plan(t_peer_pusher2, t_cfg, not_grouped_flat, {})
leave_peer_sets = [o for o in leave_peer_plan.ops
                  if o.path == WGP and o.action == "set"]
check("leaving the group reverts the hub peer's allowed-address to just "
      "the hub pool, dropping the other sites' subnets",
      len(leave_peer_sets) == 1
      and leave_peer_sets[0].params.get("allowed-address") == "10.10.0.0/16")

# no hub peer configured at all (e.g. router never provisioned for the
# tunnel) -> nothing to extend, no crash
t_peer_api3 = FakeApi({("ip", "route"): [],
                       WG: [{"name": "mikromon",
                            "comment": "mikromon:tunnel:if"}]})
t_peer_pusher3 = Pusher(t_cfg, t_peer_api3, dry_run=True)
no_peer_plan = F.tunnel_plan(t_peer_pusher3, t_cfg, in_group_flat, {})
check("no hub peer configured -> no allowed-address ops attempted, no crash",
      not any(o.path == WGP for o in no_peer_plan.ops))

# hub_endpoint_ops: for migrating the hub to a new server/IP (or a DDNS
# hostname) without re-provisioning every router by hand — updates ONLY
# endpoint-address/endpoint-port on the router's own hub-peer entry, never
# touching allowed-address (so it never undoes a VPN-group extension).
hep_api = FakeApi({
    WGP: [{".id": "*h1", "comment": "mikromon:tunnel:hub",
          "endpoint-address": "203.0.113.9", "endpoint-port": "51820",
          "allowed-address": "10.10.0.0/16, 192.168.2.0/24"}],
})
hep_plan = F.hub_endpoint_ops(Pusher(t_cfg, hep_api, dry_run=True),
                              "new.hub.example.com", "51821")
check("moving the hub updates endpoint-address and endpoint-port",
      len(hep_plan) == 1
      and hep_plan[0].params.get("endpoint-address") == "new.hub.example.com"
      and hep_plan[0].params.get("endpoint-port") == "51821")
check("moving the hub never touches allowed-address (would undo a VPN-"
      "group extension)", "allowed-address" not in hep_plan[0].params)

check("already pointed at the requested endpoint -> no-op",
      F.hub_endpoint_ops(Pusher(t_cfg, hep_api, dry_run=True),
                         "203.0.113.9", "51820") == [])

hep_api_none = FakeApi({WGP: []})
check("no hub peer configured -> no ops, no crash",
      F.hub_endpoint_ops(Pusher(t_cfg, hep_api_none, dry_run=True),
                         "new.hub.example.com", "51821") == [])

# hub_endpoint_ops(..., pubkey=...): a full identity migration — the NEW
# server generated its own fresh keypair (never moved a private key
# between hosts by hand), so a router needs both its new address AND its
# new public key pushed together.
hep_api2 = FakeApi({
    WGP: [{".id": "*h2", "comment": "mikromon:tunnel:hub",
          "endpoint-address": "old.hub.example.com", "endpoint-port": "51820",
          "public-key": "OLDPUBKEY=", "allowed-address": "10.10.0.0/16"}],
})
hep_plan2 = F.hub_endpoint_ops(Pusher(t_cfg, hep_api2, dry_run=True),
                               "new.hub.example.com", "51820",
                               pubkey="NEWPUBKEY=")
check("supplying pubkey= also updates the hub peer's public-key",
      len(hep_plan2) == 1
      and hep_plan2[0].params.get("public-key") == "NEWPUBKEY="
      and hep_plan2[0].params.get("endpoint-address") == "new.hub.example.com")
check("still never touches allowed-address even during a full identity move",
      "allowed-address" not in hep_plan2[0].params)

check("re-applying the same new pubkey+address is a no-op",
      F.hub_endpoint_ops(Pusher(t_cfg, FakeApi({
          WGP: [{".id": "*h2", "comment": "mikromon:tunnel:hub",
                "endpoint-address": "new.hub.example.com",
                "endpoint-port": "51820", "public-key": "NEWPUBKEY=",
                "allowed-address": "10.10.0.0/16"}]}), dry_run=True),
          "new.hub.example.com", "51820", pubkey="NEWPUBKEY=") == [])

hep_plan3 = F.hub_endpoint_ops(Pusher(t_cfg, hep_api2, dry_run=True),
                               "yet-another.example.com", "51820")
check("pubkey=None (the default) moves the address only, never touching "
      "public-key — same behavior as before this parameter existed",
      len(hep_plan3) == 1 and "public-key" not in hep_plan3[0].params)

# web.py's grouping actions validate subnet conflicts before ever writing to
# hub.json, but tunnel_plan still refuses defensively if _vpn_error is set.
err_flat = {"_vpn_in_group": True,
           "_vpn_error": "That network overlaps with the VPN tunnel network "
                         "(10.10.0.0/16) — pick a different one.",
           "_vpn_hub_ip": "10.10.0.1", "_vpn_other_subnets": []}
try:
    F.tunnel_plan(t_plan_pusher, t_cfg, err_flat, {})
    check("tunnel_plan raises on a subnet conflict instead of silently applying", False)
except PushError as exc:
    check("tunnel_plan raises PushError with the conflict message",
          "overlaps" in str(exc))


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


# ---- 15. gateway failover: recursive routes + RouterOS check-gateway=ping --
print("gateway failover (routes tab):")
from mikromon.config import WanEndpoint  # noqa: E402

_FO_TAG = "mikromon:failover:"
link_fibre = WanEndpoint(interface="ether1", name="Fibre")
link_backup = WanEndpoint(interface="ether5", name="Backup")
link_wireless = WanEndpoint(interface="ether10", name="Wireless")
fo_cfg = _t.SimpleNamespace(
    name="R1", wan=_t.SimpleNamespace(links=[link_fibre, link_backup, link_wireless]))
fo_router_state = {
    ("ip", "route"): [],
    ("tool", "netwatch"): [],
    ("interface", "pppoe-client"): [],
    ("ip", "dhcp-client"): [
        {".id": "*1", "interface": "ether1", "gateway": "10.0.0.1"},
        {".id": "*2", "interface": "ether5", "gateway": "10.0.1.1"},
        {".id": "*3", "interface": "ether10", "gateway": "10.0.2.1", "disabled": "true"},
    ],
    ("interface", "l2tp-client"): [],
    ("ppp", "active"): [],
    ("ip", "address"): [],
}
fo_api = FakeApi(dict(fo_router_state))
fo_pusher = Pusher(fo_cfg, fo_api, dry_run=False)
enable_plan = F.routes_plan(fo_pusher, fo_cfg, {"fo_enabled": "1"}, {})
route_adds = [o for o in enable_plan.ops if o.path == ("ip", "route") and o.action == "add"]
main_adds = {o.params["comment"]: o for o in route_adds}

check("ALL 3 configured links get a failover route (not just primary/secondary)",
      {o.params["comment"] for o in route_adds} ==
      {f"{_FO_TAG}primary", f"{_FO_TAG}secondary", f"{_FO_TAG}link3"})
check("route comments use the internal mikromon:failover: tag",
      f"{_FO_TAG}primary" in main_adds)
check("no netwatch entries are created — plain distance-based routes only, "
      "by explicit request (no check IP, no check-gateway, no script)",
      not any(o.path == ("tool", "netwatch") and o.action == "add"
             for o in enable_plan.ops))
check("each link's default route uses its own REAL detected gateway "
      "directly (no check IP, no recursion)",
      main_adds[f"{_FO_TAG}primary"].params["gateway"] == "10.0.0.1"
      and main_adds[f"{_FO_TAG}secondary"].params["gateway"] == "10.0.1.1")
check("check-gateway/target-scope are NOT set on these routes — no "
      "RouterOS-side health check, by explicit request",
      "check-gateway" not in main_adds[f"{_FO_TAG}primary"].params
      and "target-scope" not in main_adds[f"{_FO_TAG}primary"].params)
check("link3's own route distance is 3 (position + 1, no explicit Distance set)",
      main_adds[f"{_FO_TAG}link3"].params["distance"] == "3")
check("no RouterOS scripts use invalid $(var) shell-style syntax",
      not any("$(" in str(v) for o in enable_plan.ops
             for v in o.params.values() if isinstance(v, str)))
check("ALL configured WAN clients get add-default-route=no when enabling",
      sum(1 for o in enable_plan.ops if o.action == "set"
          and o.params.get("add-default-route") == "no") == 3)

# Apply it, then re-plan: should be a no-op (idempotent, no flapping churn).
for op in enable_plan.ops:
    fo_api.execute(op)
replan = F.routes_plan(fo_pusher, fo_cfg,
                       {"fo_enabled": "1"}, {})
check("re-applying the same enabled config is a no-op (no churn/flapping)",
      not any(o.path in (("ip", "route"), ("tool", "netwatch")) for o in replan.ops))

# Now disable failover: must remove ALL managed routes (one per configured
# link) AND restore every configured link's own routing — add-default-
# route=yes and disabled=no always, but default-route-distance ONLY if the
# link has an explicit Distance chosen (none of these 3 do), since that
# field is never touched while failover is on and so already holds
# whatever it was before failover started.
disable_plan = F.routes_plan(fo_pusher, fo_cfg, {"fo_enabled": ""}, {})
removed_routes = {o.params[".id"] for o in disable_plan.ops
                  if o.path == ("ip", "route") and o.action == "remove"}
check("disabling removes all 3 managed failover routes (one per link)",
      len(removed_routes) == 3)
dhcp_restores = [o for o in disable_plan.ops if o.path == ("ip", "dhcp-client")]
check("ALL 3 configured links get restored",
      {o.params[".id"] for o in dhcp_restores} == {"*1", "*2", "*3"})
check("restored clients get add-default-route=yes",
      any(o.params.get("add-default-route") == "yes"
          and o.params[".id"] == "*1" for o in dhcp_restores))
check("none of these links has an explicit Distance, so default-route-"
      "distance is left untouched entirely (not overwritten with a guess)",
      not any("default-route-distance" in o.params for o in dhcp_restores))
check("restored clients get disabled=no",
      any(o.params.get("disabled") == "no" and o.params[".id"] == "*3"
          for o in dhcp_restores))
check("no interface is ever bounced (disable/enable) to force a change "
      "live — that line may carry mikromon's own connection to the "
      "router, so an automatic reconnect risks a self-lockout",
      not any(o.params.get(".id") == "*1" and "disabled" in o.params
             for o in disable_plan.ops))

# Safe ordering, per link — the actual regression reported live: turning
# failover off/on removed or disabled every link's routing all at once
# before any of it was restored, and since mikromon's own connection to
# the router typically rides over one of these WAN links, that left the
# router with no default route at all for the whole gap, sometimes
# dropping the push mid-apply before it ever reached the fix for that
# link. Ops for a given link must never leave a window with nothing
# covering it: the replacement must exist before the original is torn
# down, link by link, not route-removal-for-everyone then restore-for-
# everyone (or route-add-for-everyone then disable-for-everyone).
def _idx(ops, pred):
    return next((i for i, o in enumerate(ops) if pred(o)), None)


for role, cid in (("primary", "*1"), ("secondary", "*2"), ("link3", "*3")):
    add_idx = _idx(enable_plan.ops, lambda o, r=role: o.path == ("ip", "route")
                   and o.action == "add" and o.params.get("comment") == f"{_FO_TAG}{r}")
    disable_client_idx = _idx(
        enable_plan.ops, lambda o, c=cid: o.path == ("ip", "dhcp-client")
        and o.params.get(".id") == c and o.params.get("add-default-route") == "no")
    check(f"enabling: {role}'s static route is added before its own client "
          f"is told to stop routing (never every route first, then every "
          f"client after)",
          add_idx is not None and disable_client_idx is not None
          and add_idx < disable_client_idx)

    restore_idx = _idx(
        disable_plan.ops, lambda o, c=cid: o.path == ("ip", "dhcp-client")
        and o.params.get(".id") == c and o.params.get("add-default-route") == "yes")
    remove_idx = _idx(
        disable_plan.ops, lambda o, r=role: o.action == "remove"
        and o.desc == f"remove failover route comment={_FO_TAG}{r}")
    check(f"disabling: {role}'s client is restored (add-default-route=yes) "
          f"before its own static route is removed (never every route "
          f"removed first, then every client restored after)",
          restore_idx is not None and remove_idx is not None
          and restore_idx < remove_idx)

# Confirmed live: some RouterOS versions/menus report add-default-route as
# "false" instead of "no" over the API — a strict == "no" comparison would
# never detect that it needs restoring, silently leaving the checkbox
# unticked forever after turning failover off. Every add-default-route
# check must tolerate both spellings, same as the existing "disabled" checks.
tf_link = WanEndpoint(interface="Wikiworx", name="Wikiworx")
tf_cfg = _t.SimpleNamespace(name="R1", wan=_t.SimpleNamespace(links=[tf_link]))
tf_api = FakeApi({
    ("ip", "route"): [
        {".id": "*10", "comment": "mikromon:failover:primary",
         "dst-address": "0.0.0.0/0", "gateway": "10.0.0.1", "distance": "1"},
        {".id": "*11", "comment": "mikromon:failover:check:primary",
         "dst-address": "1.1.1.1/32", "gateway": "10.0.0.1", "distance": "1"},
    ],
    ("tool", "netwatch"): [
        {".id": "*20", "comment": "mikromon:failover:watch:primary", "host": "1.1.1.1"},
    ],
    ("interface", "pppoe-client"): [
        {".id": "*1", "name": "Wikiworx", "add-default-route": "false", "disabled": "false"},
    ],
    ("ip", "dhcp-client"): [],
    ("interface", "l2tp-client"): [], ("ppp", "active"): [], ("ip", "address"): [],
})
tf_pusher = Pusher(tf_cfg, tf_api, dry_run=False)
tf_plan = F.routes_plan(tf_pusher, tf_cfg, {"fo_enabled": ""}, {})
check("add-default-route reported as \"false\" (not \"no\") is still "
      "correctly detected as off and restored to yes when failover turns off",
      any(o.path == ("interface", "pppoe-client") and o.action == "set"
          and o.params.get("add-default-route") == "yes" for o in tf_plan.ops))

# PPP/PPPoE links get NO managed static route at all — every gateway value
# ever tried for one (interface name, the interface's own address) turned
# out unreliable on real hardware. RouterOS's own PPP client already routes
# correctly on its own the moment the session connects, so these links stay
# at add-default-route=yes (restored here since it was "false") and only
# get their priority set directly via default-route-distance.
tf_api_on = FakeApi({
    ("ip", "route"): [],
    ("tool", "netwatch"): [],
    ("interface", "pppoe-client"): [
        {".id": "*1", "name": "Wikiworx", "add-default-route": "false", "disabled": "false"},
    ],
    ("ip", "dhcp-client"): [],
    ("interface", "l2tp-client"): [], ("ppp", "active"): [], ("ip", "address"): [],
})
tf_plan_on = F.routes_plan(Pusher(tf_cfg, tf_api_on, dry_run=False), tf_cfg,
                          {"fo_enabled": "1"}, {})
check("a PPP link's client has add-default-route restored to yes when "
      "enabling failover — tolerating the \"false\" spelling, not just \"no\"",
      any(o.path == ("interface", "pppoe-client") and o.action == "set"
          and o.params.get(".id") == "*1"
          and o.params.get("add-default-route") == "yes" for o in tf_plan_on.ops))
check("a PPP link never gets a managed static route at all — no gateway "
      "value ever proved reliably usable for one",
      not any(o.path == ("ip", "route") and o.action == "add" for o in tf_plan_on.ops))
check("a PPP link's priority is set directly on the client's own "
      "default-route-distance instead (position-based: 1, no explicit "
      "Distance chosen)",
      any(o.path == ("interface", "pppoe-client") and o.action == "set"
          and o.params.get(".id") == "*1"
          and o.params.get("default-route-distance") == "1" for o in tf_plan_on.ops))

# Confirmed live via the router's own system log: mikromon never sent a
# single "pppoe client changed" command for a link, while its DHCP-based
# siblings got restored fine — because the WAN uplinks editor's Interface
# text ("Wikiworx") differed in case from the router's actual PPPoE client
# name ("wikiworx"). An exact == match silently (no error) treats that as
# "not found" and skips the link entirely, indistinguishable from nothing
# being wrong until you check the router's own log.
case_link = WanEndpoint(interface="Wikiworx", name="Wikiworx")
case_cfg = _t.SimpleNamespace(name="R1", wan=_t.SimpleNamespace(links=[case_link]))
case_api = FakeApi({
    ("ip", "route"): [
        {".id": "*10", "comment": "mikromon:failover:primary",
         "dst-address": "0.0.0.0/0", "gateway": "10.0.0.1", "distance": "1"},
        {".id": "*11", "comment": "mikromon:failover:check:primary",
         "dst-address": "1.1.1.1/32", "gateway": "10.0.0.1", "distance": "1"},
    ],
    ("tool", "netwatch"): [
        {".id": "*20", "comment": "mikromon:failover:watch:primary", "host": "1.1.1.1"},
    ],
    # The router's own PPPoE client is "wikiworx" — lowercase, unlike the
    # WAN uplinks editor's "Wikiworx".
    ("interface", "pppoe-client"): [
        {".id": "*1", "name": "wikiworx", "add-default-route": "no", "disabled": "false"},
    ],
    ("ip", "dhcp-client"): [],
    ("interface", "l2tp-client"): [], ("ppp", "active"): [], ("ip", "address"): [],
})
case_plan = F.routes_plan(Pusher(case_cfg, case_api, dry_run=False), case_cfg,
                          {"fo_enabled": ""}, {})
check("a case mismatch between the WAN uplinks editor's Interface text and "
      "the router's actual PPPoE client name is still matched and restored "
      "(not silently skipped)",
      any(o.path == ("interface", "pppoe-client") and o.action == "set"
          and o.params.get("add-default-route") == "yes" for o in case_plan.ops))

# Same case-insensitive matching needed when ENABLING failover (setting
# the client's own default-route-distance) — not just the disable/restore
# path. This is a PPP link, so it gets no managed route at all — only its
# own default-route-distance field, matched case-insensitively.
case_api_on = FakeApi({
    ("ip", "route"): [], ("tool", "netwatch"): [],
    ("interface", "pppoe-client"): [
        {".id": "*1", "name": "wikiworx", "add-default-route": "yes", "disabled": "false"}],
    ("ip", "dhcp-client"): [],
    ("interface", "l2tp-client"): [],
    ("ppp", "active"): [{"name": "wikiworx", "remote-address": "10.0.0.1"}],
    ("ip", "address"): [],
})
case_plan_on = F.routes_plan(Pusher(case_cfg, case_api_on, dry_run=False), case_cfg,
                            {"fo_enabled": "1"}, {})
check("a PPP link never gets a managed route, even with a case mismatch "
      "between the WAN editor's text and the router's actual client name",
      not any(o.path == ("ip", "route") and o.action == "add" for o in case_plan_on.ops))
check("the case-insensitive match still finds the client to set its "
      "default-route-distance when enabling",
      any(o.path == ("interface", "pppoe-client") and o.action == "set"
          and o.params.get(".id") == "*1"
          and o.params.get("default-route-distance") == "1" for o in case_plan_on.ops))

# 4 uplinks: each gets its own route with its own real gateway and its own
# priority distance — no shared/aliased state between links.
uniq_a = WanEndpoint(interface="Wikiworx", name="Wikiworx", distance=1)
uniq_b = WanEndpoint(interface="ether5", name="Backup", distance=11)
uniq_c = WanEndpoint(interface="ether3", name="Third", distance=12)
uniq_d = WanEndpoint(interface="ether4", name="Fourth")
uniq_cfg = _t.SimpleNamespace(
    name="R1", wan=_t.SimpleNamespace(links=[uniq_a, uniq_b, uniq_c, uniq_d]))
uniq_api = FakeApi({
    ("ip", "route"): [], ("tool", "netwatch"): [],
    ("interface", "pppoe-client"): [
        {".id": "*1", "name": "Wikiworx", "add-default-route": "yes", "disabled": "false"}],
    ("ip", "dhcp-client"): [
        {".id": "*2", "interface": "ether5", "gateway": "10.0.1.1",
         "add-default-route": "yes", "disabled": "false"},
        {".id": "*3", "interface": "ether3", "gateway": "10.0.2.1",
         "add-default-route": "yes", "disabled": "false"},
        {".id": "*4", "interface": "ether4", "gateway": "10.0.3.1",
         "add-default-route": "yes", "disabled": "false"},
    ],
    ("interface", "l2tp-client"): [],
    ("ppp", "active"): [{"name": "Wikiworx", "remote-address": "10.0.0.1"}],
    ("ip", "address"): [],
})
uniq_plan = F.routes_plan(Pusher(uniq_cfg, uniq_api, dry_run=False), uniq_cfg,
                          {"fo_enabled": "1"}, {})
uniq_route_adds = [o for o in uniq_plan.ops
                  if o.path == ("ip", "route") and o.action == "add"]
uniq_gws = {o.params["comment"]: o.params["gateway"] for o in uniq_route_adds}
check("only the 3 DHCP links get a managed route — the PPP link (Wikiworx) "
      "never does",
      len(uniq_route_adds) == 3)
check("each of the 3 DHCP links' routes uses its own distinct real gateway",
      len(set(uniq_gws.values())) == 3)
check("the PPP link (Wikiworx) gets its priority set directly on its own "
      "client instead of a route",
      any(o.path == ("interface", "pppoe-client") and o.action == "set"
          and o.params.get("default-route-distance") == "1" for o in uniq_plan.ops))

# link_type is an explicit override for auto-detection (WAN tab's
# "Connection type") — auto-detection is normally reliable, but has no way
# to be corrected by hand if it ever guesses wrong for a given interface.
override_link = WanEndpoint(interface="Wikiworx", name="Wikiworx",
                            link_type="dhcp")  # force DHCP handling on a real PPP interface
override_cfg = _t.SimpleNamespace(name="R1", wan=_t.SimpleNamespace(links=[override_link]))
override_api = FakeApi({
    ("ip", "route"): [], ("tool", "netwatch"): [],
    ("interface", "pppoe-client"): [
        {".id": "*1", "name": "Wikiworx", "add-default-route": "yes", "disabled": "false"}],
    ("ip", "dhcp-client"): [],
    ("interface", "l2tp-client"): [],
    ("ppp", "active"): [{"name": "Wikiworx", "remote-address": "10.0.0.1"}],
    ("ip", "address"): [],
})
override_plan = F.routes_plan(Pusher(override_cfg, override_api, dry_run=False),
                              override_cfg, {"fo_enabled": "1"}, {})
check("link_type='dhcp' forces the managed-route strategy even on a real "
      "PPP interface (an explicit override, honored as asked)",
      any(o.path == ("ip", "route") and o.action == "add"
          and o.params.get("gateway") == "10.0.0.1" for o in override_plan.ops))
check("with link_type='dhcp' forced, the client's own default-route-distance "
      "is left alone (that field is now irrelevant — a static route owns "
      "priority instead)",
      not any(o.path == ("interface", "pppoe-client") and o.action == "set"
             and "default-route-distance" in o.params for o in override_plan.ops))

# Forcing link_type='ppp' on an interface that ISN'T actually a PPPoE
# client on the router must be a safe no-op (no route, no client field
# found to set) rather than crashing or guessing something.
wrong_override_link = WanEndpoint(interface="ether9", name="Nope", link_type="ppp")
wrong_override_cfg = _t.SimpleNamespace(
    name="R1", wan=_t.SimpleNamespace(links=[wrong_override_link]))
wrong_override_api = FakeApi({
    ("ip", "route"): [], ("tool", "netwatch"): [],
    ("interface", "pppoe-client"): [],
    ("ip", "dhcp-client"): [],
    ("interface", "l2tp-client"): [], ("ppp", "active"): [], ("ip", "address"): [],
})
wrong_override_plan = F.routes_plan(
    Pusher(wrong_override_cfg, wrong_override_api, dry_run=False),
    wrong_override_cfg, {"fo_enabled": "1"}, {})
check("forcing link_type='ppp' on an interface that isn't really a PPPoE "
      "client is a safe no-op, not a crash",
      wrong_override_plan.empty)

# Pre-existing tag-based failover routes/netwatch (from an earlier apply)
# must be recognized as ours and cleaned up when disabling.
tagged_api = FakeApi({
    ("ip", "route"): [
        {".id": "*9", "comment": "mikromon:failover:primary",
         "dst-address": "0.0.0.0/0", "gateway": "10.0.0.1", "distance": "1"},
        {".id": "*10", "comment": "mikromon:failover:check:primary",
         "dst-address": "1.1.1.1/32", "gateway": "10.0.0.1", "distance": "1"},
    ],
    ("tool", "netwatch"): [
        {".id": "*11", "comment": "mikromon:failover:watch:primary", "host": "1.1.1.1"},
    ],
    ("interface", "pppoe-client"): [],
    ("ip", "dhcp-client"): [
        {".id": "*1", "interface": "ether1", "gateway": "10.0.0.1"},
    ],
    ("interface", "l2tp-client"): [],
    ("ppp", "active"): [],
    ("ip", "address"): [],
})
tagged_cfg = _t.SimpleNamespace(name="R1", wan=_t.SimpleNamespace(links=[link_fibre]))
tagged_pusher = Pusher(tagged_cfg, tagged_api, dry_run=False)
tagged_disable = F.routes_plan(tagged_pusher, tagged_cfg, {"fo_enabled": ""}, {})
check("tag-based failover routes are recognized as ours and removed",
      {o.params[".id"] for o in tagged_disable.ops
       if o.path == ("ip", "route") and o.action == "remove"} == {"*9", "*10"})
check("tag-based netwatch entry is recognized as ours and removed",
      {o.params[".id"] for o in tagged_disable.ops
       if o.path == ("tool", "netwatch") and o.action == "remove"} == {"*11"})

# detect_wan_gateways: the WAN tab's "detected gateway" display reuses the
# exact same detection _apply_failover uses, deliberately ignoring any
# manual override already saved on the link (the whole point is to show
# what would be auto-detected, for comparison against — or confirmation
# of — that override).
dwg_links = [WanEndpoint(interface="Axxess", name="Axxess", gateway="9.9.9.9"),
            WanEndpoint(interface="ether2", name="Backup")]
dwg_api = FakeApi({
    ("interface", "pppoe-client"): [{"name": "Axxess"}],
    ("ip", "dhcp-client"): [{"interface": "ether2", "gateway": "172.17.232.254"}],
    ("ppp", "active"): [],
    ("ip", "address"): [],
})
dwg = F.detect_wan_gateways(dwg_api, dwg_links)
check("detect_wan_gateways ignores a saved manual override — it reports "
      "what auto-detection alone would find (falls back to the interface "
      "name here, since PPP-active/ip-address gave nothing usable)",
      dwg["Axxess"] == "Axxess")
check("detect_wan_gateways finds a DHCP link's real gateway",
      dwg["ether2"] == "172.17.232.254")

# Confirmed live: the interface's OWN assigned address (/ip/address's
# 'address' field) is NOT a usable gateway — it's this router's own IP, not
# a next hop — even though it can look like a plausible fallback candidate.
# Detection must never use it; when ppp-active and the 'network' field both
# give nothing, it falls back to the interface name instead (still a
# separate, deliberate design choice — see _gateway_for_link).
ownaddr_links = [WanEndpoint(interface="Axxess", name="Axxess")]
ownaddr_api = FakeApi({
    ("interface", "pppoe-client"): [{"name": "Axxess"}],
    ("ip", "dhcp-client"): [],
    ("ppp", "active"): [{"name": "Axxess"}],  # no remote-address field at all
    ("ip", "address"): [{"interface": "Axxess", "address": "100.127.128.105/32"}],
})
ownaddr_dwg = F.detect_wan_gateways(ownaddr_api, ownaddr_links)
check("never falls back to the interface's own assigned address — that's "
      "this router's own IP, not a real gateway, even when nothing else "
      "is available",
      ownaddr_dwg["Axxess"] == "Axxess")

# A real 'network' field (the actual documented remote-end case) is still
# used correctly when it IS available.
network_api = FakeApi({
    ("interface", "pppoe-client"): [{"name": "Axxess"}],
    ("ip", "dhcp-client"): [],
    ("ppp", "active"): [],
    ("ip", "address"): [{"interface": "Axxess", "address": "100.127.128.105/32",
                        "network": "41.2.3.4"}],
})
network_dwg = F.detect_wan_gateways(network_api, ownaddr_links)
check("a real distinct 'network' (remote-end) value is used when available",
      network_dwg["Axxess"] == "41.2.3.4")

# ---- 16. explicit per-uplink Distance (WAN uplinks editor) -----------------
print("explicit WAN uplink distance (auto-detects the router client; saved "
      "immediately but NOT force-reconnected — see the safety note above):")
dist_wiki = WanEndpoint(interface="Wikiworx", name="Wikiworx", distance=1)
dist_backup = WanEndpoint(interface="ether2-backup", name="Backup", distance=5)
dist_voip = WanEndpoint(interface="ether3-voip", name="VoIP")  # no explicit distance
dist_cfg = _t.SimpleNamespace(
    name="R1", wan=_t.SimpleNamespace(links=[dist_wiki, dist_backup, dist_voip]))
dist_state = {
    ("ip", "route"): [],
    ("tool", "netwatch"): [],
    ("interface", "pppoe-client"): [
        {".id": "*1", "name": "Wikiworx", "add-default-route": "yes",
         "default-route-distance": "1", "disabled": "false"},
    ],
    ("ip", "dhcp-client"): [
        {".id": "*2", "interface": "ether2-backup", "add-default-route": "yes",
         "default-route-distance": "1", "disabled": "false"},
        {".id": "*3", "interface": "ether3-voip", "add-default-route": "yes",
         "default-route-distance": "1", "disabled": "false"},
    ],
    ("interface", "l2tp-client"): [],
    ("ppp", "active"): [],
    ("ip", "address"): [],
}
dist_api = FakeApi(dict(dist_state))
dist_pusher = Pusher(dist_cfg, dist_api, dry_run=False)
dist_plan = F.routes_plan(dist_pusher, dist_cfg, {"fo_enabled": ""}, {})
dist_sets = [o for o in dist_plan.ops if o.action == "set"
            and "default-route-distance" in o.params]
check("Wikiworx is already at its chosen distance (1) — no churn for it",
      "*1" not in {o.params.get(".id") for o in dist_sets}
      and not any(o.params.get(".id") == "*1" for o in dist_plan.ops))
check("the changed link's distance is set to the chosen value (5)",
      any(o.params[".id"] == "*2" and o.params["default-route-distance"] == "5"
          for o in dist_sets))
check("changing the distance does NOT bounce the interface — it's saved on "
      "the client for the next natural reconnect, not forced live (that "
      "line may carry mikromon's own connection to the router)",
      not any(o.params.get(".id") == "*2" and "disabled" in o.params
             for o in dist_plan.ops))
check("a link with no explicit distance never gets its default-route-"
      "distance touched (left exactly as it was before failover started)",
      not any(o.params.get(".id") == "*3" and "default-route-distance" in o.params
             for o in dist_plan.ops))
check("re-applying the same chosen distances is a no-op (idempotent, no "
      "repeated reconnects)",
      not any("default-route-distance" in o.params or "disabled" in o.params
             for o in F.routes_plan(
                 Pusher(dist_cfg, FakeApi({
                     ("ip", "route"): [], ("tool", "netwatch"): [],
                     ("interface", "pppoe-client"): [
                         {".id": "*1", "name": "Wikiworx", "add-default-route": "yes",
                          "default-route-distance": "1", "disabled": "false"}],
                     ("ip", "dhcp-client"): [
                         {".id": "*2", "interface": "ether2-backup",
                          "add-default-route": "yes", "default-route-distance": "5",
                          "disabled": "false"},
                         {".id": "*3", "interface": "ether3-voip",
                          "add-default-route": "yes", "default-route-distance": "3",
                          "disabled": "false"}],
                     ("interface", "l2tp-client"): [], ("ppp", "active"): [],
                     ("ip", "address"): [],
                 }), dry_run=False),
                 dist_cfg, {"fo_enabled": ""}, {}).ops))

# With failover ON, a 3rd link's explicit Distance becomes the distance of
# ITS OWN static failover route (failover now manages every configured
# link, not just primary/secondary) — the client's own default-route-
# distance field is irrelevant at that point since add-default-route=no.
dist_wiki2 = WanEndpoint(interface="Wikiworx", name="Wikiworx", distance=1)
dist_backup2 = WanEndpoint(interface="ether2-backup", name="Backup", distance=2)
dist_voip2 = WanEndpoint(interface="ether3-voip", name="VoIP", distance=9)
fo_dist_cfg = _t.SimpleNamespace(
    name="R1", wan=_t.SimpleNamespace(links=[dist_wiki2, dist_backup2, dist_voip2]))
fo_dist_state = dict(dist_state)
fo_dist_state[("ip", "dhcp-client")] = [
    {".id": "*2", "interface": "ether2-backup", "gateway": "10.0.1.1",
     "add-default-route": "yes", "default-route-distance": "1", "disabled": "false"},
    {".id": "*3", "interface": "ether3-voip", "gateway": "10.0.3.1",
     "add-default-route": "yes", "default-route-distance": "1", "disabled": "false"},
]
fo_dist_api = FakeApi(fo_dist_state)
fo_dist_pusher = Pusher(fo_dist_cfg, fo_dist_api, dry_run=False)
fo_dist_plan = F.routes_plan(fo_dist_pusher, fo_dist_cfg,
                             {"fo_enabled": "1", "fo_primary_check": "1.1.1.1",
                              "fo_secondary_check": "8.8.8.8"}, {})
voip_route_adds = [o for o in fo_dist_plan.ops if o.path == ("ip", "route")
                   and o.action == "add" and o.params["comment"] == "mikromon:failover:link3"]
check("a 3rd managed link's static failover route uses its own explicit "
      "Distance (9), not the auto position value (3)",
      any(o.params["distance"] == "9" for o in voip_route_adds))
check("the 3rd link's own DHCP client is not separately touched for "
      "distance while failover manages it via a static route",
      not any(o.params.get(".id") == "*3" and "default-route-distance" in o.params
             for o in fo_dist_plan.ops))

# Explicit "snapshot" scenario: a link with no chosen Distance keeps
# WHATEVER default-route-distance is already on the router (42 — set there
# by something outside mikromon before failover was ever touched), while a
# link WITH an explicit Distance is forced to exactly that value and
# nothing else, regardless of what's currently on the router.
snap_link_a = WanEndpoint(interface="ether1", name="A", distance=7)
snap_link_b = WanEndpoint(interface="ether5", name="B")  # no explicit distance
snap_cfg = _t.SimpleNamespace(name="R1", wan=_t.SimpleNamespace(links=[snap_link_a, snap_link_b]))
snap_api = FakeApi({
    ("ip", "route"): [
        {".id": "*10", "comment": "mikromon:failover:primary",
         "dst-address": "0.0.0.0/0", "gateway": "10.0.0.1", "distance": "7"},
        {".id": "*11", "comment": "mikromon:failover:check:primary",
         "dst-address": "1.1.1.1/32", "gateway": "10.0.0.1", "distance": "1"},
        {".id": "*12", "comment": "mikromon:failover:secondary",
         "dst-address": "0.0.0.0/0", "gateway": "10.0.1.1", "distance": "2"},
        {".id": "*13", "comment": "mikromon:failover:check:secondary",
         "dst-address": "8.8.8.8/32", "gateway": "10.0.1.1", "distance": "1"},
    ],
    ("tool", "netwatch"): [
        {".id": "*20", "comment": "mikromon:failover:watch:primary", "host": "1.1.1.1"},
        {".id": "*21", "comment": "mikromon:failover:watch:secondary", "host": "8.8.8.8"},
    ],
    ("interface", "pppoe-client"): [],
    ("ip", "dhcp-client"): [
        {".id": "*1", "interface": "ether1", "gateway": "10.0.0.1",
         "add-default-route": "no", "default-route-distance": "99", "disabled": "false"},
        {".id": "*2", "interface": "ether5", "gateway": "10.0.1.1",
         "add-default-route": "no", "default-route-distance": "42", "disabled": "false"},
    ],
    ("interface", "l2tp-client"): [], ("ppp", "active"): [], ("ip", "address"): [],
})
snap_pusher = Pusher(snap_cfg, snap_api, dry_run=False)
snap_plan = F.routes_plan(snap_pusher, snap_cfg, {"fo_enabled": ""}, {})
check("a link WITH an explicit Distance is forced to exactly that value "
      "(7), ignoring whatever is currently on the router (99)",
      any(o.params.get(".id") == "*1" and o.params.get("default-route-distance") == "7"
          for o in snap_plan.ops))
check("a link with NO explicit Distance keeps its untouched pre-failover "
      "value (42) — nothing computed, nothing overwritten",
      not any(o.params.get(".id") == "*2" and "default-route-distance" in o.params
             for o in snap_plan.ops))
check("both links get add-default-route=yes (never left at no) regardless "
      "of whether their distance changed",
      all(any(o.params.get(".id") == cid and o.params.get("add-default-route") == "yes"
             for o in snap_plan.ops) for cid in ("*1", "*2")))
check("neither link is bounced (disabled/enabled) to force anything live",
      not any("disabled" in o.params for o in snap_plan.ops))


# ---- 16. Routes tab display: PPPoE distance/status must not always read as
#          "1"/unknown just because add-default-route=no hides the field ----
print("routes tab display (PPPoE distance shown correctly, not stuck at 1):")
# Confirmed live: with gateway failover on, add-default-route=no on every
# client makes RouterOS omit default-route-distance from the API response,
# so the Routes tab falls back to reading the distance off the matching
# 0.0.0.0/0 route instead. For a PPPoE/L2TP client that fallback compared
# the route's gateway (an IP — the PPP remote-address) against the client's
# own NAME ("Wikiworx") — never equal — so it always fell through to the
# hardcoded "1" default, even though the failover route actually holds the
# real chosen distance (10).
disp_cfg = _t.SimpleNamespace(
    name="R1", wan=_t.SimpleNamespace(links=[
        WanEndpoint(interface="Wikiworx", name="Wikiworx", distance=10),
        WanEndpoint(interface="ether2", name="Backup", distance=11)]))
disp_state = {
    ("ip", "route"): [
        # The failover static route for the PPPoE link: gateway is the PPP
        # remote address (what _gateway_for_link actually uses), not "Wikiworx".
        {".id": "*1", "comment": "mikromon:failover:primary",
         "dst-address": "0.0.0.0/0", "gateway": "41.2.3.4", "distance": "10",
         "active": "true"},
        {".id": "*2", "comment": "mikromon:failover:secondary",
         "dst-address": "0.0.0.0/0", "gateway": "10.0.1.1", "distance": "11",
         "active": "false"},
    ],
    ("tool", "netwatch"): [],
    ("interface", "pppoe-client"): [
        {".id": "*3", "name": "wikiworx", "running": "true",
         "add-default-route": "no"},  # field hidden while add-default-route=no
    ],
    ("ip", "dhcp-client"): [
        {".id": "*4", "interface": "ether2", "gateway": "10.0.1.1",
         "status": "bound", "add-default-route": "no"},
    ],
    ("interface", "l2tp-client"): [],
    ("ppp", "active"): [
        {"name": "wikiworx", "remote-address": "41.2.3.4"},
    ],
    ("ip", "address"): [],
}
disp_current = F.routes_read(Pusher(disp_cfg, FakeApi(dict(disp_state)), dry_run=True), disp_cfg)

# This is exactly the screenshot's condition: failover on, so add-default-
# route=no on every client, and RouterOS omits default-route-distance from
# the API entirely — _wan_sortable_items (the Routes tab's drag-order list)
# computes distance unconditionally regardless of that, so it's the one
# that must show the real value here.
items = F._wan_sortable_items(disp_current)
ppp_item = next((it for it in items if it["id"].startswith("pppoe:")), None)
check("the Routes tab's drag-order list shows the PPPoE primary's real "
      "distance (10), not the old always-1 fallback",
      ppp_item is not None and ppp_item["_dist"] == "10")
dhcp_item = next((it for it in items if it["id"].startswith("dhcp:")), None)
check("the DHCP backup's distance in the drag-order list still reads "
      "correctly (unaffected by this fix)",
      dhcp_item is not None and dhcp_item["_dist"] == "11")

# Distance-based direct-gateway design: a managed route's own "gateway"
# field IS the real ISP gateway directly (no recursion, no substitution
# needed), so the Routes tab's client-to-route matching (by gateway) works
# unmodified — confirms this stays true for the current design.
rec_cfg = _t.SimpleNamespace(
    name="R1", wan=_t.SimpleNamespace(links=[
        WanEndpoint(interface="Wikiworx", name="Wikiworx", distance=10),
        WanEndpoint(interface="ether2", name="Backup", distance=11)]))
rec_state = {
    ("ip", "route"): [
        {".id": "*1", "comment": "mikromon:failover:primary",
         "dst-address": "0.0.0.0/0", "gateway": "41.2.3.4",
         "distance": "10", "active": "true"},
        {".id": "*3", "comment": "mikromon:failover:secondary",
         "dst-address": "0.0.0.0/0", "gateway": "10.0.1.1",
         "distance": "11", "active": "false"},
    ],
    ("tool", "netwatch"): [],
    ("interface", "pppoe-client"): [
        {".id": "*5", "name": "wikiworx", "running": "true",
         "add-default-route": "no"},
    ],
    ("ip", "dhcp-client"): [
        {".id": "*6", "interface": "ether2", "gateway": "10.0.1.1",
         "status": "bound", "add-default-route": "no"},
    ],
    ("interface", "l2tp-client"): [],
    ("ppp", "active"): [{"name": "wikiworx", "remote-address": "41.2.3.4"}],
    ("ip", "address"): [],
}
rec_current = F.routes_read(Pusher(rec_cfg, FakeApi(dict(rec_state)), dry_run=True), rec_cfg)
rec_items = F._wan_sortable_items(rec_current)
rec_ppp = next((it for it in rec_items if it["id"].startswith("pppoe:")), None)
rec_dhcp = next((it for it in rec_items if it["id"].startswith("dhcp:")), None)
check("the PPPoE primary's real distance (10) is shown on the drag-order list",
      rec_ppp is not None and rec_ppp["_dist"] == "10")
check("the DHCP secondary's real distance (11) is shown, distinct from "
      "the primary's",
      rec_dhcp is not None and rec_dhcp["_dist"] == "11")

# The Routes tab's Failover summary line must make it obvious when a link
# has no detectable gateway IP (PPP-active/DHCP gave nothing usable, so
# _gateway_for_link fell back to routing via the interface itself) instead
# of silently showing the same "via X" text either way — reported live as
# confusing/looking broken with no way to tell from the dashboard alone.
rec_summary = F.routes_summary(rec_current, rec_cfg)
fo_primary_line = next((ln for ln in rec_summary if ln.startswith("Failover primary")), "")
check("a real gateway IP is shown plainly",
      "via 41.2.3.4" in fo_primary_line)

fallback_state = {**rec_state,
    ("ip", "route"): [
        {".id": "*1", "comment": "mikromon:failover:primary",
         "dst-address": "0.0.0.0/0", "gateway": "Axxess",
         "distance": "10", "active": "true"},
    ],
}
fallback_current = F.routes_read(
    Pusher(rec_cfg, FakeApi(dict(fallback_state)), dry_run=True), rec_cfg)
fallback_summary = F.routes_summary(fallback_current, rec_cfg)
fallback_line = next((ln for ln in fallback_summary
                     if ln.startswith("Failover primary")), "")
check("falling back to the interface itself (no gateway IP detected) is "
      "called out explicitly, with a hint to re-apply",
      "no gateway IP found" in fallback_line and "re-applying" in fallback_line)

# The current (no-managed-route) design for PPP links: no "Failover primary
# via ..." route line exists at all since there's no managed route — the
# summary must still report something useful for that link, reading the
# client's own connection state and distance directly. This is what a
# PPP link actually looks like after applying under the current design:
# add-default-route=yes (restored) with default-route-distance set.
noroute_state = {**rec_state,
    ("ip", "route"): [],
    ("interface", "pppoe-client"): [
        {".id": "*5", "name": "wikiworx", "running": "true",
         "add-default-route": "yes", "default-route-distance": "10"},
    ],
}
noroute_current = F.routes_read(
    Pusher(rec_cfg, FakeApi(dict(noroute_state)), dry_run=True), rec_cfg)
noroute_summary = F.routes_summary(noroute_current, rec_cfg)
noroute_line = next((ln for ln in noroute_summary
                    if ln.startswith("Failover primary")), "")
check("a PPP link with no managed route (the current design) reports its "
      "own connection state and distance instead of going silent",
      "via its own PPP connection" in noroute_line
      and "connected" in noroute_line and "distance 10" in noroute_line)

# routes_summary's own route-status text ("route active"/"route inactive")
# only appears on the add-default-route=yes branch (a plain, non-failover
# line) and goes through the same _route_status_for fix — it reads distance
# straight off the client's own field (unaffected by this bug), but the
# status lookup had the identical route.gateway-vs-client.name mismatch.
disp_state_plain = {**disp_state,
    ("interface", "pppoe-client"): [
        {".id": "*3", "name": "wikiworx", "running": "true",
         "add-default-route": "yes", "default-route-distance": "10"},
    ],
}
disp_current_plain = F.routes_read(
    Pusher(disp_cfg, FakeApi(dict(disp_state_plain)), dry_run=True), disp_cfg)
disp_lines = F.routes_summary(disp_current_plain, disp_cfg)
ppp_line = next((ln for ln in disp_lines if ln.startswith("PPPOE")), "")
check("routes_summary's PPPoE line resolves route status (matched via "
      "ppp/active remote-address, not the client's name), not blank",
      "route active" in ppp_line)

# routes_plan (what the Routes tab's Apply button actually runs) must never
# be influenced by the Routes tab's own read-only drag-order list
# ("wan_order" in the submitted form data). It used to run a second pass
# (_apply_wan_order) driven by that list, which submitted back on EVERY
# apply regardless of whether the user touched it — silently overwriting
# each client's default-route-distance with a sequential rank (1, 2, 3...)
# instead of the explicit Distance chosen on the WAN tab (10, 11, 12).
# Confirmed live: a router already correctly at distance 10/11/12 got its
# DHCP backups reset to 2/3 on the very next Routes-tab apply, even with
# the drag list left untouched. Distance has exactly one source of truth
# now (link.distance) — a PPP link's client DOES get default-route-distance
# set directly (that's the current, intentional design, unrelated to this
# bug), but only ever to that one real value, never a wan_order-derived rank.
order_plan = F.routes_plan(
    Pusher(disp_cfg, FakeApi(dict(disp_state)), dry_run=True), disp_cfg,
    {"fo_enabled": "1"},
    {"wan_order": ["pppoe:3", "dhcp:4"]})
ppp_dist_ops = [o for o in order_plan.ops
               if o.path == ("interface", "pppoe-client")
               and "default-route-distance" in o.params]
check("wan_order data is completely ignored by routes_plan",
      not any(o.path in (("ip", "dhcp-client"), ("interface", "l2tp-client"))
             and "default-route-distance" in o.params
             for o in order_plan.ops)
      and len(ppp_dist_ops) <= 1)
check("the PPP client's default-route-distance, when set, is always the "
      "real explicit Distance from the WAN tab (10) — never a "
      "wan_order-derived sequential rank (1, 2, 3...)",
      all(o.params["default-route-distance"] == "10" for o in ppp_dist_ops))


print("nextdns_cloud_ops (the DNS tab's NextDNS box — a real NextDNS.io cloud "
      "profile per router, distinct from the unrelated 'nextdns' local "
      "DNS-filter feature above):")
_NDRES = ("system", "resource")
DNS = ("ip", "dns")
nd_cfg = types.SimpleNamespace(name="R1", nextdns_enabled=False, nextdns_profile_id="")

# nextdns_cloud_ops: enabling with a profile id sets use-doh-server + verify-doh-cert.
nd_api = FakeApi({_NDRES: [{"version": "7.14.3"}], DNS: [{".id": "*1"}]})
nd_pusher = Pusher(nd_cfg, nd_api, dry_run=True)
enable_plan = F.nextdns_cloud_ops(nd_pusher, "abc123")
check("enabling sets use-doh-server to this router's own NextDNS profile URL",
      any(o.params.get("use-doh-server") == "https://dns.nextdns.io/abc123"
          for o in enable_plan.ops))
check("enabling also turns on verify-doh-cert",
      any(o.params.get("verify-doh-cert") == "yes" for o in enable_plan.ops))

# Disabling (empty profile_id) clears use-doh-server, touches nothing else.
nd_api2 = FakeApi({_NDRES: [{"version": "7.14.3"}],
                   DNS: [{".id": "*1", "use-doh-server":
                          "https://dns.nextdns.io/abc123"}]})
disable_plan = F.nextdns_cloud_ops(Pusher(nd_cfg, nd_api2, dry_run=True), "")
check("disabling clears use-doh-server",
      any(o.params.get("use-doh-server") == "" for o in disable_plan.ops)
      and not any("verify-doh-cert" in o.params for o in disable_plan.ops))

# Already in the desired state -> no ops (idempotent). Needs an existing
# `servers` entry, allow-remote-requests already on, AND the force-DNS NAT
# rules already present — any one of those being off/missing is exactly
# what the checks below cover, and would no longer be a no-op.
nd_api3 = FakeApi({_NDRES: [{"version": "7.14.3"}],
                   DNS: [{".id": "*1", "use-doh-server":
                          "https://dns.nextdns.io/abc123",
                          "verify-doh-cert": "yes",
                          "servers": "9.9.9.9,149.112.112.112",
                          "allow-remote-requests": "true"}],
                   ("ip", "firewall", "nat"): [
                       {".id": "*10", "chain": "dstnat", "protocol": "udp",
                        "dst-port": "53", "action": "redirect",
                        "to-ports": "53", "comment": "mikromon:dnsforce:udp"},
                       {".id": "*11", "chain": "dstnat", "protocol": "tcp",
                        "dst-port": "53", "action": "redirect",
                        "to-ports": "53", "comment": "mikromon:dnsforce:tcp"},
                   ]})
check("already-enabled router with a working bootstrap resolver, "
      "allow-remote-requests on, AND the force-DNS NAT rules already "
      "present -> empty plan",
      F.nextdns_cloud_ops(Pusher(nd_cfg, nd_api3, dry_run=True), "abc123").empty)

# DoH needs an ordinary resolver to look up the DoH server's own hostname —
# a router with use-doh-server already set but an EMPTY `servers` list has
# nothing to resolve dns.nextdns.io with, so DNS never comes up at all even
# though "enabling" appeared to succeed. Confirmed the actual cause of a
# live "NextDNS says enabled but doesn't connect" report.
nd_api_nobootstrap = FakeApi({_NDRES: [{"version": "7.14.3"}],
                              DNS: [{".id": "*1", "use-doh-server":
                                     "https://dns.nextdns.io/abc123",
                                     "verify-doh-cert": "yes"}]})
bootstrap_plan = F.nextdns_cloud_ops(
    Pusher(nd_cfg, nd_api_nobootstrap, dry_run=True), "abc123")
check("enabling with no existing DNS servers fills in a bootstrap resolver "
      "so the DoH hostname itself can be resolved",
      any(o.params.get("servers") == "9.9.9.9,149.112.112.112"
          for o in bootstrap_plan.ops))

# An existing Quick DNS provider preset (e.g. AdGuard) is now OVERRIDDEN,
# not left alone — confirmed live: leaving it in place still left that
# preset's own toggle showing "on" on the DNS tab, reading as if it and
# NextDNS were two competing providers rather than NextDNS being the only
# thing actually in effect once enabled.
nd_api_existing_servers = FakeApi({_NDRES: [{"version": "7.14.3"}],
                                   DNS: [{".id": "*1",
                                          "servers": "94.140.14.14,94.140.15.15"}]})
existing_servers_plan = F.nextdns_cloud_ops(
    Pusher(nd_cfg, nd_api_existing_servers, dry_run=True), "abc123")
check("enabling overrides an existing Quick DNS provider preset with the "
      "neutral bootstrap pair",
      any(o.params.get("servers") == "9.9.9.9,149.112.112.112"
          for o in existing_servers_plan.ops))
check("that neutral bootstrap pair doesn't overlap ANY Quick DNS preset's "
      "own IPs, so enabling also clears every preset's toggle back off "
      "(none of them would still show as active on the DNS tab)",
      not ({"9.9.9.9", "149.112.112.112"} &
           frozenset().union(*(set(s.split(","))
                               for s in F._DNS_PRESET_SERVERS.values()))))

# allow-remote-requests is what lets the router answer DNS queries FROM
# LAN clients at all — without it, DoH is correctly configured but only
# ever benefits the router itself; every client silently falls back to
# its own/ISP DNS instead, looking exactly like "NextDNS isn't being
# used" even though "enabling" reported success. Confirmed the actual
# cause of a live report matching that description.
nd_api_no_remote = FakeApi({_NDRES: [{"version": "7.14.3"}],
                            DNS: [{".id": "*1", "servers": "1.1.1.1",
                                   "allow-remote-requests": "false"}]})
remote_plan = F.nextdns_cloud_ops(
    Pusher(nd_cfg, nd_api_no_remote, dry_run=True), "abc123")
check("enabling turns on allow-remote-requests when it's off",
      any(o.params.get("allow-remote-requests") == "true"
          for o in remote_plan.ops))
nd_api_remote_already_on = FakeApi({_NDRES: [{"version": "7.14.3"}],
                                    DNS: [{".id": "*1", "servers": "1.1.1.1",
                                           "allow-remote-requests": "true"}]})
already_on_plan = F.nextdns_cloud_ops(
    Pusher(nd_cfg, nd_api_remote_already_on, dry_run=True), "abc123")
check("enabling with allow-remote-requests already on doesn't re-set it",
      not any("allow-remote-requests" in o.params for o in already_on_plan.ops))

# allow-remote-requests only helps a client that actually ASKS the router
# for DNS — one with its own manually-set resolver never asks, and keeps
# bypassing NextDNS entirely. Enabling now also forces every client's
# port-53 traffic to the router (the DNS tab's own "force client DNS" NAT
# redirect, requested explicitly so this stops being a manual second step).
force_ops = [o for o in enable_plan.ops if o.path == ("ip", "firewall", "nat")
            and o.action == "add"]
check("enabling also adds the force-client-DNS NAT redirect (udp+tcp on "
      "port 53), not just the DNS-level settings",
      len(force_ops) == 2
      and all(o.params.get("action") == "redirect"
              and o.params.get("dst-port") == "53"
              and o.params.get("comment", "").startswith("mikromon:dnsforce:")
              for o in force_ops)
      and {o.params.get("protocol") for o in force_ops} == {"udp", "tcp"})
nd_api_force_already_on = FakeApi({
    _NDRES: [{"version": "7.14.3"}],
    DNS: [{".id": "*1", "servers": "1.1.1.1",
          "allow-remote-requests": "true"}],
    ("ip", "firewall", "nat"): [
        {".id": "*10", "chain": "dstnat", "protocol": "udp", "dst-port": "53",
         "action": "redirect", "to-ports": "53",
         "comment": "mikromon:dnsforce:udp"},
        {".id": "*11", "chain": "dstnat", "protocol": "tcp", "dst-port": "53",
         "action": "redirect", "to-ports": "53",
         "comment": "mikromon:dnsforce:tcp"},
    ]})
force_already_on_plan = F.nextdns_cloud_ops(
    Pusher(nd_cfg, nd_api_force_already_on, dry_run=True), "abc123")
check("enabling with the force-DNS NAT rules already present doesn't "
      "re-add or churn them",
      not any(o.path == ("ip", "firewall", "nat")
              for o in force_already_on_plan.ops))

# Disabling never needs a bootstrap resolver, allow-remote-requests, or the
# force-DNS NAT redirect — it isn't establishing a new DoH connection, so
# none of these only-relevant-when-enabling fixes apply when profile_id is
# empty. Whether to keep forcing client DNS with NextDNS off is the DNS
# tab's own toggle's call, not this one's.
disable_no_servers_plan = F.nextdns_cloud_ops(
    Pusher(nd_cfg, nd_api_nobootstrap, dry_run=True), "")
check("disabling never adds a bootstrap resolver (only relevant when "
      "actually enabling DoH)",
      not any("servers" in o.params for o in disable_no_servers_plan.ops))
check("disabling never touches allow-remote-requests either",
      not any("allow-remote-requests" in o.params
              for o in disable_no_servers_plan.ops))
check("disabling never touches the force-DNS NAT redirect either",
      not any(o.path == ("ip", "firewall", "nat")
              for o in disable_no_servers_plan.ops))

# RouterOS version gate: DoH needs 7.1+; older firmware -> no attempt at all
# (there's no way to get a per-router NextDNS profile working without DoH).
nd_api_old = FakeApi({_NDRES: [{"version": "6.49.10"}], DNS: [{".id": "*1"}]})
old_plan = F.nextdns_cloud_ops(Pusher(nd_cfg, nd_api_old, dry_run=True), "abc123")
check("RouterOS 6.x (no DoH support) -> empty plan instead of a doomed set",
      old_plan.empty)
check("unsupported RouterOS is reflected in the plan's own summary",
      "7.1" in old_plan.summary)
# ... but clearing (disabling) an old-firmware router's DoH still works —
# there's nothing version-gated about clearing a field that's already set.
nd_api_old_set = FakeApi({_NDRES: [{"version": "6.49.10"}],
                          DNS: [{".id": "*1", "use-doh-server":
                                 "https://dns.nextdns.io/abc123"}]})
old_clear = F.nextdns_cloud_ops(Pusher(nd_cfg, nd_api_old_set, dry_run=True), "")
check("clearing an already-set use-doh-server still works even on RouterOS 6.x",
      any(o.params.get("use-doh-server") == "" for o in old_clear.ops))

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL PUSH ENGINE TESTS PASSED")
