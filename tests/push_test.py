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

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL PUSH ENGINE TESTS PASSED")
