"""A change on a router whose flash has no room for the safety backup.

Nothing is sent unless the reader chooses to go ahead without a backup, and
then only after a warning that the change cannot be undone. With room on the
flash, the backup (and Safe mode) happen as always, whatever was asked.

Run: python tests/no_backup_test.py
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import web  # noqa: E402
from mikromon.push import FEATURES, FlashFullError, Pusher  # noqa: E402
from mikromon.push import safemode as sm  # noqa: E402
from mikromon.push.api import PushError  # noqa: E402
from mikromon.push.plan import Operation, Plan  # noqa: E402

FAILS = []
MB = 1024 * 1024


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


class FakeApi:
    """A router with a given amount of free flash, a scheduler table, and a
    record of everything sent to it."""

    def __init__(self, free):
        self.executed = []
        self.scheduler = []
        self.files = [{".id": "*90", "name": "routeros-7.16-arm.npk",
                       "size": str(9 * MB)}]
        self.free = free
        self.device = types.SimpleNamespace(ping=lambda addr, count=2: 0)

    def fetch(self, path):
        if path == ("file",):
            return [dict(f) for f in self.files]
        if path == ("system", "resource"):
            return [{"total-hdd-space": str(16 * MB),
                     "free-hdd-space": str(self.free)}]
        if path == ("system", "scheduler"):
            return [dict(r) for r in self.scheduler]
        return []

    def execute(self, op):
        self.executed.append(op)
        if op.path == ("system", "backup"):
            self.files.append({".id": "*b", "name": op.params["name"] + ".backup",
                               "size": "100000"})
        if op.path == ("system", "scheduler") and op.action == "add":
            self.scheduler.append({".id": "*new", **op.params})
            return "*new"
        return "*1" if op.action == "add" else None


class FakeAudit:
    def __init__(self):
        self.rows = []

    def append(self, *row):
        self.rows.append(row)


cfg = types.SimpleNamespace(name="R1", push_username="", push_password="")
change = Plan("R1", [Operation("add", ("ip", "firewall", "filter"),
                               {"chain": "input", "action": "drop"},
                               desc="the change")])
tracker = sm.SafeModeTracker(os.path.join(tempfile.mkdtemp(), "s.json"))


def sent(api):
    return [o.desc for o in api.executed]


print("a full flash, nothing chosen")
api = FakeApi(free=50 * 1024)
try:
    web._safe_apply(Pusher(cfg, api, dry_run=False), change, slug="security",
                    device="R1", hub_ip="10.10.0.1", safe=True, tracker=tracker)
    err = None
except PushError as exc:
    err = exc
check("the change is refused, as before", err is not None
      and "the change" not in sent(api))
check("...with its own kind of error, so the page can offer a way on",
      isinstance(err, FlashFullError))
check("...that says nothing was changed", "Nothing was changed" in str(err))

print("\na full flash, sent without a backup")
api = FakeApi(free=50 * 1024)
audit = FakeAudit()
armed = web._safe_apply(Pusher(cfg, api, dry_run=False, audit=audit, user="u"),
                        change, slug="security", device="R1",
                        hub_ip="10.10.0.1", safe=True, tracker=tracker,
                        no_backup=True)
check("the change goes out", "the change" in sent(api))
check("...without a backup", not any(o.path == ("system", "backup")
                                     for o in api.executed))
check("...and without a Safe mode timer, which would have nothing to restore",
      armed["token"] == "" and not any(
          o.action == "add" and o.path == ("system", "scheduler")
          for o in api.executed))
check("the result says it went out without a backup",
      armed["no_backup"] is True and armed["backup"] == "")
check("the activity log records that it cannot be undone",
      any(r[4] == "skipped" and "cannot be undone" in r[5]
          for r in audit.rows))

print("\nroom on the flash, 'without a backup' asked anyway")
api = FakeApi(free=8 * MB)
armed = web._safe_apply(Pusher(cfg, api, dry_run=False), change,
                        slug="security", device="R1", hub_ip="10.10.0.1",
                        safe=True, tracker=tracker, no_backup=True)
check("a backup is still made: skipping is only for a full flash",
      any(o.path == ("system", "backup") for o in api.executed)
      and armed["no_backup"] is False)
check("...and Safe mode is still armed", bool(armed["token"]))

print("\nwhat the page says")
try:
    web._safe_arm(Pusher(cfg, FakeApi(free=0), dry_run=False), slug="wan",
                  hub_ip="", safe=False, tracker=None)
    msg = ""
except FlashFullError as exc:
    msg = str(exc)
friendly = web._friendly_push_error(msg)
check("a full flash is not called 'could not reach the router'",
      "storage is too full" in friendly and "reach" not in friendly)
check("...and still names what is taking the space",
      "routeros-7.16-arm.npk" in friendly)

submitted = {"csrf": ["T"], "apply": ["1"], "device": ["R1"],
             "feature": ["security"], "safe_revert": ["1"], "opt": ["x"]}
box = web._no_backup_offer("R1", "security", "TOK", submitted, "/device/push")
form = re.search(r"<form.*?</form>", box, re.S).group(0)
fields = dict(re.findall(r'name="(\w+)" value="([^"]*)"', form))
check("the offer warns that there is no backup to go back to",
      "cannot be returned to a previous backup" in box
      and "not enough space" in box)
check("...and that Safe mode cannot protect it", "Safe mode" in box)
check("its button sends the same change again, marked 'no backup'",
      fields.get("no_backup") == "1" and fields.get("apply") == "1"
      and fields.get("opt") == "x" and fields.get("device") == "R1"
      and fields.get("feature") == "security" and fields.get("csrf") == "TOK")
check("...without Safe mode, which cannot work without the backup",
      "safe_revert" not in fields)
check("...only once 'I understand' is ticked",
      re.search(r'name="no_backup_ok" value="1" required', form) is not None)
check("the safer way, freeing up space, is offered beside it",
      "tab=backups" in box)

user = {"login": "o@a.c", "role": "owner", "org_id": 1}
page = web._render_feature_tab("R1", user, "security", FEATURES["security"],
                               "TOK", error=msg, submitted=submitted,
                               offer_no_backup=True)
check("the tab shows the offer under the error",
      "Send it without a backup?" in page and "storage is too full" in page)
page = web._render_feature_tab("R1", user, "security", FEATURES["security"],
                               "TOK", error="timed out", submitted=submitted)
check("other errors do not offer it", "Send it without a backup?" not in page)
page = web._render_feature_tab("R1", {**user, "role": "viewer"}, "security",
                               FEATURES["security"], "TOK", error=msg,
                               submitted=submitted, offer_no_backup=True,
                               can_manage=False)
check("someone who cannot manage the router is not offered it",
      "Send it without a backup?" not in page)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL NO-BACKUP TESTS PASSED")
