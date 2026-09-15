"""Someone deleting OUR login off a router must not be silent.

Reported live: several routers were tampered with. The intruder created their
own logins and removed the monitoring account. The new logins alerted. The
removal -- the part that ends both the monitoring and the ability to put it
back -- said nothing at all, because removals were deliberately ignored.

That reasoning was right for other people's accounts and wrong for exactly
one. These tests pin down the difference, because making it alert on every
removal is how people learn to filter the whole lot.

Run:  ./.venv/Scripts/python.exe tests/user_tamper_test.py
"""
from __future__ import annotations

import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon.alert import Severity
from mikromon.checks.security import SecurityCheck

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


class Ctx:
    now = 0

    def __init__(self):
        self.events = []
        self.mem = {}

    def event(self, key, sev, title, **kw):
        self.events.append({"key": key, "sev": sev, "title": title,
                            "cause": kw.get("cause", "")})


class Snap:
    errors = ()

    def __init__(self, users):
        self._u = users

    def rows(self, key):
        return [{"name": n} for n in self._u] if key == "users" else []


def dev(username="mkmonitor", push=""):
    # engine.py calls check.run(snap, cfg, ctx) -- `dev` IS the DeviceConfig,
    # with the login fields directly on it. The first version of this fake
    # wrapped them in a .cfg attribute that nothing real has, so the test
    # asserted the bug instead of catching it.
    return types.SimpleNamespace(username=username, push_username=push)


def run(before, after, d=None):
    d = d or dev()
    c, ctx = SecurityCheck(), Ctx()
    c._scan_users(Snap(before), d, ctx, ctx.mem, True)   # seed
    ctx.events = []
    c._scan_users(Snap(after), d, ctx, ctx.mem, False)
    return ctx.events


print("\nThe account this dashboard depends on")

ev = run(["admin", "mkmonitor"], ["admin"])
check("deleting our monitoring login raises an alert at all -- it did not "
      "before, and the router simply began failing to authenticate, which "
      "reads exactly like a password drifting out of step",
      len(ev) == 1)
check("...as CRITICAL, because it ends the monitoring AND the ability to "
      "put it back",
      ev and ev[0]["sev"] is Severity.CRITICAL)
check("...naming the account, so it is actionable without opening the router",
      ev and "mkmonitor" in ev[0]["title"])
check("...and saying how to recover, which is the one thing the reader "
      "needs next",
      ev and "Provision" in ev[0]["cause"])

print("\nThe real incident: our login removed, theirs added")

ev = run(["admin", "mkmonitor"], ["admin", "hacker"])
keys = {e["key"] for e in ev}
check("both halves are reported -- the account that appeared and the one "
      "that vanished",
      any(k.startswith("router_user_gone:mkmonitor") for k in keys)
      and any(k.startswith("router_user:hacker") for k in keys))
check("the deletion outranks the creation in severity",
      max(e["sev"] for e in ev if e["key"].startswith("router_user_gone"))
      is Severity.CRITICAL)

print("\nStill quiet about everything else")

check("somebody else's account being removed says nothing, which is what "
      "keeps these alerts worth reading",
      run(["admin", "mkmonitor", "bob"], ["admin", "mkmonitor"]) == [])
check("an unchanged account list says nothing",
      run(["admin", "mkmonitor"], ["admin", "mkmonitor"]) == [])
check("the first poll of a router never alerts on accounts that were "
      "already there",
      not [e for e in run([], ["admin", "mkmonitor"]) if "gone" in e["key"]])

print("\nA separate push account is covered too")

ev = run(["admin", "mkmonitor", "mkpush"], ["admin", "mkmonitor"],
         d=dev("mkmonitor", "mkpush"))
check("a device configured with its own push login alerts when THAT is "
      "removed, since losing it ends config changes just the same",
      len(ev) == 1 and "mkpush" in ev[0]["title"])

print("\nNothing is claimed when the account list could not be read")

c, ctx = SecurityCheck(), Ctx()


class Broken(Snap):
    errors = ("users",)


c._scan_users(Broken([]), dev(), ctx, ctx.mem, False)
check("a failed read is not treated as every account having vanished -- "
      "that would alert the whole fleet at once on one bad poll",
      ctx.events == [])

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL USER-TAMPER TESTS PASSED")
