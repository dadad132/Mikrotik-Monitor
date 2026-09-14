"""A router that cannot save its own configuration must say so.

Found live, and it cost days. The router was reachable, our own API user was
logging into it successfully on every poll, and not one setting had persisted
for days. The dashboard showed it merely as "unprovisioned", so the script
was pasted again and again -- and every paste was accepted, reported success,
and changed nothing.

The router had been saying why in its own log the whole time:

    could not save configuration changes, no free inodes left.

The free-space check cannot catch this. RouterOS runs out of INODES -- how
many files it can hold -- long before bytes, so a board full of tiny log
fragments reports plenty of free space while being unable to write config.
That is the trap these tests pin down.

Run:  ./.venv/Scripts/python.exe tests/unsaveable_test.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon.alert import Severity
from mikromon.checks.resources import ResourceCheck

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


class Ctx:
    now = 0

    def __init__(self):
        self.fired = {}

    def sample(self, *a, **k):
        pass

    def threshold(self, key, value, **k):
        self.fired.setdefault("_gauges", {})[key] = value

    def memory(self, *a, **k):
        return {}

    def transition(self, key, healthy=True, **kw):
        self.fired[key] = {"healthy": healthy, "title": kw.get("title", ""),
                           "cause": kw.get("cause", ""),
                           "severity": kw.get("severity")}


class Snap:
    errors = ()

    def __init__(self, log, resource=None):
        self._log = log
        self.resource = resource if resource is not None else dict(_RES)

    def rows(self, key):
        return self._log if key == "log" else []


class Dev:
    def check_enabled(self, _):
        return True

    def th(self, _):
        return 10.0


# A board with ample free BYTES -- which is the whole point.
_RES = {"total-hdd-space": "16000000", "free-hdd-space": "9000000",
        "cpu-load": "5", "total-memory": "64000000",
        "free-memory": "30000000", "uptime": "1d2h", "version": "7.20.7",
        "board-name": "E50UG", "bad-blocks": "0"}


def run(log, resource=None):
    ctx = Ctx()
    try:
        ResourceCheck().run(Snap(log, resource), Dev(), ctx)
    except Exception:  # noqa: BLE001 — unrelated gauges need richer fixtures
        pass
    return ctx.fired.get("config_unsaveable")


print("\nReading it out of the router's own log")

# Verbatim from the router.
BAD = [{"message": "user mkmonitor logged in from 10.10.0.1 via api"},
       {"message": "could not save configuration changes, no free inodes left."},
       {"message": "user mkmonitor logged out from 10.10.0.1 via api"}]

got = run(BAD)
check("the exact line the router logs raises a condition",
      got is not None and got["healthy"] is False)
check("...as CRITICAL, because every change made anywhere is being lost "
      "while this is true",
      got and got["severity"] is Severity.CRITICAL)
check("...quoting what the router actually said, so it is recognisable "
      "against the log rather than being a paraphrase",
      got and "no free inodes left" in got["cause"])
check("...and saying what to do about it, since nothing in the dashboard "
      "can fix a full flash",
      got and "/file print" in got["cause"] and "reboot" in got["cause"])

check("the other wording RouterOS uses is caught too",
      (run([{"message": "could not save configuration changes"}]) or {})
      .get("healthy") is False)

check("matching is case-insensitive",
      (run([{"message": "COULD NOT SAVE CONFIGURATION CHANGES"}]) or {})
      .get("healthy") is False)

print("\nNot firing when it should not")

check("an ordinary log raises nothing",
      (run([{"message": "user mkmonitor logged in from 10.10.0.1 via api"},
            {"message": "system started"}]) or {}).get("healthy") is True)

check("an empty log raises nothing", (run([]) or {}).get("healthy") is True)

check("a router that merely MENTIONS inodes in passing is not condemned",
      (run([{"message": "script: checking inodes on the backup volume"}])
       or {}).get("healthy") is True)

print("\nWhy the free-space check could never have caught this")

got = run(BAD, dict(_RES, **{"free-hdd-space": "9000000",
                             "total-hdd-space": "16000000"}))
check("it fires on a board reporting 56% of its storage FREE -- inodes run "
      "out long before bytes do, which is exactly why the percentage-based "
      "storage check sat at OK throughout",
      got is not None and got["healthy"] is False)

print("\nRecovering")

check("once the router stops logging it, the condition clears by itself "
      "rather than needing anybody to acknowledge it",
      (run([{"message": "system started"}]) or {}).get("healthy") is True)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL UNSAVEABLE-CONFIG TESTS PASSED")
