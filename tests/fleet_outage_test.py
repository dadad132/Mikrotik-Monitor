"""One fault at the monitoring end must not be reported as a dozen router
outages.

From a live diagnostics report: three routers, in two different companies, on
different ISPs, in different cities, all recovered at the same SECOND
(2026-09-07 14:43:31). Two more shared another second. Unrelated routers do
not fail and recover in lockstep -- one event on the monitoring side was
being recorded and emailed as a separate outage per router.

The half that is easy to get wrong is the undo. Silencing the alert but
leaving the condition flipped means the RECOVERY alert still arrives a minute
later, telling everyone their routers are back from an outage nobody was ever
told about. So the conditions are put back, not just the emails dropped.

Run:  ./.venv/Scripts/python.exe tests/fleet_outage_test.py
"""
from __future__ import annotations

import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon.alert import Alert, Severity
from mikromon.engine import Engine

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


class FakeState:
    def __init__(self, names):
        self.data = {"devices": {n: {"conditions": {}} for n in names}}

    def condition(self, device, key):
        return (self.data["devices"].setdefault(device, {"conditions": {}})
                ["conditions"].setdefault(key, {}))


def engine_with(names):
    """An Engine with just enough wired up to exercise the filter."""
    eng = Engine.__new__(Engine)
    eng.devices = [types.SimpleNamespace(name=n) for n in names]
    eng.state = FakeState(names)
    eng.now_fn = lambda: 1000.0
    return eng


def down(name):
    return Alert(name, "reachability", Severity.CRITICAL,
                 "Device UNREACHABLE")


def other(name, key="cpu"):
    return Alert(name, key, Severity.WARNING, "CPU high")


FLEET = [f"Branch {i:02d}" for i in range(15)]

print("\nA fault at the monitoring end")

eng = engine_with(FLEET)
before = {n: {} for n in FLEET}
batch = [down(n) for n in FLEET[:12]] + [other("Branch 13")]
out = eng._filter_fleet_wide_outage(batch, before)

check("twelve of fifteen routers going down in one cycle does not produce "
      "twelve emails",
      not any(a.key == "reachability" for a in out))
check("...it produces exactly one, about the monitoring end",
      sum(1 for a in out if a.key == "fleet_unreachable") == 1)
check("...naming how many and which, so it can be checked rather than "
      "taken on faith",
      any("12 of 15" in a.title for a in out)
      and any("Branch 00" in a.cause for a in out))
check("...and pointing at the things that actually cause it, since the "
      "reader's next question is what to look at",
      any("provisioned" in a.cause and "restarting" in a.cause for a in out))
check("unrelated alerts in the same cycle are untouched",
      any(a.key == "cpu" and a.device == "Branch 13" for a in out))

check("the recorded state is PUT BACK, not just the email dropped -- "
      "otherwise the recovery alert still arrives next cycle announcing "
      "routers are back from an outage nobody was told about",
      all(eng.state.condition(n, "reachability") == {} for n in FLEET[:12]))

print("\nReal outages still get through")

eng = engine_with(FLEET)
batch = [down("Branch 00"), down("Branch 01"), down("Branch 02")]
out = eng._filter_fleet_wide_outage(batch, {n: {} for n in FLEET})
check("three branches out of fifteen is a real outage, not a fleet event, "
      "and is alerted per router",
      len([a for a in out if a.key == "reachability"]) == 3
      and not any(a.key == "fleet_unreachable" for a in out))

eng = engine_with(FLEET)
out = eng._filter_fleet_wide_outage([down("Branch 00")], {n: {} for n in FLEET})
check("a single router going down always alerts", len(out) == 1
      and out[0].key == "reachability")

print("\nSmall installs are not mis-read")

eng = engine_with(["A", "B"])
out = eng._filter_fleet_wide_outage([down("A")], {"A": {}, "B": {}})
check("one of two devices is 50% of the fleet but is obviously just one "
      "router -- a fraction alone would have swallowed it",
      len(out) == 1 and out[0].key == "reachability")

eng = engine_with(["A", "B"])
out = eng._filter_fleet_wide_outage([down("A"), down("B")],
                                    {"A": {}, "B": {}})
check("...and even both of them is too few to conclude anything about the "
      "hub", len(out) == 2)

print("\nOnly NEW outages count")

eng = engine_with(FLEET)
# Eleven were already down and stay down; one is new. That is not a fleet
# event -- it is one router failing on a bad day.
prior = {n: ({"status": "problem"} if i < 11 else {})
         for i, n in enumerate(FLEET)}
out = eng._filter_fleet_wide_outage([down(n) for n in FLEET[:12]], prior)
check("routers that were ALREADY down are not counted again, so a fleet "
      "that has been half-offline for a week does not suppress the one "
      "branch that failed today",
      len([a for a in out if a.key == "reachability"]) == 12
      and not any(a.key == "fleet_unreachable" for a in out))

print("\nRecoveries are never swallowed")

eng = engine_with(FLEET)
ups = [Alert(n, "reachability", Severity.CRITICAL, "back", recovery=True)
       for n in FLEET[:12]]
out = eng._filter_fleet_wide_outage(ups, {n: {} for n in FLEET})
check("twelve routers coming back at once is good news and is passed "
      "through untouched", len(out) == 12)

print("\nNothing to do")

eng = engine_with(FLEET)
check("an empty cycle stays empty",
      eng._filter_fleet_wide_outage([], {n: {} for n in FLEET}) == [])

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL FLEET-OUTAGE TESTS PASSED")
