"""A router restarted from the dashboard is Restarting, not an outage.

Press Reboot -- or update it, run a script that restarts it, restore a backup
-- and of course it goes offline for a minute or three. The monitor could not
tell that from a router falling over, so it emailed "Device UNREACHABLE" and
then "reachable again" about something the reader had just done, and the
dashboard showed it red.

Now the dashboard writes down that it is restarting a router, and the
monitor, which is a separate process, reads that on every poll:
  * a router it was told about that goes down in that window has its alerts
    held for five minutes, and is shown as Restarting
  * back within the five minutes, nobody is emailed -- not the outage, not
    the recovery
  * still down after them, the alert goes out, saying it was restarted from
    the dashboard and has not come back
  * a router that was NOT restarted from the dashboard is alerted on as ever

Run:  ./.venv/Scripts/python.exe tests/planned_restart_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import restarts as R  # noqa: E402
from mikromon import web  # noqa: E402
from mikromon.alert import Alert, Severity  # noqa: E402
from mikromon.engine import Engine  # noqa: E402
from mikromon.push import features as F  # noqa: E402

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


T0 = 1_800_000_000.0
d = tempfile.mkdtemp()
PATH = R.path_for(os.path.join(d, "devices.db"))

print("What the dashboard writes down")
check("the file lives beside the devices database",
      PATH == os.path.join(d, R.FILENAME) and R.path_for(None) == "")
R.plan(PATH, "R1", start=T0, latest=T0 + 120, why="Rebooted from the "
       "dashboard", by="owner@alpha.test", now=T0)
check("a restart starting now is expected now",
      "R1" in R.expected(PATH, T0 + 30))
check("...not before it begins (a minute's slack for clocks apart)",
      "R1" not in R.expected(PATH, T0 - 120) and "R1" in R.expected(PATH, T0 - 30))
check("...nor once it should long since have begun",
      "R1" not in R.expected(PATH, T0 + 121))
check("it says who did what", R.describe(R.expected(PATH, T0)["R1"])
      == "Rebooted from the dashboard by owner@alpha.test")
R.plan(PATH, "R2", start=T0 + 3600, latest=T0 + 3600 + 1200, now=T0)
check("a restart booked for later is not expected until then",
      "R2" not in R.expected(PATH, T0) and "R2" in R.expected(PATH, T0 + 3700))
R.cancel(PATH, "R2")
check("...and is gone when it is cancelled",
      "R2" not in R.expected(PATH, T0 + 3700))
R.plan(PATH, "R3", start=T0 + 10 * 86400, now=T0 + 10 * 86400)
check("records long past are dropped the next time the file is written",
      "R1" not in R._load(PATH) and "R3" in R._load(PATH))
R.plan("", "R1", start=T0)
check("without a devices database nothing is written and nothing breaks",
      R.expected("", T0) == {})


print("\nThe monitor holds a restarted router's alerts")


class FakeState:
    def __init__(self):
        self.data = {"devices": {}}

    def _dev(self, name):
        return self.data["devices"].setdefault(name, {"conditions": {},
                                                      "facts": {}})

    def condition(self, device, key):
        return self._dev(device)["conditions"].setdefault(key, {})

    def facts(self, device):
        return self._dev(device).setdefault("facts", {})


clock = {"now": T0}
eng = Engine.__new__(Engine)
eng.state = FakeState()
eng.now_fn = lambda: clock["now"]
eng._restarts_path = PATH


def down(name, key="reachability"):
    eng.state.condition(name, key)["status"] = "problem"
    return Alert(name, key, Severity.CRITICAL, "Device UNREACHABLE",
                 cause="No TCP response.")


def back(name, key="reachability"):
    eng.state.condition(name, key)["status"] = "ok"
    return Alert(name, key, Severity.CRITICAL, "Device reachable again",
                 recovery=True)


R.plan(PATH, "R1", start=T0, latest=T0 + 120, why="Rebooted from the "
       "dashboard", by="owner@alpha.test", now=T0)
clock["now"] = T0 + 100
out = eng._hold_planned_restarts([down("R1"), down("Other")])
check("a router restarted from the dashboard going offline is not emailed",
      [a.device for a in out] == ["Other"])
check("...but a router nobody restarted still is", any(
    a.device == "Other" and not a.recovery for a in out))
check("...and the restarted one is marked Restarting, with what happened "
      "and until when", eng.state.facts("R1")["restarting"]["what"]
      == "Rebooted from the dashboard by owner@alpha.test"
      and eng.state.facts("R1")["restarting"]["until"]
      == T0 + 100 + R.GRACE_SECONDS)
clock["now"] = T0 + 160
out = eng._hold_planned_restarts([down("R1", "api_error")])
check("whatever else it raises while it boots is held with it -- even after "
      "the window for the restart to begin has closed", out == [])
clock["now"] = T0 + 220
out = eng._hold_planned_restarts([back("R1"), back("R1", "api_error")])
check("back within five minutes: nobody hears about it, not even that it "
      "recovered", out == [])
check("...and the Restarting mark is taken off",
      "restarting" not in eng.state.facts("R1"))

print("\nStill down after five minutes")
R.plan(PATH, "R4", start=T0 + 1000, latest=T0 + 1120, why="Updated from the "
       "dashboard", by="owner@alpha.test", now=T0 + 1000)
clock["now"] = T0 + 1060
eng._hold_planned_restarts([down("R4")])
clock["now"] = T0 + 1060 + R.GRACE_SECONDS - 1
check("nothing is sent while the five minutes run",
      eng._hold_planned_restarts([]) == [])
clock["now"] = T0 + 1060 + R.GRACE_SECONDS
out = eng._hold_planned_restarts([])
check("at five minutes the offline alert goes out after all",
      len(out) == 1 and out[0].device == "R4" and not out[0].recovery
      and out[0].title == "Device UNREACHABLE")
check("...saying it was restarted from the dashboard and is not back",
      "Updated from the dashboard by owner@alpha.test, and not back 5 "
      "minutes later." in out[0].detail and out[0].ts == clock["now"])
check("...and it is Offline again, not Restarting",
      "restarting" not in eng.state.facts("R4"))
clock["now"] += 60
out = eng._hold_planned_restarts([back("R4")])
check("when it does come back, that recovery is announced: the outage was",
      len(out) == 1 and out[0].recovery)

print("\nA problem it already had")
eng.state.condition("R5", "cpu")["status"] = "problem"
R.plan(PATH, "R5", start=T0 + 2000, latest=T0 + 2120, now=T0 + 2000)
clock["now"] = T0 + 2010
eng._hold_planned_restarts([down("R5")])
out = eng._hold_planned_restarts([back("R5", "cpu")])
check("an alert sent before the restart still gets its recovery -- the "
      "restart may well have fixed it", len(out) == 1
      and out[0].key == "cpu" and out[0].recovery)

print("\nThe dashboard")
_now = time.time()
_v = {"up": 0, "problems": [], "restarting": {
    "since": _now, "until": _now + 240,
    "what": "Rebooted from the dashboard by owner@alpha.test"}}
cls, label, tip = web._status_badge(_v)
check("a router being restarted reads Restarting, in amber, not Offline",
      (cls, label) == ("warn", "Restarting")
      and "Rebooted from the dashboard by owner@alpha.test" in tip
      and "held until" in tip)
check("...and without the mark it is Offline as ever",
      web._status_badge({"up": 0, "problems": []})[:2] == ("crit", "Offline"))
rows = web._dash_device_rows([dict(_v, device="R1")])
check("the dashboard row says Restarting", ">Restarting<" in rows
      and 'title="Rebooted from the dashboard' in rows)


class Store:
    def latest(self, name):
        return {}


def view(facts, status):
    state = {"devices": {"R1": {"facts": facts, "conditions": {
        "reachability": {"status": status}}}}}
    return web._device_view(Store(), state, "R1")


_mark = {"restarting": {"since": _now, "until": _now + 240, "what": "x"}}
check("a down router the monitor marked is restarting",
      view(_mark, "problem")["restarting"] is not None)
check("...an up one is not, whatever the mark says",
      view(_mark, "ok")["restarting"] is None)
check("...and a mark whose time is up is ignored -- a monitor stopped mid-"
      "restart must not leave a router Restarting for ever",
      view({"restarting": {"until": _now - 1}}, "problem")["restarting"]
      is None)

print("\nEvery way of restarting from the dashboard says so")
check("Reboot", F.update_plan(types.SimpleNamespace(api=None), types.
                              SimpleNamespace(name="R1"),
                              {"update_action": "reboot"}, {})
      .restart_window == (0, 120))
check("a script that restarts the router", F.scripts_plan(
    types.SimpleNamespace(api=types.SimpleNamespace(
        fetch=lambda p: [{".id": "*1", "name": "r", "source": "/system reboot",
                          "comment": "mikromon:script:r"}])),
    types.SimpleNamespace(name="R1"),
    {"script_action": "run", "script_name": "r"}, {}).restart_window
      == (0, 120))
check("...but not a script that does not", F.scripts_plan(
    types.SimpleNamespace(api=types.SimpleNamespace(
        fetch=lambda p: [{".id": "*1", "name": "q", "source": ":log info x",
                          "comment": "mikromon:script:q"}])),
    types.SimpleNamespace(name="R1"),
    {"script_action": "run", "script_name": "q"}, {}).restart_window == ())


class UpdApi:
    def fetch(self, path):
        return {("system", "clock"): [{"date": "2026-10-15",
                                       "time": "16:41:07"}],
                ("system", "resource"): [{"version": "7.16.2"}],
                ("system", "package", "update"): [
                    {"latest-version": "7.18.2"}]}.get(tuple(path), [])


_pu = types.SimpleNamespace(api=UpdApi())
_now_plan = F.update_plan(_pu, types.SimpleNamespace(name="R1"),
                          {"update_action": "install"}, {})
check("an update now: from its timer two minutes out, allowing for the "
      "download", _now_plan.restart_window == (120, 120 + 20 * 60))
_later = F.update_plan(_pu, types.SimpleNamespace(name="R1"),
                       {"update_action": "download_later",
                        "reboot_at": "2026-10-16T02:00"}, {})
check("an update restarting later: from the time picked (counted from now, "
      "so the router's clock being out does not matter)",
      _later.restart_window[0] == (9 * 3600 + 19 * 60)
      and _later.restart_window[1] - _later.restart_window[0] == 20 * 60)
check("the dashboard names each one",
      web._restart_why("update", {"update_action": "install"})
      == "Updated from the dashboard"
      and web._restart_why("scripts", {"script_name": "r"})
      == "Restarted by the script 'r' from the dashboard"
      and web._restart_why("update", {"update_action": "reboot"})
      == "Rebooted from the dashboard")

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL PLANNED RESTART TESTS PASSED")
