"""Safe mode, end to end without a router.

What has to hold:
  * the timer is on the router BEFORE the change is sent, so a change that
    cuts the connection while it goes out is still undone;
  * a change is kept only once the server has logged back in after it;
  * a change the router had to undo is noticed and reported, and so is a
    router that never came back;
  * a second change replaces the first one's timer, and the first watcher
    never confirms the second change.

Run:  ./.venv/Scripts/python.exe tests/safemode_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import web  # noqa: E402
from mikromon import web_shared  # noqa: E402
from mikromon.push import Pusher  # noqa: E402
from mikromon.push import safemode as sm  # noqa: E402
from mikromon.push.api import PushError  # noqa: E402
from mikromon.push.plan import Operation, Plan  # noqa: E402

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class FakeRouter:
    """Just enough router for the watcher: a scheduler table, an uptime, and
    whether it can be reached at all."""

    def __init__(self, clock):
        self.clock = clock
        self.reachable = True
        self.boot = clock() - 86400
        self.scheduler = []
        self.removed = []

    def arm(self, token):
        self.scheduler.append({".id": f"*{len(self.scheduler) + 1}",
                               "name": "mikromon-autorevert",
                               "comment": f"mikromon:autorevert:{token}"})

    def revert(self):
        """What the router's own timer does: restore, reboot, timer gone."""
        self.scheduler = [r for r in self.scheduler
                          if r["name"] != "mikromon-autorevert"]
        self.boot = self.clock()

    def open_api(self, device):
        if not self.reachable:
            raise OSError("timed out")
        router = self

        class Api:
            def fetch(self, path):
                if path == ("system", "scheduler"):
                    return [dict(r) for r in router.scheduler]
                if path == ("system", "resource"):
                    up = int(router.clock() - router.boot)
                    return [{"uptime": f"{up}s"}]
                return []

            def execute(self, op):
                router.removed.append(op.params[".id"])
                router.scheduler = [r for r in router.scheduler
                                    if r[".id"] != op.params[".id"]]

        return Api(), (lambda: None)


tmp = tempfile.mkdtemp()

print("the constants agree")
check("the dashboard and the watcher use the same one-minute check",
      web_shared._SAFE_CHECK_SECONDS == sm.CHECK_SECONDS == 60)

print("\na good change")
clk = Clock()
rtr = FakeRouter(clk)
events = []
tr = sm.SafeModeTracker(os.path.join(tmp, "a.json"), open_api=rtr.open_api,
                        on_event=lambda e, ev: events.append(ev), clock=clk)
rtr.arm("t1")
tr.register(device="R1", feature="security", backup="before-x", token="t1",
            user="o@x.test")
clk.t += 30
tr.tick()
check("nothing is decided before the router's own check has run",
      tr.status("R1")["state"] == "waiting" and rtr.scheduler)
clk.t += 33  # 63 s after the change
tr.tick()
check("just after the router's check, the server logs in and takes the "
      "timer down", tr.status("R1")["state"] == "confirmed"
      and not rtr.scheduler and events == ["confirmed"])

print("\na change that cut the tunnel")
clk = Clock()
rtr = FakeRouter(clk)
events = []
tr = sm.SafeModeTracker(os.path.join(tmp, "b.json"), open_api=rtr.open_api,
                        on_event=lambda e, ev: events.append((ev, e)), clock=clk)
rtr.arm("t2")
tr.register(device="R1", feature="wan", backup="before-y", token="t2")
rtr.reachable = False
for _ in range(20):           # 62 s .. 122 s: cannot get in
    clk.t += 4
    tr.tick()
check("while it cannot log in it keeps trying, and says so",
      tr.status("R1")["state"] in ("confirming", "unconfirmed"))
clk.t = clk.t  # router restores at ~65 s, reboots, is back at 150 s
rtr.revert()
clk.t += 70
rtr.reachable = True
for _ in range(15):
    clk.t += 4
    tr.tick()
st = tr.status("R1")
check("when the router is back without its timer and has restarted since "
      "the change, the change is reported as undone",
      st["state"] == "reverted" and [e for e, _ in events] == ["reverted"])
check("...with the router's own evidence in the message",
      "restarted" in st["detail"])

print("\na change undone quickly")
clk = Clock()
rtr = FakeRouter(clk)
events = []
tr = sm.SafeModeTracker(os.path.join(tmp, "c.json"), open_api=rtr.open_api,
                        on_event=lambda e, ev: events.append(ev), clock=clk)
rtr.arm("t3")
tr.register(device="R1", feature="routes", backup="b", token="t3")
clk.t += 62
rtr.reachable = False
tr.tick()
clk.t += 30                    # it restored and rebooted in that time
rtr.revert()
rtr.reachable = True
clk.t += 8
tr.tick()
check("a router already back from its restore inside the window is "
      "recognised too", tr.status("R1")["state"] == "reverted"
      and events == ["reverted"])

print("\na router that never comes back")
clk = Clock()
rtr = FakeRouter(clk)
events = []
tr = sm.SafeModeTracker(os.path.join(tmp, "d.json"), open_api=rtr.open_api,
                        on_event=lambda e, ev: events.append(ev), clock=clk)
rtr.arm("t4")
tr.register(device="R1", feature="wan", backup="b", token="t4")
rtr.reachable = False
for _ in range(400):
    clk.t += 4
    tr.tick()
check("after fifteen minutes it says the router needs a person",
      tr.status("R1")["state"] == "lost" and events == ["lost"])

print("\ntwo changes in a row")
clk = Clock()
rtr = FakeRouter(clk)
events = []
tr = sm.SafeModeTracker(os.path.join(tmp, "e.json"), open_api=rtr.open_api,
                        on_event=lambda e, ev: events.append(ev), clock=clk)
rtr.arm("first")
tr.register(device="R1", feature="security", backup="b1", token="first")
clk.t += 20
rtr.scheduler = []             # the second change clears the way...
rtr.arm("second")              # ...and arms its own timer
tr.register(device="R1", feature="security", backup="b2", token="second")
check("the first change's watcher stands down as soon as a second change "
      "replaces its timer", tr.status("R1", "first")["state"] == "superseded")
clk.t += 63
tr.tick()
check("the second change is confirmed by its own watcher, and only once",
      tr.status("R1", "second")["state"] == "confirmed"
      and events == ["confirmed"])

print("\nsomeone presses Keep")
clk = Clock()
rtr = FakeRouter(clk)
tr = sm.SafeModeTracker(os.path.join(tmp, "f.json"), open_api=rtr.open_api,
                        clock=clk)
rtr.arm("k")
tr.register(device="R1", feature="qos", backup="b", token="k")
tr.mark_kept("R1", by="o@x.test")
check("Keep settles it straight away", tr.status("R1")["state"] == "confirmed"
      and "o@x.test" in tr.status("R1")["detail"])

print("\na dashboard restart in the middle")
clk = Clock()
rtr = FakeRouter(clk)
path = os.path.join(tmp, "g.json")
tr = sm.SafeModeTracker(path, open_api=rtr.open_api, clock=clk)
rtr.arm("r")
tr.register(device="R1", feature="wan", backup="b", token="r")
tr2 = sm.SafeModeTracker(path, open_api=rtr.open_api, clock=clk)
clk.t += 63
tr2.tick()
check("the watcher picks up where it left off -- an abandoned "
      "confirmation would revert a good change",
      tr2.status("R1")["state"] == "confirmed" and not rtr.scheduler)

print("\nwhat the page says")
d = sm.describe({"state": "waiting", "armed_at": 0}, now=10)
check("while waiting it counts down to the router's check",
      d["wait"] == sm.CHECK_SECONDS - 10 and "Nothing" in d["detail"])
check("every final state has a plain headline",
      all(sm.describe({"state": s, "armed_at": 0}, now=0)["headline"]
          for s in ("confirmed", "reverted", "lost", "superseded")))

print("\nthe order things go to the router in")


class FakeApi:
    def __init__(self, fail_on=None, drop_after_fail=False, reach=True):
        self.executed = []
        self.fail_on = fail_on
        self.drop = drop_after_fail
        self.dropped = False
        self.scheduler = [{".id": "*old", "name": "mikromon-autorevert",
                           "comment": "mikromon:autorevert:stale"}]
        self.device = types.SimpleNamespace(
            ping=lambda addr, count=2: 0 if reach else 100)

    def fetch(self, path):
        if self.dropped:
            raise PushError("connection lost")
        if path == ("system", "scheduler"):
            return [dict(r) for r in self.scheduler]
        return []

    def execute(self, op):
        if self.dropped:
            raise PushError("connection lost")
        if self.fail_on and op.desc == self.fail_on:
            if self.drop:
                self.dropped = True
            raise PushError("simulated failure")
        self.executed.append(op)
        if op.path == ("system", "scheduler"):
            if op.action == "add":
                self.scheduler.append({".id": "*new", **op.params})
                return "*new"
            if op.action == "remove":
                self.scheduler = [r for r in self.scheduler
                                  if r[".id"] != op.params[".id"]]
        return "*1" if op.action == "add" else None


cfg = types.SimpleNamespace(name="R1", push_username="", push_password="")
change = Plan("R1", [Operation("add", ("ip", "firewall", "filter"),
                               {"chain": "input", "action": "drop"},
                               desc="the change")])
clk = Clock()
tr = sm.SafeModeTracker(os.path.join(tmp, "h.json"), clock=clk)
api = FakeApi()
p = Pusher(cfg, api, dry_run=False)
armed = web._safe_apply(p, change, slug="security", device="R1",
                        hub_ip="10.10.0.1", safe=True, tracker=tr, user="u")
order = [(o.action, o.path, o.desc) for o in api.executed]
i_clear = next(i for i, o in enumerate(order) if o[0] == "remove")
i_backup = next(i for i, o in enumerate(order) if o[1] == ("system", "backup"))
i_arm = next(i for i, o in enumerate(order)
             if o[0] == "add" and o[1] == ("system", "scheduler"))
i_change = next(i for i, o in enumerate(order) if o[2] == "the change")
check("an old timer is cleared first, so the backup never contains one",
      i_clear < i_backup and order[i_clear][1] == ("system", "scheduler"))
check("the timer is armed BEFORE the change is sent", i_backup < i_arm < i_change)
check("a router that pings the hub now gets the ping test",
      armed["mode"] == "ping" and armed["token"]
      and tr.status("R1", armed["token"])["state"] == "waiting")

api = FakeApi(reach=False)
armed = web._safe_apply(Pusher(cfg, api, dry_run=False), change, slug="security",
                        device="R1", hub_ip="10.10.0.1", safe=True, tracker=tr)
check("one that cannot ping the hub before the change gets the login test "
      "only", armed["mode"] == "login")

api = FakeApi(fail_on="the change")
try:
    web._safe_apply(Pusher(cfg, api, dry_run=False), change, slug="security",
                    device="R2", hub_ip="10.10.0.1", safe=True, tracker=tr)
    raised = False
except PushError:
    raised = True
check("a change the router refused is reported, and its timer is taken down "
      "again (nothing changed, so nothing to undo)",
      raised and not [r for r in api.scheduler if r[".id"] == "*new"]
      and tr.status("R2") is None)

api = FakeApi(fail_on="the change", drop_after_fail=True)
try:
    web._safe_apply(Pusher(cfg, api, dry_run=False), change, slug="security",
                    device="R3", hub_ip="10.10.0.1", safe=True, tracker=tr)
    msg = ""
except PushError as exc:
    msg = str(exc)
check("a change that took the connection with it leaves the timer to do its "
      "job, says so, and is watched",
      "put the previous settings back" in msg
      and tr.status("R3")["state"] == "waiting")

api = FakeApi()
armed = web._safe_apply(Pusher(cfg, api, dry_run=False), change, slug="security",
                        device="R4", hub_ip="10.10.0.1", safe=True, tracker=None)
check("with no watcher running there is no timer at all -- an unwatched "
      "timer would revert every change", armed["token"] == ""
      and not any(o.action == "add" and o.path == ("system", "scheduler")
                  for o in api.executed))

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL SAFE MODE TESTS PASSED")
