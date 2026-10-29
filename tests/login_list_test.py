"""Long-standing logins must not be reported as newly created.

Reported live: Recent activity kept saying "New login 'admin' / 'eugene' /
'mkmonitor' created on the router" for accounts that had been on Howler for
months -- all at once, twice in a day, and mailed to the company as security
warnings.

The cause was the router connection, not the router. When one read timed out
over the tunnel, the router's reply to it was still on its way, and the API
cannot tell one reply from the next. Every later read in that poll got the
reply meant for the one before it, with no error: /user came back holding
the /system/routerboard reply, which has no account names in it, so the
login check stored "no logins". The next good poll compared the real list
with that and called every account new.

These tests pin both halves of the fix:
  * a read that breaks partway gets a fresh connection, so the rest of the
    poll reads what it asked for (a refused menu does not need one)
  * an empty login list is never believed, never stored, and is noted once
    in Recent activity -- not mailed, and not counted in the status report

Run:  ./.venv/Scripts/python.exe tests/login_list_test.py
"""
from __future__ import annotations

import collections
import os
import sys
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import librouteros.exceptions  # noqa: E402

from mikromon import device as device_mod  # noqa: E402
from mikromon import web  # noqa: E402
from mikromon.alert import Alert, Severity  # noqa: E402
from mikromon.alert_log import AlertLog  # noqa: E402
from mikromon.checks.security import SecurityCheck  # noqa: E402
from mikromon.notify import org_email  # noqa: E402

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


USERS = [{"name": "admin", "group": "full"},
         {"name": "eugene", "group": "full"},
         {"name": "mkmonitor", "group": "mkmonitor"}]


class Router:
    """Answers each request in order, like the RouterOS API. A path listed
    in `stall` times out once, but its reply still arrives afterwards."""

    def __init__(self, stall=(), refuse_login_after=None):
        self.stall = set(stall)
        self.logins = 0
        self.refuse_login_after = refuse_login_after
        self.menus = {
            ("system", "resource"): [{"uptime": "5w", "version": "7.16"}],
            ("system", "routerboard"): [{"model": "RB5009",
                                         "serial-number": "HD1234"}],
            ("user",): USERS,
            ("user", "active"): [{"name": "mkmonitor", "via": "api"}],
            ("log",): [{"message": "system started", "topics": "system"}],
        }

    def reply(self, path):
        if path == ("system", "health"):
            return librouteros.exceptions.TrapError("no such command prefix")
        return [dict(r) for r in self.menus.get(path, [])]


class Conn:
    def __init__(self, router):
        self.router = router
        self.queue = collections.deque()
        self.closed = False
        router.logins += 1

    def path(self, *path):
        conn = self

        class Path:
            def __iter__(self):
                return iter(conn.call(path))
        return Path()

    def call(self, path):
        if self.closed:
            raise librouteros.exceptions.ConnectionClosed("closed")
        self.queue.append(self.router.reply(path))
        if path in self.router.stall:
            self.router.stall.discard(path)
            raise TimeoutError("timed out")
        r = self.queue.popleft()
        if isinstance(r, Exception):
            raise r
        return r

    def close(self):
        self.closed = True


def poll(router):
    def connect(**_):
        if (router.refuse_login_after is not None
                and router.logins >= router.refuse_login_after):
            raise OSError("timed out")
        return Conn(router)

    real = device_mod.librouteros.connect
    device_mod.librouteros.connect = connect
    try:
        cfg = types.SimpleNamespace(
            name="Howler", username="mkmonitor", password="pw",
            host="10.10.0.9", api_port=8728, timeout=10, use_ssl=False)
        d = device_mod.Device(cfg)
        return d, d.fetch(device_mod.DATASETS)
    finally:
        device_mod.librouteros.connect = real


def names(snap):
    return sorted(r.get("name") for r in snap.rows("users"))


print("Reading the router")

r = Router()
d, snap = poll(r)
check("a healthy poll logs in once and reads the real login list",
      r.logins == 1 and names(snap) == ["admin", "eugene", "mkmonitor"])

d, snap = poll(Router(stall=[("ip", "route")]))
check("the incident: one read times out and the login list that follows "
      "is still the login list, not the routerboard reply",
      names(snap) == ["admin", "eugene", "mkmonitor"])
check("...and so is everything after it",
      snap.first("routerboard").get("model") == "RB5009"
      and snap.first("log").get("message") == "system started")
check("...because the connection was replaced, once",
      d.api is not None and isinstance(d.api, Conn) and d.api.router.logins == 2)
check("...and the read that broke is recorded as not read",
      "route" in snap.errors and "timed out" in snap.errors["route"]
      and snap.rows("route") == [])

r = Router()
d, snap = poll(r)
check("a menu the router refuses (no /system/health on this board) does not "
      "cost a second login: its reply ended cleanly",
      "health" in snap.errors and r.logins == 1
      and names(snap) == ["admin", "eugene", "mkmonitor"])

r = Router(stall=[("ip", "route"), ("system", "history")])
d, snap = poll(r)
check("a second break in one poll gives up the rest instead of guessing",
      r.logins == 2 and d.api is None
      and "twice" in snap.errors.get("dhcp_lease", "")
      and snap.rows("dhcp_lease") == [])
check("...keeping what was read correctly before it",
      names(snap) == ["admin", "eugene", "mkmonitor"]
      and snap.first("log").get("message") == "system started")

r = Router(stall=[("ip", "route")], refuse_login_after=1)
d, snap = poll(r)
check("if logging in again fails, the rest is marked not read -- the login "
      "list included, which the login check already ignores",
      "users" in snap.errors and "not read" in snap.errors["users"]
      and d.api is None)


print("\nThe login check")


class Ctx:
    def __init__(self):
        self.events = []
        self.mem = {}

    def event(self, key, sev, title, **kw):
        self.events.append({"key": key, "sev": sev, "title": title,
                            "cause": kw.get("cause", "")})


class Snap:
    def __init__(self, rows, errors=()):
        self._rows = rows
        self.errors = errors
        self.data = {"users": rows}

    def rows(self, key):
        return self._rows if key == "users" else []


DEV = types.SimpleNamespace(username="mkmonitor", push_username="")
ALL = [dict(r) for r in USERS]
ROUTERBOARD = [{"model": "RB5009", "serial-number": "HD1234"}]

c, ctx = SecurityCheck(), Ctx()
c._scan_users(Snap(ALL), DEV, ctx, ctx.mem, True)
c._scan_users(Snap(ROUTERBOARD), DEV, ctx, ctx.mem, False)
check("a list with no account names in it raises no security alert -- not "
      "'monitoring login DELETED', not anything",
      not [e for e in ctx.events if e["key"].startswith("router_user")])
check("...but says so once, as a note rather than a warning",
      [(e["key"], e["sev"]) for e in ctx.events]
      == [("login_list_unreadable", Severity.INFO)])
check("...in words that say the router's accounts are fine",
      ctx.events and "not affected" in ctx.events[0]["cause"])
check("...and the stored list is kept",
      ctx.mem["router_users"] == ["admin", "eugene", "mkmonitor"])

ctx.events = []
c._scan_users(Snap([]), DEV, ctx, ctx.mem, False)
check("a second bad read in a row adds nothing more", ctx.events == [])

c._scan_users(Snap(ALL), DEV, ctx, ctx.mem, False)
check("the next good read reports no 'New login' for accounts that were "
      "there all along -- the reported bug", ctx.events == [])

c._scan_users(Snap([]), DEV, ctx, ctx.mem, False)
check("a later bad read, after a good one, is noted again",
      [e["key"] for e in ctx.events] == ["login_list_unreadable"])

ctx.events = []
nothing = Snap([])
nothing.data = {}
c._scan_users(nothing, DEV, ctx, ctx.mem, False)
check("a poll that never asked for the list is not mistaken for an empty "
      "answer", ctx.events == [])

ctx.events = []
c._scan_users(Snap(ALL + [{"name": "hacker", "group": "full"}]), DEV, ctx,
              ctx.mem, False)
check("a login that really is new still alerts straight after",
      [e["key"] for e in ctx.events] == ["router_user:hacker"])

c, ctx = SecurityCheck(), Ctx()
ctx.mem.update({"initialized": True, "router_users": []})
c._scan_users(Snap(ALL), DEV, ctx, ctx.mem, False)
check("a router whose stored list is already empty (a bad read kept by the "
      "old code) starts again from what is there now, without alerting",
      ctx.events == []
      and ctx.mem["router_users"] == ["admin", "eugene", "mkmonitor"])


print("\nWhere the note shows up")

tmp = tempfile.mkdtemp()
db = os.path.join(tmp, "alert_log.db")
note = Alert("Howler", "login_list_unreadable", Severity.INFO,
             "Login list read back empty; ignored", ts=1000.0)
n = org_email.OrgEmailNotifier(None, os.path.join(tmp, "auth.db"),
                               os.path.join(tmp, "devices.db"),
                               alert_log_db=db)
mailed = []
n._deliver = lambda *a: mailed.append(a)
n.send([note])
rows = AlertLog(db).recent()
check("it is written to Recent activity",
      [r["key"] for r in rows] == ["login_list_unreadable"])
check("...and mailed to nobody", mailed == []
      and not org_email._should_notify(note))

subj, txt, htm = org_email._build_report(
    "Howler Co", ["Howler"], {"devices": {}}, "weekly", "[EM]", 0, 2000,
    events_by_device={"Howler": rows})
check("the weekly report does not count it as a WAN issue",
      "No WAN issues" in txt and "Login list" not in txt)

html = web._activity_timeline_box([], rows + [
    {"ts": 900.0, "device": "Howler", "key": "router_user:eugene",
     "title": "New login 'eugene' created on the router", "severity": 20,
     "recovery": 0},
    {"ts": 800.0, "device": "Howler", "key": "wan_link:0",
     "title": "WAN 1 down", "severity": 20, "recovery": 0}])
check("Recent activity files login rows under Logins, not "
      "'WAN / reachability'",
      html.count("<td>Logins</td>") == 2
      and html.count("<td>WAN / reachability</td>") == 1)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL LOGIN LIST TESTS PASSED")
