"""The Update tab updates, end to end through the dashboard, on a fake router.

It said an update was available and then could not install it: the only
button was "Preview changes", which sent the update channel, and with the
channel unchanged the answer was "already in the desired state". Now:
  * an available update shows Update now, which opens two choices --
    download and install now (the router restarts), or download now and
    restart at a time picked by the router's own clock and time zone
  * each is confirmed in plain words first, and the restart can be cancelled
  * every step is a one-shot timer on the router, so a download that takes
    minutes does not depend on this server's session staying up
  * a time too soon, too far off, or on a router whose clock was never set
    is refused with the reason

Run:  ./.venv/Scripts/python.exe tests/update_tab_test.py
"""
from __future__ import annotations

import html
import http.cookiejar
import itertools
import json
import os
import re
import sys
import tempfile
import threading
import types
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mikromon.push as push_pkg  # noqa: E402
from mikromon import web  # noqa: E402
from mikromon.auth import AuthStore  # noqa: E402
from mikromon.config import DEFAULT_THRESHOLDS  # noqa: E402
from mikromon.devices_store import DevicesStore  # noqa: E402
from mikromon.metrics import MetricsStore  # noqa: E402
from mikromon.push import features as F  # noqa: E402
from mikromon.webguard import GuardedHTTPServer  # noqa: E402

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


SCHED = ("system", "scheduler")
PKG = ("system", "package", "update")
CLOCK = ("system", "clock")


class FakePath:
    def __init__(self, router, segs):
        self.r, self.segs = router, segs

    def __iter__(self):
        return iter([dict(x) for x in self.r.tables.setdefault(self.segs, [])])

    def add(self, **params):
        nid = f"*{next(self.r.ids)}"
        self.r.tables.setdefault(self.segs, []).append(
            {".id": nid, **{k: str(v) for k, v in params.items()}})
        self.r.log.append(("add", self.segs, dict(params)))
        return nid

    def update(self, **params):
        for x in self.r.tables.setdefault(self.segs, []):
            if x.get(".id") == params.get(".id"):
                x.update({k: str(v) for k, v in params.items()})
        self.r.log.append(("set", self.segs, dict(params)))

    def remove(self, rid):
        rows = self.r.tables.setdefault(self.segs, [])
        self.r.tables[self.segs] = [x for x in rows if x.get(".id") != rid]
        self.r.log.append(("remove", self.segs, rid))

    def __call__(self, cmd, **params):
        self.r.log.append(("run", self.segs, cmd))
        return iter([])


class FakeRouter:
    def __init__(self):
        self.ids = itertools.count(100)
        self.log = []
        self.tables = {
            ("system", "resource"): [{"version": "7.16.2", "uptime": "3d"}],
            CLOCK: [{"date": "2026-10-15", "time": "16:41:07",
                     "time-zone-name": "Africa/Johannesburg"}],
            PKG: [{".id": "*0", "channel": "stable",
                   "installed-version": "7.16.2", "latest-version": "7.18.2",
                   "status": "New version is available"}],
            ("system", "routerboard"): [{".id": "*0",
                                         "current-firmware": "7.16.2",
                                         "upgrade-firmware": "7.16.2"}],
            SCHED: [{".id": "*4", "name": "their-own", "interval": "1h",
                     "on-event": ":log info z", "start-time": "startup"}],
        }

    def jobs(self, kind=""):
        return [s for s in self.tables[SCHED]
                if s.get("comment", "").startswith("mikromon:update:" + kind)]


class FakeDevice:
    def __init__(self, router):
        self.router = router
        self.api = None

    def reachable(self, timeout=None, attempts=None):
        return True

    def connect(self):
        self.api = types.SimpleNamespace(
            path=lambda *s: FakePath(self.router, s), close=lambda: None)
        return self.api

    def close(self):
        pass


ROUTER = FakeRouter()
_orig_rw = push_pkg.rw_device
push_pkg.rw_device = lambda cfg: FakeDevice(ROUTER)

tmp = tempfile.mkdtemp()
mdb, sfile, adb, ddb = (os.path.join(tmp, x) for x in
                        ("m.db", "s.json", "a.db", "d.db"))
MetricsStore(mdb).close()
with open(sfile, "w") as fh:
    json.dump({"devices": {}}, fh)
a = AuthStore(adb)
org = a.signup("owner@alpha.test", "a-password-for-the-test", "Alpha")
a.close()
ds = DevicesStore(ddb)
ds.upsert({"name": "R1", "host": "10.10.3.7", "username": "u", "password": "p"},
          DEFAULT_THRESHOLDS, org_id=org)
ds.close()
srv = GuardedHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, AuthStore(adb), web.SessionManager(), secure_cookies=False,
    devices_db=ddb, defaults=dict(DEFAULT_THRESHOLDS), admin_2fa=False))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()
op = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def req(path, data=None):
    body = urllib.parse.urlencode(data, doseq=True).encode() if data else None
    try:
        r = op.open(urllib.request.Request(BASE + path, data=body), timeout=30)
        return r.status, html.unescape(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return e.code, html.unescape(e.read().decode("utf-8", "replace"))


def sent_to_scheduler(since):
    return [e for e in ROUTER.log[since:] if e[1] == SCHED]


try:
    req("/login", {"email": "owner@alpha.test",
                   "password": "a-password-for-the-test"})

    print("An available update can actually be installed")
    st, page = req("/device?name=R1&tab=update")
    tok = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    check("the tab opens", st == 200)
    check("it says which version is waiting and which is running",
          "Update available" in page and "7.18.2" in page and "7.16.2" in page)
    check("...with an Update now button", ">Update now</summary>" in page)
    check("which opens the two ways to take it",
          "Download and install now" in page
          and "Download now, restart later" in page
          and 'value="install"' in page and 'value="download_later"' in page)
    check("the restart time is picked on a date-and-time field, suggested "
          "for the next quiet hour on the router's clock",
          'type="datetime-local" name="reboot_at"' in page
          and 'value="2026-10-16T02:00"' in page)
    check("...and the router's own time and time zone are shown, since that "
          "is the clock the restart goes by",
          "It is 16:41 on 15 October 2026 (Africa/Johannesburg) on the router"
          in page)
    check("the old Preview changes button is gone: the channel form's button "
          "says what it does", "Preview changes" not in page
          and "Change channel" in page)

    base = {"csrf": tok, "device": "R1", "feature": "update"}

    print("\nDownload now, restart later")
    n = len(ROUTER.log)
    st, page = req("/device/push", {**base, "update_action": "download_later",
                                    "reboot_at": "2026-10-16T02:00"})
    check("it is asked in plain words first, nothing sent yet",
          "Download the update now and restart later?" in page
          and "Yes, do that" in page and not sent_to_scheduler(n))
    check("...saying when the router restarts, by its own clock",
          "Restart the router at 02:00 on 16 October 2026 "
          "(Africa/Johannesburg) by its own clock" in page)
    check("...and no Safe mode box: the restart is the point",
          'name="safe_revert"' not in page)
    st, page = req("/device/push", {**base, "update_action": "download_later",
                                    "reboot_at": "2026-10-16T02:00",
                                    "apply": "1"})
    dl, rs = ROUTER.jobs("download"), ROUTER.jobs("reboot")
    check("confirmed, the router gets two one-shot timers: the download two "
          "minutes from now, and the restart at the chosen time",
          len(dl) == 1 and len(rs) == 1
          and dl[0]["start-date"] == "2026-10-15"
          and dl[0]["start-time"] == "16:43:00"
          and rs[0]["start-date"] == "2026-10-16"
          and rs[0]["start-time"] == "02:00:00"
          and dl[0]["interval"] == rs[0]["interval"] == "0s")
    check("the download timer downloads, it does not install",
          "update download" in dl[0]["on-event"]
          and "install" not in dl[0]["on-event"])
    check("the restart installs what was downloaded -- and if the download "
          "was lost, fetches and installs it anyway",
          "ownloaded" in rs[0]["on-event"]
          and "/system reboot" in rs[0]["on-event"]
          and "update install" in rs[0]["on-event"])
    check("the timers may restart the router", "reboot" in rs[0]["policy"])
    check("the page then says what happens and when",
          "Downloading now, and the site stays online" in page
          and "02:00 on 16 October 2026" in page)
    check("...and shows the planned restart with a way to cancel it",
          "Restart planned" in page and "Cancel the planned restart" in page)
    check("their own scheduler entry is untouched",
          any(s["name"] == "their-own" for s in ROUTER.tables[SCHED]))
    from mikromon import restarts as _rs  # noqa: E402
    _planned = _rs._load(_rs.path_for(ddb)).get("R1") or {}
    check("the monitor is told the router restarts then, so it does not email "
          "that it went offline", _planned.get("why")
          == "Restarted for an update planned from the dashboard"
          and _planned.get("by") == "owner@alpha.test"
          and _planned["latest"] - _planned["start"] == 20 * 60)

    req("/device/push", {**base, "update_action": "download_later",
                         "reboot_at": "2026-10-16T03:30", "apply": "1"})
    rs = ROUTER.jobs("reboot")
    check("picking another time replaces the plan rather than adding a "
          "second restart", len(rs) == 1 and rs[0]["start-time"] == "03:30:00"
          and len(ROUTER.jobs("download")) == 1)

    print("\nCancelling the restart")
    st, page = req("/device/push", {**base, "update_action": "cancel_reboot"})
    check("asked first", "Cancel the planned restart?" in page
          and "Yes, cancel it" in page and len(ROUTER.jobs("reboot")) == 1)
    st, page = req("/device/push", {**base, "update_action": "cancel_reboot",
                                    "apply": "1"})
    check("the restart timer is gone, the download stays",
          not ROUTER.jobs("reboot") and len(ROUTER.jobs("download")) == 1)
    check("...and the page says the update installs at the next restart",
          "Planned restart cancelled" in page
          and "Restart planned" not in page)
    check("...and the monitor is told it is off",
          "R1" not in _rs._load(_rs.path_for(ddb)))
    st, page = req("/device/push", {**base, "update_action": "cancel_reboot"})
    check("cancelling with nothing planned says so instead of offering to "
          "send nothing", "Nothing to do" in page and "Yes, cancel it" not in page)

    print("\nDownload and install now")
    st, page = req("/device/push", {**base, "update_action": "install"})
    check("asked in plain words, saying the site goes offline",
          "Download and install the update now?" in page
          and "Yes, update now" in page and "offline" in page)
    st, page = req("/device/push", {**base, "update_action": "install",
                                    "apply": "1"})
    now = ROUTER.jobs("now")
    check("confirmed, one timer two minutes out installs and restarts -- "
          "the router does it, whatever happens to this connection",
          len(now) == 1 and now[0]["start-time"] == "16:43:00"
          and "update install" in now[0]["on-event"]
          and not ROUTER.jobs("download") and not ROUTER.jobs("reboot"))
    check("...and the page says it starts within two minutes",
          "The update starts on the router within two minutes" in page)
    check("...and the monitor holds its alerts while it restarts",
          (_rs._load(_rs.path_for(ddb)).get("R1") or {}).get("why")
          == "Updated from the dashboard")

    print("\nTimes that cannot work are refused, with the reason")
    n = len(ROUTER.log)
    st, page = req("/device/push", {**base, "update_action": "download_later",
                                    "reboot_at": "2026-10-15T16:45"})
    check("a restart before the download can finish",
          "Nothing was sent to the router." in page
          and "at least 10 minutes" in page
          and "16:41 on 15 October 2026" in page and not sent_to_scheduler(n))
    st, page = req("/device/push", {**base, "update_action": "download_later",
                                    "reboot_at": "2027-03-01T02:00"})
    check("one more than 30 days off", "within 30 days" in page)
    st, page = req("/device/push", {**base, "update_action": "download_later",
                                    "reboot_at": "tomorrow"})
    check("something that is not a date and time",
          "Pick the date and time" in page)

    print("\nA router whose clock was never set")
    ROUTER.tables[CLOCK] = [{"date": "1970-01-02", "time": "05:12:00",
                             "time-zone-name": "manual"}]
    st, page = req("/device?name=R1&tab=update")
    check("offers no time of day to restart at, and says why",
          "clock is not set" in page and 'name="reboot_at"' not in page
          and "Download and install now" in page)
    st, page = req("/device/push", {**base, "update_action": "download_later",
                                    "reboot_at": "2026-10-16T02:00"})
    check("...and refuses one posted anyway", "clock is not set" in page
          and "Nothing was sent to the router." in page)
    req("/device/push", {**base, "update_action": "install", "apply": "1"})
    check("installing now still works: two minutes from now is two minutes "
          "on any clock", ROUTER.jobs("now")
          and ROUTER.jobs("now")[0]["start-date"] == "1970-01-02"
          and ROUTER.jobs("now")[0]["start-time"] == "05:14:00")
    ROUTER.tables[CLOCK] = [{"date": "2026-10-15", "time": "16:41:07",
                             "time-zone-name": "Africa/Johannesburg"}]

    print("\nUp to date")
    ROUTER.tables[PKG][0].update({"latest-version": "7.16.2",
                                  "status": "System is already up to date"})
    st, page = req("/device?name=R1&tab=update")
    check("no Update now when there is nothing to install",
          ">Update now</summary>" not in page
          and "Update available" not in page
          and 'value="download_later"' not in page)
    check("...but the router's answer, and a way to ask it again",
          "System is already up to date" in page
          and "Check for updates now" in page)
    st, page = req("/device/push", {**base, "update_action": "check"})
    check("checking is asked in plain words too",
          "Check for a newer RouterOS?" in page and "Yes, check now" in page)
finally:
    srv.shutdown()
    push_pkg.rw_device = _orig_rw

print("\nThe pieces")


class Api:
    def __init__(self, version, tables=None):
        self.version, self.tables = version, tables or {}

    def fetch(self, path):
        if tuple(path) == ("system", "resource"):
            return [{"version": self.version}]
        return [dict(r) for r in self.tables.get(tuple(path), [])]


check("an older RouterOS gets its dates the old way (oct/16/2026)",
      F._ros_date_text(Api("7.9.2"), F.datetime.date(2026, 10, 16))
      == "oct/16/2026"
      and F._ros_date_text(Api("7.16"), F.datetime.date(2026, 10, 16))
      == "2026-10-16")
_clk = {"date": "2026-10-15", "time": "00:30", "tz": "UTC", "unset": False}
check("the suggested restart is tonight's 02:00 when that is still ahead",
      F.default_restart(_clk) == F.datetime.datetime(2026, 10, 15, 2, 0))
check("...and tomorrow's once it is too close or past",
      F.default_restart(dict(_clk, time="01:30"))
      == F.datetime.datetime(2026, 10, 16, 2, 0)
      and F.default_restart(dict(_clk, time="16:41"))
      == F.datetime.datetime(2026, 10, 16, 2, 0))
check("...and none on a clock that was never set",
      F.default_restart(dict(_clk, date="1970-01-02", unset=True)) is None)

_past = Api("7.16", {
    ("system", "clock"): [{"date": "2026-10-15", "time": "16:41:07"}],
    SCHED: [{".id": "*9", "name": "mikromon-update-restart",
             "comment": "mikromon:update:reboot", "start-date": "2026-10-14",
             "start-time": "02:00:00", "interval": "0s"}],
    PKG: [{}], ("system", "routerboard"): [{}]})
check("a restart timer whose time has passed is a leftover, not a plan",
      F.update_read(types.SimpleNamespace(api=_past), None)["restart"] is None)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL UPDATE TAB TESTS PASSED")
