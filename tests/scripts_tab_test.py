"""The Scripts tab, end to end through the dashboard, against a fake router.

Opening the tab once a router had a script of ours on it was a 502: the WAN
tab's failover check called .get on whatever a tab read, and the Scripts read
is a list. Queues, Port forwarding and Restrict access read lists too, and
Restrict access always has rows, so it had failed on every visit. Checked here:
  * every tab whose read is a list opens with rows in it
  * a timer per script -- every day, every week on a set day, or off -- on the
    router's own scheduler, previewed first, and quiet when nothing changed
  * removing a script takes its timer with it
  * Run on a script that restarts the router leaves Safe mode unticked
  * a name the router would hand back as a number is refused, and one already
    on a router still lists

Run:  ./.venv/Scripts/python.exe tests/scripts_tab_test.py
"""
from __future__ import annotations

import datetime
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


def ros(v):
    """What librouteros hands back for a word: digits as an int, yes/no and
    true/false as a bool."""
    try:
        return int(v)
    except (TypeError, ValueError):
        return {"yes": True, "true": True, "no": False,
                "false": False}.get(v, v)


SCHED = ("system", "scheduler")
SCRIPT = ("system", "script")


# ---- a router, as far as librouteros is concerned --------------------------
class FakePath:
    def __init__(self, router, segs):
        self.r, self.segs = router, segs

    def __iter__(self):
        return iter([{k: ros(v) for k, v in x.items()}
                     for x in self.r.tables.setdefault(self.segs, [])])

    def _stored(self, params):
        row = {k: str(v) for k, v in params.items() if k != ".id"}
        # RouterOS shows an interval of 7d back as 1w.
        if self.segs == SCHED and row.get("interval") == "7d":
            row["interval"] = "1w"
        return row

    def add(self, **params):
        nid = f"*{next(self.r.ids)}"
        row = {".id": nid, **self._stored(params)}
        if self.segs == SCHED:
            row.update({"next-run": "2026-10-14 03:00:00", "run-count": "0",
                        "owner": "rw"})
        self.r.tables.setdefault(self.segs, []).append(row)
        self.r.log.append(("add", self.segs, dict(params)))
        return nid

    def update(self, **params):
        for x in self.r.tables.setdefault(self.segs, []):
            if x.get(".id") == params.get(".id"):
                x.update(self._stored(params))
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
            ("system", "resource"): [{"version": "7.15.3", "uptime": "3d"}],
            ("system", "clock"): [{"date": "2026-10-13", "time": "20:41:10",
                                   "time-zone-name": "Africa/Johannesburg"}],
            SCRIPT: [
                {".id": "*1", "name": "theirs", "source": ":log info x"},
                {".id": "*2", "name": "reboot", "source": "/system reboot",
                 "comment": "mikromon:script:reboot", "run-count": "0"},
                {".id": "*3", "name": "2024", "source": ":log info y",
                 "comment": "mikromon:script:2024"}],
            SCHED: [{".id": "*4", "name": "their-own", "interval": "1h",
                     "on-event": ":log info z", "start-time": "startup"}],
            ("ip", "service"): [
                {".id": "*5", "name": "api", "port": "8728", "disabled": "false",
                 "address": ""},
                {".id": "*6", "name": "winbox", "port": "8291",
                 "disabled": "false", "address": ""}],
            ("queue", "simple"): [
                {".id": "*7", "name": "guest", "target": "192.168.88.0/24",
                 "max-limit": "5M/5M", "comment": "mikromon:qos:guest"}],
            ("ip", "firewall", "nat"): [
                {".id": "*8", "chain": "dstnat", "action": "dst-nat",
                 "protocol": "tcp", "dst-port": "8080",
                 "to-addresses": "192.168.88.10", "to-ports": "80",
                 "comment": "mikromon:pf:cam"}],
            ("file",): [],
        }

    def timers(self):
        return [s for s in self.tables[SCHED]
                if s.get("comment", "").startswith("mikromon:scriptsched:")]


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
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001 -- a dropped connection, nginx's 502
        return f"dropped: {e}", ""


def ops_sent(since):
    return [e for e in ROUTER.log[since:] if e[1] == SCHED]


try:
    req("/login", {"email": "owner@alpha.test",
                   "password": "a-password-for-the-test"})

    print("tabs whose read is a list open with rows in them")
    for tab, label in (("scripts", "Scripts"), ("harden", "Restrict access"),
                       ("qos", "Queues"), ("portfwd", "Port forwarding")):
        st, page = req(f"/device?name=R1&tab={tab}")
        check(f"{label} opens (it was a 502)", st == 200)
    st, page = req("/device?name=R1&tab=scripts")
    tok = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    check("our scripts are listed, a hand-made one is not",
          "<b>reboot</b>" in page and "<b>theirs</b>" not in page)
    check("a script already on the router under an all-digit name still "
          "lists", "<b>2024</b>" in page)
    check("each script says it has no timer yet, beside a form to set one",
          page.count("Not scheduled") >= 2 and 'name="sched_every"' in page
          and 'name="sched_time"' in page)
    check("the router's own clock is shown, since that is what timers use",
          "20:41 on 2026-10-13 (Africa/Johannesburg)" in page)
    check("the add form can put a timer on a new script",
          "Run it on a timer" in page)

    base = {"csrf": tok, "device": "R1", "feature": "scripts",
            "script_name": "reboot", "script_action": "schedule"}

    print("a timer, every day")
    n = len(ROUTER.log)
    daily = {**base, "sched_every": "day", "sched_day": "mon",
             "sched_time": "03:00"}
    st, prev = req("/device/push", daily)
    check("Save timer previews first and sends nothing",
          st == 200 and "Dry run" in prev
          and "run script &#x27;reboot&#x27; every day at 03:00" in prev
          and not ops_sent(n))
    st, done = req("/device/push", {**daily, "apply": "1"})
    t = ROUTER.timers()
    check("one scheduler entry runs the script at 03:00 every day",
          st == 200 and len(t) == 1 and t[0]["interval"] == "1d"
          and t[0]["start-time"] == "03:00:00"
          and t[0]["on-event"] == '/system script run "reboot"'
          and t[0]["name"] == "mikromon-script-reboot"
          and t[0]["disabled"] == "no")
    check("it may reboot: the timer carries the script's full policy",
          "reboot" in t[0]["policy"].split(","))
    st, page = req("/device?name=R1&tab=scripts")
    check("the tab says so, with the router's next run",
          "Every day at 03:00" in page and "next run 2026-10-14" in page)

    print("a timer, every week")
    weekly = {**base, "sched_every": "week", "sched_day": "sat",
              "sched_time": "23:30"}
    st, done = req("/device/push", {**weekly, "apply": "1"})
    t = ROUTER.timers()
    start = datetime.date.fromisoformat(t[0]["start-date"])
    check("the same entry moves to Saturdays at 23:30, not a second one",
          len(t) == 1 and t[0]["interval"] == "1w"
          and t[0]["start-time"] == "23:30:00")
    check("the start date is a Saturday on or before today, in the ISO form "
          "a 7.10+ router reads",
          start.weekday() == 5 and start <= datetime.date.today())
    st, prev = req("/device/push", weekly)
    check("saving the same timer again changes nothing, though the router "
          "shows 7d back as 1w", "no changes" in prev)
    st, page = req("/device?name=R1&tab=scripts")
    check("the tab reads it back as Saturdays", "Every Saturday at 23:30" in page)

    print("bad input is refused before anything is sent")
    n = len(ROUTER.log)
    st, prev = req("/device/push", {**weekly, "sched_time": "25:00"})
    check("a time that is not HH:MM is refused, with what to type",
          "like 03:00" in html.unescape(prev) and not ops_sent(n))
    st, prev = req("/device/push", {**weekly, "sched_day": "funday"})
    check("a week with no day is refused", "Pick the day" in prev
          and not ops_sent(n))

    print("off, and removing the script")
    st, done = req("/device/push", {**base, "sched_every": "off", "apply": "1"})
    check("Not scheduled takes the timer off", ROUTER.timers() == [])
    check("the router's own scheduler entry was never touched",
          any(s["name"] == "their-own" for s in ROUTER.tables[SCHED]))
    req("/device/push", {**daily, "apply": "1"})
    st, prev = req("/device/push", {**base, "script_action": "remove"})
    check("Remove previews taking the timer off first, then the script",
          prev.find("remove the timer for script") != -1
          and prev.find("remove the timer for script")
          < prev.find("remove script name=reboot"))

    print("a new script with a timer, in one go")
    n = len(ROUTER.log)
    new = {"csrf": tok, "device": "R1", "feature": "scripts",
           "new_name": "nightly-reboot", "new_source": "/system reboot",
           "sched_every": "week", "sched_day": "sun", "sched_time": "02:15"}
    st, done = req("/device/push", {**new, "apply": "1"})
    adds = [e for e in ROUTER.log[n:] if e[0] == "add"]
    check("the script goes on first, then its timer",
          [e[1] for e in adds if e[1] in (SCRIPT, SCHED)] == [SCRIPT, SCHED]
          and any(t["on-event"] == '/system script run "nightly-reboot"'
                  and t["interval"] == "1w" for t in ROUTER.timers()))
    check("the script named 2024 was left alone -- read back as a number, it "
          "used to be added again and the original removed",
          not [e for e in ROUTER.log[n:] if e[1] == SCRIPT and (
              e[2] == "*3" or (isinstance(e[2], dict)
                               and e[2].get("name") == "2024"))])
    n = len(ROUTER.log)
    req("/device/push", {**new, "sched_every": "off",
                         "new_source": "/system reboot\n", "apply": "1"})
    check("re-saving a script with No on the add form leaves its timer be",
          any(t["name"] == "mikromon-script-nightly-reboot"
              for t in ROUTER.timers()) and not ops_sent(n))

    print("Run on a script that restarts the router")
    st, prev = req("/device/push", {**base, "script_action": "run"})
    box = re.search(r'name="safe_revert" value="1"([^>]*)>', prev)
    check("Safe mode is offered but left unticked, and it says why",
          box is not None and "checked" not in box.group(1)
          and "restarts the router" in prev)
    req("/device/push", {"csrf": tok, "device": "R1", "feature": "scripts",
                         "new_name": "log-it", "new_source": ":log info x",
                         "apply": "1"})
    st, prev = req("/device/push", {**base, "script_action": "run",
                                    "script_name": "log-it"})
    box = re.search(r'name="safe_revert" value="1"([^>]*)>', prev)
    check("any other script keeps Safe mode ticked",
          box is not None and "checked" in box.group(1))

    print("names")
    n = len(ROUTER.log)
    st, prev = req("/device/push", {"csrf": tok, "device": "R1",
                                    "feature": "scripts", "new_name": "2026",
                                    "new_source": ":log info x"})
    check("an all-digit name is refused, saying why",
          "name with a letter in it" in prev
          and not [e for e in ROUTER.log[n:] if e[0] != "run"])
finally:
    srv.shutdown()
    push_pkg.rw_device = _orig_rw

print("dates in the form each RouterOS reads")


def _api(version):
    return types.SimpleNamespace(fetch=lambda path: (
        [{"version": version}] if path == ("system", "resource") else []))


old = F._week_start(_api("6.49.8"), "mon")
check("a router before 7.10 gets oct/12/2026, and it is a Monday",
      re.fullmatch(r"[a-z]{3}/\d\d/\d{4}", old) is not None
      and F._ros_date(old).weekday() == 0)
new = F._week_start(_api("7.16"), "fri")
check("7.10 and later get 2026-10-09, and it is a Friday",
      re.fullmatch(r"\d{4}-\d\d-\d\d", new) is not None
      and F._ros_date(new).weekday() == 4)
check("a start time of 'startup' or a blank date reads as no date, not an "
      "exception", F._ros_date("startup") is None and F._ros_date("") is None)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL SCRIPTS TAB TESTS PASSED")
