"""The Backups tab's "Check for space to free", end to end.

A router whose flash is full cannot take a safety backup, so no change can be
made to it. The tab lists what is using the space and deletes what the
dashboard made itself -- and only that: a file put on the router any other
way is listed, never deleted, whatever the form sends.

Run:  ./.venv/Scripts/python.exe tests/flash_space_test.py
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import re
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mikromon.push as push_pkg
import mikromon.push.api as push_api
from mikromon import web
from mikromon.auth import AuthStore
from mikromon.config import DEFAULT_THRESHOLDS
from mikromon.devices_store import DevicesStore
from mikromon.metrics import MetricsStore

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


MB = 1024 * 1024


class FakeRouter:
    """A router's /file, /system/resource and friends, kept in memory.
    Deleting a file gives its size back to the free space."""

    def __init__(self):
        self.files = [
            {".id": "*1", "name": "flash/before-wan-20261001-090000.backup",
             "size": str(90 * 1024)},
            {".id": "*2", "name": "flash/before-dns-20261005-090000.backup",
             "size": str(95 * 1024)},
            {".id": "*3", "name": "flash/before-wan-20261008-090000.backup",
             "size": str(96 * 1024)},
            {".id": "*4", "name": "flash/routeros-7.16.2-mipsbe.npk",
             "size": str(11 * MB)},
            {".id": "*5", "name": "flash/site-before-move.backup",
             "size": str(94 * 1024)},
            {".id": "*6", "name": "flash", "type": "directory"},
        ]
        self.free = 20 * 1024
        self.ran = []

    def fetch(self, path):
        path = tuple(path)
        if path == ("file",):
            return [dict(f) for f in self.files]
        if path == ("system", "resource"):
            return [{"total-hdd-space": str(16 * MB),
                     "free-hdd-space": str(self.free)}]
        return []

    def execute(self, op):
        if op.action == "remove" and op.path == ("file",):
            gone = [f for f in self.files if f[".id"] == op.params[".id"]]
            self.files = [f for f in self.files if f not in gone]
            self.free += sum(int(f.get("size") or 0) for f in gone)
            return None
        self.ran.append(op)
        return None


router = FakeRouter()


class _Dev:
    def close(self):
        pass


class _Api:
    def __init__(self, dev):
        pass

    def connect(self):
        return self

    def close(self):
        pass

    def fetch(self, path):
        return router.fetch(path)

    def execute(self, op):
        return router.execute(op)


tmp = tempfile.mkdtemp()
mdb, sfile, adb, ddb, pdb = (os.path.join(tmp, x) for x in (
    "m.db", "s.json", "a.db", "d.db", "p.db"))
MetricsStore(mdb).close()
with open(sfile, "w") as fh:
    json.dump({"devices": {}}, fh)
auth = AuthStore(adb)
org = auth.signup("owner@alpha.test", "secret123", "Alpha")
DEF = dict(DEFAULT_THRESHOLDS)
ds = DevicesStore(ddb)
ds.upsert({"name": "R1", "host": "10.0.0.1", "username": "u",
           "password": "p"}, DEF, org_id=org)
ds.close()

orig = (push_pkg.rw_device, push_api.PushApi)
push_pkg.rw_device = lambda cfg: _Dev()
push_api.PushApi = _Api
srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, auth, web.SessionManager(), secure_cookies=False,
    devices_db=ddb, defaults=DEF, push_log_db=pdb))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()

op = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def req(path, data=None):
    body = urllib.parse.urlencode(data, doseq=True).encode() if data else None
    try:
        r = op.open(urllib.request.Request(BASE + path, data=body), timeout=10)
        return r.status, r.read().decode("utf-8", "replace"), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), ""


try:
    req("/login", {"email": "owner@alpha.test", "password": "secret123"})
    st, page, _ = req("/device?name=R1&tab=backups")
    check("the Backups tab offers the check", st == 200
          and "Check for space to free" in page
          and "never deletes a file it did not make" in page)
    csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    check("...and Delete only next to the dashboard's own backups",
          page.count('value="delete"') == 3
          and "Not made by the dashboard" in page)

    st, page, _ = req("/device?name=R1&tab=backups&scan=1")
    boxes = re.findall(r'<input type="checkbox"[^>]*>', page)
    check("checking lists the dashboard's backups with checkboxes, the old "
          "one ticked and the newest not",
          len(boxes) == 3
          and sum(" checked" in b for b in boxes) == 2
          and "routeros-7.16.2-mipsbe.npk" in page
          and 'value="flash/routeros-7.16.2-mipsbe.npk"' not in page)

    st, page, url = req("/device/backup", {
        "csrf": csrf, "device": "R1", "backup_action": "cleanup",
        "file": ["flash/before-wan-20261001-090000.backup",
                 "flash/before-dns-20261005-090000.backup",
                 "flash/routeros-7.16.2-mipsbe.npk",
                 "flash/site-before-move.backup"]})
    names = {f["name"] for f in router.files}
    check("Delete selected removes the dashboard's own backups",
          "flash/before-wan-20261001-090000.backup" not in names
          and "flash/before-dns-20261005-090000.backup" not in names)
    check("...and nothing else, even when the form names other files",
          "flash/routeros-7.16.2-mipsbe.npk" in names
          and "flash/site-before-move.backup" in names
          and "flash/before-wan-20261008-090000.backup" in names)
    check("...then says how much it freed, from the router's own figures",
          "Deleted 2 file(s)." in page and "Flash now 205.0 KB free (was "
          "20.0 KB)" in page and "scan=1" in url)

    st, page, _ = req("/device/backup", {
        "csrf": csrf, "device": "R1", "backup_action": "delete",
        "bkname": "flash/site-before-move.backup"})
    check("a hand-made backup cannot be deleted from the page, even by a "
          "crafted request", "not made by the dashboard" in page
          and any(f["name"] == "flash/site-before-move.backup"
                  for f in router.files))

    # Still nearly full, so a new backup is refused rather than squeezed in.
    st, page, _ = req("/device/backup", {"csrf": csrf, "device": "R1",
                                         "apply": "1", "bkname": ""})
    check("with the flash still nearly full, a new backup is refused, and "
          "the page says what is taking the space",
          "Not enough free flash" in page
          and "routeros-7.16.2-mipsbe.npk" in page and not router.ran)
    # ...which the owner removes in Winbox, as the page says.
    router.files = [f for f in router.files if not f["name"].endswith(".npk")]
    router.free += 11 * MB

    st, page, _ = req("/device/backup", {"csrf": csrf, "device": "R1",
                                         "bkname": "before move"})
    label = re.search(r'name="bkname" value="([^"]+)"', page)
    check("a backup made with a label is named as the dashboard's own",
          label is not None
          and re.fullmatch(r"mikromon-before-move-\d{8}-\d{6}", label.group(1)))
    req("/device/backup", {"csrf": csrf, "device": "R1", "apply": "1",
                           "bkname": label.group(1) if label else ""})
    saved = [o.params.get("name") for o in router.ran
             if o.params.get("_cmd") == "save"]
    check("...and confirming saves it under exactly that name",
          saved == [label.group(1) if label else None])
finally:
    srv.shutdown()
    srv.server_close()
    push_pkg.rw_device, push_api.PushApi = orig

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL FLASH SPACE TESTS PASSED")
