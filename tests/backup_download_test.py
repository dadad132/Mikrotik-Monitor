"""A router's backups can be downloaded, to keep somewhere other than the router.

A backup kept only on the router's flash goes with the router -- stolen,
burnt out, reset. The Guide used to say "download it in Winbox", which most
people reading it cannot do. Now:
  * every backup on the Backups tab has a Download button, and making one
    lands back on the tab with "Download it" for the file just made
  * the file is copied off the router over SFTP, through the tunnel, with
    the dashboard's own login; RouterOS's API cannot hand over a binary file
  * only a file the router lists as a backup is handed over, only to whoever
    may manage that router, and every download is in the activity log
  * SSH switched off, or refusing the login, is said in plain words

Run:  ./.venv/Scripts/python.exe tests/backup_download_test.py
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
import mikromon.router_files as RF  # noqa: E402
from mikromon import web  # noqa: E402
from mikromon.auth import AuthStore  # noqa: E402
from mikromon.config import DEFAULT_THRESHOLDS  # noqa: E402
from mikromon.devices_store import DevicesStore  # noqa: E402
from mikromon.metrics import MetricsStore  # noqa: E402
from mikromon.push.audit import AuditLog  # noqa: E402
from mikromon.webguard import GuardedHTTPServer  # noqa: E402

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


FILE = ("file",)
SVC = ("ip", "service")


class FakePath:
    def __init__(self, router, segs):
        self.r, self.segs = router, segs

    def __iter__(self):
        return iter([dict(x) for x in self.r.tables.setdefault(self.segs, [])])

    def add(self, **params):
        nid = f"*{next(self.r.ids)}"
        self.r.tables.setdefault(self.segs, []).append(
            {".id": nid, **{k: str(v) for k, v in params.items()}})
        return nid

    def update(self, **params):
        pass

    def remove(self, rid):
        rows = self.r.tables.setdefault(self.segs, [])
        self.r.tables[self.segs] = [x for x in rows if x.get(".id") != rid]

    def __call__(self, cmd, **params):
        # /system backup save writes the file, as the router would.
        if self.segs == ("system", "backup") and cmd == "save":
            self.r.tables[FILE].append(
                {".id": f"*{next(self.r.ids)}",
                 "name": "flash/" + params["name"] + ".backup",
                 "size": "41.2KiB", "creation-time": "2026-10-23 10:00:00"})
        return iter([])


class FakeRouter:
    def __init__(self):
        self.ids = itertools.count(100)
        self.tables = {
            ("system", "resource"): [{"version": "7.16.2", "uptime": "3d",
                                      "free-hdd-space": "80000000",
                                      "total-hdd-space": "128000000"}],
            FILE: [{".id": "*1", "name": "flash/mikromon-20261020-090000.backup",
                    "size": "40.1KiB", "creation-time": "2026-10-20 09:00:00"},
                   {".id": "*2", "name": "flash/winbox-export.rsc",
                    "size": "6.0KiB", "creation-time": "2026-10-19 08:00:00"},
                   {".id": "*3", "name": "flash/routeros-7.18.2-arm.npk",
                    "size": "12.4MiB", "creation-time": "2026-10-18 08:00:00"}],
            SVC: [{".id": "*9", "name": "ssh", "port": "2222",
                   "disabled": "false"}],
        }


class FakeDevice:
    def __init__(self, router, cfg):
        self.router, self.cfg, self.api = router, cfg, None

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
push_pkg.rw_device = lambda cfg: FakeDevice(ROUTER, cfg)
pulled = []
_orig_dl = RF.download
mode = {"raise": None}


def fake_download(host, port, username, password, path, timeout=20.0):
    pulled.append((host, port, username, path))
    if mode["raise"]:
        raise RF.RouterFileError(mode["raise"])
    return b"MIKROTIK-BACKUP\x00\x01\x02" + path.encode()


RF.download = fake_download

tmp = tempfile.mkdtemp()
mdb, sfile, adb, ddb, pdb = (os.path.join(tmp, x) for x in
                             ("m.db", "s.json", "a.db", "d.db", "p.db"))
MetricsStore(mdb).close()
with open(sfile, "w") as fh:
    json.dump({"devices": {}}, fh)
a = AuthStore(adb)
org = a.signup("owner@alpha.test", "a-password-for-the-test", "Alpha")
a.add_member(org, "member@alpha.test", "a-password-for-the-test")
a.close()
ds = DevicesStore(ddb)
ds.upsert({"name": "R1", "host": "10.10.3.7", "username": "mkm-1",
           "password": "k7Vq2pXw9tLm"}, DEFAULT_THRESHOLDS, org_id=org)
ds.close()
srv = GuardedHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, AuthStore(adb), web.SessionManager(), secure_cookies=False,
    devices_db=ddb, defaults=dict(DEFAULT_THRESHOLDS), push_log_db=pdb,
    admin_2fa=False))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()


def opener():
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def req(op, path, data=None, raw=False):
    body = urllib.parse.urlencode(data, doseq=True).encode() if data else None
    try:
        r = op.open(urllib.request.Request(BASE + path, data=body), timeout=30)
        payload = r.read()
        return (r.status, payload if raw else
                html.unescape(payload.decode("utf-8", "replace")), r.headers)
    except urllib.error.HTTPError as e:
        payload = e.read()
        return (e.code, payload if raw else
                html.unescape(payload.decode("utf-8", "replace")), e.headers)


owner = opener()
req(owner, "/login", {"email": "owner@alpha.test",
                      "password": "a-password-for-the-test"})
BK = "flash/mikromon-20261020-090000.backup"

try:
    print("On the Backups tab")
    st, page, _ = req(owner, "/device?name=R1&tab=backups")
    tok = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    check("every backup has a Download button -- whoever made it",
          page.count(">Download</a>") == 2
          and f"/device/backup/download?device=R1&file="
              f"{urllib.parse.quote(BK)}" in page
          and "file=flash/winbox-export.rsc" in page.replace("%2F", "/"))
    check("...and a package file, which is not a backup, has none",
          "routeros-7.18.2-arm.npk" not in page)
    check("it says a backup is the whole configuration, keys and all",
          "passwords and keys included" in page)

    print("\nDownloading one")
    st, body, hdr = req(owner, "/device/backup/download?device=R1&file="
                        + urllib.parse.quote(BK), raw=True)
    check("the file comes back as a download", st == 200
          and body.startswith(b"MIKROTIK-BACKUP")
          and hdr.get("Content-Type") == "application/octet-stream"
          and 'attachment; filename="R1-mikromon-20261020-090000.backup"'
          in hdr.get("Content-Disposition", ""))
    check("...copied off the router over SFTP through the tunnel, on the SSH "
          "port the router says it uses, with the dashboard's login",
          pulled[-1] == ("10.10.3.7", 2222, "mkm-1", BK))
    check("...and not kept by the browser's cache",
          hdr.get("Cache-Control") == "no-store")
    log = AuditLog(pdb).recent(5, device="R1")
    check("the download is in the activity log, with who and what",
          any(r["feature"] == "backup:download" and r["status"] == "ok"
              and BK in r["summary"] and r["username"] == "owner@alpha.test"
              for r in log))

    print("\nWhat is not handed over")
    n = len(pulled)
    st, page, _ = req(owner, "/device/backup/download?device=R1&file="
                      + urllib.parse.quote("flash/routeros-7.18.2-arm.npk"))
    check("a file the router does not list as a backup is refused, and "
          "nothing is fetched", "is not a backup on this router" in page
          and len(pulled) == n)
    st, page, _ = req(owner, "/device/backup/download?device=R1&file="
                      + urllib.parse.quote("../../etc/passwd"))
    check("...nor a made-up path", "is not a backup on this router" in page
          and len(pulled) == n)
    member = opener()
    req(member, "/login", {"email": "member@alpha.test",
                           "password": "a-password-for-the-test"})
    st, page, _ = req(member, "/device/backup/download?device=R1&file="
                      + urllib.parse.quote(BK))
    check("a member the router is not allocated to cannot download it",
          st == 403 and "Not allowed" in page and len(pulled) == n)

    print("\nWhen it cannot be copied off")
    ROUTER.tables[SVC][0]["disabled"] = "true"
    st, page, _ = req(owner, "/device/backup/download?device=R1&file="
                      + urllib.parse.quote(BK))
    check("SSH switched off is said in plain words, with what to do, and "
          "nothing is tried", "SSH is switched off on this router" in page
          and "Could not download it:" in page and len(pulled) == n)
    ROUTER.tables[SVC][0]["disabled"] = "false"
    mode["raise"] = ("The router refused the dashboard's login (mkm-1) over "
                     "SSH.")
    st, page, _ = req(owner, "/device/backup/download?device=R1&file="
                      + urllib.parse.quote(BK))
    check("a copy that fails says why, on the Backups tab",
          "refused the dashboard's login" in page
          and "Could not download it:" in page)
    mode["raise"] = None

    print("\nStraight after making one")
    st, page, _ = req(owner, "/device/backup", {
        "csrf": tok, "device": "R1", "bkname": "before-trip", "apply": "1"})
    made = [f["name"] for f in ROUTER.tables[FILE]
            if "before-trip" in f["name"]]
    check("the tab says it was made and offers to download that one there "
          "and then", made and "Backup created on the router." in page
          and ">Download it</a>" in page
          and urllib.parse.quote(made[0]) in page)
finally:
    srv.shutdown()
    push_pkg.rw_device = _orig_rw
    RF.download = _orig_dl

print("\nCopying a file over SFTP")


class AuthErr(Exception):
    pass


class SSHErr(Exception):
    pass


def fake_paramiko(connect=None, stat=None, data=b"x", size=None):
    """Just enough of paramiko for router_files.download."""
    class File:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return data

    class SFTP:
        def stat(self, path):
            if stat:
                raise stat
            return types.SimpleNamespace(
                st_size=len(data) if size is None else size)

        def open(self, path, mode):
            return File()

        def close(self):
            pass

    class Client:
        def set_missing_host_key_policy(self, p):
            pass

        def connect(self, *a, **k):
            if connect:
                raise connect

        def open_sftp(self):
            return SFTP()

        def close(self):
            pass

    return types.SimpleNamespace(
        SSHClient=Client, AutoAddPolicy=lambda: None,
        AuthenticationException=AuthErr, SSHException=SSHErr)


def attempt(**kw):
    sys.modules["paramiko"] = fake_paramiko(**kw)
    try:
        return _orig_dl("10.10.3.7", 22, "mkm-1", "pw", BK)
    except RF.RouterFileError as exc:
        return str(exc)
    finally:
        sys.modules.pop("paramiko", None)


check("a file that is there comes back as its bytes",
      attempt(data=b"BACKUP") == b"BACKUP")
check("a refused login says which login, and what it needs",
      "refused the dashboard's login (mkm-1)" in attempt(connect=AuthErr())
      and "ssh and ftp" in attempt(connect=AuthErr()))
check("SSH that cannot be reached says where it tried",
      "Could not open SSH on the router (10.10.3.7, port 22)"
      in attempt(connect=OSError("timed out")))
check("a file gone from the router says so",
      "no longer on the router" in attempt(stat=FileNotFoundError()))
check("something far too big to be a backup is refused",
      "not a backup this page can hand over"
      in attempt(size=RF.MAX_BYTES + 1))

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL BACKUP DOWNLOAD TESTS PASSED")
