"""End-to-end auth test for the web dashboard: email login, companies (orgs),
per-user device scoping, cross-org isolation, self-signup, /account self-edit,
the legacy->multi-tenant migration, owner-only access, /metrics token and CSRF.
Runs a real server on localhost.

Run:  ./.venv/Scripts/python.exe tests/web_auth_test.py
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import re
import sqlite3
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import web
from mikromon.auth import AuthStore
from mikromon.config import DEFAULT_THRESHOLDS
from mikromon.devices_store import DevicesStore
from mikromon.metrics import MetricsStore

FAILS = []
BASE = "http://127.0.0.1:8098"
DEF = dict(DEFAULT_THRESHOLDS)


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


def opener(redirect=True):
    handlers = [urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())]
    if not redirect:
        class _NR(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        handlers.append(_NR)
    return urllib.request.build_opener(*handlers)


def req(op, path, data=None, base=BASE):
    body = urllib.parse.urlencode(data).encode() if data else None
    try:
        r = op.open(urllib.request.Request(base + path, data=body), timeout=5)
        return getattr(r, "status", r.code), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def csrf_of(body):
    return re.search(r'name="csrf" value="([^"]+)"', body).group(1)


# ---- fixtures --------------------------------------------------------------
tmp = tempfile.mkdtemp()
mdb, sfile, adb, wdb = (os.path.join(tmp, x)
                        for x in ("m.db", "state.json", "a.db", "dev.db"))
ms = MetricsStore(mdb)
now = time.time()
ms.record([(now, "R1", "cpu", "", 10), (now, "R1", "up", "", 1),
           (now, "R2", "cpu", "", 20), (now, "R2", "up", "", 1),
           (now, "R3", "cpu", "", 30), (now, "R3", "up", "", 1)])
ms.close()
with open(sfile, "w") as fh:
    json.dump({"devices": {n: {"conditions": {}} for n in ("R1", "R2", "R3")}}, fh)

# Two companies. Acme owns R1 + R2; Other Co owns R3.
a = AuthStore(adb)
acme = a.signup("admin@acme.test", "admin123", "Acme")        # org 1, owner
a.add_member(acme, "bob@acme.test", "bob123", devices=["R2"])  # member, R2 only
other = a.signup("zoe@other.test", "zoe12345", "Other Co")     # org 2, owner
a.close()

ds = DevicesStore(wdb)
ds.upsert({"name": "R1", "host": "10.0.0.1"}, DEF, org_id=acme)
ds.upsert({"name": "R2", "host": "10.0.0.2"}, DEF, org_id=acme)
ds.upsert({"name": "R3", "host": "10.0.0.3"}, DEF, org_id=other)
ds.close()

print("AuthStore (email + orgs):")
a = AuthStore(adb)
check("verify good password", a.verify("admin@acme.test", "admin123") is not None)
check("login is case-insensitive on email",
      a.verify("Admin@Acme.test", "admin123") is not None)
check("reject bad password", a.verify("admin@acme.test", "nope") is None)
admin = a.get_user("admin@acme.test")
bob = a.get_user("bob@acme.test")
zoe = a.get_user("zoe@other.test")
check("owner role + own company", a.is_owner(admin) and admin["org_id"] == acme)
check("member role", not a.is_owner(bob) and bob["role"] == "member")
check("two distinct companies", acme != other and zoe["org_id"] == other)
check("owner sees all org devices",
      a.allowed_devices(admin, ["R1", "R2"]) == ["R1", "R2"])
check("member scoped to allowed", a.allowed_devices(bob, ["R1", "R2"]) == ["R2"])
check("can_see honours the device's org",
      a.can_see(admin, "R1", device_org=acme)
      and not a.can_see(admin, "R3", device_org=other))
a.close()

# ---- legacy -> multi-tenant migration --------------------------------------
print("Legacy schema migration:")
ldb = os.path.join(tmp, "legacy.db")
lc = sqlite3.connect(ldb)
lc.executescript(
    "CREATE TABLE users (username TEXT PRIMARY KEY, pw_hash TEXT, salt TEXT, "
    "iterations INTEGER, role TEXT, devices TEXT, created REAL);")
salt, pw, iters = __import__("mikromon.auth", fromlist=["hash_password"]) \
    .hash_password("oldpass")
lc.execute("INSERT INTO users VALUES (?,?,?,?,?,?,?)",
           ("oldadmin", pw, salt, iters, "admin", "*", now))
lc.execute("INSERT INTO users VALUES (?,?,?,?,?,?,?)",
           ("olduser", pw, salt, iters, "user", '["R2"]', now))
lc.commit()
lc.close()
am = AuthStore(ldb)
mu = am.get_user("oldadmin")
check("legacy admin still logs in (by username as email)",
      am.verify("oldadmin", "oldpass") is not None)
check("legacy admin -> owner", mu and mu["role"] == "owner")
check("everyone landed in one Default company",
      mu["org_id"] == am.get_user("olduser")["org_id"]
      and am.org_name(mu["org_id"]) == "Default")
check("legacy 'user' -> member, devices preserved",
      am.get_user("olduser")["role"] == "member"
      and am.get_user("olduser")["devices"] == ["R2"])
am.close()

# ---- self-signup on a fresh empty server -----------------------------------
print("Self-signup (anyone creates a company):")
adb_empty = os.path.join(tmp, "empty.db")
AuthStore(adb_empty).close()
srv0 = ThreadingHTTPServer(("127.0.0.1", 8097), web.make_handler(
    mdb, sfile, AuthStore(adb_empty), web.SessionManager()))
threading.Thread(target=srv0.serve_forever, daemon=True).start()
B0 = "http://127.0.0.1:8097"
try:
    st, _ = req(opener(redirect=False), "/", base=B0)
    check("no accounts -> / redirects to /signup", st == 303)
    st, body = req(opener(), "/signup", base=B0)
    check("/signup shows the create-company form",
          st == 200 and "company" in body.lower())
    op0 = opener()
    st, body = req(op0, "/signup",
                   {"company": "Startup", "email": "founder@startup.test",
                    "password": "startup1"}, B0)
    check("signing up creates the company + logs in",
          st == 200 and "mikromon" in body)
    st, body = req(op0, "/signup", base=B0)
    check("a logged-in visitor to /signup lands on the dashboard",
          st == 200 and "create your company account" not in body.lower())
    a3 = AuthStore(adb_empty)
    u = a3.get_user("founder@startup.test")
    check("new account persisted as owner of its company",
          u and u["role"] == "owner" and a3.org_name(u["org_id"]) == "Startup")
    a3.close()
finally:
    srv0.shutdown()
    srv0.server_close()

# ---- live server (with the devices DB so org isolation is real) ------------
srv = ThreadingHTTPServer(("127.0.0.1", 8098), web.make_handler(
    mdb, sfile, AuthStore(adb), web.SessionManager(),
    secure_cookies=False, metrics_token="promtok", devices_db=wdb, defaults=DEF))
threading.Thread(target=srv.serve_forever, daemon=True).start()
try:
    print("Unauthenticated:")
    st, _ = req(opener(redirect=False), "/")
    check("GET / -> redirect to login", st == 303)
    st, body = req(opener(), "/login")
    check("GET /login -> form", st == 200 and "sign in" in body.lower())
    st, _ = req(opener(redirect=False), "/api/devices")
    check("GET /api/devices -> 401", st == 401)

    print("Owner login + company-wide visibility:")
    admin = opener()
    st, body = req(admin, "/login",
                   {"email": "admin@acme.test", "password": "admin123"})
    check("login owner -> dashboard with Acme's routers (not R3)",
          st == 200 and "R1" in body and "R2" in body and "R3" not in body)
    st, body = req(admin, "/api/devices")
    check("owner /api/devices sees R1+R2 only",
          {d["device"] for d in json.loads(body)} == {"R1", "R2"})
    st, body = req(admin, "/admin")
    check("owner can open the Team page", st == 200 and "Team" in body)

    print("Scoped member (bob -> only R2):")
    bob = opener()
    st, body = req(bob, "/login", {"email": "bob@acme.test", "password": "bob123"})
    check("bob dashboard shows R2 not R1",
          st == 200 and "R2" in body and "R1" not in body)
    st, body = req(bob, "/api/devices")
    check("bob /api/devices sees only R2",
          {d["device"] for d in json.loads(body)} == {"R2"})
    st, _ = req(bob, "/api/series?device=R1&metric=cpu")
    check("bob blocked from R1 series (403)", st == 403)
    st, _ = req(bob, "/admin")
    check("member blocked from the Team page (403)", st == 403)

    print("Cross-company isolation (Other Co):")
    zoe = opener()
    st, body = req(zoe, "/login", {"email": "zoe@other.test", "password": "zoe12345"})
    check("zoe sees only her own R3",
          st == 200 and "R3" in body and "R1" not in body and "R2" not in body)
    st, body = req(zoe, "/api/devices")
    check("zoe /api/devices sees only R3",
          {d["device"] for d in json.loads(body)} == {"R3"})
    st, _ = req(zoe, "/api/series?device=R1&metric=cpu")
    check("zoe blocked from Acme's R1 series (403)", st == 403)
    st, _ = req(zoe, "/device?name=R1")
    check("zoe blocked from Acme's R1 device page (403)", st == 403)

    print("Account self-service (edit email/password):")
    _, acct = req(bob, "/account")
    bc = csrf_of(acct)
    st, _ = req(bob, "/account", {"csrf": bc, "email": "bob@acme.test",
                "password": "bobnewpw"})
    a4 = AuthStore(adb)
    check("password change takes effect",
          a4.verify("bob@acme.test", "bobnewpw") is not None
          and a4.verify("bob@acme.test", "bob123") is None)
    a4.close()
    _, acct = req(bob, "/account")
    bc = csrf_of(acct)
    st, _ = req(bob, "/account", {"csrf": bc, "email": "bobby@acme.test",
                "password": ""})
    a4 = AuthStore(adb)
    check("email change takes effect + keeps session",
          a4.get_user("bobby@acme.test") is not None
          and a4.get_user("bob@acme.test") is None)
    a4.close()
    st, body = req(bob, "/api/devices")
    check("still logged in under the new email", st == 200)

    print("Prometheus /metrics:")
    st, _ = req(opener(), "/metrics")
    check("no token -> 401", st == 401)
    st, body = req(opener(), "/metrics?token=promtok")
    check("token -> 200 with all devices",
          st == 200 and "R1" in body and "R3" in body)

    print("Owner adds a member (with CSRF) + write isolation:")
    _, adminpage = req(admin, "/admin")
    csrf = csrf_of(adminpage)
    st, _ = req(admin, "/admin/add", {"csrf": csrf, "email": "carol@acme.test",
                "password": "carol123", "role": "member", "devices": "R1"})
    a2 = AuthStore(adb)
    carol = a2.get_user("carol@acme.test")
    check("new member created in the owner's company + scoped",
          carol is not None and carol["org_id"] == acme
          and carol["devices"] == ["R1"])
    a2.close()
    st, _ = req(admin, "/admin/add", {"email": "mallory@acme.test",
                "password": "x123456", "devices": "R1"})  # no csrf
    check("add without CSRF rejected (400)", st == 400)
    # An owner must not act on another company's device.
    st, _ = req(admin, "/device/wan", {"csrf": csrf, "device": "R3"})
    check("owner blocked from a device in another company (403)", st == 403)
finally:
    srv.shutdown()
    srv.server_close()

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL AUTH TESTS PASSED")
