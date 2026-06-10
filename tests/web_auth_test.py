"""End-to-end auth test for the web dashboard: login, per-user device scoping,
admin-only access, /metrics token, and CSRF. Runs a real server on localhost.

Run:  ./.venv/Scripts/python.exe tests/web_auth_test.py
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import re
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
from mikromon.metrics import MetricsStore

FAILS = []
BASE = "http://127.0.0.1:8098"


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


# ---- fixtures --------------------------------------------------------------
tmp = tempfile.mkdtemp()
mdb, sfile, adb = (os.path.join(tmp, x) for x in ("m.db", "state.json", "a.db"))
ms = MetricsStore(mdb)
now = time.time()
ms.record([(now, "R1", "cpu", "", 10), (now, "R1", "up", "", 1),
           (now, "R2", "cpu", "", 20), (now, "R2", "up", "", 1)])
ms.close()
with open(sfile, "w") as fh:
    json.dump({"devices": {"R1": {"conditions": {}}, "R2": {"conditions": {}}}}, fh)
a = AuthStore(adb)
a.add_user("admin", "admin123", role="admin", devices="*")
a.add_user("bob", "bob123", role="user", devices=["R2"])
a.close()

print("AuthStore:")
a = AuthStore(adb)
check("verify good password", a.verify("admin", "admin123") is not None)
check("reject bad password", a.verify("admin", "nope") is None)
check("admin sees all devices",
      a.allowed_devices(a.get_user("admin"), ["R1", "R2"]) == ["R1", "R2"])
check("user scoped to allowed",
      a.allowed_devices(a.get_user("bob"), ["R1", "R2"]) == ["R2"])
a.close()

# ---- first-run setup (empty auth DB, separate server) ----------------------
print("First-run setup (bootstrap admin in browser):")
adb_empty = os.path.join(tmp, "empty.db")
AuthStore(adb_empty).close()  # create schema, zero users
srv0 = ThreadingHTTPServer(("127.0.0.1", 8097), web.make_handler(
    mdb, sfile, AuthStore(adb_empty), web.SessionManager()))
threading.Thread(target=srv0.serve_forever, daemon=True).start()
B0 = "http://127.0.0.1:8097"
try:
    st, _ = req(opener(redirect=False), "/", base=B0)
    check("no admin -> / redirects to /setup", st == 303)
    st, body = req(opener(), "/setup", base=B0)
    check("/setup shows create-admin form",
          st == 200 and "administrator" in body.lower())
    op0 = opener()
    st, body = req(op0, "/setup", {"username": "root", "password": "rootpass"}, B0)
    check("creating first admin logs in -> dashboard", st == 200 and "mikromon" in body)
    st, _ = req(opener(redirect=False), "/setup", base=B0)
    check("setup closed once an admin exists (-> /login)", st == 303)
    a3 = AuthStore(adb_empty)
    u = a3.get_user("root")
    check("first admin persisted as admin/all-devices",
          u and u["role"] == "admin" and u["devices"] == "*")
    a3.close()
finally:
    srv0.shutdown()
    srv0.server_close()

# ---- live server -----------------------------------------------------------
srv = ThreadingHTTPServer(("127.0.0.1", 8098), web.make_handler(
    mdb, sfile, AuthStore(adb), web.SessionManager(),
    secure_cookies=False, metrics_token="promtok"))
threading.Thread(target=srv.serve_forever, daemon=True).start()
try:
    print("Unauthenticated:")
    st, _ = req(opener(redirect=False), "/")
    check("GET / -> redirect to login", st == 303)
    st, body = req(opener(), "/login")
    check("GET /login -> form", st == 200 and "sign in" in body.lower())
    st, _ = req(opener(redirect=False), "/api/devices")
    check("GET /api/devices -> 401", st == 401)

    print("Admin login + full visibility:")
    admin = opener()
    st, body = req(admin, "/login", {"username": "admin", "password": "admin123"})
    check("login admin -> dashboard with both routers",
          st == 200 and "R1" in body and "R2" in body)
    st, body = req(admin, "/api/devices")
    devs = {d["device"] for d in json.loads(body)}
    check("admin /api/devices sees R1+R2", devs == {"R1", "R2"})
    st, body = req(admin, "/admin")
    check("admin can open /admin", st == 200 and "User management" in body)

    print("Scoped user (bob -> only R2):")
    bob = opener()
    st, body = req(bob, "/login", {"username": "bob", "password": "bob123"})
    check("bob dashboard shows R2 not R1",
          st == 200 and "R2" in body and "R1" not in body)
    st, body = req(bob, "/api/devices")
    check("bob /api/devices sees only R2",
          {d["device"] for d in json.loads(body)} == {"R2"})
    st, _ = req(bob, "/api/series?device=R1&metric=cpu")
    check("bob blocked from R1 series (403)", st == 403)
    st, _ = req(bob, "/admin")
    check("bob blocked from /admin (403)", st == 403)

    print("Prometheus /metrics:")
    st, _ = req(opener(), "/metrics")
    check("no token -> 401", st == 401)
    st, body = req(opener(), "/metrics?token=promtok")
    check("token -> 200 with all devices",
          st == 200 and "R1" in body and "R2" in body)

    print("Admin creates a user (with CSRF):")
    _, adminpage = req(admin, "/admin")
    csrf = re.search(r'name="csrf" value="([^"]+)"', adminpage).group(1)
    st, _ = req(admin, "/admin/add", {"csrf": csrf, "username": "carol",
                "password": "carol123", "role": "user", "devices": "R1"})
    a2 = AuthStore(adb)
    check("new user created + scoped", a2.get_user("carol") is not None
          and a2.get_user("carol")["devices"] == ["R1"])
    a2.close()
    st, _ = req(admin, "/admin/add", {"username": "mallory",
                "password": "x123456", "devices": "R1"})  # no csrf
    check("add without CSRF rejected (400)", st == 400)
finally:
    srv.shutdown()
    srv.server_close()

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL AUTH TESTS PASSED")
