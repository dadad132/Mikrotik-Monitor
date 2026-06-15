"""Tests for web-managed devices: store CRUD, engine load/hot-reload, and the
admin /devices web flow (add / edit / delete, admin-only).

Run:  ./.venv/Scripts/python.exe tests/devices_test.py
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

from mikromon import web
from mikromon.auth import AuthStore
from mikromon.config import DEFAULT_THRESHOLDS, AppConfig, build_device
from mikromon.devices_store import DevicesStore
from mikromon.engine import Engine
from mikromon.metrics import MetricsStore

FAILS = []
DEF = dict(DEFAULT_THRESHOLDS)


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


tmp = tempfile.mkdtemp()

print("DevicesStore CRUD:")
ddb = os.path.join(tmp, "d.db")
ds = DevicesStore(ddb)
ds.upsert({"name": "R1", "host": "10.0.0.1", "checks": {"resources": True}}, DEF)
check("device stored", ds.names() == ["R1"])
check("raw round-trips host", ds.raw("R1")["host"] == "10.0.0.1")
cfgs = ds.list_configs(DEF)
check("builds DeviceConfig", len(cfgs) == 1 and cfgs[0].name == "R1")
ds.upsert({"name": "R1b", "host": "10.0.0.2"}, DEF, original_name="R1")
check("rename replaces old row", ds.names() == ["R1b"])
ds.delete("R1b")
check("delete works", ds.names() == [])
ds.seed_from([build_device({"name": "S1", "host": "1.1.1.1"}, DEF)], DEF)
check("seed_from populates empty store", ds.names() == ["S1"])
ds.close()

print("Engine loads + hot-reloads from store:")
edb = os.path.join(tmp, "e.db")
d = DevicesStore(edb)
d.upsert({"name": "E1", "host": "127.0.0.1"}, DEF)
d.close()
cfg = AppConfig(state_file=os.path.join(tmp, "st.json"), devices_db=edb,
                defaults=DEF, devices=[])
eng = Engine(cfg)
check("engine loads device from store", [x.name for x in eng.devices] == ["E1"])
d = DevicesStore(edb)
d.upsert({"name": "E2", "host": "127.0.0.2"}, DEF)
d.close()
eng.devices = eng._devices_from_store()
check("engine hot-reload sees new device",
      sorted(x.name for x in eng.devices) == ["E1", "E2"])

print("Web /devices flow (admin only):")
mdb, sfile, adb, wdb = (os.path.join(tmp, x) for x in
                        ("m.db", "s.json", "a.db", "w.db"))
MetricsStore(mdb).close()
with open(sfile, "w") as fh:
    json.dump({"devices": {}}, fh)
a = AuthStore(adb)
a.add_user("admin", "admin123", role="admin", devices="*")
a.add_user("bob", "bob123", role="user", devices=[])
a.close()
DevicesStore(wdb).close()

srv = ThreadingHTTPServer(("127.0.0.1", 8096), web.make_handler(
    mdb, sfile, AuthStore(adb), web.SessionManager(), devices_db=wdb, defaults=DEF))
threading.Thread(target=srv.serve_forever, daemon=True).start()
B = "http://127.0.0.1:8096"


def op_login(user, pw):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    op.open(urllib.request.Request(B + "/login", data=urllib.parse.urlencode(
        {"username": user, "password": pw}).encode()), timeout=5)
    op.cj = cj
    return op


class _NoRedir(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None  # don't auto-follow 303 (the target may poll a router)


def post_status(op, path, data):
    """POST and return just the status, WITHOUT following the 303 redirect."""
    o = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(op.cj), _NoRedir)
    body = urllib.parse.urlencode(data, doseq=True).encode()
    try:
        r = o.open(urllib.request.Request(B + path, data=body), timeout=8)
        return getattr(r, "status", r.code)
    except urllib.error.HTTPError as e:
        return e.code


def get(op, path):
    try:
        r = op.open(B + path, timeout=5)
        return getattr(r, "status", r.code), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def post(op, path, data):
    body = urllib.parse.urlencode(data, doseq=True).encode()
    try:
        r = op.open(urllib.request.Request(B + path, data=body), timeout=8)
        return getattr(r, "status", r.code), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


try:
    admin = op_login("admin", "admin123")
    st, body = get(admin, "/devices")
    check("admin GET /devices", st == 200 and "Add a device" in body)
    csrf = re.search(r'name="csrf" value="([^"]+)"', body).group(1)
    st, body = post(admin, "/devices/save", {
        "csrf": csrf, "original_name": "", "name": "WebR1", "host": "9.9.9.9",
        "api_port": "8728", "username": "monitor", "password": "secret",
        "link_name": ["Vodacom", "MTN", "LTE"],
        "link_iface": ["ether1", "ether2", "lte1"],
        "link_gw": ["", "", ""],
        "checks": ["resources", "interfaces"], "sources": ["dhcp"]})
    saved = DevicesStore(wdb)
    raw = saved.raw("WebR1")
    check("device added via web", raw is not None and raw["host"] == "9.9.9.9")
    check("checks captured from form",
          raw["checks"]["resources"] and not raw["checks"]["security"])
    check("3 WAN links captured in priority order",
          [l["name"] for l in raw["wan"]["links"]] == ["Vodacom", "MTN", "LTE"])
    saved.close()
    # edit: change host, leave password blank -> keep existing
    st, _ = post(admin, "/devices/save", {
        "csrf": csrf, "original_name": "WebR1", "name": "WebR1", "host": "8.8.8.8",
        "api_port": "8728", "username": "monitor", "password": "",
        "checks": ["resources"]})
    saved = DevicesStore(wdb)
    raw = saved.raw("WebR1")
    check("edit updates host, keeps password",
          raw["host"] == "8.8.8.8" and raw["password"] == "secret")
    saved.close()
    # --- Backups tab (config-push engine) wired into the web UI ---
    st, body = get(admin, "/device?name=WebR1")
    check("admin can open a web-managed device page (before any poll)",
          st == 200 and "Overview" in body and "tab=backups" in body)
    st, body = post(admin, "/device/backup",
                    {"csrf": csrf, "device": "WebR1", "bkname": "unittest"})
    check("backup dry-run preview works without a router",
          st == 200 and "Dry run" in body and "unittest" in body
          and "Confirm" in body)
    nobody = op_login("bob", "bob123")
    st, _ = get(nobody, "/device?name=WebR1&tab=backups")
    check("non-admin blocked from the Backups tab (403)", st == 403)
    st, _ = post(nobody, "/device/backup", {"csrf": "x", "device": "WebR1"})
    check("non-admin blocked from creating a backup (403)", st == 403)
    # --- all engines opened: device tabs + activity log ---
    st, body = get(admin, "/device?name=WebR1")
    check("device tab bar links every engine (sd-wan/security/qos/portfwd)",
          all(s in body for s in ("tab=sdwan", "tab=security", "tab=qos",
                                  "tab=portfwd", "tab=nextdns", "tab=remote",
                                  "tab=interfaces")))
    st, body = get(admin, "/logs")
    check("admin can open the activity log", st == 200 and "activity log" in body.lower())
    st, _ = get(nobody, "/logs")
    check("non-admin blocked from the activity log (403)", st == 403)
    st, _ = post(nobody, "/device/push",
                 {"csrf": "x", "device": "WebR1", "feature": "security"})
    check("non-admin blocked from pushing config (403)", st == 403)
    # --- WAN uplinks editable from the SD-WAN tab (saved to the device) ---
    st = post_status(admin, "/device/wan",
                     {"csrf": csrf, "device": "WebR1",
                      "link_name": ["Fibre", "LTE"],
                      "link_iface": ["ether1", "lte1"], "link_gw": ["", ""]})
    check("WAN save accepted (redirect)", st == 303)
    saved = DevicesStore(wdb)
    raw = saved.raw("WebR1")
    check("WAN uplinks saved from the SD-WAN tab",
          [l["interface"] for l in raw["wan"]["links"]] == ["ether1", "lte1"])
    saved.close()
    st = post_status(nobody, "/device/wan",
                     {"csrf": "x", "device": "WebR1", "link_iface": ["x"]})
    check("non-admin blocked from editing WAN (403)", st == 403)
    st, _ = post(admin, "/devices/delete", {"csrf": csrf, "name": "WebR1"})
    saved = DevicesStore(wdb)
    check("device deleted via web", saved.names() == [])
    saved.close()
    # non-admin is blocked
    bob = op_login("bob", "bob123")
    st, _ = get(bob, "/devices")
    check("non-admin blocked from /devices (403)", st == 403)
    st, _ = post(bob, "/devices/save", {"csrf": "x", "name": "X", "host": "1.1.1.1"})
    check("non-admin blocked from saving (403)", st == 403)
finally:
    srv.shutdown()
    srv.server_close()

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL DEVICE TESTS PASSED")
