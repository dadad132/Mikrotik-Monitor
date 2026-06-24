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
import time
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

# keep_only sweeps orphan series so the devices DB stays authoritative.
mko = MetricsStore(os.path.join(tmp, "ko.db"))
mko.record([(1.0, "E1", "up", "", 1.0), (1.0, "Ghost", "up", "", 1.0)])
mko.keep_only({"E1", "E2"})
check("keep_only drops devices not in the keep set, keeps the rest",
      mko.devices() == ["E1"])
mko.keep_only(set())
check("keep_only with an empty set clears everything", mko.devices() == [])
mko.close()

# Web-managed mode: constructing the engine sweeps orphan metrics for any
# device no longer in the devices DB (deletes / old-build leftovers), so they
# can't keep haunting the dashboard.
mdb_e = os.path.join(tmp, "e-metrics.db")
now = time.time()  # recent ts so the retention prune doesn't pre-empt the sweep
mse = MetricsStore(mdb_e)
mse.record([(now, "E1", "up", "", 1.0), (now, "Ghost", "up", "", 1.0)])
mse.close()
Engine(AppConfig(state_file=os.path.join(tmp, "st2.json"), devices_db=edb,
                 metrics_db=mdb_e, defaults=DEF, devices=[]))
mse = MetricsStore(mdb_e)
left = mse.devices()
mse.close()
check("engine sweep keeps managed-device metrics, purges orphan metrics",
      "E1" in left and "Ghost" not in left)

print("Web render helpers (offline):")
cfgwan = build_device({"name": "R", "host": "1.1.1.1", "wan": {"links": [
    {"name": "Fibre", "interface": "ether1"},
    {"name": "LTE", "interface": "lte1"}]}}, DEF)
wed = web._wan_uplink_editor("R", cfgwan, "csrf")
check("SD-WAN WAN editor has up/down reorder controls",
      "pushMoveRow(this,-1)" in wed and "pushMoveRow(this,1)" in wed)
check("reorder JS is defined on feature tabs", "function pushMoveRow" in web._FEATURE_JS)
check("toggles render as on/off sliders",
      'class="switch"' in web._field_html(
          {"type": "toggle", "name": "opt", "value": "x", "label": "L"}))
# hub SSTP-secret registry: stable per-device tunnel IPs + chap-secrets writing
hub = {}
ip1 = web._alloc_tunnel_ip(hub, "A")
ip2 = web._alloc_tunnel_ip(hub, "B")
check("tunnel IPs are unique and stable per device",
      ip1 != ip2 and web._alloc_tunnel_ip(hub, "A") == ip1)
peersp = os.path.join(tmp, "wg-peers.conf")
ok1, _ = web._write_wg_peers(peersp, {
    "branch7": {"ip": "10.10.0.2", "pubkey": "PUBKEYB7="},
    "hq": {"ip": "10.10.0.3", "pubkey": "PUBKEYHQ="}})
body_peers = open(peersp).read()
check("WireGuard peers file lists each device as a [Peer]",
      ok1 and "PublicKey = PUBKEYB7=" in body_peers
      and "AllowedIPs = 10.10.0.2/32" in body_peers
      and body_peers.count("[Peer]") == 2)
kp = web._wg_keypair()
check("wg keypair helper returns a tuple (priv/pub or graceful None+err)",
      isinstance(kp, tuple) and len(kp) == 2)
# provisioning script: "lock API" binds api/api-ssl to the tunnel subnet + sets
# up API-SSL, so the API has no public exposure. Only emitted with a tunnel.
locked = web._provision_script(
    "R", {"host": "1.1.1.1"}, "mon", "pw1234567890", hub_ip="102.36.140.219",
    hub_pubkey="HUBKEY=", wg_priv="PRIV=", tunnel_ip="10.10.0.2",
    subnet="10.10.0.0/24", lock_api=True)
check("lock-API binds api + api-ssl to the tunnel subnet (plain API, no cert)",
      "/ip service set api address=10.10.0.0/24" in locked
      and "/ip service set api-ssl address=10.10.0.0/24" in locked
      and "certificate add" not in locked
      and "api-ssl certificate=" not in locked)
unlocked = web._provision_script(
    "R", {"host": "1.1.1.1"}, "mon", "pw1234567890", hub_ip="102.36.140.219",
    hub_pubkey="HUBKEY=", wg_priv="PRIV=", tunnel_ip="10.10.0.2",
    subnet="10.10.0.0/24", lock_api=False)
check("lock-API omitted when not requested",
      "/ip service set api address=" not in unlocked)
# single user: ONE full-access login does both monitoring and config-push
oneu = web._provision_script(
    "R", {"host": "1.1.1.1"}, "mikromon", "pw1234567890")
check("script creates exactly one full-access user (no second read-only user)",
      "/user add name=mikromon " in oneu and "group=full" in oneu
      and "group=read" not in oneu and oneu.count("/user add name=") == 1)
# dashboard hides devices with no data (added but never successfully polled)
check("dashboard hides a device with no data, shows one with telemetry",
      not web._device_has_data({"metrics": {}, "problems": [], "facts": {}})
      and web._device_has_data({"metrics": {"cpu": 5}, "problems": [],
                                "facts": {}})
      and web._device_has_data({"metrics": {}, "problems": [{"key": "x"}],
                                "facts": {}}))
itab = web._interfaces_table({"ifaces": [
    {"name": "ether1", "type": "ether", "running": "true",
     "mac-address": "AA:BB", "mtu": "1500", "comment": "WAN"},
    {"name": "bridge1", "type": "bridge", "running": "false", "disabled": "true"}],
    "addrs": [{"interface": "ether1", "address": "192.168.88.1/24"}]})
check("interfaces table shows type, status and IPs",
      "ether1" in itab and "ether" in itab and "bridge" in itab
      and "192.168.88.1/24" in itab and "disabled" in itab and "up" in itab)

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
        "api_port": "8728", "timeout": "25", "username": "monitor",
        "password": "secret",
        "link_name": ["Vodacom", "MTN", "LTE"],
        "link_iface": ["ether1", "ether2", "lte1"],
        "link_gw": ["", "", ""],
        "checks": ["resources", "interfaces"], "sources": ["dhcp"]})
    saved = DevicesStore(wdb)
    raw = saved.raw("WebR1")
    check("device added via web", raw is not None and raw["host"] == "9.9.9.9")
    check("API timeout captured from form", raw.get("timeout") == 25)
    check("checks captured from form",
          raw["checks"]["resources"] and not raw["checks"]["security"])
    check("3 WAN links captured in priority order",
          [l["name"] for l in raw["wan"]["links"]] == ["Vodacom", "MTN", "LTE"])
    saved.close()
    # API port is optional in the form: blank defaults to 8728, or 8729 with SSL.
    post(admin, "/devices/save", {
        "csrf": csrf, "original_name": "", "name": "SslR", "host": "1.2.3.4",
        "api_port": "", "use_ssl": "on", "username": "monitor", "password": "x",
        "checks": ["resources"]})
    saved = DevicesStore(wdb)
    check("blank API port + API-SSL defaults to 8729",
          (saved.raw("SslR") or {}).get("api_port") == 8729)
    saved.delete("SslR")
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
    # Web-managed mode: the devices DB is the single source of truth. A managed
    # device shows on the dashboard; a device with leftover metrics but NOT in
    # the Devices tab (an orphan) must NOT appear at all — it's gone the moment
    # it leaves the tab, with no need to "remove" it from the dashboard.
    ms = MetricsStore(mdb)
    ms.record([(1.0, "WebR1", "up", "", 1.0), (1.0, "GhostR", "up", "", 1.0)])
    ms.close()
    st, apidev = get(admin, "/api/devices")
    shown = [d.get("device") for d in json.loads(apidev)]
    check("managed device (in the Devices tab) shows on the dashboard",
          "WebR1" in shown)
    check("orphan device (metrics but not in the Devices tab) is hidden",
          "GhostR" not in shown)
    # The per-device Remove button still purges any leftover series from the DB.
    forget_st = post_status(admin, "/device/forget",
                            {"csrf": csrf, "device": "GhostR"})
    check("Remove button purges an orphan device's metrics from the DB",
          forget_st in (302, 303)
          and "GhostR" not in MetricsStore(mdb).devices())
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
                                  "tab=interfaces", "tab=scripts", "tab=harden",
                                  "tab=tunnel", "tab=hubtunnel", "tab=update",
                                  "tab=provision")))
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
    # --- Provision tab: generate a bootstrap script + save strong creds ---
    st, body = get(admin, "/device?name=WebR1&tab=provision")
    check("admin can open the Provision tab", st == 200 and "Connect (WinBox)" in body)
    check("credentials are hidden until revealed (masked + Show toggle)",
          'type="password"' in body and "mmReveal" in body)
    st, body = post(admin, "/device/provision",
                    {"csrf": csrf, "device": "WebR1", "pwuser": "mikromon",
                     "transport": "wg", "hub": "102.36.140.219",
                     "enable_api": "1", "harden": "1"})
    check("provision generates a bootstrap script (user + API)",
          st == 200 and "/user add name=mikromon" in body
          and "/ip service set api disabled=no" in body)
    check("provision script is guarded/idempotent (safe on configured units)",
          ":if ([:len [/user find name=mikromon]] = 0)" in body
          and '[/system identity get name] = &quot;MikroTik&quot;' in body)
    check("WG hub not set up here -> prompts to run install.sh (no tunnel block)",
          "install.sh" in body and "/interface wireguard add" not in body)
    # enabling the API is OPTIONAL: leaving the box unchecked omits the line
    st, body2 = post(admin, "/device/provision",
                     {"csrf": csrf, "device": "WebR1", "pwuser": "mikromon",
                      "transport": "wg", "hub": "102.36.140.219"})
    check("API enable is optional (omitted when unchecked)",
          st == 200 and "/user add name=mikromon" in body2
          and "/ip service set api disabled=no" not in body2)
    saved = DevicesStore(wdb)
    raw = saved.raw("WebR1")
    check("provision saved the single user + a strong generated password",
          raw["username"] == "mikromon" and len(raw.get("password", "")) >= 16
          and not raw.get("push_username"))
    saved.close()
    st = post_status(nobody, "/device/provision",
                     {"csrf": "x", "device": "WebR1"})
    check("non-admin blocked from provisioning (403)", st == 403)
    # seed leftover metrics + saved state, then prove delete purges them so the
    # device stops showing on the dashboard (it lists anything with samples).
    from mikromon.state import StateStore
    ms = MetricsStore(mdb)
    ms.record([(1.0, "WebR1", "up", "", 1.0)])
    check("device has metrics before delete", "WebR1" in ms.devices())
    ms.close()
    stt = StateStore(sfile).load()
    stt.facts("WebR1")["model"] = "RB5009"
    stt.save()
    st, _ = post(admin, "/devices/delete", {"csrf": csrf, "name": "WebR1"})
    saved = DevicesStore(wdb)
    check("device deleted via web", saved.names() == [])
    saved.close()
    ms = MetricsStore(mdb)
    check("delete purges the device's metrics (gone from dashboard)",
          "WebR1" not in ms.devices())
    ms.close()
    with open(sfile, encoding="utf-8") as fh:
        state_after = json.load(fh)
    check("delete purges the device's saved monitoring state",
          "WebR1" not in state_after.get("devices", {}))
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
