"""Guest Wi-Fi and CAPsMAN wired into the cockpit, over real HTTP.

The backend stores and planners have their own tests. This suite is about the
parts a user actually touches: the portal a guest opens without a session, the
owner's pages and CSV, the forms that save and push configuration, the sidebar
links, the guide, and the org/CSRF gates around every write.

Run:  .venv/bin/python tests/web_wifi_test.py
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

from mikromon import capsman as C  # noqa: E402
from mikromon import guide_tabs  # noqa: E402
from mikromon import guest_wifi as W  # noqa: E402
from mikromon import web  # noqa: E402
from mikromon import web_wifi as WW  # noqa: E402
from mikromon.auth import AuthStore  # noqa: E402
from mikromon.config import SmtpConfig  # noqa: E402
from mikromon.device import DeviceError  # noqa: E402
from mikromon.devices_store import DevicesStore  # noqa: E402
from mikromon.metrics import MetricsStore  # noqa: E402
from mikromon.push import Pusher  # noqa: E402
from mikromon.push.api import PushError  # noqa: E402
from mikromon.push.audit import AuditLog  # noqa: E402
from mikromon.web_shared import _dash_icon, _nav_items  # noqa: E402

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


print("Page renderers: the whole cockpit, escaping every hostile value")

OWNER = {"role": "owner", "email": "owner@alpha.test", "org_name": "Alpha"}
PORTAL = {
    "id": 4, "org_id": 7, "slug": "alpha-guest", "device": "R1",
    "brand_name": "<script>brand()</script> Alpha",
    "headline": "Welcome, <b>guests</b>", "enabled": 1,
    "guest_password": "welcome2026", "guest_username": "guest",
    "hotspot_iface": "vlan-guest", "accent_color": "#2563eb",
}
LEADS = [{"id": 1, "name": "<script>lead()</script>", "email": "jane@x.test",
          "phone": "", "company": "", "marketing_optin": 1,
          "client_mac": "aa:bb:cc:dd:ee:ff", "created_at": 1000.0}]
STATS = {"total": 9, "last_24h": 2, "last_7d": 5, "last_30d": 9,
         "optin_count": 4, "optin_pct": 44.4}
PAGES = WW.render_guest_wifi_page(
    OWNER, "tok", [PORTAL], LEADS, STATS, [{"name": "R1"}],
    base_url="https://em.test", flash="Portal saved", search="jane")
check("the Guest Wi-Fi page is a full cockpit page with its CSRF token",
      "<!doctype html>" in PAGES and 'name="csrf" value="tok"' in PAGES
      and "Guest Wi-Fi" in PAGES)
check("it has KPIs, a portal studio with preview/snippet/push, and lead search",
      "Leads captured" in PAGES and "Portal Studio" in PAGES
      and "/guest-wifi/push" in PAGES and "/guest-wifi/leads.csv" in PAGES
      and 'name="search" value="jane"' in PAGES)
check("hostile portal and lead text is escaped, never executed",
      "<script>brand()" not in PAGES and "<script>lead()" not in PAGES
      and "&lt;script&gt;brand()" in PAGES and "&lt;b&gt;guests&lt;/b&gt;" in PAGES)

XSS_BASE = 'https://portal.test/" onmouseover="alert(1)'
XSS_PAGE = WW.render_guest_wifi_page(
    OWNER, "tok", [PORTAL], [], STATS, [{"name": "R1"}], base_url=XSS_BASE)
check("a hostile portal URL cannot break out of the preview link",
      'onmouseover="alert(1)' not in XSS_PAGE
      and "&quot; onmouseover" in XSS_PAGE)
check("unchecked boxes publish zero and stored secrets are masked",
      '<input type="hidden" name="require_name" value="0">' in XSS_PAGE
      and '<input type="hidden" name="enabled" value="0">' in XSS_PAGE
      and 'type="password" name="guest_password"' in XSS_PAGE
      and 'type="password" name="shared_secret"' in XSS_PAGE)

LIVE = {
    "device": "R1", "driver": "wifi", "capsman_enabled": True,
    "aps": [{"name": "AP-One", "state": "connected", "clients_count": 2}],
    "ssids": [{"name": "mm-cfg-staff", "ssid": "Alpha Staff"}],
    "clients": [{"mac": "11:22:33:44:55:66", "ip": "10.0.0.9",
                 "ssid": "Alpha Staff", "ap": "AP-One",
                 "signal_dbm": -55, "signal_pct": 78, "uptime": "1h"}],
    "blocked": [],
    "error": "<script>read()</script>",
}
SYNC = [{"device": "R1", "status": "error", "changes": 0,
         "summary": "sync failed", "error": "<script>sync()</script>"}]
CAPS = WW.render_capsman_page(
    OWNER, "tok", [{"device": "R1", "enabled": 1,
                    "last_sync_status": "error"}],
    [{"id": 1, "name": "staff", "ssid": "Alpha Staff", "purpose": "staff",
      "vlan_id": 22, "security_mode": "wpa2-psk", "enabled": 1}],
    [{"id": 2, "mac": "de:ad:be:ef:00:01", "reason": "test"}],
    [LIVE], [{"name": "R1"}], flash="Synced", sync_results=SYNC)
check("the CAPsMAN page has KPIs, fleet sync, controllers, SSIDs and ACL",
      'name="csrf" value="tok"' in CAPS and "/capsman/sync-all" in CAPS
      and "Sync All" in CAPS and "SSIDs / VLANs" in CAPS
      and "Blocked MACs" in CAPS and "de:ad:be:ef:00:01" in CAPS)
check("live APs and clients are shown with signal and block/disconnect actions",
      "AP-One" in CAPS and "11:22:33:44:55:66" in CAPS
      and "-55" in CAPS and "/capsman/client-disconnect" in CAPS
      and "/capsman/client-block" in CAPS and "/capsman/client-unblock" in CAPS)
check("raw CAPsMAN sync and read errors are escaped before they reach HTML",
      "<script>sync()" not in CAPS and "<script>read()" not in CAPS
      and "&lt;script&gt;sync()" in CAPS and "&lt;script&gt;read()" in CAPS)
check("CAPsMAN checkboxes publish zero and the passphrase is masked",
      '<input type="hidden" name="client_isolation" value="0">' in CAPS
      and '<input type="hidden" name="enabled" value="0">' in CAPS
      and 'type="password" name="passphrase"' in CAPS)

print("Navigation and guide: links people can follow and help they can read")

nav = dict(_nav_items(OWNER))
check("owners see both new pages in the nav, after Devices",
      nav.get("/capsman") == "Wi-Fi / CAPsMAN"
      and nav.get("/guest-wifi") == "Guest Wi-Fi"
      and list(nav).index("/devices") < list(nav).index("/capsman")
      < list(nav).index("/guest-wifi"))
check("both nav entries get a clean inline SVG icon",
      "<svg" in _dash_icon("/capsman")
      and "<svg" in _dash_icon("/guest-wifi")
      and "<script" not in _dash_icon("/capsman"))
check("the guide has help for both new pages",
      "guest-wifi" in guide_tabs.BY_SLUG and "capsman" in guide_tabs.BY_SLUG
      and guide_tabs.BY_SLUG["guest-wifi"]["steps"]
      and guide_tabs.BY_SLUG["capsman"]["steps"])
check("QoS and Departments now mention speed limits and VoIP line pinning",
      "department" in guide_tabs.BY_SLUG["qos"]["what"].lower()
      and "voip" in guide_tabs.BY_SLUG["qos"]["what"].lower()
      and "speed" in guide_tabs.BY_SLUG["departments"]["what"].lower()
      and "voip" in guide_tabs.BY_SLUG["departments"]["what"].lower())


class FakeApi:
    """RouterOS menus in memory, with the fetch/execute shape Pusher expects."""

    def __init__(self, state):
        self.state = state
        self.executed = []
        self.closed = False
        self._n = 200

    def fetch(self, path):
        return [dict(row) for row in self.state.get(tuple(path), [])]

    def execute(self, op):
        self.executed.append(op)
        rows = self.state.setdefault(tuple(op.path), [])
        if op.action == "add":
            self._n += 1
            rid = f"*{self._n}"
            rows.append({**{k: str(v) for k, v in op.params.items()},
                         ".id": rid})
            return rid
        if op.action == "set":
            for row in rows:
                if row.get(".id") == str(op.params.get(".id")):
                    row.update({k: str(v) for k, v in op.params.items()
                                if k != ".id"})
                    return None
            rows.append({**{k: str(v) for k, v in op.params.items()},
                         ".id": f"*{self._n + 1}"})
            return None
        if op.action == "remove":
            self.state[tuple(op.path)] = [
                row for row in rows
                if row.get(".id") != str(op.params.get(".id"))]
            return None
        raise PushError("unknown action " + op.action)

    def close(self):
        self.closed = True


W_MGR = ("interface", "wifi", "capsman")
W_RCAP = ("interface", "wifi", "capsman", "remote-cap")
W_RADIO = ("interface", "wifi", "radio")
W_IFACE = ("interface", "wifi")
W_REG = ("interface", "wifi", "registration-table")
W_CFG = ("interface", "wifi", "configuration")
W_ACL = ("interface", "wifi", "access-list")
ROUTER_STATE = {
    W_MGR: [{".id": "*1", "enabled": False}],
    W_RCAP: [{".id": "*2", "name": "cap-ap1", "identity": "AP-One",
              "address": "10.0.0.2", "mac-address": "AA:BB:CC:DD:EE:01",
              "radio-mac": "AA:BB:CC:DD:EE:01", "state": "pending",
              "version": "7.15.2", "board-name": "hAP ax^3"}],
    W_RADIO: [{".id": "*4", "name": "radio1", "radio-mac": "AA:BB:CC:DD:EE:01",
               "state": "running"}],
    W_IFACE: [{".id": "*6", "name": "wifi-staff",
               "mac-address": "AA:BB:CC:DD:EE:01",
               "radio-mac": "AA:BB:CC:DD:EE:01", "mode": "ap",
               "disabled": False, "ssid": "Alpha Staff",
               "configuration": "mm-cfg-staff"}],
    W_REG: [{".id": "*8", "interface": "wifi-staff",
             "mac-address": "11:22:33:44:55:66", "signal-strength": "-55dBm",
             "tx-rate": "866Mbps", "rx-rate": "780Mbps", "uptime": "1h2m"}],
    W_CFG: [{".id": "*12", "name": "mm-cfg-staff", "ssid": "Alpha Staff",
             "comment": C.TAG + "cfg:staff"}],
    W_ACL: [],
    ("ip", "dhcp-server", "lease"): [
        {".id": "*10", "mac-address": "11:22:33:44:55:66",
         "address": "10.30.0.23", "status": "bound"}],
}
HOTSPOT_STATE = {
    ("ip", "hotspot", "user", "profile"): [],
    ("ip", "hotspot", "profile"): [],
    ("ip", "hotspot"): [],
    ("ip", "hotspot", "user"): [],
    ("ip", "hotspot", "walled-garden"): [],
}

print("Over HTTP: sessions, CSRF, org isolation, and public guests")

tmp = tempfile.mkdtemp(prefix="web-wifi-")
wdir = os.path.join(tmp, "web")
os.makedirs(wdir)
mdb, sfile, adb, ddb, pdb = (os.path.join(wdir, name) for name in
                             ("m.db", "state.json", "auth.db", "devices.db",
                              "push.db"))
MetricsStore(mdb).close()
with open(sfile, "w", encoding="utf-8") as fh:
    json.dump({"devices": {}}, fh)
auth = AuthStore(adb)
alpha = auth.signup("owner@alpha.test", "secret123", "Alpha")
beta = auth.signup("owner@beta.test", "secret123", "Beta")
auth.add_member(alpha, "member@alpha.test", "secret123")
auth.set_setting("public_base_url", "https://portal.test")
ds = DevicesStore(ddb)
ds.upsert({"name": "R1", "host": "10.0.0.2"}, {}, org_id=alpha)
ds.upsert({"name": "B1", "host": "10.0.1.2"}, {}, org_id=beta)
ds.close()
gw = W.GuestWifiStore(os.path.join(wdir, "guest_wifi.db"))
caps = C.CapsmanStore(os.path.join(wdir, "capsman.db"))

real_caps_connect = web._capsman_connect
real_wifi_connect = web._wifi_connect
web._capsman_connect = lambda cfg: FakeApi(ROUTER_STATE)
web._wifi_connect = lambda cfg: FakeApi(HOTSPOT_STATE)

srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, auth, web.SessionManager(), secure_cookies=False,
    devices_db=ddb, defaults={}, push_log_db=pdb, admin_2fa=False,
    rate_limit=False,
    smtp_cfg=SmtpConfig(host="smtp.test", from_addr="noc@test.test")))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()


def opener():
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def req(op, path, data=None, headers=None):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    try:
        r = op.open(urllib.request.Request(BASE + path, data=body,
                                           headers=headers or {}), timeout=15)
        return r.status, r.read().decode("utf-8", "replace"), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), e.headers


def login(email):
    o = opener()
    req(o, "/login", {"email": email, "password": "secret123"})
    return o


def csrf_of(page):
    m = re.search(r'name="csrf" value="([^"]+)"', page)
    return m.group(1) if m else ""


try:
    anon = opener()
    owner = login("owner@alpha.test")
    st, page, _ = req(owner, "/guest-wifi")
    token = csrf_of(page)
    check("an owner opens Guest Wi-Fi and gets a real CSRF token",
          st == 200 and bool(token) and "Portal Studio" in page
          and 'href="/guest-wifi/leads.csv"' in page)
    st, page, _ = req(owner, "/guest-wifi/save", {
        "csrf": token, "slug": "alpha-guest", "device": "R1",
        "brand_name": "Alpha Guest", "headline": "Welcome, guests!",
        "guest_password": "welcome2026", "hotspot_iface": "vlan-guest",
        "down_mbps": "10", "up_mbps": "5", "require_name": "1",
        "require_email": "1", "show_marketing_optin": "1", "enabled": "1"})
    check("saving a portal goes through the owner route",
          st == 200 and "Portal saved" in page)
    portal = gw.get_portal_by_slug("alpha-guest")
    check("the saved portal is scoped to Alpha and sealed at rest",
          portal is not None and portal["org_id"] == alpha
          and portal["guest_password"] == "welcome2026")

    st, _, _ = req(owner, "/guest-wifi/save", {
        "csrf": token, "id": portal["id"], "slug": "alpha-guest",
        "brand_name": "Alpha Guest", "device": "R1"})
    off = gw.get_portal_by_slug("alpha-guest")
    check("unchecked portal boxes really turn those features off",
          st == 200 and off["require_name"] == 0 and off["require_email"] == 0
          and off["show_marketing_optin"] == 0 and off["enabled"] == 0)
    st, _, _ = req(owner, "/guest-wifi/save", {
        "csrf": token, "id": portal["id"], "slug": "alpha-guest",
        "brand_name": "Alpha Guest", "device": "R1", "require_name": "1",
        "require_email": "1", "show_marketing_optin": "1", "enabled": "1"})
    check("the portal can be switched back on again",
          gw.get_portal_by_slug("alpha-guest")["enabled"] == 1)

    st, splash, _ = req(anon, "/portal/alpha-guest")
    check("a guest opens the branded portal without a session",
          st == 200 and "Alpha Guest" in splash
          and "Connect to Wi-Fi" in splash)
    st, legacy, _ = req(anon, "/guest/alpha-guest")
    check("the backend's /guest URL still reaches the same portal",
          st == 200 and "Alpha Guest" in legacy)

    st, connected, _ = req(anon, "/portal/alpha-guest/connect", {
        "name": "Jane Doe", "email": " Jane@Example.test ",
        "terms": "1", "marketing_optin": "1",
        "link-login-only": "http://10.0.0.2/cgi-bin/hotspot/login?dst=1",
        "link-orig": "http://example.test/welcome",
        "mac": "aa:bb:cc:dd:ee:ff", "ip": "10.9.0.4"})
    leads = gw.list_leads(alpha)
    check("a public POST records the lead and hands off to the router",
          st == 200 and ("Connecting" in connected or "connected" in connected)
          and len(leads) == 1 and leads[0]["email"] == "jane@example.test"
          and leads[0]["marketing_optin"] == 1
          and leads[0]["client_mac"] == "aa:bb:cc:dd:ee:ff")

    st, poisoned, _ = req(anon, "/portal/alpha-guest/connect", {
        "name": "Mallory", "email": "mallory@example.test", "terms": "1",
        "link-login-only": "https://attacker.test/login"})
    check("a forged hotspot login host is refused before a lead is stored",
          st == 400 and "not trusted" in poisoned.lower()
          and len(gw.list_leads(alpha)) == 1)

    st, bad, _ = req(anon, "/portal/alpha-guest/connect", {
        "name": "Bad Email", "email": "not-an-email", "terms": "1"})
    check("a bad submission is refused without storing a lead",
          st == 400 and "valid email" in bad and len(gw.list_leads(alpha)) == 1)
    st, no_terms, _ = req(anon, "/portal/alpha-guest/connect", {
        "name": "No Terms", "email": "no@example.test"})
    check("the guest must accept the terms before we keep their details",
          st == 400 and "terms" in no_terms.lower()
          and len(gw.list_leads(alpha)) == 1)
    st, legacy_conn, _ = req(anon, "/guest/alpha-guest/connect", {
        "name": "Legacy Guest", "email": "legacy@example.test", "terms": "1",
        "link-login-only": "http://10.0.0.2/cgi-bin/hotspot/login"})
    check("the rendered /guest form action reaches the same public route",
          st == 200 and "Connecting" in legacy_conn
          and len(gw.list_leads(alpha)) == 2)

    gw.upsert_portal(alpha, {"slug": "off-guest", "brand_name": "Off",
                             "enabled": 0})
    st, _, _ = req(anon, "/portal/off-guest")
    st2, _, _ = req(anon, "/portal/does-not-exist")
    check("disabled and unknown portals do not render a splash page",
          st == 404 and st2 == 404)

    st, csv_text, headers = req(
        owner, f"/guest-wifi/leads.csv?portal_id={portal['id']}")
    check("an owner exports only their own leads as an attachment",
          st == 200 and "text/csv" in headers.get("Content-Type", "")
          and "attachment" in headers.get("Content-Disposition", "")
          and "Jane Doe" in csv_text and "jane@example.test" in csv_text)

    beta_owner = login("owner@beta.test")
    st, beta_page, _ = req(beta_owner, "/guest-wifi")
    st, beta_csv, _ = req(
        beta_owner, f"/guest-wifi/leads.csv?portal_id={portal['id']}")
    check("another company sees neither Alpha's portal nor its leads",
          st == 200 and "alpha-guest" not in beta_page
          and "Jane Doe" not in beta_csv and "jane@example.test" not in beta_csv)
    st, page, _ = req(beta_owner, "/guest-wifi/save", {
        "csrf": csrf_of(beta_page), "id": portal["id"], "slug": "beta-guest",
        "brand_name": "Beta", "enabled": "1"})
    check("another company cannot edit or delete an Alpha portal by id",
          "does not belong" in page
          and gw.get_portal_by_slug("beta-guest") is None)
    st, _, _ = req(beta_owner, "/guest-wifi/delete", {
        "csrf": csrf_of(beta_page), "id": portal["id"]})
    check("the Alpha portal survives a cross-company delete",
          gw.get_portal_by_slug("alpha-guest") is not None)

    member = login("member@alpha.test")
    st, _, _ = req(member, "/guest-wifi")
    st2, _, _ = req(member, "/capsman")
    check("a non-owner cannot open either new page", st == 403 and st2 == 403)
    st, member_page, _ = req(member, "/dashboard")
    st2, _, _ = req(member, "/guest-wifi/save", {
        "csrf": csrf_of(member_page), "slug": "member-guest",
        "brand_name": "Member", "enabled": "1"})
    check("a member with a valid CSRF token still cannot write Wi-Fi settings",
          st == 200 and bool(csrf_of(member_page)) and st2 == 403
          and gw.get_portal_by_slug("member-guest") is None)
    st, _, _ = req(owner, "/guest-wifi/save", {"slug": "no-csrf"})
    st2, _, _ = req(owner, "/capsman/controller",
                    {"csrf": "wrong", "device": "R1"})
    check("both write surfaces enforce CSRF", st == 400 and st2 == 400)

    st, page, _ = req(owner, "/capsman")
    token = csrf_of(page)
    check("an owner opens CAPsMAN with the fleet controls",
          st == 200 and "Sync All" in page and 'name="csrf" value="' in page)
    st, page, _ = req(owner, "/capsman/controller", {
        "csrf": token, "device": "R1", "enabled": "1", "driver": "wifi"})
    check("a controller is saved through the owner route",
          st == 200 and "Controller saved" in page
          and [c["device"] for c in caps.list_controllers(alpha)] == ["R1"])
    st, page, _ = req(owner, "/capsman/controller", {
        "csrf": token, "device": "B1", "enabled": "1"})
    check("a controller cannot be pointed at another company's router",
          st == 403)
    st, _, _ = req(owner, "/capsman/controller", {
        "csrf": token, "device": "R1", "driver": "wifi"})
    check("an unchecked controller box really pauses the controller",
          caps.list_controllers(alpha)[0]["enabled"] == 0)
    st, _, _ = req(owner, "/capsman/controller", {
        "csrf": token, "device": "R1", "enabled": "1", "driver": "wifi"})
    st, page, _ = req(owner, "/capsman/ssid-save", {
        "csrf": token, "name": "staff", "ssid": "Alpha Staff",
        "purpose": "staff", "vlan_id": "22", "security_mode": "wpa2-psk",
        "passphrase": "longenough", "client_isolation": "1", "enabled": "1"})
    ssids = caps.list_ssids(alpha)
    check("an SSID/VLAN is saved and its passphrase comes back unsealed",
          st == 200 and "SSID saved" in page
          and len(ssids) == 1 and ssids[0]["ssid"] == "Alpha Staff"
          and ssids[0]["vlan_id"] == 22
          and ssids[0]["passphrase"] == "longenough")
    st, _, _ = req(owner, "/capsman/ssid-save", {
        "csrf": token, "id": ssids[0]["id"], "name": "staff",
        "ssid": "Alpha Staff", "purpose": "staff", "vlan_id": "22",
        "security_mode": "wpa2-psk", "passphrase": "longenough"})
    paused = caps.list_ssids(alpha)[0]
    check("unchecked SSID boxes are saved as off, not defaulted back on",
          paused["enabled"] == 0 and paused["client_isolation"] == 0)
    st, _, _ = req(owner, "/capsman/ssid-save", {
        "csrf": token, "id": ssids[0]["id"], "name": "staff",
        "ssid": "Alpha Staff", "purpose": "staff", "vlan_id": "22",
        "security_mode": "wpa2-psk", "passphrase": "longenough",
        "client_isolation": "1", "enabled": "1"})
    temp = caps.upsert_ssid(alpha, {"name": "temp", "ssid": "Temp",
                                    "purpose": "guest", "security_mode": "open"})
    st, page, _ = req(owner, "/capsman/ssid-delete", {
        "csrf": token, "id": temp["id"]})
    check("an unwanted SSID can be deleted",
          st == 200 and "SSID removed" in page
          and "temp" not in [s["name"] for s in caps.list_ssids(alpha)])

    caps.set_controller(alpha, "B1", enabled=1, driver="wifi")
    opened = []

    def bad_connect(cfg):
        opened.append(cfg.name)
        raise PushError("offline")

    web._capsman_connect = bad_connect
    st, page, _ = req(owner, "/capsman/sync-all", {"csrf": token})
    check("sync-all never pushes to a router another company now owns",
          st == 200 and "B1" not in opened
          and "no device config for B1" in page)
    caps.set_controller(alpha, "B1", enabled=0)
    web._capsman_connect = lambda cfg: FakeApi(ROUTER_STATE)

    st, page, _ = req(owner, "/capsman")
    check("the live fleet view shows APs, clients and signal from the router",
          st == 200 and "AP-One" in page and "11:22:33:44:55:66" in page
          and "-55" in page)

    st, page, _ = req(owner, "/capsman/adopt", {
        "csrf": token, "device": "R1", "ap_mac": "AA:BB:CC:DD:EE:01"})
    check("a pending AP can be adopted through the cockpit",
          st == 200 and "AP adopted" in page)
    st, page, _ = req(owner, "/capsman/client-block", {
        "csrf": token, "device": "R1", "mac": "11:22:33:44:55:66",
        "reason": "test"})
    check("a live client is blocked and lands in the org's ACL store",
          st == 200 and "Client blocked" in page
          and [b["mac"] for b in caps.list_blocked_macs(alpha)]
          == ["11:22:33:44:55:66"])
    st, page, _ = req(owner, "/capsman/client-unblock", {
        "csrf": token, "device": "R1", "mac": "11:22:33:44:55:66"})
    check("the same MAC can be unblocked again",
          st == 200 and "Client unblocked" in page
          and caps.list_blocked_macs(alpha) == [])
    st, page, _ = req(owner, "/capsman/client-disconnect", {
        "csrf": token, "device": "R1", "client_id": "*8"})
    check("a client can be disconnected without deleting the controller",
          st == 200 and "Client disconnected" in page
          and not [r for r in ROUTER_STATE[W_REG]
                   if r.get(".id") == "*8"])

    class FailingBlockApi(FakeApi):
        def execute(self, op):
            if tuple(op.path) == W_ACL:
                raise PushError("block refused")
            return super().execute(op)

    web._capsman_connect = lambda cfg: FailingBlockApi(ROUTER_STATE)
    st, page, _ = req(owner, "/capsman/client-block", {
        "csrf": token, "device": "R1", "mac": "22:22:22:22:22:22",
        "reason": "fail"})
    check("a failed router block is not recorded in the local ACL",
          st == 200 and "block refused" in page
          and "22:22:22:22:22:22" not in [
              b["mac"] for b in caps.list_blocked_macs(alpha)])
    web._capsman_connect = lambda cfg: FakeApi(ROUTER_STATE)

    web._capsman_connect = lambda cfg: (_ for _ in ()).throw(
        PushError("<script>evil()</script>"))
    st, page, _ = req(owner, "/capsman/sync-all", {"csrf": token})
    check("a fleet sync renders its result, escaping the raw router error",
          st == 200 and "sync failed" in page.lower()
          and "&lt;script&gt;evil()&lt;/script&gt;" in page
          and "<script>evil()" not in page)
    web._capsman_connect = lambda cfg: FakeApi(ROUTER_STATE)

    st, page, _ = req(owner, "/guest-wifi/push", {
        "csrf": token, "portal_id": portal["id"], "device": "R1"})
    check("the Push button provisions the hotspot through the write engine",
          st == 200 and "Hotspot provisioned" in page
          and any("mm-guest-alpha-guest" in str(row)
                  for rows in HOTSPOT_STATE.values() for row in rows))

    web._wifi_connect = lambda cfg: (_ for _ in ()).throw(
        DeviceError("Connection failed: router offline"))
    st, page, _ = req(owner, "/guest-wifi/push", {
        "csrf": token, "portal_id": portal["id"], "device": "R1"})
    check("an offline router during hotspot push shows an error, not a 500",
          st == 200 and "router offline" in page)
    web._wifi_connect = lambda cfg: FakeApi(HOTSPOT_STATE)

    activity = AuditLog(pdb).recent(device="R1")
    check("Wi-Fi router writes land in the shared audit log",
          any(x["feature"] == "guestwifi" and x["mode"] == "apply"
              for x in activity)
          and any(x["feature"] == "capsman" and x["mode"] == "apply"
                  for x in activity))

    gw.upsert_portal(alpha, {"slug": "ratelimit-guest",
                             "brand_name": "Rate", "enabled": 1})
    codes = []
    for i in range(6):
        st, _, _ = req(anon, "/portal/ratelimit-guest/connect", {
            "name": f"Rate {i}", "email": f"rate{i}@example.test",
            "terms": "1"})
        codes.append(st)
    check("public portal posts are rate limited per guest portal",
          codes[-1] == 429 and all(code in (200, 400) for code in codes[:-1]))
    st, _, _ = req(anon, "/portal/ratelimit-guest/connect", {
        "name": "Forwarded Guest", "email": "forwarded@example.test",
        "terms": "1"}, headers={"X-Real-IP": "198.51.100.77"})
    check("a forwarded guest gets their own rate-limit bucket", st == 200)
finally:
    web._capsman_connect = real_caps_connect
    web._wifi_connect = real_wifi_connect
    srv.shutdown()
    srv.server_close()
    gw.close()
    caps.close()
    auth.close()

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL WEB WIFI TESTS PASSED")
