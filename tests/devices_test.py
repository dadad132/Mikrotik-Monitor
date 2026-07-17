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
from mikromon.config import DEFAULT_THRESHOLDS, AppConfig, build_device, device_to_dict
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

print("Startup grace period: suppress alerts right after the monitor "
      "restarts, then re-alert on anything still down:")


class _FakeNotifier:
    name = "fake"

    def __init__(self):
        self.sent = []

    def send(self, alerts):
        self.sent.append(list(alerts))


from mikromon.alert import Alert, Severity  # noqa: E402

fn = _FakeNotifier()
gcfg = AppConfig(state_file=os.path.join(tmp, "grace.json"),
                 defaults=DEF, devices=[], startup_grace_minutes=20)
geng = Engine(gcfg, notifiers=[fn], devices=[])
clock = [1_000_000.0]
geng.now_fn = lambda: clock[0]
geng._start_ts = clock[0]

down_alert = Alert("R1", "reachability", Severity.CRITICAL, "Device UNREACHABLE")
geng.dispatch([down_alert])
check("an alert during the grace window is logged but NOT sent",
      fn.sent == [])

clock[0] += 5 * 60  # 5 minutes in — still well inside the 20-minute window
geng.dispatch([down_alert])
check("still suppressed 5 minutes in (grace window hasn't elapsed)",
      fn.sent == [])

# Simulate this condition having been persisted as "problem" by a real
# transition() call during the (suppressed) grace window.
cond = geng.state.condition("R1", "reachability")
cond.update({"status": "problem", "since": clock[0], "title": "Device UNREACHABLE",
            "severity": int(Severity.CRITICAL)})

clock[0] += 16 * 60  # 21 minutes total — grace period has now elapsed
geng._maybe_resync_after_grace()
check("once the grace period elapses, anything still down gets a fresh alert",
      len(fn.sent) == 1 and len(fn.sent[0]) == 1
      and fn.sent[0][0].device == "R1" and fn.sent[0][0].key == "reachability"
      and "20-minute" in fn.sent[0][0].detail)

fn.sent.clear()
geng._maybe_resync_after_grace()
check("the resync only fires once (not every poll after grace ends)",
      fn.sent == [])

fn.sent.clear()
clock[0] += 60
geng.dispatch([Alert("R1", "reachability", Severity.INFO, "Resolved",
                    recovery=True)])
check("normal delivery resumes for new alerts after the grace period",
      len(fn.sent) == 1)

# A condition that recovered DURING the grace window (before it elapsed)
# must not be re-announced at resync time — only what's still actually down.
fn.sent.clear()
gcfg2 = AppConfig(state_file=os.path.join(tmp, "grace2.json"),
                  defaults=DEF, devices=[], startup_grace_minutes=20)
geng2 = Engine(gcfg2, notifiers=[fn], devices=[])
clock2 = [2_000_000.0]
geng2.now_fn = lambda: clock2[0]
geng2._start_ts = clock2[0]
geng2.state.condition("R2", "reachability").update({"status": "ok"})
clock2[0] += 21 * 60
geng2._maybe_resync_after_grace()
check("a condition that's healthy by the time grace ends is not re-alerted",
      fn.sent == [])

print("Web render helpers (offline):")
cfgwan = build_device({"name": "R", "host": "1.1.1.1", "wan": {"links": [
    {"name": "Fibre", "interface": "ether1"},
    {"name": "LTE", "interface": "lte1"}]}}, DEF)
wed = web._wan_uplink_editor("R", cfgwan, "csrf")
check("SD-WAN WAN editor has up/down reorder controls",
      "pushMoveRow(this,-1)" in wed and "pushMoveRow(this,1)" in wed)

# A chosen per-uplink Distance must survive save -> reload, not silently
# revert to "auto". Confirmed live: device_to_dict() (used when re-saving
# an edited device) built the wan.links dicts without a "distance" key at
# all, so a chosen value round-tripped fine in memory but was dropped the
# moment it got serialized back to storage — the next page load then saw
# no distance in the DB and showed "auto" again.
cfgdist = build_device({"name": "R", "host": "1.1.1.1", "wan": {"links": [
    {"name": "Fibre", "interface": "ether1", "distance": 10},
    {"name": "Backup", "interface": "ether5", "distance": 11},
    {"name": "VoIP", "interface": "ether3"}]}}, DEF)
check("build_device parses an explicit per-uplink Distance",
      [ep.distance for ep in cfgdist.wan.links] == [10, 11, None])
resaved = device_to_dict(cfgdist)
check("device_to_dict includes distance when serializing back for storage "
      "(this is the exact field that was silently dropped)",
      [lk.get("distance") for lk in resaved["wan"]["links"]] == [10, 11, None])
cfgdist2 = build_device(resaved, DEF)
check("a second save/load round-trip still has the same chosen distances",
      [ep.distance for ep in cfgdist2.wan.links] == [10, 11, None])
wed_dist = web._wan_uplink_editor("R", cfgdist, "csrf")
check("the WAN uplinks editor actually displays the saved Distance value "
      "(10) in that row's input, not blank/auto",
      'name="link_distance" type="number" min="1" max="253" placeholder="auto" '
      'value="10"' in wed_dist)
check("a link with no chosen Distance shows the blank/auto placeholder, "
      "not a stray 'None'",
      'value="None"' not in wed_dist)

# Detecting which port actually has the ISP plugged in (varies per install —
# some start on ether1, others ether5) so it doesn't have to be guessed.
wed_detect = web._wan_uplink_editor(
    "R", cfgwan, "csrf",
    ifaces=[{"name": "ether1"}, {"name": "ether5"}, {"name": "lte1"}],
    online_ifaces={"ether5"})
check("a port with a detected live internet connection is flagged in the dropdown",
      "ether5  \U0001f310 has an active internet connection" in wed_detect)
check("a port with no detected connection is listed plainly",
      '<option value="ether1">ether1</option>' in wed_detect)
check("the detected port sorts to the top of the dropdown",
      wed_detect.index('value="ether5"') < wed_detect.index('value="ether1"')
      and wed_detect.index('value="ether5"') < wed_detect.index('value="lte1"'))
check("the detection note only shows when ifaces (live router data) is available",
      "has an active internet connection" not in wed  # no ifaces passed above
      and "mikromon detected an active internet connection" in wed_detect)

# WAN Status dashboard box: a backup link that's individually down (its own
# wan_link:N condition is a "problem") must show Offline, not just infer
# "Online" from the overall picture looking fine. Confirmed live: a stopped
# DHCP client backup still showed "[Online] (Inactive)" here while the
# Routes tab correctly showed it as stopped/no default route.
wan_mdb = os.path.join(tmp, "wan-metrics.db")
wan_store = MetricsStore(wan_mdb)
wan_state = {"devices": {"R1": {
    "facts": {"wan_links": ["Wikiworx", "Backup", "VOIP"]},
    "conditions": {
        "reachability": {"status": "ok"},
        "wan_link:1": {"status": "problem", "level": "problem"},
    },
}}}
wan_page = web._render_device(wan_store, wan_state, "R1",
                              {"role": "owner", "email": "test@test.com"})
wan_store.close()
check("primary (index 0, no problem) shows Online",
      "Wikiworx</span>" in wan_page)
row1 = wan_page[wan_page.index("Backup</span>"):wan_page.index("VOIP</span>")]
check("a backup with its own wan_link:N problem shows Offline, not "
      "Online/Inactive, even though the overall WAN health is 'full'",
      "[Offline]" in row1 and "[Online]" not in row1)
row2 = wan_page[wan_page.index("VOIP</span>"):]
check("a backup with NO problem of its own still shows Online (Inactive) "
      "as before", "[Online]" in row2 and "Inactive" in row2)

# Network Throughput box: metrics.latest() returns the all-time latest value
# per label, with no time filter — so a WAN interface that was later renamed
# or removed in the WAN uplinks editor would otherwise keep showing its
# frozen last-ever reading forever, right next to a peak of 0 (nothing in the
# last-hour window), which looks like broken/inconsistent data. Confirmed
# live: a stale "ether1-wikiwrox" entry kept showing alongside the correctly
# working "Wikiworx" one. facts["wan_traffic_interfaces"], cached fresh every
# poll, is the current allow-list.
tp_mdb = os.path.join(tmp, "tp-metrics.db")
tp_store = MetricsStore(tp_mdb)
now = time.time()
tp_store.record([
    (now - 1800, "R2", "rx_bps", "Wikiworx", 5_300_000),
    (now - 1800, "R2", "tx_bps", "Wikiworx", 393_500),
    (now - 7200, "R2", "rx_bps", "ether1-wikiwrox", 852_700),  # stale: 2h old
    (now - 7200, "R2", "tx_bps", "ether1-wikiwrox", 184_200),
])
tp_state = {"devices": {"R2": {
    "facts": {"wan_traffic_interfaces": ["Wikiworx"]},
    "conditions": {"reachability": {"status": "ok"}},
}}}
tp_page = web._render_device(tp_store, tp_state, "R2",
                             {"role": "owner", "email": "test@test.com"})
tp_store.close()
check("the currently-configured WAN interface's throughput card shows",
      "Wikiworx</b>" in tp_page)
check("a stale/renamed interface's frozen old reading is not shown",
      "ether1-wikiwrox" not in tp_page)

# Devices whose engine hasn't re-polled since this fact was added yet (key
# entirely absent) must keep showing everything, not go blank.
tp_mdb2 = os.path.join(tmp, "tp-metrics2.db")
tp_store2 = MetricsStore(tp_mdb2)
tp_store2.record([(now - 60, "R3", "rx_bps", "ether1", 1_000_000),
                  (now - 60, "R3", "tx_bps", "ether1", 200_000)])
tp_state2 = {"devices": {"R3": {"facts": {},
             "conditions": {"reachability": {"status": "ok"}}}}}
tp_page2 = web._render_device(tp_store2, tp_state2, "R3",
                              {"role": "owner", "email": "test@test.com"})
tp_store2.close()
check("no wan_traffic_interfaces fact yet -> falls back to showing everything",
      "ether1</b>" in tp_page2)

check("reorder JS is defined on feature tabs", "function pushMoveRow" in web._FEATURE_JS)
check("toggles render as on/off sliders",
      'class="switch"' in web._field_html(
          {"type": "toggle", "name": "opt", "value": "x", "label": "L"}))
# device tab bar: SD-WAN renamed to WAN; Update/Backups moved under a
# Maintenance dropdown that also has a CSRF-guarded Reboot button (admin only)
bar = web._device_tabbar("R", "overview", True, "CSRF1")
check("tab bar shows WAN, not SD-WAN",
      ">WAN<" in bar and "SD-WAN" not in bar)
check("Maintenance dropdown groups Update + Backups + a Reboot form",
      'class="tabdrop"' in bar and ">Maintenance" in bar
      and "tab=update" in bar and "tab=backups" in bar
      and '/device/reboot' in bar and 'value="CSRF1"' in bar)
check("non-admin tab bar has no Maintenance dropdown / reboot",
      "Maintenance" not in web._device_tabbar("R", "overview", False, "CSRF1"))
# backup 'Created' date: prefer the YYYYMMDD-HHMMSS stamp in mikromon names,
# else the router's creation-time
check("backup date parsed from the mikromon backup name",
      web._fmt_backup_date("before-r-20260625-143005.backup", "") == "2026-06-25 14:30")
check("backup date falls back to the router creation-time",
      web._fmt_backup_date("hand.backup", "jun/01/2026") == "jun/01/2026")
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
      # /16 (not /24): matches the peer's allowed-address widening so any
      # device on the hub's 10.10.x.x range can still reach the API.
      "/ip service set api address=10.10.0.0/16" in locked
      and "/ip service set api-ssl address=10.10.0.0/16" in locked
      and "certificate add" not in locked
      and "api-ssl certificate=" not in locked)
check("tunnel-accept firewall rule is moved FIRST so a drop can't block it",
      'move [find comment="mikromon:tunnel:fw"] destination=0' in locked)
check("provisioning enables WebFig + Winbox for remote management over tunnel",
      "/ip service set www disabled=no" in locked
      and "/ip service set winbox disabled=no" in locked)
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
# diagnosis: tell a self-inflicted change from an ISP / wider-area outage
check("healthy device -> no diagnosis", web._diagnose(True, False, None, 0) is None)
check("down right after a change -> blames the change",
      web._diagnose(False, False, 3, 0)[0] == "change")
check("down with several others down -> wider/area outage",
      web._diagnose(False, False, 3, 2)[0] == "area")
check("up but WAN down -> ISP/internet problem, not the change",
      web._diagnose(True, True, None, 0)[0] == "internet")
check("down with no recent change or outage -> generic offline",
      web._diagnose(False, False, 999, 0)[0] == "offline")
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
org = a.signup("admin@acme.test", "admin123", "Acme")   # owner of Acme
a.add_member(org, "bob@acme.test", "bob123", devices=[])  # member, no devices
a.add_member(org, "carol@acme.test", "carol123",         # member allocated WebR1
             devices=["WebR1"])
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
        {"email": user, "password": pw}).encode()), timeout=5)
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
    admin = op_login("admin@acme.test", "admin123")
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
    # "resources" matches the default (True) so storage omits it as redundant;
    # "security" is a real override (False) and is stored explicitly.
    check("checks captured from form",
          raw["checks"].get("resources", True) and not raw["checks"]["security"])
    check("3 WAN links captured in priority order",
          [l["name"] for l in raw["wan"]["links"]] == ["Vodacom", "MTN", "LTE"])
    saved.close()
    # Script-first add: a BLANK host means "provision over the tunnel" — the
    # device is saved with a pre-assigned tunnel IP (no public IP) and the user
    # is sent to the provisioning script tab.
    redir = post_status(admin, "/devices/save", {
        "csrf": csrf, "original_name": "", "name": "DialHome", "host": "",
        "checks": ["resources"]})
    saved = DevicesStore(wdb)
    raw = saved.raw("DialHome")
    # Allocated from the full 10.10.0.0/16 (not just .0.x) — see _alloc_tunnel_ip.
    check("blank host -> device saved with a tunnel IP (no public IP)",
          raw is not None and raw["host"].startswith("10.10."))
    check("blank-host add redirects to the provisioning script tab",
          redir == 303)
    saved.delete("DialHome")
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
    # /device/forget now renders an offboard-result page (200) instead of
    # redirecting, so the admin can see whether the router cleanup succeeded.
    check("Remove button purges an orphan device's metrics from the DB",
          forget_st == 200
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
    # A member NOT allocated the device is blocked from managing it. Use a
    # VALID CSRF so we're testing the permission (403), not CSRF (400).
    nobody = op_login("bob@acme.test", "bob123")
    _, bacct = get(nobody, "/account")
    bcsrf = re.search(r'name="csrf" value="([^"]+)"', bacct).group(1)
    st, _ = get(nobody, "/device?name=WebR1&tab=backups")
    check("unallocated member blocked from the Backups tab (403)", st == 403)
    st, _ = post(nobody, "/device/backup", {"csrf": bcsrf, "device": "WebR1"})
    check("unallocated member blocked from creating a backup (403)", st == 403)
    # A member the device IS allocated to gets full device management. (We test
    # the offline management paths — backup dry-run + WAN save — since a live
    # push/connect would hang on the unreachable test host; the permission gate
    # is the same for all device routes.)
    ally = op_login("carol@acme.test", "carol123")
    _, cacct = get(ally, "/account")
    ccsrf = re.search(r'name="csrf" value="([^"]+)"', cacct).group(1)
    st, _ = get(ally, "/device?name=WebR1")
    check("allocated member CAN open the device page", st == 200)
    st, body = post(ally, "/device/backup",
                    {"csrf": ccsrf, "device": "WebR1", "bkname": "memtest"})
    check("allocated member can run a device action (backup dry-run)",
          st == 200 and "Dry run" in body)
    st = post_status(ally, "/device/wan",
                     {"csrf": ccsrf, "device": "WebR1",
                      "link_name": ["Fibre"], "link_iface": ["ether1"],
                      "link_gw": [""]})
    check("allocated member can save device config (WAN uplinks) — 303", st == 303)
    st, _ = get(ally, "/devices")
    check("allocated member is still blocked from device inventory (403)",
          st == 403)
    # --- all engines opened: device tabs + activity log ---
    st, body = get(admin, "/device?name=WebR1")
    check("device tab bar links every engine (wan/security/qos/portfwd)",
          all(s in body for s in ("tab=wan", "tab=security", "tab=qos",
                                  "tab=portfwd", "tab=nextdns", "tab=remote",
                                  "tab=interfaces", "tab=scripts", "tab=harden",
                                  "tab=tunnel", "tab=update",
                                  "tab=provision")))
    check("Hub tunnel tab removed", "tab=hubtunnel" not in body)
    st, body = get(admin, "/logs")
    check("admin can open the activity log", st == 200 and "activity log" in body.lower())
    st, _ = get(nobody, "/logs")
    check("non-admin blocked from the activity log (403)", st == 403)
    st, _ = post(nobody, "/device/push",
                 {"csrf": bcsrf, "device": "WebR1", "feature": "security"})
    check("unallocated member blocked from pushing config (403)", st == 403)
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
                     {"csrf": bcsrf, "device": "WebR1", "link_iface": ["x"]})
    check("unallocated member blocked from editing WAN (403)", st == 403)
    # --- Provision tab: generate a bootstrap script + save strong creds ---
    st, body = get(admin, "/device?name=WebR1&tab=provision")
    check("admin can open the Provision tab",
          st == 200 and "Generate provisioning script" in body)
    st, body = post(admin, "/device/provision",
                    {"csrf": csrf, "device": "WebR1", "pwuser": "mikromon",
                     "transport": "wg", "hub": "102.36.140.219",
                     "enable_api": "1", "harden": "1"})
    check("provision generates a bootstrap script (user + API)",
          st == 200 and "/user add name=mikromon" in body
          and "/ip service set api disabled=no" in body)
    # Credentials shown after generating are masked until "Show" is clicked.
    check("credentials are hidden until revealed (masked + Show toggle)",
          'type="password"' in body and "mmReveal" in body)
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
                     {"csrf": bcsrf, "device": "WebR1"})
    check("unallocated member blocked from provisioning (403)", st == 403)
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
    bob = op_login("bob@acme.test", "bob123")
    _, bacct2 = get(bob, "/account")
    bcsrf2 = re.search(r'name="csrf" value="([^"]+)"', bacct2).group(1)
    st, _ = get(bob, "/devices")
    check("member blocked from /devices inventory (403)", st == 403)
    st, _ = post(bob, "/devices/save",
                 {"csrf": bcsrf2, "name": "X", "host": "1.1.1.1"})
    check("member blocked from adding a device (owner-only, 403)", st == 403)
finally:
    srv.shutdown()
    srv.server_close()

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL DEVICE TESTS PASSED")
