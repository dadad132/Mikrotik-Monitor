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

from mikromon import nextdns as nextdns_mod
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

import types as _types  # noqa: E402

# Devices are polled concurrently (bounded thread pool), not one at a time —
# with many devices, sequential polling could take far longer than
# poll_interval to get through everyone.
conc_cfg = AppConfig(state_file=os.path.join(tmp, "conc.json"), devices=[],
                     poll_concurrency=10, defaults=DEF)
conc_eng = Engine(conc_cfg, devices=[], notifiers=[])
conc_eng.devices = [_types.SimpleNamespace(name=f"D{i}") for i in range(5)]
_delay = 0.3
def _fake_poll_slow(device):
    time.sleep(_delay)
    return []
conc_eng._poll_device = _fake_poll_slow
_t0 = time.time()
conc_eng.run_once()
_elapsed = time.time() - _t0
check("polling 5 devices concurrently takes ~1 delay, not 5x (proves "
      "devices are actually polled in parallel, not one at a time)",
      _elapsed < _delay * 3)

# One device's crash must not stop the others from being polled — a plain
# sequential loop with no per-future isolation would let one bad device
# take down the whole poll cycle.
seen = []
def _fake_poll_with_failure(device):
    if device.name == "Bad":
        raise RuntimeError("boom")
    seen.append(device.name)
    return []
fail_cfg = AppConfig(state_file=os.path.join(tmp, "failpoll.json"), devices=[],
                     poll_concurrency=10, defaults=DEF)
fail_eng = Engine(fail_cfg, devices=[], notifiers=[])
fail_eng.devices = [_types.SimpleNamespace(name=n) for n in ("A", "Bad", "C")]
fail_eng._poll_device = _fake_poll_with_failure
fail_eng.run_once()
check("one device's crash doesn't stop the other devices from being polled",
      sorted(seen) == ["A", "C"])

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

# link_type (the WAN tab's "Connection type" override — Auto/Dial-up/DHCP,
# see _apply_failover) must round-trip through save/load exactly like
# Distance does.
cfgtype = build_device({"name": "R", "host": "1.1.1.1", "wan": {"links": [
    {"name": "Axxess", "interface": "Axxess", "link_type": "ppp"},
    {"name": "Backup", "interface": "ether2", "link_type": "dhcp"},
    {"name": "Auto", "interface": "ether3"}]}}, DEF)
check("build_device parses an explicit link_type override",
      [ep.link_type for ep in cfgtype.wan.links] == ["ppp", "dhcp", ""])
check("an unrecognized link_type value is treated as auto (empty), not "
      "passed through as garbage",
      build_device({"name": "R", "host": "1.1.1.1", "wan": {"links": [
          {"name": "X", "interface": "ether1", "link_type": "nonsense"}]}},
          DEF).wan.links[0].link_type == "")
resaved_type = device_to_dict(cfgtype)
check("device_to_dict includes link_type when serializing back for storage",
      [lk.get("link_type") for lk in resaved_type["wan"]["links"]] == ["ppp", "dhcp", ""])
cfgtype2 = build_device(resaved_type, DEF)
check("a second save/load round-trip still has the same link_type choices",
      [ep.link_type for ep in cfgtype2.wan.links] == ["ppp", "dhcp", ""])
wed_type = web._wan_uplink_editor("R", cfgtype, "csrf")
check("the WAN uplinks editor shows the saved Connection type selected "
      "for each row",
      '<option value="ppp" selected>Dial-up (PPPoE)</option>' in wed_type
      and '<option value="dhcp" selected>DHCP / static</option>' in wed_type)
check("a link with no chosen type defaults to 'Auto' selected (also true "
      "for the blank trailing 'add new' row and the hidden <template> row, "
      "hence 3)",
      wed_type.count('<option value="" selected>Auto</option>') == 3)

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

# The interface picker groups dial-up (PPPoE/PPTP/L2TP) separately from
# plain ethernet ports, so it's clear at a glance which kind of connection
# each option is instead of guessing from a raw RouterOS type name.
wed_groups = web._wan_uplink_editor(
    "R", cfgwan, "csrf",
    ifaces=[{"name": "ether1", "type": "ether"},
           {"name": "Axxess", "type": "pppoe-out"},
           {"name": "vlan10", "type": "vlan"}])
check("dial-up (PPPoE-type) interfaces are grouped under their own optgroup",
      'label="Dial-up (PPPoE/PPTP/L2TP)"' in wed_groups
      and wed_groups.index('label="Dial-up (PPPoE/PPTP/L2TP)"')
      < wed_groups.index('value="Axxess"'))
check("plain ethernet/other ports are grouped separately from dial-up",
      'label="Ethernet / other ports"' in wed_groups
      and wed_groups.index('label="Ethernet / other ports"')
      < wed_groups.index('value="ether1"'))

# The Gateway column shows what mikromon auto-detects (as a placeholder,
# and a small "detected:" hint) and lets the admin type in an override —
# reported live: automatic detection can land on the interface name itself
# (no gateway IP found from PPP/DHCP) or the wrong address, so a manual
# escape hatch is needed rather than only ever trusting auto-detection.
cfggw = build_device({"name": "R", "host": "1.1.1.1", "wan": {"links": [
    {"name": "Axxess", "interface": "Axxess"},
    {"name": "Backup", "interface": "ether2", "gateway": "172.17.232.254"}]}}, DEF)
wed_gw = web._wan_uplink_editor(
    "R", cfggw, "csrf", detected_gateways={"Axxess": "Axxess", "ether2": "172.17.232.254"})
check("a link with no manual override shows the detected value as a "
      "placeholder (so it's visible without typing anything)",
      'name="link_gw" placeholder="Axxess" value=""' in wed_gw)
check("a link WITH a manually-saved override shows that value filled in, "
      "not the detected one",
      'name="link_gw" placeholder="172.17.232.254" '
      'value="172.17.232.254"' in wed_gw)
check("no redundant 'detected: X' hint when the saved override already "
      "matches the detected value",
      wed_gw.count("detected:") == 0)
wed_mismatch = web._wan_uplink_editor(
    "R", cfggw, "csrf", detected_gateways={"Axxess": "Axxess", "ether2": "10.0.0.9"})
check("a 'detected: X' hint appears when the live-detected gateway differs "
      "from what's saved, so a stale override is visible",
      "detected: 10.0.0.9" in wed_mismatch)

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
# RouterOS's "Device Mode" security feature blocks adding a scheduler over
# the API on some hardware — the raw error is opaque, so it's translated
# into a plain explanation + the (physical, one-time) fix steps instead.
dm_msg = web._friendly_push_error(
    "apply failed after 2 op(s); rolled back 0. add /system/scheduler "
    "failed: failure: not allowed by device-mode")
check("a device-mode error gets a plain-language explanation, not raw text",
      "Device Mode" in dm_msg and "physically" in dm_msg)
check("the device-mode fix steps are included",
      "/system/device-mode/update scheduler=yes" in dm_msg
      and "power-cycle" in dm_msg.lower())
check("an unrelated error gets no special-cased message (caller falls "
      "back to the generic box)",
      web._friendly_push_error("connection refused") == "")
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

# Personal VPN access (road-warrior peers) — a person's own direct WireGuard
# peer of the HUB itself (not riding on any one router's connection), org-
# scoped so one company's staff can never be handed access to another
# company's routers on this shared, multi-tenant hub (Team page).
rw_hub = {}
rw_ip1 = web._alloc_roadwarrior_ip(rw_hub, "keyalice", "alice", 1)
rw_ip2 = web._alloc_roadwarrior_ip(rw_hub, "keybob", "bob", 1)
check("road-warrior IPs are unique and stable per key",
      rw_ip1 != rw_ip2
      and web._alloc_roadwarrior_ip(rw_hub, "keyalice", "alice", 1) == rw_ip1)
collide_hub = {"leases": {"R1": rw_ip1}}
check("road-warrior allocation never collides with an existing device lease",
      web._alloc_roadwarrior_ip(collide_hub, "keycarol", "carol", 1) != rw_ip1)

leases_hub = {
    "leases_meta": {"R1": {"ip": "10.10.1.1", "pubkey": "R1KEY="}},
    "leases": {"R1": "10.10.1.1"},
    "roadwarriors": {"keyalice": {"label": "alice", "org_id": 1,
                                  "ip": "10.10.9.9", "pubkey": "ALICEPUB="}},
}
merged = web._hub_wg_leases(leases_hub)
check("_hub_wg_leases keeps a router's own entry untouched by road-warriors "
      "(no more folding into its 'extra' allowed IPs)",
      merged["R1"]["ip"] == "10.10.1.1" and merged["R1"]["extra"] == [])
check("a road-warrior gets its OWN dedicated hub peer entry",
      any(v["ip"] == "10.10.9.9" and v["pubkey"] == "ALICEPUB="
          for k, v in merged.items() if k != "R1"))
rw_peersp = os.path.join(tmp, "wg-peers-rw.conf")
web._write_wg_peers(rw_peersp, merged)
rw_body = open(rw_peersp).read()
check("the hub's peers file has TWO separate [Peer] blocks — the router's "
      "own and the road-warrior's own, each with just its own /32",
      rw_body.count("[Peer]") == 2
      and "AllowedIPs = 10.10.1.1/32" in rw_body
      and "AllowedIPs = 10.10.9.9/32" in rw_body)

# _rw_allowed_subnets: what a road-warrior's OWN client config should route
# through the tunnel — org-scoped, never another company's devices/subnets.
rw_wdb = os.path.join(tmp, "rworgs", "devices.db")
os.makedirs(os.path.dirname(rw_wdb), exist_ok=True)
rw_ds = DevicesStore(rw_wdb)
rw_ds.upsert({"name": "OrgA-R1", "host": "10.0.9.1"}, DEF, org_id=1)
rw_ds.upsert({"name": "OrgB-R1", "host": "10.0.9.2"}, DEF, org_id=2)
rw_ds.close()
rw_scope_hub = {
    "leases": {"OrgA-R1": "10.10.5.5", "OrgB-R1": "10.10.6.6"},
    "vpn_groups": {
        "OrgA-R1": {"subnet": "192.168.10.0/24", "members": {}},
        "OrgB-R1": {"subnet": "192.168.20.0/24", "members": {}},
    },
}
scope_a = web._rw_allowed_subnets(rw_scope_hub, rw_wdb, 1)
check("a road-warrior's allowed subnets include their OWN company's device "
      "tunnel IP", "10.10.5.5/32" in scope_a)
check("...and their own company's linked VPN-group subnet",
      "192.168.10.0/24" in scope_a)
check("...but NEVER another company's device tunnel IP",
      "10.10.6.6/32" not in scope_a)
check("...or another company's VPN-group subnet",
      "192.168.20.0/24" not in scope_a)

# _org_wg_addresses: who a fresh Remote-access temporary login should be
# restricted to — everything _rw_allowed_subnets covers, PLUS every Personal
# VPN peer already issued to this company's own team (Team page), still
# never another company's.
rw_scope_hub["roadwarriors"] = {
    "keyalice": {"label": "Alice's laptop", "org_id": 1, "ip": "10.10.44.44"},
    "keymallory": {"label": "Mallory (org B)", "org_id": 2, "ip": "10.10.55.55"},
}
org_addrs_a = web._org_wg_addresses(rw_scope_hub, rw_wdb, 1)
check("a temp login's allowed addresses include this org's own device "
      "tunnel IP", "10.10.5.5/32" in org_addrs_a)
check("...and this org's own linked VPN-group subnet",
      "192.168.10.0/24" in org_addrs_a)
check("...and every Personal VPN peer already issued to THIS org's team",
      "10.10.44.44/32" in org_addrs_a)
check("...but never another org's device tunnel IP",
      "10.10.6.6/32" not in org_addrs_a)
check("...or another org's VPN-group subnet",
      "192.168.20.0/24" not in org_addrs_a)
check("...or another org's Personal VPN peer",
      "10.10.55.55/32" not in org_addrs_a)

# _build_wg_diagnostics_lines: the superadmin diagnostics report's hub/
# tunnel section — everything needed to debug "can't reach a device" or
# "VPN routing isn't working" without SSH access, degrading gracefully
# when devices_db/hub.json isn't there and when the wg/systemctl/journalctl/
# ip binaries aren't available (as on this test machine).
check("no devices_db configured -> a clear one-line explanation, not a crash",
      any("no hub in use" in ln
          for ln in web._build_wg_diagnostics_lines(None)))
wgdiag_wdb = os.path.join(tmp, "wgdiag", "devices.db")
os.makedirs(os.path.dirname(wgdiag_wdb), exist_ok=True)
wgdiag_hub_file = web._hub_path(wgdiag_wdb)
web._hub_save(wgdiag_hub_file, {
    "hub_ip": "203.0.113.9", "listen_port": "51820", "subnet": "10.10.0.0/16",
    "hub_pubkey": "HUBPUBKEY=",
    "leases_meta": {"R1": {"ip": "10.10.1.1", "pubkey": "R1PUB="}},
    "roadwarriors": {"k1": {"label": "Alice", "org_id": 1,
                            "ip": "10.10.44.44", "pubkey": "APUB="}},
    "vpn_groups": {"R1": {"subnet": "192.168.10.0/24",
                          "members": {"R2": {"subnet": "192.168.20.0/24"}}}},
})
wgdiag_lines = web._build_wg_diagnostics_lines(wgdiag_wdb)
wgdiag_text = "\n".join(wgdiag_lines)
check("shows the registered router peer (name, tunnel IP, pubkey presence)",
      "R1: ip=10.10.1.1 pubkey=set" in wgdiag_text)
check("shows the registered Personal VPN peer",
      "Alice: org_id=1 ip=10.10.44.44 pubkey=set" in wgdiag_text)
check("shows the VPN site-to-site group and its sub-unit",
      "R1 (main)" in wgdiag_text and "+ R2 (sub-unit)" in wgdiag_text)
check("never leaks a private key (hub.json only ever stores public ones)",
      "PRIVATE" not in wgdiag_text.upper()
      and "PRIVKEY" not in wgdiag_text.upper())
check("missing/unavailable diagnostic commands degrade to a clear note, "
      "not a crash or a stack trace",
      "Traceback" not in wgdiag_text)

# Site-to-site VPN (VPN tab): one router is the "main host" for a group,
# other routers are added as "sub-units" of it — each sub-unit's subnet
# gets routed through the hub's own tunnel IP, to the main host and every
# other sub-unit in the same group.
vpn_groups_hub = {
    "vpn_groups": {
        "HQ": {"subnet": "192.168.1.0/24",
              "members": {"Branch": {"subnet": "192.168.2.0/24"}}},
    },
}
check("_vpn_flat_subnets includes both the main host and its sub-units",
      web._vpn_flat_subnets(vpn_groups_hub) ==
      {"HQ": "192.168.1.0/24", "Branch": "192.168.2.0/24"})
check("_vpn_group_info identifies a main host, with its group dict",
      web._vpn_group_info(vpn_groups_hub, "HQ") ==
      ("main", vpn_groups_hub["vpn_groups"]["HQ"]))
check("_vpn_group_info identifies a sub-unit, with its main host's name",
      web._vpn_group_info(vpn_groups_hub, "Branch") == ("member", "HQ"))
check("_vpn_group_info reports (None, None) for a device in no group",
      web._vpn_group_info(vpn_groups_hub, "Nobody") == (None, None))

conflict_hub = {"subnet": "10.10.0.0/16", **vpn_groups_hub}
check("a subnet overlapping the hub's own tunnel pool is rejected",
      "tunnel network" in web._subnet_conflict(conflict_hub, "Third", "10.10.5.0/24"))
check("a subnet overlapping the main host's subnet is rejected",
      "HQ" in web._subnet_conflict(conflict_hub, "Third", "192.168.1.0/25"))
check("a subnet overlapping an existing sub-unit's subnet is rejected",
      "Branch" in web._subnet_conflict(conflict_hub, "Third", "192.168.2.0/25"))
check("a clear, non-overlapping subnet passes",
      web._subnet_conflict(conflict_hub, "Third", "192.168.3.0/24") == "")
check("a device re-confirming its OWN already-registered subnet is not a conflict",
      web._subnet_conflict(conflict_hub, "HQ", "192.168.1.0/24") == "")
check("garbage input is rejected with a clear message, not a crash",
      "valid" in web._subnet_conflict(conflict_hub, "Third", "not-a-subnet"))

sites_hub = {
    "leases_meta": {"HQ": {"ip": "10.10.1.1", "pubkey": "HQKEY="},
                    "Branch": {"ip": "10.10.1.2", "pubkey": "BRKEY="}},
    "leases": {"HQ": "10.10.1.1", "Branch": "10.10.1.2"},
    **vpn_groups_hub,
}
sites_merged = web._hub_wg_leases(sites_hub)
check("_hub_wg_leases folds both the main host's and its sub-unit's LAN "
      "subnets into their own 'extra' allowed addresses",
      sites_merged["HQ"]["extra"] == ["192.168.1.0/24"]
      and sites_merged["Branch"]["extra"] == ["192.168.2.0/24"])
sites_peersp = os.path.join(tmp, "wg-peers-sites.conf")
web._write_wg_peers(sites_peersp, sites_merged)
sites_body = open(sites_peersp).read()
check("a site's LAN subnet is written with its own mask, not force-suffixed /32",
      "AllowedIPs = 10.10.1.1/32, 192.168.1.0/24" in sites_body)

routesp = os.path.join(tmp, "wg-routes.conf")
ok_routes, _ = web._write_wg_routes(routesp, sites_hub)
routes_body = open(routesp).read()
check("wg-routes.conf lists one line per registered site subnet (main "
      "host + sub-units)",
      ok_routes and set(routes_body.split()) == {"192.168.1.0/24", "192.168.2.0/24"})

# _prep_vpn_group: the web-layer glue that reads a device's spot in the VPN
# grouping and injects what tunnel_plan needs (the other subnets in ITS OWN
# group + the hub's tunnel IP) since tunnel_plan never sees devices_db. It
# is read-only with respect to grouping itself — that only ever changes via
# the dedicated make-main/add-member/remove-member/stop-main actions.
vpn_devices_db = os.path.join(tmp, "vpndevices.json")
web._hub_save(web._hub_path(vpn_devices_db), dict(vpn_groups_hub))

hq_flat = {}
web._prep_vpn_group("HQ", hq_flat, vpn_devices_db)
check("_prep_vpn_group recognizes a main host and injects the hub's tunnel IP",
      hq_flat["_vpn_in_group"] is True and hq_flat["_vpn_hub_ip"] == "10.10.0.1")
check("a main host's 'other subnets' are its sub-units' subnets",
      hq_flat["_vpn_other_subnets"] == ["192.168.2.0/24"])

branch_flat = {}
web._prep_vpn_group("Branch", branch_flat, vpn_devices_db)
check("_prep_vpn_group recognizes a sub-unit",
      branch_flat["_vpn_in_group"] is True)
check("a sub-unit's 'other subnets' are its main host's subnet plus any "
      "OTHER sub-units' subnets (none here)",
      branch_flat["_vpn_other_subnets"] == ["192.168.1.0/24"])

nobody_flat = {}
web._prep_vpn_group("Nobody", nobody_flat, vpn_devices_db)
check("a device in no group at all gets nothing to route to",
      nobody_flat["_vpn_in_group"] is False
      and nobody_flat["_vpn_other_subnets"] == [])

vpn_peersp = os.path.join(tmp, "wg-peers-sync.conf")
vpn_routesp = os.path.join(tmp, "wg-routes-sync.conf")
sync_hub = web._hub_load(web._hub_path(vpn_devices_db))
sync_hub["wg_peers"], sync_hub["wg_routes"] = vpn_peersp, vpn_routesp
sync_hub["leases_meta"] = {"HQ": {"ip": "10.10.1.1", "pubkey": "HQKEY="}}
sync_hub["leases"] = {"HQ": "10.10.1.1"}
web._hub_save(web._hub_path(vpn_devices_db), sync_hub)
web._sync_vpn_group_to_hub(vpn_devices_db)
check("_sync_vpn_group_to_hub writes both the peers file and the routes file",
      "192.168.1.0/24" in open(vpn_peersp).read()
      and "192.168.1.0/24" in open(vpn_routesp).read())

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
mdb, sfile, adb, wdb, pldb, aldb = (os.path.join(tmp, x) for x in
                        ("m.db", "s.json", "a.db", "w.db", "pl.db", "al.db"))
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
    mdb, sfile, AuthStore(adb), web.SessionManager(), devices_db=wdb, defaults=DEF,
    push_log_db=pldb, alert_log_db=aldb))
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
    # A POST handler that redirects to /device?...&tab=X&error=... (rather
    # than folding the failure into &msg=...) used to have that error text
    # silently dropped — the generic /device GET route only ever read msg=
    # from the query string, never error=, so _feature_tab_page always saw
    # error="" regardless of what was actually in the URL.
    st, body = get(admin, "/device?name=WebR1&tab=wan&error="
                          "a+distinctive+test+error+xyz123")
    check("an error= query param on a generic feature tab actually renders "
          "(regression: used to be silently dropped)",
          "a distinctive test error xyz123" in body)
    # --- VPN tab site-to-site grouping: guard paths that don't need a live
    # router connection (the actual subnet-detection paths are covered
    # offline, in the "Site-to-site VPN" unit tests above) ---
    hub_for_vpn = web._hub_load(web._hub_path(wdb))
    hub_for_vpn.setdefault("vpn_groups", {})["WebR1"] = {
        "subnet": "192.168.50.0/24", "members": {}}
    web._hub_save(web._hub_path(wdb), hub_for_vpn)
    st = post_status(admin, "/device/vpn-make-main", {"csrf": csrf, "device": "WebR1"})
    check("make-main is refused (redirect) when already part of a VPN group",
          st == 303)
    st = post_status(admin, "/device/vpn-add-member",
                     {"csrf": csrf, "device": "WebR1", "member": ""})
    check("add-member with no sub-unit selected is rejected (400)", st == 400)
    st = post_status(nobody, "/device/vpn-add-member",
                     {"csrf": bcsrf, "device": "WebR1", "member": "WebR2"})
    check("unallocated member blocked from adding a VPN sub-unit (403)", st == 403)
    o = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(admin.cj), _NoRedir)
    body = urllib.parse.urlencode(
        {"csrf": csrf, "device": "WebR1"}).encode()
    try:
        r = o.open(urllib.request.Request(B + "/device/vpn-stop-main",
                                          data=body), timeout=8)
        st, location = getattr(r, "status", r.code), r.headers.get("Location", "")
    except urllib.error.HTTPError as e:
        st, location = e.code, e.headers.get("Location", "")
    # WebR1 has no members here, so stop-main should succeed. WebR1's host
    # (8.8.8.8, from an earlier WAN-edit test) is unreachable as a router,
    # so the auto-push this now triggers should fail gracefully (bounded by
    # dev.reachable()'s quick probe, not a full connect timeout) and say so
    # in the redirect message, rather than silently doing nothing.
    check("stop-main succeeds (redirect) when the group has no sub-units", st == 303)
    check("stop-main's auto-push reports the unreachable router, not silence",
          "unreachable" in urllib.parse.unquote(location))
    hub_after_stop = web._hub_load(web._hub_path(wdb))
    check("stop-main actually removed WebR1 from vpn_groups",
          "WebR1" not in hub_after_stop.get("vpn_groups", {}))
    # "Refresh routes & firewall rule now" — forces a re-push for a whole
    # group without a disruptive remove-and-re-add (e.g. after a mikromon
    # update changes what gets pushed, or a router was offline originally).
    st = post_status(nobody, "/device/vpn-refresh",
                     {"csrf": bcsrf, "device": "WebR1"})
    check("unallocated member blocked from refreshing VPN routes (403)",
          st == 403)
    st = post_status(admin, "/device/vpn-refresh", {"csrf": csrf, "device": "WebR1"})
    check("refresh on a router that's not in any VPN group just says so "
          "(redirect, no crash)", st == 303)
    hub_for_refresh = web._hub_load(web._hub_path(wdb))
    hub_for_refresh.setdefault("vpn_groups", {})["WebR1"] = {
        "subnet": "192.168.60.0/24",
        "members": {"WebR2": {"subnet": "192.168.61.0/24"}}}
    web._hub_save(web._hub_path(wdb), hub_for_refresh)
    o = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(admin.cj), _NoRedir)
    body = urllib.parse.urlencode({"csrf": csrf, "device": "WebR1"}).encode()
    try:
        r = o.open(urllib.request.Request(B + "/device/vpn-refresh",
                                          data=body), timeout=8)
        st, location = getattr(r, "status", r.code), r.headers.get("Location", "")
    except urllib.error.HTTPError as e:
        st, location = e.code, e.headers.get("Location", "")
    check("refresh on a grouped router (main w/ a sub-unit) succeeds "
          "(redirect)", st == 303)
    check("refresh attempted a push to BOTH the main and its sub-unit, not "
          "just the one clicked from",
          "WebR1" in urllib.parse.unquote(location)
          and "WebR2" in urllib.parse.unquote(location))
    # _build_vpn_router_diagnostics_lines: the diagnostics report's live
    # expected-vs-actual comparison for every router in a VPN group — the
    # direct way to tell "the grouping bookkeeping says connected" from
    # "the router genuinely has the route". WebR1's host (8.8.8.8) is
    # unreachable as a router, so this also proves the bounded reachable()
    # probe kicks in here too (no hang for the full connect timeout).
    vpn_diag = "\n".join(web._build_vpn_router_diagnostics_lines(wdb, DEF))
    check("shows what route WebR1 (main) expects, computed the same way "
          "the real push does", "expects a route to each of: 192.168.61.0/24"
          in vpn_diag)
    check("an unreachable router is reported clearly and quickly, not a "
          "silent hang", "WebR1" in vpn_diag and "UNREACHABLE" in vpn_diag)
    check("no VPN groups at all -> a clear one-line explanation, not a crash",
          "no VPN groups registered" in
          "\n".join(web._build_vpn_router_diagnostics_lines(
              os.path.join(tmp, "novpngroups", "devices.db"), DEF)))
    # --- Remote access tab: "forgot to copy it" regenerate button — guard
    # paths only (an actual regenerate needs a live router connection,
    # same limitation as the rest of this section) ---
    st = post_status(admin, "/device/remote-regenerate",
                     {"csrf": csrf, "device": "WebR1", "username": ""})
    check("remote-regenerate with no login selected is rejected (400)", st == 400)
    st = post_status(nobody, "/device/remote-regenerate",
                     {"csrf": bcsrf, "device": "WebR1", "username": "alice"})
    check("unallocated member blocked from regenerating a remote login (403)",
          st == 403)
    # "Test connectivity" — permission gate only (a real run needs a live
    # router connection, same limitation as the rest of this section).
    st = post_status(nobody, "/device/remote-test",
                     {"csrf": bcsrf, "device": "WebR1"})
    check("unallocated member blocked from testing Remote access connectivity (403)",
          st == 403)
    # --- Team page: personal VPN access (road-warrior peers) — guard paths.
    # A real add needs `wg` (wireguard-tools) on the test host to generate a
    # keypair, which isn't guaranteed here, so this only covers permission
    # and org-scoping, not the happy path (covered offline above). ---
    st = post_status(nobody, "/admin/roadwarrior-add",
                     {"csrf": bcsrf, "label": "Bob's laptop"})
    check("member (non-owner) blocked from issuing personal VPN access (403)",
          st == 403)
    st = post_status(admin, "/admin/roadwarrior-add", {"csrf": csrf, "label": ""})
    check("adding a VPN peer with no label is rejected (redirect w/ error)",
          st == 303)
    other_org_hub = web._hub_load(web._hub_path(wdb))
    other_org_hub.setdefault("roadwarriors", {})["otherorgkey"] = {
        "label": "Someone else's laptop", "org_id": 999999,
        "ip": "10.10.44.44", "pubkey": "OTHERORGPUB="}
    web._hub_save(web._hub_path(wdb), other_org_hub)
    st = post_status(admin, "/admin/roadwarrior-revoke",
                     {"csrf": csrf, "key": "otherorgkey"})
    check("owner cannot revoke another company's VPN peer, even by guessing "
          "its key (404)", st == 404)
    still_there = web._hub_load(web._hub_path(wdb))
    check("that other company's peer is untouched",
          "otherorgkey" in still_there.get("roadwarriors", {}))
    st, body = get(admin, "/logs")
    check("admin can open the activity log", st == 200 and "activity log" in body.lower())
    st, _ = get(nobody, "/logs")
    check("non-admin blocked from the activity log (403)", st == 403)

    # The Activity tab must be scoped per-company — a user (even a
    # superadmin, viewing their OWN Activity tab) must never see another
    # company's push/alert history. admin@acme.test is the very first
    # signup on this AuthStore db, so it was auto-promoted to superadmin —
    # exactly the account type that used to bypass this scoping.
    from mikromon.push import AuditLog
    from mikromon.alert_log import AlertLog
    a_orgs = AuthStore(adb)
    org_b = a_orgs.signup("owner@orgb.test", "orgb123", "OrgB")
    check("admin@acme.test (first-ever signup) is a superadmin",
          bool(a_orgs.get_user("admin@acme.test").get("is_superadmin")))
    a_orgs.close()
    ds_orgb = DevicesStore(wdb)
    ds_orgb.upsert({"name": "OrgB-Router", "host": "8.8.4.4"}, DEF, org_id=org_b)
    ds_orgb.close()
    AuditLog(pldb).append("WebR1", "admin@acme.test", "security", "apply",
                          "ok", "Acme push marker", "")
    AuditLog(pldb).append("OrgB-Router", "owner@orgb.test", "security", "apply",
                          "ok", "OrgB push marker", "")
    AlertLog(aldb).append("WebR1", "wan_link:0", "Acme WAN down", 2, False)
    AlertLog(aldb).append("OrgB-Router", "wan_link:0", "OrgB WAN down", 2, False)
    st, body = get(admin, "/logs")
    check("superadmin's own Activity tab shows their own company's push log",
          st == 200 and "Acme push marker" in body)
    check("superadmin's own Activity tab shows their own company's alerts",
          "Acme WAN down" in body)
    check("superadmin's own Activity tab does NOT show another company's push log",
          "OrgB push marker" not in body)
    check("superadmin's own Activity tab does NOT show another company's alerts",
          "OrgB WAN down" not in body)
    # Clean up the extra device so later tests (which assume only WebR1
    # exists in this store) are unaffected.
    ds_orgb_cleanup = DevicesStore(wdb)
    ds_orgb_cleanup.delete("OrgB-Router")
    ds_orgb_cleanup.close()
    # --- Superadmin: "Hub endpoint" — migrate the hub to a new server/IP
    # (or a DDNS hostname) without re-provisioning every router by hand ---
    st, _ = post(nobody, "/superadmin/hub-endpoint",
                {"csrf": bcsrf, "hub_ip": "hub.example.com", "hub_port": "51820"})
    check("non-superadmin blocked from changing the hub endpoint (403)",
          st == 403)
    st, body = post(admin, "/superadmin/hub-endpoint",
                    {"csrf": csrf, "hub_ip": "", "hub_port": "51820"})
    check("empty hostname/IP is rejected", "cannot be empty" in body)
    st, body = post(admin, "/superadmin/hub-endpoint",
                    {"csrf": csrf, "hub_ip": "hub.example.com",
                     "hub_port": "51820"})
    check("saving a new hub endpoint (no push) succeeds",
          "Hub endpoint set to hub.example.com:51820" in body)
    hub_after_endpoint = web._hub_load(web._hub_path(wdb))
    check("the new endpoint is persisted to hub.json for future provisions",
          hub_after_endpoint.get("hub_ip") == "hub.example.com"
          and hub_after_endpoint.get("listen_port") == "51820")
    st, body = post(admin, "/superadmin/hub-endpoint",
                    {"csrf": csrf, "hub_ip": "hub2.example.com",
                     "hub_port": "51820", "push_now": "1"})
    check("push_now attempts (and reports on) every already-registered "
          "router — WebR1's host is unreachable, so this also proves the "
          "bounded probe kicks in here too (no hang for the full connect "
          "timeout)", "Pushed to 0/1" in body and "unreachable" in body)
    # New public key field — for a full identity migration where the new
    # server generated its own fresh keypair (never copying a private key
    # between hosts by hand).
    st, body = post(admin, "/superadmin/hub-endpoint",
                    {"csrf": csrf, "hub_ip": "hub3.example.com",
                     "hub_port": "51820", "hub_pubkey": "NEWSERVERPUBKEY="})
    check("saving a new hub public key is reflected in the confirmation",
          "with a new public key" in body)
    hub_after_pubkey = web._hub_load(web._hub_path(wdb))
    check("the new public key is persisted to hub.json for future "
          "provisions too, not just the address",
          hub_after_pubkey.get("hub_pubkey") == "NEWSERVERPUBKEY=")
    st, body = post(admin, "/superadmin/hub-endpoint",
                    {"csrf": csrf, "hub_ip": "hub3.example.com",
                     "hub_port": "51820"})
    check("leaving the pubkey field blank on a later save doesn't wipe "
          "the previously-set one back to empty",
          web._hub_load(web._hub_path(wdb)).get("hub_pubkey")
          == "NEWSERVERPUBKEY=")
    # Clean up: this suite's later Provision-tab tests assert hub_pubkey is
    # NOT set (to check the "run install.sh" prompt on an unconfigured hub),
    # so restore that state rather than leaking this test's hub_pubkey into
    # tests that run after it in this same shared wdb/hub.json.
    _hub_cleanup = web._hub_load(web._hub_path(wdb))
    _hub_cleanup.pop("hub_pubkey", None)
    web._hub_save(web._hub_path(wdb), _hub_cleanup)

    # --- Superadmin: "NextDNS" — platform API key + per-router profiles ---
    # /device/nextdns redirects to the live tab page, which (like the VPN
    # tab) tries a real connect to the router first — WebR1's host (9.9.9.9)
    # is a real, filtered address in this sandbox that hangs rather than
    # failing fast, so these checks read the redirect's own Location header
    # (where the confirmation/error message lives) instead of following it,
    # same trick the existing vpn-stop-main/vpn-refresh tests above use.
    def post_loc(op, path, data):
        o = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(op.cj), _NoRedir)
        body = urllib.parse.urlencode(data, doseq=True).encode()
        try:
            r = o.open(urllib.request.Request(B + path, data=body), timeout=8)
            st = getattr(r, "status", r.code)
            loc = r.headers.get("Location", "")
        except urllib.error.HTTPError as e:
            st, loc = e.code, e.headers.get("Location", "")
        return st, urllib.parse.unquote(loc)

    st, _ = post(nobody, "/superadmin/nextdns",
                {"csrf": bcsrf, "api_key": "x", "template_profile": ""})
    check("non-superadmin blocked from saving NextDNS settings (403)", st == 403)

    check("_nextdns_box, with no platform API key configured yet, tells the "
          "admin a superadmin needs to set one up first",
          "superadmin needs to add a NextDNS API key" in
          web._nextdns_box("WebR1", build_device({"name": "WebR1",
                                                   "host": "9.9.9.9"}, DEF),
                           csrf, False))

    st, loc = post_loc(admin, "/device/nextdns",
                       {"csrf": csrf, "device": "WebR1", "enable": "1"})
    check("enabling NextDNS with no platform API key configured is refused, "
          "not a silent no-op or a crash",
          "isn't set up on this server yet" in loc)

    st, body = post(admin, "/superadmin/nextdns",
                    {"csrf": csrf, "api_key": "sekret-nextdns-key",
                     "template_profile": "tmpl99"})
    check("saving NextDNS settings succeeds", "NextDNS settings saved" in body)
    check("the platform API key + template are persisted",
          AuthStore(adb).get_nextdns() ==
          {"api_key": "sekret-nextdns-key", "template_profile": "tmpl99"})

    st, body = get(admin, "/superadmin")
    check("superadmin page shows the API key is saved (masked, like SMTP), "
          "never the raw key", "(saved)" in body
          and "sekret-nextdns-key" not in body)

    check("_nextdns_box now offers to enable it, once a platform key exists",
          "Enable NextDNS for this router" in
          web._nextdns_box("WebR1", build_device({"name": "WebR1",
                                                   "host": "9.9.9.9"}, DEF),
                           csrf, True))

    # A failure creating the profile (e.g. NextDNS account plan/profile
    # limit reached) must show up in the redirect's own message, not
    # silently vanish (an earlier bug: this used a separate error= query
    # param that the /device GET route never actually read, so the
    # message disappeared entirely — looked exactly like "nothing happens").
    def _fake_create_fails(api_key, name, clone_from=""):
        raise nextdns_mod.NextDnsError("simulated: profile limit reached")

    orig_create = nextdns_mod.create_profile
    nextdns_mod.create_profile = _fake_create_fails
    try:
        st, loc = post_loc(admin, "/device/nextdns",
                           {"csrf": csrf, "device": "WebR1", "enable": "1"})
    finally:
        nextdns_mod.create_profile = orig_create
    check("a failed profile creation shows the reason in the redirect "
          "(not a silent no-op)",
          "Could not create a NextDNS profile" in loc
          and "profile limit reached" in loc)
    ds_after_failed_create = DevicesStore(wdb)
    raw_after_failed_create = ds_after_failed_create.raw("WebR1")
    ds_after_failed_create.close()
    check("nothing is saved as enabled when profile creation fails",
          not raw_after_failed_create.get("nextdns_enabled")
          and not raw_after_failed_create.get("nextdns_profile_id"))

    # Enable: a fresh NextDNS profile is created via the (mocked) API,
    # cloning the configured template, and the router is pushed to use it —
    # WebR1's host (9.9.9.9) is unreachable, so the push itself is skipped
    # (bounded by dev.reachable()'s quick probe inside the handler itself,
    # unrelated to the live-tab-page issue above), but the profile is still
    # created and the local enabled state saved.
    create_calls = []

    def _fake_create(api_key, name, clone_from=""):
        create_calls.append((api_key, name, clone_from))
        return "created-profile-1"

    orig_create = nextdns_mod.create_profile
    nextdns_mod.create_profile = _fake_create
    try:
        st, loc = post_loc(admin, "/device/nextdns",
                           {"csrf": csrf, "device": "WebR1", "enable": "1"})
    finally:
        nextdns_mod.create_profile = orig_create
    check("enabling NextDNS reports success even though the router itself "
          "is unreachable right now",
          "NextDNS enabled for this router" in loc and "unreachable" in loc)
    check("create_profile was called with the platform key, the device "
          "name, and the configured template to clone",
          create_calls == [("sekret-nextdns-key", "WebR1", "tmpl99")])
    ds_after_enable = DevicesStore(wdb)
    raw_after_enable = ds_after_enable.raw("WebR1")
    ds_after_enable.close()
    check("the assigned profile id + enabled flag are persisted to the device",
          raw_after_enable.get("nextdns_enabled") is True
          and raw_after_enable.get("nextdns_profile_id") == "created-profile-1")

    box_after_enable = web._nextdns_box(
        "WebR1", build_device(raw_after_enable, DEF), csrf, True)
    check("_nextdns_box now shows the assigned profile + a link into NextDNS",
          "created-profile-1" in box_after_enable
          and "my.nextdns.io/created-profile-1/setup" in box_after_enable)

    print("  diagnostics report picks up the live NextDNS state:")
    diag_report = web._build_nextdns_diagnostics_lines(
        AuthStore(adb), wdb, DEF)
    diag_text = "\n".join(diag_report)
    check("report lists WebR1 (NextDNS enabled) with its assigned profile id",
          "--- WebR1 ---" in diag_text and "created-profile-1" in diag_text)
    check("report shows the platform API key as configured",
          "platform API key: configured" in diag_text)
    check("WebR1's host (9.9.9.9) is unreachable, so the report says so "
          "instead of hanging or crashing",
          "UNREACHABLE from this server right now" in diag_text)

    # Re-enabling (already enabled) must NOT create a second profile.
    orig_create = nextdns_mod.create_profile
    nextdns_mod.create_profile = _fake_create
    try:
        post_loc(admin, "/device/nextdns",
                {"csrf": csrf, "device": "WebR1", "enable": "1"})
    finally:
        nextdns_mod.create_profile = orig_create
    check("re-submitting enable=1 while already enabled is a no-op — no "
          "second profile created", len(create_calls) == 1)

    # Disable: deletes the profile via the (mocked) API and clears local state.
    delete_calls = []

    def _fake_delete(api_key, profile_id):
        delete_calls.append((api_key, profile_id))

    orig_delete = nextdns_mod.delete_profile
    nextdns_mod.delete_profile = _fake_delete
    try:
        st, loc = post_loc(admin, "/device/nextdns",
                           {"csrf": csrf, "device": "WebR1", "enable": "0"})
    finally:
        nextdns_mod.delete_profile = orig_delete
    check("disabling NextDNS confirms", "NextDNS disabled for this router" in loc)
    check("delete_profile was called for the profile that had been created",
          delete_calls == [("sekret-nextdns-key", "created-profile-1")])
    ds_after_disable = DevicesStore(wdb)
    raw_after_disable = ds_after_disable.raw("WebR1")
    ds_after_disable.close()
    check("local state is cleared after disabling",
          raw_after_disable.get("nextdns_enabled") is False
          and raw_after_disable.get("nextdns_profile_id") == "")

    # A failing delete (e.g. the profile was already removed on NextDNS's
    # side) must still clear the LOCAL state — never leave a router stuck
    # permanently showing "enabled" just because the cleanup call failed.
    nextdns_mod.create_profile = _fake_create
    try:
        post_loc(admin, "/device/nextdns", {"csrf": csrf, "device": "WebR1", "enable": "1"})
    finally:
        nextdns_mod.create_profile = orig_create

    def _fake_delete_fails(api_key, profile_id):
        raise nextdns_mod.NextDnsError("simulated: already gone")

    orig_delete = nextdns_mod.delete_profile
    nextdns_mod.delete_profile = _fake_delete_fails
    try:
        post_loc(admin, "/device/nextdns",
                {"csrf": csrf, "device": "WebR1", "enable": "0"})
    finally:
        nextdns_mod.delete_profile = orig_delete
    ds_after_failed_delete = DevicesStore(wdb)
    raw_after_failed_delete = ds_after_failed_delete.raw("WebR1")
    ds_after_failed_delete.close()
    check("local state still clears even when the NextDNS API delete call fails",
          raw_after_failed_delete.get("nextdns_enabled") is False
          and raw_after_failed_delete.get("nextdns_profile_id") == "")

    st = post_status(nobody, "/device/nextdns",
                     {"csrf": bcsrf, "device": "WebR1", "enable": "1"})
    check("unallocated member blocked from toggling NextDNS on a device "
          "they can't manage (403)", st == 403)

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
    # A manual gateway override (link_gw) must round-trip — the escape
    # hatch for when automatic detection (PPP-active/DHCP) falls back to
    # the interface name or picks the wrong address.
    st = post_status(admin, "/device/wan",
                     {"csrf": csrf, "device": "WebR1",
                      "link_name": ["Fibre", "LTE"],
                      "link_iface": ["ether1", "lte1"],
                      "link_gw": ["41.2.3.4", ""]})
    check("manual gateway override save accepted (redirect)", st == 303)
    saved = DevicesStore(wdb)
    raw = saved.raw("WebR1")
    check("the manual gateway override is saved on that link",
          raw["wan"]["links"][0]["gateway"] == "41.2.3.4")
    check("a link left blank keeps auto-detection (no override saved)",
          raw["wan"]["links"][1].get("gateway", "") == "")
    saved.close()
    # link_type (Connection type override) must also round-trip, and an
    # unrecognized value must never persist as garbage.
    st = post_status(admin, "/device/wan",
                     {"csrf": csrf, "device": "WebR1",
                      "link_name": ["Fibre", "LTE"],
                      "link_iface": ["ether1", "lte1"],
                      "link_gw": ["", ""],
                      "link_type": ["dhcp", "bogus"]})
    check("link_type save accepted (redirect)", st == 303)
    saved = DevicesStore(wdb)
    raw = saved.raw("WebR1")
    check("an explicit link_type override is saved on that link",
          raw["wan"]["links"][0]["link_type"] == "dhcp")
    check("an unrecognized link_type value is saved as auto (empty), not "
          "passed through as-is",
          raw["wan"]["links"][1]["link_type"] == "")
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
