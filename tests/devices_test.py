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
import types
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
# Asserts the value that came back, not the whole input's markup: pinning
# every attribute made this fail the next time the placeholder text changed,
# which told us nothing about whether the distance round-tripped.
_dist_inputs = re.findall(r'<input name="link_distance"[^>]*>', wed_dist)
check("the WAN uplinks editor actually displays the saved Distance value "
      "(10) in that row's input, not blank",
      any('value="10"' in i for i in _dist_inputs))
check("...and the placeholder shows the ladder a blank row would get, so the "
      "default is visible without reading the guide",
      any('placeholder="10, 11' in i for i in _dist_inputs))
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
check("the marker only appears when live router data was available",
      "has an active internet connection" not in wed  # no ifaces passed above
      and "has an active internet connection" in wed_detect)
# The separate legend paragraph is gone with the rest of the editor's grey
# prose. It can go because the marker explains itself on the option it sits
# on -- a legend elsewhere on the page was always a worse place to say it.
check("the marker is explained on the option itself, not in a legend "
      "paragraph the reader has to find and match up",
      "🌐 has an active internet connection" in wed_detect)
check("...and the editor points at the guide instead of carrying 220 words "
      "of explanation above the table",
      'href="/guide#tab-wan"' in wed_detect
      and "List your internet links" not in wed_detect)

# Reported live: a customer changed a Distance, pressed Save, was told "WAN
# uplinks saved", and the router kept its old value -- because saving wrote
# the device record and never contacted the router.
check("the editor offers a save that actually reaches the router, not only "
      "one that writes the record",
      'name="push" value="1"' in wed_detect
      and "Save &amp; apply to router" in wed_detect)
check("there is only ONE save button, so there is no way to save and quietly "
      "not push — that ambiguity is what made this tab misleading",
      wed_detect.count('type="submit"') == 1
      and "without applying" not in wed_detect)
# Pressing Enter in a text box submits with no button value, which used to
# fall through to the silent record-only path.
# Reported live: Save & apply reached the preview, and pressing Apply there
# came back "No router was named in that request". The preview page rebuilds
# its Apply form entirely from the submitted fields, and the WAN tab handed it
# an empty set -- so the confirm POST identified neither the router nor the
# change.
from mikromon.push.plan import Plan as _Plan, Operation as _Op
from mikromon.push import FEATURES as _FEATS
_prev = _Plan("R", [_Op("set", ("ip", "route"), {".id": "*1", "distance": "10"},
                        desc="set distance 10")], summary="routes")


def _apply_fields(submitted):
    html = web._render_feature_tab(
        "R", {"login": "o@a.c", "role": "owner", "org_id": 1}, "routes",
        _FEATS["routes"], "CSRF", preview=_prev, submitted=submitted)
    form = re.search(r'<form method="POST" action="/device/push">.*?</form>',
                     html, re.S).group(0)
    got = dict(re.findall(r'name="(\w+)" value="([^"]*)"', form))
    got.pop("csrf", None)
    return got


check("the Apply button under a preview always names the router and the "
      "change, even when the preview was built by a caller that submitted "
      "nothing — otherwise it posts a confirmed change with no target",
      _apply_fields({}).get("device") == "R"
      and _apply_fields({}).get("feature") == "routes")
check("...and does not duplicate them when the submission already had them",
      list(_apply_fields({"device": ["R"], "feature": ["routes"]}).items()).count(
          ("device", "R")) == 1)
check("...while still carrying the rest of the submission through, so Apply "
      "acts on what was previewed and not on a different plan",
      _apply_fields({"device": ["R"], "feature": ["routes"],
                     "fo_enabled": ["1"]}).get("fo_enabled") == "1")

check("the push flag is a hidden field rather than a value on the button, so "
      "submitting with the Enter key pushes too",
      '<input type="hidden" name="push" value="1">' in wed_detect)
_fo_on = web._wan_uplink_editor("R", cfgwan, "csrf", ifaces=[], failover_on=True)
_fo_off = web._wan_uplink_editor("R", cfgwan, "csrf", ifaces=[], failover_on=False)
check("the live failover state travels with the form -- routes_plan reads a "
      "missing fo_enabled as 'switch failover off', so a distance change "
      "would otherwise tear down the failover it was meant to adjust",
      'name="fo_enabled" value="1"' in _fo_on
      and 'name="fo_enabled" value=""' in _fo_off)

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

    def _fake_create(api_key, name):
        create_calls.append((api_key, name))
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
    check("create_profile is called with just the platform key and the "
          "device name — NEVER a clone id, which NextDNS rejects outright "
          "(HTTP 400 'extraneous parameter clone'); a template profile is "
          "copied across afterwards instead",
          create_calls == [("sekret-nextdns-key", "WebR1")])
    ds_after_enable = DevicesStore(wdb)
    raw_after_enable = ds_after_enable.raw("WebR1")
    ds_after_enable.close()
    check("the assigned profile id + enabled flag are persisted to the device",
          raw_after_enable.get("nextdns_enabled") is True
          and raw_after_enable.get("nextdns_profile_id") == "created-profile-1")

    box_after_enable = web._nextdns_box(
        "WebR1", build_device(raw_after_enable, DEF), csrf, True)
    check("_nextdns_box now shows the assigned profile, with everything "
          "managed in-app instead of a link out to NextDNS.io",
          "created-profile-1" in box_after_enable
          and "my.nextdns.io" not in box_after_enable)

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

    print("  diagnostics report surfaces the full DoH prerequisite state "
          "for a REACHABLE router (not just use-doh-server):")

    class _FakeRouterApi:
        def __init__(self, data):
            self.data = data

        def path(self, *segments):
            return self.data.get(segments, [])

    class _FakeDevice:
        def __init__(self, data):
            self.api = _FakeRouterApi(data)

        def reachable(self, timeout=None):
            return True

        def connect(self):
            return self.api

        def close(self):
            pass

    import mikromon.push as push_pkg
    orig_rw_device = push_pkg.rw_device
    push_pkg.rw_device = lambda cfg: _FakeDevice({
        ("system", "resource"): [{"version": "7.14.3"}],
        ("ip", "dns"): [{"use-doh-server": "https://dns.nextdns.io/created-profile-1",
                         "verify-doh-cert": "yes", "servers": "",
                         "allow-remote-requests": "false"}],
    })
    try:
        reachable_report = "\n".join(web._build_nextdns_diagnostics_lines(
            AuthStore(adb), wdb, DEF))
    finally:
        push_pkg.rw_device = orig_rw_device
    check("use-doh-server matches -> reported OK",
          "status: OK, matches the assigned profile." in reachable_report)
    check("verify-doh-cert value is shown",
          "verify-doh-cert: yes" in reachable_report)
    check("an empty bootstrap servers list is called out as empty, not "
          "silently omitted",
          "servers (bootstrap resolver" in reachable_report
          and "(empty)" in reachable_report)
    check("allow-remote-requests=false is shown plainly (this is the field "
          "that determines whether LAN clients — not just the router "
          "itself — actually use NextDNS)",
          "allow-remote-requests (must be true/yes for LAN clients, not "
          "just the router itself, to use this): false" in reachable_report)

    print("  diagnostics answer the question that actually matters: is it the "
          "ROUTER or the CLIENT that isn't using NextDNS?")
    # The router perfect, the clients bypassing it. This is the state that
    # produced "This device is not using NextDNS" on my.nextdns.io while every
    # line of the old report said OK -- it had nothing to say about the client
    # side at all.
    push_pkg.rw_device = lambda cfg: _FakeDevice({
        ("system", "resource"): [{"version": "7.14.3"}],
        ("ip", "dns"): [{"use-doh-server":
                         "https://dns.nextdns.io/created-profile-1",
                         "verify-doh-cert": "false",
                         "servers": "9.9.9.9,149.112.112.112",
                         "allow-remote-requests": "true"}],
        # no mikromon:dnsforce: rules, and DHCP hands out Google
        ("ip", "dhcp-server", "network"): [
            {"address": "192.168.88.0/24", "dns-server": "8.8.8.8,8.8.4.4"}],
        ("ip", "dns", "cache"): [],
    })
    try:
        bypass_report = "\n".join(web._build_nextdns_diagnostics_lines(
            AuthStore(adb), wdb, DEF))
    finally:
        push_pkg.rw_device = orig_rw_device
    check("a missing force-client-DNS redirect is called out -- without it a "
          "client with its own resolver never touches NextDNS, which the "
          "router-side settings alone can never reveal",
          "force-client-DNS NAT redirect: MISSING" in bypass_report)
    check("DHCP handing clients a PUBLIC resolver is shown, and flagged",
          "8.8.8.8" in bypass_report
          and "points at a PUBLIC resolver" in bypass_report)
    check("an empty router DNS cache is reported as nothing having resolved "
          "through it, rather than left unmentioned",
          "router's own DNS cache: 0 entries" in bypass_report
          and "EMPTY" in bypass_report)
    check("the report states plainly that my.nextdns.io's banner tests the "
          "BROWSER's machine, not the router -- the single most repeated "
          "source of confusion here",
          "MACHINE RUNNING THE BROWSER" in bypass_report
          and "Logs tab" in bypass_report)

    # The healthy case must NOT cry wolf.
    push_pkg.rw_device = lambda cfg: _FakeDevice({
        ("system", "resource"): [{"version": "7.14.3"}],
        ("ip", "dns"): [{"use-doh-server":
                         "https://dns.nextdns.io/created-profile-1",
                         "verify-doh-cert": "false",
                         "servers": "9.9.9.9,149.112.112.112",
                         "allow-remote-requests": "true"}],
        ("ip", "firewall", "nat"): [
            {"chain": "dstnat", "protocol": "udp", "dst-port": "53",
             "action": "redirect", "comment": "mikromon:dnsforce:udp"},
            {"chain": "dstnat", "protocol": "tcp", "dst-port": "53",
             "action": "redirect", "comment": "mikromon:dnsforce:tcp"}],
        ("ip", "dhcp-server", "network"): [
            {"address": "192.168.88.0/24", "dns-server": "192.168.88.1"}],
        ("ip", "dns", "cache"): [{"name": "example.com"}, {"name": "a.b"}],
    })
    try:
        healthy_report = "\n".join(web._build_nextdns_diagnostics_lines(
            AuthStore(adb), wdb, DEF))
    finally:
        push_pkg.rw_device = orig_rw_device
    check("a correctly-forced router reports the redirect as present, for "
          "both protocols, with no warning",
          "force-client-DNS NAT redirect: present and enabled" in healthy_report
          and "tcp" in healthy_report and "udp" in healthy_report)
    check("DHCP pointing clients at the router itself is not flagged as public",
          "points at a PUBLIC resolver" not in healthy_report)
    check("a populated DNS cache is reported as the resolver working",
          "the resolver is answering queries" in healthy_report)

    # Rules present but disabled is the same outcome as absent, and is easy to
    # miss by eye on the router.
    push_pkg.rw_device = lambda cfg: _FakeDevice({
        ("system", "resource"): [{"version": "7.14.3"}],
        ("ip", "dns"): [{"use-doh-server":
                         "https://dns.nextdns.io/created-profile-1",
                         "allow-remote-requests": "true"}],
        ("ip", "firewall", "nat"): [
            {"chain": "dstnat", "protocol": "udp", "dst-port": "53",
             "action": "redirect", "disabled": "true",
             "comment": "mikromon:dnsforce:udp"}],
    })
    try:
        disabled_report = "\n".join(web._build_nextdns_diagnostics_lines(
            AuthStore(adb), wdb, DEF))
    finally:
        push_pkg.rw_device = orig_rw_device
    check("a redirect rule that exists but is DISABLED is reported as such, "
          "not counted as present",
          "present but DISABLED" in disabled_report)

    print("  parental control save: a bad curated id must not silently "
          "block every future save forever:")
    section_calls = []

    def _fake_get_profile(api_key, pid):
        return {"parentalControl": {"categories": [], "services": []}}

    def _fake_update_section(api_key, pid, section, patch):
        section_calls.append(patch)
        # Simulate NextDNS rejecting the WHOLE categories array over one
        # bad id in it — confirmed live behavior: a single opaque 400
        # "invalid" with no indication of which entry caused it.
        if "categories" in patch and any(
                c["id"] == "gambling" and c["active"] for c in patch["categories"]):
            raise nextdns_mod.NextDnsError(
                'simulated: PATCH /parentalControl failed: HTTP 400 — '
                '{"errors":[{"code":"invalid"}]}')

    orig_get_profile = nextdns_mod.get_profile
    orig_update_section = nextdns_mod.update_section
    nextdns_mod.get_profile = _fake_get_profile
    nextdns_mod.update_section = _fake_update_section
    try:
        # Bug as reported: checking the (simulated-bad) "gambling" category
        # must fail ONLY that save, not the booleans/services alongside it.
        section_calls.clear()
        st, loc = post_loc(admin, "/device/nextdns-parental",
                           {"csrf": csrf, "device": "WebR1",
                            "cat_gambling": "1", "b_safeSearch": "1"})
        check("a rejected category patch is reported, but doesn't stop the "
              "booleans and services patches from being attempted and "
              "succeeding (three independent PATCH calls, not one "
              "all-or-nothing one)",
              "categories: FAILED" in loc and "booleans: saved" in loc
              and "services: saved" in loc)

        # The actual regression: an UNCHECKED curated category must never be
        # submitted at all — confirmed live, including every curated id
        # unconditionally on every save meant one bad id (whatever it was)
        # permanently blocked ALL future saves, even ones that never
        # touched it.
        section_calls.clear()
        st, loc = post_loc(admin, "/device/nextdns-parental",
                           {"csrf": csrf, "device": "WebR1",
                            "b_safeSearch": "1"})
        cat_patch = next(p for p in section_calls if "categories" in p)
        check("a save that never checks the bad curated category doesn't "
              "include it at all, and succeeds",
              cat_patch["categories"] == [] and "categories: saved" in loc
              and "FAILED" not in loc)

        # Checking a DIFFERENT (good) category sends only that one id, not
        # the entire curated catalog.
        section_calls.clear()
        st, loc = post_loc(admin, "/device/nextdns-parental",
                           {"csrf": csrf, "device": "WebR1",
                            "cat_piracy": "1"})
        cat_patch = next(p for p in section_calls if "categories" in p)
        check("checking one category sends only that one id, not the "
              "whole curated list",
              cat_patch["categories"] == [{"id": "piracy", "active": True}])
    finally:
        nextdns_mod.get_profile = orig_get_profile
        nextdns_mod.update_section = orig_update_section

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
    print("  \"why is it unreachable\" separates the three things that used "
          "to look identical:")
    import socket as _sock
    import threading as _thr

    # A router answering on Winbox but not on the API port: reachable, with
    # the API specifically shut. Confirmed live as indistinguishable from a
    # dead router before this existed.
    _srv = _sock.socket()
    _srv.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
    _srv.bind(("127.0.0.1", 0))
    _open_port = _srv.getsockname()[1]
    _srv.listen(5)
    _thr.Thread(target=lambda: [_srv.accept() for _ in range(4)],
                daemon=True).start()
    try:
        orig_ports = web._REACH_PORTS
        web._REACH_PORTS = [(_open_port, "Winbox")]
        try:
            reachable = web._why_unreachable("127.0.0.1", 1, timeout=0.4)
        finally:
            web._REACH_PORTS = orig_ports
    finally:
        _srv.close()
    joined = "\n".join(reachable)
    check("something answering on ANY management port proves the tunnel is "
          "up, so the verdict points at the API service rather than at power "
          "or WireGuard",
          "router IS reachable over the tunnel" in joined
          and "NOT a tunnel or power problem" in joined)
    check("...and it names which port answered, so the finding is checkable "
          "rather than asserted", f"Winbox:{_open_port}" in joined)

    # Nothing answering anywhere: genuinely off, or the tunnel is down.
    orig_ports = web._REACH_PORTS
    web._REACH_PORTS = [(9, "discard")]
    try:
        silent = "\n".join(web._why_unreachable("127.0.0.1", 9, timeout=0.4))
    finally:
        web._REACH_PORTS = orig_ports
    check("nothing answering anywhere gives the opposite verdict — off, or "
          "the tunnel is down",
          "either off, or its WireGuard tunnel" in silent)
    check("...and says plainly that logging in from the router's own LAN "
          "does not rule the tunnel out, which is exactly the wrong "
          "conclusion to draw",
          "does NOT rule the tunnel out" in silent)

    print("  one physical router registered under two names is surfaced:")
    import json as _json
    import tempfile as _tf

    _d = _tf.mkdtemp()
    _st = os.path.join(_d, "dupstate.json")
    _now = time.time()
    _json.dump({"devices": {
        "ECA Richards Bay": {
            "facts": {"serial": "HFF09XYZ", "identity": "ECA Richardsbay",
                      "updated": _now},
            "conditions": {"reachability": {"status": "ok"},
                           "api_error": {"status": "problem"}}},
        "ECA Richardsbay": {
            "facts": {"serial": "HFF09XYZ", "identity": "ECA Richardsbay",
                      "updated": _now},
            "conditions": {"reachability": {"status": "problem"}}},
        "Unrelated": {"facts": {"serial": "OTHER123", "identity": "Unrelated",
                                "updated": _now}, "conditions": {}},
    }}, open(_st, "w"))
    _rep = web._build_diagnostics_report(None, None, _st, None, DEF)
    check("two entries sharing a SERIAL are reported as one router registered "
          "twice — each carries its own tunnel IP, WireGuard key and login, "
          "so provisioning one silently invalidates the other's credentials",
          "SAME SERIAL HFF09XYZ" in _rep
          and "ECA Richards Bay, ECA Richardsbay" in _rep)
    check("...and the consequence is spelled out, not left to be inferred",
          "no longer matches the" in _rep)
    check("a router with a serial of its own is NOT dragged into it",
          "OTHER123" not in _rep)

    # No duplicates at all must not emit the section.
    _st2 = os.path.join(_d, "clean.json")
    _json.dump({"devices": {
        "A": {"facts": {"serial": "S1", "identity": "A", "updated": _now},
              "conditions": {}},
        "B": {"facts": {"serial": "S2", "identity": "B", "updated": _now},
              "conditions": {}},
    }}, open(_st2, "w"))
    check("a fleet with no duplicates gets no section at all, rather than an "
          "empty heading to scroll past",
          "Possible duplicate devices" not in
          web._build_diagnostics_report(None, None, _st2, None, DEF))

    print("  a passing connection test clears a stale offline state:")
    import json as _js
    import tempfile as _tf2

    _sd = _tf2.mkdtemp()
    _sf = os.path.join(_sd, "state.json")

    def _put_reach(status):
        _js.dump({"devices": {"R": {"conditions": {"reachability": {
            "status": status, "since": 1.0,
            "pending": "ok", "pending_n": 1}}}}}, open(_sf, "w"))

    def _reach():
        return _js.load(open(_sf))["devices"]["R"]["conditions"]["reachability"]

    _put_reach("problem")
    check("a device still marked offline is cleared once a test actually "
          "reaches it — being told SUCCESS while the same screen says "
          "offline is what stops a dashboard being believed",
          web._clear_stale_offline(_sf, "R") is True
          and _reach()["status"] == "ok")
    check("...and the debounce counters are reset with it, so the next poll "
          "starts from a clean state rather than a half-counted flip",
          _reach()["pending"] is None and _reach()["pending_n"] == 0)

    _put_reach("ok")
    check("a device already healthy is left alone — nothing to clear",
          web._clear_stale_offline(_sf, "R") is False
          and _reach()["status"] == "ok")
    check("it only ever CLEARS, never marks a device down, so a test can "
          "never manufacture a state it did not observe",
          web._clear_stale_offline(_sf, "nosuchdevice") is False)
    check("no state file configured is a quiet no-op, not an error that "
          "would take the test result down with it",
          web._clear_stale_offline("", "R") is False)

    print("  a single dropped probe must not read as offline:")

    class _UpStore:
        def __init__(self, up): self.up = up
        def latest(self, _name):
            return ({} if self.up is None
                    else {("up", ""): {"value": self.up, "ts": 0}})

    def _up_of(up_sample, reach_status):
        conds = ({} if reach_status is None
                 else {"reachability": {"status": reach_status}})
        st = {"devices": {"R": {"conditions": conds, "facts": {"model": "x"}}}}
        return web._device_view(_UpStore(up_sample), st, "R")["up"]

    check("a probe that failed ONCE, while the debounce still says ok, reads "
          "as ONLINE — the engine needs two consecutive failures before it "
          "calls a device down, and the dashboard has to agree with the "
          "alerting rather than flip on one lost packet",
          _up_of(0.0, "ok") == 1)
    check("a device the debounce has actually confirmed down reads as offline",
          _up_of(0.0, "problem") == 0)
    check("the confirmed verdict wins over a stale sample that still says up "
          "— one source of truth, and it is the debounced one",
          _up_of(1.0, "problem") == 0)
    check("a healthy device is unaffected", _up_of(1.0, "ok") == 1)
    check("with the reachability check switched off there is no condition to "
          "consult, so the raw sample is still used",
          _up_of(0.0, None) == 0 and _up_of(1.0, None) == 1)

    print("  dashboard fleet traffic + firmware blocks:")

    def _tdev(n, up, tp, facts):
        return {"device": n, "up": up, "throughput": tp, "facts": facts,
                "problems": [], "_conditions": {}, "metrics": {},
                "wan_health": "full"}

    _tdevs = [
        _tdev("Busy", 1, {"live": {"rx_bps": 20e6, "tx_bps": 5e6},
                          "renamed-away": {"rx_bps": 500e6, "tx_bps": 0}},
              {"version": "7.12.1 (stable)", "update_available": True,
               "wan_traffic_interfaces": ["live"]}),
        _tdev("Quiet", 1, {"live": {"rx_bps": 1e6, "tx_bps": 1e6}},
              {"version": "7.23.2 (stable)",
               "wan_traffic_interfaces": ["live"]}),
        _tdev("Gone", 0, {"live": {"rx_bps": 900e6, "tx_bps": 900e6}},
              {"version": "7.20.7 (long-term)", "update_available": True,
               "wan_traffic_interfaces": ["live"]}),
    ]
    _traffic = web._fleet_traffic_chip(_tdevs)
    check("an interface no longer being sampled is left out of the fleet "
          "total — throughput keeps the last value ever seen per label, so a "
          "renamed link would otherwise contribute its final reading forever",
          "500" not in _traffic)
    check("an OFFLINE router contributes nothing — its last reading is what "
          "it was carrying before it went, and counting it would show "
          "traffic for a site that is passing none",
          "900" not in _traffic)
    check("the busiest site is named and linked, so the number leads "
          "somewhere", "Busy" in _traffic and "/device?name=Busy" in _traffic)
    check("a fleet with no samples yet says so rather than claiming 0",
          "No throughput samples yet" in web._fleet_traffic_chip(
              [_tdev("New", 1, {}, {})]))

    _fw = web._firmware_chip(_tdevs)
    check("routers with an update waiting are counted — collected every poll "
          "and, until now, only ever a column on the Devices page",
          ">2<" in _fw and "Updates available" in _fw)
    check("the oldest version in the fleet is named, comparing numerically "
          "rather than as text so 7.9 does not look newer than 7.12",
          "7.12.1" in _fw and "Busy" in _fw)
    check("...and the channel suffix does not confuse that comparison",
          web._version_key("7.12.1 (stable)")
          < web._version_key("7.20.7 (long-term)"))
    check("an unparseable version sorts NEWEST, so it is never wrongly "
          "reported as the oldest thing in the fleet",
          web._version_key("") > web._version_key("7.23.2"))
    check("a fully patched fleet says so instead of showing a bare 0",
          "All up to date" in web._firmware_chip(
              [_tdev("OK", 1, {}, {"version": "7.23.2"})]))
    check("with no versions recorded it says that, rather than picking an "
          "oldest from nothing",
          "No versions recorded" in web._firmware_chip(
              [_tdev("New", 1, {}, {})]))

    print("  dashboard suggestions: collapsed, per-device, dismissable:")
    _now = time.time()

    def _sdev(n, up, probs, conds, facts=None):
        return {"device": n, "up": up, "problems": probs, "_conditions": conds,
                "facts": facts or {}, "metrics": {}, "throughput": {},
                "wan_health": "full"}

    _devs = [
        _sdev("Down One", 0,
              [{"key": "reachability", "since": _now - 86400 * 4,
                "level": "problem"}],
              {"reachability": {"title": "Device UNREACHABLE"}}),
        _sdev("Busy Box", 1,
              [{"key": "storage", "since": _now - 86400 * 14, "level": "crit"},
               {"key": "iface_down:ether3-voip", "since": _now - 3600,
                "level": "problem"}],
              {"storage": {}, "iface_down:ether3-voip":
               {"title": "Interface ether3-voip link DOWN"}}),
        _sdev("Old Firmware", 1, [], {},
              {"update_available": True, "version": "7.12.1"}),
    ]
    _panel = web._suggestion_panel(_devs, csrf=csrf)

    check("the panel is CLOSED on load — the count is the button, and a list "
          "this long is scrolled past when it is always on screen",
          'id="sgPanel" hidden' in _panel)
    check("the Suggestions chip is a real button that opens it",
          "chip-btn" in web._stat_chip(3, "Suggestions", "info",
                                       onclick="mmSgToggle()")
          and "mmSgToggle()" in web._stat_chip(3, "S", "", onclick="mmSgToggle()"))
    check("...and an ordinary counter chip stays a plain block, not a button",
          "chip-btn" not in web._stat_chip(5, "Devices"))

    check("opening it offers one filter per router that actually has "
          "suggestions, plus All — so you pick whose list to read rather "
          "than reading everyone's",
          'data-sgdev=""' in _panel
          and 'data-sgdev="Down One"' in _panel
          and 'data-sgdev="Busy Box"' in _panel)
    check("every row is tagged with its device so filtering happens in the "
          "browser, without a reload that would lose the rest of the page",
          _panel.count('data-sgrow=') == 4)

    check("each suggestion can be ignored, scoped to that exact condition on "
          "that one router",
          _panel.count(">Ignore<") == 4
          and 'name="key" value="iface_down:ether3-voip"' in _panel
          and 'action="/dashboard/suggestion"' in _panel)

    _ignored = web._suggestion_panel(
        _devs, csrf=csrf,
        ignored_by_device={"Busy Box": ["iface_down:ether3-voip"]})
    check("an ignored suggestion drops out of the list",
          "ether3-voip" not in _ignored.split("sg-ignored")[0])
    check("...but only that one — the other suggestion on the SAME router "
          "stays, so dismissing a port that is dark on purpose does not "
          "silence the port beside it",
          "Storage is filling up" in _ignored)
    check("...and it is listed as ignored with a way to bring it back, "
          "rather than vanishing with no trace",
          "1 ignored suggestion(s)" in _ignored and ">Restore<" in _ignored)

    check("ignoring is scoped per DEVICE: the same key ignored on one router "
          "does not hide it on another",
          "Device UNREACHABLE" in web._suggestion_panel(
              _devs, csrf=csrf,
              ignored_by_device={"Busy Box": ["reachability"]}))

    _items = web._suggestion_items(_devs)
    check("offline routers come first, then oldest-first, with items that "
          "carry no timestamp last — an update notice must not outrank a "
          "fortnight-old fault",
          [i["device"] for i in _items][0] == "Down One"
          and [i["key"] for i in _items][-1] == "update")

    check("without a csrf token no Ignore button is rendered at all, rather "
          "than one that would be rejected on submit",
          ">Ignore<" not in web._suggestion_panel(_devs, csrf=""))
    check("a healthy fleet says so plainly instead of an empty box",
          "Nothing needs attention" in web._suggestion_panel(
              [_sdev("Fine", 1, [], {})], csrf=csrf))

    # The chip is the count of what the panel will actually show. A chip
    # reading 10 above a list of 8 looks broken, and makes ignoring something
    # feel like it did not take.
    for _ig, _want in (({}, 4),
                       ({"Busy Box": ["iface_down:ether3-voip"]}, 3),
                       ({"Busy Box": ["iface_down:ether3-voip", "storage"]}, 2)):
        _it = web._suggestion_items(_devs, _ig)
        _pn = web._suggestion_panel(_devs, csrf=csrf, ignored_by_device=_ig,
                                    items=_it)
        check(f"with {sum(len(v) for v in _ig.values())} ignored, the count "
              f"is {_want} and the panel renders exactly that many rows — "
              f"the number and the list come from one place, so they cannot "
              f"disagree",
              len(_it) == _want and _pn.count("data-sgrow=") == _want)

    check("ignoring something reduces the number on the chip — the raw "
          "condition total keeps counting things the dashboard has been told "
          "to hide, which is why it is no longer what gets displayed",
          len(web._suggestion_items(_devs, {"Busy Box": ["storage"]}))
          < len(web._suggestion_items(_devs, {})))

    print("  dashboard fleet strip (latency + what is at risk):")

    def _fdev(name, up, lat):
        return {"device": name, "up": up, "throughput": {}, "facts": {},
                "problems": [],
                "metrics": {"latency_ms": lat} if lat is not None else {}}

    healthy = web._fleet_summary([_fdev("R1", 1, 12.4), _fdev("R2", 1, 31.0),
                                  _fdev("R3", 1, 8.2)])
    check("the fleet average is the mean round trip across online routers",
          healthy["latency_avg"] == 17.2 and healthy["latency_worst"] == 31.0)
    check("a healthy fleet still says so — a strip that only appears with bad "
          "news is one nobody learns to read, and its silence cannot be told "
          "apart from not measuring",
          "No units at risk" in web._fleet_status_strip(healthy))

    # The important one: an unreachable router has no latency to contribute.
    with_down = web._fleet_summary([_fdev("R1", 1, 12.4),
                                    _fdev("Howler", 0, None)])
    check("an OFFLINE router does not drag the average down — counting it as "
          "zero would make the fleet look faster at exactly the moment "
          "something is wrong", with_down["latency_avg"] == 12.4)
    check("...and it is named as at risk instead",
          with_down["down"] == ["Howler"]
          and "1 offline: Howler" in web._fleet_status_strip(with_down))

    slow = web._fleet_summary([_fdev("R1", 1, 20.0), _fdev("Vryheid", 1, 410.0)])
    check("a router past the latency threshold is called out by name",
          slow["slow"] == ["Vryheid"]
          and "Vryheid" in web._fleet_status_strip(slow))
    check("...while routers under it are not",
          "R1" not in web._fleet_status_strip(slow))

    both = web._fleet_summary([_fdev("Howler", 0, None),
                               _fdev("Vryheid", 1, 410.0), _fdev("R1", 1, 20.0)])
    strip_both = web._fleet_status_strip(both)
    check("offline and slow are reported together, at the more serious of the "
          "two severities",
          "1 offline" in strip_both and "1 slow" in strip_both
          and 'fs-risk crit' in strip_both)

    none_yet = web._fleet_summary([_fdev("R1", 1, None)])
    check("a fleet with no readings yet says exactly that, rather than "
          "showing a confident 0 ms",
          none_yet["latency_avg"] is None
          and "no readings yet" in web._fleet_status_strip(none_yet))

    check("a device name is escaped where it goes into the strip",
          "&lt;b&gt;" in web._fleet_status_strip(
              web._fleet_summary([_fdev("<b>x", 0, None)])))

    print("  the DNS tab still renders with NextDNS ENABLED:")
    # Regression guard. The panels the tab assembles are only reachable once
    # NextDNS is on, so a helper deleted in a refactor stayed invisible until
    # a customer enabled it and the whole tab broke -- which is exactly what
    # happened when the per-uplink work was reverted and took the router-test
    # button out with it. Rendering every panel here fails loudly instead.
    _nd_cfg = build_device({"name": "WebR1", "host": "10.0.0.1",
                            "nextdns_enabled": True,
                            "nextdns_profile_id": "abc123"}, DEF)
    try:
        _tab = (web._nextdns_box("WebR1", _nd_cfg, csrf, True)
                + web._nextdns_test_box("WebR1", csrf)
                + web._nextdns_list_box("WebR1", csrf, "Blocked", "denylist", [])
                + web._nextdns_security_box("WebR1", csrf, {})
                + web._nextdns_parental_box("WebR1", csrf, {})
                + web._nextdns_privacy_box("WebR1", csrf, {}))
        _err = ""
    except Exception as exc:  # noqa: BLE001
        _tab, _err = "", f"{type(exc).__name__}: {exc}"
    check("every panel the DNS tab assembles when NextDNS is enabled still "
          "exists and renders — a missing one takes the whole tab down, and "
          "only for customers who have it switched on",
          not _err and len(_tab) > 1000)
    check("the router-test button is among them, pointing at its handler",
          "/device/nextdns-test" in _tab)
    check("the probe domain the test handler blocks is defined — it is "
          "referenced from the handler, so losing it is a NameError nobody "
          "sees until the button is pressed",
          getattr(web, "_NEXTDNS_PROBE_DOMAIN", "") == "example.org")
    check("...and the report renderer the handler returns through is present",
          callable(getattr(web, "_nextdns_test_report_html", None)))

    # --- the retired per-uplink profiles get cleaned up ------------------
    # A router provisioned while mikromon briefly ran one profile per WAN
    # uplink still carries the extra profile ids. They refer to real profiles
    # on the NextDNS account, so dropping the field without deleting them
    # would strand them there with nothing left that knows their ids.
    print("  leftover per-uplink profiles are deleted, not stranded:")
    ds_legacy = DevicesStore(wdb)
    raw_legacy = ds_legacy.raw("WebR1")
    raw_legacy["nextdns_enabled"] = True
    raw_legacy["nextdns_profile_id"] = "main-x"
    raw_legacy["nextdns_wan_profiles"] = {"1": "backup-x", "2": "voip-x"}
    ds_legacy.upsert(raw_legacy, DEF, org_id=None)
    ds_legacy.close()

    cfg_legacy = build_device(raw_legacy, DEF)
    check("nextdns_all_profile_ids still finds the leftovers, which is the "
          "only reason the field is kept at all",
          cfg_legacy.nextdns_all_profile_ids()
          == ["main-x", "backup-x", "voip-x"])

    deleted_legacy = []

    def _fake_delete_legacy(api_key, profile_id):
        deleted_legacy.append(profile_id)

    orig_delete = nextdns_mod.delete_profile
    nextdns_mod.delete_profile = _fake_delete_legacy
    try:
        notes = web._nextdns_cleanup_legacy("k", raw_legacy)
    finally:
        nextdns_mod.delete_profile = orig_delete
    check("every leftover profile is deleted from NextDNS",
          sorted(deleted_legacy) == ["backup-x", "voip-x"])
    check("...the main profile is NOT — it is the one the router uses",
          "main-x" not in deleted_legacy)
    check("...and the field is emptied so it never runs twice",
          raw_legacy.get("nextdns_wan_profiles") == {})
    check("what happened is reported back rather than done silently",
          len(notes) == 2 and all("backup-x" in n or "voip-x" in n
                                  for n in notes))

    def _delete_fails(api_key, profile_id):
        raise nextdns_mod.NextDnsError("simulated: already gone")

    raw_legacy["nextdns_wan_profiles"] = {"1": "gone-x"}
    nextdns_mod.delete_profile = _delete_fails
    try:
        notes = web._nextdns_cleanup_legacy("k", raw_legacy)
    finally:
        nextdns_mod.delete_profile = orig_delete
    check("a profile that cannot be deleted still gets let go of locally, and "
          "says so — a device that will not release a stale id is worse than "
          "an orphan on the account",
          raw_legacy.get("nextdns_wan_profiles") == {}
          and any("by hand" in n for n in notes))

    check("a router that never had them is a no-op",
          web._nextdns_cleanup_legacy("k", {"nextdns_wan_profiles": {}}) == [])

    # Put WebR1 back the way the rest of the suite expects to find it.
    ds_restore = DevicesStore(wdb)
    raw_restore = ds_restore.raw("WebR1")
    raw_restore["nextdns_enabled"] = False
    raw_restore["nextdns_profile_id"] = ""
    raw_restore["nextdns_wan_profiles"] = {}
    ds_restore.upsert(raw_restore, DEF, org_id=None)
    ds_restore.close()

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
    # The handshake self-check only exists when a tunnel is actually being
    # set up, so it is exercised against a script generated WITH hub keys --
    # the POST above deliberately has no hub configured.
    _tunnel_script = web._provision_script(
        "ECA Richards Bay", {"host": "10.10.63.177"}, "mkmonitor", "pw",
        hub_ip="38.54.63.107", hub_port="51820", hub_pubkey="HUBKEY=",
        wg_priv="PRIVKEY=", tunnel_ip="10.10.63.177", subnet="10.10.0.0/16")
    check("the script ends by reporting whether the tunnel actually came up "
          "-- pasting it used to be silent about that, so a router whose "
          "config is perfect but whose link blocks the tunnel looked exactly "
          "like a success until the dashboard called it unreachable hours "
          "later",
          "waiting 6s for the WireGuard handshake" in _tunnel_script
          and "last-handshake" in _tunnel_script)
    check("...and says what a blank handshake means, since the router's own "
          "config is not where the fault lies in that case",
          "not getting out" in _tunnel_script
          and "UDP" in _tunnel_script
          and "38.54.63.107:51820" in _tunnel_script)
    check("the self-check is emitted only when a tunnel is being set up, not "
          "on a script that has no WireGuard section to report on",
          "waiting 6s for the WireGuard handshake" not in body)

    _keyed = web._provision_script(
        "R", {"host": "1.1.1.1"}, "mkmonitor", "pw",
        hub_ip="38.54.63.107", hub_port="51820", hub_pubkey="HUB=",
        wg_priv="PRIV=", wg_pub="EXPECTEDPUBKEY=",
        tunnel_ip="10.10.63.177", subnet="10.10.0.0/16")
    check("the tunnel is pinned to an MTU every path can carry, on creation "
          "AND on re-provision -- RouterOS defaults WireGuard to 1420, which "
          "assumes 1500 underneath; on PPPoE/LTE/CGNAT the excess is dropped "
          "in SILENCE because WireGuard sets DF, so small exchanges (login, "
          "port probe, one-row resource read) succeed while the first larger "
          "reply vanishes",
          _tunnel_script.count(f"mtu={web._WG_TUNNEL_MTU}") == 2)
    check("...and that MTU is the value IPv6 guarantees every path carries, "
          "so it needs no knowledge of what is underneath",
          web._WG_TUNNEL_MTU == 1280)

    check("the script compares the router's own WireGuard key against the one "
          "the hub was given -- a mismatch makes the hub discard every "
          "handshake in silence, which from the router is indistinguishable "
          "from the packets never arriving (rx stays 0 while tx climbs)",
          "EXPECTEDPUBKEY=" in _keyed
          and "KEY MISMATCH" in _keyed
          and "public-key" in _keyed)
    check("...and it runs BEFORE the handshake wait, so a key problem is not "
          "misread as a blocked link",
          _keyed.index("KEY MISMATCH")
          < _keyed.index("waiting 6s for the WireGuard handshake"))
    check("a script generated without a registered public key omits the "
          "comparison rather than checking against an empty string",
          ":local mmwant" not in web._provision_script(
              "R", {"host": "1.1.1.1"}, "mkmonitor", "pw",
              hub_ip="38.54.63.107", hub_port="51820", hub_pubkey="HUB=",
              wg_priv="PRIV=", tunnel_ip="10.10.63.177",
              subnet="10.10.0.0/16"))
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
    # A bare "forbidden" body named neither the router nor the reason, and
    # four separate checks all rendered that same one word -- a screenshot of
    # it could not be traced back to any of them.
    st, dbody = post(bob, "/device/wan",
                     {"csrf": bcsrf2, "device": "R1", "push": "1"})
    check("a refused device action says WHICH router and WHY, instead of the "
          "single word 'forbidden' that four different checks all produced",
          st == 403 and "R1" in dbody
          and ("not allowed to manage" in dbody
               or "different company" in dbody))
finally:
    srv.shutdown()
    srv.server_close()

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL DEVICE TESTS PASSED")
