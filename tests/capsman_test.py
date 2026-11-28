"""CAPsMAN: many APs, three SSIDs, live clients, one button for the fleet.

This suite is deliberately offline. A fake RouterOS answers fetch/execute the
way librouteros does (every value a string, `.id` on every row), so the tests
can proveVLANs, isolation, blocked clients and rollback without a single
physical AP. Two fakes are used: RouterOS 7's /interface/wifi/* and the older
/caps-man/* menus; both must end up in the same state for the same inputs.

Run:  .venv/bin/python tests/capsman_test.py
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import threading
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import capsman as C  # noqa: E402
from mikromon.push import Pusher  # noqa: E402
from mikromon.push.api import PushError  # noqa: E402
from mikromon.push.plan import Plan  # noqa: E402

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


def refuses(fn, *a, **kw):
    try:
        fn(*a, **kw)
        return False, ""
    except C.CapsmanError as exc:
        return True, str(exc)


def clone(state):
    return {tuple(path): [dict(row) for row in rows]
            for path, rows in state.items()}


TMP = tempfile.mkdtemp(prefix="capsman-")
store = C.CapsmanStore(os.path.join(TMP, "capsman.db"))

GUEST = {"name": "guest-net", "ssid": "Acme Guest", "purpose": "guest",
         "vlan_id": 20, "passphrase": "guest-pass-2026", "down_mbps": 10,
         "up_mbps": 5}
STAFF = {"name": "staff-net", "ssid": "Acme Staff", "purpose": "staff",
         "vlan_id": 30, "passphrase": "staff-pass-2026"}
IOT = {"name": "iot-net", "ssid": "Acme IoT", "purpose": "iot",
       "vlan_id": 40, "security_mode": "wpa2-wpa3",
       "passphrase": "iot-pass-2026", "band": "2ghz"}

print("SSIDs: three purposes, sealed secrets, strict validation")

guest = store.upsert_ssid(1, GUEST)
check("a guest SSID has an id and safe defaults",
      guest["id"] > 0 and guest["security_mode"] == "wpa2-psk"
      and guest["client_isolation"] == 1 and guest["band"] == "dual"
      and guest["bridge"] == "bridge" and guest["enabled"] == 1
      and guest["updated_at"] > 0)
staff = store.upsert_ssid(1, STAFF)
iot = store.upsert_ssid(1, IOT)
check("staff keeps client-to-client traffic by default, guests and IoT do not",
      staff["client_isolation"] == 0 and iot["client_isolation"] == 1
      and iot["security_mode"] == "wpa2-wpa3")
check("a passphrase comes back in plain form for provisioning",
      guest["passphrase"] == "guest-pass-2026")

raw = sqlite3.connect(os.path.join(TMP, "capsman.db")).execute(
    "SELECT passphrase FROM capsman_ssids WHERE id=?", (guest["id"],)).fetchone()
check("...but is sealed in SQLite, so a copied database leaks no Wi-Fi key",
      str(raw[0]).startswith("enc1:"))

same = store.upsert_ssid(1, {"name": "guest-net", "ssid": "Guest (new)"})
check("a partial upsert by name updates rather than colliding with itself",
      same["id"] == guest["id"] and same["ssid"] == "Guest (new)"
      and same["vlan_id"] == 20 and same["purpose"] == "guest"
      and same["passphrase"] == "guest-pass-2026")
by_id = store.upsert_ssid(1, {"id": staff["id"], "ssid": "Acme Staff",
                              "org_id": 2, "passphrase": "staff-pass-2026"})
check("an explicit id updates only that SSID, and a forged org_id is ignored",
      by_id["id"] == staff["id"] and by_id["org_id"] == 1
      and store.list_ssids(2) == [])

count = len(store.list_ssids(1))
bad = [
    ("unsafe name", dict(GUEST, name="Bad Name!")),
    ("empty name", dict(GUEST, name="")),
    ("empty ssid", dict(GUEST, name="empty-ssid", ssid="")),
    ("long ssid", dict(GUEST, name="long-ssid", ssid="x" * 33)),
    ("unknown purpose", dict(GUEST, name="other-purpose", purpose="sales")),
    ("vlan 1", dict(GUEST, name="vlan-one", vlan_id=1)),
    ("vlan 4095", dict(GUEST, name="vlan-max", vlan_id=4095)),
    ("unknown security", dict(GUEST, name="wep-ssid",
                              security_mode="wep")),
    ("short passphrase", dict(GUEST, name="short-key",
                              passphrase="short")),
    ("long passphrase", dict(GUEST, name="long-key",
                             passphrase="x" * 64)),
    ("unknown band", dict(GUEST, name="six-ghz", band="6ghz")),
    ("negative speed", dict(GUEST, name="neg-speed", down_mbps=-1)),
    ("huge speed", dict(GUEST, name="huge-speed", up_mbps=10001)),
]
for label, data in bad:
    refused, why = refuses(store.upsert_ssid, 1, data)
    check(f"refuses {label} with a reason", refused and len(why) > 8)
check("no rejected SSID left a row behind", len(store.list_ssids(1)) == count)
check("63 characters is a usable WPA passphrase",
      store.upsert_ssid(1, dict(GUEST, name="long-ok",
                                passphrase="p" * 63))["passphrase"]
      == "p" * 63)
open_ssid = store.upsert_ssid(1, {"name": "open-net", "ssid": "Open",
                                  "purpose": "guest", "security_mode": "open",
                                  "passphrase": "ignored"})
check("an open network stores no key at all", open_ssid["passphrase"] == "")

other = store.upsert_ssid(2, GUEST)
check("the same profile name is allowed in another organisation",
      other["id"] != guest["id"] and other["org_id"] == 2)
check("another org cannot list, update or delete this org's SSIDs",
      all(r["id"] != guest["id"] for r in store.list_ssids(2))
      and refuses(store.upsert_ssid, 2, {"id": guest["id"],
                                        "ssid": "Stolen"})[0]
      and store.delete_ssid(2, guest["id"]) is False)
check("the owning org can delete its SSID",
      store.delete_ssid(1, open_ssid["id"]) is True
      and store.delete_ssid(1, open_ssid["id"]) is False)

print("\nControllers: driver choice and sync state are per organisation")

r1 = store.set_controller(1, "R1")
check("a controller starts enabled on the automatic driver",
      r1["device"] == "R1" and r1["enabled"] == 1 and r1["driver"] == "auto"
      and r1["last_sync_at"] is None and r1["last_sync_status"] == "")
store.set_controller(1, "R2", enabled=False, driver="legacy")
check("a disabled controller and its driver choice are remembered",
      [c["driver"] for c in store.list_controllers(1) if c["device"] == "R2"]
      == ["legacy"] and store.list_controllers(2) == [])
check("updating a controller does not erase its sync history",
      store.set_controller(1, "R1", driver="wifi")["driver"] == "wifi"
      and store.set_controller(1, "R1")["last_sync_at"] is None)
check("bad driver and device names are refused",
      refuses(store.set_controller, 1, "R3", driver="openwrt")[0]
      and refuses(store.set_controller, 1, "bad/name")[0])
sync_at = store.record_sync(1, "R1", "ok", "12 changes")
check("a sync result is recorded with a timestamp",
      sync_at is not None and sync_at["last_sync_status"] == "ok"
      and sync_at["last_sync_summary"] == "12 changes"
      and sync_at["last_sync_at"] > 0)
check("a sync result cannot be written for another org's controller",
      store.record_sync(2, "R1", "ok", "forged") is None
      and store.list_controllers(1)[0]["last_sync_summary"] == "12 changes")
check("an unknown status is refused",
      refuses(store.record_sync, 1, "R1", "maybe", "?")[0])

print("\nBlocked clients: uppercase MACs, unique per org")

blocked = store.block_mac(1, "aa:bb:cc:dd:ee:99", reason="rogue",
                          blocked_by="admin")
check("a MAC is normalised and the reason is kept",
      blocked["mac"] == "AA:BB:CC:DD:EE:99" and blocked["reason"] == "rogue"
      and blocked["blocked_by"] == "admin" and blocked["created_at"] > 0)
check("blocking the same client twice updates the same row",
      store.block_mac(1, "AA-BB-CC-DD-EE-99", reason="still rogue")["id"]
      == blocked["id"] and len(store.list_blocked_macs(1)) == 1)
for mac in ("AA:BB:CC:DD:EE", "GG:BB:CC:DD:EE:99",
            "AA-BB:CC-DD-EE-99", ""):
    check(f"refuses the malformed MAC {mac!r}",
          refuses(store.block_mac, 1, mac)[0])
check("another org cannot see or unblock this MAC",
      store.list_blocked_macs(2) == []
      and store.unblock_mac(2, blocked["mac"]) is False)
check("the owning org can unblock, in any MAC spelling",
      store.unblock_mac(1, "aa-bb-cc-dd-ee-99") is True
      and store.unblock_mac(1, blocked["mac"]) is False)
store.block_mac(1, "DE:AD:BE:EF:00:01", reason="known attacker")

errors = []


def write_blocks(index):
    try:
        store.block_mac(1, f"02:00:00:00:00:{index:02X}")
    except Exception as exc:  # noqa: BLE001
        errors.append(exc)


threads = [threading.Thread(target=write_blocks, args=(i,)) for i in range(8)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
check("eight concurrent writes do not trip 'database is locked'",
      not errors and len(store.list_blocked_macs(1)) >= 9)


class FakeApi:
    """RouterOS menus in memory, with the fetch/execute shape Pusher expects."""

    def __init__(self, state=None, fail_desc=None, fail_paths=()):
        # Keep the caller's rows: apply() must be visible to the test that
        # builds the next plan, exactly as a real router would be.
        self.state = state if state is not None else {}
        self.fail_desc = fail_desc
        self.fail_paths = {tuple(path) for path in fail_paths}
        self.executed = []
        self.closed = False
        self._n = 100

    def fetch(self, path):
        path = tuple(path)
        if path in self.fail_paths:
            raise PushError("read failed: /" + "/".join(path))
        return [dict(row) for row in self.state.get(path, [])]

    def execute(self, op):
        if self.fail_desc and op.desc == self.fail_desc:
            raise PushError("simulated failure: " + op.desc)
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


WIFI_MGR = ("interface", "wifi", "capsman")
W_DP = ("interface", "wifi", "datapath")
W_SEC = ("interface", "wifi", "security")
W_CFG = ("interface", "wifi", "configuration")
W_PROV = ("interface", "wifi", "provisioning")
W_ACL = ("interface", "wifi", "access-list")
W_REG = ("interface", "wifi", "registration-table")
L_MGR = ("caps-man", "manager")
L_DP = ("caps-man", "datapath")
L_ACL = ("caps-man", "access-list")
L_REG = ("caps-man", "registration-table")

WIFI_STATE = {
    WIFI_MGR: [{".id": "*1", "enabled": False}],
    ("interface", "wifi", "capsman", "remote-cap"): [
        {".id": "*2", "name": "cap-ap1", "identity": "AP-One",
         "address": "10.0.0.2", "mac-address": "AA:BB:CC:DD:EE:01",
         "radio-mac": "AA:BB:CC:DD:EE:01", "state": "pending",
         "version": "7.15.2", "board-name": "hAP ax^3"},
        {".id": "*3", "name": "cap-ap2", "identity": "AP-Two",
         "address": "10.0.0.3", "mac-address": "AA:BB:CC:DD:EE:02",
         "radio-mac": "AA:BB:CC:DD:EE:02", "state": "connected",
         "version": "7.15.2", "board-name": "cAP ax"}],
    ("interface", "wifi", "radio"): [
        {".id": "*4", "name": "radio1", "radio-mac": "AA:BB:CC:DD:EE:01",
         "remote-cap": "*2", "state": "running"},
        {".id": "*5", "name": "radio2", "radio-mac": "AA:BB:CC:DD:EE:02",
         "remote-cap": "*3", "state": "running"}],
    ("interface", "wifi"): [
        {".id": "*6", "name": "wifi-staff",
         "mac-address": "AA:BB:CC:DD:EE:01",
         "radio-mac": "AA:BB:CC:DD:EE:01", "mode": "ap",
         "disabled": False, "ssid": "Acme Staff",
         "configuration": "mm-cfg-staff"},
        {".id": "*7", "name": "wifi-iot",
         "mac-address": "AA:BB:CC:DD:EE:02",
         "radio-mac": "AA:BB:CC:DD:EE:02", "mode": "ap",
         "disabled": False, "ssid": "Acme IoT",
         "configuration": "mm-cfg-iot"}],
    W_REG: [
        {".id": "*8", "interface": "wifi-staff",
         "mac-address": "11:22:33:44:55:66", "signal-strength": "-55dBm",
         "tx-rate": "866Mbps", "rx-rate": "780Mbps", "uptime": "1h2m"},
        {".id": "*9", "interface": "wifi-iot",
         "mac-address": "11:22:33:44:55:77", "signal-strength": "-78",
         "tx-rate": "150Mbps", "rx-rate": "144Mbps", "uptime": "12m",
         "ssid": "Acme IoT"},
        {".id": "*15", "interface": "wifi-staff",
         "mac-address": "DE:AD:BE:EF:00:01", "signal-strength": "-65",
         "tx-rate": "300Mbps", "rx-rate": "260Mbps", "uptime": "5m"}],
    ("ip", "dhcp-server", "lease"): [
        {".id": "*10", "mac-address": "11:22:33:44:55:66",
         "address": "10.30.0.23", "status": "bound"}],
    ("ip", "arp"): [
        {".id": "*11", "mac-address": "11:22:33:44:55:77",
         "address": "10.40.0.44"}],
    W_CFG: [
        {".id": "*12", "name": "mm-cfg-staff", "ssid": "Acme Staff",
         "datapath": "mm-dp-staff", "security": "mm-sec-staff",
         "comment": C.TAG + "cfg:staff"},
        {".id": "*13", "name": "mm-cfg-iot", "ssid": "Acme IoT",
         "comment": C.TAG + "cfg:iot"}],
    W_ACL: [
        {".id": "*14", "mac-address": "DE:AD:BE:EF:00:01",
         "action": "reject",
         "comment": C.TAG + "blk:DE:AD:BE:EF:00:01"}],
}
LEGACY_STATE = {
    L_MGR: [{".id": "*1", "enabled": True}],
    ("caps-man", "remote-cap"): [
        {".id": "*2", "name": "cap-l1", "identity": "AP-Legacy",
         "address": "10.0.1.2", "mac-address": "AA:BB:CC:DD:EE:11",
         "state": "connected", "version": "6.49.10",
         "board-name": "cAP"}],
    ("caps-man", "radio"): [
        {".id": "*3", "mac-address": "AA:BB:CC:DD:EE:11",
         "remote-cap": "*2", "state": "running"}],
    ("caps-man", "interface"): [
        {".id": "*4", "name": "cap-if1", "radio-mac": "AA:BB:CC:DD:EE:11",
         "ssid": "Legacy Staff", "configuration": "mm-cfg-legacy",
         "disabled": False}],
    L_REG: [
        {".id": "*5", "interface": "cap-if1",
         "mac-address": "22:33:44:55:66:77", "signal-strength": "-62",
         "tx-rate": "300Mbps", "rx-rate": "260Mbps", "uptime": "3m"}],
    ("ip", "dhcp-server", "lease"): [
        {".id": "*6", "mac-address": "22:33:44:55:66:77",
         "address": "10.1.0.9", "status": "bound"}],
    ("caps-man", "configuration"): [
        {".id": "*7", "name": "mm-cfg-legacy", "ssid": "Legacy Staff",
         "comment": C.TAG + "cfg:legacy"}],
}

print("\nDriver detection and live state: both RouterOS generations")

check("RouterOS 7 wins the auto probe when its CAPsMAN menu exists",
      C.detect_driver(FakeApi(WIFI_STATE), "auto") == "wifi")
check("legacy is the fallback when /interface/wifi is absent",
      C.detect_driver(FakeApi(LEGACY_STATE, fail_paths=[WIFI_MGR]), "auto")
      == "legacy")
check("an explicit driver preference is honoured",
      C.detect_driver(FakeApi(WIFI_STATE), "legacy") == "legacy"
      and C.detect_driver(FakeApi(LEGACY_STATE), "wifi") == "wifi")
check("an unknown driver preference is refused",
      refuses(C.detect_driver, FakeApi(WIFI_STATE), "openwrt")[0])

live = C.read_controller(FakeApi(WIFI_STATE), "R1")
ap_fields = {"id", "name", "identity", "address", "radio_mac", "model",
             "version", "state", "radios", "clients_count", "pending"}
client_fields = {"id", "device", "mac", "ip", "ssid", "ap", "interface",
                 "signal_dbm", "signal_pct", "tx_rate", "rx_rate", "uptime",
                 "blocked"}
check("a live read reports one healthy driver and no error",
      live["device"] == "R1" and live["driver"] == "wifi"
      and live["capsman_enabled"] is False and live["error"] == "")
check("both remote CAPs are listed with their identity, model and radios",
      len(live["aps"]) == 2
      and all(ap_fields <= set(ap) for ap in live["aps"])
      and any(ap["identity"] == "AP-One" and ap["model"] == "hAP ax^3"
              and ap["state"] == "pending" and ap["pending"]
              and ap["radios"] >= 1 and ap["clients_count"] == 2
              for ap in live["aps"]))
check("a client gains its IP from DHCP, its SSID from WiFi, and its AP",
      len(live["clients"]) == 3
      and all(client_fields <= set(c) for c in live["clients"])
      and any(c["mac"] == "11:22:33:44:55:66" and c["ip"] == "10.30.0.23"
              and c["ssid"] == "Acme Staff" and c["ap"] == "wifi-staff"
              and c["device"] == "R1" for c in live["clients"]))
check("ARP is the fallback when the registration table carries no IP",
      any(c["mac"] == "11:22:33:44:55:77" and c["ip"] == "10.40.0.44"
          and c["ssid"] == "Acme IoT" for c in live["clients"]))
check("signal is reported in dBm and as a percentage, with rates and uptime",
      any(c["mac"] == "11:22:33:44:55:66" and c["signal_dbm"] == -55
          and 0 < c["signal_pct"] < 100 and c["tx_rate"] == "866Mbps"
          and c["rx_rate"] == "780Mbps" and c["uptime"] == "1h2m"
          for c in live["clients"]))
check("a blocked client is marked as blocked in the live view",
      any(c["mac"] == "DE:AD:BE:EF:00:01" and c["blocked"]
          for c in live["clients"])
      and [b["mac"] for b in live["blocked"]] == ["DE:AD:BE:EF:00:01"])
check("published configurations are visible in the read",
      any(s["name"] == "mm-cfg-staff" and s["ssid"] == "Acme Staff"
          for s in live["ssids"]))

legacy_live = C.read_controller(
    FakeApi(LEGACY_STATE, fail_paths=[WIFI_MGR]), "R2", driver_pref="legacy")
check("legacy caps-man reads its own manager, APs, clients and DHCP join",
      legacy_live["driver"] == "legacy"
      and legacy_live["capsman_enabled"] is True
      and len(legacy_live["aps"]) == 1
      and legacy_live["aps"][0]["identity"] == "AP-Legacy"
      and any(c["mac"] == "22:33:44:55:66:77" and c["ip"] == "10.1.0.9"
              and c["ap"] == "cap-if1"
              for c in legacy_live["clients"]))
offline = C.read_controller(
    FakeApi({}, fail_paths=[WIFI_MGR, L_MGR]), "R3")
check("a router that answers nothing yields empty lists and an error",
      offline["error"] != "" and offline["aps"] == []
      and offline["clients"] == [] and offline["ssids"] == [])
partial = C.read_controller(
    FakeApi(WIFI_STATE, fail_paths=[("ip", "arp")]), "R1")
check("a failed live join is reported, not silently shown as unblocked",
      "arp" in partial["error"] and len(partial["clients"]) == 3
      and len(partial["blocked"]) == 1)

cfg = types.SimpleNamespace(name="R1")

print("\nAP adoption: enable the manager, approve the AP, then stop")

state = clone(WIFI_STATE)
adopt = C.build_adopt_ap_plan(
    FakeApi(state), cfg, ap_mac="aa:bb:cc:dd:ee:01")
check("adoption returns a reversible Plan for this router",
      isinstance(adopt, Plan) and adopt.device == "R1"
      and not adopt.empty and all(op.inverse is not None for op in adopt.ops))
check("the CAPsMAN manager is switched on",
      any(tuple(op.path) == WIFI_MGR and op.action == "set"
          and op.params.get("enabled") == "yes" for op in adopt.ops))
prov_add = [op for op in adopt.ops
            if tuple(op.path) == ("interface", "wifi", "provisioning")
            and op.action == "add"]
check("a tagged provisioning rule approves the requested AP",
      len(prov_add) == 1
      and prov_add[0].params.get("radio-mac") == "AA:BB:CC:DD:EE:01"
      and prov_add[0].params.get("action") == "create-dynamic-enabled"
      and prov_add[0].params["comment"].startswith(C.TAG + "ap:"))
Pusher(cfg, FakeApi(state), dry_run=False).apply(adopt)
check("applying adoption enables the manager and stores the rule",
      state[WIFI_MGR][0]["enabled"] == "yes"
      and len(state[("interface", "wifi", "provisioning")]) == 1)
check("adopting the same AP again makes no changes",
      C.build_adopt_ap_plan(FakeApi(state), cfg,
                            ap_mac="AA:BB:CC:DD:EE:01").empty)
check("an AP can be adopted by name as well as MAC",
      not C.build_adopt_ap_plan(FakeApi(clone(WIFI_STATE)), cfg,
                                ap_name="AP-Two").empty)
check("adoption needs a target",
      refuses(C.build_adopt_ap_plan, FakeApi(WIFI_STATE), cfg)[0])
unmanaged = clone(WIFI_STATE)
unmanaged[("interface", "wifi", "provisioning")] = [
    {".id": "*99", "identity": "AP-One", "comment": "made by a human"}]
unmanaged_plan = C.build_adopt_ap_plan(FakeApi(unmanaged), cfg,
                                       ap_name="AP-One")
check("a human's provisioning rule is never rewritten or removed",
      all(op.params.get(".id") != "*99" for op in unmanaged_plan.ops))

legacy_adopt_state = clone(LEGACY_STATE)
legacy_adopt_state[("caps-man", "interface")][0]["disabled"] = True
legacy_adopt = C.build_adopt_ap_plan(
    FakeApi(legacy_adopt_state), cfg, ap_name="AP-Legacy",
    driver_pref="legacy")
check("legacy adoption also enables a disabled CAP interface, reversibly",
      any(tuple(op.path) == ("caps-man", "interface")
          and op.params.get("disabled") == "no"
          and op.inverse is not None for op in legacy_adopt.ops))
Pusher(cfg, FakeApi(legacy_adopt_state), dry_run=False).apply(legacy_adopt)
check("a second legacy adoption is a no-op",
      C.build_adopt_ap_plan(FakeApi(legacy_adopt_state), cfg,
                            ap_name="AP-Legacy", driver_pref="legacy").empty)
check("an unknown AP is refused before anything is sent",
      refuses(C.build_adopt_ap_plan, FakeApi(WIFI_STATE), cfg,
              ap_name="AP-Ghost")[0])

print("\nFleet publishing: Guest, Staff and IoT together, idempotently")

fleet_ssids = [r for r in store.list_ssids(1)
               if r["name"] in ("guest-net", "staff-net", "iot-net")]
fleet_blocks = store.list_blocked_macs(1)
fleet_blocks = [r for r in fleet_blocks
                if r["mac"] == "DE:AD:BE:EF:00:01"]
WIFI_EMPTY = {WIFI_MGR: [{".id": "*1", "enabled": False}]}
plan = C.build_sync_plan(Pusher(cfg, FakeApi(WIFI_EMPTY), dry_run=True),
                         cfg, fleet_ssids, fleet_blocks)
paths = [tuple(op.path) for op in plan.ops]
check("sync is a Plan that enables CAPsMAN and writes all five menus",
      isinstance(plan, Plan) and plan.device == "R1" and not plan.empty
      and WIFI_MGR in paths
      and paths.count(W_DP) == 3 and paths.count(W_SEC) == 3
      and paths.count(W_CFG) == 3 and paths.count(W_PROV) >= 1
      and paths.count(W_ACL) == len(fleet_blocks))
check("every operation has a rollback inverse",
      all(op.inverse is not None for op in plan.ops))

dps = {op.params["name"]: op.params for op in plan.ops
       if tuple(op.path) == W_DP}
check("each SSID gets its own VLAN and bridge on the datapath",
      all(dps[f"mm-dp-{s['name']}"]["vlan-id"] == str(s["vlan_id"])
          and dps[f"mm-dp-{s['name']}"]["bridge"] == s["bridge"]
          for s in fleet_ssids))
check("guest and IoT isolate clients, staff does not",
      dps["mm-dp-guest-net"]["client-isolation"] == "yes"
      and dps["mm-dp-iot-net"]["client-isolation"] == "yes"
      and dps["mm-dp-staff-net"]["client-isolation"] == "no")
secs = {op.params["name"]: op.params for op in plan.ops
        if tuple(op.path) == W_SEC}
check("WPA2, WPA3 and mixed mode are published with their passphrases",
      secs["mm-sec-guest-net"]["auth-types"] == "wpa2-psk"
      and secs["mm-sec-guest-net"]["passphrase"] == "guest-pass-2026"
      and secs["mm-sec-iot-net"]["auth-types"] == "wpa2-psk,wpa3-psk"
      and secs["mm-sec-iot-net"]["passphrase"] == "iot-pass-2026")
configs = {op.params["name"]: op.params for op in plan.ops
           if tuple(op.path) == W_CFG}
check("each configuration points at its datapath and security profile",
      all(configs[f"mm-cfg-{s['name']}"]["ssid"] == s["ssid"]
          and configs[f"mm-cfg-{s['name']}"]["datapath"]
          == f"mm-dp-{s['name']}"
          and configs[f"mm-cfg-{s['name']}"]["security"]
          == f"mm-sec-{s['name']}" for s in fleet_ssids))
provision = [op.params for op in plan.ops if tuple(op.path) == W_PROV]
check("one provisioning rule broadcasts staff as master and the rest as "
      "slaves on every AP",
      len(provision) == 1
      and provision[0]["action"] == "create-dynamic-enabled"
      and provision[0]["master-configuration"] == "mm-cfg-staff-net"
      and set(provision[0]["slave-configurations"].split(","))
      == {"mm-cfg-guest-net", "mm-cfg-iot-net"}
      and provision[0]["comment"] == C.TAG + "prov:fleet")
acl = [op.params for op in plan.ops if tuple(op.path) == W_ACL]
check("blocked MACs become tagged reject rules",
      acl == [{"mac-address": "DE:AD:BE:EF:00:01", "action": "reject",
               "comment": C.TAG + "blk:DE:AD:BE:EF:00:01"}])
check("all managed rows carry exact per-row tags, not a shared prefix",
      sorted(op.params["comment"] for op in plan.ops
             if "comment" in op.params and tuple(op.path) != W_PROV)
      == sorted([C.TAG + kind + s["name"] for kind in ("dp:", "sec:", "cfg:")
                 for s in fleet_ssids]
                + [C.TAG + "blk:DE:AD:BE:EF:00:01"]))
check("Wi-Fi passphrases are sent to the router but never to the audit log",
      all(secret not in plan.diff_text()
          for secret in ("guest-pass-2026", "staff-pass-2026",
                         "iot-pass-2026"))
      and any(op.params.get("passphrase") == "guest-pass-2026"
              for op in plan.ops))

applied_state = clone(WIFI_EMPTY)
Pusher(cfg, FakeApi(applied_state), dry_run=False).apply(plan)
check("applying creates the manager, datapaths, security, configs and rules",
      applied_state[WIFI_MGR][0]["enabled"] == "yes"
      and len(applied_state[W_DP]) == 3 and len(applied_state[W_SEC]) == 3
      and len(applied_state[W_CFG]) == 3 and len(applied_state[W_ACL]) == 1)
second = C.build_sync_plan(Pusher(cfg, FakeApi(applied_state), dry_run=True),
                           cfg, fleet_ssids, fleet_blocks)
check("a second sync is completely idempotent", second.empty)

changed = [dict(s, passphrase="brand-new-secret")
           if s["name"] == "guest-net" else s for s in fleet_ssids]
changed_plan = C.build_sync_plan(
    Pusher(cfg, FakeApi(applied_state), dry_run=True), cfg, changed,
    fleet_blocks)
check("only the changed security profile is re-sent",
      len(changed_plan.ops) == 1
      and tuple(changed_plan.ops[0].path) == W_SEC
      and changed_plan.ops[0].params.get("passphrase") == "brand-new-secret"
      and "brand-new-secret" not in changed_plan.diff_text())

bool_state = clone(applied_state)
bool_state[WIFI_MGR][0]["enabled"] = True
for row in bool_state[W_DP]:
    row["client-isolation"] = row["name"] != "mm-dp-staff-net"
check("RouterOS yes/no read-back as true/false does not cause endless sets",
      C.build_sync_plan(Pusher(cfg, FakeApi(bool_state), dry_run=True),
                        cfg, fleet_ssids, fleet_blocks).empty)

opened = [dict(s, security_mode="open", passphrase="")
          if s["name"] == "guest-net" else s for s in fleet_ssids]
open_plan = C.build_sync_plan(
    Pusher(cfg, FakeApi(applied_state), dry_run=True), cfg, opened,
    fleet_blocks)
check("switching to open clears the old key and auth types on the router",
      any(tuple(op.path) == W_SEC
          and op.params.get("name") == "mm-sec-guest-net"
          and op.params.get("passphrase") == ""
          and op.params.get("auth-types") == ""
          for op in open_plan.ops)
      and "guest-pass-2026" not in open_plan.diff_text())

disabled = [dict(s, enabled=0) if s["name"] == "iot-net" else s
            for s in fleet_ssids]
removed = C.build_sync_plan(
    Pusher(cfg, FakeApi(applied_state), dry_run=True), cfg, disabled,
    fleet_blocks)
check("disabling an SSID removes only its own tagged rows and drops it "
      "from provisioning",
      all(tuple(op.path) in (W_DP, W_SEC, W_CFG, W_PROV)
          for op in removed.ops)
      and sum(1 for op in removed.ops if op.action == "remove") == 3
      and any(tuple(op.path) == W_PROV
              and op.params.get("slave-configurations")
              == "mm-cfg-guest-net" for op in removed.ops))
Pusher(cfg, FakeApi(applied_state), dry_run=False).apply(removed)
check("the reconciled state is stable again",
      C.build_sync_plan(Pusher(cfg, FakeApi(applied_state), dry_run=True),
                        cfg, disabled, fleet_blocks).empty)

all_off_state = clone(WIFI_EMPTY)
Pusher(cfg, FakeApi(all_off_state), dry_run=False).apply(
    C.build_sync_plan(Pusher(cfg, FakeApi(all_off_state), dry_run=True),
                      cfg, fleet_ssids, []))
all_off = C.build_sync_plan(
    Pusher(cfg, FakeApi(all_off_state), dry_run=True), cfg, [], [])
check("disabling every SSID also removes the fleet provisioning rule",
      any(tuple(op.path) == W_PROV and op.action == "remove"
          and op.params.get(".id")
          and all_off_state[W_PROV][0]["comment"] == C.TAG + "prov:fleet"
          for op in all_off.ops))
Pusher(cfg, FakeApi(all_off_state), dry_run=False).apply(all_off)
check("an all-disabled controller settles to no changes",
      C.build_sync_plan(Pusher(cfg, FakeApi(all_off_state), dry_run=True),
                        cfg, [], []).empty)

unblocked = C.build_sync_plan(
    Pusher(cfg, FakeApi(applied_state), dry_run=True), cfg, disabled, [])
check("removing a block deletes only its tagged reject rule",
      len(unblocked.ops) == 1 and tuple(unblocked.ops[0].path) == W_ACL
      and unblocked.ops[0].action == "remove")

human_state = clone(WIFI_EMPTY)
human_state[W_DP] = [{".id": "*99", "name": "hand-made-dp",
                      "bridge": "other", "comment": "made by a human"}]
human_plan = C.build_sync_plan(
    Pusher(cfg, FakeApi(human_state), dry_run=True), cfg, fleet_ssids, [])
check("a lookalike datapath made by a human is never touched",
      all(op.params.get(".id") != "*99" for op in human_plan.ops))

lower_mac_state = {
    WIFI_MGR: [{".id": "*1", "enabled": True}],
    W_ACL: [{".id": "*5", "mac-address": "de:ad:be:ef:00:01",
             "action": "reject",
             "comment": C.TAG + "blk:DE:AD:BE:EF:00:01"}],
}
lower_mac_plan = C.build_sync_plan(
    Pusher(cfg, FakeApi(lower_mac_state), dry_run=True), cfg, [],
    [{"mac": "DE:AD:BE:EF:00:01"}])
check("lowercase MACs read back are still recognised as our tagged rules",
      lower_mac_plan.empty)

legacy_empty = {L_MGR: [{".id": "*1", "enabled": False}]}
legacy_plan = C.build_sync_plan(
    Pusher(cfg, FakeApi(legacy_empty), dry_run=True), cfg, fleet_ssids,
    fleet_blocks, driver_pref="legacy")
legacy_dps = {op.params["name"]: op.params for op in legacy_plan.ops
              if tuple(op.path) == L_DP}
check("legacy sync writes the equivalent caps-man menus",
      any(tuple(op.path) == L_MGR and op.params.get("enabled") == "yes"
          for op in legacy_plan.ops)
      and len(legacy_dps) == 3
      and any(tuple(op.path) == ("caps-man", "provisioning")
              for op in legacy_plan.ops)
      and any(tuple(op.path) == L_ACL for op in legacy_plan.ops))
check("legacy datapaths use VLAN tagging and client isolation correctly",
      all(legacy_dps[f"mm-dp-{s['name']}"]["vlan-mode"] == "use-tag"
          and legacy_dps[f"mm-dp-{s['name']}"]["vlan-id"]
          == str(s["vlan_id"])
          and legacy_dps[f"mm-dp-{s['name']}"]["local-forwarding"] == "no"
          for s in fleet_ssids)
      and legacy_dps["mm-dp-guest-net"]["client-to-client-forwarding"]
      == "no"
      and legacy_dps["mm-dp-staff-net"]["client-to-client-forwarding"]
      == "yes")

no_vlan = [dict(s, vlan_id=None) if s["name"] == "staff-net" else s
           for s in fleet_ssids]
no_vlan_plan = C.build_sync_plan(
    Pusher(cfg, FakeApi(legacy_empty), dry_run=True), cfg, no_vlan, [],
    driver_pref="legacy")
no_vlan_dp = next(op.params for op in no_vlan_plan.ops
                  if tuple(op.path) == L_DP
                  and op.params.get("name") == "mm-dp-staff-net")
check("a VLAN-less legacy SSID uses untagged frames, not an empty VLAN",
      no_vlan_dp.get("vlan-mode") == "no-tag"
      and "vlan-id" not in no_vlan_dp)
legacy_applied = clone(legacy_empty)
Pusher(cfg, FakeApi(legacy_applied), dry_run=False).apply(legacy_plan)
check("legacy sync is idempotent too",
      C.build_sync_plan(Pusher(cfg, FakeApi(legacy_applied), dry_run=True),
                        cfg, fleet_ssids, fleet_blocks,
                        driver_pref="legacy").empty)

print("\nLive client actions: disconnect, block, unblock")

state = clone(WIFI_STATE)
check("a client can be disconnected by MAC and is really removed",
      C.disconnect_client(FakeApi(state), mac="11:22:33:44:55:66") is True
      and not any(row.get("mac-address") == "11:22:33:44:55:66"
                  for row in state[W_REG]))
check("disconnecting the same client twice reports false, not an error",
      C.disconnect_client(FakeApi(state), mac="11:22:33:44:55:66") is False)
check("a client can also be disconnected by its registration id",
      C.disconnect_client(FakeApi(clone(WIFI_STATE)), client_id="*15")
      is True)
check("legacy registrations use the caps-man menu",
      C.disconnect_client(FakeApi(LEGACY_STATE),
                          mac="22:33:44:55:66:77",
                          driver_pref="legacy") is True)
check("disconnect needs an identifier",
      refuses(C.disconnect_client, FakeApi(WIFI_STATE))[0])

state = clone(WIFI_STATE)
block_plan = C.block_client_plan(
    Pusher(cfg, FakeApi(state), dry_run=True), cfg, "11:22:33:44:55:66",
    reason="rogue laptop")
block_paths = [tuple(op.path) for op in block_plan.ops]
check("blocking adds a reject ACL and disconnects the live registration",
      W_ACL in block_paths and W_REG in block_paths
      and any(op.action == "add" and op.params.get("action") == "reject"
              and op.params.get("comment")
              == C.TAG + "blk:11:22:33:44:55:66" for op in block_plan.ops)
      and any(op.action == "remove" for op in block_plan.ops
              if tuple(op.path) == W_REG))
check("the reason is recorded in the plan, not in the owned ACL comment",
      "rogue laptop" in block_plan.diff_text()
      and all(op.params.get("comment") == C.TAG + "blk:11:22:33:44:55:66"
              for op in block_plan.ops if "comment" in op.params))
Pusher(cfg, FakeApi(state), dry_run=False).apply(block_plan)
check("applying a block leaves no active registration for that MAC",
      not any(row.get("mac-address") == "11:22:33:44:55:66"
              for row in state[W_REG])
      and any(row.get("mac-address") == "11:22:33:44:55:66"
              for row in state[W_ACL]))
check("a second block plan is a no-op",
      C.block_client_plan(Pusher(cfg, FakeApi(state), dry_run=True), cfg,
                          "11:22:33:44:55:66").empty)
unblock_plan = C.unblock_client_plan(
    Pusher(cfg, FakeApi(state), dry_run=True), cfg, "11:22:33:44:55:66")
check("unblocking removes our reject rule",
      len(unblock_plan.ops) == 1 and unblock_plan.ops[0].action == "remove"
      and tuple(unblock_plan.ops[0].path) == W_ACL)
human_acl = clone(WIFI_STATE)
human_acl[W_ACL] = [{".id": "*77", "mac-address": "11:22:33:44:55:66",
                     "action": "reject", "comment": "made by a human"}]
human_unblock = C.unblock_client_plan(
    Pusher(cfg, FakeApi(human_acl), dry_run=True), cfg,
    "11:22:33:44:55:66")
check("an unmanaged reject rule is not deleted by unblock",
      human_unblock.empty)
human_block_state = clone(WIFI_STATE)
human_block_state[W_ACL] = [{
    ".id": "*77", "mac-address": "11:22:33:44:55:66", "action": "reject",
    "comment": "made by a human"}]
human_block = C.block_client_plan(
    Pusher(cfg, FakeApi(human_block_state), dry_run=True), cfg,
    "11:22:33:44:55:66")
check("a human's reject rule does not stop us adding our own tagged block",
      any(tuple(op.path) == W_ACL and op.action == "add"
          and op.params.get("comment")
          == C.TAG + "blk:11:22:33:44:55:66" for op in human_block.ops))

print("\nOne-click fleet sync: every site, its own status, no aborts")

fleet_store = C.CapsmanStore(os.path.join(TMP, "fleet.db"))
for name, enabled, driver in (("R1", 1, "auto"), ("R2", 1, "auto"),
                              ("R3", 1, "legacy"), ("R4", 0, "auto"),
                              ("R5", 1, "auto")):
    fleet_store.set_controller(77, name, enabled=bool(enabled), driver=driver)
for row in store.list_ssids(1):
    if row["name"] in ("guest-net", "staff-net", "iot-net"):
        fleet_store.upsert_ssid(77, dict(row, id=None))
fleet_store.block_mac(77, "DE:AD:BE:EF:00:01")
cfgs = [types.SimpleNamespace(name=name) for name in ("R1", "R2", "R3", "R4")]
fleet_states = {
    "R1": clone(WIFI_EMPTY),
    "R3": clone({L_MGR: [{".id": "*1", "enabled": False}]}),
}
audits = []


class Audit:
    def append(self, device, user, feature, mode, status, summary, detail):
        audits.append((device, user, feature, status))


def connect(one_cfg):
    if one_cfg.name == "R2":
        raise PushError("router offline: connection timed out")
    return Pusher(one_cfg, FakeApi(fleet_states[one_cfg.name]),
                  dry_run=False, audit=Audit(), user="admin")


results = C.sync_all_controllers(77, fleet_store, cfgs, connect_fn=connect,
                                 user="admin")
by_device = {r["device"]: r for r in results}
check("every enabled controller is attempted, even without a device config",
      list(by_device) == ["R1", "R2", "R3", "R5"]
      and "R4" not in by_device)
check("reachable sites apply their plans; an unreachable one is offline; "
      "a missing config is an error",
      by_device["R1"]["status"] == "ok" and by_device["R1"]["changes"] > 0
      and by_device["R2"]["status"] == "offline"
      and "offline" in by_device["R2"]["error"]
      and by_device["R3"]["status"] == "ok"
      and by_device["R5"]["status"] == "error"
      and "config" in by_device["R5"]["error"])
check("all results carry the documented shape",
      all(set(r) == {"device", "status", "changes", "summary", "error"}
          for r in results))
check("each controller's sync result is stored, and the disabled one is "
      "left alone",
      [(c["device"], c["last_sync_status"])
       for c in fleet_store.list_controllers(77)]
      == [("R1", "ok"), ("R2", "offline"), ("R3", "ok"),
          ("R4", ""), ("R5", "error")]
      and fleet_store.list_controllers(77)[3]["last_sync_at"] is None)
check("the audit log records the committed pushes with their user",
      any(a[2] == "capsman" and a[1] == "admin" for a in audits))

again_results = C.sync_all_controllers(
    77, fleet_store, cfgs, connect_fn=connect, user="admin")
again_by_device = {r["device"]: r for r in again_results}
check("a repeat run reports unchanged, not another set of changes",
      all(again_by_device[d]["status"] == "unchanged"
          and again_by_device[d]["changes"] == 0 for d in ("R1", "R3"))
      and fleet_store.list_controllers(77)[0]["last_sync_status"]
      == "unchanged")

probe = C.build_sync_plan(
    Pusher(cfg, FakeApi(clone(WIFI_EMPTY)), dry_run=True), cfg,
    fleet_store.list_ssids(77), fleet_store.list_blocked_macs(77))
fail_desc = next(op.desc for op in probe.ops if tuple(op.path) == W_DP)


def connect_failing(one_cfg):
    if one_cfg.name == "R2":
        raise PushError("router offline")
    api = FakeApi(clone(WIFI_EMPTY), fail_desc=fail_desc) \
        if one_cfg.name == "R1" else FakeApi(
            {L_MGR: [{".id": "*1", "enabled": "yes"}]})
    return Pusher(one_cfg, api, dry_run=False)


failed = C.sync_all_controllers(77, fleet_store, cfgs,
                                connect_fn=connect_failing)
failed_by_device = {r["device"]: r for r in failed}
check("a failed apply is recorded as an error and the rest of the fleet "
      "still runs",
      failed_by_device["R1"]["status"] == "error"
      and failed_by_device["R1"]["changes"] == 0
      and "simulated failure" in failed_by_device["R1"]["error"]
      and failed_by_device["R2"]["status"] == "offline"
      and failed_by_device["R3"]["status"] == "ok")

dry_store = C.CapsmanStore(os.path.join(TMP, "dry.db"))
dry_store.set_controller(1, "R1")
dry_store.upsert_ssid(1, dict(fleet_ssids[0], id=None))
dry_state = clone(WIFI_EMPTY)
dry_cfg = types.SimpleNamespace(name="R1")
dry_results = C.sync_all_controllers(
    1, dry_store, [dry_cfg],
    connect_fn=lambda one: Pusher(one, FakeApi(dry_state), dry_run=True))
check("a dry-run pusher handed to sync is forced to commit",
      dry_results[0]["status"] == "ok" and dry_results[0]["changes"] > 0
      and dry_state[WIFI_MGR][0]["enabled"] == "yes"
      and len(dry_state.get(W_DP, [])) == 1)
dry_store.close()

nasty_store = C.CapsmanStore(os.path.join(TMP, "nasty.db"))
for name in ("R1", "R2"):
    nasty_store.set_controller(1, name)
nasty_cfgs = [types.SimpleNamespace(name=n) for n in ("R1", "R2")]
attempts = []


def nasty_connect(one_cfg):
    attempts.append(one_cfg.name)
    if one_cfg.name == "R1":
        raise PushError("router said:\n" + "x" * 1200)
    raise PushError("router offline")


nasty_results = C.sync_all_controllers(1, nasty_store, nasty_cfgs,
                                       connect_fn=nasty_connect)
check("one malformed error message cannot abort the rest of the fleet",
      [r["device"] for r in nasty_results] == ["R1", "R2"]
      and attempts == ["R1", "R2"]
      and all("\n" not in r["summary"] and len(r["summary"]) <= 1000
              for r in nasty_results))
check("even a very long, multi-line failure is stored safely",
      all("\n" not in c["last_sync_summary"]
          and len(c["last_sync_summary"]) <= 1000
          for c in nasty_store.list_controllers(1)))
nasty_store.close()

store.close()
fleet_store.close()
print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL CAPSMAN TESTS PASSED")
