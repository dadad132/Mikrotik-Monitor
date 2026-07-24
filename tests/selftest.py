"""Offline self-test: drive the checks with simulated RouterOS data.

Runs without a real router (or even the network). Verifies that:
  * a healthy snapshot produces no alerts,
  * failover / internet-down / reboot / high-CPU / link-down / a new failed
    login each produce exactly the expected alert,
  * recovery produces a RESOLVED alert,
  * the email notifier renders a digest.

Run:  ./.venv/Scripts/python.exe tests/selftest.py
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon.baseline import Baseline, is_high
from mikromon.checks.wan import WanCheck
from mikromon.checks.wan_traffic import WanTrafficCheck
from mikromon.checks.resources import ResourceCheck
from mikromon.checks.interfaces import InterfaceCheck
from mikromon.checks.security import SecurityCheck
from mikromon.checks.clients import ClientCountCheck
from mikromon.checks.client_usage import ClientUsageCheck
from mikromon.config import (DEFAULT_CHECKS, DEFAULT_THRESHOLDS, DeviceConfig,
                             SmtpConfig, WanConfig, WanEndpoint)
from mikromon.context import CheckContext
from mikromon.device import Snapshot
from mikromon.notify.email_smtp import EmailNotifier
from mikromon.state import StateStore

FAILS = []


def check(name, condition):
    status = "ok  " if condition else "FAIL"
    print(f"  [{status}] {name}")
    if not condition:
        FAILS.append(name)


def snap(**datasets) -> Snapshot:
    s = Snapshot()
    for k, v in datasets.items():
        s.data[k] = v
    return s


def run(check_obj, datasets, dev, store, confirm=1, now=None):
    ctx = CheckContext(dev.name, store, now=now, default_confirm=confirm)
    check_obj.run(snap(**datasets), dev, ctx)
    return ctx.alerts


def drive(check_obj, dev, store, snapshots, base_now=1_000_000.0, step=10.0):
    """Run a check across successive polls; return the final poll's alerts."""
    alerts = []
    for i, ds in enumerate(snapshots):
        alerts = run(check_obj, ds, dev, store, now=base_now + i * step)
    return alerts


def mkdev(name, **over):
    th = {**DEFAULT_THRESHOLDS, **over.pop("thresholds", {})}
    return DeviceConfig(name=name, host="1.1.1.1", thresholds=th, **over)


def keys(alerts):
    return [a.key for a in alerts]


# --------------------------------------------------------------------------
dev = DeviceConfig(name="TestRouter", host="10.0.0.1", lan_subnets=["192.168.88.0/24"])
store = StateStore(os.path.join(tempfile.gettempdir(), "mikromon-selftest.json"))

print("WAN failover / internet-down:")
healthy_routes = {"route": [
    {"dst-address": "0.0.0.0/0", "gateway": "1.1.1.1", "distance": "1",
     "active": "true", "gateway-status": "1.1.1.1 reachable via ether1"},
]}
failover_routes = {"route": [
    {"dst-address": "0.0.0.0/0", "gateway": "1.1.1.1", "distance": "1",
     "active": "false", "gateway-status": "1.1.1.1 unreachable"},
    {"dst-address": "0.0.0.0/0", "gateway": "10.0.0.1", "distance": "2",
     "active": "true", "gateway-status": "10.0.0.1 reachable via lte1"},
]}
down_routes = {"route": [
    {"dst-address": "0.0.0.0/0", "gateway": "1.1.1.1", "distance": "1",
     "active": "false", "gateway-status": "1.1.1.1 unreachable"},
]}

a = run(WanCheck(), healthy_routes, dev, store)
check("healthy WAN -> no alert", a == [])
a = run(WanCheck(), failover_routes, dev, store)
check("failover -> wan_failover WARNING", keys(a) == ["wan_failover"]
      and a[0].severity.label == "WARNING" and "unreachable" in a[0].cause)
a = run(WanCheck(), healthy_routes, dev, store)
check("back on primary -> RESOLVED", len(a) == 1 and a[0].recovery)
a = run(WanCheck(), down_routes, dev, store)
check("no active route -> internet_down CRITICAL",
      keys(a) == ["internet_down"] and a[0].severity.label == "CRITICAL")

print("WAN 3-tier alerting (named Main + Backup links, one email per tier):")
dev2 = mkdev("TestRouter2", wan=WanConfig(links=[
    WanEndpoint(interface="ether1", gateway="1.1.1.1", name="Main"),
    WanEndpoint(interface="lte1", gateway="10.0.0.1", name="Backup"),
]))
both_up = {"route": [
    {"dst-address": "0.0.0.0/0", "gateway": "1.1.1.1", "distance": "1",
     "active": "true", "gateway-status": "1.1.1.1 reachable via ether1"},
    {"dst-address": "0.0.0.0/0", "gateway": "10.0.0.1", "distance": "2",
     "active": "true", "gateway-status": "10.0.0.1 reachable via lte1"},
]}
main_down = {"route": [
    {"dst-address": "0.0.0.0/0", "gateway": "1.1.1.1", "distance": "1",
     "active": "false", "gateway-status": "1.1.1.1 unreachable"},
    {"dst-address": "0.0.0.0/0", "gateway": "10.0.0.1", "distance": "2",
     "active": "true", "gateway-status": "10.0.0.1 reachable via lte1"},
]}
backup_down = {"route": [
    {"dst-address": "0.0.0.0/0", "gateway": "1.1.1.1", "distance": "1",
     "active": "true", "gateway-status": "1.1.1.1 reachable via ether1"},
    {"dst-address": "0.0.0.0/0", "gateway": "10.0.0.1", "distance": "2",
     "active": "false", "gateway-status": "10.0.0.1 unreachable"},
]}
both_down2 = {"route": [
    {"dst-address": "0.0.0.0/0", "gateway": "1.1.1.1", "distance": "1",
     "active": "false", "gateway-status": "1.1.1.1 unreachable"},
    {"dst-address": "0.0.0.0/0", "gateway": "10.0.0.1", "distance": "2",
     "active": "false", "gateway-status": "10.0.0.1 unreachable"},
]}

a = run(WanCheck(), both_up, dev2, store)
check("both links up (seed) -> no alert", a == [])

a = run(WanCheck(), main_down, dev2, store)
check("tier 1: main down, backup up -> exactly one alert (wan_failover)",
      keys(a) == ["wan_failover"] and "DOWN" in a[0].title
      and "Main" in a[0].title and "Backup" in a[0].title)

a = run(WanCheck(), both_up, dev2, store)
check("tier 1 recovers", len(a) == 1 and a[0].recovery and a[0].key == "wan_failover")

a = run(WanCheck(), backup_down, dev2, store)
check("tier 2: backup down, main up -> exactly one alert (wan_link:1)",
      keys(a) == ["wan_link:1"] and "Backup" in a[0].title
      and "still up" in a[0].title)

a = run(WanCheck(), both_up, dev2, store)
check("tier 2 recovers", len(a) == 1 and a[0].recovery and a[0].key == "wan_link:1")

a = run(WanCheck(), both_down2, dev2, store)
check("tier 3: both down -> exactly one alert (internet_down), "
      "not one per link too",
      keys(a) == ["internet_down"] and a[0].severity.label == "CRITICAL")

a = run(WanCheck(), both_up, dev2, store)
check("tier 3 recovers", len(a) == 1 and a[0].recovery and a[0].key == "internet_down")

print("WAN per-link check: managed static route found by its comment tag "
      "when gateway/interface matching can't (confirmed live: a genuinely "
      "active backup was reported DOWN because its route's gateway-status "
      "text didn't parse to match the configured interface name):")
dev3 = mkdev("TestRouter3", wan=WanConfig(links=[
    WanEndpoint(interface="ether1", gateway="1.1.1.1", name="Main"),
    WanEndpoint(interface="ether2-backup", gateway="", name="Backup"),
]))
# The backup's managed static route: active and genuinely fine, but its
# gateway-status has no "via ether2-backup" text at all (e.g. a PPP remote
# IP or a static route RouterOS didn't annotate that way) — interface/
# gateway matching alone would miss it; only the comment tag identifies it.
unparseable_but_up = {"route": [
    {"dst-address": "0.0.0.0/0", "gateway": "1.1.1.1", "distance": "1",
     "active": "true", "gateway-status": "1.1.1.1 reachable via ether1",
     "comment": "mikromon:failover:primary"},
    {"dst-address": "0.0.0.0/0", "gateway": "10.9.9.9", "distance": "2",
     "active": "true", "gateway-status": "10.9.9.9 reachable",
     "comment": "mikromon:failover:secondary"},
]}
a = run(WanCheck(), unparseable_but_up, dev3, store)
check("a genuinely-up backup found via its failover comment tag raises no "
      "alert (not misreported as 'no route found')", a == [])

# Same route, but now actually down — the comment-tag fallback must still
# correctly detect that, not just always report "up" once it finds a match.
unparseable_and_down = {"route": [
    unparseable_but_up["route"][0],
    {"dst-address": "0.0.0.0/0", "gateway": "10.9.9.9", "distance": "2",
     "active": "false", "gateway-status": "10.9.9.9 unreachable",
     "comment": "mikromon:failover:secondary"},
]}
a = run(WanCheck(), unparseable_and_down, dev3, store)
check("the SAME route reported down is correctly alerted, not masked by "
      "the comment-tag fallback always assuming it's fine",
      keys(a) == ["wan_link:1"] and "Backup" in a[0].title)

print("WAN per-link check: same fallback, but for the CURRENT push/features.py "
      "comment scheme — the uplink's own configured name, not the old internal "
      "tag (confirms the switch to name-based route comments didn't quietly "
      "break the very fallback the two tests above exist to guard):")
dev7 = mkdev("TestRouter7", wan=WanConfig(links=[
    WanEndpoint(interface="ether1", gateway="1.1.1.1", name="Main"),
    WanEndpoint(interface="ether2-backup", gateway="", name="Backup"),
]))
named_but_up = {"route": [
    {"dst-address": "0.0.0.0/0", "gateway": "1.1.1.1", "distance": "1",
     "active": "true", "gateway-status": "1.1.1.1 reachable via ether1",
     "comment": "Main"},
    {"dst-address": "0.0.0.0/0", "gateway": "10.9.9.9", "distance": "2",
     "active": "true", "gateway-status": "10.9.9.9 reachable",
     "comment": "Backup"},
]}
a = run(WanCheck(), named_but_up, dev7, store)
check("a genuinely-up backup found via its CURRENT name-based route comment "
      "raises no alert (not misreported as 'no route found')", a == [])

named_and_down = {"route": [
    named_but_up["route"][0],
    {"dst-address": "0.0.0.0/0", "gateway": "10.9.9.9", "distance": "2",
     "active": "false", "gateway-status": "10.9.9.9 unreachable",
     "comment": "Backup"},
]}
a = run(WanCheck(), named_and_down, dev7, store)
check("the SAME route reported down is correctly alerted under the "
      "name-based comment scheme too",
      keys(a) == ["wan_link:1"] and "Backup" in a[0].title)

print("WAN per-link check: a PLAIN (unmanaged, failover-off) dynamic route "
      "found via the DHCP client's own live gateway field, not just text-"
      "parsing gateway-status (confirmed live: some ISPs on a router showed "
      "offline while others on the SAME router matched fine, because "
      "gateway-status text parsing is inherently inconsistent):")
dev6 = mkdev("TestRouter6", wan=WanConfig(links=[
    WanEndpoint(interface="ether2-terana", gateway="", name="Main"),
    WanEndpoint(interface="ether3-vodacom", gateway="", name="Backup"),
]))
plain_but_up = {
    "route": [
        {"dst-address": "0.0.0.0/0", "gateway": "1.1.1.1", "distance": "1",
         "active": "true", "gateway-status": "1.1.1.1 reachable via ether2-terana"},
        # No "via <iface>" text at all, and the gateway is a bare IP with no
        # managed mikromon:failover: comment — a genuinely plain dynamic
        # DHCP-client-created route, exactly as it looks with failover off.
        {"dst-address": "0.0.0.0/0", "gateway": "10.9.9.9", "distance": "2",
         "active": "true", "gateway-status": "10.9.9.9 reachable"},
    ],
    "dhcp_client": [
        {"interface": "ether2-terana", "gateway": "1.1.1.1"},
        {"interface": "ether3-vodacom", "gateway": "10.9.9.9"},
    ],
}
a = run(WanCheck(), plain_but_up, dev6, store)
check("a genuinely-up plain dynamic route is found via the DHCP client's "
      "own gateway field, not misreported as 'no route found'", a == [])

plain_and_down = {
    "route": [plain_but_up["route"][0],
             {"dst-address": "0.0.0.0/0", "gateway": "10.9.9.9", "distance": "2",
              "active": "false", "gateway-status": "10.9.9.9 unreachable"}],
    "dhcp_client": plain_but_up["dhcp_client"],
}
a = run(WanCheck(), plain_and_down, dev6, store)
check("the SAME plain route reported down is correctly alerted",
      keys(a) == ["wan_link:1"] and "Backup" in a[0].title)

print("WAN per-link check: DHCP-client matching tolerates a case difference "
      "between the WAN uplinks editor's Interface text and the router's own "
      "interface name (confirmed live: an exact match silently, with no "
      "error, treated a case-mismatched link as unmatched):")
dev8 = mkdev("TestRouter8", wan=WanConfig(links=[
    WanEndpoint(interface="Wikiworx", gateway="", name="Main"),
    WanEndpoint(interface="ether3-vodacom", gateway="", name="Backup"),
]))
case_but_up = {
    "route": [
        {"dst-address": "0.0.0.0/0", "gateway": "1.1.1.1", "distance": "1",
         "active": "true", "gateway-status": "1.1.1.1 reachable"},
        {"dst-address": "0.0.0.0/0", "gateway": "10.9.9.9", "distance": "2",
         "active": "true", "gateway-status": "10.9.9.9 reachable"},
    ],
    # The router's actual DHCP client interface is "wikiworx" (lowercase) —
    # differs in case from the WAN uplinks editor's "Wikiworx".
    "dhcp_client": [
        {"interface": "wikiworx", "gateway": "1.1.1.1"},
        {"interface": "ether3-vodacom", "gateway": "10.9.9.9"},
    ],
}
a = run(WanCheck(), case_but_up, dev8, store)
check("a genuinely-up link is still matched despite the case difference "
      "(not misreported as 'no route found')", a == [])

case_and_down = {
    "route": [case_but_up["route"][0],
             {"dst-address": "0.0.0.0/0", "gateway": "10.9.9.9", "distance": "2",
              "active": "false", "gateway-status": "10.9.9.9 unreachable"}],
    "dhcp_client": case_but_up["dhcp_client"],
}
a = run(WanCheck(), case_and_down, dev8, store)
check("the SAME case-insensitively-matched route reported down is "
      "correctly alerted",
      keys(a) == ["wan_link:1"] and "Backup" in a[0].title)

print("WAN check: stale wan_failover/wan_link conditions clear instead of "
      "freezing forever (confirmed live: a device with WAN-failover "
      "monitoring turned off kept showing every uplink permanently offline "
      "— a real problem recorded before the check was disabled just never "
      "got re-evaluated to clear it):")
dev4 = mkdev("TestRouter4", wan=WanConfig(links=[
    WanEndpoint(interface="ether1", gateway="1.1.1.1", name="Main"),
    WanEndpoint(interface="lte1", gateway="10.0.0.1", name="Backup"),
]), checks={**DEFAULT_CHECKS, "wan_failover": False})
# Pre-seed stale "problem" conditions, as if a real outage had been recorded
# before monitoring was switched off for this device.
for key in ("wan_failover", "wan_link:1", "wan_link:0"):
    cond = store.condition("TestRouter4", key)
    cond.update({"status": "problem", "since": 1_000_000.0})
a = run(WanCheck(), both_up, dev4, store)
cleared = {al.key for al in a if al.recovery}
check("wan_failover check disabled: stale wan_failover clears",
      "wan_failover" in cleared)
check("wan_failover check disabled: stale wan_link:1 clears",
      "wan_link:1" in cleared)
check("wan_failover check disabled: stale wan_link:0 (an old leftover key "
      "no longer ever written) clears too", "wan_link:0" in cleared)
check("the conditions are genuinely healthy now, not just alerted once",
      store.condition("TestRouter4", "wan_failover").get("status") == "ok"
      and store.condition("TestRouter4", "wan_link:1").get("status") == "ok")

# Same idea, but the check is still ON — only the LINK COUNT dropped to 1,
# so per-link backup checks can't mean anything anymore (nothing to compare
# against), while wan_failover itself is left alone (still meaningful).
dev5 = mkdev("TestRouter5", wan=WanConfig(links=[
    WanEndpoint(interface="ether1", gateway="1.1.1.1", name="Main"),
]), checks={**DEFAULT_CHECKS, "wan_failover": True})
for key in ("wan_link:1", "wan_link:2"):
    store.condition("TestRouter5", key).update(
        {"status": "problem", "since": 1_000_000.0})
single_link_routes = {"route": [
    {"dst-address": "0.0.0.0/0", "gateway": "1.1.1.1", "distance": "1",
     "active": "true", "gateway-status": "1.1.1.1 reachable via ether1"},
]}
a = run(WanCheck(), single_link_routes, dev5, store)
cleared5 = {al.key for al in a if al.recovery}
check("only 1 link configured now: stale wan_link:N entries clear",
      "wan_link:1" in cleared5 and "wan_link:2" in cleared5)

# Confirmed live via the superadmin diagnostics report: with failover ON
# and multiple links configured (the normal, common case — not either of
# the two scenarios above), a "wan_link:0" condition from before the
# primary was excluded from this loop stayed frozen at "problem" for over
# two weeks on three separate real devices, with an empty title, because
# nothing in either branch above ever re-evaluates it in this state.
# Same for any index beyond the current link count (a backup uplink that
# was since removed).
dev9 = mkdev("TestRouter9", wan=WanConfig(links=[
    WanEndpoint(interface="ether1", gateway="1.1.1.1", name="Main"),
    WanEndpoint(interface="lte1", gateway="10.0.0.1", name="Backup"),
    WanEndpoint(interface="lte2", gateway="10.0.0.2", name="Link3"),
]), checks={**DEFAULT_CHECKS, "wan_failover": True})
for key in ("wan_link:0", "wan_link:5"):
    store.condition("TestRouter9", key).update(
        {"status": "problem", "since": 1_000_000.0})
store.condition("TestRouter9", "wan_link:1").update(
    {"status": "problem", "since": 1_000_000.0})
three_link_routes = {"route": [
    {"dst-address": "0.0.0.0/0", "gateway": "1.1.1.1", "distance": "1",
     "active": "true", "gateway-status": "1.1.1.1 reachable via ether1"},
    {"dst-address": "0.0.0.0/0", "gateway": "10.0.0.1", "distance": "2",
     "active": "false", "gateway-status": "10.0.0.1 unreachable via lte1"},
    {"dst-address": "0.0.0.0/0", "gateway": "10.0.0.2", "distance": "3",
     "active": "true", "gateway-status": "10.0.0.2 reachable via lte2"},
]}
a = run(WanCheck(), three_link_routes, dev9, store)
cleared9 = {al.key for al in a if al.recovery}
check("wan_link:0 (never written while failover manages 2+ links — the "
      "primary is covered by wan_failover instead) clears even though "
      "failover is ON and there's more than one link",
      "wan_link:0" in cleared9)
check("wan_link:5 (beyond the 3 currently configured links — a removed "
      "backup uplink) clears too",
      "wan_link:5" in cleared9)
check("a genuinely in-range, still-relevant wan_link:1 is NOT swept up by "
      "this clearing — it gets re-evaluated normally instead (still down "
      "here, so it stays a problem, not incorrectly cleared)",
      "wan_link:1" not in cleared9
      and store.condition("TestRouter9", "wan_link:1").get("status") == "problem")

print("Resources (reboot / CPU):")
run(ResourceCheck(), {"resource": [{"uptime": "1h", "cpu-load": "5",
    "version": "7.14", "total-memory": "1000", "free-memory": "800"}],
    "health": []}, dev, store)  # seed uptime/version
a = run(ResourceCheck(), {"resource": [{"uptime": "1m", "cpu-load": "5",
    "version": "7.14", "total-memory": "1000", "free-memory": "800"}],
    "health": []}, dev, store)
check("uptime went backwards -> reboot", "reboot" in keys(a))
a = run(ResourceCheck(), {"resource": [{"uptime": "2m", "cpu-load": "98",
    "version": "7.14", "total-memory": "1000", "free-memory": "800"}],
    "health": []}, dev, store)
check("CPU 98% -> cpu CRITICAL",
      any(k == "cpu" and al.severity.label == "CRITICAL"
          for k, al in zip(keys(a), a)))

print("Interfaces:")
run(InterfaceCheck(), {"interface": [{"name": "ether1", "type": "ether",
    "running": "true", "disabled": "false", "link-downs": "0"}]},
    dev, store)  # seed
# A port that has carried a link (link-downs>0) and is now down -> a real fault.
a = run(InterfaceCheck(), {"interface": [{"name": "ether1", "type": "ether",
    "running": "false", "disabled": "false", "link-downs": "1"}]}, dev, store)
check("link down (in use) -> iface_down WARNING",
      any(k.startswith("iface_down") for k in keys(a)))
# A spare ether port: down, never up, no IP, no comment -> nothing plugged in,
# so it must NOT raise a problem.
a = run(InterfaceCheck(), {"interface": [{"name": "ether9", "type": "ether",
    "running": "false", "disabled": "false", "link-downs": "0"}]}, dev, store)
check("spare/unplugged port -> no iface_down",
      not any(k.startswith("iface_down:ether9") for k in keys(a)))
# Same spare port but carrying an IP -> configured, so a down link IS a fault.
a = run(InterfaceCheck(), {"interface": [{"name": "ether9", "type": "ether",
    "running": "false", "disabled": "false", "link-downs": "0"}],
    "ip_address": [{"interface": "ether9", "address": "192.0.2.1/24",
                    "disabled": "false"}]}, dev, store)
check("configured port (has IP) down -> iface_down WARNING",
      any(k.startswith("iface_down:ether9") for k in keys(a)))

print("Security (dedup + first-run seeding):")
log1 = {"log": [{"time": "10:00:00", "topics": "system,error,account",
    "message": "login failure for user admin from 203.0.113.9 via ssh"}],
    "history": [], "active": []}
a = run(SecurityCheck(), log1, dev, store)
check("first run seeds, no alert", a == [])
a = run(SecurityCheck(), log1, dev, store)
check("same line again -> still no alert (dedup)", a == [])
log2 = {"log": log1["log"] + [{"time": "10:05:00",
    "topics": "system,error,account",
    "message": "login failure for user admin from 203.0.113.9 via ssh"}],
    "history": [], "active": []}
a = run(SecurityCheck(), log2, dev, store)
check("new failed login -> exactly one alert", len(a) == 1
      and a[0].severity.label == "WARNING")

print("Learned baseline engine:")
bstore = {}
bl = Baseline(bstore, alpha=0.3, warmup=5, scheme="global")
for _ in range(6):
    bl.update(10, 1_000_000)
warm = bl.score(10, 1_000_000)
check("baseline warms up", warm["warm"] is True)
spike = bl.score(40, 1_000_000)
check("spike flagged high", is_high(spike, 40, floor=5, min_ratio=1.5, z=3))
check("normal value not flagged",
      not is_high(bl.score(11, 1_000_000), 11, floor=5, min_ratio=1.5, z=3))
check("below-floor never flagged",
      not is_high(spike, 3, floor=5, min_ratio=1.5, z=3))

print("Device-count anomaly:")
def leases(n):
    return {"dhcp_lease": [{"status": "bound",
            "mac-address": f"AA:BB:CC:00:{i // 256:02X}:{i % 256:02X}"}
            for i in range(n)]}
cc_dev = mkdev("cc", client_count_sources=["dhcp"],
               thresholds={"baseline_warmup": 3, "baseline_buckets": "global",
                           "baseline_z": 2, "client_min_count": 5,
                           "client_count_ratio": 1.5})
cc_store = StateStore("cc")
a = drive(ClientCountCheck(), cc_dev, cc_store, [leases(10)] * 4 + [leases(40)])
check("device-count spike -> alert", "client_count" in keys(a)
      and a[0].facts.get("count") == 40)
a = drive(ClientCountCheck(), cc_dev, StateStore("cc2"), [leases(10)] * 6)
check("steady device count -> no alert", a == [])

print("WAN throughput anomaly:")
def ifrow(rx):
    return {"interface": [{"name": "ether1", "type": "ether", "running": "true",
            "disabled": "false", "rx-byte": str(int(rx)), "tx-byte": "0"}]}
# 1 Mbit/s steady (1.25 MB / 10s) then a jump to 100 Mbit/s.
rxs = [0, 1.25e6, 2.5e6, 3.75e6, 5.0e6, 6.25e6, 131.25e6]
wt_dev = mkdev("wt", traffic_interfaces=["ether1"],
               thresholds={"baseline_warmup": 3, "baseline_buckets": "global",
                           "baseline_z": 2, "traffic_floor_mbit": 1,
                           "traffic_ratio": 1.5})
a = drive(WanTrafficCheck(), wt_dev, StateStore("wt"), [ifrow(v) for v in rxs])
check("throughput spike -> alert",
      any(k.startswith("wan_traffic:ether1:rx") for k in keys(a)))

# The WAN uplinks editor's typed Interface text ("Wikiworx") can differ in
# case from the router's actual interface name ("wikiworx") for the same
# link — this must not silently drop that link's throughput samples.
def ifrow_case(rx):
    return {"interface": [{"name": "wikiworx", "type": "ether", "running": "true",
            "disabled": "false", "rx-byte": str(int(rx)), "tx-byte": "0"}]}
wt_dev2 = mkdev("wt2", traffic_interfaces=["Wikiworx"],
                thresholds={"baseline_warmup": 3, "baseline_buckets": "global",
                            "baseline_z": 2, "traffic_floor_mbit": 1,
                            "traffic_ratio": 1.5})
wt2_store = StateStore("wt2")
WanTrafficCheck().run(snap(**ifrow_case(0)), wt_dev2,
                      CheckContext(wt_dev2.name, wt2_store, now=1_000_000.0))
ctx3 = CheckContext(wt_dev2.name, wt2_store, now=1_000_010.0)
WanTrafficCheck().run(snap(**ifrow_case(1.25e6)), wt_dev2, ctx3)
check("case-mismatched interface (Wikiworx vs wikiworx) records a sample",
      any(m == "rx_bps" and lab == "Wikiworx" for m, _, lab in ctx3.samples))

print("Per-client top-talker:")
def queue(total):
    return {"queue_simple": [{"name": "pc1", "target": "192.168.88.10",
            "bytes": f"0/{int(total)}"}], "kid_control": []}
# 6 Mbit/s steady (7.5 MB / 10s) then a jump to 50 Mbit/s.
totals = [0, 7.5e6, 15e6, 22.5e6, 30e6, 37.5e6, 100e6]
cu_dev = mkdev("cu", thresholds={"baseline_warmup": 3, "baseline_z": 2,
                                 "client_floor_mbit": 5, "client_usage_ratio": 2})
a = drive(ClientUsageCheck(), cu_dev, StateStore("cu"), [queue(t) for t in totals])
check("top-talker spike -> alert", any(k == "client_usage:pc1" for k in keys(a))
      and "Top-talker" in (a[0].title if a else ""))

print("Email rendering:")
smtp = SmtpConfig(host="localhost", to_addrs=["it@example.com"])
notifier = EmailNotifier(smtp)
from mikromon.alert import Alert, Severity
sample = [
    Alert("TestRouter", "wan_failover", Severity.WARNING,
          "WAN failover — now on BACKUP uplink (lte1)",
          cause="Primary uplink 1.1.1.1 unreachable."),
    Alert("TestRouter", "reboot", Severity.CRITICAL, "Router rebooted",
          cause="Uptime counter went backwards."),
]
text = notifier._plain(sample)
html = notifier._html(sample)
check("plain text contains 'Why'", "Why" in text and "BACKUP" in text)
check("html contains color-coded entry", "border-left" in html and "Router rebooted" in html)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)} check(s): {', '.join(FAILS)}")
    sys.exit(1)
print("ALL SELF-TESTS PASSED")
