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

print("WAN failover: the PRIMARY link's own route matched via RouterOS's "
      "immediate-gw field (\"<gateway-ip>%<interface>\"), not just "
      "gateway-status text (confirmed live: a genuinely-up, traffic-"
      "carrying primary was reported as failed-over to a garbled "
      "\"<ip>%<interface>\" backup name, because gateway-status had no "
      "\"via <iface>\" text AND the route was plain/unmanaged/no DHCP "
      "entry — the immediate-gw fallback existed but returned the whole "
      "raw zone-id string instead of just the interface part, so it could "
      "never match the configured link):")
dev9 = mkdev("TestRouter9", wan=WanConfig(links=[
    WanEndpoint(interface="ether1-internet", gateway="", name="ZWN 1"),
    WanEndpoint(interface="ether1-backup", gateway="", name="ZWN 2"),
]))
primary_immediate_gw_only = {"route": [
    # No "via <iface>" text, no managed/name comment, and (deliberately)
    # no dhcp_client entry for this interface at all — the ONLY thing that
    # can identify this as the primary link is immediate-gw.
    {"dst-address": "0.0.0.0/0", "gateway": "192.168.63.1", "distance": "1",
     "active": "true", "gateway-status": "192.168.63.1 reachable",
     "immediate-gw": "192.168.63.1%ether1-internet"},
    {"dst-address": "0.0.0.0/0", "gateway": "10.9.9.9", "distance": "2",
     "active": "true", "gateway-status": "10.9.9.9 reachable via ether1-backup"},
]}
a = run(WanCheck(), primary_immediate_gw_only, dev9, store)
check("a genuinely-up PRIMARY found only via immediate-gw raises no false "
      "failover alert", a == [])

primary_immediate_gw_down = {"route": [
    {"dst-address": "0.0.0.0/0", "gateway": "192.168.63.1", "distance": "1",
     "active": "false", "gateway-status": "192.168.63.1 unreachable",
     "immediate-gw": "192.168.63.1%ether1-internet"},
    primary_immediate_gw_only["route"][1],
]}
a = run(WanCheck(), primary_immediate_gw_down, dev9, store)
check("the SAME primary actually failing over is still correctly "
      "detected, not masked by the immediate-gw fallback assuming it's "
      "always fine",
      keys(a) == ["wan_failover"]
      and "ZWN 1" in a[0].title and "ZWN 2" in a[0].title
      # The garbled raw zone-id string must never leak into a human-facing
      # alert title — this is the same _iface_of() fix, applied to the
      # NOW-current backup link's own name, not a raw route field.
      and "%" not in a[0].title)

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

print("a dataset that could not be READ is not the same as bad news:")
_wan_dev = DeviceConfig(
    name="R", host="1.1.1.1",
    wan=WanConfig(links=[WanEndpoint(name="ZWN 1", interface="ether1"),
                         WanEndpoint(name="ZWN 2", interface="ether2")]),
    checks=dict(DEFAULT_CHECKS), thresholds=dict(DEFAULT_THRESHOLDS))


class _CountingCtx:
    def __init__(self):
        self.calls = []
        self.store = type("S", (), {"data": {"devices": {}}})()
        self.device = "R"
        self.now = 0

    def transition(self, key, healthy, **kw):
        self.calls.append((key, healthy))

    def sample(self, *a, **k):
        pass

    def memory(self, n):
        return {}


_failed = Snapshot()
_failed.data["route"] = []
_failed.data["dhcp_client"] = []
_failed.errors["route"] = "timed out"
_c1 = _CountingCtx()
WanCheck().run(_failed, _wan_dev, _c1)
check("a route table that could not be fetched says NOTHING, rather than "
      "reading the empty result as 'this router has no default route' -- "
      "which is how a router that was reachable, answering and routing fine "
      "had every one of its uplinks declared offline",
      _c1.calls == [])

_really_empty = Snapshot()
_really_empty.data["route"] = []
_really_empty.data["dhcp_client"] = []
_c2 = _CountingCtx()
WanCheck().run(_really_empty, _wan_dev, _c2)
check("...while a route table that really IS empty still reports internet "
      "down, so suppressing the unknown case costs no real alert",
      ("internet_down", False) in _c2.calls)

print()

print("\"update available\" needs the router to actually CHECK:")
import time as _time
import types as _ty

import mikromon.engine as _E


class _CmdDev:
    def __init__(self, ok=True):
        self.name = "R"
        self.ok = ok
        self.calls = []

    def run_command(self, path, cmd, **kw):
        self.calls.append((path, cmd))
        return self.ok


class _FactStore:
    def __init__(self):
        self._f = {}

    def facts(self, n):
        return self._f.setdefault(n, {})


_ue = _E.Engine.__new__(_E.Engine)
_ue.state = _FactStore()
_ucfg = _ty.SimpleNamespace(name="R")
_unow = _time.time()

_ud = _CmdDev()
_ue._maybe_check_updates(_ud, _ucfg, _unow)
check("the router is asked to check for a newer RouterOS -- reading "
      "/system/package/update alone can never answer it, because RouterOS "
      "leaves latest-version EMPTY until a check has run, which is why the "
      "Devices page showed a dash for every router",
      _ud.calls == [(("system", "package", "update"), "check-for-updates")])

_ue._maybe_check_updates(_ud, _ucfg, _unow + 60)
check("...but not again on the next poll -- the check is a real request out "
      "to MikroTik from every router, so it is daily rather than per minute",
      len(_ud.calls) == 1)

_ue._maybe_check_updates(_ud, _ucfg, _unow + _E._UPDATE_CHECK_EVERY + 1)
check("...and it does run again a day later", len(_ud.calls) == 2)

_ue.state = _FactStore()
_refuses = _CmdDev(ok=False)
_ue._maybe_check_updates(_refuses, _ucfg, _unow)
_ue._maybe_check_updates(_refuses, _ucfg, _unow + 60)
check("a router that REFUSES the command (an older read-only monitor login) "
      "is still only asked once a day, not hammered every poll",
      len(_refuses.calls) == 1)

print()

print("one stuck device must not freeze the whole fleet's state:")
from concurrent.futures import ThreadPoolExecutor as _TPE

from mikromon.config import AppConfig as _AppCfg

_E._CYCLE_BUDGET_FLOOR = 0.4  # keep the test quick; behaviour is identical


def _bare_engine():
    e = _E.Engine.__new__(_E.Engine)
    e.config = _AppCfg(poll_interval=1, state_file="./_t.json", devices=[])
    e.now_fn = _time.time
    e._in_flight = set()
    e.state = _ty.SimpleNamespace(save=lambda: None, data={},
                                  prune_unknown_devices=lambda *a: None)
    e.devices_store = None
    e.metrics = None
    e.notifiers = []
    e.dry_run = True
    e._grace_seconds = 0
    e._grace_resynced = True
    e._start_ts = 0
    e._pool = _TPE(max_workers=4)
    e.dispatch = lambda b: None
    e._maybe_resync_after_grace = lambda: None
    e._check_scheduled_reports = lambda: None
    return e


_polled = []
_eng = _bare_engine()


def _poll(d):
    if d.name == "Stuck":
        _time.sleep(30)          # far beyond the cycle budget
    _polled.append(d.name)
    return []


_eng._poll_device = _poll
_D = lambda n: _ty.SimpleNamespace(name=n, cfg=_ty.SimpleNamespace(name=n))
_eng.devices = [_D("Stuck"), _D("A"), _D("B")]

_t0 = _time.time()
_eng.run_once()
_elapsed = _time.time() - _t0
check("a cycle gives up on a device that never returns instead of waiting "
      "forever -- state.json is only saved once the cycle ends, so one router "
      "that accepts TCP and then stalls used to freeze the recorded state of "
      "every OTHER device for as long as it hung",
      _elapsed < 5)
check("...while the healthy devices in that same cycle are still polled",
      sorted(_polled) == ["A", "B"])
check("...and the straggler is remembered as still running",
      _eng._in_flight == {"Stuck"})

_polled.clear()
_t0 = _time.time()
_eng.run_once()
check("the next cycle SKIPS the device still stuck rather than stacking a "
      "second poll on it -- re-submitting would pile up threads until the "
      "pool had none left for the healthy routers",
      _time.time() - _t0 < 1 and sorted(_polled) == ["A", "B"])

check("a device that finishes releases its slot, so a one-off slow poll does "
      "not lock that device out of every future cycle",
      "A" not in _eng._in_flight and "B" not in _eng._in_flight)

print()

print("reachability probe (a dropped packet is not a dead router):")
import socket as _s
import types as _t

from mikromon.device import (Device as _Device, _REACH_ATTEMPTS,
                             _REACH_MIN_TIMEOUT)

_tries = {"n": 0}
_real_conn = _s.create_connection


class _Conn:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _flaky(addr, timeout=None):
    _tries["n"] += 1
    if _tries["n"] == 1:
        raise OSError("simulated dropped SYN")
    return _Conn()


_cfg = _t.SimpleNamespace(host="h", api_port=8728, timeout=5, name="R")
_s.create_connection = _flaky
try:
    _ok = _Device(_cfg).reachable()
finally:
    _s.create_connection = _real_conn
check("a dropped SYN followed by a good one still counts as reachable -- "
      "these routers are reached over a UDP tunnel that drops the odd "
      "packet, and asking only once cannot tell that from a dead router",
      _ok is True and _tries["n"] == 2)

_tries["n"] = 0


def _always_down(addr, timeout=None):
    _tries["n"] += 1
    raise OSError("down")


_s.create_connection = _always_down
try:
    _dev = _Device(_cfg)
    _down = _dev.reachable(timeout=0.05)
finally:
    _s.create_connection = _real_conn
check("a router that really is down is still reported down, after a bounded "
      "number of attempts rather than retrying forever",
      _down is False and _tries["n"] == _REACH_ATTEMPTS)
check("...and contributes no latency reading, which would otherwise be the "
      "OS giving-up time rather than a round trip",
      _dev.last_probe_ms is None)

# Retrying must not make a down device SLOWER to give up on. A poll cycle and
# several web handlers walk whole fleets, and the down devices are exactly the
# slow ones -- written naively, the retry doubled that and timed a handler out.
_seen_timeouts = []


def _record_timeout(addr, timeout=None):
    _seen_timeouts.append(timeout)
    raise OSError("down")


_s.create_connection = _record_timeout
try:
    _Device(_t.SimpleNamespace(host="h", api_port=8728, timeout=60,
                               name="R")).reachable()
finally:
    _s.create_connection = _real_conn
check("the attempts SHARE the timeout budget rather than multiplying it, so "
      "retrying costs no extra wall-clock on a device that is really down",
      len(_seen_timeouts) == _REACH_ATTEMPTS
      and abs(sum(_seen_timeouts) - 5.0) < 0.01)

print()

print("poll fetch order (a measurement must not be distorted by the act of "
      "collecting everything else):")
from mikromon.device import _FETCH_LAST, _fetch_order

_poll = {"resource", "identity", "routerboard", "pkg_update", "route",
         "interface", "ip_address", "health", "log", "history", "active",
         "dhcp_client"}
_order = _fetch_order(_poll)
check("/system/resource is fetched FIRST -- cpu-load is a ~1s sample, so "
      "reading it after /log and /system/history reports mikromon's own "
      "polling load instead of the router's (the 'mikromon says 76%, Winbox "
      "says 5%' contradiction: both true, different moments)",
      _order[0] == "resource")
check("the bulk menus are fetched LAST, after every measurement is taken",
      all(_order.index(n) > _order.index("resource")
          for n in _FETCH_LAST if n in _poll))
check("ordering is deterministic -- it used to be set-iteration order, which "
      "Python re-randomises per process, so a device could read high for "
      "weeks, get 'fixed' by an unrelated restart, and regress later",
      _fetch_order(_poll) == _fetch_order(set(reversed(sorted(_poll)))))
check("no dataset is dropped or duplicated by the reordering",
      sorted(_order) == sorted(_poll) and len(_order) == len(_poll))
check("a caller asking for a subset gets only that subset",
      _fetch_order({"log", "resource"}) == ["resource", "log"])
check("an unknown dataset name is passed through rather than silently "
      "swallowed (fetch() is what decides it has no menu)",
      "made_up" in _fetch_order({"made_up", "resource"}))

print()
if FAILS:
    print(f"FAILED: {len(FAILS)} check(s): {', '.join(FAILS)}")
    sys.exit(1)
print("ALL SELF-TESTS PASSED")
