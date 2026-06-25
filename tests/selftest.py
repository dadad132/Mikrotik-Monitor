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
from mikromon.config import DEFAULT_THRESHOLDS, DeviceConfig, SmtpConfig, WanConfig, WanEndpoint
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
