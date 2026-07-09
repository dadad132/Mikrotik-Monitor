"""Offline tests for the alert-history log and the periodic Account-page
status report: AlertLog persistence, problem/recovery event pairing across a
time window, and _build_report's period summary (vs. the live-snapshot
fallback when alert_log_db isn't configured).

Run:  ./.venv/Scripts/python.exe tests/report_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon.alert_log import AlertLog
from mikromon.notify.org_email import _build_report, _event_line, _pair_events

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


T0 = 1_000_000.0
tmp = tempfile.mkdtemp()

print("AlertLog: append + between + prune:")
alog = AlertLog(os.path.join(tmp, "alert_log.db"))
alog.append("R1", "wan_failover", "Primary WAN \"Main\" is DOWN", 20, False, ts=T0)
alog.append("R1", "wan_failover", "Resolved: Primary WAN is DOWN", 10, True, ts=T0 + 900)
alog.append("R1", "wan_link:1", "Backup WAN uplink \"Backup\" is DOWN", 20, False, ts=T0 + 2000)
alog.append("R2", "internet_down", "Internet DOWN", 30, False, ts=T0 + 500)

rows_r1 = alog.between(["R1"], T0 - 100, T0 + 3000)
check("between() returns only the requested device's rows, oldest first",
      [r["key"] for r in rows_r1] == ["wan_failover", "wan_failover", "wan_link:1"]
      and all(r["device"] == "R1" for r in rows_r1))
check("between() excludes other devices",
      len(alog.between(["R2"], T0 - 100, T0 + 3000)) == 1)
check("between() respects the since/until window",
      alog.between(["R1"], T0 + 1000, T0 + 3000) == [
          r for r in rows_r1 if r["ts"] >= T0 + 1000])
check("between() with no devices is an empty list", alog.between([], T0, T0 + 1) == [])

alog.prune(keep_days=0)
check("prune(0) removes everything older than now",
      alog.between(["R1"], T0 - 100, T0 + 3000) == [])

print("_pair_events: problem/recovery pairing:")
resolved = [
    {"key": "wan_failover", "title": "Primary WAN is DOWN", "ts": T0, "recovery": False},
    {"key": "wan_failover", "title": "Resolved", "ts": T0 + 900, "recovery": True},
]
events = _pair_events(resolved)
check("a resolved problem becomes one event with start+end",
      len(events) == 1 and events[0]["start"] == T0 and events[0]["end"] == T0 + 900
      and events[0]["title"] == "Primary WAN is DOWN")

ongoing = resolved + [
    {"key": "wan_link:1", "title": "Backup WAN uplink is DOWN", "ts": T0 + 2000,
     "recovery": False},
]
events2 = _pair_events(ongoing)
still_open = [e for e in events2 if e["end"] is None]
check("a problem with no recovery row is still open (end=None)",
      len(still_open) == 1 and still_open[0]["start"] == T0 + 2000)

already_in_progress = [
    {"key": "wan_failover", "title": "Resolved", "ts": T0 + 50, "recovery": True},
]
events3 = _pair_events(already_in_progress)
check("a recovery with no matching open problem started before the window "
      "(start=None)", events3[0]["start"] is None and events3[0]["end"] == T0 + 50)

print("_event_line: human-readable formatting:")
resolved_line = _event_line({"title": "Primary WAN is DOWN", "start": T0,
                             "end": T0 + 900}, until=T0 + 5000)
check("a resolved event shows start, end and duration",
      "Primary WAN is DOWN" in resolved_line and "15m" in resolved_line)
ongoing_line = _event_line({"title": "Backup down", "start": T0, "end": None},
                           until=T0 + 3600)
check("an ongoing event says still ongoing with elapsed time",
      "still ongoing" in ongoing_line and "1h" in ongoing_line)
early_line = _event_line({"title": "Resolved", "start": None, "end": T0 + 50},
                         until=T0 + 5000)
check("an event that started before the window says so",
      "before this period" in early_line)

print("_build_report: period summary vs. live-snapshot fallback:")
state_data = {"devices": {
    "R1": {"conditions": {
        "reachability": {"healthy": True},
        "wan_link:1": {"healthy": False, "title": "Backup WAN uplink is DOWN",
                       "since": T0 + 2000, "severity": 20},
    }, "facts": {"identity": "R1", "model": "hAP ac2", "version": "7.14"}},
    "R2": {"conditions": {"reachability": {"healthy": True}},
           "facts": {"identity": "R2"}},
}}
events_by_device = {
    "R1": [
        {"key": "wan_failover", "title": "Primary WAN is DOWN", "ts": T0,
         "recovery": False, "severity": 20},
        {"key": "wan_failover", "title": "Resolved", "ts": T0 + 900,
         "recovery": True, "severity": 10},
        {"key": "wan_link:1", "title": "Backup WAN uplink is DOWN", "ts": T0 + 2000,
         "recovery": False, "severity": 20},
    ],
    "R2": [],
}
subj, txt, html = _build_report(
    "Acme", ["R1", "R2"], state_data, "weekly", "[EasyMikrotik]",
    since=T0 - 100, until=T0 + 5000, events_by_device=events_by_device)
check("subject names the org and schedule", "Acme" in subj and "Weekly" in subj)
check("R1's resolved failover event appears with its duration",
      "Primary WAN is DOWN" in txt and "15m" in txt)
check("R1's still-open backup-down event appears as ongoing",
      "Backup WAN uplink is DOWN" in txt and "ongoing" in txt)
check("R2 with no events is reported clean",
      "No WAN issues this period" in txt)
check("no mention of history being unavailable when it IS available",
      "history logging isn't enabled" not in txt.lower())
check("html body mirrors the same content", "Primary WAN is DOWN" in html)

subj2, txt2, html2 = _build_report(
    "Acme", ["R1"], state_data, "weekly", "[EasyMikrotik]",
    since=T0 - 100, until=T0 + 5000, events_by_device=None)
check("without alert_log configured, falls back to the live snapshot",
      "Backup WAN uplink is DOWN" in txt2  # still-unhealthy condition shown
      and "history" in txt2.lower())
check("the resolved (no-longer-active) failover is NOT in the fallback "
      "snapshot (it can only see live state, not history)",
      "Primary WAN is DOWN" not in txt2)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL REPORT TESTS PASSED")
