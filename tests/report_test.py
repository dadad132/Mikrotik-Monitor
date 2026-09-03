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

from mikromon.alert import Alert, Severity
from mikromon.alert_log import AlertLog
from mikromon.auth import AuthStore
from mikromon.config import SmtpConfig
from mikromon.devices_store import DevicesStore
from mikromon.notify import org_email
from mikromon.notify.org_email import (OrgEmailNotifier, _build_report,
                                       _event_line, _pair_events,
                                       _should_notify)

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
        "reachability": {"status": "ok"},
        "wan_link:1": {"status": "problem", "title": "Backup WAN uplink is DOWN",
                       "since": T0 + 2000, "severity": 20},
    }, "facts": {"identity": "R1", "model": "hAP ac2", "version": "7.14"}},
    "R2": {"conditions": {"reachability": {"status": "ok"}},
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

print("_should_notify: a recovery alert for a WAN condition is not filtered out:")
problem_alert = Alert("R1", "wan_failover", Severity.WARNING,
                      "Primary WAN \"Main\" is DOWN — running on backup \"Backup\"",
                      recovery=False, ts=T0)
recovery_alert = Alert("R1", "wan_failover", Severity.INFO,
                       "WAN restored — back on primary uplink Main",
                       recovery=True, ts=T0 + 900)
check("the DOWN (problem) alert passes the notify filter",
      _should_notify(problem_alert))
check("the RESTORED (recovery) alert ALSO passes the notify filter — same "
      "key, only severity/recovery differ, neither of which _should_notify "
      "checks", _should_notify(recovery_alert))

# Reported live: alerts arrived every time a WAN uplink dropped and never
# when one came back. Recoveries were emitted as INFO, notifiers filter on
# `severity >= min_severity`, and config.example.yaml ships min_severity as
# WARNING -- so every "back online" was discarded before it reached anyone.
print("a recovery reaches whoever was told about the problem:")
import tempfile as _tf
from mikromon.state import StateStore as _SS
from mikromon.context import CheckContext as _CC
from mikromon.notify import render as _render
from mikromon.notify.base import Notifier as _N


class _Chan(_N):
    name = "chan"
    def __init__(self, min_sev): self.min_severity = min_sev
    def send(self, alerts): pass


def _run(problem_sev, min_sev):
    """Drive one condition down and back up; return what a channel delivers."""
    st = _SS(os.path.join(_tf.mkdtemp(), "s.json")).load()
    chan, out, now = _Chan(min_sev), [], [1000.0]
    for healthy in (False, False, True, True):
        now[0] += 60
        ctx = _CC("R1", st, now=now[0], default_confirm=2)
        ctx.transition("wan_failover", healthy=healthy, severity=problem_sev,
                       title="Primary WAN is DOWN",
                       recovery_title="WAN restored")
        out += [a for a in ctx.alerts if chan.applicable([a])]
    return [("recovery" if a.recovery else "problem") for a in out]


check("with the shipped min_severity of WARNING, a WARNING problem and its "
      "recovery are BOTH delivered — an alert channel that only ever reports "
      "failures teaches people that no news means nothing happened",
      _run(Severity.WARNING, Severity.WARNING) == ["problem", "recovery"])
check("...and the same holds for a CRITICAL problem",
      _run(Severity.CRITICAL, Severity.WARNING) == ["problem", "recovery"])
check("a channel that never reported the problem is not told it is resolved "
      "either — the recovery inherits the problem's severity, so filtering "
      "stays consistent in both directions",
      _run(Severity.WARNING, Severity.CRITICAL) == [])
check("the recovery still reads as RESOLVED rather than by its inherited "
      "severity, so raising it does not make an all-clear look like an alarm",
      "RESOLVED" in _render.subject("[MikroMon]", [recovery_alert]))

print("OrgEmailNotifier.send(): a recovery alert is actually delivered, "
      "not silently dropped:")
sent = []


def _fake_smtp_send(smtp_cfg, msg):
    sent.append(msg)


_orig_smtp_send = org_email._smtp_send
org_email._smtp_send = _fake_smtp_send
try:
    tmp2 = tempfile.mkdtemp()
    adb = os.path.join(tmp2, "auth.db")
    wdb = os.path.join(tmp2, "devices.db")
    auth = AuthStore(adb)
    org_id = auth.signup("owner@acme.test", "password123", "Acme")
    auth.set_alert_emails(org_id, ["it@acme.test"])
    auth.close()
    ds = DevicesStore(wdb)
    ds.upsert({"name": "R1", "host": "10.0.0.1"}, {}, org_id=org_id)
    ds.close()

    smtp_cfg = SmtpConfig(host="smtp.example.test", port=587,
                         from_addr="alerts@example.test")
    notifier = OrgEmailNotifier(smtp_cfg, adb, wdb)

    notifier.send([problem_alert])
    check("the DOWN alert is actually delivered (one email sent)",
          len(sent) == 1 and "To" in sent[0]
          and sent[0]["To"] == "it@acme.test")

    notifier.send([recovery_alert])
    check("the RESTORED alert is ALSO delivered — a second, separate email, "
          "not silently dropped after the first",
          len(sent) == 2)
    check("the recovery email's subject is tagged RESOLVED, not a severity "
          "label", "RESOLVED" in sent[1]["Subject"])

    # Alert email is the part of this product customers actually feel. A
    # suspension that left it running would be one they never notice: locked
    # out of the site, still being told their WAN dropped.
    from mikromon.billing import BillingStore
    bdb = os.path.join(tmp2, "billing.db")
    bstore = BillingStore(bdb)
    bstore.set_plan(org_id, "d5")
    billed = OrgEmailNotifier(smtp_cfg, adb, wdb, billing_db=bdb)
    billed.send([problem_alert])
    check("a company in good standing still gets its alerts when billing is "
          "wired in", len(sent) == 3)

    bstore.suspend(org_id)
    billed.send([problem_alert])
    check("a suspended company stops receiving alerts, so the suspension is "
          "something they actually notice",
          len(sent) == 3)

    bstore.unsuspend(org_id)
    billed.send([problem_alert])
    check("...and alerts resume the moment they are restored, with no "
          "reconfiguration", len(sent) == 4)

    bstore.suspend(org_id)
    bstore.db.close()
    os.remove(bdb)
    billed.send([problem_alert])
    check("if the billing db cannot be read the alert still goes out -- a "
          "real outage is worth more than this filter",
          len(sent) == 5)
finally:
    org_email._smtp_send = _orig_smtp_send

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL REPORT TESTS PASSED")
