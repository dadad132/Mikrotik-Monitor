"""A router with a dead uplink is neither Healthy nor Offline.

Reported from the dashboard: a site running on its backup line sat in the
list saying "Healthy" with a silent grey alert count beside it. Nothing about
the row said the site had lost its redundancy.

The status was two-valued on purpose, and for CPU or temperature that
reasoning still holds -- most warnings are the router behaving correctly, and
an amber badge for that teaches people to ignore amber. A lost WAN uplink is
different in kind: the customer is paying for two lines and running on one.

Run:  ./.venv/Scripts/python.exe tests/dash_status_test.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon.web import _severity, _dash_device_rows, _DASH_STATUS_BADGE

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


def dev(name, up, *problems):
    return {"device": name, "up": up,
            "problems": [{"key": k, "level": "warn", "since": 0}
                         for k in problems]}


print("\nWhat counts as Partial")

check("a router running on its backup line is Partial, not Healthy -- this "
      "is the case the middle state exists for",
      _severity(dev("B", True, "wan_failover")) == "warn")
check("a failed BACKUP uplink is Partial too: the site is one fault from "
      "being offline and nothing else would say so",
      _severity(dev("C", True, "wan_link:1")) == "warn")
check("a router with nothing wrong is Healthy",
      _severity(dev("A", True)) == "ok")
check("a router that cannot be reached is Offline, and that still outranks "
      "everything else",
      _severity(dev("E", False, "wan_failover", "reachability")) == "crit")

print("\nWhat deliberately does NOT trigger it")

for key in ("cpu_anomaly", "memory_anomaly", "temperature", "storage",
            "config_unsaveable", "api_error"):
    check(f"'{key}' alone leaves the router Healthy -- widening this is how "
          f"the middle state stops meaning anything",
          _severity(dev("D", True, key)) == "ok")

print("\nThe row itself")

html = _dash_device_rows([
    dev("Alpha", True),
    dev("Bravo", True, "wan_failover", "wan_link:1"),
    dev("Charlie", False, "reachability"),
])

check("Partial is shown as a badge, spelled out",
      ">Partial<" in html and ">Healthy<" in html and ">Offline<" in html)
check("the alert count is AMBER on a router that is still up -- grey on "
      "grey read as a column heading rather than something to act on",
      'alert-badge warn' in html)
check("...and red only when the router is actually down",
      'alert-badge crit' in html)
check("the count is a LINK to that router's own problems, which is the "
      "question anyone asks next: three what, on which one?",
      'href="/device?name=Bravo#alerts"' in html)
check("...with a title that says what clicking does",
      'open alerts for this router' in html)
check("a router with no alerts shows a dash, not a zero",
      "&mdash;" in html)

print("\nNothing indexes the status with a two-value table any more")

check("every severity has a badge, so a Partial router cannot raise "
      "KeyError while the page renders",
      all(s in _DASH_STATUS_BADGE for s in ("ok", "warn", "crit")))

order = {"crit": 0, "warn": 1, "ok": 2}
check("the list sorts Offline first, then Partial, then the rest",
      [order[_severity(d)] for d in
       (dev("x", False, "reachability"), dev("y", True, "wan_failover"),
        dev("z", True))] == [0, 1, 2])

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL DASHBOARD STATUS TESTS PASSED")
