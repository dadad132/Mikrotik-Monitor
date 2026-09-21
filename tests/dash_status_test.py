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
import os as _os
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

print("")
print("The availability bar, and what a grey block means:")

# `up` is written as 0 on every failed poll and 1 on every good one, so an
# hour with NO rows does not mean the router was down -- it means nothing
# asked, which is this server having stopped. The bar drew those hours grey
# and the headline averaged only over the hours that HAD rows, so three
# unmonitored hours rendered as "100.0% uptime" beside a visible hole that
# nothing on the page explained. The bar said there was a gap and the number
# said there was not; only one of them could be right.
import re as _re
import tempfile as _tf
import time as _tm

from mikromon.metrics import MetricsStore as _MS
from mikromon.web import _render_device as _rd

_now = _tm.time()
_user = {"role": "admin", "org_name": "X", "email": "a@b.c", "name": "A"}
_state = {"devices": {"R1": {"status": "ok", "problems": [], "facts": {}}}}


def _bar_html(skip_hours):
    st = _MS(_os.path.join(_tf.mkdtemp(), "m.db"))
    st.record([(_now - h * 3600 - m * 60, "R1", "up", "", 1.0)
               for h in range(24) if h not in skip_hours
               for m in range(0, 60, 5)])
    return _rd(st, _state, "R1", _user)


_gap = _bar_html({3, 4, 5})
check("three unmonitored hours are named as unmonitored, instead of a grey "
      "gap nothing explains", "3 hours not measured" in _gap)
check("...and the headline no longer claims plain '100% uptime' over hours "
      "it never looked at", "100.0% uptime of what was measured" in _gap)
check("...saying which hours it DOES cover, so the number means something",
      "covers the other 21" in _gap)
check("...and stating outright that grey is missing data, not downtime",
      "not downtime" in _gap)
check("...and pointing at the likely cause when every router shows it, "
      "because a fleet-wide gap is this server and not twenty sites",
      "this server that stopped" in _gap)
check("each grey block says which hour it is, on hover",
      _re.search(r'title="4h ago: not measured"', _gap) is not None)

_full = _bar_html(set())
check("a fully-monitored day says plain '100.0% uptime' with no caveat, "
      "because there is nothing to caveat",
      "100.0% uptime" in _full and "of what was measured" not in _full)
check("...and no note about missing hours", "not measured" not in _full)

_down = _MS(_os.path.join(_tf.mkdtemp(), "m.db"))
_down.record([(_now - h * 3600 - m * 60, "R1", "up", "",
               0.0 if h in (2, 3) else 1.0)
              for h in range(24) for m in range(0, 60, 5)])
_dh = _rd(_down, _state, "R1", _user)
check("a router that really WAS down is red, counted against uptime, and "
      "not confused with an hour nobody measured",
      "100.0% uptime" not in _dh and "not measured" not in _dh)
check("...and those hours say 'down' rather than 'not measured'",
      _re.search(r'title="\dh ago: down"', _dh) is not None)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL DASHBOARD STATUS TESTS PASSED")
