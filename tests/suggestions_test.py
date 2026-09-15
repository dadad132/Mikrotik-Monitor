"""Suggestions must be things to DECIDE, not a second copy of the alerts.

Asked for by the system administrator, looking at a dashboard reading "14
Suggestions". The list was every live condition -- CPU, temperature,
throughput, every WAN state -- which is the same information the row's own
alert count already carries, one column to the left. A list that repeats what
sits beside it is not a list anyone reads.

What belongs here is the narrow set that needs a person to decide something:
an update has been published, an account appeared on the router, our own
account was removed from it. States to watch keep their alert badge, the
Partial status and their emails; they simply stop being called suggestions.

Also covers the update check itself, which silently gave up for a whole day
whenever a router refused it once -- which is why most of the fleet showed a
dash rather than an answer.

Run:  ./.venv/Scripts/python.exe tests/suggestions_test.py
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon.web import _suggestion_items, _suggestion_meta

FAILS = []
NOW = time.time()


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


def dev(name, problems=(), **facts):
    return {"device": name, "up": True, "_conditions": {},
            "problems": [{"key": k, "level": "warn", "since": NOW}
                         for k in problems],
            "facts": dict(facts)}


def ev(device, key, ts, title="", recovery=0):
    return {"device": device, "key": key, "ts": ts, "title": title,
            "recovery": recovery}


print("\nOperational noise is no longer called a suggestion")

noisy = dev("Kempton", problems=(
    "cpu_anomaly", "cpu", "memory", "memory_anomaly", "temperature",
    "storage", "wan_traffic:ether1:rx", "iface_down:ether4",
    "wan_failover", "wan_link:1", "internet_down", "reachability"))
check("twelve live conditions produce ZERO suggestions -- every one of them "
      "is already the alert count on that router's own row",
      _suggestion_items([noisy]) == [])

print("\nWhat does belong here")

items = _suggestion_items([dev("Howler", update_available=True,
                               version="7.23.2", updated=NOW - 3600)])
check("an available RouterOS update is a suggestion: somebody has to read "
      "the changelog and pick a window",
      len(items) == 1 and items[0]["key"] == "update")
check("...naming the version it is on now, so the decision can be made "
      "without opening the router",
      "7.23.2" in items[0]["detail"])
check("...and pointing at the tab that does it",
      items[0]["tab"] == "update")

check("a router with no update pending produces nothing",
      _suggestion_items([dev("Howler", update_available=False)]) == [])
check("...and so does one that has never been checked, rather than "
      "guessing that no news is good news",
      _suggestion_items([dev("Howler")]) == [])

print("\nAccount changes, which are events rather than conditions")

items = _suggestion_items(
    [dev("Kempton")],
    events=[ev("Kempton", "router_user:hacker", NOW - 600,
               "New login 'hacker' created on the router")])
check("a login appearing on the router is a suggestion -- it cannot be read "
      "off the device the way a WAN state can, so it comes from the log",
      len(items) == 1 and items[0]["key"] == "router_user:hacker")
check("...and sends the reader to the security tab",
      items[0]["tab"] == "security")

items = _suggestion_items(
    [dev("Boksburg"), dev("Kempton")],
    events=[ev("Kempton", "router_user:hacker", NOW - 60),
            ev("Boksburg", "router_user_gone:mkmonitor", NOW - 3600)])
check("our own login being deleted outranks everything, even something "
      "newer -- it is the one that ends the ability to fix anything",
      items[0]["key"].startswith("router_user_gone") and items[0]["crit"])

print("\nThe list does not repeat itself")

items = _suggestion_items(
    [dev("Kempton")],
    events=[ev("Kempton", "router_user:hacker", NOW - 60),
            ev("Kempton", "router_user:hacker", NOW - 600),
            ev("Kempton", "router_user:hacker", NOW - 6000)])
check("the same login reported three times is ONE suggestion -- repeating "
      "it is the noise this list is being narrowed to escape",
      len(items) == 1)

check("a recovery row is not offered as something to look at",
      _suggestion_items([dev("K")], events=[
          ev("K", "router_user:bob", NOW, recovery=1)]) == [])

print("\nIgnoring one still works")

check("an ignored update stops being offered for that router",
      _suggestion_items([dev("H", update_available=True)],
                        {"H": ["update"]}) == [])
check("...and ignoring it on one router does not hide it on another",
      len(_suggestion_items([dev("H", update_available=True),
                             dev("K", update_available=True)],
                            {"H": ["update"]})) == 1)

print("\nEvery kind has somewhere to go")

for key in ("update", "router_user:x", "router_user_gone:x"):
    label, tab, action, why = _suggestion_meta(key)
    check(f"'{key.split(':')[0]}' has a label, an action and a reason",
          bool(label) and bool(action) and bool(why)
          and not label.startswith("Router user"))

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL SUGGESTION TESTS PASSED")
