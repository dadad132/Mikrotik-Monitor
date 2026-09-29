"""Three months suspended, and nobody has said anything either way.

A suspended account keeps its plan, its device cap and every configuration
push ever made to its routers, so that a customer who pays is working again
in seconds. That is the right trade at a week. At three months it is a
filing cabinet nobody is paying for, and a customer who may have left
without anyone here noticing.

So the owner gets asked. And because "we are waiting on funds" is the one
answer that makes removal the wrong move, it has to be an answer somebody
can give -- recorded as a hold that stops the clock, and that expires, so
replying once is not a way to keep an account for ever.

The line this file guards hardest: NOTHING here deletes anything. The letter
says an account will eventually be removed, because that is what makes
somebody reply, but the removal is a person's decision made in the panel. An
automatic deletion of a customer's history on a timer has a silent and
permanent failure mode, and the thing it saves is disk space.

Run:  python tests/dormant_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import billing as B
from mikromon import web_auth
from mikromon.notify.org_email import _build_dormant_notice

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


DAY = 86400.0
NOW = time.time()


def suspended(store, org_id, days):
    store.set_plan(org_id, "d5")
    store.suspend(org_id)
    store._upsert(org_id, suspended_since=NOW - days * DAY)


def store():
    return B.BillingStore(os.path.join(tempfile.mkdtemp(), "b.db"))


print("When a suspension becomes a question")

st = store()
suspended(st, 1, 100)
suspended(st, 2, 10)
suspended(st, 3, 89)
due = [d["org_id"] for d in st.orgs_dormant(NOW)]
check("an account suspended past three months is raised",
      due == [1])
check("...and one suspended last week is not: an invoice a fortnight late "
      "is a normal thing that resolves itself", 2 not in due)
check("...nor one a day short of the line, because the line is a line",
      3 not in due)

check("how long it has been off comes back with it, since three months and "
      "three years are different conversations",
      round(st.orgs_dormant(NOW)[0]["days"]) == 100)

print("\nThe answer that stops the clock")

st = store()
suspended(st, 1, 120)
st.set_funds_hold(1)
check("a company that says it is waiting on funds is left alone -- the one "
      "answer that makes removing an account the wrong move",
      st.orgs_dormant(NOW) == [])
check("...but it still appears in the panel's list, marked as held, or the "
      "list reads shorter than the truth",
      [d["org_id"] for d in st.all_dormant(NOW)] == [1]
      and st.all_dormant(NOW)[0]["on_hold"])
check("the hold EXPIRES, so replying once is not a way to keep an account "
      "for ever",
      [d["org_id"] for d in
       st.orgs_dormant(NOW + (B.FUNDS_HOLD_DAYS + 1) * DAY)] == [1])

print("\nAsked again, not asked once")

st = store()
suspended(st, 1, 100)
st.mark_dormant_warned(1, NOW)
check("having been asked, a company is not asked again tomorrow",
      st.orgs_dormant(NOW + DAY) == [])
check("...but IS a month later, because one email can be missed -- which is "
      "the whole reason the offline reminder exists too",
      [d["org_id"] for d in
       st.orgs_dormant(NOW + (B.DORMANT_REMIND_DAYS + 1) * DAY)] == [1])

print("\nComing back clears everything")

st = store()
suspended(st, 1, 200)
st.mark_dormant_warned(1, NOW)
st.set_funds_hold(1)
st.unsuspend(1)
row = st.get(1)
check("a company that pays is active again, with the whole dormancy clock "
      "wiped rather than left to fire later",
      row["status"] == "active" and row["suspended_since"] is None
      and row["dormant_warned"] is None and row["funds_hold_until"] is None)

st = store()
suspended(st, 1, 100)
st.suspend(1)
check("re-suspending an account that was never reactivated does NOT restart "
      "the clock, or an account can be kept young by suspending it again",
      round((NOW - st.get(1)["suspended_since"]) / DAY) == 100)

print("\nThe letter")

_subj, _txt, _htm = _build_dormant_notice(
    "Alpha Freight", 104, "[mm]", "billing@easymikrotik.com", devices=5,
    hold_days=60)
check("the subject says how long, which is the part that gets read",
      "3 months" in _subj and "Alpha Freight" in _subj)
check("it says their data is still there, because somebody who thinks it is "
      "already gone has no reason to reply",
      "still here" in _txt)
check("it offers the waiting-on-funds answer explicitly, which is the one "
      "that matters to a customer who intends to pay and cannot this month",
      "Waiting on funds" in _txt and "60 days" in _txt)
check("...and a way to say they are finished, so a customer who has left "
      "can say so instead of being chased", "Finished with it" in _txt)
check("it names somewhere to reply", "billing@easymikrotik.com" in _txt)
check("it promises NOTHING is deleted automatically, because that is true "
      "and because a letter naming a deadline the system will not honour "
      "teaches people to ignore the next one",
      "Nothing is deleted automatically" in _txt)
check("it names no date for deletion, since no date exists",
      not any(w in _txt.lower() for w in ("will be deleted on",
                                          "deleted on ", "by 30 ")))
check("the html says the same things", "Waiting on funds" in _htm
      and "Nothing is deleted automatically" in _htm)

print("\nThe panel, where the decision is actually made")

rows = [{"org_id": 1, "plan": "d5", "device_limit": 5,
         "suspended_since": NOW - 120 * DAY, "funds_hold_until": None,
         "dormant_warned": NOW - 5 * DAY, "on_hold": False, "days": 120},
        {"org_id": 2, "plan": "d25", "device_limit": 25,
         "suspended_since": NOW - 200 * DAY,
         "funds_hold_until": NOW + 30 * DAY,
         "dormant_warned": None, "on_hold": True, "days": 200}]
box = web_auth._dormant_box(rows, {1: "Alpha Freight", 2: "Bravo Ltd"}, "tok")
check("both are listed, held or not", "Alpha Freight" in box
      and "Bravo Ltd" in box)
check("...with how long each has been off", "4 months" in box
      and "6 months" in box)
check("...and which have already been asked",
      "asked" in box.lower() and "waiting on funds until" in box)
check("the panel states plainly that nothing is deleted automatically, so "
      "nobody assumes the list is a queue that empties itself",
      "Nothing is deleted automatically" in box)
check("...and offers the button that records a customer's reply",
      "funds-hold" in box)
check("an empty list renders nothing at all rather than an empty table",
      web_auth._dormant_box([], {}, "tok") == "")

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL DORMANT ACCOUNT TESTS PASSED")
