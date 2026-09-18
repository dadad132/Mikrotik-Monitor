"""Changing packet: on the 28th, or now for the difference.

Two things were wrong and one was missing.

Periods advanced by `months * 30 * 86400`. Thirty-day months are not months:
a packet starting 31 January reached 26 January a year later, so every
customer got about five free days a year and their renewal date wandered
backwards out from under them. Everyone now renews on the 28th -- the only
late-month day that exists in February, so there is no clamping rule and
therefore no clamping bug.

And there was no way to change packet at all unless card payment was
switched on. The ladder listed twenty prices and rendered a button on none of
them, so a customer who wanted a bigger packet had to email somebody.

Run:  python tests/plan_change_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import billing as B
from mikromon import web_auth

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


def fresh():
    return B.BillingStore(os.path.join(tempfile.mkdtemp(), "b.db"))


def d(ts):
    return time.strftime("%d %b %Y", time.localtime(ts))


DAY = 86400.0
SMALL, BIG = B.plan_by_name("d5"), B.plan_by_name("d25")

print("\nEverybody renews on the 28th, February included")

check("the billing day is the 28th", B.BILLING_DAY == 28)

for start in ("2026-01-31", "2026-02-27", "2026-02-28", "2026-12-31",
              "2027-01-01"):
    t = time.mktime(time.strptime(start, "%Y-%m-%d"))
    nxt = B.next_billing_date(t)
    check(f"signing up {start} renews on a 28th ({d(nxt)})",
          time.localtime(nxt).tm_mday == 28 and nxt > t)

# The whole point: a year of renewals lands on the same day it started.
t = B.next_billing_date(time.mktime(time.strptime("2026-01-31", "%Y-%m-%d")))
start_day = time.localtime(t).tm_mday
for _ in range(12):
    t = B.add_billing_months(t, 1)
check("twelve renewals later it is still the 28th, in the same month it "
      "started -- 30-day steps drifted this back five days a year, which is "
      "five days of free service per customer per year",
      time.localtime(t).tm_mday == start_day
      and time.strftime("%b %Y", time.localtime(t)) == "Feb 2027")

check("February is not a special case, because the 28th of it exists",
      time.localtime(B.add_billing_months(
          time.mktime(time.strptime("2027-01-28", "%Y-%m-%d")), 1)
      ).tm_mday == 28)

print("\nPro-rata: pay for the days you actually get")

end = time.mktime(time.strptime("2026-10-28", "%Y-%m-%d"))
half = time.mktime(time.strptime("2026-10-13", "%Y-%m-%d"))

p = B.prorata(30.00, end, half)
check("halfway through a period costs about half",
      14.0 < p["amount"] < 16.0)
check("...worked out from the real length of THIS period, not an assumed 30",
      abs(p["days_in_period"] - 30) < 2)

check("the day the period ends costs nothing -- there are no days left to "
      "sell", B.prorata(30.00, end, end)["amount"] == 0.0)
check("a period already past costs nothing rather than going negative",
      B.prorata(30.00, end, end + 10 * DAY)["amount"] == 0.0)
check("a whole period ahead costs the whole amount, never more",
      B.prorata(30.00, end, end - 40 * DAY)["amount"] == 30.00)

print("\nUpgrading costs the difference, and only for the days left")

q = B.upgrade_quote(SMALL, BIG, end, half)
diff = BIG["price"] - SMALL["price"]
check("an upgrade is charged the DIFFERENCE between the packets, not the "
      "new packet -- they already paid for these days on the old one",
      0 < q["due_now"] < diff)
check("...roughly half of it, halfway through the month",
      abs(q["due_now"] - diff / 2) < diff * 0.1)
check("it is recognised as an upgrade", q["kind"] == "upgrade")
check("and the renewal date does NOT move: extending it as well would hand "
      "over a month for the price of a fortnight",
      q["period_end"] == end)

q = B.upgrade_quote(BIG, SMALL, end, half)
check("a downgrade costs nothing now", q["due_now"] == 0.0)
check("...and takes effect at the renewal, not immediately -- what they "
      "have already paid for runs to the end of the month",
      q["kind"] == "downgrade" and q["effective"] == end)

q = B.upgrade_quote(SMALL, SMALL, end, half)
check("choosing the packet you are already on is not a transaction",
      q["kind"] == "same" and q["due_now"] == 0.0)

check("moving up from the free packet charges the whole new packet "
      "pro-rata, since there was nothing paid to credit against",
      B.upgrade_quote(None, SMALL, end, half)["due_now"] > 0)

print("\nA booked change is an intention until the day arrives")

st = fresh()
st.set_plan(1, SMALL["name"])
end = st.get(1)["current_period_end"]
st.schedule_plan_change(1, BIG["name"], end)

check("the change is recorded and readable",
      (st.pending_change(1) or {}).get("plan") == BIG["name"])
check("...but nothing has changed yet: 'you move on the 28th' and 'you have "
      "moved' are different statements and only one is true today",
      st.get(1)["plan"] == SMALL["name"]
      and st.get(1)["device_limit"] == SMALL["devices"])
check("applying it early does nothing at all",
      st.apply_pending_change(1, end - DAY) == "")
check("on the day, it takes effect", st.apply_pending_change(1, end) == BIG["name"])
check("...cap and all", st.get(1)["device_limit"] == BIG["devices"])
check("and it is not applied twice", st.apply_pending_change(1, end) == "")

st.schedule_plan_change(1, SMALL["name"], end)
st.cancel_plan_change(1)
check("a booked change can be called off before it happens",
      st.pending_change(1) is None)

try:
    st.schedule_plan_change(1, "not-a-packet", end)
    check("an unknown packet raises", False)
except ValueError:
    check("an unknown packet is refused rather than booked and forgotten",
          True)

print("\nPaying the pro-rata invoice is what moves the cap")

st = fresh()
st.set_plan(2, SMALL["name"])
end = st.get(2)["current_period_end"]
q = B.upgrade_quote(SMALL, BIG, end)
oid = st.create_order(2, BIG["name"], int(q["due_now"] * 100),
                      kind="upgrade", provider="zoho", currency="USD")

check("raising the invoice alone does not raise the cap -- a device limit "
      "that rises on a click rises for anyone who clicks",
      st.get(2)["device_limit"] == SMALL["devices"])

st.mark_order_paid(oid, "inv-1")
st.apply_paid_order(st.order(oid))
row = st.get(2)
check("paying it moves them onto the bigger packet", row["plan"] == BIG["name"])
check("...with the bigger cap", row["device_limit"] == BIG["devices"])
check("...and the renewal date exactly where it was, so nobody pays twice "
      "for the same days", abs(row["current_period_end"] - end) < 1)

# A renewal, by contrast, must still extend.
oid2 = st.create_order(2, BIG["name"], 11000, kind="renewal", provider="zoho")
st.mark_order_paid(oid2, "inv-2")
st.apply_paid_order(st.order(oid2))
check("a RENEWAL still extends the period, one calendar month on",
      st.get(2)["current_period_end"] == B.add_billing_months(end, 1))

print("\nThe control a customer actually uses")

html = web_auth._change_packet_box("tok", SMALL["name"], 3,
                                   time.time() + 10 * DAY)
check("there is a dropdown of packets, which there was not before unless "
      "card payment happened to be switched on", "<select" in html)
check("both routes are offered, and named by what they cost",
      "Change on the 28th" in html and "invoice me the difference" in html)
check("each option says what changing to it would cost today",
      "now, or free on the" in html)
check("...and the page explains the difference before either is clicked, "
      "because that IS the decision",
      "costs nothing now" in html and "renewal date does not move" in html)

html_small = web_auth._change_packet_box("tok", BIG["name"], 20,
                                         time.time() + 10 * DAY)
check("packets smaller than the devices in use are disabled rather than "
      "offered -- picking one would lock devices somebody is monitoring, "
      "and they would find out by being unable to work",
      'disabled' in html_small)

booked = web_auth._change_packet_box(
    "tok", SMALL["name"], 3, time.time() + 10 * DAY,
    pending={"plan": BIG["name"], "label": BIG["label"],
             "from": time.time() + 10 * DAY})
check("once booked, the page says what will happen and when, instead of "
      "offering the choice again",
      "Packet change booked" in booked and BIG["label"] in booked)
check("...and offers to call it off", "Cancel this change" in booked)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL PLAN CHANGE TESTS PASSED")
