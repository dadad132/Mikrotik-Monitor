"""Pay and carry on; do not pay and stop. The second half was never wired.

The grace and suspension machinery all existed -- in_grace_period, is_locked,
suspend, GRACE_DAYS -- and nothing called any of it on a timer. `suspend()`
had exactly one caller: a button in the superadmin panel. And billing_status
short-circuits on status == "active", so a lapsed account kept reporting
itself active whatever its paid-up date said.

Confirmed by running it before the fix: three months past the renewal date,
no payment, and the account was still fully active on its whole device cap.
Which means every customer had, in effect, a free account after their first
month -- the invoice went out, nobody had to pay it, and nothing anywhere
noticed.

The other half of the same question is how anybody learns a bank transfer
arrived. Nothing can: an EFT lands where the invoicing system has no sight of
it. So a person says so, once, in one place, and both systems are told.

Run:  python tests/lapse_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import billing as B
from mikromon import billing_runner as R
from mikromon import web_auth

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


DAY = 86400.0
PLAN = B.PLANS[0]["name"]


class FakeAuth:
    """Only what the runner asks of a settings store."""

    def get_yoco(self):
        return {"secret_key": "k", "webhook_secret": "w"}

    def get_setting(self, key, default=None):
        return default

    def set_setting(self, key, value):
        pass

    def org(self, org_id):
        return {"name": "Alpha Freight"}

    def list_users(self, org_id):
        return []


def lapsed(days_ago=1.0):
    st = B.BillingStore(os.path.join(tempfile.mkdtemp(), "b.db"))
    st.set_plan(1, PLAN)
    st._upsert(1, current_period_end=time.time() - days_ago * DAY)
    return st


print("\nAn account that stops paying actually stops")

st = lapsed()
check("before the pass it still reads active, because nothing has looked yet",
      st.billing_status(1) == "active")

moved = st.lapse_due()
check("the pass moves a lapsed account into the grace period",
      moved["grace"] == [1] and st.billing_status(1) == "grace")
check("...and it still WORKS during grace: a payment in transit and a "
      "customer who has stopped paying look identical for a few days, and "
      "only one of them deserves to be cut off",
      st.device_limit(1) == B.PLANS[0]["devices"])
check("...with the grace deadline measured from when the period ended, not "
      "from when the pass happened to run",
      0 < st.days_left_in_grace(1) <= B.GRACE_DAYS)

check("running the pass again the next day changes nothing -- it is not a "
      "countdown that restarts every time something looks at it",
      st.lapse_due(time.time() + DAY)["grace"] == [])

moved = st.lapse_due(time.time() + (B.GRACE_DAYS + 1) * DAY)
check("when the grace period expires the account is suspended",
      moved["suspended"] == [1] and st.billing_status(1) == "suspended")
check("and a suspended account is not suspended a second time",
      st.lapse_due(time.time() + 100 * DAY)["suspended"] == [])

print("\nPaying at any point undoes all of it")

for when, label in ((0.0, "during grace"), (B.GRACE_DAYS + 1, "after suspension")):
    st = lapsed()
    st.lapse_due()
    if when:
        st.lapse_due(time.time() + when * DAY)
    oid = st.create_order(1, PLAN, 2500, kind="renewal", provider="zoho")
    st.mark_order_paid(oid, "x")
    st.apply_paid_order(st.order(oid))
    row = st.get(1)
    check(f"paying {label} switches the account back on",
          st.billing_status(1) == "active")
    check(f"...and clears the grace deadline, so it is not still counting "
          f"down behind the scenes ({label})",
          row["grace_period_end"] is None)
    check(f"...and the packet runs to a real date in the future ({label})",
          row["current_period_end"] > time.time())

print("\nWho is never lapsed")

st = B.BillingStore(os.path.join(tempfile.mkdtemp(), "b.db"))
st.set_free(2)
check("a company on the free packet is not lapsed -- there is nothing to "
      "lapse", st.lapse_due()["grace"] == [])

st.set_plan(3, PLAN)
check("a company paid up into the future is left alone",
      st.lapse_due()["grace"] == [])

st.set_unlimited(4)
check("a comped unlimited account is not lapsed either, since nobody is "
      "invoicing it", 4 not in st.lapse_due()["grace"])

print("\nRecording a bank transfer by hand")

# The card path never needs this: Yoco's webhook records itself, which is
# the whole reason it is the only rail. This is for somebody who paid by
# EFT anyway, which people do, and which nothing can detect because the
# money lands where this server cannot see it.
st = lapsed()
st.lapse_due()
oid = st.create_order(1, PLAN, 2500, kind="renewal", provider="yoco",
                      currency="USD")

check("recording it switches the account back on immediately, rather than "
      "at some next pass -- somebody who has paid should not wait",
      R.mark_paid(st, FakeAuth(), oid) == ""
      and st.billing_status(1) == "active")
check("recording the same invoice twice does nothing the second time",
      "already" in R.mark_paid(st, FakeAuth(), oid).lower())

try:
    R.mark_paid(st, FakeAuth(), 99999)
    check("an unknown invoice raises", False)
except R.BillingError as exc:
    check("an invoice that does not exist is refused rather than silently "
          "doing nothing", "No such invoice" in str(exc))

print("\nThe panel somebody works through with a bank statement open")

html = web_auth._outstanding_box(
    [{"order_id": 1, "org_id": 1, "name": "Alpha Freight", "plan": "d5",
      "kind": "renewal", "amount": 25.0, "currency": "USD",
      "invoice_id": "INV-1", "raised": time.time() - 20 * DAY,
      "due": time.time(), "reference": "ALPHAFREIGHT-0001"}], "tok")
check("it names the company, the amount and the reference a bank statement "
      "will show",
      "Alpha Freight" in html and "$25.00" in html
      and "ALPHAFREIGHT-0001" in html)
check("...and how long it has been outstanding, in red once it is well past "
      "due", "20 days outstanding" in html)
check("...with the one button that does the whole job", "Paid</button>" in html)
check("...which asks first, because it takes money-received as fact",
      "confirm(" in html)
check("nothing outstanding renders nothing at all, rather than an empty "
      "table", web_auth._outstanding_box([], "tok") == "")

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL LAPSE TESTS PASSED")
