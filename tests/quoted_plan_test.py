"""A quote has to carry a price, or it is free service with extra steps.

Above a hundred devices the ladder stops and the deal is quoted. The only
way the panel could then switch such a company on was set_unlimited(), which
records plan="unlimited" -- a name the price list does not contain. So the
renewal run looked it up, found nothing, wrote a line at INFO and moved on.

Every pass. For ever.

Which means the largest customers in the system -- the ones a quote exists
for because the money is worth a conversation -- were active, uncapped,
their paid-up date ticking over, and never invoiced. The one check that
looks for companies who will never be billed explicitly skipped 'unlimited',
so nothing said so there either.

The point of this file is the bit that is easy to get wrong: a quoted
company must be billed from what was AGREED, and a company with nothing
agreed must not be billed from something invented -- it must be reported.

Run:  python tests/quoted_plan_test.py
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


def store():
    return B.BillingStore(os.path.join(tempfile.mkdtemp(), "b.db"))


class FakeAuth:
    def get_yoco(self):
        return {"secret_key": "k", "webhook_secret": "w"}

    def org(self, i):
        return {"name": "Big Co"}

    def list_users(self, i):
        return []


print("The fault: a quoted company was never invoiced")

st = store()
st.set_unlimited(7)
st._upsert(7, current_period_end=time.time() + 3 * DAY)
sent = []
raised = R.raise_due_invoices(st, FakeAuth(), send=lambda *a: sent.append(a))
check("an 'unlimited' company is still NOT invoiced -- inventing a price "
      "for a deal somebody negotiated would be worse than not billing",
      raised == 0 and sent == [])
check("...but it is now REPORTED as having no price, which is the part that "
      "was missing: before this it vanished into a log line at INFO",
      [o["org_id"] for o in st.orgs_without_a_price()] == [7])

print("\nThe fix: the agreed figure is recorded and billed")

st = store()
st.set_quoted_plan(9, devices=250, price_usd=620.00, label="250 devices",
                   period_end=time.time() + 3 * DAY)
row = st.get(9)
check("the company is active on the cap that was bought",
      row["status"] == "active" and row["device_limit"] == 250)
check("...at the price that was agreed, stored in cents so nothing rounds "
      "it on the way to an invoice", row["custom_cents"] == 62000)

sent = []
raised = R.raise_due_invoices(st, FakeAuth(), send=lambda *a: sent.append(a))
check("the renewal run invoices them, exactly as it does a packet on the "
      "ladder -- which is the whole difference between a quote that bills "
      "and one that quietly does not", raised == 1)
check("...for the agreed amount, not a tier price and not zero",
      sent[0][3] == 620.00 and sent[0][4] == "USD")
check("...and they no longer appear as unpriced", st.orgs_without_a_price() == [])

plan = B.plan_for(row)
check("the plan reads like any other to everything downstream, so the "
      "invoice, the pro-rata and the renewal all take it without knowing "
      "it was negotiated",
      plan["price"] == 620.00 and plan["devices"] == 250
      and plan["currency"] == B.BILLING_CURRENCY)
check("...carrying the label somebody typed, since '250 devices' is what "
      "the customer agreed to and 'quoted' is not",
      plan["label"] == "250 devices")

print("\nWhat must not be possible")

try:
    st.set_quoted_plan(11, devices=300, price_usd=0)
    check("switching a company on with no price is refused", False)
except ValueError as exc:
    check("switching a company on with NO price is refused outright, "
          "because that is exactly how the largest accounts ended up never "
          "invoiced", "agreed monthly price" in str(exc))

try:
    st.set_quoted_plan(11, devices=300, price_usd=-50)
    check("a negative price is refused", False)
except ValueError:
    check("...as is a negative one", True)

check("a company on a normal packet is untouched by any of this: its price "
      "still comes off the ladder",
      B.plan_for({"plan": "d25", "custom_cents": None})["price_usd"]
      == B.plan_by_name("d25")["price_usd"])
check("...and an agreed price BEATS the ladder when both exist, because a "
      "quoted company is not on a tier",
      B.plan_for({"plan": "d25", "custom_cents": 99900})["price"] == 999.00)

st2 = store()
st2.set_quoted_plan(12, devices=300, price_usd=700)
st2.clear_quoted_price(12)
check("an agreed price can be cleared, e.g. moving a company back onto a "
      "packet", (st2.get(12) or {}).get("custom_cents") in (None, 0))

print("\nAnd somewhere to type it")

_rows = [{"id": 9, "name": "Big Co", "owner_email": "a@big.test",
          "user_count": 1, "created": time.time() - 90 * DAY,
          "device_count": 250, "active_count": 250,
          "bill": {"status": "active", "plan": "quoted", "device_limit": 250,
                   "custom_cents": 62000}}]
html = web_auth._render_superadmin(
    {"email": "me@x.test", "role": "owner", "is_superadmin": True},
    _rows, [], csrf="tok", billing_on=True)
check("the panel shows what was agreed, so nobody has to open the database "
      "to find out what a customer pays", "620.00" in html)

_rows[0]["bill"] = {"status": "active", "plan": "unlimited",
                    "device_limit": 0}
html = web_auth._render_superadmin(
    {"email": "me@x.test", "role": "owner", "is_superadmin": True},
    _rows, [], csrf="tok", billing_on=True)
check("...and says loudly when a company has none, since that is a customer "
      "running for free that nothing else mentions",
      "No price" in html and "Nothing invoices" in html)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL QUOTED PLAN TESTS PASSED")
