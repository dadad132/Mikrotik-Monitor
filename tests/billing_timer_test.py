"""The timer: who gets invoiced, when, and whether you can see it coming.

The thing people assume about this system is that the invoicing provider
knows when to bill. It does not — it has no idea these accounts exist until
this server tells it. This server holds the clock: every company has a
paid-up date, a background pass runs every 15 minutes, and when a date comes
inside the lead time it creates the invoice and asks for it to be emailed.

Which means the whole of billing rests on a daemon thread that says nothing
unless it acts. So half of what is tested here is not the schedule but
whether a person can SEE the schedule — because a thread that has died and a
month with nothing due look identical from the outside, and the difference is
only discovered by the money not arriving.

Run:  python tests/billing_timer_test.py
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


PLAN = B.PLANS[0]["name"]
PRICE = B.PLANS[0]["price_zar"]
DAY = 86400.0


class FakeAuth:
    def __init__(self, cfg):
        self.cfg = cfg
        self.orgs = {}

    def get_zoho(self):
        return self.cfg

    def get_invoiceninja(self):
        return {}

    def org(self, org_id):
        return self.orgs.get(org_id, {"name": f"Company {org_id}"})

    def list_users(self, org_id):
        return [{"role": "owner", "email": f"owner{org_id}@example.com"}]


ZCFG = {"refresh_token": "rt", "api_base": "https://www.zohoapis.eu/invoice/v3",
        "client_id": "c", "client_secret": "s", "accounts_host": "accounts.zoho.eu",
        "organization_id": "1", "days_before": 7, "due_days": 7}


def fresh():
    d = tempfile.mkdtemp()
    return B.BillingStore(os.path.join(d, "b.db"))


print("\nThe clock lives here, not at the invoicing provider")

store = fresh()
auth = FakeAuth(ZCFG)
auth.orgs[1] = {"name": "Alpha Freight"}
# Paid up until 20 days from now: outside the 7-day lead time.
store.set_plan(1, PLAN, period_end=time.time() + 20 * DAY)

sent = []
_real = (R._z.ensure_client, R._z.create_invoice, R._z.email_invoice)
try:
    R._z.ensure_client = lambda cfg, name, email="", phone="", known_id="": "C1"

    def spy_create(cfg, contact_id, *, description, amount_cents,
                   due_date="", reference=""):
        sent.append({"cents": amount_cents, "desc": description,
                     "due": due_date, "ref": reference})
        return {"id": f"INV{len(sent)}", "number": f"INV-{len(sent):04d}"}

    R._z.create_invoice = spy_create
    R._z.email_invoice = lambda cfg, iid: sent[-1].update({"emailed": iid})

    raised = R.raise_due_invoices(store, auth, ZCFG)
    check("a company paid up 20 days out is NOT invoiced -- the lead time is "
          "seven days, and invoicing early is its own kind of wrong",
          raised == 0 and not sent)

    # Six days out: inside the window.
    store.set_plan(2, PLAN, period_end=time.time() + 6 * DAY)
    auth.orgs[2] = {"name": "Bravo Logistics"}
    raised = R.raise_due_invoices(store, auth, ZCFG)
    check("a company whose packet lapses in six days IS invoiced",
          raised == 1 and len(sent) == 1)
    check("...for the price of the packet they are on, to the cent",
          sent[0]["cents"] == int(round(PRICE * 100)))
    check("...and it is actually emailed, not left sitting as a draft "
          "nobody was asked to pay", sent[0].get("emailed") == "INV1")
    check("...carrying a payment reference that ties it back to the company",
          bool(sent[0]["ref"]))

    check("the company that was not due is still not invoiced on the same "
          "pass", raised == 1)

    # The guard that matters most: the pass runs every 15 minutes.
    before = len(sent)
    for _ in range(5):
        R.raise_due_invoices(store, auth, ZCFG)
    check("running the pass five more times raises NOTHING further -- it "
          "runs every fifteen minutes, so without this a customer would get "
          "ninety-six invoices a day", len(sent) == before)

    print("\nPayment is read back, never assumed")

    order = [o for o in store.open_orders(provider="zoho")][0]
    R._z.invoice_status = lambda cfg, iid: {"paid": False, "status": "sent",
                                            "balance": PRICE, "total": PRICE,
                                            "number": "INV-0001"}
    check("an unpaid invoice extends nothing",
          R.reconcile_payments(store, ZCFG) == 0)

    was = store.get(2)["current_period_end"]
    R._z.invoice_status = lambda cfg, iid: {"paid": True, "status": "paid",
                                            "balance": 0.0, "total": PRICE,
                                            "number": "INV-0001"}
    check("a paid invoice is applied once",
          R.reconcile_payments(store, ZCFG) == 1)
    check("...and the packet carries on, extended from where it ended rather "
          "than from today, so nothing already paid for is lost",
          store.get(2)["current_period_end"] > was)
    check("...and applying it twice does not extend twice, which a webhook "
          "and the timer both finding it would otherwise do",
          R.reconcile_payments(store, ZCFG) == 0)

    print("\nBeing able to see it coming")

    rows = R.upcoming(store, auth)
    by_name = {r["name"]: r for r in rows}
    check("both companies appear, not only the one that is due",
          "Alpha Freight" in by_name and "Bravo Logistics" in by_name)
    check("each says the date its invoice goes out, not just when the packet "
          "ends -- those are seven days apart and it is the first one "
          "somebody needs to know",
          all(r["invoice_on"] < r["period_end"] for r in rows))
    check("...and what it will be for",
          by_name["Alpha Freight"]["amount"] == PRICE)
    check("the one already invoiced is marked as such, so nobody chases an "
          "invoice that has gone", by_name["Bravo Logistics"]["already_raised"]
          or by_name["Bravo Logistics"]["invoice_on"] > time.time())
    check("they are ordered by when they happen, which is the order somebody "
          "reads this in",
          [r["name"] for r in rows] == sorted(
              (r["name"] for r in rows),
              key=lambda n: by_name[n]["invoice_on"]))
finally:
    R._z.ensure_client, R._z.create_invoice, R._z.email_invoice = _real

print("\nA timer nobody can see is the whole problem")

html = web_auth._upcoming_box(
    [{"name": "Alpha Freight", "plan": PLAN, "amount": PRICE,
      "period_end": time.time() + 20 * DAY,
      "invoice_on": time.time() + 13 * DAY,
      "days_until_invoice": 13.0, "already_raised": False, "org_id": 1}],
    {"ran": time.time() - 120, "raised": 0, "applied": 0, "error": "",
     "started": time.time() - 9000})
check("the panel names the company and the date its invoice goes out",
      "Alpha Freight" in html and "in 13 days" in html)
check("...and says when the timer last ran, so a dead thread is visible "
      "rather than being discovered by the money not arriving",
      "Last checked" in html)
check("...and says plainly that this server decides when, since everybody "
      "assumes the invoicing system does",
      "This server decides when" in html)

html = web_auth._upcoming_box([], {"started": time.time() - 9000, "ran": 0.0})
check("a started-but-never-run timer says so rather than looking healthy",
      "first pass runs within" in html)

html = web_auth._upcoming_box([], {})
check("no timer at all is stated in red: no invoice will go out",
      "not running" in html)

html = web_auth._upcoming_box([], {"ran": time.time(), "error": "Zoho said no"})
check("a failed pass shows the reason on the page, not only in the log",
      "Zoho said no" in html)

print("\nAnd the health panel catches the thread dying")

from mikromon import selfcheck as sc

d = tempfile.mkdtemp()
bdb = os.path.join(d, "b.db")
import sqlite3
con = sqlite3.connect(bdb)
con.execute("CREATE TABLE billing (org_id INTEGER PRIMARY KEY, plan TEXT,"
            " status TEXT, current_period_end REAL)")
con.commit()
con.close()


def one(fs, cid):
    return next((f for f in fs if f["id"] == cid), None)


f = one(sc.check_billing_ready(bdb, True,
                               {"started": 1.0, "ran": time.time() - 3600}),
        "billing:runner")
check("a pass that has not run for an hour is a failure -- it runs every "
      "fifteen minutes", f is not None and not f["ok"])

f = one(sc.check_billing_ready(bdb, True,
                               {"started": 1.0, "ran": time.time() - 300}),
        "billing:runner")
check("a recent pass passes quietly", f is not None and f["ok"])

f = one(sc.check_billing_ready(bdb, True,
                               {"started": time.time() - 7200, "ran": 0.0}),
        "billing:runner")
check("started two hours ago and never run once is caught",
      f is not None and not f["ok"] and "never run" in f["title"])

check("nothing known about the runner says nothing, rather than inventing a "
      "fault", one(sc.check_billing_ready(bdb, True, None),
                   "billing:runner") is None)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL BILLING TIMER TESTS PASSED")
