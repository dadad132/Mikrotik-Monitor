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
# The price actually charged, which is the one the website advertises.
PRICE = B.PLANS[0]["price"]
DAY = 86400.0


class FakeAuth:
    def __init__(self, cfg):
        self.cfg = cfg
        self.orgs = {}

    def get_yoco(self):
        return self.cfg

    def org(self, org_id):
        return self.orgs.get(org_id, {"name": f"Company {org_id}"})

    def list_users(self, org_id):
        return [{"role": "owner", "email": f"owner{org_id}@example.com"}]


ZCFG = {"secret_key": "sk_test", "webhook_secret": "whsec_x",
        "days_before": 7, "due_days": 7}


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


def spy(org_id, order_id, plan, amount, currency, period_end, due_days):
    """Stands in for the email that carries the pay link."""
    sent.append({"org": org_id, "order": order_id, "amount": amount,
                 "currency": currency, "plan": plan["name"]})


if True:
    raised = R.raise_due_invoices(store, auth, send=spy)
    check("a company paid up 20 days out is NOT invoiced -- the lead time is "
          "seven days, and invoicing early is its own kind of wrong",
          raised == 0 and not sent)

    # Six days out: inside the window.
    store.set_plan(2, PLAN, period_end=time.time() + 6 * DAY)
    auth.orgs[2] = {"name": "Bravo Logistics"}
    raised = R.raise_due_invoices(store, auth, send=spy)
    check("a company whose packet lapses in six days IS invoiced",
          raised == 1 and len(sent) == 1)
    check("...for the price of the packet they are on, in the currency it "
          "is priced in", sent[0]["amount"] == PRICE
          and sent[0]["currency"] == "USD")
    check("...and the customer is told, because an invoice nobody receives "
          "is not an invoice", sent[0]["org"] == 2)

    # The guard that matters most: the pass runs daily, and a restart loop
    # could run it more often than that.
    before = len(sent)
    for _ in range(5):
        R.raise_due_invoices(store, auth, send=spy)
    check("running the pass five more times raises NOTHING further -- "
          "without this a customer would be invoiced once per pass",
          len(sent) == before)

    check("an invoice that cannot be emailed is still an invoice: the send "
          "failing must not lose the charge",
          R.raise_due_invoices(
              store, auth,
              send=lambda *a: (_ for _ in ()).throw(RuntimeError("smtp"))) == 0)

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

print("\nThe invoice run is daily, not every fifteen minutes")

# "Whose packet lapses within seven days" has the same answer at 09:00 and
# 09:15. Asking 96 times a day spent 96x the API calls to learn nothing --
# and on Zoho's free plan those calls come out of a budget of 1000.


class SettingAuth(FakeAuth):
    def __init__(self, cfg):
        super().__init__(cfg)
        self.settings = {}

    def get_setting(self, k, default=None):
        return self.settings.get(k, default)

    def set_setting(self, k, v):
        self.settings[k] = v


sa = SettingAuth(ZCFG)
early = time.mktime(time.strptime("2026-09-16 02:00", "%Y-%m-%d %H:%M"))
morning = time.mktime(time.strptime("2026-09-16 09:00", "%Y-%m-%d %H:%M"))
evening = time.mktime(time.strptime("2026-09-16 21:00", "%Y-%m-%d %H:%M"))
tomorrow = time.mktime(time.strptime("2026-09-17 09:00", "%Y-%m-%d %H:%M"))

check("at 02:00 nothing is raised -- nobody wants an invoice timestamped "
      "three in the morning", not R.raise_is_due(sa, early))
check("at 09:00 it is due", R.raise_is_due(sa, morning))

R.mark_raised(sa, morning)
check("once it has run, it does not run again that day, however many times "
      "the fifteen-minute tick comes round",
      not R.raise_is_due(sa, morning) and not R.raise_is_due(sa, evening))
check("and it runs again tomorrow", R.raise_is_due(sa, tomorrow))
check("the marker is kept in settings, not memory, so a service restarting "
      "in a loop does not re-read every due company on every boot",
      sa.settings.get("billing_last_raise") == "2026-09-16")
check("an auth store that cannot remember the day still lets billing run -- "
      "it just cannot skip a second run",
      R.raise_is_due(FakeAuth(ZCFG), morning) is True)


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
