"""A renewal paid late is the invoice that went out, in full -- whichever
button pays it.

What it was: a company suspended for not paying its 28 October invoice that
came back on 20 November was charged one of two prices depending on the
button. The emailed link took the full month (and the December invoice
followed the next day). The suspended page and the Billing tab charged a
pro rata eight days -- and left the full invoice open, still listed as owed,
still payable from its link, adding a month if anybody did.

The rule now:
  * paid late, in the grace days or after suspension, the outstanding
    renewal invoice is owed in full, and every button pays THAT invoice
  * the Billing tab and the suspended page show it, with the invoice to open
    again (a suspended company could not open anything but /billing)
  * once the month it was for is over, the invoice lapses -- nothing is owed
    for a month never given, it is not raised again, its link stops working
    -- and coming back is charged pro rata from that day, like a first payment

Run:  ./.venv/Scripts/python.exe tests/late_payment_test.py
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import re
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mikromon.billing as B  # noqa: E402
import mikromon.yoco as yoco_mod  # noqa: E402
from mikromon import billing_runner as R  # noqa: E402
from mikromon import paylink, web, web_auth  # noqa: E402
from mikromon.auth import AuthStore  # noqa: E402
from mikromon.config import DEFAULT_THRESHOLDS  # noqa: E402
from mikromon.metrics import MetricsStore  # noqa: E402

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


DAY = 86400
NOW = time.time()
_lt = time.localtime(NOW)
# The last 28th that has been, and the one before: real billing dates, so
# the month arithmetic is the same arithmetic the server does.
LAST28 = time.mktime((_lt.tm_year, _lt.tm_mon, B.BILLING_DAY, 0, 0, 0, 0, 0,
                      -1))
if LAST28 > NOW:
    _m = _lt.tm_mon - 1 or 12
    LAST28 = time.mktime((_lt.tm_year - (_lt.tm_mon == 1), _m, B.BILLING_DAY,
                          0, 0, 0, 0, 0, -1))
_p = time.localtime(LAST28)
PREV28 = time.mktime((_p.tm_year - (_p.tm_mon == 1), _p.tm_mon - 1 or 12,
                      B.BILLING_DAY, 0, 0, 0, 0, 0, -1))
PLAN = "d5"
PRICE_CENTS = int(round(B.plan_by_name(PLAN)["price"] * 100))


def store():
    return B.BillingStore(os.path.join(tempfile.mkdtemp(), "b.db"))


print("The invoice a late payer owes")
st = store()
st.set_plan(1, PLAN, period_end=LAST28)
inv = st.create_order(1, PLAN, PRICE_CENTS, currency="USD", due=LAST28)
st.lapse_due(NOW)
check("the month an invoice was for is over only once the next 28th has "
      "passed", not B.renewal_month_over(st.order(inv), NOW)
      and B.renewal_month_over({"due": PREV28, "months": 1}, NOW))
check("behind on its renewal, a company owes that invoice",
      (st.outstanding_renewal(1, NOW) or {}).get("id") == inv)
st.suspend(1)
check("...still, once suspended", (st.outstanding_renewal(1, NOW) or {})
      .get("id") == inv)
st.mark_order_paid(inv, "x")
st.apply_paid_order(st.order(inv), now=NOW)
check("paid late, in full, it runs to the next 28th -- the month it was for",
      st.billing_status(1) == "active"
      and abs(st.get(1)["current_period_end"]
              - B.add_billing_months(LAST28, 1)) < 2)
check("...and a company paid up owes nothing", st.outstanding_renewal(1, NOW)
      is None)

print("\nOnce the month it was for is over")
st = store()
st.set_plan(2, PLAN, period_end=PREV28)
old = st.create_order(2, PLAN, PRICE_CENTS, currency="USD", due=PREV28)
st.suspend(2)
check("an invoice for a month that has ended is not owed",
      st.outstanding_renewal(2, NOW) is None)


class FakeAuth:
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


raised = []
R.run_once(st, FakeAuth(), now=NOW, force_raise=True,
           send=lambda *a: raised.append(a))
check("the daily pass withdraws it as lapsed, so it leaves the list of money "
      "owed", st.order(old)["status"] == "lapsed"
      and old not in [o["id"] for o in st.open_orders(require_external=False)])
check("...and does not raise it again the next morning",
      raised == [] and not [o for o in st.orders_for_org(2)
                            if o["status"] not in B.WITHDRAWN + ("paid",)])
R.run_once(st, FakeAuth(), now=NOW + DAY, force_raise=True,
           send=lambda *a: raised.append(a))
check("...nor the morning after", raised == [])

st2 = store()
st2.set_plan(3, PLAN, period_end=LAST28)
cur = st2.create_order(3, PLAN, PRICE_CENTS, currency="USD", due=LAST28)
check("an invoice whose month is still running is left alone",
      st2.lapse_stale_renewals(NOW) == [] and st2.order(cur)["status"]
      not in B.WITHDRAWN)

print("\nThe pages")
_o = {"id": 7, "plan": PLAN, "amount_cents": PRICE_CENTS, "currency": "USD",
      "due": LAST28, "status": "pending", "kind": "renewal", "months": 1,
      "created": LAST28 - 7 * DAY}
box = web_auth._orders_box([_o])
check("an unpaid renewal invoice in the payments list says it is waiting, "
      "with the invoice to open -- it read 'Not completed', with nothing to "
      "click", "Waiting for payment" in box
      and "/billing/invoice?id=7" in box and "Not completed" not in box)
box = web_auth._orders_box([dict(_o, status="lapsed")])
check("...and once lapsed, says why", "the month it was for ended unpaid"
      in box)


# ---- end to end -------------------------------------------------------------
tmp = tempfile.mkdtemp()
mdb, sfile, adb, bdb = (os.path.join(tmp, x) for x in
                        ("m.db", "s.json", "a.db", "b.db"))
MetricsStore(mdb).close()
with open(sfile, "w") as fh:
    json.dump({"devices": {}}, fh)
auth = AuthStore(adb)
org = auth.signup("jp@eca.test", "secret123", "ECA")
auth.set_yoco({"secret_key": "sk_test_x", "webhook_secret": "whsec_x"})
auth.set_setting("public_base_url", "https://easymikrotik.test")
bs = B.BillingStore(bdb)
bs.set_plan(org, PLAN, period_end=LAST28)
owed = bs.create_order(org, PLAN, PRICE_CENTS, currency="USD", due=LAST28)
bs.suspend(org)

started = []
orig = (yoco_mod.create_checkout, B.zar_amount)
yoco_mod.create_checkout = lambda key, cents, **kw: (
    started.append((cents, kw.get("metadata"))) or
    {"id": f"ch_{len(started)}", "redirectUrl": "https://c.yoco.test/pay"})
B.zar_amount = lambda usd: {"amount": round(usd * 18, 2), "rate": 18.0,
                            "date": "2026-10-16", "source": "test",
                            "stale": False}
srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, auth, web.SessionManager(), secure_cookies=False,
    defaults=dict(DEFAULT_THRESHOLDS), billing_cfg={"db": bdb},
    devices_db=os.path.join(tmp, "d.db"), admin_2fa=False))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


jar = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
raw = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),
                                  NoRedirect)


def req(path, data=None, follow=True):
    body = urllib.parse.urlencode(data).encode() if data else None
    try:
        r = (op if follow else raw).open(
            urllib.request.Request(BASE + path, data=body), timeout=15)
        return r.status, r.read().decode("utf-8", "replace"), r.geturl()
    except urllib.error.HTTPError as e:
        return (e.code, e.read().decode("utf-8", "replace"),
                e.headers.get("Location", ""))


try:
    req("/login", {"email": "jp@eca.test", "password": "secret123"})
    st_, page, _ = req("/billing")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    amount = web_auth._order_usd(bs.order(owed), B.plan_by_name(PLAN))
    print("\nA suspended company, with its invoice still owed")
    check("the suspended page says what is outstanding",
          "Account Suspended" in page and "Outstanding:" in page
          and amount in page)
    check("...offers that invoice to open again -- the copy somebody asks "
          "for when the email is lost", f"/billing/invoice?id={owed}" in page)
    check("...and pays THAT amount, not a packet picked afresh",
          f"Pay {amount} and switch everything back on" in page
          and "<select" not in page)
    st_, inv, _ = req(f"/billing/invoice?id={owed}")
    check("a suspended company can open its invoice now",
          st_ == 200 and "Total Due" in inv and "Pay by card" in inv)
    n_orders = len(bs.orders_for_org(org))
    st_, _, where = req("/billing/checkout", {"csrf": csrf, "plan": PLAN,
                                              "agree": "1"}, follow=False)
    check("paying from the suspended page charges the outstanding invoice in "
          "full, converted to rands", where == "https://c.yoco.test/pay"
          and started and started[-1][0] == round(PRICE_CENTS * 18)
          and started[-1][1]["order"] == str(owed))
    check("...on that invoice, with no second order beside it",
          len(bs.orders_for_org(org)) == n_orders)
    st_, page, _ = req("/billing/checkout", {"csrf": csrf, "plan": "d10",
                                             "agree": "1"})
    check("asking for another packet while it is owed is told to pay it "
          "first", "is still outstanding" in page
          and len(started) == 1)

    print("\nIn the grace days, on the Billing tab")
    bs._upsert(org, status="grace", current_period_end=NOW - DAY,
               grace_period_end=NOW + 6 * DAY)
    bs.db.execute("UPDATE orders SET due = ? WHERE id = ?", (NOW - DAY, owed))
    bs.db.commit()
    st_, page, _ = req("/billing")
    check("the overdue invoice is at the top, with a way to pay it and to "
          "open it", "overdue" in page and "Pay now</a>" in page
          and f"/billing/invoice?id={owed}" in page
          and page.index("overdue") < page.index("Choose a packet"))
    check("...and the packet buttons wait until it is paid -- they offered a "
          "pro rata price for the same month",
          'type="submit" name="plan"' not in page
          and "Pay the overdue invoice above first" in page)
    st_, _, where = req("/billing/checkout", {"csrf": csrf, "plan": PLAN,
                                              "agree": "1"}, follow=False)
    check("...and a checkout posted anyway pays that invoice too",
          started[-1][1]["order"] == str(owed)
          and started[-1][0] == round(PRICE_CENTS * 18))

    print("\nSuspended past the end of the month it was for")
    token = paylink.make(auth, owed)
    bs._upsert(org, status="suspended", current_period_end=PREV28,
               grace_period_end=None)
    bs.db.execute("UPDATE orders SET due = ? WHERE id = ?", (PREV28, owed))
    bs.db.commit()
    bs.lapse_stale_renewals(NOW)
    st_, page, _ = req("/billing")
    check("nothing is owed for a month never given: the page offers to start "
          "again, pro rata from today", "Outstanding:" not in page
          and "<select" in page
          and "days from today to the next 28th" in page)
    st_, pay, _ = req(f"/pay?t={token}")
    check("...and the old invoice's link no longer takes money for it",
          "no longer payable" in pay and "Pay by card" not in pay)
    n = len(started)
    req("/billing/checkout", {"csrf": csrf, "plan": PLAN, "agree": "1"},
        follow=False)
    first = [o for o in bs.orders_for_org(org) if o.get("kind") == "first"]
    check("coming back is charged like a first payment: the days to the next "
          "28th", len(started) == n + 1 and len(first) == 1
          and first[0]["amount_cents"] <= round(B.plan_by_name(PLAN)["price"]
                                                * 18 * 100))
finally:
    srv.shutdown()
    yoco_mod.create_checkout, B.zar_amount = orig

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL LATE PAYMENT TESTS PASSED")
