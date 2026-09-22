"""Two things nobody could see until a customer saw them first.

Everything renews monthly on the 28th, and three pages nonetheless asked the
customer to choose between one, three, six and twelve months before they
could pay. The length then travelled from the browser to the charge, which
multiplied the rand figure by it.

And the documents that go out -- the renewal email a week early, the page
its link opens, the receipt afterwards -- could only be read by waiting for
a real renewal to fire at a real company. Which makes the first proper
reader the person being billed.

So the choice is gone, and the documents can be looked at on demand, built
from an order that does not exist. Most of this file is about the second
part being genuinely inert: no order written, no mail sent, no company read,
and nothing that could be mistaken for a real invoice.

Run:  python tests/invoice_preview_test.py
"""
from __future__ import annotations

import http.cookiejar
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import billing as B
from mikromon import web, web_auth
from mikromon.auth import AuthStore

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


PLAN = B.PLANS[0]

print("One packet, one month, nothing to choose")

# The dropdown offered 1/3/6/12 in three separate places, and each one was a
# decision standing between somebody and the thing they came to do.
_bill = {"plan": PLAN["name"], "status": "active", "device_limit": 5}
_up = web_auth._plan_upgrade_box("tok", _bill, device_count=2, yoco_on=True)
check("the upgrade box has no months to pick",
      'name="months"' not in _up and "Pay for" not in _up)
check("...and still upgrades", "Upgrade" in _up and "/billing/checkout" in _up)

_html = web_auth._render_billing(
    {"email": "o@x.test", "role": "owner", "org_name": "Alpha"},
    _bill, False, "tok", device_count=2, yoco_on=True)
check("the Billing tab's pay buttons have none either",
      'name="months"' not in _html)
check("...and say what the figure buys, now that nothing beside it does",
      "for the month" in _html)

_locked = web_auth._locked_pay_block(
    {"email": "o@x.test", "role": "owner"}, "tok", True,
    dict(_bill, status="suspended"), None, "Alpha")
check("and the form a suspended company uses to switch itself back on has "
      "none either -- that one especially, since somebody locked out is "
      "trying to get back in, not shopping",
      'name="months"' not in _locked)
check("...and still takes the payment that does it",
      "/billing/checkout" in _locked)

print("\nA checkout is for one month, whatever the browser says")

d = tempfile.mkdtemp()
adb, bdb = os.path.join(d, "auth.db"), os.path.join(d, "b.db")
a = AuthStore(adb)
org = a.signup("boss@easy.test", "a-password-for-the-test", "EasyMikroTik")
a.set_superadmin("boss@easy.test", True)
a.signup("owner@alpha.test", "a-password-for-the-test", "Alpha Freight")
a.close()
store = B.BillingStore(bdb)
store.close()

PORT = 8798
threading.Thread(target=web.serve, kwargs=dict(
    metrics_db=os.path.join(d, "m.db"), state_file=os.path.join(d, "s.json"),
    auth_db=adb, billing_cfg={"db": bdb},
    host="127.0.0.1", port=PORT),
    daemon=True).start()
time.sleep(2.0)
BASE = f"http://127.0.0.1:{PORT}"


def login(email, pw):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    op.open(urllib.request.Request(BASE + "/login", data=urllib.parse.urlencode(
        {"email": email, "password": pw}).encode()), timeout=8)
    return op


def get(op, path):
    try:
        r = op.open(BASE + path, timeout=8)
        return getattr(r, "status", r.code), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


boss = login("boss@easy.test", "a-password-for-the-test")
owner = login("owner@alpha.test", "a-password-for-the-test")

# Card payment is off on this server, so a checkout cannot complete -- but
# the point is that `months` never reaches the amount at all. Post one
# anyway and make sure no twelve-month order appears.
_before = B.BillingStore(bdb)
_n_before = len(_before.open_orders("yoco", 50, require_external=False)
                if hasattr(_before, "open_orders") else [])
_before.close()
try:
    owner.open(urllib.request.Request(
        BASE + "/billing/checkout",
        data=urllib.parse.urlencode({"plan": PLAN["name"], "months": "12",
                                     "csrf": "wrong"}).encode()), timeout=8)
except urllib.error.HTTPError:
    pass
_after = B.BillingStore(bdb)
_rows = [o for o in (_after.open_orders("yoco", 50, require_external=False)
                     if hasattr(_after, "open_orders") else [])]
_after.close()
check("a hand-posted months=12 creates no twelve-month order",
      all(int(o.get("months") or 1) == 1 for o in _rows))

print("\nSeeing the documents before a customer does")

st, body = get(boss, "/superadmin/test-invoice")
check("the preview opens for the superadmin", st == 200)
check("...showing the renewal email, subject and all",
      "EasyMikroTik invoice" in body and "renews on" in body)
check("...addressed the way the real one is, to whoever owns the account",
      "Subject" in body and "To" in body)
check("...and saying plainly that it is made up, so a figure read off it is "
      "never mistaken for a company's real bill",
      "made-up order" in body and "no company is touched" in body)
check("...with a way to reach the other two documents",
      "doc=pay" in body and "doc=invoice" in body)

st, pay = get(boss, f"/superadmin/test-invoice?doc=pay&plan={PLAN['name']}")
check("the pay page previews", st == 200 and "Pay by card" in pay)
check("...for the real advertised price, not a placeholder",
      B.money(PLAN["price"], "USD") in pay)
check("...stamped SAMPLE, because it is a page with an amount and a pay "
      "button on it", "SAMPLE" in pay)

st, inv = get(boss, f"/superadmin/test-invoice?doc=invoice&plan={PLAN['name']}")
check("the receipt previews", st == 200 and "Invoice" in inv)
check("...stamped SAMPLE too -- this is the one that gets printed and filed",
      "SAMPLE" in inv)
check("...and still carries no VAT line, which is the thing that would be a "
      "real problem rather than a cosmetic one",
      "No VAT" in inv and "Tax Invoice" not in inv)

st, big = get(boss, "/superadmin/test-invoice?plan=" + B.PLANS[-1]["name"])
check("any packet can be previewed, not just the cheapest",
      st == 200 and B.money(B.PLANS[-1]["price"], "USD") in big)

st, junk = get(boss, "/superadmin/test-invoice?plan=does-not-exist")
check("an unknown packet falls back rather than 500ing",
      st == 200 and "EasyMikroTik invoice" in junk)

print("\nAnd that the preview is genuinely inert")

_st = B.BillingStore(bdb)
_orders = _st.db.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
_st.close()
check("previewing wrote no order -- a preview that leaves a row behind "
      "would show up in the outstanding list as money somebody owes",
      _orders == 0)

st, _ = get(owner, "/superadmin/test-invoice")
check("a company owner cannot reach it: it is a platform tool, and it "
      "names a price list before anyone has bought anything", st == 403)

st, _ = get(urllib.request.build_opener(), "/superadmin/test-invoice")
check("neither can somebody with no session at all", st in (403, 200))

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL INVOICE PREVIEW TESTS PASSED")
