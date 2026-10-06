"""Cancelling, and the Terms & Conditions people agree to when they pay.

Cancelling: nothing stops on the day. The month already paid for runs to the
28th; on the 28th access to every unit ends with no grace; paying the next
invoice switches it all back on. The owner can change their mind before then.

Terms: readable before signing up, accepted at signup and with every payment,
and the version accepted is recorded each time.

Run:  ./.venv/Scripts/python.exe tests/terms_cancel_test.py
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

from mikromon import billing as B
from mikromon import web, web_auth, web_landing
from mikromon.auth import AuthStore
from mikromon.config import DEFAULT_THRESHOLDS
from mikromon.metrics import MetricsStore
from mikromon.web_terms import TERMS_VERSION, render_terms

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


def at(y, m, d, h=10):
    return time.mktime((y, m, d, h, 0, 0, 0, 0, -1))


tmp = tempfile.mkdtemp()

print("Cancelling, in the billing store")

st = B.BillingStore(os.path.join(tmp, "b.db"))
end = at(2026, 10, 28, 0)
st._upsert(1, status="active", plan="d5", device_limit=5,
           current_period_end=end)
when = st.request_cancel(1, now=at(2026, 10, 10))
check("cancelling keeps the paid month: access runs to the 28th", when == end)
row = st.get(1)
check("...and is recorded", bool(row["cancel_requested"]))
check("...so the countdown is to the 28th itself, with no grace",
      B.suspends_at(row, "active") == end)

check("nothing happens before the 28th",
      st.lapse_due(at(2026, 10, 20)) == {"grace": [], "suspended": []}
      and st.get(1)["status"] == "active")
moved = st.lapse_due(at(2026, 10, 28, 6))
check("on the 28th the account is suspended straight away -- access to "
      "every unit ends, with no seven days of grace",
      moved["suspended"] == [1] and st.billing_status(1) == "suspended")

oid = st.create_order(1, "d5", 2500, kind="renewal")
st.mark_order_paid(oid, "p1")
st.apply_paid_order(st.order(oid), now=at(2026, 11, 2))
row = st.get(1)
check("paying the next invoice switches it all back on",
      st.billing_status(1) == "active" and not row["cancel_requested"])
check("...for the month that invoice was for", time.strftime(
    "%Y-%m-%d", time.localtime(row["current_period_end"])) == "2026-11-28")

st._upsert(2, status="active", plan="d5", device_limit=5,
           current_period_end=end)
st.request_cancel(2, now=at(2026, 10, 10))
st.withdraw_cancel(2)
moved = st.lapse_due(at(2026, 10, 28, 6))
check("withdrawing the cancellation puts the account back on the normal "
      "path: grace, not an immediate cut-off",
      moved["grace"] == [2] and moved["suspended"] == [])

st._upsert(3, status="trial", device_limit=1,
           trial_end=time.time() + 5 * 86400)
try:
    st.request_cancel(3)
    _refused = False
except ValueError:
    _refused = True
check("there is nothing to cancel without a paid month running", _refused)

print("\nWhat the owner sees")

USER = {"email": "o@x.test", "role": "owner", "org_name": "Alpha"}
_running = {"status": "active", "plan": "d5", "device_limit": 5,
            "current_period_end": time.time() + 12 * 86400}
page = web_auth._render_billing(USER, _running, False, "tok", device_count=2)
check("a paying company has a Cancel button", "Cancel subscription" in page
      and 'action="/billing/cancel"' in page)
check("...whose warning says access to ALL units ends, and how to get it back",
      "ALL of your units" in page and "pay the next invoice" in page)
page = web_auth._render_billing(
    USER, dict(_running, cancel_requested=time.time()), False, "tok",
    device_count=2)
check("once cancelled, the page says until when, and offers to keep the "
      "subscription instead", "Cancellation requested" in page
      and "Keep my subscription" in page and "Cancel subscription" not in page)
page = web_auth._render_billing(USER, {"status": "trial", "device_limit": 1,
                                       "trial_end": time.time() + 9e5},
                                False, "tok", device_count=1)
check("a trial has nothing to cancel, so no button",
      "Cancel subscription" not in page)

print("\nAgreeing to the terms")

from mikromon import fxrate as _FX  # noqa: E402
_FX._cache["USDZAR"] = {"rate": 16.5, "date": "2026-10-01",
                        "source": "test", "pair": "USDZAR",
                        "fetched": time.time()}
page = web_auth._render_billing(USER, {"status": "trial", "device_limit": 1},
                                False, "tok", device_count=1, yoco_on=True)
check("the packet list is one form with one required tick-box",
      page.count('name="agree"') == 1 and "required" in page
      and page.count('action="/billing/checkout"') == 1)
check("...and each button says which packet", 'name="plan" value="d5"' in page)
check("the pay-link page needs the tick too",
      'name="agree"' in web_auth._pay_page(
          {"id": 1, "plan": "d5", "amount_cents": 2500, "currency": "USD"},
          "", token="t"))
check("so does creating an account", 'name="agree"' in web_auth._render_signup())

terms = render_terms({"bank_holder": "Acme Networks (Pty) Ltd",
                      "email": "billing@acme.test"})
check("the terms name who they are with, and how to reach them",
      "Acme Networks (Pty) Ltd" in terms and "billing@acme.test" in terms)
check("...say payments are not refundable",
      "Payments are not refundable" in terms)
check("...say how cancelling works", "lose access to all of your" in terms
      and "pay the next invoice" in terms)
check("...say a first payment is pro rata to the 28th",
      "pro rata" in terms and "28th" in terms)
check("...and carry their version", TERMS_VERSION in terms)

landing = web_landing.render_landing()
check("the landing page links to the terms", 'href="/terms"' in landing)
check("...and its FAQ no longer claims RouterOS 6 works",
      "RouterOS 6 and 7" not in landing and "RouterOS 7.1 or later" in landing)
check("...or that cancelling is a button that does not exist: it describes "
      "the real one", "Cancel button on your Billing tab" in landing)

print("\nEnd to end")

mdb, sfile, adb = (os.path.join(tmp, x) for x in ("m.db", "s.json", "a.db"))
MetricsStore(mdb).close()
with open(sfile, "w") as fh:
    json.dump({"devices": {}}, fh)
bdb = os.path.join(tmp, "web-billing.db")
srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, AuthStore(adb), web.SessionManager(), secure_cookies=False,
    defaults=dict(DEFAULT_THRESHOLDS), billing_cfg={"db": bdb}))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()


def opener():
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def req(op, path, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    try:
        r = op.open(urllib.request.Request(BASE + path, data=body), timeout=10)
        return getattr(r, "status", r.code), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


try:
    s, body = req(opener(), "/terms")
    check("the terms are public: readable before signing up", s == 200
          and "Terms &amp; Conditions" in body)

    o = opener()
    req(o, "/signup", {"company": "Beta", "email": "own@beta.test",
                       "password": "secret123", "phone": "0821234567",
                       "agree": "1"})
    a = AuthStore(adb)
    version, accepted = a.terms_of("own@beta.test")
    org_id = a.get_user("own@beta.test")["org_id"]
    a.close()
    check("signing up records which terms were accepted, and when",
          version == TERMS_VERSION and accepted and accepted <= time.time())

    bs = B.BillingStore(bdb)
    bs.set_plan(org_id, "d5", period_end=time.time() + 10 * 86400)
    _, page = req(o, "/billing")
    tok = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    req(o, "/billing/cancel", {"csrf": tok})
    check("the owner can cancel from the Billing tab",
          bool(bs.get(org_id)["cancel_requested"]))
    _, page = req(o, "/billing")
    check("...and is told until when they keep access",
          "Cancellation requested" in page)
    req(o, "/billing/cancel", {"csrf": tok, "action": "undo"})
    check("...and can take it back", not bs.get(org_id)["cancel_requested"])
    bs.db.close()
finally:
    srv.shutdown()
    srv.server_close()

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL TERMS & CANCEL TESTS PASSED")
