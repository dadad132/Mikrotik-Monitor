"""Billing → "Change now — invoice me the difference", end to end.

It called the Zoho invoicing provider that went out with the move to Yoco,
so every press failed with nothing but a 502 from nginx. It now raises its
own invoice like every other one: an upgrade order for the difference over
the days left, emailed with a pay link, payable from the Billing page, and
moving the packet -- not the renewal date -- when paid.

Run:  ./.venv/Scripts/python.exe tests/upgrade_now_test.py
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

import mikromon.notify.org_email as org_email
from mikromon import billing as B
from mikromon import web
from mikromon.auth import AuthStore
from mikromon.config import DEFAULT_THRESHOLDS, SmtpConfig
from mikromon.metrics import MetricsStore

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


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
period_end = B.first_billing_date(time.time())
bs.set_plan(org, "d5", period_end=period_end)
bs.db.close()

sent = []
orig_send = org_email._smtp_send
org_email._smtp_send = lambda cfg, msg: sent.append(msg)

srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, auth, web.SessionManager(), secure_cookies=False,
    defaults=dict(DEFAULT_THRESHOLDS), billing_cfg={"db": bdb},
    devices_db=os.path.join(tmp, "d.db"),   # keeps its rate cache in tmp
    smtp_cfg=SmtpConfig(host="smtp.test", from_addr="billing@eca.test")))
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()
op = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def req(path, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    try:
        r = op.open(urllib.request.Request(BASE + path, data=body), timeout=15)
        return r.status, r.read().decode("utf-8", "replace"), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), ""


try:
    req("/login", {"email": "jp@eca.test", "password": "secret123"})
    st, page, _ = req("/billing")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)

    st, page, url = req("/billing/change-plan", {
        "csrf": csrf, "plan": "d10", "when": "now"})
    check("Change now no longer crashes: it comes back to Billing with an "
          "answer", st == 200 and "/billing" in url
          and "Invoice for $" in page)

    bs = B.BillingStore(bdb)
    orders = [o for o in bs.orders_for_org(org) if o.get("kind") == "upgrade"]
    quote = B.upgrade_quote(B.plan_by_name("d5"), B.plan_by_name("d10"),
                            period_end)
    check("it raises an upgrade invoice for the difference over the days "
          "left", len(orders) == 1 and orders[0]["plan"] == "d10"
          and orders[0]["status"] != "paid"
          and abs(orders[0]["amount_cents"]
                  - round(quote["due_now"] * 100)) <= 1)
    check("...which does not stand in for the month's renewal invoice -- an "
          "unpaid upgrade must not stop the renewal being raised",
          not bs.has_open_order_for_period(org, period_end))

    check("...and emails it to the owner with a link that pays it",
          len(sent) == 1 and "jp@eca.test" in sent[0]["To"]
          and "upgrade to" in sent[0]["Subject"].lower()
          and "https://easymikrotik.test/pay?t=" in sent[0].get_content())
    check("...in words that say what it is: the days left, not a month",
          "day" in sent[0].get_content()
          and "renewal date does not change" in sent[0].get_content())
    check("the page says it was emailed and how to pay",
          "emailed to jp@eca.test" in page and "Pay it below" in page)
    check("...and the Billing page offers to pay it there and then, at "
          "the top as well as in the payments list",
          "waiting for payment" in page and "Pay now</a>" in page
          and page.index("Pay now</a>") < page.index("Change your packet")
          and "Waiting for payment" in page
          and 'href="https://easymikrotik.test/pay?t=' in page
          and "upgrade for the rest of the month" in page)

    req("/billing/change-plan", {"csrf": csrf, "plan": "d10", "when": "now"})
    check("pressing it twice finds the same invoice instead of raising a "
          "second one to pay", len([o for o in bs.orders_for_org(org)
                                    if o.get("kind") == "upgrade"]) == 1)

    link = re.search(r'href="https://easymikrotik\.test(/pay\?t=[^"]+)"',
                     page).group(1)
    st, pay, _ = req(link.replace("&amp;", "&"))
    check("the pay page says it is an upgrade for the rest of the month",
          "Upgrade for the rest of this month" in pay
          and "billed monthly" not in pay)

    bs.apply_paid_order(dict(orders[0], status="paid"))
    row = bs.get(org)
    check("paying it moves the packet and leaves the renewal date alone",
          row["plan"] == "d10" and row["device_limit"] == 10
          and abs(float(row["current_period_end"]) - period_end) < 1)
    bs.db.close()
finally:
    srv.shutdown()
    srv.server_close()
    org_email._smtp_send = orig_send

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL UPGRADE-NOW TESTS PASSED")
