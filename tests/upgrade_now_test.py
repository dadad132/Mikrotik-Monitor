"""Billing → "Change now — invoice me the difference", end to end.

It called the Zoho invoicing provider that went out with the move to Yoco,
so every press failed with nothing but a 502 from nginx. It now raises its
own invoice like every other one: an upgrade order for the difference over
the days left, emailed with a pay link, payable from the Billing page, and
moving the packet -- not the renewal date -- when paid.

Run:  ./.venv/Scripts/python.exe tests/upgrade_now_test.py
"""
from __future__ import annotations

import base64
import hashlib
import hmac
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
SECRET = "whsec_" + base64.b64encode(b"upgrade-test-signing-key-32byte").decode()
auth.set_yoco({"secret_key": "sk_test_x", "webhook_secret": SECRET})
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

    # Paying from the emailed link. The pay page is public and posts to
    # /pay, which sat behind the login and CSRF checks: a customer was sent
    # to log in, and a logged-in one got "bad csrf token".
    import http.client  # noqa: E402

    import mikromon.billing as billing_mod  # noqa: E402
    import mikromon.yoco as yoco_mod  # noqa: E402
    started = []
    orig_checkout, orig_zar = yoco_mod.create_checkout, billing_mod.zar_amount
    yoco_mod.create_checkout = lambda key, cents, **kw: (
        started.append(cents) or {"id": f"ch_{len(started)}",
                                  "redirectUrl": "https://c.yoco.test/pay"})
    billing_mod.zar_amount = lambda usd: {"amount": round(usd * 18, 2),
                                          "rate": 18.0, "date": "2026-10-08",
                                          "source": "test", "stale": False}

    def post_pay(token, cookie=""):
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1],
                                       timeout=15)
        body = urllib.parse.urlencode({"t": token, "agree": "1"})
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if cookie:
            headers["Cookie"] = cookie
        c.request("POST", "/pay", body=body, headers=headers)
        r = c.getresponse()
        out = (r.status, r.getheader("Location") or "",
               r.read().decode("utf-8", "replace"))
        c.close()
        return out

    token = urllib.parse.parse_qs(urllib.parse.urlparse(
        link.replace("&amp;", "&")).query)["t"][0]
    try:
        st, where, body = post_pay(token)
        check("a customer who is not logged in pays straight from the "
              "emailed link: Pay by card goes to Yoco, not to a login page",
              st == 303 and where == "https://c.yoco.test/pay"
              and len(started) == 1)
        check("...charged the invoice's own amount, converted to rands",
              bool(started) and started[0]
              == round(orders[0]["amount_cents"] / 100 * 18 * 100))
        cookie = "; ".join(f"{c.name}={c.value}" for c in
                           op.handlers[[type(h).__name__ for h in op.handlers]
                                       .index("HTTPCookieProcessor")]
                           .cookiejar)
        st, where, body = post_pay(token, cookie)
        check("...and so does someone who happens to be logged in -- no "
              "'bad csrf token'", st == 303 and "csrf" not in body.lower()
              and where == "https://c.yoco.test/pay")
        st, where, body = post_pay("forged.token.here")
        check("a forged pay link still gets nowhere",
              st == 200 and "not valid" in body and len(started) == 2)
    finally:
        yoco_mod.create_checkout, billing_mod.zar_amount = (orig_checkout,
                                                            orig_zar)

    # Yoco's signed webhook says it was paid, exactly as it would.
    event = json.dumps({"type": "payment.succeeded", "payload": {
        "id": "p_up1", "amount": started[0] if started else 0,
        "metadata": {"order": str(orders[0]["id"])}}}).encode()
    ts = str(int(time.time()))
    sig = base64.b64encode(hmac.new(
        base64.b64decode(SECRET[len("whsec_"):]),
        b"msg_up1." + ts.encode() + b"." + event,
        hashlib.sha256).digest()).decode()
    c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1],
                                   timeout=15)
    c.request("POST", "/billing/yoco-webhook", body=event, headers={
        "Content-Type": "application/json", "webhook-id": "msg_up1",
        "webhook-timestamp": ts, "webhook-signature": f"v1,{sig}"})
    hook = c.getresponse()
    hook.read()
    c.close()
    row = bs.get(org)
    check("Yoco's webhook marks the invoice paid...",
          hook.status == 200 and bs.order(orders[0]["id"])["status"] == "paid")
    check("...and paying it moves the packet and leaves the renewal date alone",
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
