"""The receipt, and the email, say what the card was actually charged.

Reported with a real payment: a $25 invoice, paid by card, charged R411.xx.
The invoice said $25.00 and nothing else, so the customer looked the rate up
-- and got R410.xx, because a live rate moves all day and ours is the ECB's
daily reference. The "payment received" email said "we have received R25.00":
the dollar figure with a rand sign in front of it.

Now:
  * the rand charge and the rate behind it are recorded on the order when
    the checkout opens, and the webhook records what Yoco actually took
  * a receipt is in the currency the card was charged, with the dollar price
    and the exact rate (source and date) between them
  * an unpaid invoice is in rand for a reader in South Africa -- a browser
    region of ZA, or a company that has already paid in rand -- and in
    dollars otherwise, with the rand a card payment would come to today
  * the email says what was received in rand, what that is in dollars, the
    rate, and the date the packet is now paid up to

Run:  ./.venv/Scripts/python.exe tests/charged_currency_test.py
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
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
import mikromon.fxrate as FX  # noqa: E402
import mikromon.notify.org_email as org_email  # noqa: E402
import mikromon.yoco as yoco_mod  # noqa: E402
from mikromon import paylink, web, web_auth  # noqa: E402
from mikromon.auth import AuthStore  # noqa: E402
from mikromon.config import DEFAULT_THRESHOLDS, SmtpConfig  # noqa: E402
from mikromon.metrics import MetricsStore  # noqa: E402

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


RATE = {"rate": 16.4492, "date": "2026-10-20", "source": "ECB reference rate",
        "pair": "USDZAR", "fetched": time.time()}
BASIS = FX.describe(RATE)
NOW = time.time()

print("Both figures, on the order")
st = B.BillingStore(os.path.join(tempfile.mkdtemp(), "b.db"))
oid = st.create_order(1, "d5", 2500, currency="USD", due=NOW + 7 * 86400)
st.set_order_charge(oid, 41123, "ZAR", 16.4492, BASIS)
o = st.order(oid)
check("opening the checkout records the rand charge and the rate behind it",
      o["charged_cents"] == 41123 and o["charged_currency"] == "ZAR"
      and o["fx_rate"] == 16.4492 and "ECB reference rate of 2026-10-20"
      in o["fx_basis"])
st.record_charged(oid, 41125, "ZAR")
check("...and the webhook records what Yoco actually took",
      st.order(oid)["charged_cents"] == 41125)
st.record_charged(oid, 0, "ZAR")
check("...but an event with no amount does not wipe it",
      st.order(oid)["charged_cents"] == 41125)
a = B.order_amounts(st.order(oid))
check("a dollar invoice paid by card: $25 price, R411.25 charged, at the rate",
      a["usd"] == 25.0 and a["charged"] == 411.25
      and a["charged_currency"] == "ZAR" and a["rate"] == 16.4492)
zo = st.create_order(1, "d5", 41123, currency="ZAR", fx_rate=16.4492,
                     fx_basis=BASIS)
a = B.order_amounts(st.order(zo))
check("an order the Billing tab opened in rand: the rand is the charge, the "
      "dollars come back through its rate",
      a["charged"] == 411.23 and a["charged_currency"] == "ZAR"
      and abs(a["usd"] - 25.0) < 0.01)

print("\nThe receipt")
paid = dict(st.order(oid), status="paid", paid=NOW, payment_id="p_1")
f = web_auth._invoice_fields({"name": "ECA Consulting (Pty) Ltd"}, paid,
                             {"name": "Sales"})
check("it is in the currency the card was charged: R411.25, not $25.00",
      f["total"] == "R411.25" and f["currency"] == "ZAR")
check("...with the dollar price and the exact rate, source and date, so it "
      "can be checked rather than looked up",
      "Price US$25.00, charged by card in rand" in f["payment_block"]
      and "ECB reference rate of 2026-10-20" in f["payment_block"]
      and "16.4492" in f["payment_block"])
old = dict(paid, charged_cents=None, charged_currency=None)
f = web_auth._invoice_fields({"name": "ECA"}, old, {})
check("a card payment made before the charge was recorded says so, rather "
      "than inventing a rand figure",
      f["total"] == "$25.00" and "was not recorded" in f["payment_block"])
eft = dict(old, payment_id="eft:6")
check("...and a bank transfer recorded by hand has no card note",
      "was not recorded" not in web_auth._invoice_fields(
          {"name": "ECA"}, eft, {})["payment_block"])

print("\nAn invoice not paid yet")
unpaid = dict(st.order(oid), charged_cents=None, charged_currency=None,
              status="pending", paid=None)
FX._cache["USDZAR"] = dict(RATE)
f = web_auth._invoice_fields({"name": "ECA"}, unpaid, {},
                             pay_link="https://x/pay?t=1", local="ZAR")
check("for a reader in South Africa it is in rand, at the last published "
      "rate, saying the rate on the day it is paid is the one charged",
      f["total"] == "R411.23" and f["currency"] == "ZAR"
      and "rate on the day it is paid" in f["payment_block"])
f = web_auth._invoice_fields({"name": "ECA"}, unpaid, {},
                             pay_link="https://x/pay?t=1")
check("for anybody else it is in dollars, with what a card payment comes to "
      "in rand today", f["total"] == "$25.00"
      and "about R411.23" in f["payment_block"])
FX._cache.clear()
_cp = FX.CACHE_PATH
FX.CACHE_PATH = ""
f = web_auth._invoice_fields({"name": "ECA"}, unpaid, {},
                             pay_link="https://x/pay?t=1", local="ZAR")
check("with no rate to hand it stays in dollars rather than guessing -- and "
      "drawing the invoice never waits on a rate provider",
      f["total"] == "$25.00" and "R" not in f["total"])
FX.CACHE_PATH = _cp

print("\nThe email")
text = web._payment_received_text(
    paid, "ECA Consulting (Pty) Ltd",
    time.mktime((2026, 11, 28, 0, 0, 0, 0, 0, -1)))
check("it says what was received in rand -- it said R25.00 for a $25 "
      "invoice charged R411", "we have received R411.25 from ECA Consulting"
      in text and "R25.00" not in text)
check("...what that is in dollars, at what rate",
      "That is US$25.00 for your packet, converted at the ECB reference rate "
      "of 2026-10-20 (1 USD = 16.4492 ZAR)." in text)
check("...and the date the packet is now paid up to, not 'the next 1 month'",
      "paid up until 28 November 2026" in text and "1 month" not in text)


# ---- end to end: pay link -> Yoco -> webhook -> receipt and email ---------
tmp = tempfile.mkdtemp()
mdb, sfile, adb, bdb = (os.path.join(tmp, x) for x in
                        ("m.db", "s.json", "a.db", "b.db"))
MetricsStore(mdb).close()
with open(sfile, "w") as fh:
    json.dump({"devices": {}}, fh)
auth = AuthStore(adb)
org = auth.signup("jp@eca.test", "secret123", "ECA Consulting (Pty) Ltd")
SECRET = "whsec_" + base64.b64encode(b"charged-test-signing-key-32byte").decode()
auth.set_yoco({"secret_key": "sk_test_x", "webhook_secret": SECRET})
auth.set_setting("public_base_url", "https://easymikrotik.test")
bs = B.BillingStore(bdb)
period_end = B.first_billing_date(time.time())
bs.set_plan(org, "d5", period_end=period_end)
inv = bs.create_order(org, "d5", 2500, currency="USD", due=period_end)

sent = []
started = []
orig = (org_email._smtp_send, yoco_mod.create_checkout, B.zar_amount)
org_email._smtp_send = lambda cfg, msg: sent.append(msg)
yoco_mod.create_checkout = lambda key, cents, **kw: (
    started.append(cents) or {"id": "ch_1",
                              "redirectUrl": "https://c.yoco.test/pay"})
B.zar_amount = lambda usd: {"amount": round(usd * RATE["rate"], 2),
                            "rate": RATE["rate"], "date": RATE["date"],
                            "source": RATE["source"], "stale": False}
srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(
    mdb, sfile, auth, web.SessionManager(), secure_cookies=False,
    defaults=dict(DEFAULT_THRESHOLDS), billing_cfg={"db": bdb},
    devices_db=os.path.join(tmp, "d.db"),
    smtp_cfg=SmtpConfig(host="smtp.test", from_addr="noreply@eca.test"),
    admin_2fa=False))
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
op = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def get(path, lang=""):
    r = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}")
    if lang:
        r.add_header("Accept-Language", lang)
    try:
        resp = op.open(r, timeout=15)
        return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


try:
    print("\nEnd to end")
    op.open(urllib.request.Request(
        f"http://127.0.0.1:{PORT}/login", data=urllib.parse.urlencode(
            {"email": "jp@eca.test", "password": "secret123"}).encode()),
        timeout=15)
    FX._cache["USDZAR"] = dict(RATE)
    st_, page = get(f"/billing/invoice?id={inv}", "en-ZA,en;q=0.9")
    check("an unpaid invoice opened from a South African browser is in rand",
          st_ == 200 and "R411.23" in page and "Rate (ZAR)" in page)
    st_, page = get(f"/billing/invoice?id={inv}", "en-US,en;q=0.9")
    check("...and from a browser elsewhere, in dollars with the rand beside "
          "it", "$25.00" in page and "about R411.23" in page
          and "Rate (USD)" in page)

    token = paylink.make(auth, inv)
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=15)
    c.request("POST", "/pay", body=urllib.parse.urlencode(
        {"t": token, "agree": "1"}),
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    c.getresponse().read()
    c.close()
    o = bs.order(inv)
    check("paying from the link records the rand charge and the rate on the "
          "invoice", started == [41123] and o["charged_cents"] == 41123
          and o["fx_rate"] == RATE["rate"]
          and "ECB reference rate of 2026-10-20" in (o["fx_basis"] or ""))

    event = json.dumps({"type": "payment.succeeded", "payload": {
        "id": "p_1", "amount": 41123,
        "metadata": {"order": str(inv)}}}).encode()
    ts = str(int(time.time()))
    sig = base64.b64encode(hmac.new(
        base64.b64decode(SECRET[len("whsec_"):]),
        b"msg_1." + ts.encode() + b"." + event, hashlib.sha256).digest()).decode()
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=15)
    c.request("POST", "/billing/yoco-webhook", body=event, headers={
        "Content-Type": "application/json", "webhook-id": "msg_1",
        "webhook-timestamp": ts, "webhook-signature": f"v1,{sig}"})
    c.getresponse().read()
    c.close()
    for _ in range(50):
        if sent:
            break
        time.sleep(0.1)
    o = bs.order(inv)
    check("Yoco's webhook marks it paid and records what it took",
          o["status"] == "paid" and o["charged_cents"] == 41123)
    body = sent[-1].get_content() if sent else ""
    check("the email says R411.23 was received -- not R25.00",
          "we have received R411.23" in body and "R25.00" not in body
          and "US$25.00" in body)
    st_, page = get(f"/billing/invoice?id={inv}", "en-US")
    check("the receipt is in rand whatever the browser, since that is what "
          "the card was charged", "Total Paid" in page and "R411.23" in page
          and "Price US$25.00, charged by card in rand" in page)
    st_, page = get("/billing", "en-US")
    check("the payments list shows the rand charge beside the price",
          "(R411.23)" in page)
    inv2 = bs.create_order(org, "d5", 2500, currency="USD",
                           due=B.add_billing_months(period_end, 1))
    st_, page = get(f"/billing/invoice?id={inv2}", "en-US,en;q=0.9")
    check("a company that has paid in rand gets its next invoice in rand, "
          "whatever its browser's language", "Rate (ZAR)" in page
          and "R411.23" in page)
finally:
    srv.shutdown()
    org_email._smtp_send, yoco_mod.create_checkout, B.zar_amount = orig
    FX._cache.clear()

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL CHARGED CURRENCY TESTS PASSED")
