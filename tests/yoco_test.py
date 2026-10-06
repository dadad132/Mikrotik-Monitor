"""Offline tests for the Yoco payment loop: webhook signature verification,
checkout creation, and the order lifecycle that turns a payment into a plan.

The point of most of these is that money is involved, so the interesting
cases are the ones where somebody is lying to us: a replayed callback, a
tampered body, a forged signature, a payment for less than the order, or the
same genuine callback delivered twice (which Yoco does, on purpose).

No real network calls: urlopen is monkeypatched.

Run:  ./.venv/Scripts/python.exe tests/yoco_test.py
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import fxrate as _FX
from mikromon import yoco
from mikromon.billing import BillingStore, plan_by_name, zar_amount

# Pinned: an expected figure must not move with the market, and
# checking arithmetic should not need a network call.
_FX._cache["USDZAR"] = {"rate": 16.2593, "date": "2026-09-21",
                        "source": "ECB reference rate",
                        "pair": "USDZAR", "fetched": 1e12}

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


SECRET = "whsec_" + base64.b64encode(b"a-shared-signing-key-32-bytes!!").decode()


def sign(body: bytes, *, wid="msg_1", ts=None, secret=SECRET):
    """Build the three headers Yoco sends, the way Yoco builds them."""
    ts = str(int(ts if ts is not None else time.time()))
    key = base64.b64decode(secret[len("whsec_"):])
    signed = wid.encode() + b"." + ts.encode() + b"." + body
    sig = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()
    return {"webhook-id": wid, "webhook-timestamp": ts,
            "webhook-signature": f"v1,{sig}"}


BODY = json.dumps({
    "type": "payment.succeeded",
    "payload": {"id": "p_abc", "amount": 202400,
                "metadata": {"order": "1", "org": "3"}},
}).encode()


# ---------------------------------------------------------------- signatures
print("\nWebhook verification")

check("a genuine, freshly signed event verifies",
      yoco.verify_webhook(SECRET, sign(BODY), BODY))

check("a body edited in flight is rejected -- this is the whole point: the "
      "amount and the order id live in the body, so an unsigned body means "
      "anyone who finds the URL can grant themselves a packet",
      not yoco.verify_webhook(SECRET, sign(BODY),
                              BODY.replace(b"202400", b"100")))

check("a signature made with a different secret is rejected",
      not yoco.verify_webhook(SECRET, sign(BODY, secret="whsec_" +
                                           base64.b64encode(b"wrong").decode()),
                              BODY))

check("a real event captured and replayed ten minutes later is rejected, so "
      "one recording cannot be re-sent monthly to keep a plan alive",
      not yoco.verify_webhook(SECRET, sign(BODY, ts=time.time() - 600), BODY))

check("...but a couple of seconds of clock drift still verifies",
      yoco.verify_webhook(SECRET, sign(BODY, ts=time.time() - 5), BODY))

check("with no secret configured, nothing verifies -- the webhook fails "
      "closed rather than accepting everything while unconfigured",
      not yoco.verify_webhook("", sign(BODY), BODY))

check("missing headers are rejected rather than raising",
      not yoco.verify_webhook(SECRET, {}, BODY))

# During a secret rotation Yoco signs with both. Dropping the second would
# quietly lose real payments for the length of the rotation.
_h = sign(BODY)
_h["webhook-signature"] = "v1,ZmFrZQ== " + _h["webhook-signature"]
check("during a secret rotation, two signatures are sent and the valid one "
      "is accepted",
      yoco.verify_webhook(SECRET, _h, BODY))

check("the secret is base64-decoded, not signed as printable text: signing "
      "the raw string verifies nothing and fails against every real event",
      yoco._secret_bytes(SECRET) == b"a-shared-signing-key-32-bytes!!")


# -------------------------------------------------------------- event shapes
print("\nReading an event")

kind, meta, pid, amount = yoco.event_of(json.loads(BODY))
check("type, metadata, payment id and amount are read from the nested shape",
      kind == "payment.succeeded" and meta["order"] == "1"
      and pid == "p_abc" and amount == 202400)

kind2, meta2, pid2, _ = yoco.event_of(
    {"type": "payment.succeeded", "id": "p_flat", "metadata": {"order": "9"}})
check("a flat event (older shape) is read too, so a format change does not "
      "silently stop every upgrade completing",
      kind2 == "payment.succeeded" and meta2["order"] == "9" and pid2 == "p_flat")

check("a junk payload yields empty values instead of raising",
      yoco.event_of({}) == ("", {}, "", 0))


# ----------------------------------------------------------------- checkouts
print("\nCreating a checkout")

_seen = {}


class _Resp:
    def __init__(self, text): self._t = text
    def read(self): return self._t.encode()
    def __enter__(self): return self
    def __exit__(self, *a): return False


def _fake_urlopen(req, timeout=None):
    _seen["body"] = json.loads(req.data.decode())
    _seen["auth"] = req.headers.get("Authorization")
    return _Resp(json.dumps({"id": "ch_1", "redirectUrl": "https://pay/1"}))


_real = urllib.request.urlopen
urllib.request.urlopen = _fake_urlopen
try:
    res = yoco.create_checkout("sk_test", 202400, metadata={"order": 1},
                               success_url="https://x/ok")
    check("a checkout returns Yoco's redirect URL",
          res["redirectUrl"] == "https://pay/1")
    check("the amount is sent in cents as an integer, because money in floats "
          "is how R19.99 becomes R19.990000000000002",
          _seen["body"]["amount"] == 202400
          and isinstance(_seen["body"]["amount"], int))
    check("metadata values are stringified, since that is what comes back",
          _seen["body"]["metadata"] == {"order": "1"})
    check("the secret key is sent as a bearer token, not in the body",
          _seen["auth"] == "Bearer sk_test"
          and "sk_test" not in json.dumps(_seen["body"]))

    try:
        yoco.create_checkout("", 100)
        check("an unconfigured server refuses to start a checkout", False)
    except yoco.YocoError:
        check("an unconfigured server refuses to start a checkout", True)

    try:
        yoco.create_checkout("sk_test", 0)
        check("a zero-rand checkout is refused", False)
    except yoco.YocoError:
        check("a zero-rand checkout is refused", True)
finally:
    urllib.request.urlopen = _real


# ------------------------------------------------------- webhook registration
print("\nRegistering the webhook")

_reg = {}


def _reg_urlopen(req, timeout=None):
    _reg["url"] = req.full_url
    _reg["body"] = json.loads(req.data.decode())
    _reg["auth"] = req.headers.get("Authorization")
    return _Resp(json.dumps({"id": "wh_1", "secret": "whsec_abc"}))


urllib.request.urlopen = _reg_urlopen
try:
    out = yoco.register_webhook("sk_live", "https://mm.example/billing/yoco-webhook")
    check("registering returns the signing secret, which Yoco gives out once "
          "and never again -- so the server stores it rather than asking "
          "somebody to copy it",
          out["secret"] == "whsec_abc")
    check("it posts to Yoco's webhook endpoint with the key as a bearer token",
          _reg["url"] == "https://payments.yoco.com/api/webhooks"
          and _reg["auth"] == "Bearer sk_live")
    check("...sending the name and url fields Yoco documents",
          set(_reg["body"]) == {"name", "url"}
          and _reg["body"]["url"].endswith("/billing/yoco-webhook"))

    try:
        yoco.register_webhook("sk_live", "http://mm.example/billing/yoco-webhook")
        check("a plain-http URL is refused before Yoco ever sees it", False)
    except yoco.YocoError as exc:
        check("a plain-http URL is refused before Yoco ever sees it, with a "
              "message that says which URL was wrong -- Yoco will not deliver "
              "to http, and their rejection does not say why",
              "https" in str(exc).lower())

    try:
        yoco.register_webhook("", "https://mm.example/x")
        check("registering without a secret key is refused", False)
    except yoco.YocoError:
        check("registering without a secret key is refused", True)
finally:
    urllib.request.urlopen = _real


def _no_secret(req, timeout=None):
    return _Resp(json.dumps({"id": "wh_2"}))


urllib.request.urlopen = _no_secret
try:
    yoco.register_webhook("sk_live", "https://mm.example/x")
    check("a registration that comes back without a secret is treated as a "
          "failure", False)
except yoco.YocoError:
    check("a registration that comes back without a secret is treated as a "
          "failure, rather than saving a half-configured state that looks "
          "fine on screen and silently drops every payment", True)
finally:
    urllib.request.urlopen = _real


# ------------------------------------------------------------------- orders
print("\nOrders: a payment becoming a plan")

_fd, _path = tempfile.mkstemp(suffix=".db")
os.close(_fd)
store = BillingStore(_path)
try:
    plan = plan_by_name("d25")
    cents = int(round(zar_amount(plan["price_usd"])["amount"] * 100)) * 3
    oid = store.create_order(3, "d25", cents, months=3)
    order = store.order(oid)
    check("an order is written before anyone is sent to pay, so a payment "
          "always has something to be reconciled against",
          order["status"] == "pending" and order["amount_cents"] == cents)

    check("the first webhook for an order applies it",
          store.mark_order_paid(oid, "p_abc") is True)
    check("the same webhook delivered again does not -- Yoco retries by "
          "design, and a second application would extend the plan twice for "
          "one payment",
          store.mark_order_paid(oid, "p_abc") is False)

    store.apply_paid_order(store.order(oid))
    bill = store.get(3)
    check("paying moves the company onto the packet it paid for",
          bill["plan"] == "d25" and bill["device_limit"] == 25)
    from mikromon.billing import BILLING_DAY, add_billing_months
    _end = bill["current_period_end"]
    check("...for the months it paid for: three whole calendar months, "
          "landing on the 28th like every other account",
          time.localtime(_end).tm_mday == BILLING_DAY)
    _months = ((time.localtime(_end).tm_year - time.localtime().tm_year) * 12
               + time.localtime(_end).tm_mon - time.localtime().tm_mon)
    check(f"...three months on, not ninety days (got {_months})",
          2 <= _months <= 4)

    # Renewing early must add to what is left, not restart from today.
    oid2 = store.create_order(3, "d25", cents, months=1)
    store.mark_order_paid(oid2, "p_def")
    store.apply_paid_order(store.order(oid2))
    _end2 = store.get(3)["current_period_end"]
    check("renewing early adds to the time already paid for rather than "
          "throwing it away -- one more calendar month past where it "
          "already ended, not one month from today",
          _end2 == add_billing_months(_end, 1))

    # Reported: "the new account that just paid is only expiring after 61
    # days and not 30". A first payment added a month to TODAY, and
    # add_billing_months always lands on the 28th of the NEXT month -- so
    # paying on 5 October skipped 28 October and ran to 28 November. With
    # the seven days of grace the panel counts down to, that read 61.
    from mikromon.billing import days_until_suspension, first_billing_date
    _oct5 = time.mktime((2026, 10, 5, 10, 0, 0, 0, 0, -1))
    oid4 = store.create_order(4, "d25", cents, months=1)
    store.mark_order_paid(oid4, "p_new")
    store.apply_paid_order(store.order(oid4), now=_oct5)
    _row4 = store.get(4)
    check("a new account paying on 5 October is paid up to 28 October, the "
          "first billing date, as when a packet is switched on by hand",
          time.strftime("%Y-%m-%d", time.localtime(
              _row4["current_period_end"])) == "2026-10-28")
    check("...so its countdown reads 30 days (23 paid + 7 grace), not 61",
          round(days_until_suspension(_row4, "active", now=_oct5)) == 30)
    _oct20 = time.mktime((2026, 10, 20, 10, 0, 0, 0, 0, -1))
    oid5 = store.create_order(5, "d25", cents, months=1)
    store.mark_order_paid(oid5, "p_new2")
    store.apply_paid_order(store.order(oid5), now=_oct20)
    check("one paying on 20 October is active to 28 October, not to the end "
          "of November -- the first payment buys the rest of this month",
          time.strftime("%Y-%m-%d", time.localtime(
              store.get(5)["current_period_end"])) == "2026-10-28")
    # Priced at 23:30 on the 27th, settled just after midnight: it covers
    # what it was priced for, not a month from when the card cleared.
    _late = time.mktime((2026, 10, 27, 23, 30, 0, 0, 0, -1))
    oid8 = store.create_order(8, "d25", cents, months=1, kind="first")
    store.db.execute("UPDATE orders SET created = ? WHERE id = ?",
                     (_late, oid8))
    store.db.commit()
    store.mark_order_paid(oid8, "p_midnight")
    store.apply_paid_order(store.order(oid8), now=_late + 3600)
    check("a first payment covers the days it was priced for, even when the "
          "card settles after midnight",
          time.strftime("%Y-%m-%d", time.localtime(
              store.get(8)["current_period_end"])) == "2026-10-28")
    # A renewal paid after its period ended had the same fault: a month
    # added to the day it was paid, then rounded on to the next 28th.
    store._upsert(6, status="active", plan="d25", device_limit=25,
                  current_period_end=time.mktime(
                      (2026, 9, 28, 0, 0, 0, 0, 0, -1)))
    oid6 = store.create_order(6, "d25", cents, months=1)
    store.mark_order_paid(oid6, "p_late")
    store.apply_paid_order(store.order(oid6), now=_oct5)
    check("a renewal paid late runs to the next billing date, not a month "
          "past it", time.strftime("%Y-%m-%d", time.localtime(
              store.get(6)["current_period_end"])) == "2026-10-28")

    # And the account that was already given the extra month: suspending
    # and restoring it changed nothing, because neither touches the date.
    store._upsert(7, status="active", plan="d25", device_limit=25,
                  current_period_end=time.mktime(
                      (2026, 11, 28, 0, 0, 0, 0, 0, -1)))
    store.suspend(7)
    store.unsuspend(7)
    check("suspending and restoring leaves the paid-up date alone -- which "
          "is why it still said 61 days",
          time.strftime("%Y-%m-%d", time.localtime(
              store.get(7)["current_period_end"])) == "2026-11-28")
    store.set_paid_until(7, time.mktime((2026, 10, 28, 12, 0, 0, 0, 0, -1)))
    _row7 = store.get(7)
    check("set_paid_until corrects it, to the start of that 28th",
          _row7["current_period_end"]
          == time.mktime((2026, 10, 28, 0, 0, 0, 0, 0, -1)))
    check("...and on 5 October the countdown then reads 30 days",
          round(days_until_suspension(_row7, "active", now=_oct5)) == 30)
    try:
        store.set_paid_until(7, time.mktime((2026, 10, 30, 0, 0, 0, 0, 0, -1)))
        _refused = False
    except ValueError:
        _refused = True
    check("...and refuses any day but the 28th", _refused)

    # A suspended company that pays should come back on its own.
    store.suspend(3)
    oid3 = store.create_order(3, "d50", 100, months=1)
    store.mark_order_paid(oid3, "p_ghi")
    store.apply_paid_order(store.order(oid3))
    check("a suspended company that pays is un-suspended by the payment, "
          "without anyone at our end having to notice",
          not store.is_suspended(3) and store.get(3)["device_limit"] == 50)

    rows = store.orders_for_org(3)
    check("the company can see what it has bought, newest first",
          len(rows) == 3 and rows[0]["id"] == oid3)
    check("orders are scoped to the company that placed them",
          store.orders_for_org(999) == [])
finally:
    store.close()
    try:
        os.unlink(_path)
    except OSError:
        pass


print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL YOCO TESTS PASSED")
