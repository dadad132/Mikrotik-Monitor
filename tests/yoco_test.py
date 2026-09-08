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

from mikromon import yoco
from mikromon.billing import BillingStore, plan_by_name

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
    cents = int(round(plan["price_zar"] * 100)) * 3
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
    _left = (bill["current_period_end"] - time.time()) / 86400
    check(f"...for the months it paid for (~90 days, got {_left:.0f})",
          88 < _left < 92)

    # Renewing early must add to what is left, not restart from today.
    oid2 = store.create_order(3, "d25", cents, months=1)
    store.mark_order_paid(oid2, "p_def")
    store.apply_paid_order(store.order(oid2))
    _left2 = (store.get(3)["current_period_end"] - time.time()) / 86400
    check(f"renewing early adds to the time already paid for rather than "
          f"throwing it away (~120 days, got {_left2:.0f})",
          118 < _left2 < 122)

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
