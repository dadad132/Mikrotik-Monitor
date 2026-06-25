"""Offline tests for the (dormant) Stripe billing module: device-limit
enforcement, webhook signature verification, and applying webhook events to the
local store. No network — the Stripe REST calls are not exercised here.

Run:  ./.venv/Scripts/python.exe tests/billing_test.py
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import billing

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


def signed(payload: bytes, secret: str, ts=None) -> str:
    ts = ts or int(time.time())
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + payload,
                   hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


print("Device-limit enforcement:")
check("unlimited (0) always allows", billing.can_add_device(0, 999))
check("under the limit allows", billing.can_add_device(5, 4))
check("at the limit blocks", not billing.can_add_device(5, 5))

print("Limit from a subscription object:")
check("metadata.device_limit wins",
      billing.limit_from_subscription(
          {"metadata": {"device_limit": "10"},
           "items": {"data": [{"quantity": 3}]}}) == 10)
check("falls back to seat quantity",
      billing.limit_from_subscription({"items": {"data": [{"quantity": 7}]}}) == 7)
check("nothing -> unlimited (0)", billing.limit_from_subscription({}) == 0)

print("Webhook signature verification:")
secret = "whsec_test_123"
body = json.dumps({"type": "ping"}).encode()
ev = billing.verify_webhook(body, signed(body, secret), secret)
check("valid signature parses the event", ev["type"] == "ping")
try:
    billing.verify_webhook(body, signed(body, "wrong_secret"), secret)
    check("bad signature rejected", False)
except ValueError:
    check("bad signature rejected", True)
try:
    billing.verify_webhook(body, signed(body, secret, ts=1), secret)
    check("stale timestamp rejected", False)
except ValueError:
    check("stale timestamp rejected", True)
try:
    billing.verify_webhook(body, "garbage", secret)
    check("malformed header rejected", False)
except ValueError:
    check("malformed header rejected", True)

print("Applying webhook events to the store:")
tmp = tempfile.mkdtemp()
store = billing.BillingStore(os.path.join(tmp, "b.db"))
check("new org is unlimited by default", store.device_limit(1) == 0)
check("can add freely under no limit", store.can_add(1, 100))
# Checkout completes -> link Stripe customer to org 1.
store.apply_event({"type": "checkout.session.completed",
                   "data": {"object": {"client_reference_id": "1",
                                       "customer": "cus_ABC"}}})
check("checkout links the customer to the org",
      store.org_for_customer("cus_ABC") == 1)
# Subscription becomes active with a 3-device quantity.
store.apply_event({"type": "customer.subscription.updated",
                   "data": {"object": {"id": "sub_1", "customer": "cus_ABC",
                                       "status": "active",
                                       "items": {"data": [{"quantity": 3,
                                                 "price": {"id": "price_x"}}]}}}})
check("active subscription sets the device limit", store.device_limit(1) == 3)
check("now blocked at the limit", not store.can_add(1, 3))
check("still allowed under the limit", store.can_add(1, 2))
# Cancellation -> back to unlimited-but-inactive (limit cleared).
store.apply_event({"type": "customer.subscription.deleted",
                   "data": {"object": {"id": "sub_1", "customer": "cus_ABC",
                                       "status": "canceled"}}})
row = store.get(1)
check("cancellation clears the limit + marks canceled",
      row["device_limit"] == 0 and row["status"] == "canceled")
store.close()

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL BILLING TESTS PASSED")
