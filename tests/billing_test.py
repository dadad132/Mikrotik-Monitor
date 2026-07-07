"""Offline tests for the PayFast billing module: device-limit enforcement,
signed payment-link building, ITN signature verification (including the
fail-closed/trust-signature fallback when PayFast's validate endpoint is
unreachable), and the BillingStore trial/active/grace/lockout lifecycle.

No real network calls are made — verify_itn's call to PayFast's validate
endpoint is exercised by monkeypatching urllib.request.urlopen.

Run:  ./.venv/Scripts/python.exe tests/billing_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import billing

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


class _FakeResponse:
    def __init__(self, text): self._text = text
    def read(self): return self._text.encode()
    def __enter__(self): return self
    def __exit__(self, *a): return False


def _patch_urlopen(behavior):
    """behavior: a callable(req) -> _FakeResponse, or an Exception instance to
    raise (simulating the validate endpoint being unreachable)."""
    import urllib.request as ur
    original = ur.urlopen

    def fake(req, timeout=None):
        if isinstance(behavior, Exception):
            raise behavior
        return behavior(req)

    ur.urlopen = fake
    return original


def _unpatch_urlopen(original):
    import urllib.request as ur
    ur.urlopen = original


print("Device-limit enforcement:")
check("unlimited (0) always allows", billing.can_add_device(0, 999))
check("under the limit allows", billing.can_add_device(5, 4))
check("at the limit blocks", not billing.can_add_device(5, 5))

print("Signed payment-link building (build_payment_data):")
data = billing.build_payment_data(
    merchant_id="10000100", merchant_key="46f0cd694581a",
    passphrase="jt7NOE43FZPn", sandbox=True,
    org_id=42, plan_name="small", buyer_email="owner@acme.test",
    buyer_name="Ada Owner", notify_url="https://x/billing/itn",
    return_url="https://x/billing/ok", cancel_url="https://x/billing/cancel")
check("amount matches the plan price", data["amount"] == "1270.00")
check("custom fields route the ITN back to the org + plan",
      data["custom_int1"] == "42" and data["custom_str1"] == "small")
check("buyer name is split into first/last",
      data["name_first"] == "Ada" and data["name_last"] == "Owner")
check("merchant_key is not signed but is present in the form data",
      "merchant_key" in data and "signature" in data)
try:
    billing.build_payment_data(
        merchant_id="x", merchant_key="y", org_id=1, plan_name="nope",
        notify_url="n", return_url="r", cancel_url="c")
    check("unknown plan raises", False)
except ValueError:
    check("unknown plan raises", True)

print("ITN signature verification (verify_itn):")
passphrase = "jt7NOE43FZPn"
good = {"payment_status": "COMPLETE", "custom_int1": "42",
        "custom_str1": "small", "m_payment_id": "42:100"}
good["signature"] = billing._pf_signature(good, passphrase)
bad = dict(good, signature="0" * 32)

orig = _patch_urlopen(RuntimeError("should not reach the network"))
check("bad signature is rejected without even calling the network",
      billing.verify_itn(bad, passphrase=passphrase) is False)
_unpatch_urlopen(orig)

orig = _patch_urlopen(urllib.error.URLError("unreachable"))
check("good signature + passphrase set + validate unreachable -> trusted",
      billing.verify_itn(good, passphrase=passphrase) is True)
check("good signature + NO passphrase + validate unreachable -> fail closed",
      billing.verify_itn(good, passphrase="") is False)
_unpatch_urlopen(orig)

orig = _patch_urlopen(lambda req: _FakeResponse("VALID"))
check("validate endpoint reachable and confirms -> True",
      billing.verify_itn(good, passphrase=passphrase) is True)
_unpatch_urlopen(orig)

orig = _patch_urlopen(lambda req: _FakeResponse("INVALID"))
check("validate endpoint reachable and denies -> False",
      billing.verify_itn(good, passphrase=passphrase) is False)
_unpatch_urlopen(orig)

print("cancel_subscription (best-effort, never raises):")
orig = _patch_urlopen(urllib.error.URLError("unreachable"))
check("network failure returns False instead of raising",
      billing.cancel_subscription("tok123", merchant_id="m", merchant_key="k",
                                  passphrase=passphrase) is False)
_unpatch_urlopen(orig)

print("BillingStore — trial / active / grace / lockout lifecycle:")
tmp = tempfile.mkdtemp()
store = billing.BillingStore(os.path.join(tmp, "b.db"))

check("org with no billing record is on the free-plan cap",
      store.device_limit(1) == billing.FREE_DEVICES
      and store.billing_status(1) == "none" and not store.is_locked(1))
check("free-plan cap is enforced", store.can_add(1, billing.FREE_DEVICES - 1)
      and not store.can_add(1, billing.FREE_DEVICES))

store.start_trial(2)
check("start_trial sets status=trial with the trial device cap",
      store.billing_status(2) == "trial"
      and store.device_limit(2) == billing.FREE_DEVICES
      and not store.is_locked(2))

# A completed payment activates the org at the plan's device limit.
store.apply_itn({"payment_status": "COMPLETE", "custom_int1": "3",
                 "custom_str1": "medium", "m_payment_id": "3:1",
                 "token": "TOK-3"})
check("COMPLETE activates the org at the plan's device limit",
      store.billing_status(3) == "active" and store.device_limit(3) == 30)
check("can_add respects the active plan's limit",
      store.can_add(3, 29) and not store.can_add(3, 30))
check("org_for_token resolves the org from its subscription token",
      store.org_for_token("TOK-3") == 3)

# A failed/cancelled payment starts the grace period (org stays usable).
store.apply_itn({"payment_status": "CANCELLED", "custom_int1": "3",
                 "custom_str1": "medium", "m_payment_id": "3:2"})
check("CANCELLED moves the org into its grace period, not locked yet",
      store.billing_status(3) == "grace" and store.in_grace_period(3)
      and not store.is_locked(3))
check("days_left_in_grace is within the configured grace window",
      0 < store.days_left_in_grace(3) <= billing.GRACE_DAYS)

# Once the grace deadline has passed, the org is locked.
store._upsert(3, grace_period_end=time.time() - 1)
check("a grace deadline in the past locks the org",
      store.is_locked(3) and store.billing_status(3) == "locked"
      and not store.in_grace_period(3))

store.close()

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL BILLING TESTS PASSED")
