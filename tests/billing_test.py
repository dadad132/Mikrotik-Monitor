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

print("Device packets (fives, up to the quote threshold):")
_devs = [p["devices"] for p in billing.PLANS]
check("packets step in fives all the way to the last tier, with no gaps -- "
      "a missing size is a customer who cannot buy what they need",
      _devs == list(range(5, billing.MAX_TIER_DEVICES + 1, 5)))
check("price rises with every step up, so a bigger packet is never cheaper "
      "than a smaller one",
      all(billing.PLANS[i]["price_usd"] < billing.PLANS[i + 1]["price_usd"]
          for i in range(len(billing.PLANS) - 1)))
check("...while the per-device rate falls with every step, which is the "
      "whole reason to buy a bigger packet",
      all(billing.tier_rate_usd(a) > billing.tier_rate_usd(b)
          for a, b in zip(_devs, _devs[1:])))
check("the ladder runs $25 for 5 devices to $290 for 100",
      billing.plan_by_name("d5")["price_usd"] == 25
      and billing.plan_by_name("d100")["price_usd"] == 290)
check("a ten-cent-per-step rate from 15 devices up, as priced",
      [billing.tier_rate_usd(n) for n in (15, 20, 45, 70, 100)]
      == [4.60, 4.50, 4.00, 3.50, 2.90])
check("every packet price is a whole dollar -- these get read off a page and "
      "typed into a banking app",
      all(float(p["price_usd"]).is_integer() for p in billing.PLANS))

print("Above the last packet it is a quote, not a tier:")
check("100 devices is still a packet",
      not billing.needs_quote(billing.MAX_TIER_DEVICES))
check("101 devices needs a quote", billing.needs_quote(101))
check("there is no tier above the threshold to accidentally sell",
      not any(p["devices"] > billing.QUOTE_ABOVE_DEVICES
              for p in billing.PLANS))

print("Retired plan names still resolve (existing subscribers):")
for _old, _want in [("starter", 5), ("small", 15), ("medium", 30),
                    ("business", 50), ("pro", 100)]:
    check(f"{_old!r} keeps its {_want}-device cap rather than dropping to the "
          f"free tier, which would lock devices a customer is paying for",
          billing.plan_by_name(_old)["devices"] == _want)
check("the retired enterprise plans keep caps larger than any tier on sale",
      billing.plan_by_name("ent500")["devices"] == 500
      and billing.plan_by_name("ent1000")["devices"] == 1000)
check("an unknown plan name still resolves to nothing",
      billing.plan_by_name("no-such-plan") is None)

print("Signed payment-link building (build_payment_data):")
_t15 = billing.plan_by_name("d15")
data = billing.build_payment_data(
    merchant_id="10000100", merchant_key="46f0cd694581a",
    passphrase="jt7NOE43FZPn", sandbox=True,
    org_id=42, plan_name="d15", buyer_email="owner@acme.test",
    buyer_name="Ada Owner", notify_url="https://x/billing/itn",
    return_url="https://x/billing/ok", cancel_url="https://x/billing/cancel")
# Derived, not hard-coded: a literal here would go stale the next time a
# price moves and would then be asserting last year's number.
check("amount matches the plan price",
      data["amount"] == f'{_t15["price_zar"]:.2f}')
check("custom fields route the ITN back to the org + plan",
      data["custom_int1"] == "42" and data["custom_str1"] == "d15")
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
      and store.device_limit(2) == billing.TRIAL_DEVICES
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

# Manual superadmin plan assignment (payment handled off-platform).
print("Manual plan assignment (superadmin):")
p_small = billing.plan_by_name("d15")
store.set_plan(10, "d15")
check("set_plan activates the org with the plan's device cap",
      store.billing_status(10) == "active"
      and store.device_limit(10) == p_small["devices"]
      and store.get(10)["plan"] == "d15")
# A superadmin re-saving a company that is still on a retired name must not
# silently shrink their cap.
store.set_plan(11, "business")
check("assigning a retired plan name still grants the cap it was sold with",
      store.device_limit(11) == 50 and store.billing_status(11) == "active")
check("assigned plan is not locked and enforces the cap",
      not store.is_locked(10)
      and store.can_add(10, p_small["devices"] - 1)
      and not store.can_add(10, p_small["devices"]))
store.set_unlimited(10)
check("set_unlimited gives an unlimited (0) cap, still active",
      store.device_limit(10) == 0 and store.can_add(10, 99999)
      and store.billing_status(10) == "active")
store.set_free(10)
check("set_free drops back to the free cap",
      store.device_limit(10) == billing.FREE_DEVICES
      and store.can_add(10, billing.FREE_DEVICES - 1)
      and not store.can_add(10, billing.FREE_DEVICES))
try:
    store.set_plan(10, "no-such-plan")
    check("set_plan rejects an unknown plan", False)
except ValueError:
    check("set_plan rejects an unknown plan", True)

print("Suspending a company that has not paid:")
store.set_plan(20, "d50")
check("a paying company is not locked", not store.is_locked(20))
store.suspend(20)
check("suspending locks them out immediately, whatever the dates say",
      store.is_locked(20) and store.billing_status(20) == "suspended"
      and store.is_suspended(20))
check("...but their plan and device cap are kept, so restoring is one flip "
      "and not an admin rebuilding the account from memory",
      store.get(20)["plan"] == "d50" and store.device_limit(20) == 50)
store.unsuspend(20)
check("restoring puts them straight back on the plan they kept",
      not store.is_locked(20) and store.billing_status(20) == "active"
      and store.device_limit(20) == 50)

# The case a date-driven lockout cannot reach: the calendar says they are
# fine, the bank says otherwise.
store.start_trial(21)
check("a company mid-trial is not locked", not store.is_locked(21))
store.suspend(21)
check("...and can still be suspended -- a manual suspension outranks an "
      "unexpired trial, which is the whole reason to have the button",
      store.is_locked(21) and store.billing_status(21) == "suspended")

store.set_free(22)
store.suspend(22)
store.unsuspend(22)
check("restoring a company that never had a plan returns them to the free "
      "cap, not to a paid state they were never on",
      store.billing_status(22) in ("none", "inactive")
      and store.device_limit(22) == billing.FREE_DEVICES)
check("unsuspend on a company that was not suspended does nothing",
      (store.set_plan(23, "d5") or store.unsuspend(23) or True)
      and store.billing_status(23) == "active")
check("suspended orgs come back in one batched query, since the alert path "
      "asks for the whole set at once during an outage",
      store.suspended_orgs() == {21})

print("Quote requests from companies past the last packet:")
store.add_quote_request(77, 340, "ops@myit.test", "Q4 rollout, 340 sites")
check("a request is recorded with the size and contact asked for",
      store.open_quote_count() == 1
      and store.quote_requests()[0]["devices"] == 340
      and store.quote_requests()[0]["contact"] == "ops@myit.test")
store.add_quote_request(77, 400, "ops@myit.test", "still waiting")
check("a second request from the same company is kept, not collapsed -- it "
      "usually means the first went unanswered, which is the signal worth "
      "seeing",
      store.open_quote_count() == 2)
check("newest first, so the panel leads with the freshest ask",
      store.quote_requests()[0]["devices"] == 400)
store.mark_quote_handled(store.quote_requests()[0]["id"])
check("marking one handled drops it off the open list without deleting it",
      store.open_quote_count() == 1
      and len(store.quote_requests(include_handled=True)) == 2)
check("a note far longer than any form should send is truncated rather than "
      "stored whole",
      (store.add_quote_request(78, 200, "x@y.z", "N" * 5000) or True)
      and len(store.quote_requests()[0]["note"]) <= 2000)

store.close()

print("EFT payment reference (manual bank-transfer reconciliation):")
from mikromon.billing import payment_reference, org_id_from_reference

check("the reference names the company, so a statement line says who paid "
      "without a lookup",
      payment_reference(42, "My IT Africa") == "MYITAFRICA-0042"
      and payment_reference(7, "Kyotech") == "KYOTECH-0007")
check("...with punctuation and spaces stripped, because a banking app's "
      "reference field rejects most of them",
      payment_reference(3, "A&B Net (Pty) Ltd.") == "ABNETPTYLTD-0003")
check("...falling back to the plain prefix when there is no name to use",
      payment_reference(9) == "EMK-0009")
check("...but the ID still decides identity, so two companies with the same "
      "name never share a reference",
      payment_reference(42, "Acme") != payment_reference(43, "Acme"))
check("...and it survives a rename: the ID half is what gets matched, so a "
      "customer's saved beneficiary keeps working",
      org_id_from_reference(payment_reference(42, "Old Name")) == 42
      and org_id_from_reference(payment_reference(42, "New Name")) == 42)
check("...and short enough to survive a banking app's reference field, "
      "which truncates (Capitec's is 20 characters)",
      len(payment_reference(9999, "A Very Long Company Name Ltd")) <= 20)

for _raw, _want in [
        ("MYITAFRICA-0042", 42),
        ("EMK-0042", 42),              # references issued before the rename
        ("emk-0042", 42),              # statements lower-case things
        ("EMK0042", 42),               # the hyphen gets dropped
        ("EMK 42", 42),                # and re-typed loosely
        ("PAYMENT EMK-0042 MY IT AFRICA", 42),   # buried in a description
        ("EFT 20260825 MYITAFRICA-0042", 42),    # ...next to a date
        ("random text", None),
        ("", None)]:
    check(f"a statement line {_raw!r} resolves to org {_want} — bank "
          f"statements mangle what the payer typed, so matching has to "
          f"tolerate case, a missing hyphen and surrounding text",
          org_id_from_reference(_raw) == _want)

check("a reference for one org never resolves to another",
      org_id_from_reference(payment_reference(7)) == 7
      and org_id_from_reference(payment_reference(70)) == 70)
check("...including when the company name itself ends in digits: those are "
      "dropped from the name half, so they cannot run into the id and resolve "
      "to a different account",
      payment_reference(7, "Net24") == "NET-0007"
      and org_id_from_reference(payment_reference(7, "Net24")) == 7)
check("the device count is deliberately NOT in the reference -- it changes as "
      "an account grows, and a reference that changes is one the customer's "
      "saved beneficiary no longer matches",
      payment_reference(42, "My IT Africa") == "MYITAFRICA-0042")

print()
print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL BILLING TESTS PASSED")
