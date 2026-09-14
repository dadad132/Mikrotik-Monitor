"""The Invoice Ninja renewal loop: invoice before the packet lapses, and let
the payment carry the service on by itself.

The design these tests pin down is that **the webhook is never believed**.
Invoice Ninja signs nothing, so a callback only says which invoice to go and
look at; whether it is paid is read back from the API. The consequence worth
testing is the other half: a webhook that never arrives must not leave a
paying customer suspended, so the same question is asked on a timer.

No network: the API layer is monkeypatched.

Run:  ./.venv/Scripts/python.exe tests/invoiceninja_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import billing_runner, invoiceninja
from mikromon.billing import BillingStore, plan_by_name

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


class FakeAuth:
    """Just the three things billing_runner asks of the auth store."""

    def __init__(self, cfg, orgs, users):
        self._cfg, self._orgs, self._users = cfg, orgs, users

    def get_invoiceninja(self):
        return self._cfg

    def org(self, org_id):
        return self._orgs.get(int(org_id))

    def list_users(self, org_id):
        return self._users.get(int(org_id), [])


CFG = {"url": "https://billing.test", "token": "tok", "days_before": 7,
       "due_days": 7}


# ---------------------------------------------- reading a webhook payload
print("\nFinding the invoice a webhook is talking about")

check("an invoice_id anywhere in the body is found",
      invoiceninja.invoice_ids_in(
          {"data": {"invoice_id": "Inv1", "amount": 10}}) == ["Inv1"])

check("...including the shape Invoice Ninja uses for a payment, where the "
      "invoices hang off the payment as paymentables",
      invoiceninja.invoice_ids_in(
          {"payment": {"paymentables": [{"invoice_id": "A"},
                                        {"invoice_id": "B"}]}}) == ["A", "B"])

check("a bare id nested under 'invoices' counts, since that is how an "
      "invoice event arrives",
      invoiceninja.invoice_ids_in({"invoices": [{"id": "X9"}]}) == ["X9"])

check("a bare top-level id does NOT count -- that is the payment's own id, "
      "and treating it as an invoice would look up the wrong record",
      invoiceninja.invoice_ids_in({"id": "pay_1", "amount": 5}) == [])

check("duplicates collapse", invoiceninja.invoice_ids_in(
    {"a": {"invoice_id": "Z"}, "b": {"invoice_id": "Z"}}) == ["Z"])

check("junk yields nothing rather than raising",
      invoiceninja.invoice_ids_in(None) == []
      and invoiceninja.invoice_ids_in([1, "x", None]) == [])


# ------------------------------------------------------- the renewal pass
print("\nInvoicing a company before its packet lapses")

_fd, _path = tempfile.mkstemp(suffix=".db")
os.close(_fd)
store = BillingStore(_path)
raised_calls = []
paid_invoices = set()


def fake_ensure_client(base, token, org_id, name, **kw):
    return f"client-{org_id}"


def fake_create_invoice(base, token, client_id, *, description, amount,
                        due_days=7, reference="", terms=""):
    raised_calls.append({"client": client_id, "amount": amount,
                         "description": description, "reference": reference})
    return {"id": f"inv-{len(raised_calls)}", "number": f"00{len(raised_calls)}",
            "link": "https://billing.test/view/x"}


def fake_email_invoice(base, token, invoice_id):
    raised_calls[-1]["emailed"] = invoice_id


def fake_invoice_status(base, token, invoice_id):
    is_paid = invoice_id in paid_invoices
    return {"paid": is_paid, "balance": 0.0 if is_paid else 100.0,
            "amount": 100.0, "number": invoice_id, "status_id": "4" if is_paid
            else "2", "is_deleted": False}


billing_runner.ensure_client = fake_ensure_client
billing_runner.create_invoice = fake_create_invoice
billing_runner.email_invoice = fake_email_invoice
billing_runner.invoice_status = fake_invoice_status

try:
    now = time.time()
    plan = plan_by_name("d25")

    # Lapses in 3 days: inside the 7-day window.
    store.set_plan(1, "d25")
    store._upsert(1, status="active", current_period_end=now + 3 * 86400)
    # Lapses in 20 days: outside it.
    store.set_plan(2, "d25")
    store._upsert(2, status="active", current_period_end=now + 20 * 86400)
    # On a trial, with nothing to renew.
    store.start_trial(3)

    auth = FakeAuth(CFG,
                    {1: {"name": "Acme", "alert_emails": ["ops@acme.test"]},
                     2: {"name": "Later Co", "alert_emails": []}},
                    {1: [{"role": "owner", "email": "boss@acme.test"}]})

    n = billing_runner.raise_due_invoices(store, auth, CFG, now=now)
    check(f"the company whose packet lapses this week is invoiced ({n})",
          n == 1 and len(raised_calls) == 1)
    check("...for the packet it is already on, not a bigger one -- a renewal "
          "is not an upsell, and putting a larger figure on it would be a "
          "serious thing to get wrong",
          abs(raised_calls[0]["amount"] - plan["price_zar"]) < 0.01)
    check("...quoting the same reference the customer uses for an EFT, so a "
          "bank line, an Invoice Ninja record and an order can be tied "
          "together by eye",
          raised_calls[0]["reference"].startswith("ACME-"))
    check("...and it is actually emailed", raised_calls[0].get("emailed"))

    check("a company whose packet is still three weeks out is left alone",
          all(c["client"] != "client-2" for c in raised_calls))
    check("a company on a free trial is never invoiced -- billing somebody "
          "who is still evaluating would be the worst possible first "
          "impression",
          all(c["client"] != "client-3" for c in raised_calls))

    n2 = billing_runner.raise_due_invoices(store, auth, CFG, now=now + 3600)
    check("running again the next morning does not raise a second invoice "
          "for the same period", n2 == 0 and len(raised_calls) == 1)

    print("\nUntil it is paid, nothing changes")

    before = store.get(1)["current_period_end"]
    applied = billing_runner.reconcile_payments(store, CFG)
    check("an unpaid invoice applies nothing",
          applied == 0 and store.get(1)["current_period_end"] == before)

    print("\nPaying it carries the service on, with nobody intervening")

    paid_invoices.add("inv-1")
    applied = billing_runner.reconcile_payments(store, CFG)
    check("the payment is picked up and applied", applied == 1)
    row = store.get(1)
    check("...the packet continues, extended from where it was rather than "
          "from today, so nothing already paid for is lost",
          row["current_period_end"] > before
          and abs(row["current_period_end"] - (before + 30 * 86400)) < 7200)
    check("...and the company is active", row["status"] == "active")

    check("the same payment seen twice does not extend it twice -- the timer "
          "and a webhook both finding it is the normal case, not the odd one",
          billing_runner.reconcile_payments(store, CFG) == 0)

    print("\nA suspended company that pays comes back on its own")

    store.set_plan(4, "d25")
    store._upsert(4, status="active", current_period_end=now + 2 * 86400)
    auth._orgs[4] = {"name": "Lapsed Co", "alert_emails": ["a@b.c"]}
    billing_runner.raise_due_invoices(store, auth, CFG, now=now)
    store.suspend(4)
    check("...is suspended to begin with", store.is_suspended(4))
    paid_invoices.add("inv-2")
    billing_runner.reconcile_payments(store, CFG)
    check("paying the invoice lifts the suspension without anybody at our "
          "end having to notice",
          not store.is_suspended(4) and store.get(4)["status"] == "active")

    print("\nThings that should not be applied")

    store.set_plan(5, "d25")
    store._upsert(5, status="active", current_period_end=now + 2 * 86400)
    auth._orgs[5] = {"name": "Deleted Inv Co", "alert_emails": []}
    billing_runner.raise_due_invoices(store, auth, CFG, now=now)
    _before5 = store.get(5)["current_period_end"]

    def deleted_status(base, token, invoice_id):
        return {"paid": True, "balance": 0.0, "amount": 100.0,
                "number": invoice_id, "status_id": "4", "is_deleted": True}

    billing_runner.invoice_status = deleted_status
    billing_runner.reconcile_payments(store, CFG)
    check("an invoice deleted in Invoice Ninja grants nothing, even though "
          "its balance reads zero",
          store.get(5)["current_period_end"] == _before5)
    billing_runner.invoice_status = fake_invoice_status

    def boom(base, token, invoice_id):
        raise invoiceninja.InvoiceNinjaError("Invoice Ninja is down")

    billing_runner.invoice_status = boom
    check("Invoice Ninja being unreachable is survived without applying or "
          "cancelling anything -- the next pass asks again",
          billing_runner.reconcile_payments(store, CFG) == 0)
    billing_runner.invoice_status = fake_invoice_status

    print("\nWith nothing configured, the runner does nothing at all")

    check("no url or token means no calls and no errors",
          billing_runner.run_once(store, FakeAuth({}, {}, {})) == (0, 0))
finally:
    store.close()
    try:
        os.unlink(_path)
    except OSError:
        pass


print("\nReading whether an invoice is really settled")

_answers = {}
invoiceninja._api = lambda base, token, path, **kw: _answers

_answers = {"amount": 100.0, "balance": 0.0, "status_id": "4", "number": "7"}
check("an invoice whose balance has reached zero is paid",
      invoiceninja.invoice_status("u", "t", "i")["paid"])

_answers = {"amount": 100.0, "balance": 40.0, "status_id": "3", "number": "7"}
check("a PART payment is not -- the packet is granted for money received in "
      "full, and partial-payment is exactly where a status flag alone would "
      "get it wrong",
      not invoiceninja.invoice_status("u", "t", "i")["paid"])

_answers = {"amount": 0.0, "balance": 0.0, "status_id": "1", "number": "7"}
check("a zero-amount invoice is not treated as paid, even though its balance "
      "is zero and nobody has paid anything",
      not invoiceninja.invoice_status("u", "t", "i")["paid"])

_answers = {"amount": None, "balance": "oops", "status_id": None}
check("unreadable figures do not raise mid-reconcile",
      invoiceninja.invoice_status("u", "t", "i")["paid"] is False)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL INVOICE NINJA TESTS PASSED")
