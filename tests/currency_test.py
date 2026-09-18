"""Charge the price the website advertises, in the currency it advertises it.

The prices were decided in USD -- tier_rate_usd is the source, and every page
quotes dollars. The invoice was raised in rands, converted at a constant
compiled into the source:

    _ZAR_PER_USD = 18.4

That was right on the day it was written and quietly wrong every day after.
Whenever the real rate sat above it, every invoice under-charged by the
difference, on every account, for as long as nobody checked -- and nothing
could report it, because both figures were internally consistent. The site
said $345 and the invoice said R6348, and only one of those was the price.

The same mistake existed in three places, which is what makes it worth a test
file: the price, the order record that defaults to a currency nobody passed,
and the documents that print a figure with a symbol somebody assumed.

Run:  python tests/currency_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import billing as B
from mikromon import billing_runner as R
from mikromon import web_auth

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


print("\nThe price is the advertised price")

check("we bill in the currency the prices were decided in",
      B.BILLING_CURRENCY == "USD")

for p in B.PLANS:
    assert p["price"] == float(p["price_usd"]), p
check("every tier's charged price equals its advertised price, exactly -- "
      "not converted, not rounded through another currency",
      all(p["price"] == float(p["price_usd"]) for p in B.PLANS))
check("...and each says which currency it is in, so no caller has to assume",
      all(p["currency"] == "USD" for p in B.PLANS))

check("the rand figure still exists, because a card gateway settles in rands "
      "and cannot take anything else",
      all(p["price_zar"] > 0 for p in B.PLANS))
check("...but it is NOT what anyone is invoiced: the two differ by the "
      "conversion, which is the whole bug",
      all(p["price"] != p["price_zar"] for p in B.PLANS))

check("money() prints the currency it is handed, rather than a house default",
      B.money(25, "USD") == "$25.00" and B.money(460, "ZAR") == "R460.00")
check("...and an unknown currency is named rather than printed bare, since a "
      "number with no symbol is the thing that started this",
      "XAF" in B.money(10, "XAF"))

print("\nThe order records what it was actually raised in")

store = B.BillingStore(os.path.join(tempfile.mkdtemp(), "b.db"))
oid = store.create_order(1, B.PLANS[0]["name"], 2500)
check("an order created without naming a currency records the one we bill "
      "in -- it used to default to ZAR while every caller left it unset, so "
      "every order recorded a currency it was not raised in",
      store.order(oid)["currency"] == "USD")

oid2 = store.create_order(2, B.PLANS[0]["name"], 46000, currency="ZAR")
check("a card charge records ZAR, because that is what the card is charged",
      store.order(oid2)["currency"] == "ZAR")

print("\nWhat Zoho is told")

sent = {}
_real = R._z.create_invoice
try:
    def spy(cfg, contact_id, *, description, amount_cents, due_date="",
            reference="", currency=""):
        sent.update({"cents": amount_cents, "currency": currency})
        return {"id": "INV1", "number": "INV-0001"}

    R._z.create_invoice = spy
    prov = R.provider_from_cfg({"refresh_token": "rt", "api_base": "https://x",
                                "client_id": "c", "client_secret": "s"})
    prov.create_invoice("C1", description="Renewal", amount=25.00,
                        due_days=7, reference="EM-1", currency="USD")
    check("the invoice carries its currency to Zoho -- without it the "
          "invoice takes the organisation's base currency, so a price "
          "decided in dollars goes out as the same NUMBER in rands",
          sent["currency"] == "USD")
    check("...and the amount is the advertised one, in cents, converted "
          "exactly once", sent["cents"] == 2500)
finally:
    R._z.create_invoice = _real

print("\nNothing prints a figure with a symbol somebody assumed")

inv = web_auth._render_invoice(
    {"email": "a@b.c", "role": "owner", "org_name": "Acme", "name": "A"},
    {"name": "Acme"},
    {"id": 7, "plan": B.PLANS[0]["name"], "months": 1,
     "amount_cents": 2500, "org_id": 3, "paid": time.time(),
     "currency": "USD"},
    {"name": "EasyMikroTik", "email": "billing@x"}, "EasyMikroTik")
check("the invoice document prints dollars for an order raised in dollars",
      "$25.00" in inv and "R25.00" not in inv)
check("...and names the currency beside the total, because a bare symbol on "
      "a document somebody files is worth arguing about later",
      "USD" in inv)

inv_zar = web_auth._render_invoice(
    {"email": "a@b.c", "role": "owner", "org_name": "Acme", "name": "A"},
    {"name": "Acme"},
    {"id": 8, "plan": B.PLANS[0]["name"], "months": 1,
     "amount_cents": 46000, "org_id": 3, "paid": time.time(),
     "currency": "ZAR"},
    {"name": "EasyMikroTik", "email": "billing@x"}, "EasyMikroTik")
check("a card order raised in rands still prints rands -- the document "
      "follows the order, not the house currency",
      "R460.00" in inv_zar and "$460.00" not in inv_zar)

check("an invoice is never headed 'Tax Invoice' while unregistered for VAT",
      "Tax Invoice" not in inv)

print("\nThe upcoming-invoices panel shows what will actually be charged")

html = web_auth._upcoming_box(
    [{"name": "Alpha", "plan": "d5", "amount": 25.0, "currency": "USD",
      "period_end": time.time() + 20 * 86400,
      "invoice_on": time.time() + 13 * 86400,
      "days_until_invoice": 13.0, "already_raised": False, "org_id": 1}],
    {"ran": time.time(), "error": "", "started": 1.0})
check("the figure on the panel is the figure on the invoice",
      "$25.00" in html and "R25.00" not in html)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL CURRENCY TESTS PASSED")
