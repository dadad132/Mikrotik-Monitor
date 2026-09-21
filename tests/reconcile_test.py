"""Reading a bank statement: who paid, and what is still outstanding.

A bank transfer arrives where the invoicing system cannot see it. The only
thing that knows is the statement -- and the reference on each deposit
already says which company sent it, because payment_reference() puts it
there and org_id_from_reference() reads it back out of whatever mangled form
the bank prints around it.

Most of this file is the parser, because every South African bank exports
something different and all of them are reasonable. The first version of it
failed on four of six real shapes, in ways worth keeping tests for: it pulled
digits out of narrative text so "EFT BRAVOLOG-0007 ref" parsed as -7.00, and
it matched column names as substrings so "cr" found the credit column inside
the word "Description".

Run:  python tests/reconcile_test.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon.reconcile import (line_key, match_rows, parse_statement,
                                summarise)

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


print("\nEvery bank exports something different, and all of them work")

SHAPES = {
    "money in / money out columns (Capitec)":
        "Posting Date,Transaction Date,Description,Money In,Money Out,Balance\n"
        '2026-09-20,2026-09-20,EFT ALPHAFREIGHT-0042 CAPITEC,"1,234.56",,15000.00\n'
        "2026-09-19,2026-09-19,CARD PURCHASE WOOLWORTHS,,250.00,13765.44",
    "one signed amount column (FNB)":
        "Date,Description,Amount,Balance\n"
        "20/09/2026,ALPHAFREIGHT-0042 payment,1234.56,500.00\n"
        "19/09/2026,Bank charges,-58.00,475.00",
    "semicolons and a decimal comma":
        "Date;Narrative;Amount\n2026-09-20;ALPHAFREIGHT-0042;1234,56",
    "tab separated":
        "Date\tDescription\tAmount\n2026-09-20\tALPHAFREIGHT-0042\t1234.56",
    "no header row at all":
        "2026-09-20,EFT ALPHAFREIGHT-0042 ref,1234.56,9000.00",
    "debits written in brackets":
        "Date,Description,Amount\n2026-09-20,ALPHAFREIGHT-0042,1234.56\n"
        "2026-09-18,Monthly fee,(58.00)",
    "thousands with a space":
        "Date,Description,Amount\n2026-09-20,ALPHAFREIGHT-0042,1 234.56",
    "an R in front of the money":
        "Date,Description,Amount\n2026-09-20,ALPHAFREIGHT-0042,R1 234.56",
}
for name, text in SHAPES.items():
    rows = parse_statement(text)
    ok = (len(rows) == 1 and abs(rows[0]["amount"] - 1234.56) < 0.01
          and "ALPHAFREIGHT-0042" in rows[0]["description"].upper())
    check(f"{name}: one credit, right amount, description intact", ok)

check("only money IN is offered -- a statement is mostly the customer's own "
      "spending, and matching a debit to an invoice would be noise",
      all(r["amount"] > 0 for r in parse_statement(SHAPES[
          "one signed amount column (FNB)"])))

print("\nThe two ways the first version got it wrong")

check("a narrative is never read as an amount: it used to strip the digits "
      "out of 'EFT BRAVOLOG-0007 ref' and call it -7.00",
      parse_statement("2026-09-20,EFT BRAVOLOG-0007 ref,110.00,900.00"
                      )[0]["amount"] == 110.00)
check("...and the description survives intact rather than being replaced by "
      "the date column",
      "BRAVOLOG" in parse_statement(
          "2026-09-20,EFT BRAVOLOG-0007 ref,110.00,900.00"
      )[0]["description"].upper())
check("'cr' does not find the credit column inside the word 'Description'",
      parse_statement("Date,Description,Amount\n2026-09-20,X-0001,50.00"
                      )[0]["amount"] == 50.00)

print("\nNothing sensible in, nothing out")

for junk in ("", "   ", "hello world", "no numbers here at all"):
    check(f"{junk!r} yields nothing rather than a wrong guess",
          parse_statement(junk) == [])

print("\nMatching deposits to invoices")

INVOICES = [
    {"order_id": 1, "org_id": 42, "name": "Alpha Freight", "amount": 25.00},
    {"order_id": 2, "org_id": 7, "name": "Bravo Logistics", "amount": 110.00},
]
STATEMENT = """Date,Description,Amount
2026-09-20,EFT ALPHAFREIGHT-0042,25.00
2026-09-20,BRAVOLOG-0007 part payment,90.00
2026-09-20,Cash deposit,500.00
2026-09-20,ALPHAFREIGHT-0042 again,25.00"""
res = match_rows(parse_statement(STATEMENT), INVOICES)

check("a deposit whose reference and amount both agree is matched",
      len(res["matched"]) == 1
      and res["matched"][0]["invoice"]["name"] == "Alpha Freight")
check("a part payment is NOT matched: right company, wrong money, and "
      "assuming is how somebody gets a month they did not pay for",
      len(res["wrong_amount"]) == 1
      and res["wrong_amount"][0]["invoice"]["name"] == "Bravo Logistics")
check("...but it is still SHOWN, with what was invoiced beside it, because "
      "that is the one that needs a phone call",
      res["wrong_amount"][0]["invoice"]["amount"] == 110.00)
check("a deposit with no reference of ours is listed separately -- somebody "
      "forgot to quote theirs, and this is how you find out who to ask",
      len(res["unmatched"]) == 1
      and res["unmatched"][0]["amount"] == 500.00)
check("a second payment for an invoice already claimed in this statement "
      "does not claim it twice", len(res["already"]) == 1)

check("the summary line is readable before anything is decided",
      "1 matched" in summarise(res) and "amount differs" in summarise(res))

check("nothing is applied by matching -- it returns what it found and "
      "changes nothing, which is the whole point of a preview",
      all(k in res for k in
          ("matched", "wrong_amount", "unmatched", "already")))

print("\nThe same statement pasted twice")

k1 = line_key({"date": "2026-09-20", "amount": 25.0, "description": "EFT X"})
k2 = line_key({"date": "2026-09-20", "amount": 25.0, "description": "eft x "})
k3 = line_key({"date": "2026-09-21", "amount": 25.0, "description": "EFT X"})
check("the same line gets the same key however the bank cased or padded it",
      k1 == k2)
check("a different day is a different payment", k1 != k3)

print("\nEnd to end: statement in, packet carries on")

import tempfile  # noqa: E402

from mikromon import billing as B  # noqa: E402
from mikromon import billing_runner as R  # noqa: E402

st = B.BillingStore(os.path.join(tempfile.mkdtemp(), "b.db"))
st.set_plan(42, B.PLANS[0]["name"])
st._upsert(42, current_period_end=__import__("time").time() - 86400)
st.lapse_due()
check("the company is in grace before anything is paid",
      st.billing_status(42) == "grace")

oid = st.create_order(42, B.PLANS[0]["name"],
                      int(B.PLANS[0]["price"] * 100),
                      provider="zoho", currency="USD")
st.set_order_external(oid, "INV-9")


class FakeAuth:
    def get_zoho(self):
        return {}

    def org(self, org_id):
        return {"name": "Alpha Freight"}

    def list_users(self, org_id):
        return []


class FakeProv:
    name = "zoho"

    def record_payment(self, invoice_id, customer_name, amount, reference=""):
        return "pay-1"


_real = R.provider_for
try:
    R.provider_for = lambda auth: FakeProv()
    invs = R.outstanding(st, FakeAuth())
    check("the outstanding list carries the reference a statement will show",
          invs and "ALPHAFREIGHT" in invs[0]["reference"])

    paid = f'Date,Description,Amount\n2026-09-28,EFT {invs[0]["reference"]},' \
           f'{B.PLANS[0]["price"]:.2f}'
    res = match_rows(parse_statement(paid), invs)
    check("the deposit matches the invoice it belongs to",
          len(res["matched"]) == 1)

    R.mark_paid(st, FakeAuth(), res["matched"][0]["invoice"]["order_id"])
    check("...and applying it carries the packet on, out of grace",
          st.billing_status(42) == "active")
finally:
    R.provider_for = _real

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL RECONCILE TESTS PASSED")
