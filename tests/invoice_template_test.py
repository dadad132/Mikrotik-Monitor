"""Somebody else's invoice design, filled in by this system.

The built-in invoice is fine and looks like everyone else's. A business with
an invoice design already -- one an accountant recognises, one that matches
the quotes going out beside it -- should not have to keep two.

So a template is an HTML file with {{placeholders}}. Which makes the whole
question one of what happens to the values on the way in, because a company
name is the one field on an invoice that somebody else chose, and an
ampersand in it must not be able to break the page it is printed on.

Run:  python tests/invoice_template_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import billing as B
from mikromon import invoice_template as T
from mikromon import web_auth

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


print("Filling a template in")

TPL = ("<h1>{{company}}</h1><p>{{total}} {{currency}}</p>"
       "<div>{{logo}}</div><code>{{reference}}</code>"
       "<a href='{{pay_link}}'>pay</a><i>{{nonsense}}</i>")

out = T.render(TPL, {"company": "Smith & Sons <Pty> Ltd", "total": "$25.00",
                     "currency": "USD", "logo": "<svg id='mark'></svg>",
                     "reference": "SMITHSONS-0001",
                     "pay_link": "https://easymikrotik.com/pay?t=x"})
check("a value is escaped on the way in: a company name is the one field "
      "somebody else chose, and an ampersand in it must not break the page "
      "it is printed on",
      "Smith &amp; Sons &lt;Pty&gt; Ltd" in out
      and "<Pty>" not in out)
check("the logo is NOT escaped, because it is a drawing rather than a value "
      "-- that is the whole point of putting it there",
      "<svg id='mark'></svg>" in out)
check("the template's own markup is left alone: it is markup on purpose",
      out.startswith("<h1>"))
check("a placeholder nothing fills is left exactly as written, so a "
      "mistyped name shows up on the page instead of vanishing into a gap "
      "nobody can account for", "{{nonsense}}" in out)
check("spacing inside the braces is tolerated, because people type it",
      T.render("{{ total }}", {"total": "$25.00"}) == "$25.00")
check("a missing value renders as nothing rather than the word None",
      T.render("[{{paid_on}}]", {"paid_on": None}) == "[]")

print("\nWhat an upload is allowed to be")

d = tempfile.mkdtemp()

try:
    T.save(b"", d)
    check("an empty upload is refused", False)
except T.TemplateError as exc:
    check("an empty upload is refused with a reason", "No file" in str(exc))

try:
    T.save(b"%PDF-1.4 not html at all", d)
    check("a PDF is refused", False)
except T.TemplateError as exc:
    check("a PDF or a Word file is refused, and told what to do instead",
          "HTML" in str(exc))

try:
    T.save(b"\xff\xfe\x00\x01binary", d)
    check("a binary file is refused", False)
except T.TemplateError as exc:
    check("...as is anything that is not text at all", "not text" in str(exc))

try:
    T.save(b"<html>" + b"x" * T.MAX_BYTES, d)
    check("an oversized file is refused", False)
except T.TemplateError as exc:
    check("something far too big is refused rather than stored, and the "
          "limit is stated", "limit" in str(exc))

print("\nWarnings, which are not refusals")

notes = T.check("<h1>TAX INVOICE</h1><p>VAT No 4123456789</p>"
                "{{company}} {{total}}")
check("a template calling itself a Tax Invoice is flagged: this business is "
      "not VAT registered, so issuing one is a real problem rather than a "
      "cosmetic one",
      any("VAT" in n for n in notes))

notes = T.check("<script>alert(1)</script>{{company}}{{total}}")
check("a script tag is pointed out, because it runs in the browser of every "
      "customer who opens an invoice",
      any("script" in n.lower() for n in notes))

notes = T.check("<p>hello</p>")
check("a template with no {{total}} is flagged -- an invoice that does not "
      "say what is owed is not an invoice",
      any("total" in n for n in notes))

notes = T.check(T.example())
check("the starting point this hands out is itself clean: no VAT wording, "
      "no script, and every placeholder is one that gets filled",
      notes == [])
check("...and it is a whole HTML document somebody can open and edit, not a "
      "list of field names",
      "<!doctype html>" in T.example().lower()
      and "{{logo}}" in T.example())

print("\nEnd to end, as the invoice")

_store = B.BillingStore(os.path.join(d, "b.db"))
_oid = _store.create_order(7, B.PLANS[0]["name"],
                           int(B.PLANS[0]["price"] * 100), currency="USD")
_order = dict(_store.order(_oid))
_store.close()

fields = web_auth._invoice_fields(
    {"name": "Alpha Freight"}, _order, {"name": "Me", "email": "me@x.test"},
    pay_link="https://easymikrotik.com/pay?t=abc")
check("the figures come off the ORDER, so a template shows what was charged "
      "rather than today's price list",
      fields["total"] == "$25.00" and fields["currency"] == "USD")
check("...the company it is for", fields["company"] == "Alpha Freight")
check("...the reference a bank statement will show",
      fields["reference"].startswith("ALPHAFREIGH"))
check("...and the pay link, so a template can put a button on the document",
      fields["pay_link"].endswith("t=abc"))
check("the logo is the real drawing at document size, not a picture pasted "
      "in two years ago", "<svg" in fields["logo"] and "MikroTik" in fields["logo"])

_saved = T.save(TPL.encode("utf-8"), d)
check("saving leaves a template that every invoice then renders from",
      T.load(d).startswith("<h1>{{company}}")
      and T.uploaded(d).startswith("<h1>{{company}}"))
check("...and removing it goes back to the built-in design rather than to "
      "nothing at all: there is always an invoice",
      T.remove(d) and T.uploaded(d) == ""
      and "INVOICE" in T.load(d))
check("removing when there is none is not an error", T.remove(d) is False)

print("\nThe design this system ships")

# The design arrived as a PDF describing a business other than this one.
_built = T.load(d)
check("it carries NO VAT or tax line: this business is not VAT registered, "
      "and the original had 'Tax / VAT (15%)' on it",
      "VAT (15" not in _built and "Tax /" not in _built)
check("...and does not call itself a Tax Invoice",
      "tax invoice" not in _built.lower())
check("...nor carries a discount row that would always read -$0.00, since "
      "there is no discount anywhere in this system",
      "Discount" not in _built)
check("no bank account number is baked into the design -- the one in the "
      "original came from a sample, and an account number that is not this "
      "business's is the worst thing that can be printed on an invoice",
      "6284" not in _built and "250655" not in _built)
check("it says plainly that no VAT has been charged",
      "No VAT" in " ".join(_built.split()))
check("the terms do not ask for proof of payment: a card payment activates "
      "the packet by itself, and asking for proof invites back the manual "
      "step the card rail exists to remove",
      "proof of payment" not in _built.lower())
check("what somebody downloads to edit IS the design being sent, not a "
      "simplified stand-in", T.example() == T.load(d))

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL INVOICE TEMPLATE TESTS PASSED")
