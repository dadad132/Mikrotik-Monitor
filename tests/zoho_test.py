"""Zoho Invoice: the OAuth dance, and what the errors are allowed to say.

The API calls are the easy part. What costs time is the credential setup,
because Zoho's failure modes are indistinguishable by eye -- a mistyped
secret and the wrong data centre both come back "invalid_client" -- and the
grant code is single-use and expires in minutes, so every wrong guess costs
another round trip to the console.

So most of what is tested here is not "does it work" but "when it doesn't,
does it say which of the four possible mistakes was made".

Run:  python tests/zoho_test.py
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mikromon.zoho as z

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


class Fake:
    """Stands in for _request. Records calls, answers from a script."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def __call__(self, url, *, method="GET", headers=None, form=None,
                 body=None, timeout=25.0):
        self.calls.append({"url": url, "method": method,
                           "headers": dict(headers or {}),
                           "form": dict(form or {}), "body": body})
        if not self.replies:
            raise AssertionError(f"unexpected extra call to {url}")
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def with_fake(replies):
    f = Fake(replies)
    z._request = f
    return f


_real_request = z._request
CFG = {"client_id": "1000.CID", "client_secret": "sec",
       "refresh_token": "1000.refresh", "accounts_host": "accounts.zoho.eu",
       "api_base": "https://www.zohoapis.eu/invoice/v3",
       "organization_id": "7770001"}


print("\nTrading the grant code, without anyone knowing the data centre")

f = with_fake([z.ZohoError("invalid_client"),
               {"refresh_token": "1000.rt", "access_token": "1000.at"}])
got = z.exchange_code("1000.CID", "sec", "1000.aaa.bbb")
check("the .com data centre is tried first, then .eu -- nobody should have "
      "to know which one their account landed on",
      "accounts.zoho.com" in f.calls[0]["url"]
      and "accounts.zoho.eu" in f.calls[1]["url"])
check("what comes back is everything needed later, pinned to the data centre "
      "that actually answered",
      got["refresh_token"] == "1000.rt"
      and got["accounts_host"] == "accounts.zoho.eu"
      and got["api_base"] == "https://www.zohoapis.eu/invoice/v3")
check("the access token is NOT saved -- it is dead in an hour and keeping it "
      "only invites something to use a stale one",
      "access_token" not in got)

f = with_fake([z.ZohoError("invalid_code")])
try:
    z.exchange_code("1000.CID", "sec", "1000.used.already")
    check("a spent code raises", False)
except z.ZohoError as exc:
    check("a spent or expired code stops at the FIRST data centre -- it fails "
          "identically everywhere, and trying the rest burns the seconds the "
          "code has left", len(f.calls) == 1)
    check("...and says so in words that match what happened, rather than "
          "'invalid_code'", "expired" in str(exc) and "single-use" in str(exc))
    check("...and says the other values are remembered, because the next "
          "attempt should be one paste and not three",
          "remembered" in str(exc))

f = with_fake([z.ZohoError("invalid_client")] * len(z.DATA_CENTRES))
try:
    z.exchange_code("1000.CID", "wrong", "1000.aaa.bbb")
    check("a bad secret raises", False)
except z.ZohoError as exc:
    check("a rejected client is only blamed on the credentials AFTER every "
          "data centre has been tried -- the same error means both, and "
          "guessing sends you to re-copy a secret that was fine",
          len(f.calls) == len(z.DATA_CENTRES))
    check("...and says exactly that", "not the region" in str(exc))

try:
    z.exchange_code("", "sec", "code")
    check("missing values raise before any call", False)
except z.ZohoError as exc:
    check("missing values are caught before spending the code",
          "needed" in str(exc))

print("\nScopes: the mistake everybody makes once")

check("the scope string is comma separated with no spaces -- a single space "
      "and Zoho rejects the whole thing as an invalid scope",
      "," in z.SCOPES and " " not in z.SCOPES)
check("...and asks for what the code actually uses",
      all(p in z.SCOPES for p in ("ZohoInvoice.contacts.CREATE",
                                  "ZohoInvoice.invoices.CREATE",
                                  "ZohoInvoice.settings.READ")))

print("\nAccess tokens are minted, cached, and never stored")

z.forget_tokens()
f = with_fake([{"access_token": "at-1", "expires_in": 3600}])
t1 = z.access_token(CFG)
t2 = z.access_token(CFG)
check("the refresh token is exchanged for an access token", t1 == "at-1")
check("a second call inside the hour reuses it rather than minting another "
      "-- Zoho counts tokens, and spending one per API call wastes them",
      t2 == "at-1" and len(f.calls) == 1)
check("the refresh grant goes to the data centre recorded at connect time",
      "accounts.zoho.eu" in f.calls[0]["url"])

z.forget_tokens()
f = with_fake([{"access_token": "at-2", "expires_in": 30}])
z.access_token(CFG)
f2 = with_fake([{"access_token": "at-3", "expires_in": 3600}])
check("a token about to expire is replaced before it is used, not after it "
      "fails mid-call", z.access_token(CFG) == "at-3")

z.forget_tokens()
f = with_fake([{"error": "invalid_grant"}])
try:
    z.access_token(CFG)
    check("a revoked refresh token raises", False)
except z.ZohoError as exc:
    check("a refresh token that no longer works says to reconnect, rather "
          "than failing somewhere deep in a billing run",
          "invalid_grant" in str(exc) or "reconnect" in str(exc))

try:
    z.access_token({})
    check("no credentials raises", False)
except z.ZohoError as exc:
    check("an unconfigured server says so plainly",
          "not connected" in str(exc).lower())

print("\nEvery API call carries the organisation, or reads the wrong books")

z.forget_tokens()
f = with_fake([{"access_token": "at", "expires_in": 3600},
               {"organizations": [{"organization_id": "7770001",
                                   "name": "EasyMikrotik"}]}])
check("ping names whose books the credential opens", z.ping(CFG) == "EasyMikrotik")
hdrs = f.calls[1]["headers"]
check("the org id goes on the request -- an account with two organisations "
      "would otherwise invoice out of whichever Zoho felt like",
      hdrs.get("X-com-zoho-invoice-organizationid") == "7770001")
check("and the token is sent the way Zoho wants it, which is not Bearer",
      hdrs.get("Authorization") == "Zoho-oauthtoken at")

z.forget_tokens()
f = with_fake([{"access_token": "at", "expires_in": 3600},
               {"organizations": []}])
try:
    z.ping(CFG)
    check("no organisations raises", False)
except z.ZohoError as exc:
    check("a token the API accepts but that can see NOTHING points at the "
          "missing scope, which is the actual cause",
          "settings.READ" in str(exc))

z.forget_tokens()
f = with_fake([{"access_token": "at", "expires_in": 3600},
               {"code": 57, "message": "You are not authorized"}])
try:
    z._api(CFG, "/invoices", retry=False)
    check("a non-zero code raises", False)
except z.ZohoError as exc:
    check("Zoho reports failure with a non-zero code inside a 200 OK, and "
          "that is treated as the failure it is",
          "not authorized" in str(exc))

print("\nInvoices")

z.forget_tokens()
f = with_fake([{"access_token": "at", "expires_in": 3600},
               {"invoice": {"invoice_id": "INV1", "invoice_number": "INV-0007"}}])
got = z.create_invoice(CFG, "C1", description="Monitoring — October",
                       amount_cents=34500, due_date="2026-10-07",
                       reference="org-12")
body = f.calls[1]["body"]
check("the invoice comes back with both the id and the human number",
      got == {"id": "INV1", "number": "INV-0007"})
check("cents are converted to rands exactly once -- divide twice and a "
      "customer is billed R3.45 instead of R345, and nobody notices until "
      "the month end", body["line_items"][0]["rate"] == 345.00)
check("the due date and our own reference are carried, so a payment can be "
      "traced back to the packet it renews",
      body["due_date"] == "2026-10-07" and body["reference_number"] == "org-12")

try:
    z.create_invoice(CFG, "", description="x", amount_cents=100)
    check("invoicing nobody raises", False)
except z.ZohoError:
    check("an invoice with no contact is refused here rather than creating "
          "an orphan in Zoho", True)

z.forget_tokens()
f = with_fake([{"access_token": "at", "expires_in": 3600}, {}, {}])
z.email_invoice(CFG, "INV1")
check("sending marks it sent BEFORE emailing -- Zoho keeps it a draft "
      "otherwise, and a draft is an invoice nobody was asked to pay",
      "/status/sent" in f.calls[1]["url"] and "/email" in f.calls[2]["url"])

print("\nPaid means the money arrived, not that a word says so")

for status, total, balance, paid in (
        ("paid", 345.0, 0.0, True),
        ("sent", 345.0, 345.0, False),
        ("partially_paid", 345.0, 100.0, False),
        ("overdue", 345.0, 345.0, False),
        ("draft", 0.0, 0.0, False)):
    z.forget_tokens()
    with_fake([{"access_token": "at", "expires_in": 3600},
               {"invoice": {"status": status, "total": total,
                            "balance": balance}}])
    got = z.invoice_status(CFG, "INV1")
    check(f"{status} with {balance:.0f} outstanding -> paid={paid}",
          got["paid"] is paid)

check("a partly-paid invoice is NOT paid: reactivating a service somebody "
      "half bought is a decision nobody made", True)

print("\nReading invoice ids out of a callback")

check("a plain body", z.invoice_ids_in({"invoice_id": "A"}) == ["A"])
check("a nested one", z.invoice_ids_in({"data": {"invoice": {"invoice_id": "B"}}}) == ["B"])
check("a list of them",
      z.invoice_ids_in([{"invoice_id": "C"}, {"invoice_id": "D"}]) == ["C", "D"])
check("duplicates collapse, so one callback does not cause the same lookup "
      "three times",
      z.invoice_ids_in({"a": {"invoice_id": "E"}, "b": {"invoice_id": "E"}}) == ["E"])
check("nothing recognisable is not an error -- the reconcile pass asks the "
      "same question on a timer anyway",
      z.invoice_ids_in({"hello": "world"}) == [] and z.invoice_ids_in(None) == [])

print("\nFinding a company again after it has been renamed")

z.forget_tokens()
f = with_fake([{"access_token": "at", "expires_in": 3600},
               {"contacts": [{"contact_id": "C9"}]}])
check("email is matched before name, because a company renamed here has not "
      "been renamed in Zoho -- matching on the stale name would create a "
      "second contact and bill the customer twice",
      z.find_client(CFG, "acc@co.za", "New Name") == "C9"
      and "acc%40co.za" in f.calls[1]["url"])

z.forget_tokens()
f = with_fake([{"access_token": "at", "expires_in": 3600},
               {"contacts": []}, {"contacts": [{"contact_id": "C7"}]}])
check("...falling back to the name when no email matches",
      z.find_client(CFG, "none@co.za", "Acme") == "C7")

f = with_fake([])
check("a contact id we already hold skips the search entirely",
      z.ensure_client(CFG, "Acme", known_id="C1") == "C1" and not f.calls)

print("\nThe billing runner actually routes through Zoho")

import mikromon.billing_runner as br


class FakeAuth:
    def __init__(self, zoho=None, ninja=None):
        self._z, self._n = zoho or {}, ninja or {}

    def get_zoho(self):
        return self._z

    def get_invoiceninja(self):
        return self._n


NINJA = {"url": "https://bill.example.com", "token": "tok"}

check("with only Invoice Ninja connected, nothing changes",
      br.provider_for(FakeAuth(ninja=NINJA)).name == "invoiceninja")
check("with only Zoho connected, Zoho is used",
      br.provider_for(FakeAuth(zoho=CFG)).name == "zoho")
check("with BOTH connected Zoho wins -- an OAuth connection was made "
      "deliberately and recently, where a stale Invoice Ninja URL can sit in "
      "settings for months after anybody stopped using it",
      br.provider_for(FakeAuth(zoho=CFG, ninja=NINJA)).name == "zoho")
check("with neither, there is no provider and the runner does nothing at all",
      br.provider_for(FakeAuth()) is None)
check("a half-connected Zoho -- token but no data centre -- does not count "
      "as connected, because every call would fail on a missing api_base",
      br.provider_for(FakeAuth(zoho={"refresh_token": "rt"})) is None)

check("a cfg handed to a function picks the provider, rather than the "
      "function going back to settings and possibly acting on the other one",
      br.provider_from_cfg(CFG).name == "zoho"
      and br.provider_from_cfg(NINJA).name == "invoiceninja"
      and br.provider_from_cfg({}) is None)

# The two APIs disagree about units and about how a due date is expressed.
# Absorbing that in the adapter is the whole point -- if it leaks, a customer
# is invoiced a hundredth of what they owe, and nobody notices for a month.
sent = {}
_real = (z.create_invoice, z.ensure_client, z.email_invoice)
try:
    def spy_create(cfg, contact_id, *, description, amount_cents,
                   due_date="", reference=""):
        sent.update({"cents": amount_cents, "due": due_date,
                     "ref": reference, "contact": contact_id})
        return {"id": "INV9", "number": "INV-0009"}

    z.create_invoice = spy_create
    z.ensure_client = lambda cfg, name, email="", phone="", known_id="": "C5"
    z.email_invoice = lambda cfg, iid: sent.update({"emailed": iid})

    prov = br.provider_from_cfg(CFG)
    got = prov.create_invoice("C5", description="Renewal", amount=345.00,
                              due_days=7, reference="EM-12")
    check("rands from the price list reach Zoho as cents, converted once",
          sent["cents"] == 34500)
    check("...and a due DATE is worked out from the number of days, because "
          "Zoho will not take days", len(sent["due"]) == 10 and "-" in sent["due"])
    check("the invoice id and number come back in the shape the runner "
          "expects, whichever provider produced them",
          got == {"id": "INV9", "number": "INV-0009"})

    prov.email_invoice("INV9")
    check("emailing goes through too", sent.get("emailed") == "INV9")

    def boom(cfg, name, email="", phone="", known_id=""):
        raise z.ZohoError("Zoho says no")

    z.ensure_client = boom
    try:
        prov.ensure_client(1, "Acme", email="a@b.c")
        check("a provider error is translated", False)
    except br.ProviderError as exc:
        check("a Zoho failure arrives as the runner's own error type, so one "
              "company failing to invoice does not abort the whole pass",
              "Zoho says no" in str(exc))
finally:
    z.create_invoice, z.ensure_client, z.email_invoice = _real

z._request = _real_request

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL ZOHO TESTS PASSED")
