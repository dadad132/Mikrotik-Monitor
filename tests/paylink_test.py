"""Paying an invoice by card, with nobody at our end and no login.

Card payment was already fully automatic once it started: the gateway
confirms, the packet extends, the invoice is settled, nothing waits on a
person. What was not automatic was getting a customer INTO it — the checkout
needed a session, so somebody who received an invoice by email had to
remember a password to pay it. The path of least resistance was therefore
the bank transfer, which is the one path that needs somebody here reading a
statement.

So the invoice carries a link that pays it. Which makes the link itself
security-relevant: it reaches money without a login, so most of this file is
about what it refuses.

Run:  python tests/paylink_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import billing as B
from mikromon import paylink as PL
from mikromon.web_auth import _pay_page

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


class FakeAuth:
    """Just the settings store the signing key lives in."""

    def __init__(self):
        self.settings = {}

    def get_setting(self, key, default=None):
        return self.settings.get(key, default)

    def set_setting(self, key, value):
        self.settings[key] = value


print("\nThe link reaches the order it is for")

auth = FakeAuth()
tok = PL.make(auth, 42)
check("a token resolves back to its own order", PL.read(auth, tok) == 42)
check("...and the signing key is created once and kept, so links already in "
      "somebody's inbox keep working",
      auth.settings.get("paylink_secret")
      and PL.read(auth, PL.make(auth, 42)) == 42)
check("the order number is not simply in the clear: a guessable pay link "
      "would let a stranger read what a company was charged",
      "42" not in tok.split(".")[-1])

print("\nWhat it refuses")

check("a forged signature is refused",
      PL.read(auth, tok.rsplit(".", 1)[0] + ".AAAAAAAAAAAAAAAAAAAAAAAA") == 0)
check("a token for a different order is refused, even signed by us -- "
      "changing the order number invalidates the signature",
      PL.read(auth, "43." + tok.split(".", 1)[1]) == 0)
check("an expired token is refused", PL.read(auth, PL.make(auth, 42, ttl=-1)) == 0)
for junk in ("", "nonsense", "1.2", "a.b.c", None, "1.1.1.1"):
    check(f"{junk!r} is refused rather than raising", PL.read(auth, junk) == 0)

other = FakeAuth()
check("a token signed with a different key is refused -- rotating the secret "
      "invalidates every link already sent, which is the point of storing it "
      "rather than deriving it", PL.read(other, tok) == 0)

check("failure never says WHICH failure: telling a stranger their guess was "
      "the right shape is telling them how to guess better",
      PL.read(auth, "43." + tok.split(".", 1)[1]) == PL.read(auth, "nonsense"))

print("\nThe page a customer lands on")

order = {"id": 7, "org_id": 1, "plan": B.PLANS[0]["name"],
         "amount_cents": int(B.PLANS[0]["price"] * 100), "currency": "USD"}
html = _pay_page(order, "", org_name="Alpha Freight", token=tok)
check("it shows the company and what is owed, and nothing else",
      "Alpha Freight" in html and "$25.00" in html)
check("...with one button, because somebody arriving here has one thing to "
      "do and a menu is an invitation to go and do something else",
      html.count("<button") == 1 and "Pay by card" in html)
check("...saying the service resumes by itself, which is the promise being "
      "made", "nobody here has to do anything" in html)
check("...and naming the other way to pay, since a card is not everybody's "
      "answer", "bank transfer" in html)
check("no login form, no navigation, no account details",
      "password" not in html.lower() and "/logout" not in html)

paid = _pay_page(order, "", paid=True)
check("an invoice already settled says so instead of charging twice -- a "
      "forwarded email must not be a second payment",
      "Already paid" in paid and "<button" not in paid)

dead = _pay_page(None, "That payment link has expired or is not "
                       "valid. Ask us for a new one.")
check("an expired link explains itself and offers a way forward",
      "expired" in dead and "Ask us for a new one" in dead)
check("...without a button that cannot do anything", "<button" not in dead)

print("\nEnd to end, against a running server")

import threading  # noqa: E402
import urllib.error  # noqa: E402
import urllib.request  # noqa: E402

from mikromon import web  # noqa: E402
from mikromon.auth import AuthStore  # noqa: E402

d = tempfile.mkdtemp()
adb, bdb = os.path.join(d, "auth.db"), os.path.join(d, "b.db")
a = AuthStore(adb)
a.signup("owner@alpha.test", "pw-for-the-test", "Alpha Freight")
a.close()
store = B.BillingStore(bdb)
oid = store.create_order(1, B.PLANS[0]["name"],
                         int(B.PLANS[0]["price"] * 100),
                         currency="USD", provider="zoho")
store.close()

PORT = 8797
threading.Thread(target=web.serve, kwargs=dict(
    metrics_db=os.path.join(d, "m.db"), state_file=os.path.join(d, "s.json"),
    auth_db=adb, billing_cfg={"db": bdb},
    host="127.0.0.1", port=PORT),
    daemon=True).start()
time.sleep(2.0)

live = AuthStore(adb)
real_tok = PL.make(live, oid)
live.close()
BASE = f"http://127.0.0.1:{PORT}"


def get(path):
    try:
        r = urllib.request.urlopen(BASE + path, timeout=8)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


st, body = get(f"/pay?t={real_tok}")
check("the pay page opens with NO session at all -- which is the whole "
      "point: a customer who must log in to pay takes the bank transfer "
      "instead", st == 200 and "Pay by card" in body)
check("...showing what is owed", "$25.00" in body)

st, body = get("/pay?t=forged.123.abc")
check("a forged link gets a page that explains, not a stack trace or a 500",
      st == 200 and "not valid" in body)

st, body = get("/pay")
check("no token at all is handled the same way", st == 200 and "link" in body)

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL PAY LINK TESTS PASSED")
