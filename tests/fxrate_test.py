"""The rand figure has to come from somewhere a customer can check.

Prices are decided in USD. A card gateway that settles in rands needs a
conversion — and the conversion cannot be a number we picked. If the site
says $25 and the card is charged R460, the customer is entitled to expect
that R460 is what $25 costs today.

It was a constant compiled into the source:

    _ZAR_PER_USD = 18.4

On the day that was noticed the ECB reference rate was 16.26, so every rand
charge sat 13% above the dollar price advertised beside it. Nobody chose
that; it was simply never revisited — which is why "review it monthly" would
have been the same fault with more steps.

So most of what is tested here is the refusal: what happens when no
published rate can be had. Inventing one is the failure mode worth designing
against, because it is the one that produces a charge nobody can justify.

Run:  python tests/fxrate_test.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import billing as B
from mikromon import fxrate as FX

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


def reset(path=""):
    FX._cache.clear()
    FX.CACHE_PATH = path


class FakeOpen:
    """Stands in for urlopen. Answers per host, or refuses."""

    def __init__(self, replies):
        self.replies = replies
        self.urls = []

    def __call__(self, req, timeout=None):
        url = getattr(req, "full_url", str(req))
        self.urls.append(url)
        for frag, body in self.replies.items():
            if frag in url:
                if body is None:
                    raise OSError("refused")
                return _Resp(json.dumps(body).encode())
        raise OSError("no route")


class _Resp:
    def __init__(self, body):
        self._b = body

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


ECB = {"amount": 1.0, "base": "USD", "date": "2026-09-21",
       "rates": {"ZAR": 16.2593}}
BACKUP = {"result": "success", "time_last_update_unix": 1790035351,
          "rates": {"ZAR": 16.31}}

_real_open = FX.urllib.request.urlopen

print("\nThe rate comes from a source that can be named on a receipt")

reset()
FX.urllib.request.urlopen = FakeOpen({"frankfurter": ECB})
row = FX.get()
check("the ECB reference rate is preferred: published daily by a central "
      "bank, dated, and nothing to do with us",
      row["source"] == "ECB reference rate" and row["rate"] == 16.2593)
check("...carrying the date it was published for, not the date we asked",
      row["date"] == "2026-09-21")
check("...and a line a customer can check the figure against",
      "ECB reference rate of 2026-09-21" in FX.describe(row)
      and "16.2593" in FX.describe(row))

reset()
FX.urllib.request.urlopen = FakeOpen({"frankfurter": None,
                                      "er-api": BACKUP})
row = FX.get()
check("a second published source is used when the first is down, so one "
      "provider's outage does not stop a customer paying",
      row["rate"] == 16.31 and "exchangerate-api" in row["source"])

print("\nWhat it refuses to do")

reset()
FX.urllib.request.urlopen = FakeOpen({"nothing": None})
try:
    FX.get()
    check("no source raises", False)
except FX.RateUnavailable:
    check("with no published rate and nothing cached it RAISES rather than "
          "guessing -- a charge with no source behind it is worse than a "
          "charge that did not happen", True)

try:
    B.zar_amount(25.0)
    check("converting raises too", False)
except FX.RateUnavailable:
    check("...and the conversion refuses with it, rather than quietly "
          "falling back to a number somebody typed once", True)

print("\nA cached rate is used, and says which day it is from")

d = tempfile.mkdtemp()
reset(os.path.join(d, "fx.json"))
FX.urllib.request.urlopen = FakeOpen({"frankfurter": ECB})
FX.get()
check("a fetched rate is written down, so a restart does not lose it",
      os.path.exists(FX.CACHE_PATH))

FX._cache.clear()
FX.urllib.request.urlopen = FakeOpen({"nothing": None})
row = FX.get()
check("with every source down, the cached rate is used rather than failing "
      "a payment outright", row["rate"] == 16.2593)
check("...still carrying ITS OWN date, so a charge made on an old rate says "
      "which day's rate it was instead of implying it was looked up now",
      row["date"] == "2026-09-21")

print("\nAn old rate is flagged, not silently trusted")

reset()
old_day = time.strftime("%Y-%m-%d", time.localtime(time.time() - 30 * 86400))
FX.urllib.request.urlopen = FakeOpen(
    {"frankfurter": {**ECB, "date": old_day}})
row = FX.get()
check("a rate a month old is marked stale -- a long weekend is three days, "
      "so this is something wrong rather than a Sunday",
      row["stale"] and row["age_days"] > 25)

reset()
FX.urllib.request.urlopen = FakeOpen({"frankfurter": ECB})
check("yesterday's rate is not stale, because that is simply what a daily "
      "published rate looks like", not FX.get()["stale"])

print("\nThe price list no longer carries a rate anyone could charge")

check("no tier exposes a 'price_zar' that could be mistaken for a price",
      all("price_zar" not in p for p in B.PLANS))
check("...only an indicative figure, named as approximate",
      all("price_zar_approx" in p for p in B.PLANS))
check("the price itself is still USD, unconverted, exactly as advertised",
      all(p["price"] == float(p["price_usd"]) for p in B.PLANS))

reset()
FX.urllib.request.urlopen = FakeOpen({"frankfurter": ECB})
conv = B.zar_amount(B.PLANS[0]["price_usd"])
check("a real conversion uses the published rate, not the fallback constant",
      abs(conv["amount"] - B.PLANS[0]["price_usd"] * 16.2593) < 0.01)
check("...and differs from what the old constant would have charged, which "
      "is the whole point", conv["amount"] < B.PLANS[0]["price_zar_approx"])

print("\nWhat was charged, and on what basis, outlives the day")

st = B.BillingStore(os.path.join(tempfile.mkdtemp(), "b.db"))
oid = st.create_order(1, B.PLANS[0]["name"], int(conv["amount"] * 100),
                      currency="ZAR", provider="yoco",
                      fx_rate=conv["rate"], fx_basis=FX.describe(
                          {**conv, "pair": "USDZAR"}))
o = st.order(oid)
check("the order records the rate it was converted at",
      abs(float(o["fx_rate"]) - 16.2593) < 1e-6)
check("...and the sentence naming the source and date, because the question "
      "later is not what was charged but on what basis",
      "ECB reference rate of 2026-09-21" in str(o["fx_basis"]))

FX.urllib.request.urlopen = _real_open
reset()

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL FX RATE TESTS PASSED")
