"""Staying inside what other people's APIs will give us.

This exists because of arithmetic, not theory. Reconciling payments costs one
API call per open invoice, the pass ran every fifteen minutes, and Zoho's
free plan allows 1000 requests a day:

    15 open invoices x 96 passes = 1440 calls/day

So from some point each afternoon every call would have failed with HTTP 429,
every day, looking exactly like Zoho being down. Nothing counted, so nothing
could have said so.

Two limits, because APIs impose two kinds, and the difference decides what a
caller should do: a per-minute rate is a scheduling problem and waiting fixes
it, while a spent daily budget is a design problem and waiting only hides it.

Run:  python tests/ratelimit_test.py
"""
from __future__ import annotations

import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon import ratelimit as RL

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


print("\nThe arithmetic that made this necessary")

check("fifteen open invoices checked every fifteen minutes is over Zoho's "
      "free daily cap, which is the whole reason this module exists",
      15 * (24 * 60 // 15) > 1000)

print("\nA burst is allowed; a flood is paced")

lim = RL.Limiter("test", per_minute=600, burst=5)
t0 = time.monotonic()
for _ in range(5):
    lim.acquire()
check("the bucket's worth goes straight through, so an idle service is not "
      "punished for suddenly having work", time.monotonic() - t0 < 0.2)

t0 = time.monotonic()
lim.acquire()
check("the one past it waits for a refill rather than being refused -- a "
      "burst is a scheduling problem and waiting is the right answer",
      0.05 < time.monotonic() - t0 < 1.0)

print("\nA spent daily budget raises, because it cannot be waited out")

lim = RL.Limiter("daily", per_minute=6000, per_day=3, burst=10)
for _ in range(3):
    lim.acquire()
try:
    lim.acquire()
    check("the fourth call raises", False)
except RL.RateLimited as exc:
    check("the call past the daily quota raises instead of sleeping -- "
          "blocking here would hang the billing thread until midnight",
          True)
    check("...naming the limit and when it comes back, since the reader is "
          "an admin wondering why invoices stopped",
          "daily limit of 3" in str(exc) and "midnight" in str(exc))

snap = lim.snapshot()
check("the panel can see what has been spent",
      snap["used_today"] == 3 and snap["left_today"] == 0)

print("\nA wait that would be absurd is refused rather than slept through")

lim = RL.Limiter("slow", per_minute=1, burst=1)
lim.acquire()
try:
    lim.acquire(max_wait=0.5)
    check("a 60-second wait is refused", False)
except RL.RateLimited as exc:
    check("a caller facing a minute's wait fails fast and lets its own loop "
          "retry, instead of holding a thread hostage", "wait" in str(exc))

print("\nThe provider's opinion beats our arithmetic")

lim = RL.Limiter("429", per_minute=6000, burst=50)
lim.acquire()
before = lim.snapshot()["tokens"]
lim.note_429(retry_after=2.0)
check("a 429 empties the bucket, so the next call does not go straight back "
      "out -- that is how a brief throttle becomes a ban",
      lim.snapshot()["tokens"] < before)

print("\nReading Retry-After, in both shapes servers send it")


class H(dict):
    def get(self, k, d=None):
        return dict.get(self, k, d)


check("a plain number of seconds", RL.retry_after_seconds(H({"Retry-After": "30"})) == 30.0)
check("an HTTP date is converted to seconds from now",
      RL.retry_after_seconds(H({"Retry-After":
                                time.strftime("%a, %d %b %Y %H:%M:%S GMT",
                                              time.gmtime(time.time() + 60))})) > 30)
check("absent means zero, not a crash", RL.retry_after_seconds(H()) == 0.0)
check("nonsense means zero too",
      RL.retry_after_seconds(H({"Retry-After": "soon"})) == 0.0)
check("no headers at all is survivable", RL.retry_after_seconds(None) == 0.0)

print("\nOne budget per provider, not one per caller")

a = RL.limiter("shared-provider", 60, 100)
b = RL.limiter("shared-provider", 60, 100)
check("asking twice returns the SAME limiter -- the dashboard thread and the "
      "billing thread both call Zoho, and two limiters would each happily "
      "spend the whole budget", a is b)

a.acquire()
check("...so what one spends, the other sees", b.snapshot()["used_today"] == 1)

print("\nSafe to share between threads")

lim = RL.Limiter("threaded", per_minute=60000, per_day=500, burst=500)
errors = []


def hammer():
    try:
        for _ in range(50):
            lim.acquire()
    except Exception as exc:  # noqa: BLE001
        errors.append(exc)


ts = [threading.Thread(target=hammer) for _ in range(10)]
for t in ts:
    t.start()
for t in ts:
    t.join()
check("ten threads taking fifty each account for exactly five hundred, with "
      "nothing lost or double-counted",
      not errors and lim.snapshot()["used_today"] == 500)

print("\nEvery provider that calls out is actually limited")

from mikromon import nextdns, yoco  # noqa: E402

for mod, name in ((yoco, "yoco"), (nextdns, "nextdns")):
    src = open(mod.__file__, encoding="utf-8").read()
    check(f"{name} acquires budget before calling out",
          ".acquire()" in src)
    check(f"{name} honours a 429 rather than retrying straight into it",
          "note_429" in src)

check("the exchange-rate source is limited too -- it is fetched on every "
      "card payment, and hammering a free published feed is how access to "
      "it goes away",
      "FX rates" in open(
          os.path.join(os.path.dirname(os.path.dirname(
              os.path.abspath(__file__))), "mikromon", "fxrate.py"),
          encoding="utf-8").read())

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL RATE LIMIT TESTS PASSED")
