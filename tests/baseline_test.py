"""The learned baseline remembers DAYS, not minutes.

Replays a site polled once a minute: 20 devices on a normal weekday at
10:00. The old baseline learned per sample, so one hour of polls washed out
every earlier day -- a slow climb from 20 to 60 devices inside an hour never
alerted, and "normal" ended the hour at 47. These checks hold the new one to
what people mean by normal: what this hour usually looks like.

Run:  ./.venv/Scripts/python.exe tests/baseline_test.py
"""
from __future__ import annotations

import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mikromon.baseline import Baseline, is_high, is_low, learn, sigma_str  # noqa: E402

FAILS = []


def check(name, ok):
    print(f"  [{'ok  ' if ok else 'FAIL'}] {name}")
    if not ok:
        FAILS.append(name)


random.seed(7)
# Monday 5 Oct 2026, 10:00 local time.
MON_10 = time.mktime((2026, 10, 5, 10, 0, 0, 0, 0, -1))
DAY = 86400


def fresh():
    return Baseline({}, alpha=0.05, warmup=168, scheme="hourweek",
                    visit_alpha=0.15, min_visits=3)


def wd(i):
    """Seconds from MON_10 to the i-th weekday after it (0 = that Monday).
    Weekends are their own buckets, so the weekday scenarios skip them."""
    return (i // 5 * 7 + i % 5) * DAY


def normal_hour(bl, day, level=20):
    """The 10:00-10:59 of the `day`-th weekday, polled every minute."""
    for m in range(60):
        bl.update(level + random.choice([-1, 0, 0, 1]), MON_10 + wd(day) + m * 60)


print("warming up")
bl = fresh()
normal_hour(bl, 0)
check("after one day a bucket is NOT trusted to alert yet",
      not bl.score(60, MON_10 + wd(1))["warm"])
normal_hour(bl, 1)
normal_hour(bl, 2)
s = bl.score(20, MON_10 + wd(3))
check("after three separate days it is", s["warm"] and s["visits"] == 3)

print("\nthe slow climb that used to slip past")
bl = fresh()
for d in range(5):
    normal_hour(bl, d)
mem = {}
flagged = 0
for m in range(60):
    t = MON_10 + wd(5) + m * 60
    v = 20 + 40 * m / 59
    s = bl.score(v, t)
    hi = is_high(s, v, floor=5, min_ratio=1.5, z=3.0)
    flagged += hi
    learn(bl, v, t, hi, mem, "count", 72 * 3600)
check("20 -> 60 devices over an hour is flagged for most of that hour",
      flagged >= 30)
check("...and 'normal' at 10:00 stays about 20 instead of following the "
      "climb up", abs(bl.score(20, MON_10 + wd(6))["mean"] - 20) < 3)

print("\none day's busy hour does not rewrite normal")
bl = fresh()
for d in range(6):
    normal_hour(bl, d, 20)
normal_hour(bl, 6, 28)          # a busier Monday, not flagged
mean = bl.score(20, MON_10 + wd(7))["mean"]
check("a single busier day moves normal only a little (one day of many)",
      20.5 < mean < 23)

print("\na lasting new level becomes normal")
bl = fresh()
for d in range(5):
    normal_hour(bl, d, 20)
mem = {}
alerts = []
for d in range(5, 12):          # the office grew: 40 every day from now on
    for m in range(60):
        t = MON_10 + wd(d) + m * 60
        s = bl.score(40, t)
        hi = is_high(s, 40, floor=5, min_ratio=1.5, z=3.0)
        learn(bl, 40, t, hi, mem, "count", 72 * 3600)
    alerts.append(is_high(bl.score(40, MON_10 + wd(d) + 3599), 40,
                          floor=5, min_ratio=1.5, z=3.0))
check("it alerts on the first days of the new level", alerts[0] and alerts[1])
check("...and stops once that level has lasted three days and been learned",
      not alerts[-1])

print("\ntoo FEW")
bl = fresh()
for d in range(5):
    normal_hour(bl, d, 40)
s = bl.score(3, MON_10 + wd(5))
check("forty devices at 10:00 dropping to three is flagged as LOW",
      is_low(s, 3, min_typical=10, max_ratio=0.4, z=3.0))
check("...and described as below normal", sigma_str(s["z"]).endswith("below"))
check("a small dip is not", not is_low(bl.score(35, MON_10 + wd(5)), 35,
                                       min_typical=10, max_ratio=0.4, z=3.0))
small = fresh()
for d in range(5):
    normal_hour(small, d, 4)
check("a site that only ever has a handful is never 'too few'",
      not is_low(small.score(0, MON_10 + wd(5)), 0, min_typical=10,
                 max_ratio=0.4, z=3.0))

print("\nweekends are their own normal")
bl = fresh()
for d in range(5):
    normal_hour(bl, d, 40)
sat = MON_10 + 5 * DAY
check("Saturday 10:00 is a different bucket that has not learned yet, so it "
      "cannot flag a quiet Saturday as 'too few'",
      not bl.score(3, sat)["warm"])

print("\nwhat was learned before keeps working")
old = {"wk-10": {"mean": 20.0, "var": 1.0, "n": 500}}
bl = Baseline(old, alpha=0.05, warmup=168, scheme="hourweek",
              visit_alpha=0.15, min_visits=3)
check("a bucket that was warm under the old sample count stays warm",
      bl.score(20, MON_10)["warm"])
g = Baseline({}, alpha=0.3, warmup=3, scheme="global")
for v in (10, 10, 10):
    g.update(v, MON_10)
check("the 'global' scheme (the demo) still learns per sample",
      g.score(10, MON_10)["warm"])

print()
if FAILS:
    print(f"FAILED: {len(FAILS)}: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL BASELINE TESTS PASSED")
