"""Learned baseline for 'is this abnormal vs normal?' detection.

A `Baseline` keeps lightweight running statistics (an exponentially-weighted
mean and variance) per *time bucket*, so "normal" can differ by hour of day or
day of week. It needs no history retention — O(1) memory per bucket — and the
state persists across restarts (it lives in the StateStore).

What "normal for Tuesday 10:00" has to mean is the last several Tuesdays (or
weekdays) at 10:00 -- not the last twenty minutes. A bucket is visited once a
day, but sampled every poll: at one poll a minute that is sixty samples per
visit, and a per-sample learning rate let one visit wash out every earlier
day. A slow climb from 20 devices to 60 inside an hour then never alerted at
all, because "normal" climbed with it. So the learning rate here is set PER
VISIT and spread across that visit's samples: each day's 10:00 counts about
as much as any other day's, whatever the poll interval.

Design choices that keep alerts trustworthy:
  * **Warm-up by days:** a bucket won't alert until it has seen `min_visits`
    separate visits (days, for the hour schemes), so one unusual first
    morning cannot become "normal".
  * **Freeze-on-anomaly:** while a value is judged abnormal the caller skips
    update(), so a spike doesn't poison "normal" and the condition stays
    flagged until the value genuinely returns to baseline...
  * **...unless it lasts:** a level that stays "abnormal" for days is the new
    normal (an office that grew, a bigger line). learn() starts folding it in
    after `accept_after`, so the alert clears by itself instead of firing for
    ever.
  * **Guards:** an absolute floor and a minimum ratio stop tiny, harmless
    wiggles on a quiet metric from ever alerting -- in either direction.
"""
from __future__ import annotations

import math
import time

_BUCKET_SECONDS = 3600


def bucket_key(scheme: str, now: float) -> str:
    if scheme == "global":
        return "g"
    lt = time.localtime(now)
    if scheme == "hourweek":
        # Mon-Fri share a bucket per hour; Sat/Sun separate (captures weekends).
        day = "wk" if lt.tm_wday < 5 else f"we{lt.tm_wday}"
        return f"{day}-{lt.tm_hour}"
    return str(lt.tm_hour)  # default: hour-of-day


class Baseline:
    """EWMA mean/variance per time bucket, stored in a caller-owned dict.

    `alpha` is the per-sample rate, used as-is by the "global" scheme (one
    bucket, every sample a step). For the hour schemes `visit_alpha`, when
    given, is the rate per VISIT of a bucket and wins; `min_visits` is how
    many separate visits make a bucket warm. Without them this behaves as it
    always did, so a caller that passes neither is unchanged.
    """

    def __init__(self, store: dict, *, alpha: float = 0.1, warmup: int = 24,
                 scheme: str = "hour", visit_alpha: float | None = None,
                 min_visits: int | None = None):
        self.store = store          # {bucket: {"mean", "var", "n", ...}}
        self.alpha = float(alpha)
        self.warmup = int(warmup)
        self.scheme = scheme
        self.visit_alpha = (float(visit_alpha) if visit_alpha is not None
                            and scheme != "global" else None)
        self.min_visits = (int(min_visits) if min_visits is not None
                           and scheme != "global" else None)

    def _bucket(self, now: float) -> dict:
        key = bucket_key(self.scheme, now)
        st = self.store.setdefault(key, {"mean": 0.0, "var": 0.0, "n": 0})
        if "visits" not in st:
            # A bucket learned before visits were counted: if it was warm by
            # the old sample count, call it warm now too rather than making
            # every existing router learn from scratch.
            st["visits"] = (self.min_visits or 1) if st["n"] >= self.warmup \
                else (1 if st["n"] else 0)
        return st

    def _warm(self, st: dict) -> bool:
        if self.min_visits is not None:
            return st.get("visits", 0) >= self.min_visits and st["n"] >= 3
        return st["n"] >= self.warmup

    def score(self, value: float, now: float | None = None) -> dict:
        """Grade `value` against what's normal for this bucket (no learning)."""
        now = time.time() if now is None else now
        st = self._bucket(now)
        n, mean, var = st["n"], st["mean"], st["var"]
        std = math.sqrt(max(var, 0.0))
        if n == 0:
            z = 0.0
        elif std > 1e-9:
            z = (value - mean) / std
        else:
            z = (math.inf if value > mean else -math.inf if value < mean
                 else 0.0)
        return {"mean": mean, "std": std, "z": z, "n": n,
                "visits": st.get("visits", 0), "warm": self._warm(st)}

    def _sample_alpha(self, now: float) -> float:
        """This sample's learning rate. Per-visit rate spread over however
        many samples a visit holds, measured from the actual spacing of
        samples so a change of poll interval needs no retuning."""
        if self.visit_alpha is None:
            return self.alpha
        last = self.store.get("_last")
        dt = self.store.get("_dt")
        if last is not None and 0 < now - last < _BUCKET_SECONDS:
            gap = now - last
            dt = gap if dt is None else 0.8 * dt + 0.2 * gap
            self.store["_dt"] = dt
        self.store["_last"] = now
        per_visit = max(1.0, _BUCKET_SECONDS / (dt or 60.0))
        return 1.0 - (1.0 - self.visit_alpha) ** (1.0 / per_visit)

    def update(self, value: float, now: float | None = None) -> None:
        """Fold `value` into the bucket's running statistics."""
        now = time.time() if now is None else now
        st = self._bucket(now)
        a = self._sample_alpha(now)
        visit = int(now // _BUCKET_SECONDS)
        if st.get("last_visit") != visit:
            st["last_visit"] = visit
            if st["n"]:
                st["visits"] = st.get("visits", 0) + 1
        if st["n"] == 0:
            st.update(mean=float(value), var=0.0, n=1,
                      visits=max(1, st.get("visits", 0)))
            return
        # Until there are enough samples for the rate to matter, an equal
        # average of everything seen -- otherwise the first sample would
        # dominate a slow rate for weeks.
        a = max(a, 1.0 / (st["n"] + 1))
        diff = value - st["mean"]
        incr = a * diff
        st["mean"] += incr
        st["var"] = (1 - a) * (st["var"] + diff * incr)
        st["n"] += 1


def is_high(score: dict, value: float, *, floor: float, min_ratio: float,
            z: float) -> bool:
    """True if `value` is abnormally HIGH given a baseline `score`."""
    if not score["warm"]:
        return False
    if value < floor:
        return False
    if value < score["mean"] * min_ratio:
        return False
    return score["z"] >= z


def is_low(score: dict, value: float, *, min_typical: float,
           max_ratio: float, z: float) -> bool:
    """True if `value` is abnormally LOW: well under a normal that is itself
    big enough to mean something (forty devices dropping to three matters;
    two dropping to zero is a quiet evening)."""
    if not score["warm"]:
        return False
    if score["mean"] < min_typical:
        return False
    if value > score["mean"] * max_ratio:
        return False
    return score["z"] <= -z


def learn(bl: Baseline, value: float, now: float, abnormal: bool,
          memory: dict, key: str, accept_after: float) -> bool:
    """Update `bl` with `value` unless it is abnormal -- and once a value has
    been abnormal for `accept_after` seconds without a break, take it as the
    new normal and learn it anyway. Returns whether it was learned.

    `memory` keeps when each `key` went abnormal, so this survives restarts.
    """
    since = memory.setdefault("abnormal_since", {})
    if not abnormal:
        since.pop(key, None)
        bl.update(value, now)
        return True
    start = since.setdefault(key, now)
    if accept_after and now - start >= accept_after:
        bl.update(value, now)
        return True
    return False


def make_baseline(store: dict, dev) -> Baseline:
    """A Baseline tuned from a device's thresholds -- one place, so every
    check learns the same way."""
    return Baseline(store, alpha=dev.th("baseline_alpha"),
                    warmup=dev.th("baseline_warmup"),
                    scheme=dev.th("baseline_buckets"),
                    visit_alpha=dev.th("baseline_day_alpha"),
                    min_visits=dev.th("baseline_min_days"))


def sigma_str(z: float) -> str:
    """Human phrasing for a z-score (avoids printing 'inf' on a flat baseline)."""
    if not math.isfinite(z) or abs(z) >= 100:
        return "far above" if z > 0 else "far below"
    return f"{abs(z):.1f}σ {'above' if z >= 0 else 'below'}"


def rate_bps(prev, cur, dt: float):
    """Bits/sec from two cumulative byte counters. None on reset/wrap/no data."""
    if prev is None or cur is None or dt <= 0:
        return None
    if cur < prev:          # counter reset (reboot) — re-baseline next poll
        return None
    return (cur - prev) * 8.0 / dt
