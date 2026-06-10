"""Learned baseline for 'is this abnormal vs normal?' detection.

A `Baseline` keeps lightweight running statistics (an exponentially-weighted
mean and variance) per *time bucket*, so "normal" can differ by hour of day or
day of week. It needs no history retention — O(1) memory per bucket — and the
state persists across restarts (it lives in the StateStore).

Design choices that keep alerts trustworthy:
  * **Warm-up:** a bucket won't trigger alerts until it has seen `warmup`
    samples, so you aren't paged while it's still learning.
  * **Freeze-on-anomaly:** when a value is judged abnormal the caller skips
    `update()`, so a spike doesn't poison "normal" and the condition stays
    flagged until the value genuinely returns to baseline.
  * **Guards:** an absolute floor and a minimum ratio stop tiny, harmless
    wiggles on a quiet metric from ever alerting.
"""
from __future__ import annotations

import math
import time


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
    """EWMA mean/variance per time bucket, stored in a caller-owned dict."""

    def __init__(self, store: dict, *, alpha: float = 0.1, warmup: int = 24,
                 scheme: str = "hour"):
        self.store = store          # {bucket: {"mean", "var", "n"}}
        self.alpha = float(alpha)
        self.warmup = int(warmup)
        self.scheme = scheme

    def _bucket(self, now: float) -> dict:
        key = bucket_key(self.scheme, now)
        return self.store.setdefault(key, {"mean": 0.0, "var": 0.0, "n": 0})

    def score(self, value: float, now: float | None = None) -> dict:
        """Grade `value` against what's normal for this bucket (no learning)."""
        now = time.time() if now is None else now
        st = self._bucket(now)
        n, mean, var = st["n"], st["mean"], st["var"]
        std = math.sqrt(var)
        if n == 0:
            z = 0.0
        elif std > 1e-9:
            z = (value - mean) / std
        else:
            z = math.inf if value > mean else 0.0
        return {"mean": mean, "std": std, "z": z, "n": n, "warm": n >= self.warmup}

    def update(self, value: float, now: float | None = None) -> None:
        """Fold `value` into the bucket's running statistics."""
        now = time.time() if now is None else now
        st = self._bucket(now)
        if st["n"] == 0:
            st.update(mean=float(value), var=0.0, n=1)
            return
        diff = value - st["mean"]
        incr = self.alpha * diff
        st["mean"] += incr
        st["var"] = (1 - self.alpha) * (st["var"] + diff * incr)
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


def sigma_str(z: float) -> str:
    """Human phrasing for a z-score (avoids printing 'inf' on a flat baseline)."""
    if not math.isfinite(z) or z >= 100:
        return "far above"
    return f"{z:.1f}σ above"


def rate_bps(prev, cur, dt: float):
    """Bits/sec from two cumulative byte counters. None on reset/wrap/no data."""
    if prev is None or cur is None or dt <= 0:
        return None
    if cur < prev:          # counter reset (reboot) — re-baseline next poll
        return None
    return (cur - prev) * 8.0 / dt
