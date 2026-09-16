"""Stay inside what other people's APIs will give us.

Every outbound API this system talks to publishes a limit, and until now
nothing counted. That is fine right up until it is not: Zoho's free plan
allows 1000 requests a day, and reconciling payments every fifteen minutes
costs one call per open invoice -- which is 1440 calls a day at fifteen open
invoices, comfortably over the cap. The first sign would be invoices and
payments failing with HTTP 429 from mid-afternoon onwards, every day, looking
exactly like an outage.

So there are two limits here, because APIs impose two kinds:

  * a **rate** -- requests per minute, enforced as a token bucket, which
    smooths a burst rather than rejecting it. Callers wait a moment.
  * a **daily quota**, which cannot be waited out. Blocking on that would
    hang a thread for hours, so it raises, and the caller decides.

The distinction matters: a burst is a scheduling problem and waiting fixes
it. A budget spent is a design problem and waiting only hides it.

Stdlib only, like the rest of this project.
"""
from __future__ import annotations

import logging
import threading
import time

log = logging.getLogger(__name__)


class RateLimited(Exception):
    """The daily budget is gone, or the wait would be unreasonable.

    The message is written to be shown to an admin, who wants to know what
    ran out and when it comes back, not what a token bucket is.
    """


class Limiter:
    """A token bucket plus a daily quota, safe to share across threads.

    `per_minute` refills continuously, so a caller that has been idle may
    burst up to the bucket size and then settles to the steady rate.
    `per_day` is a hard count that resets at midnight in local time -- which
    is what the providers publish it as, and being clever about their
    timezone would only shift the problem.
    """

    def __init__(self, name: str, per_minute: float = 60.0,
                 per_day: int = 0, burst: float = 0.0):
        self.name = name
        self.per_minute = float(per_minute)
        self.per_day = int(per_day)
        self.burst = float(burst or max(1.0, per_minute / 6.0))
        self._tokens = self.burst
        self._updated = time.monotonic()
        self._day = time.strftime("%Y-%m-%d")
        self._used_today = 0
        self._lock = threading.Lock()

    # -- state a panel can read ------------------------------------------
    def snapshot(self) -> dict:
        with self._lock:
            self._roll_day()
            return {"name": self.name, "per_minute": self.per_minute,
                    "per_day": self.per_day, "used_today": self._used_today,
                    "left_today": (self.per_day - self._used_today
                                   if self.per_day else None),
                    "tokens": round(self._tokens, 2)}

    def _roll_day(self) -> None:
        today = time.strftime("%Y-%m-%d")
        if today != self._day:
            self._day = today
            self._used_today = 0

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._updated
        self._updated = now
        self._tokens = min(self.burst,
                           self._tokens + elapsed * (self.per_minute / 60.0))

    def acquire(self, cost: int = 1, max_wait: float = 30.0) -> None:
        """Take `cost` requests' worth of budget, waiting if need be.

        Raises RateLimited when the daily quota is gone, or when the wait
        for the per-minute bucket would exceed `max_wait` -- a caller that
        would block for a minute is better off failing and being retried by
        whatever loop it lives in than holding a thread hostage.
        """
        deadline = time.monotonic() + max_wait
        while True:
            with self._lock:
                self._roll_day()
                if self.per_day and self._used_today + cost > self.per_day:
                    raise RateLimited(
                        f"{self.name}: the daily limit of {self.per_day} "
                        f"requests is used up. It resets at midnight; until "
                        f"then this will not call out again.")
                self._refill()
                if self._tokens >= cost:
                    self._tokens -= cost
                    self._used_today += cost
                    return
                needed = (cost - self._tokens) / (self.per_minute / 60.0)
            if time.monotonic() + needed > deadline:
                raise RateLimited(
                    f"{self.name}: {self.per_minute:.0f} requests/minute is "
                    f"already fully used and the wait would be "
                    f"{needed:.0f}s. Try again shortly.")
            time.sleep(min(needed, 0.5))

    def note_429(self, retry_after: float = 0.0) -> None:
        """The provider said we were going too fast anyway.

        Their opinion beats our arithmetic, so empty the bucket and make the
        next caller wait out whatever Retry-After they asked for. Without
        this a 429 is followed immediately by another request, which is how
        a brief throttle becomes a ban.
        """
        with self._lock:
            self._tokens = 0.0
            if retry_after > 0:
                # Push the refill clock back so the bucket stays empty.
                self._updated = time.monotonic() + min(retry_after, 300.0)
        log.warning("%s: rate limited by the provider%s", self.name,
                    f", waiting {retry_after:.0f}s" if retry_after else "")


_registry: dict = {}
_registry_lock = threading.Lock()


def limiter(name: str, per_minute: float = 60.0, per_day: int = 0,
            burst: float = 0.0) -> Limiter:
    """The shared limiter for a provider, created once.

    Shared deliberately: the dashboard thread and the billing thread both
    call Zoho, and two limiters would each happily use the whole budget.
    """
    with _registry_lock:
        lim = _registry.get(name)
        if lim is None:
            lim = Limiter(name, per_minute, per_day, burst)
            _registry[name] = lim
        return lim


def all_snapshots() -> list:
    """Every limiter's state, for the health panel."""
    with _registry_lock:
        return [lim.snapshot() for lim in _registry.values()]


def retry_after_seconds(headers) -> float:
    """Read Retry-After off a 429 response. 0 when absent or unparseable."""
    try:
        raw = headers.get("Retry-After") if headers else None
    except Exception:  # noqa: BLE001
        return 0.0
    if not raw:
        return 0.0
    try:
        return max(0.0, float(str(raw).strip()))
    except ValueError:
        # It may be an HTTP date rather than a number of seconds.
        try:
            from email.utils import parsedate_to_datetime
            when = parsedate_to_datetime(str(raw))
            return max(0.0, when.timestamp() - time.time())
        except Exception:  # noqa: BLE001
            return 0.0
