"""The USD→ZAR rate, from a published source you can name on the invoice.

Prices are decided in USD. A card gateway that settles in rands therefore
needs a conversion — and the conversion cannot be a number somebody picked.
If the site says $25 and the card is charged R460, the customer is entitled
to expect that R460 is what $25 costs today. A rate of our own choosing
makes that relationship something we asserted rather than something true.

It was a constant compiled into the source:

    _ZAR_PER_USD = 18.4

On the day this was written the real rate was 16.26, so every rand charge was
13% above the dollar price advertised beside it. Nobody chose that; it was
simply never revisited. That is the shape of the problem, and a "review it
monthly" reminder would have been the same problem with more steps.

So the rate is fetched from a published source, and the source and its date
are recorded against every charge that uses it. The primary source is the
European Central Bank's daily reference rate, because it is published, dated,
independent of us, and can be cited on a document: "converted at the ECB
reference rate of 21 September 2026".

What this deliberately will NOT do is invent a rate. If no published rate can
be had and none is cached, converting raises instead of guessing — a charge
nobody can justify is worse than a charge that did not happen.

Stdlib only, like the rest of this project.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request

log = logging.getLogger(__name__)

_TIMEOUT = 15.0

# In order. The ECB reference rate first because it is the one worth naming
# on an invoice: published daily by a central bank, dated, and nothing to do
# with us. The second is a fallback so a single provider being down does not
# stop a customer paying.
SOURCES = (
    ("ECB reference rate",
     "https://api.frankfurter.dev/v1/latest?base={base}&symbols={quote}"),
    ("exchangerate-api.com",
     "https://open.er-api.com/v6/latest/{base}"),
)

# A rate is published once per working day, so asking more often than that
# learns nothing. Weekends and holidays legitimately return Friday's.
REFRESH_SECONDS = 6 * 3600
# Past this, the rate is old enough that somebody should be told -- a long
# weekend is three days, so this is "something is wrong", not "it is Sunday".
STALE_DAYS = 4

CACHE_PATH = ""          # set by the application; "" keeps it in memory only

_cache: dict = {}
_lock = threading.Lock()


class RateUnavailable(Exception):
    """No published rate could be had, and none was cached.

    Raised rather than falling back to anything invented: a rand amount
    nobody can point at a source for is not one to charge.
    """


def _fetch(base: str, quote: str) -> dict:
    """Ask each published source in turn. Raises if none answers."""
    from .ratelimit import RateLimited, limiter

    lim = limiter("FX rates", 20)
    errors = []
    for name, template in SOURCES:
        url = template.format(base=base, quote=quote)
        try:
            lim.acquire(max_wait=5.0)
        except RateLimited as exc:
            errors.append(f"{name}: {exc}")
            continue
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "mikromon"})
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except (urllib.error.URLError, ValueError, OSError) as exc:
            errors.append(f"{name}: {exc}")
            continue
        rate = (data.get("rates") or {}).get(quote)
        if not rate:
            errors.append(f"{name}: no {quote} rate in the reply")
            continue
        # Frankfurter dates its rate; the fallback timestamps its update.
        when = str(data.get("date") or "")
        if not when:
            stamp = data.get("time_last_update_unix")
            when = (time.strftime("%Y-%m-%d", time.gmtime(float(stamp)))
                    if stamp else time.strftime("%Y-%m-%d"))
        return {"rate": float(rate), "date": when, "source": name,
                "pair": f"{base}{quote}", "fetched": time.time()}
    raise RateUnavailable("; ".join(errors) or "no source answered")


def _load_cached() -> dict:
    if not CACHE_PATH:
        return {}
    try:
        with open(CACHE_PATH, encoding="utf-8") as f:
            return json.load(f) or {}
    except (OSError, ValueError):
        return {}


def _save_cached(data: dict) -> None:
    if not CACHE_PATH:
        return
    try:
        tmp = CACHE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1)
        os.replace(tmp, CACHE_PATH)
    except OSError:
        log.exception("could not cache the exchange rate")


def get(base: str = "USD", quote: str = "ZAR", max_age: float = 0.0) -> dict:
    """The current published rate: {rate, date, source, fetched, age_days}.

    Returns the cached rate while it is fresh. When a refresh fails but a
    cached rate exists, the cached one is returned WITH ITS OWN DATE rather
    than today's -- so a charge made on a stale rate says which day's rate it
    was, instead of implying it was looked up now.
    """
    key = f"{base}{quote}"
    max_age = max_age or REFRESH_SECONDS
    with _lock:
        hit = _cache.get(key) or _load_cached().get(key)
        if hit and time.time() - float(hit.get("fetched") or 0) < max_age:
            return _with_age(hit)

    try:
        fresh = _fetch(base, quote)
    except RateUnavailable:
        if hit:
            log.warning("using the cached %s rate from %s: no source answered",
                        key, hit.get("date"))
            return _with_age(hit)
        raise

    with _lock:
        _cache[key] = fresh
        stored = _load_cached()
        stored[key] = fresh
        _save_cached(stored)
    return _with_age(fresh)


def _with_age(row: dict) -> dict:
    out = dict(row)
    try:
        published = time.mktime(time.strptime(str(row.get("date")), "%Y-%m-%d"))
        out["age_days"] = max(0.0, (time.time() - published) / 86400)
    except (ValueError, TypeError):
        out["age_days"] = None
    out["stale"] = bool(out["age_days"] is not None
                        and out["age_days"] > STALE_DAYS)
    return out


def convert(amount_usd: float, quote: str = "ZAR") -> dict:
    """Convert, and say exactly what was used to do it.

    Returns {amount, rate, date, source, stale} -- everything needed to put
    "converted at the ECB reference rate of 21 September 2026" on a receipt,
    which is what makes the figure something the customer can check rather
    than something we asserted.
    """
    row = get("USD", quote)
    return {"amount": round(float(amount_usd) * row["rate"], 2),
            "rate": row["rate"], "date": row["date"],
            "source": row["source"], "stale": row.get("stale", False),
            "age_days": row.get("age_days")}


def describe(row: dict) -> str:
    """One line a customer can read on a receipt."""
    if not row:
        return ""
    return (f"Converted at the {row.get('source', 'published')} of "
            f"{row.get('date', '')} (1 USD = {row.get('rate', 0):,.4f} "
            f"{str(row.get('pair', 'USDZAR'))[3:] or 'ZAR'}).")
