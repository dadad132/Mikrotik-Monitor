"""A link on the invoice that pays it, with no login and no human at our end.

Paying by card was already fully automatic once it started: the gateway
confirms, the packet extends, the invoice is settled, nobody here touches
anything. The problem was getting a customer INTO it. The checkout needed a
session, so somebody who received an invoice by email had to remember a
password to pay it — and the path of least resistance was therefore the bank
transfer, which is the one that needs a person at our end reading a
statement.

So the invoice carries a link that goes straight to payment. That makes the
automatic path the easy one, which is the only way it becomes the usual one.

The link is a signed token rather than an order number, because an order
number is guessable and a guessable pay link lets a stranger read what a
company was charged. It carries no secret of its own: it says which order,
and that it was issued by us, and when it stops working.

What it deliberately cannot do is anything except pay. No session is created,
nothing is readable beyond the amount and the company name already printed
on the invoice the reader is holding, and a token for a paid order is
refused — so a forwarded email cannot pay twice.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import time

log = logging.getLogger(__name__)

# Long enough to survive a customer paying late, short enough that an old
# invoice forwarded to somebody is not a live payment page forever.
TTL_SECONDS = 60 * 86400

_SETTING = "paylink_secret"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def secret(auth) -> bytes:
    """The key these links are signed with, created once and kept.

    Stored rather than derived from anything else so that rotating it is a
    deliberate act: changing it invalidates every link already sitting in a
    customer's inbox.
    """
    if auth is None:
        raise RuntimeError("no settings store to keep the paylink secret in")
    raw = auth.get_setting(_SETTING)
    if not raw:
        raw = _b64(secrets.token_bytes(32))
        auth.set_setting(_SETTING, raw)
        log.info("created the pay-link signing secret")
    return _unb64(str(raw))


def make(auth, order_id: int, ttl: int = TTL_SECONDS) -> str:
    """A token that pays one order. Carries no secret of its own."""
    expires = int(time.time()) + int(ttl)
    body = f"{int(order_id)}.{expires}"
    sig = hmac.new(secret(auth), body.encode(), hashlib.sha256).digest()
    return f"{body}.{_b64(sig[:18])}"


def read(auth, token: str) -> int:
    """The order this token pays, or 0.

    Returns 0 for anything wrong -- forged, expired, malformed -- rather
    than saying which, because telling a stranger whether their guess was
    the right shape is telling them how to guess better.
    """
    try:
        order_s, expires_s, sig = str(token or "").split(".")
        order_id, expires = int(order_s), int(expires_s)
    except (ValueError, AttributeError):
        return 0
    if expires < time.time():
        return 0
    want = hmac.new(secret(auth), f"{order_id}.{expires}".encode(),
                    hashlib.sha256).digest()
    # Constant time: a comparison that returns early leaks how much of a
    # forged signature was right.
    if not hmac.compare_digest(_b64(want[:18]), sig):
        return 0
    return order_id


def url(auth, base: str, order_id: int) -> str:
    """The full link to put on an invoice."""
    return f"{base.rstrip('/')}/pay?t={make(auth, order_id)}"
