"""Two-factor sign-in codes: TOTP (RFC 6238), as every authenticator app
(Google Authenticator, Microsoft Authenticator, Authy, 1Password ...) makes.

A stolen password is no longer enough: signing in also takes the 6-digit
code the person's phone shows, which changes every 30 seconds. One-time
recovery codes cover a lost phone; only their hashes are kept.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
import urllib.parse

PERIOD = 30
DIGITS = 6


def new_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def code_at(secret: str, step: int) -> str:
    digest = hmac.new(_key(secret), struct.pack(">Q", step),
                      hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    num = int.from_bytes(digest[off:off + 4], "big") & 0x7FFFFFFF
    return f"{num % 10 ** DIGITS:0{DIGITS}d}"


def verify(secret: str, code: str, last_step: int = 0,
           now: float | None = None, window: int = 1) -> int:
    """The time step the code belongs to, or 0. A step already used
    (<= last_step) is refused, so a code seen over someone's shoulder
    cannot be used again. One step either side allows for a phone clock
    that is a little off."""
    code = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(code) != DIGITS or not secret:
        return 0
    now_step = int((now if now is not None else time.time()) // PERIOD)
    for step in range(now_step - window, now_step + window + 1):
        if step > last_step and hmac.compare_digest(code_at(secret, step),
                                                    code):
            return step
    return 0


def uri(secret: str, account: str, issuer: str) -> str:
    """What the QR code holds: an otpauth:// link authenticator apps read."""
    label = urllib.parse.quote(f"{issuer}:{account}")
    return (f"otpauth://totp/{label}?secret={secret}"
            f"&issuer={urllib.parse.quote(issuer)}&algorithm=SHA1"
            f"&digits={DIGITS}&period={PERIOD}")


def qr_svg(text: str) -> str:
    """The QR code as inline SVG ("" if the qrcode package is missing --
    the page then shows the key to type in instead)."""
    try:
        import qrcode
        import qrcode.image.svg
    except ImportError:
        return ""
    img = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage,
                      box_size=8, border=2)
    svg = img.to_string().decode("utf-8")
    return svg[svg.find("<svg"):]


_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"   # no 0/o, 1/l/i


def recovery_codes(n: int = 10) -> list:
    out = []
    for _ in range(n):
        raw = "".join(_ALPHABET[b % len(_ALPHABET)] for b in os.urandom(8))
        out.append(f"{raw[:4]}-{raw[4:]}")
    return out


def hash_code(code: str) -> str:
    norm = "".join(ch for ch in str(code or "").lower() if ch.isalnum())
    return hashlib.sha256(norm.encode()).hexdigest()
