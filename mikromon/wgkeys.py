"""WireGuard keys without the `wg` binary: X25519 (RFC 7748) in pure Python.

A WireGuard private key is 32 random bytes, clamped; its public key is that
scalar times the curve's base point. That is all `wg genkey` / `wg pubkey`
do, and it is short enough to do here -- so a key can be made on a server
whose wireguard-tools are missing or out of reach of this service, and the
tests can make one on any machine.

Not constant-time. It runs once per key, on the server, on a key it then
hands over, so there is no secret being repeatedly exercised for a timing
attack to measure.
"""
from __future__ import annotations

import base64
import binascii
import os

_P = 2 ** 255 - 19
_A24 = 121665


def _decode_scalar(k: bytes) -> int:
    b = bytearray(k)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(bytes(b), "little")


def _decode_u(u: bytes) -> int:
    b = bytearray(u)
    b[31] &= 127
    return int.from_bytes(bytes(b), "little") % _P


def x25519(k: bytes, u: bytes) -> bytes:
    """RFC 7748 section 5: scalar `k` times the point with u-coordinate `u`."""
    if len(k) != 32 or len(u) != 32:
        raise ValueError("X25519 takes 32-byte inputs")
    k_int = _decode_scalar(k)
    x1 = _decode_u(u)
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(254, -1, -1):
        bit = (k_int >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


_BASE = (9).to_bytes(32, "little")


def public_key(private_b64: str) -> str:
    """The public key (base64) for a base64 private key."""
    raw = base64.b64decode(private_b64.strip(), validate=True)
    return base64.b64encode(x25519(raw, _BASE)).decode("ascii")


def keypair() -> tuple:
    """(private, public), both base64, as `wg genkey | wg pubkey` would."""
    b = bytearray(os.urandom(32))
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    priv = base64.b64encode(bytes(b)).decode("ascii")
    return priv, public_key(priv)


def valid_key(text: str) -> bool:
    """Is this a WireGuard key (base64 of exactly 32 bytes)? Catches the
    usual paste mistakes: a truncated key, the private key instead of the
    public one is NOT detectable this way, so the form says which to copy."""
    t = (text or "").strip()
    if len(t) != 44 or not t.endswith("="):
        return False
    try:
        return len(base64.b64decode(t, validate=True)) == 32
    except (binascii.Error, ValueError):
        return False
