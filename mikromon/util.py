"""Small, dependency-free helpers shared across the package.

RouterOS returns most field values as strings (sometimes already coerced by
librouteros). These helpers normalise those values and format human-friendly
output for alert messages.
"""
from __future__ import annotations

import hashlib
import re

_UPTIME_UNITS = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}


def as_bool(value) -> bool:
    """Coerce a RouterOS field to bool. Accepts bool/int/str ('true'/'yes')."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "1")
    return False


def as_int(value, default: int = 0) -> int:
    """Coerce a RouterOS field to int, tolerating None and junk."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        m = re.search(r"-?\d+", value)
        if m:
            return int(m.group())
    return default


_RATE_UNITS = {"": 1, "k": 1_000, "m": 1_000_000, "g": 1_000_000_000}


def rate_bps(value) -> int:
    """A RouterOS rate in bits per second; -1 when it cannot be read.

    The API hands queue limits back in bits ("18000000", or an int), while
    a person types "18M" -- both forms are read here, so a limit compares
    equal however it was written. Rates are decimal: 1M is 1,000,000."""
    if value is None or isinstance(value, bool):
        return -1
    if isinstance(value, (int, float)):
        return int(value)
    m = re.match(r"^\s*(\d+(?:\.\d+)?)\s*([kKmMgG]?)\s*$", str(value))
    if not m:
        return -1
    return int(round(float(m.group(1)) * _RATE_UNITS[m.group(2).lower()]))


def mbps_text(bps) -> str:
    """Bits per second as a plain Mbps number for a form ("18", "0.5");
    "" when unknown."""
    if bps is None or isinstance(bps, bool) or bps < 0:
        return ""
    return ("%.3f" % (bps / 1_000_000)).rstrip("0").rstrip(".")


def mbps_to_bps(text) -> int:
    """A speed typed into a form, in bits per second: a bare number is Mbps
    ("18", "0.5"), a unit is taken as written ("512k", "1G"). -1 when it is
    not a speed."""
    s = str(text or "").strip()
    if re.fullmatch(r"\d+(?:\.\d+)?", s):
        return int(round(float(s) * 1_000_000))
    return rate_bps(s) if s else -1


def as_float(value, default: float = 0.0) -> float:
    try:
        if isinstance(value, str):
            m = re.search(r"-?\d+(?:\.\d+)?", value)
            return float(m.group()) if m else default
        return float(value)
    except (TypeError, ValueError):
        return default


def uptime_to_seconds(value):
    """Parse a RouterOS uptime string ('2w3d4h5m6s' or '1d10:11:12') to seconds."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    total = 0
    for num, unit in re.findall(r"(\d+)([wdhms])", text):
        total += int(num) * _UPTIME_UNITS[unit]
    # Trailing HH:MM:SS form (used by some RouterOS versions for sub-day uptime).
    m = re.search(r"(?:^|[a-z])(\d{1,2}):(\d{2}):(\d{2})$", text)
    if m:
        total += int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))
    return total


def human_bytes(value) -> str:
    """Format a byte count as a compact binary-unit string."""
    n = float(as_int(value))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TiB"


def human_bps(bps) -> str:
    """Format a bits-per-second rate (decimal units, as ISPs quote them)."""
    bps = float(bps or 0)
    for unit in ("bps", "Kbit/s", "Mbit/s", "Gbit/s"):
        if bps < 1000 or unit == "Gbit/s":
            return f"{bps:.0f} {unit}" if unit == "bps" else f"{bps:.1f} {unit}"
        bps /= 1000
    return f"{bps:.1f} Gbit/s"


def human_duration(seconds) -> str:
    """Format a duration in seconds as e.g. '3m', '2h5m', '4d3h'."""
    seconds = int(seconds or 0)
    if seconds < 60:
        return f"{seconds}s"
    parts = []
    for label, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size:
            parts.append(f"{seconds // size}{label}")
            seconds %= size
        if len(parts) == 2:
            break
    return "".join(parts) or "0m"


def short_hash(*parts) -> str:
    """A stable short signature for deduplicating events across polls."""
    joined = "\x1f".join("" if p is None else str(p) for p in parts)
    return hashlib.sha1(joined.encode("utf-8", "replace")).hexdigest()[:16]


def ip_in_subnets(ip: str, subnets) -> bool:
    """True if `ip` falls inside any CIDR in `subnets`. Tolerant of bad input."""
    import ipaddress

    if not ip:
        return False
    # Strip a trailing :port or %zone if present.
    ip = ip.split("%")[0].strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in subnets or []:
        try:
            if addr in ipaddress.ip_network(net, strict=False):
                return True
        except ValueError:
            continue
    return False
