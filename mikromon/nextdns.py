"""Thin client for the real NextDNS.io cloud API (api.nextdns.io).

Used to give each router its own NextDNS "profile" (a Configuration ID with
its own blocklists, allowlists and query logs) instead of one profile shared
by everyone — see push/features.py's nextdns_cloud_ops() for how a profile
id is then turned into a RouterOS DNS-over-HTTPS setting on the router
itself. No dependencies beyond the stdlib (same approach as billing.py's
PayFast client).
"""
from __future__ import annotations

import hashlib as _hashlib
import json
import threading as _threading
import time as _time
import urllib.error
import urllib.parse
import urllib.request

_API_BASE = "https://api.nextdns.io"
_TIMEOUT = 10
# Cloudflare sits in front of api.nextdns.io and its bot-management WAF
# blocks the default "Python-urllib/3.x" User-Agent outright — confirmed
# live: identical requests differing ONLY in this header get a Cloudflare
# edge block (HTTP 403, "error code: 1010", plain-text body, no app-level
# headers) with the default UA, vs. reaching the real NextDNS API (proper
# JSON error body) with any ordinary one. Doesn't need to impersonate a
# browser — any non-default value clears it.
_USER_AGENT = "easymikrotik/1.0 (+https://easymikrotik.com)"

# NextDNS does not publish a figure, and answers 429 "Rate exceeded" sooner
# than you would expect. This is deliberately well below anything observed.
_LIMIT_PER_MINUTE = 30

# A profile is READ far more often than it is written: opening the DNS tab,
# the redirect after saving, and mirroring template settings all read it.
# Caching for under a minute removes almost all of that without anyone ever
# seeing a stale panel, because every write empties the entry first.
_CACHE_SECONDS = 45.0
_profile_cache: dict = {}
_cache_lock = _threading.Lock()


def _cache_key(api_key: str, profile_id: str) -> str:
    # The key is hashed so an API key never sits in a dict somebody might
    # print while debugging.
    return _hashlib.sha256(
        f"{api_key}:{profile_id}".encode()).hexdigest()


def invalidate(api_key: str = "", profile_id: str = "") -> None:
    """Forget a cached profile -- or all of them.

    Called on every write. Without it the redirect straight after saving a
    toggle would show the value from before the save, which reads exactly
    like the save having failed.
    """
    with _cache_lock:
        if api_key and profile_id:
            _profile_cache.pop(_cache_key(api_key, profile_id), None)
        else:
            _profile_cache.clear()


class NextDnsError(Exception):
    pass


def _request(method: str, path: str, api_key: str,
             body: dict | None = None,
             _retried: bool = False) -> dict:
    url = _API_BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "X-Api-Key": api_key,
        "Content-Type": "application/json",
        "User-Agent": _USER_AGENT,
    })
    from .ratelimit import limiter, RateLimited, retry_after_seconds
    _lim = limiter("NextDNS", _LIMIT_PER_MINUTE, 0)
    try:
        _lim.acquire()
    except RateLimited as exc:
        raise NextDnsError(str(exc)) from exc
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        if exc.code == 429 and not _retried:
            # One retry, because the first 429 almost always means "wait a
            # moment" -- and failing the whole panel for a second's patience
            # is a poor trade. Retry-After is honoured when they send it;
            # otherwise a short fixed pause, capped so no page load hangs.
            wait = retry_after_seconds(exc.headers) or 1.5
            _lim.note_429(wait)
            if wait <= 5.0:
                _time.sleep(wait)
                return _request(method, path, api_key, body, _retried=True)
        if exc.code == 429:
            _lim.note_429(retry_after_seconds(exc.headers))
            raise NextDnsError(
                "NextDNS is limiting how often we may ask it. The settings "
                "are fine -- this page asked once too often. Wait a few "
                "seconds and reload.") from exc
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")
        except Exception:
            pass
        raise NextDnsError(
            f"NextDNS API {method} {path} failed: HTTP {exc.code}"
            + (f" — {detail}" if detail else "")) from exc
    except urllib.error.URLError as exc:
        raise NextDnsError(f"NextDNS API unreachable: {exc.reason}") from exc
    except (OSError, TimeoutError) as exc:
        # A stall/drop while *reading* the response (as opposed to
        # connecting) surfaces as a raw OSError/TimeoutError, not URLError —
        # urllib only wraps the connect phase. Left uncaught, this would
        # propagate out of the web request handler unhandled (no response
        # sent to the browser at all) instead of becoming the graceful
        # "Could not create a NextDNS profile: ..." message the caller
        # already redirects with.
        raise NextDnsError(f"NextDNS API {method} {path} timed out or "
                           f"dropped mid-response: {exc}") from exc
    except ValueError as exc:
        # json.loads on a non-JSON (or truncated) 200 body.
        raise NextDnsError(
            f"NextDNS API {method} {path} returned an unparseable "
            f"response: {exc}") from exc


def create_profile(api_key: str, name: str) -> str:
    """Create a new NextDNS profile (a Configuration ID). Returns the new
    profile's id (e.g. "abc123").

    Deliberately creates a BLANK profile with no server-side clone. This used
    to take a `clone_from` and send it as `POST /profiles?clone=<id>`, which
    NextDNS rejects outright — confirmed live:

        HTTP 400 {"errors":[{"code":"extraneous",
                             "source":{"parameter":"clone"}}]}

    "extraneous" means the API does not know that parameter at all, so no
    value would have worked. It went unnoticed for a long time because the
    only caller passed a clone id from the superadmin's optional "template
    profile" setting, which is normally blank — with it blank the parameter
    was never appended and every profile created fine. The per-uplink
    profiles were the first caller to pass one every time, which is what
    finally surfaced it.

    Callers that want a copy of another profile create one here and then copy
    the settings across with web.py's _nextdns_mirror_settings, which uses
    only endpoints known to work and produces the same end state."""
    resp = _request("POST", "/profiles", api_key, {"name": name})
    profile_id = (resp.get("data") or {}).get("id") or resp.get("id")
    if not profile_id:
        raise NextDnsError(
            f"NextDNS API did not return a profile id: {resp!r}")
    return str(profile_id)


def rename_profile(api_key: str, profile_id: str, name: str) -> None:
    """Rename an existing profile. Used to keep a per-WAN profile's name
    tracking its uplink's friendly label after that uplink is renamed on the
    WAN tab — renaming rather than recreating means the profile keeps its
    query log and analytics history instead of starting over."""
    _request("PATCH", f"/profiles/{profile_id}", api_key, {"name": name})
    # The cached copy is now a lie. Nothing is more confusing than a
    # save that appears not to have taken because the page after it
    # re-rendered from a stale read.
    invalidate(api_key, profile_id)

def get_profile(api_key: str, profile_id: str,
                max_age: float = _CACHE_SECONDS) -> dict:
    """The full profile config — security/privacy/parentalControl toggles,
    denylist/allowlist entries — so the DNS tab can render and manage all
    of it in-app instead of sending the customer to my.nextdns.io (which
    would put them one click away from the shared platform account every
    other router's profile also lives under).

    Read through a short cache. This panel is read several times for every
    time it is changed -- opening the tab, the redirect after saving, and
    mirroring template settings all read it -- and NextDNS answers 429
    sooner than that pattern allows. Pass max_age=0 to force a fresh read;
    every write invalidates the entry, so a save is never followed by a
    stale panel."""
    key = _cache_key(api_key, profile_id)
    if max_age > 0:
        with _cache_lock:
            hit = _profile_cache.get(key)
        if hit and _time.time() - hit[0] < max_age:
            return hit[1]
    resp = _request("GET", f"/profiles/{profile_id}", api_key)
    data = resp.get("data") or resp
    with _cache_lock:
        _profile_cache[key] = (_time.time(), data)
    return data


def update_section(api_key: str, profile_id: str, section: str,
                   patch: dict) -> None:
    """PATCH one top-level settings section — "security", "privacy", or
    "parentalControl" — with just the changed fields."""
    _request("PATCH", f"/profiles/{profile_id}/{section}", api_key, patch)
    # The cached copy is now a lie. Nothing is more confusing than a
    # save that appears not to have taken because the page after it
    # re-rendered from a stale read.
    invalidate(api_key, profile_id)

def add_list_entry(api_key: str, profile_id: str, list_name: str,
                   domain: str) -> None:
    """Add a domain to the profile's "denylist" or "allowlist"."""
    _request("POST", f"/profiles/{profile_id}/{list_name}", api_key,
             {"id": domain, "active": True})
    # The cached copy is now a lie. Nothing is more confusing than a
    # save that appears not to have taken because the page after it
    # re-rendered from a stale read.
    invalidate(api_key, profile_id)

def remove_list_entry(api_key: str, profile_id: str, list_name: str,
                      domain: str) -> None:
    """Remove a domain previously added to "denylist" or "allowlist"."""
    _request("DELETE",
             f"/profiles/{profile_id}/{list_name}/"
             f"{urllib.parse.quote(domain, safe='')}", api_key)
    # The cached copy is now a lie. Nothing is more confusing than a
    # save that appears not to have taken because the page after it
    # re-rendered from a stale read.
    invalidate(api_key, profile_id)

def delete_profile(api_key: str, profile_id: str) -> None:
    """Delete a profile that's no longer needed (NextDNS disabled for that
    router, or the router removed from mikromon). Best-effort by design at
    the call site — callers should not let this block clearing the local
    "enabled" state even if it fails (the profile is orphaned but harmless,
    versus getting a router permanently stuck showing as "enabled")."""
    _request("DELETE", f"/profiles/{profile_id}", api_key)
    # The cached copy is now a lie. Nothing is more confusing than a
    # save that appears not to have taken because the page after it
    # re-rendered from a stale read.
    invalidate(api_key, profile_id)

def doh_url(profile_id: str) -> str:
    """The DNS-over-HTTPS URL for this profile — what gets pushed into
    RouterOS's /ip/dns use-doh-server field."""
    return f"https://dns.nextdns.io/{profile_id}"


def setup_url(profile_id: str) -> str:
    """A link into the NextDNS dashboard for this specific profile, so a
    user can configure its blocklists/allowlists or view its query log."""
    return f"https://my.nextdns.io/{profile_id}/setup"
